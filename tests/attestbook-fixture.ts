import { createHash, createHmac, randomUUID } from "node:crypto";
import { type IncomingMessage, type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";

/**
 * A disposable HTTP server that answers the deployed Attestbook public API contracts the issuer
 * reads (docs/api.md §3.4, §3.4.1, §3.13–3.15.2): the publication event feed, the immutable
 * version export, the frozen schema references and hosted schema document content. It signs
 * publication webhooks exactly as Attestbook does. It is test infrastructure, not a mock of the
 * issuer's own logic.
 */
export interface FixtureAttestation {
  name: string;
  bindingType?: string;
  supportedFormats?: string[];
  /** JSON Schema 2020-12 document, hosted by the fixture. */
  schema?: Record<string, unknown>;
  /** JSON Schema 2020-12 document of the `mso_mdoc` format, hosted by the fixture. */
  mdocSchema?: Record<string, unknown>;
  /** SD-JWT VC Type Metadata document, hosted by the fixture. */
  typeMetadata?: Record<string, unknown>;
  /** Extra references, as frozen in the snapshot, for documents the fixture does not host. */
  externalReferences?: { formatIdentifier: string; uri: string; integrity: string | null }[];
  /** Omits the SRI pin of the hosted references. */
  unpinned?: boolean;
}

interface HostedDocument {
  id: string;
  kind: "json_schema_2020_12" | "sd_jwt_vc_type_metadata";
  bytes: Buffer;
}

interface PublishedVersion {
  version: string;
  bytes: Buffer;
  digest: string;
  publishedAt: string;
  eventId: string;
  references: {
    attestation: string;
    formatIdentifier: string;
    uri: string;
    integrity: string | null;
  }[];
}

export class AttestbookFixture {
  readonly rulebookId = `rulebook-${randomUUID()}`;
  readonly requests: string[] = [];
  /** Responses replaced for tampering tests, keyed by request path. */
  readonly overrides = new Map<string, Buffer>();
  private readonly documents = new Map<string, HostedDocument>();
  private readonly versions: PublishedVersion[] = [];
  /** Subscriptions registered through the anonymous API (§3.15), by id. */
  readonly subscriptions = new Map<
    string,
    { callbackUrl: string; managementToken: string; webhookSecret: string; state: string }
  >();
  private server: Server | null = null;
  origin = "";

  async start(port = 0): Promise<void> {
    this.server = createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://fixture").pathname;
      this.requests.push(`${req.method} ${req.url}`);
      const override = this.overrides.get(path);
      const answer = (
        status: number,
        body: Buffer | string,
        headers: Record<string, string> = {},
      ) => {
        res.writeHead(status, { "content-type": "application/json", ...headers });
        res.end(body);
      };
      const json = (status: number, value: unknown) => answer(status, JSON.stringify(value));

      const rulebookPath = `/api/v1/rulebooks/${this.rulebookId}`;
      if (req.method === "POST" && path === `${rulebookPath}/subscriptions`) {
        return this.registerSubscription(req, json);
      }
      const subscriptionMatch = /^\/api\/v1\/subscriptions\/([^/]+)(\/verify)?$/.exec(path);
      if (subscriptionMatch) {
        const subscription = this.subscriptions.get(subscriptionMatch[1] ?? "");
        if (
          !subscription ||
          req.headers.authorization !== `Bearer ${subscription.managementToken}`
        ) {
          return json(401, { error: { code: "unauthorized", message: "unauthorized" } });
        }
        const projection = () => ({
          data: {
            id: subscriptionMatch[1],
            rulebookId: this.rulebookId,
            callbackUrl: subscription.callbackUrl,
            state: subscription.state,
          },
        });
        if (!subscriptionMatch[2]) return json(200, projection());
        return void this.verifyCallback(subscription).then(
          (verified) => {
            if (verified) subscription.state = "active";
            json(
              verified ? 200 : 409,
              verified
                ? projection()
                : { error: { code: "verification_failed", message: "challenge mismatch" } },
            );
          },
          () => json(502, { error: { code: "callback_unreachable", message: "unreachable" } }),
        );
      }
      if (path === `${rulebookPath}/events`) {
        const query = new URL(req.url ?? "/", "http://fixture").searchParams;
        const limit = Number(query.get("limit") ?? "50");
        const offset = Number(query.get("cursor") ?? "0");
        const page = this.versions.slice(offset, offset + limit);
        const hasMore = offset + limit < this.versions.length;
        return json(200, {
          data: page.map((version) => this.event(version)),
          pagination: { limit, nextCursor: hasMore ? String(offset + limit) : null, hasMore },
        });
      }
      const versionMatch = new RegExp(
        `^${rulebookPath}/versions/([^/]+)/(export|schema-references)$`,
      ).exec(path);
      if (versionMatch) {
        const version = this.versions.find(
          (candidate) => candidate.version === decodeURIComponent(versionMatch[1] ?? ""),
        );
        if (!version) return json(404, { error: { code: "not_found", message: "not found" } });
        if (versionMatch[2] === "export") {
          const bytes = override ?? version.bytes;
          return answer(200, bytes, {
            "content-type": "application/vnd.attestbook.rulebook-version+json",
            "content-digest": `sha-256=:${Buffer.from(version.digest, "hex").toString("base64")}:`,
            etag: `"${version.digest}"`,
          });
        }
        const latest = this.versions.at(-1);
        return json(200, {
          data: {
            version: version.version,
            contentDigest: version.digest,
            status: latest === version ? "published" : "historical",
            publishedAt: version.publishedAt,
            attestations: this.attestationNames(version).map((name) => ({
              name,
              schemaReferences: version.references
                .filter((reference) => reference.attestation === name)
                .map((reference) => this.referenceProjection(reference)),
            })),
            schemaReferences: [],
          },
        });
      }
      const documentMatch = /^\/api\/v1\/schema-documents\/([^/]+)\/content$/.exec(path);
      if (documentMatch) {
        const document = this.documents.get(documentMatch[1] ?? "");
        if (!document) return json(404, { error: { code: "not_found", message: "not found" } });
        return answer(200, override ?? document.bytes, {
          "content-type":
            document.kind === "json_schema_2020_12"
              ? "application/schema+json"
              : "application/json",
        });
      }
      return json(404, { error: { code: "not_found", message: "not found" } });
    });
    await new Promise<void>((resolve) => this.server?.listen(port, "127.0.0.1", resolve));
    this.origin = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  private registerSubscription(
    req: IncomingMessage,
    json: (status: number, value: unknown) => void,
  ): void {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const { callbackUrl } = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
        callbackUrl: string;
      };
      const id = randomUUID();
      const subscription = {
        callbackUrl,
        managementToken: `ats_${randomUUID()}`,
        webhookSecret: `atw_${createHash("sha256").update(id).digest("base64url")}`,
        state: "pending",
      };
      this.subscriptions.set(id, subscription);
      json(201, {
        data: {
          id,
          rulebookId: this.rulebookId,
          callbackUrl,
          state: "pending",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          managementToken: subscription.managementToken,
          webhookSecret: subscription.webhookSecret,
        },
      });
    });
  }

  /** Sends the §3.15.1 challenge and accepts only a 200 JSON answer echoing it exactly. */
  private async verifyCallback(subscription: { callbackUrl: string }): Promise<boolean> {
    const challenge = `atv_${randomUUID().replaceAll("-", "")}`;
    const response = await fetch(subscription.callbackUrl, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        type: "attestbook.subscription.verification@1",
        challenge,
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
      }),
    });
    const body = (await response.json().catch(() => null)) as { challenge?: unknown } | null;
    return (
      response.status === 200 &&
      (response.headers.get("content-type") ?? "").startsWith("application/json") &&
      body?.challenge === challenge
    );
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  get port(): number {
    return Number(new URL(this.origin).port);
  }

  /** Publishes the next version and returns its publication event. */
  publish(version: string, attestations: FixtureAttestation[]): FixtureEvent {
    const references: PublishedVersion["references"] = [];
    const snapshotAttestations = attestations.map((attestation) => {
      const frozen: { formatIdentifier: string; uri: string; integrity: string | null }[] = [];
      for (const [kind, document, formatIdentifier] of [
        ["json_schema_2020_12", attestation.schema, "dc+sd-jwt"],
        ["sd_jwt_vc_type_metadata", attestation.typeMetadata, "dc+sd-jwt"],
        ["json_schema_2020_12", attestation.mdocSchema, "mso_mdoc"],
      ] as const) {
        if (!document) continue;
        const hosted = this.host(kind, document);
        frozen.push({
          formatIdentifier,
          uri: this.documentUrl(hosted.id),
          integrity: attestation.unpinned ? null : sri(hosted.bytes),
        });
      }
      frozen.push(...(attestation.externalReferences ?? []));
      for (const reference of frozen)
        references.push({ attestation: attestation.name, ...reference });
      return {
        name: attestation.name,
        attestationLoS: "iso_18045_basic",
        bindingType: attestation.bindingType ?? "key",
        supportedFormats: attestation.supportedFormats ?? [
          ...(attestation.schema || !attestation.mdocSchema ? ["dc+sd-jwt"] : []),
          ...(attestation.mdocSchema ? ["mso_mdoc"] : []),
        ],
        schemaReferences: frozen,
      };
    });
    const bytes = Buffer.from(
      JSON.stringify({
        format: "attestbook.rulebook-version@1",
        rulebookId: this.rulebookId,
        version,
        specVersion: "ts11@1.0.1",
        name: "Fixture rulebook",
        description: "Disposable Attestbook fixture",
        sourceUrl: null,
        attestations: snapshotAttestations,
        schemaReferences: [],
      }),
      "utf8",
    );
    const published: PublishedVersion = {
      version,
      bytes,
      digest: createHash("sha256").update(bytes).digest("hex"),
      publishedAt: new Date(Date.now() + this.versions.length).toISOString(),
      eventId: `event-${randomUUID()}`,
      references,
    };
    this.versions.push(published);
    return this.event(published);
  }

  exportPath(version: string): string {
    return `/api/v1/rulebooks/${this.rulebookId}/versions/${version}/export`;
  }

  documentPaths(): string[] {
    return [...this.documents.keys()].map((id) => `/api/v1/schema-documents/${id}/content`);
  }

  private host(kind: HostedDocument["kind"], document: Record<string, unknown>): HostedDocument {
    const bytes = Buffer.from(JSON.stringify(document), "utf8");
    const id = createHash("sha256").update(kind).update(bytes).digest("hex").slice(0, 24);
    const hosted = { id, kind, bytes };
    this.documents.set(id, hosted);
    return hosted;
  }

  private documentUrl(id: string): string {
    return `${this.origin}/api/v1/schema-documents/${id}/content`;
  }

  private referenceProjection(
    reference: PublishedVersion["references"][number],
  ): Record<string, unknown> {
    const id = /\/schema-documents\/([^/]+)\/content$/.exec(reference.uri)?.[1];
    const hosted = id && reference.uri.startsWith(this.origin) ? this.documents.get(id) : undefined;
    return {
      formatIdentifier: reference.formatIdentifier,
      uri: reference.uri,
      integrity: reference.integrity,
      hostedSchema: hosted
        ? {
            id: hosted.id,
            kind: hosted.kind,
            mediaType:
              hosted.kind === "json_schema_2020_12"
                ? "application/schema+json"
                : "application/json",
            contentDigest: createHash("sha256").update(hosted.bytes).digest("hex"),
            integrity: sri(hosted.bytes),
            url: reference.uri,
            createdAt: "2026-01-01T00:00:00.000Z",
          }
        : null,
    };
  }

  private attestationNames(version: PublishedVersion): string[] {
    const document = JSON.parse(version.bytes.toString("utf8")) as {
      attestations: { name: string }[];
    };
    return document.attestations.map((attestation) => attestation.name);
  }

  private event(version: PublishedVersion): FixtureEvent {
    return {
      id: version.eventId,
      format: "attestbook.rulebook-publication-event@1",
      type: "rulebook.published",
      rulebookId: this.rulebookId,
      version: version.version,
      contentDigest: version.digest,
      publishedAt: version.publishedAt,
    };
  }
}

export interface FixtureEvent {
  id: string;
  format: "attestbook.rulebook-publication-event@1";
  type: "rulebook.published";
  rulebookId: string;
  version: string;
  contentDigest: string;
  publishedAt: string;
}

function sri(bytes: Buffer): string {
  return `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
}

/** The request Attestbook delivers for one event, signed with the subscription's secret. */
export function signedDelivery(
  secret: string,
  event: FixtureEvent,
  timestamp = new Date().toISOString(),
): { body: Buffer; headers: Record<string, string> } {
  const body = Buffer.from(JSON.stringify(event), "utf8");
  const input = [
    "attestbook.webhook-signing-input@1",
    timestamp,
    event.id,
    createHash("sha256").update(body).digest("hex"),
  ].join("\n");
  return {
    body,
    headers: {
      "content-type": "application/json",
      "x-attestbook-event-id": event.id,
      "x-attestbook-event-type": "rulebook.published",
      "x-attestbook-timestamp": timestamp,
      "x-attestbook-signature": `v1=${createHmac("sha256", secret).update(input, "utf8").digest("hex")}`,
    },
  };
}
