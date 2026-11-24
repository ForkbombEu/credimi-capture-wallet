import { isRecord } from "../shared/json.js";
import { sha256Hex } from "./digest.js";
import { type BoundedGetOptions, type BoundedResponse, boundedGet } from "./http.js";
import { SAFE_ATTESTBOOK_IDENTIFIER } from "./settings.js";
import {
  AttestbookIntegrityError,
  type SnapshotTrust,
  detectSchemaKind,
  requiredSchemaReferences,
  verifyExportedBytes,
  verifyRulebook,
  verifySnapshot,
} from "./snapshot.js";
import type {
  AttestbookSchemaDocumentRecord,
  AttestbookSchemaKind,
  AttestbookSchemaReference,
  AttestbookSnapshot,
} from "./types.js";

const API_RESPONSE_MAX_BYTES = 256 * 1024;
const EXPORT_MAX_BYTES = 1024 * 1024;
const SCHEMA_DOCUMENT_MAX_BYTES = 256 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const EVENT_PAGE_LIMIT = 100;
const MAX_EVENT_PAGES = 50;
const MAX_SCHEMA_DOCUMENTS = 64;

/** One `attestbook.rulebook-publication-event@1` from the public feed or a webhook body. */
export interface AttestbookPublicationEvent {
  readonly id: string;
  readonly format: "attestbook.rulebook-publication-event@1";
  readonly type: "rulebook.published";
  readonly rulebookId: string;
  readonly version: string;
  readonly contentDigest: string;
  readonly publishedAt: string;
}

/** The shape of an Attestbook response is not the documented contract. */
export class AttestbookContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestbookContractError";
  }
}

/**
 * Reads the deployed Attestbook public API for one configured rulebook: its publication event feed,
 * the immutable export of a published version, the schema references frozen in it and the schema
 * documents those references name. Every read is unauthenticated, bounded and limited to the
 * trusted origin, or to an explicitly allowed origin for an external schema document.
 */
export class AttestbookClient {
  constructor(
    private readonly trust: SnapshotTrust,
    private readonly fetchImpl?: typeof fetch,
  ) {}

  /** Every publication event of the rulebook, in Attestbook's ascending publication order. */
  async publicationEvents(): Promise<AttestbookPublicationEvent[]> {
    const events: AttestbookPublicationEvent[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < MAX_EVENT_PAGES; page += 1) {
      const query = new URLSearchParams({ limit: String(EVENT_PAGE_LIMIT) });
      if (cursor) query.set("cursor", cursor);
      const body = await this.getJson(`${this.rulebookPath()}/events?${query}`);
      const pagination = isRecord(body) ? body.pagination : undefined;
      if (!isRecord(body) || !Array.isArray(body.data) || !isRecord(pagination)) {
        throw new AttestbookContractError("event feed page is malformed");
      }
      for (const entry of body.data) {
        const event = publicationEventOrNull(entry);
        if (!event || event.rulebookId !== this.trust.rulebookId) {
          throw new AttestbookContractError("event feed carries a malformed publication event");
        }
        events.push(event);
      }
      if (pagination.hasMore !== true) return events;
      if (typeof pagination.nextCursor !== "string" || !pagination.nextCursor) {
        throw new AttestbookContractError("event feed page has more events but no cursor");
      }
      cursor = pagination.nextCursor;
    }
    throw new AttestbookContractError(`event feed exceeds ${MAX_EVENT_PAGES} pages`);
  }

  /**
   * Downloads and verifies the immutable snapshot a publication event pins. Nothing partially
   * trusted is returned: any mismatch rejects the whole snapshot.
   */
  async downloadSnapshot(event: AttestbookPublicationEvent): Promise<AttestbookSnapshot> {
    const versionPath = `${this.rulebookPath()}/versions/${encodeURIComponent(event.version)}`;
    const references = await this.getJson(`${versionPath}/schema-references`);
    const projection = isRecord(references) ? references.data : undefined;
    if (
      !isRecord(projection) ||
      projection.version !== event.version ||
      projection.contentDigest !== event.contentDigest ||
      (projection.status !== "published" && projection.status !== "historical")
    ) {
      throw new AttestbookContractError(
        "schema references do not describe the published version the event pins",
      );
    }
    const schemaReferences = parseSchemaReferences(projection);

    const exported = await this.get(`${versionPath}/export`, {
      maxBytes: EXPORT_MAX_BYTES,
      accept: "application/vnd.attestbook.rulebook-version+json, application/json",
    });
    verifyExportedBytes(exported.bytes, event.contentDigest, exported.contentDigest);

    const withoutDocuments: AttestbookSnapshot = {
      format: "credimi.attestbook-snapshot@1",
      origin: this.trust.origin,
      rulebookId: this.trust.rulebookId,
      version: event.version,
      contentDigest: event.contentDigest,
      publishedAt: event.publishedAt,
      eventId: event.id,
      retrievedAt: new Date().toISOString(),
      rulebookBase64: Buffer.from(exported.bytes).toString("base64"),
      schemaReferences,
      schemaDocuments: [],
    };
    const document = verifyRulebook(withoutDocuments, this.trust);
    const required = requiredSchemaReferences(schemaReferences, document);
    const uniqueReferences = required.filter(
      (reference, index) => required.findIndex((other) => other.uri === reference.uri) === index,
    );
    if (uniqueReferences.length > MAX_SCHEMA_DOCUMENTS) {
      throw new AttestbookContractError("rulebook references too many schema documents");
    }
    const schemaDocuments: AttestbookSchemaDocumentRecord[] = [];
    for (const reference of uniqueReferences) {
      schemaDocuments.push(await this.fetchSchemaDocument(reference));
    }
    return verifySnapshot({ ...withoutDocuments, schemaDocuments }, this.trust).snapshot;
  }

  private async fetchSchemaDocument(
    reference: AttestbookSchemaReference,
  ): Promise<AttestbookSchemaDocumentRecord> {
    const response = await boundedGet(reference.uri, {
      allowedOrigins: reference.hosted ? [this.trust.origin] : this.trust.allowedSchemaOrigins,
      maxBytes: SCHEMA_DOCUMENT_MAX_BYTES,
      timeoutMs: REQUEST_TIMEOUT_MS,
      accept: "application/schema+json, application/json",
      fetch: this.fetchImpl,
    });
    let kind: AttestbookSchemaKind | null = reference.hosted?.kind ?? null;
    if (!kind) {
      try {
        kind = detectSchemaKind(JSON.parse(Buffer.from(response.bytes).toString("utf8")));
      } catch {
        kind = null;
      }
    }
    if (!kind) {
      throw new AttestbookIntegrityError(
        "schema_document_malformed",
        `schema document ${reference.uri} is neither a JSON Schema nor SD-JWT VC Type Metadata`,
      );
    }
    return {
      uri: reference.uri,
      kind,
      contentDigest: sha256Hex(response.bytes),
      base64: Buffer.from(response.bytes).toString("base64"),
    };
  }

  private rulebookPath(): string {
    return `${this.trust.origin}/api/v1/rulebooks/${encodeURIComponent(this.trust.rulebookId)}`;
  }

  private get(
    url: string,
    options: Pick<BoundedGetOptions, "maxBytes" | "accept">,
  ): Promise<BoundedResponse> {
    return boundedGet(url, {
      ...options,
      allowedOrigins: [this.trust.origin],
      timeoutMs: REQUEST_TIMEOUT_MS,
      fetch: this.fetchImpl,
    });
  }

  private async getJson(url: string): Promise<unknown> {
    const response = await this.get(url, {
      maxBytes: API_RESPONSE_MAX_BYTES,
      accept: "application/json",
    });
    try {
      return JSON.parse(Buffer.from(response.bytes).toString("utf8"));
    } catch {
      throw new AttestbookContractError(`${new URL(url).pathname} did not answer JSON`);
    }
  }
}

/** A publication event exactly as documented, or null. */
export function publicationEventOrNull(value: unknown): AttestbookPublicationEvent | null {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    value.id.length === 0 ||
    value.id.length > 256 ||
    /[\r\n]/.test(value.id) ||
    value.format !== "attestbook.rulebook-publication-event@1" ||
    value.type !== "rulebook.published" ||
    typeof value.rulebookId !== "string" ||
    typeof value.version !== "string" ||
    !SAFE_ATTESTBOOK_IDENTIFIER.test(value.version) ||
    typeof value.contentDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.contentDigest) ||
    typeof value.publishedAt !== "string" ||
    Number.isNaN(Date.parse(value.publishedAt))
  ) {
    return null;
  }
  return {
    id: value.id,
    format: value.format,
    type: value.type,
    rulebookId: value.rulebookId,
    version: value.version,
    contentDigest: value.contentDigest,
    publishedAt: value.publishedAt,
  };
}

function parseSchemaReferences(projection: Record<string, unknown>): AttestbookSchemaReference[] {
  if (!Array.isArray(projection.attestations) || !Array.isArray(projection.schemaReferences)) {
    throw new AttestbookContractError("schema references projection is malformed");
  }
  const references: AttestbookSchemaReference[] = [];
  for (const attestation of projection.attestations) {
    if (
      !isRecord(attestation) ||
      typeof attestation.name !== "string" ||
      !Array.isArray(attestation.schemaReferences)
    ) {
      throw new AttestbookContractError("schema references projection is malformed");
    }
    for (const reference of attestation.schemaReferences) {
      references.push(parseSchemaReference(reference, attestation.name));
    }
  }
  for (const reference of projection.schemaReferences) {
    references.push(parseSchemaReference(reference, null));
  }
  return references;
}

function parseSchemaReference(
  value: unknown,
  attestation: string | null,
): AttestbookSchemaReference {
  if (
    !isRecord(value) ||
    typeof value.formatIdentifier !== "string" ||
    typeof value.uri !== "string" ||
    !(value.integrity === null || typeof value.integrity === "string") ||
    !(value.hostedSchema === null || isRecord(value.hostedSchema))
  ) {
    throw new AttestbookContractError("schema reference is malformed");
  }
  const hosted = value.hostedSchema;
  if (hosted === null) {
    return {
      attestation,
      formatIdentifier: value.formatIdentifier,
      uri: value.uri,
      integrity: value.integrity,
      hosted: null,
    };
  }
  if (
    (hosted.kind !== "json_schema_2020_12" && hosted.kind !== "sd_jwt_vc_type_metadata") ||
    typeof hosted.contentDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(hosted.contentDigest) ||
    typeof hosted.integrity !== "string" ||
    hosted.url !== value.uri
  ) {
    throw new AttestbookContractError("hosted schema projection is malformed");
  }
  return {
    attestation,
    formatIdentifier: value.formatIdentifier,
    uri: value.uri,
    integrity: value.integrity,
    hosted: {
      kind: hosted.kind,
      contentDigest: hosted.contentDigest,
      integrity: hosted.integrity,
    },
  };
}
