import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { loadClaimSources, resolveClaimValues } from "../src/attestbook/claims.js";
import { AttestbookClient } from "../src/attestbook/client.js";
import { compileRulebook } from "../src/attestbook/compiler.js";
import { sriMatches } from "../src/attestbook/digest.js";
import { AttestbookFetchError, allowedUrl } from "../src/attestbook/http.js";
import { AttestbookIntegrityError, verifySnapshot } from "../src/attestbook/snapshot.js";
import type { AttestbookSnapshot } from "../src/attestbook/types.js";
import {
  webhookSignature,
  webhookSignatureValid,
  webhookTimestampFresh,
} from "../src/attestbook/webhook.js";
import { DEFAULT_CONFIG, initIssuer } from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { PID_SD_JWT_VCT } from "../src/credential-definitions.js";
import { importedSdJwtCredentialSignOptions } from "../src/credential.js";
import { AttestbookFixture, type FixtureAttestation } from "./attestbook-fixture.js";

const membershipSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  required: ["member_id", "given_name"],
  properties: {
    member_id: { type: "string", minLength: 3, title: "Member number" },
    given_name: { type: "string" },
    tier: { type: "string", enum: ["gold", "silver"] },
    points: { type: "integer", minimum: 0 },
    active: { type: "boolean" },
  },
  additionalProperties: false,
};
const membershipTypeMetadata = {
  vct: "https://credentials.example.test/membership/1",
  display: [{ locale: "en-US", name: "Membership card" }],
  claims: [
    { path: ["member_id"], sd: "always", display: [{ locale: "en-US", name: "Member ID" }] },
    { path: ["active"], sd: "never" },
  ],
};
const membership: FixtureAttestation = {
  name: "Membership Card",
  schema: membershipSchema,
  typeMetadata: membershipTypeMetadata,
};

let fixture: AttestbookFixture;

beforeAll(async () => {
  fixture = new AttestbookFixture();
  await fixture.start();
});

afterAll(async () => {
  await fixture.stop();
});

afterEach(() => {
  fixture.overrides.clear();
});

function client(allowedSchemaOrigins: string[] = []): AttestbookClient {
  return new AttestbookClient({
    origin: fixture.origin,
    rulebookId: fixture.rulebookId,
    allowedSchemaOrigins,
  });
}

function trust(allowedSchemaOrigins: string[] = []) {
  return { origin: fixture.origin, rulebookId: fixture.rulebookId, allowedSchemaOrigins };
}

async function compiled(version: string, attestations: FixtureAttestation[], vctMappings = []) {
  const event = fixture.publish(version, attestations);
  const snapshot = await client().downloadSnapshot(event);
  return compileRulebook(verifySnapshot(snapshot, trust()), vctMappings);
}

describe("Attestbook webhook signatures", () => {
  // Attestbook API §3.15.2 fixed test vector.
  const vector = {
    secret: "atw_vIq7G8hzcwa9GKj68f2X2oYNzSGoDb1D_14l3zDjyT4",
    eventId: "event-vector-1",
    timestamp: "2026-01-01T00:00:00.000Z",
    body: Buffer.from(
      '{"id":"event-vector-1","format":"attestbook.rulebook-publication-event@1","type":"rulebook.published","rulebookId":"rulebook-vector","version":"1.0.1","contentDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","publishedAt":"2026-01-01T00:00:00.000Z"}',
      "utf8",
    ),
    signature: "v1=380592345e511699613ac27b3c6caf870fea8948c21e676652945021de963ed0",
  };

  it("reproduces Attestbook's published test vector", () => {
    expect(webhookSignature(vector.secret, vector.timestamp, vector.eventId, vector.body)).toBe(
      vector.signature,
    );
    expect(webhookSignatureValid({ ...vector })).toBe(true);
  });

  it("rejects a changed body, event id, timestamp, secret or a malformed header", () => {
    expect(
      webhookSignatureValid({ ...vector, body: Buffer.concat([vector.body, Buffer.from(" ")]) }),
    ).toBe(false);
    expect(webhookSignatureValid({ ...vector, eventId: "event-vector-2" })).toBe(false);
    expect(webhookSignatureValid({ ...vector, timestamp: "2026-01-01T00:00:01.000Z" })).toBe(false);
    expect(webhookSignatureValid({ ...vector, secret: `${vector.secret}x` })).toBe(false);
    expect(webhookSignatureValid({ ...vector, signature: vector.signature.toUpperCase() })).toBe(
      false,
    );
  });

  it("accepts only delivery timestamps inside the tolerance window", () => {
    const now = Date.parse("2026-01-01T00:10:00.000Z");
    expect(webhookTimestampFresh("2026-01-01T00:06:00.000Z", now)).toBe(true);
    expect(webhookTimestampFresh("2026-01-01T00:04:00.000Z", now)).toBe(false);
    expect(webhookTimestampFresh("yesterday", now)).toBe(false);
  });
});

describe("Attestbook snapshot client", () => {
  it("produces an integrity-verified snapshot of a published version with its hosted schemas", async () => {
    const event = fixture.publish("1.0", [membership]);
    const snapshot = await client().downloadSnapshot(event);

    expect(snapshot).toMatchObject({
      origin: fixture.origin,
      rulebookId: fixture.rulebookId,
      version: "1.0",
      contentDigest: event.contentDigest,
      eventId: event.id,
    });
    expect(snapshot.schemaDocuments.map((document) => document.kind).sort()).toEqual([
      "json_schema_2020_12",
      "sd_jwt_vc_type_metadata",
    ]);
    expect(
      createHash("sha256").update(Buffer.from(snapshot.rulebookBase64, "base64")).digest("hex"),
    ).toBe(event.contentDigest);
    expect((await client().publicationEvents()).at(-1)).toEqual(event);
  });

  it("rejects a modified rulebook export", async () => {
    const event = fixture.publish("1.1", [membership]);
    fixture.overrides.set(
      fixture.exportPath("1.1"),
      Buffer.from(Buffer.from(JSON.stringify({ tampered: true })).toString("utf8"), "utf8"),
    );

    await expect(client().downloadSnapshot(event)).rejects.toMatchObject({
      code: "rulebook_digest_mismatch",
    });
  });

  it("rejects a modified hosted schema document", async () => {
    const event = fixture.publish("1.2", [membership]);
    for (const path of fixture.documentPaths()) {
      fixture.overrides.set(
        path,
        Buffer.from(JSON.stringify({ ...membershipSchema, title: "changed" })),
      );
    }

    await expect(client().downloadSnapshot(event)).rejects.toBeInstanceOf(AttestbookIntegrityError);
  });

  it("re-verifies a persisted snapshot and rejects one whose bytes were altered", async () => {
    const snapshot = await client().downloadSnapshot(fixture.publish("1.3", [membership]));
    const altered: AttestbookSnapshot = {
      ...snapshot,
      schemaDocuments: snapshot.schemaDocuments.map((document, index) =>
        index === 0
          ? { ...document, base64: Buffer.from('{"type":"object"}').toString("base64") }
          : document,
      ),
    };

    expect(verifySnapshot(snapshot, trust()).document.version).toBe("1.3");
    expect(() => verifySnapshot(altered, trust())).toThrow(AttestbookIntegrityError);
    expect(() => verifySnapshot(snapshot, { ...trust(), rulebookId: "other" })).toThrow(
      /does not belong/,
    );
  });

  it("never fetches an external schema origin that is not explicitly allowed", async () => {
    const event = fixture.publish("1.4", [
      {
        name: "External",
        externalReferences: [
          {
            formatIdentifier: "dc+sd-jwt",
            uri: "https://schemas.example.test/a.json",
            integrity: "sha256-AAAA",
          },
        ],
      },
    ]);
    const before = fixture.requests.length;

    await expect(client().downloadSnapshot(event)).rejects.toMatchObject({
      code: "url_not_allowed",
    });
    expect(
      fixture.requests.slice(before).some((entry) => entry.includes("schemas.example.test")),
    ).toBe(false);
  });

  it("refuses URLs with credentials, plain HTTP outside loopback, or an untrusted origin", () => {
    expect(() =>
      allowedUrl("https://user:pw@a.example.test/x", ["https://a.example.test"]),
    ).toThrow(AttestbookFetchError);
    expect(() => allowedUrl("http://a.example.test/x", ["http://a.example.test"])).toThrow(/https/);
    expect(() => allowedUrl("https://b.example.test/x", ["https://a.example.test"])).toThrow(
      /not trusted/,
    );
  });

  it("checks W3C SRI pins against the strongest listed algorithm", () => {
    const bytes = Buffer.from("schema");
    const sha256 = `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
    const sha384 = `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
    expect(sriMatches(sha256, bytes)).toBe(true);
    expect(
      sriMatches(
        `${sha256} sha384-${createHash("sha384").update("other").digest("base64")}`,
        bytes,
      ),
    ).toBe(false);
    expect(sriMatches(`${sha384} sha256-AAAA`, bytes)).toBe(true);
    expect(sriMatches("md5-AAAA", bytes)).toBe(false);
  });
});

describe("Attestbook rulebook compiler", () => {
  it("compiles a valid attestation type into a complete credential definition", async () => {
    const result = await compiled("2.0", [membership]);

    expect(result.diagnostics.filter((diagnostic) => diagnostic.severity === "error")).toEqual([]);
    expect(result.definitions).toHaveLength(1);
    const [definition] = result.definitions;
    expect(definition).toMatchObject({
      origin: fixture.origin,
      rulebookId: fixture.rulebookId,
      version: "2.0",
      attestation: { name: "Membership Card", index: 0, bindingType: "key" },
      format: "dc+sd-jwt",
      vct: membershipTypeMetadata.vct,
      vctSource: "type_metadata",
      displayName: "Membership card",
      proofPolicy: "jwt-proof",
      claimValueProvider: "local-fixtures",
    });
    expect(definition?.credentialConfigurationId).toMatch(
      new RegExp(`^urn:attestbook:${fixture.rulebookId}:2\\.0:membership-card-[0-9a-f]{12}$`),
    );
    expect(definition?.scope).toBe(definition?.credentialConfigurationId);
    expect(definition?.claims).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "member_id",
          type: "string",
          required: true,
          selectivelyDisclosable: true,
          displayName: "Member ID",
          minLength: 3,
        }),
        expect.objectContaining({ name: "active", type: "boolean", selectivelyDisclosable: false }),
        expect.objectContaining({ name: "tier", required: false, enum: ["gold", "silver"] }),
      ]),
    );
    expect(definition?.schemaReferences).toHaveLength(2);
  });

  it("derives version-specific, deterministic configuration ids", async () => {
    const first = await compiled("2.1", [membership]);
    const second = await compiled("2.2", [membership]);

    expect(first.definitions[0]?.credentialConfigurationId).not.toBe(
      second.definitions[0]?.credentialConfigurationId,
    );
    expect(first.definitions[0]?.credentialConfigurationId).toContain(":2.1:");
  });

  it("reports unsupported constructs with the attestation and field they concern", async () => {
    const result = await compiled("3.0", [
      {
        name: "Nested",
        schema: {
          type: "object",
          properties: {
            address: { type: "object", properties: { city: { type: "string" } } },
            birthdate: { type: "string", format: "date" },
            vct: { type: "string" },
          },
        },
        typeMetadata: { vct: "https://credentials.example.test/nested/1" },
      },
      {
        name: "Unbound",
        bindingType: "none",
        schema: membershipSchema,
        typeMetadata: { vct: "urn:x:unbound" },
      },
      { name: "Untyped", schema: membershipSchema },
      { name: "Impersonating", schema: membershipSchema, typeMetadata: { vct: PID_SD_JWT_VCT } },
      { name: "Mdoc only", supportedFormats: ["mso_mdoc"] },
    ]);

    expect(result.definitions).toEqual([]);
    const findings = result.diagnostics.map(({ severity, code, attestation }) => ({
      severity,
      code,
      attestation,
    }));
    expect(findings).toEqual(
      expect.arrayContaining([
        { severity: "error", code: "unsupported_nested_claim", attestation: "Nested" },
        { severity: "error", code: "unsupported_schema_keyword", attestation: "Nested" },
        { severity: "error", code: "reserved_claim_name", attestation: "Nested" },
        { severity: "error", code: "unsupported_binding_type", attestation: "Unbound" },
        { severity: "error", code: "vct_unresolved", attestation: "Untyped" },
        { severity: "error", code: "vct_reserved", attestation: "Impersonating" },
        { severity: "info", code: "attestation_format_not_supported", attestation: "Mdoc only" },
      ]),
    );
    expect(
      result.diagnostics.find((diagnostic) => diagnostic.code === "unsupported_nested_claim")
        ?.field,
    ).toMatch(/#\/properties\/address$/);
  });

  it("resolves the vct from an explicit issuer-owned mapping when there is no Type Metadata", async () => {
    const result = await compiled("3.1", [{ name: "Mapped", schema: membershipSchema }], [
      {
        rulebookId: fixture.rulebookId,
        attestation: "Mapped",
        vct: "https://credentials.example.test/mapped/1",
      },
    ] as never);

    expect(result.definitions[0]).toMatchObject({
      vct: "https://credentials.example.test/mapped/1",
      vctSource: "issuer_mapping",
    });
  });
});

describe("generic SD-JWT VC signing options and claim fixtures", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "attestbook-signer-"));
  const config = {
    ...DEFAULT_CONFIG,
    data_dir: dataDir,
    attestbook: { ...DEFAULT_CONFIG.attestbook, enabled: true },
  };

  afterAll(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("keeps protocol-controlled members out of reach of claim data", async () => {
    await initIssuer({ data_dir: dataDir, force: true });
    const issuer = resolvedIssuerConfigurationById(config, "attestbook-experimental");
    if (!issuer) throw new Error("experimental issuer unavailable");
    const [definition] = (await compiled("4.0", [membership])).definitions;
    if (!definition) throw new Error("definition missing");
    const holderJwk = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };

    const options = importedSdJwtCredentialSignOptions({
      config: issuerAppConfig(config, issuer),
      holderJwk,
      definition,
      claims: { member_id: "M-001", given_name: "Ada", active: true },
    });
    expect(options.payload).toMatchObject({ vct: definition.vct, member_id: "M-001" });
    expect(options.disclosureFrame?._sd).toEqual(["member_id", "given_name"]);

    expect(() =>
      importedSdJwtCredentialSignOptions({
        config: issuerAppConfig(config, issuer),
        holderJwk,
        definition,
        claims: { member_id: "M-001", given_name: "Ada", vct: "urn:forged" },
      }),
    ).toThrow(/not issuable/);
  });

  it("validates fixture values against the compiled claims and names what is missing", async () => {
    const [definition] = (await compiled("4.1", [membership])).definitions;
    if (!definition) throw new Error("definition missing");
    const claimsFile = join(dataDir, "claims.json");
    writeFileSync(
      claimsFile,
      JSON.stringify({
        fixtures: { membership: { member_id: "M-001", given_name: "Ada", tier: "bronze" } },
      }),
    );
    const sources = loadClaimSources(claimsFile);

    expect(resolveClaimValues(definition, sources.fixtures.get("issuer_test_data") ?? {})).toEqual({
      ok: false,
      missing: ["member_id"],
      invalid: [],
    });
    expect(resolveClaimValues(definition, sources.fixtures.get("membership") ?? {})).toEqual({
      ok: false,
      missing: [],
      invalid: [{ claim: "tier", reason: "is not one of the schema enum values" }],
    });
    writeFileSync(claimsFile, JSON.stringify({ fixtures: { issuer_test_data: {} } }));
    expect(() => loadClaimSources(claimsFile)).toThrow(/reserved/);
  });
});
