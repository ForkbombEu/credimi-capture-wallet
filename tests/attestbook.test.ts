import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SdJwtVcService } from "@credo-ts/core";
import { exportJWK, generateKeyPair } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { AttestbookClient } from "../src/attestbook/client.js";
import { compileRulebook, vctForAttestationName } from "../src/attestbook/compiler.js";
import { sriMatches } from "../src/attestbook/digest.js";
import { ClaimGenerationError, generateClaims } from "../src/attestbook/generator.js";
import { AttestbookFetchError, allowedUrl } from "../src/attestbook/http.js";
import { claimValueErrors } from "../src/attestbook/json-schema.js";
import { AttestbookIntegrityError, verifySnapshot } from "../src/attestbook/snapshot.js";
import type {
  AttestbookCredentialDefinition,
  AttestbookSnapshot,
} from "../src/attestbook/types.js";
import {
  webhookSignature,
  webhookSignatureValid,
  webhookTimestampFresh,
} from "../src/attestbook/webhook.js";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { createIssuerSigningContext, initIssuer } from "../src/config/key-material.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { importedSdJwtCredentialSignOptions } from "../src/credentials/signing.js";
import type { JsonRecord } from "../src/types.js";
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
  vct: "urn:attestbook:membership-card",
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
const nestedSchema = {
  type: "object",
  required: ["holder", "degrees"],
  properties: {
    holder: {
      type: "object",
      required: ["given_name", "family_name"],
      properties: {
        given_name: { type: "string" },
        family_name: { type: "string" },
        email: { type: "string" },
        address: {
          type: "object",
          properties: { locality: { type: "string" }, country: { type: "string" } },
        },
      },
    },
    degrees: {
      type: "array",
      minItems: 2,
      maxItems: 4,
      items: {
        type: "object",
        required: ["level"],
        properties: {
          level: { type: "string", enum: ["bachelor", "master", "doctorate"] },
          year: { type: "integer", minimum: 1990, maximum: 2026 },
        },
      },
    },
    languages: { type: "array", items: { type: "string", enum: ["en", "it", "de"] } },
  },
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

async function compiled(version: string, attestations: FixtureAttestation[]) {
  const event = fixture.publish(version, attestations);
  const snapshot = await client().downloadSnapshot(event);
  return compileRulebook(verifySnapshot(snapshot, trust()), "key-attestation-required");
}

async function definitionOf(version: string, attestation: FixtureAttestation) {
  const result = await compiled(version, [attestation]);
  const [definition] = result.definitions;
  if (!definition) throw new Error(JSON.stringify(result.diagnostics));
  return definition;
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
      vct: "urn:attestbook:membership-card",
      vctSource: "attestation_name",
      displayName: "Membership card",
      proofPolicy: "key-attestation-required",
      claimValueProvider: "faker-js",
    });
    expect(definition?.credentialConfigurationId).toBe("urn:attestbook:membership-card");
    expect(definition?.scope).toBe("urn:attestbook:membership-card");
    const properties = definition?.claims.properties ?? [];
    expect(properties.find((property) => property.name === "member_id")).toMatchObject({
      required: true,
      node: {
        kind: "scalar",
        types: ["string"],
        minLength: 3,
        displayName: "Member ID",
        selectivelyDisclosable: true,
      },
    });
    expect(properties.find((property) => property.name === "active")?.node).toMatchObject({
      selectivelyDisclosable: false,
    });
    expect(definition?.claimMetadata).toContainEqual({
      path: ["tier"],
      mandatory: false,
      displayName: null,
    });
    expect(definition?.schemaReferences).toHaveLength(2);
  });

  it("derives the vct from the attestation name alone, without Type Metadata", async () => {
    const result = await compiled("2.1", [
      { name: "Ünïversity Diploma (EU)", schema: membershipSchema },
    ]);

    expect(result.definitions[0]).toMatchObject({
      vct: "urn:attestbook:university-diploma-eu",
      vctSource: "attestation_name",
      displayName: "Ünïversity Diploma (EU)",
    });
    expect(vctForAttestationName("  --  ")).toBeNull();
  });

  it("takes a vct the JSON Schema pins, keeping the name-derived configuration id", async () => {
    const definition = await definitionOf("2.5", {
      name: "Italian PID",
      schema: {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        required: ["vct", "issuing_country"],
        properties: {
          // As in the IT-Wallet PID schema: no `type`, the `const` fixes the value.
          vct: { const: "urn:eudi:pid:it:1" },
          issuing_country: { const: "IT" },
          issuing_authority: { type: ["string", "null"], minLength: 1 },
          place_of_birth: {
            type: "object",
            properties: { country: { type: "string" }, locality: { type: "string" } },
            minProperties: 1,
          },
        },
        additionalProperties: false,
      },
      typeMetadata: { vct: "urn:eudi:pid:it:1" },
    });

    expect(definition).toMatchObject({
      vct: "urn:eudi:pid:it:1",
      vctSource: "json_schema",
      credentialConfigurationId: "urn:attestbook:italian-pid",
      scope: "urn:attestbook:italian-pid",
    });
    expect(definition.claimMetadata.map((claim) => claim.path)).not.toContainEqual(["vct"]);
    const claims = generateClaims(definition, "pid-seed");
    expect(claims).not.toHaveProperty("vct");
    expect(claims.issuing_country).toBe("IT");
    expect(claims.issuing_authority).toEqual(expect.any(String));
    expect(claimValueErrors(definition.claims, claims)).toEqual([]);
  });

  it("keeps the vct, configuration id and scope identical across versions", async () => {
    const first = await compiled("2.2", [membership]);
    const second = await compiled("2.3", [membership]);

    expect(second.definitions[0]).toMatchObject({
      vct: first.definitions[0]?.vct,
      credentialConfigurationId: first.definitions[0]?.credentialConfigurationId,
      scope: first.definitions[0]?.scope,
      version: "2.3",
    });
    expect(second.definitions[0]?.contentDigest).not.toBe(first.definitions[0]?.contentDigest);
  });

  it("compiles nested objects and arrays into claim metadata with null array paths", async () => {
    const definition = await definitionOf("2.4", {
      name: "Diploma",
      schema: nestedSchema,
      typeMetadata: {
        vct: "urn:attestbook:diploma",
        claims: [
          { path: ["degrees", null, "level"], sd: "never" },
          { path: ["languages", null], sd: "never" },
          { path: ["holder", "email"], mandatory: true },
        ],
      },
    });

    expect(definition.claimMetadata).toEqual(
      expect.arrayContaining([
        { path: ["holder"], mandatory: true, displayName: null },
        { path: ["holder", "given_name"], mandatory: true, displayName: null },
        { path: ["holder", "email"], mandatory: true, displayName: null },
        { path: ["holder", "address", "locality"], mandatory: false, displayName: null },
        { path: ["degrees", null, "level"], mandatory: true, displayName: null },
        { path: ["degrees", null, "year"], mandatory: false, displayName: null },
        { path: ["languages"], mandatory: false, displayName: null },
      ]),
    );
    const degrees = definition.claims.properties.find(
      (property) => property.name === "degrees",
    )?.node;
    expect(degrees).toMatchObject({
      kind: "array",
      minItems: 2,
      items: {
        kind: "object",
        properties: [{ name: "level", node: { selectivelyDisclosable: false } }, expect.anything()],
      },
    });
  });

  it("reports unsupported constructs with the attestation and field they concern", async () => {
    const tooDeep = {
      type: "object",
      properties: {
        c: {
          type: "object",
          properties: { d: { type: "object", properties: { e: { type: "string" } } } },
        },
      },
    };
    const result = await compiled("3.0", [
      {
        name: "Unsupported",
        schema: {
          type: "object",
          properties: {
            birthdate: { type: "string", format: "date" },
            tuple: { type: "array", items: [{ type: "string" }] },
            iss: { type: "string" },
            nested: { type: "object", properties: { _sd: { type: "string" } } },
            a: { type: "object", properties: { b: tooDeep } },
          },
        },
      },
      { name: "Unbound", bindingType: "none", schema: membershipSchema },
      { name: "Conflicting", schema: membershipSchema, typeMetadata: { vct: "urn:eudi:pid:1" } },
      {
        name: "Schema Conflict",
        schema: {
          type: "object",
          properties: { vct: { type: "string", const: "urn:example:a" }, x: { type: "string" } },
        },
        typeMetadata: { vct: "urn:example:b" },
      },
      {
        name: "Unknown Path",
        schema: membershipSchema,
        typeMetadata: {
          vct: "urn:attestbook:unknown-path",
          claims: [{ path: ["address", "city"] }],
        },
      },
      { name: "!!!", schema: membershipSchema },
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
        { severity: "error", code: "unsupported_schema_keyword", attestation: "Unsupported" },
        { severity: "error", code: "unsupported_claim_schema", attestation: "Unsupported" },
        { severity: "error", code: "reserved_claim_name", attestation: "Unsupported" },
        { severity: "error", code: "claim_too_deep", attestation: "Unsupported" },
        { severity: "error", code: "unsupported_binding_type", attestation: "Unbound" },
        { severity: "error", code: "vct_conflict", attestation: "Conflicting" },
        { severity: "error", code: "vct_conflict", attestation: "Schema Conflict" },
        {
          severity: "error",
          code: "type_metadata_claim_not_in_schema",
          attestation: "Unknown Path",
        },
        { severity: "error", code: "vct_unresolved", attestation: "!!!" },
        { severity: "info", code: "attestation_format_not_supported", attestation: "Mdoc only" },
      ]),
    );
    expect(
      result.diagnostics
        .filter((diagnostic) => diagnostic.code === "reserved_claim_name")
        .map((d) => d.field),
    ).toEqual([
      expect.stringMatching(/#\/properties\/iss$/),
      expect.stringMatching(/#\/properties\/nested\/properties\/_sd$/),
    ]);
  });

  it("rejects two attestation types whose names derive the same vct", async () => {
    const result = await compiled("3.1", [
      { name: "Membership Card", schema: membershipSchema },
      { name: "membership-card", schema: membershipSchema },
    ]);

    expect(result.definitions).toEqual([]);
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: "duplicate_vct", attestation: "membership-card" }),
    );
  });
});

describe("generated claim values", () => {
  it("generates values reproducibly from a seed, within every schema constraint", async () => {
    const definition = await definitionOf("4.0", { name: "Diploma", schema: nestedSchema });

    const first = generateClaims(definition, "session-a");
    expect(generateClaims(definition, "session-a")).toEqual(first);
    expect(generateClaims(definition, "session-b")).not.toEqual(first);
    expect(claimValueErrors(definition.claims, first)).toEqual([]);
    expect(first.holder).toMatchObject({
      given_name: expect.any(String),
      family_name: expect.any(String),
      email: expect.stringContaining("@"),
    });
    const degrees = first.degrees as JsonRecord[];
    expect(degrees.length).toBeGreaterThanOrEqual(2);
    expect(degrees.length).toBeLessThanOrEqual(4);
    for (const degree of degrees) {
      expect(["bachelor", "master", "doctorate"]).toContain(degree.level);
      expect(degree.year).toBeGreaterThanOrEqual(1990);
      expect(degree.year).toBeLessThanOrEqual(2026);
    }
  });

  it("chooses enum members at random across seeds", async () => {
    const definition = await definitionOf("4.1", membership);
    const tiers = new Set(
      Array.from({ length: 40 }, (_, index) => generateClaims(definition, `seed-${index}`).tier),
    );

    expect(tiers).toEqual(new Set(["gold", "silver"]));
  });

  it("refuses constraints no value can satisfy", async () => {
    const definition = await definitionOf("4.2", {
      name: "Impossible",
      schema: {
        type: "object",
        properties: { code: { type: "string", minLength: 5, maxLength: 2 } },
      },
    });

    expect(() => generateClaims(definition, "seed")).toThrow(ClaimGenerationError);
  });
});

describe("generic SD-JWT VC signing options", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "attestbook-signer-"));
  const config = {
    ...DEFAULT_CONFIG,
    data_dir: dataDir,
    attestbook: { ...DEFAULT_CONFIG.attestbook, enabled: true },
  };

  afterAll(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  async function sign(definition: AttestbookCredentialDefinition, claims: JsonRecord) {
    await initIssuer({ data_dir: dataDir });
    const issuer = resolvedIssuerConfigurationById(config, "attestbook-experimental");
    if (!issuer) throw new Error("experimental issuer unavailable");
    const { publicKey } = await generateKeyPair("ES256");
    const signingConfig = issuerAppConfig(config, issuer);
    const options = importedSdJwtCredentialSignOptions({
      config: signingConfig,
      holderJwk: (await exportJWK(publicKey)) as unknown as JsonRecord,
      definition,
      claims,
    });
    const signed = await new SdJwtVcService({} as never).sign(
      createIssuerSigningContext(signingConfig) as never,
      options,
    );
    return { options, compact: signed.compact };
  }

  it("keeps protocol-controlled members out of reach of claim data", async () => {
    const definition = await definitionOf("5.0", membership);

    const { options } = await sign(definition, {
      member_id: "M-001",
      given_name: "Ada",
      active: true,
    });
    expect(options.payload).toMatchObject({ vct: definition.vct, member_id: "M-001" });
    expect(options.disclosureFrame?._sd).toEqual(["member_id", "given_name"]);
    await expect(
      sign(definition, { member_id: "M-001", given_name: "Ada", vct: "urn:forged" }),
    ).rejects.toThrow(/not a declared claim/);
  });

  it("discloses nested members and array elements individually", async () => {
    const definition = await definitionOf("5.1", {
      name: "Diploma",
      schema: nestedSchema,
      typeMetadata: {
        vct: "urn:attestbook:diploma",
        claims: [{ path: ["languages", null], sd: "never" }],
      },
    });
    const claims = generateClaims(definition, "nested-seed");

    const { compact } = await sign(definition, claims);
    const decoded = new SdJwtVcService({} as never).fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject(claims);
    const disclosures = compact
      .split("~")
      .slice(1)
      .filter(Boolean)
      .map(
        (disclosure) =>
          JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[],
      );
    const named = disclosures
      .filter((disclosure) => disclosure.length === 3)
      .map((disclosure) => disclosure[1]);
    expect(named).toEqual(
      expect.arrayContaining(["holder", "given_name", "family_name", "degrees", "level"]),
    );
    const elements = disclosures.filter((disclosure) => disclosure.length === 2);
    expect(elements).toHaveLength((claims.degrees as unknown[]).length);
    expect(named).toContain("languages");
  });
});
