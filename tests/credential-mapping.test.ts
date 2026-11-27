import type {
  OpenId4VciCredentialRequestToCredentialMapperOptions,
  OpenId4VciSignCredentials,
} from "@credo-ts/openid4vc";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { AttestbookCredentialDefinition } from "../src/attestbook/types.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { PID_FIXTURE_IDS } from "../src/configurations/shared/pid-fixtures.js";
import type { ResolvedIssuerConfiguration } from "../src/configurations/types.js";
import {
  degreeSdJwtCredentialConfigurationId,
  domesticPidCredentialConfigurationId,
  mdocCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import { DOMESTIC_PID_MDOC_NAMESPACE } from "../src/credentials/definitions.js";
import { credentialRegistry } from "../src/credentials/registry.js";
import {
  allocateStatusListReferences,
  recordCredentialRequestEvidence,
  signingOptionsForCredential,
} from "../src/openid4vci/credential-mapping.js";
import { CredoOpenId4VciIssuer } from "../src/openid4vci/credo-issuer.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { createIssuerTestEnvironment, issuerPath, requireIssuer } from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import { credentialNonce, credentialProofJwt, preAuthorizedToken } from "./support/issuance.js";
import { dpopProof, generateEs256Key } from "./support/keys.js";

const holderA = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};
const holderB = {
  kty: "EC",
  crv: "P-256",
  x: "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
  y: "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
};
const proofJwt = `${Buffer.from(
  JSON.stringify({ alg: "ES256", typ: "openid4vci-proof+jwt", x5c: ["MIIB"] }),
).toString("base64url")}.${Buffer.from(JSON.stringify({ nonce: "n" })).toString("base64url")}.sig`;
const importedDefinition = {
  origin: "https://attestbook.example.test",
  rulebookId: "rulebook",
  version: "1",
  contentDigest: "a".repeat(64),
  attestation: {
    name: "Membership Card",
    index: 0,
    attestationLoS: "basic",
    bindingType: "holder-bound",
  },
  credentialConfigurationId: "urn:example:membership-card",
  scope: "membership_card",
  format: "dc+sd-jwt",
  vct: "urn:example:membership-card",
  vctSource: "attestation_name",
  displayName: "Membership Card",
  claims: {
    kind: "object",
    displayName: null,
    selectivelyDisclosable: true,
    additionalProperties: false,
    properties: [
      {
        name: "member_id",
        required: true,
        node: {
          kind: "scalar",
          types: ["string"],
          displayName: null,
          selectivelyDisclosable: true,
        },
      },
      {
        name: "active",
        required: true,
        node: {
          kind: "scalar",
          types: ["boolean"],
          displayName: null,
          selectivelyDisclosable: false,
        },
      },
    ],
  },
  claimMetadata: [],
  schemaReferences: [],
  proofPolicy: "key-attestation-required",
  claimValueProvider: "faker-js",
  disclosurePolicy: "issuer-default-selective",
} as unknown as AttestbookCredentialDefinition;

let environment: IssuerTestEnvironment;
let config: IssuerTestEnvironment["config"];
let issuer!: ResolvedIssuerConfiguration;
let signingConfig!: IssuerTestEnvironment["config"];

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "credential-mapping-" });
  config = {
    ...environment.config,
    attestbook: { ...environment.config.attestbook, enabled: true },
  };
  issuer = requireIssuer(config, "eu-pid-device-bound");
  signingConfig = issuerAppConfig(config, issuer);
});

afterEach(() => vi.unstubAllGlobals());
afterAll(() => environment?.cleanup());

function sessionFor(
  store: CaptureStore,
  credentialId: string,
  options: { statusListEnabled?: boolean; issuerId?: string } = {},
): SessionCapture {
  const sessionIssuer = requireIssuer(config, options.issuerId ?? issuer.id);
  return store.createSession(sessionIssuer, {
    credentialConfigurationId: credentialId,
    flow: "pre_authorized_code",
    credentialOfferMode: "credential_offer",
    statusListEnabled: options.statusListEnabled ?? false,
  });
}

function credential(store: CaptureStore, id: string) {
  const result = credentialRegistry(config, store).credentialById(issuer, id);
  if (!result) throw new Error(`credential missing: ${id}`);
  return result;
}

function holderBinding(jwks: JsonRecord[]) {
  return jwks.map((jwk) => ({ method: "jwk", jwk: { toJson: () => jwk } }));
}

function signingOptions(
  store: CaptureStore,
  id: string,
  session: SessionCapture,
  holderJwks: JsonRecord[] = [holderA],
) {
  return signingOptionsForCredential({
    signingConfig,
    credential: credential(store, id),
    captureSession: session,
    holderJwks,
    statusListReferences: holderJwks.map(() => undefined),
  });
}

function sdJwtPayload(result: OpenId4VciSignCredentials): JsonRecord {
  const first = result.credentials[0];
  if (!first || !("payload" in first)) throw new Error("SD-JWT sign options missing payload");
  return first.payload as JsonRecord;
}
function statusInfo(value: unknown): unknown {
  if (value && typeof value === "object" && "statusInfo" in value) return value.statusInfo;
  return undefined;
}
function mdocNamespaces(value: unknown): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    !("namespaces" in value) ||
    !value.namespaces ||
    typeof value.namespaces !== "object"
  ) {
    throw new Error("mdoc sign options missing namespaces");
  }
  return value.namespaces as Record<string, unknown>;
}

const staticConfigurations = [
  {
    name: "PID SD-JWT",
    id: () => sdJwtCredentialConfigurationId(config, "key-attestation-required"),
    assert: (result: OpenId4VciSignCredentials) =>
      expect(sdJwtPayload(result)).toMatchObject({ vct: "urn:eudi:pid:1" }),
  },
  {
    name: "degree",
    id: () => degreeSdJwtCredentialConfigurationId(config, "key-attestation-required"),
    assert: (result: OpenId4VciSignCredentials) =>
      expect(sdJwtPayload(result)).toMatchObject({ vct: "urn:credimi:degree:1" }),
  },
  {
    name: "numeric",
    id: () => numericSdJwtCredentialConfigurationId(config, "key-attestation-required"),
    assert: (result: OpenId4VciSignCredentials) =>
      expect(sdJwtPayload(result)).toMatchObject({ vct: "urn:credimi:numeric-claims:1" }),
  },
  {
    name: "domestic SD-JWT",
    id: () => domesticPidCredentialConfigurationId("dc+sd-jwt", "key-attestation-required"),
    assert: (result: OpenId4VciSignCredentials) =>
      expect(sdJwtPayload(result)).toMatchObject({
        vct: "urn:eudi:pid:xx:1",
        credimi_domestic_claim: "credimi-domestic-value",
      }),
  },
  {
    name: "mdoc",
    id: () => mdocCredentialConfigurationId(config, "key-attestation-required"),
    assert: (result: OpenId4VciSignCredentials) => {
      expect(result.credentials[0]).toMatchObject({ docType: "eu.europa.ec.eudi.pid.1" });
      expect(Object.keys(mdocNamespaces(result.credentials[0]))).not.toContain(
        DOMESTIC_PID_MDOC_NAMESPACE,
      );
    },
  },
  {
    name: "domestic mdoc",
    id: () => domesticPidCredentialConfigurationId("mso_mdoc", "key-attestation-required"),
    assert: (result: OpenId4VciSignCredentials) =>
      expect(result.credentials[0]).toMatchObject({
        docType: "eu.europa.ec.eudi.pid.1",
        namespaces: {
          [DOMESTIC_PID_MDOC_NAMESPACE]: { credimi_domestic_claim: "credimi-domestic-value" },
        },
      }),
  },
] as const;

describe("credential mapping builders", () => {
  it.each(staticConfigurations)("dispatches $name", ({ id, assert }) => {
    const store = new CaptureStore(config);
    const credentialId = id();
    const session = sessionFor(store, credentialId);
    assert(signingOptions(store, credentialId, session));
  });
  it("preserves fixture, document number, and status reference options", () => {
    const store = new CaptureStore(config);
    const pidId = sdJwtCredentialConfigurationId(config, "key-attestation-required");
    const pidSession = sessionFor(store, pidId);
    pidSession.fixture_id = PID_FIXTURE_IDS.find((id) => id === "pid_person_b");
    pidSession.document_number = "DOC-OVERRIDE";
    const pidPayload = sdJwtPayload(signingOptions(store, pidId, pidSession));
    expect(pidPayload).toMatchObject({ family_name: "Bianchi", document_number: "DOC-OVERRIDE" });

    const sdStatusSession = sessionFor(store, pidId);
    sdStatusSession.status_reference = "negative_index";
    const sdStatusResult = signingOptionsForCredential({
      signingConfig,
      credential: credential(store, pidId),
      captureSession: sdStatusSession,
      holderJwks: [holderA],
      statusListReferences: [{ uri: "https://status.example.test/1", idx: 4 }],
    });
    expect(sdJwtPayload(sdStatusResult).status).toEqual({
      status_list: { uri: "https://status.example.test/1", idx: -1 },
    });

    const mdocId = mdocCredentialConfigurationId(config, "key-attestation-required");
    const mdocSession = sessionFor(store, mdocId);
    mdocSession.status_reference = "negative_index";
    const mdocResult = signingOptionsForCredential({
      signingConfig,
      credential: credential(store, mdocId),
      captureSession: mdocSession,
      holderJwks: [holderA],
      statusListReferences: [{ uri: "https://status.example.test/1", idx: 4 }],
    });
    expect(statusInfo(mdocResult.credentials[0])).toEqual({
      index: 4,
      uri: "https://status.example.test/1",
    });
    expect(mdocResult.credentials[0]).toHaveProperty("statusReference", "negative_index");
  });

  it("dispatches imported credentials and passes digest algorithm", async () => {
    const importedConfig = {
      ...config,
      attestbook: { ...config.attestbook, enabled: true },
    };
    const store = new CaptureStore(importedConfig);
    await credentialRegistry(importedConfig, store).activate({
      issuerId: "attestbook-experimental",
      origin: importedDefinition.origin,
      rulebookId: importedDefinition.rulebookId,
      version: importedDefinition.version,
      contentDigest: importedDefinition.contentDigest,
      publishedAt: null,
      eventId: null,
      activatedAt: "2026-11-24T00:00:00.000Z",
      definitions: [importedDefinition],
    });
    const importedIssuer = requireIssuer(importedConfig, "attestbook-experimental");
    const importedSigningConfig = issuerAppConfig(importedConfig, importedIssuer);
    const session = sessionFor(store, importedDefinition.credentialConfigurationId, {
      issuerId: importedIssuer.id,
    });
    session.credential_definition = {
      source: "attestbook",
      origin: importedDefinition.origin,
      rulebook_id: importedDefinition.rulebookId,
      version: importedDefinition.version,
      content_digest: importedDefinition.contentDigest,
      attestation: importedDefinition.attestation.name,
      vct: importedDefinition.vct,
      vct_source: "attestation_name",
    };
    session.generated_claims = {
      generator: "test",
      seed: session.session_id,
      reference_date: "2026-01-01",
      claims: { member_id: "M-1", active: true },
    };
    session.digest_algorithm = "sha-512";
    const importedCredential = credentialRegistry(importedConfig, store).credentialById(
      importedIssuer,
      importedDefinition.credentialConfigurationId,
    );
    if (!importedCredential) {
      throw new Error("imported credential configuration missing");
    }
    const result = signingOptionsForCredential({
      signingConfig: importedSigningConfig,
      credential: importedCredential,
      captureSession: session,
      holderJwks: [holderA],
      statusListReferences: [undefined],
    });
    expect(sdJwtPayload(result)).toMatchObject({
      vct: importedDefinition.vct,
      member_id: "M-1",
    });
    expect(result.credentials[0]).toHaveProperty("hashingAlgorithm", "sha-512");
  });

  it.each([
    [
      "superseded",
      "Capture session was created under a superseded credential definition",
      (session: SessionCapture) => {
        session.credential_definition = {
          content_digest: "b".repeat(64),
        } as SessionCapture["credential_definition"];
        session.generated_claims = {
          claims: {},
          generator: "test",
          seed: "s",
          reference_date: "2026-01-01",
        };
      },
    ],
    [
      "missing generated claims",
      "Capture session has no generated claims",
      (session: SessionCapture) => {
        session.credential_definition = {
          source: "attestbook",
          origin: importedDefinition.origin,
          rulebook_id: importedDefinition.rulebookId,
          version: importedDefinition.version,
          content_digest: importedDefinition.contentDigest,
          attestation: importedDefinition.attestation.name,
          vct: importedDefinition.vct,
          vct_source: "attestation_name",
        };
      },
    ],
  ] as const)("retains the exact imported guard: %s", (_name, message, mutate) => {
    const store = new CaptureStore(config);
    const session = sessionFor(
      store,
      sdJwtCredentialConfigurationId(config, "key-attestation-required"),
    );
    const imported = {
      ...credential(store, session.credential_configuration_id),
      attestbook: importedDefinition,
    };
    mutate(session);
    expect(() =>
      signingOptionsForCredential({
        signingConfig,
        credential: imported,
        captureSession: session,
        holderJwks: [holderA],
        statusListReferences: [undefined],
      }),
    ).toThrow(message);
  });
});

describe("credential mapping evidence and allocation", () => {
  it("records raw evidence and proof header fields including x5c", () => {
    const store = new CaptureStore(config);
    const session = sessionFor(
      store,
      sdJwtCredentialConfigurationId(config, "key-attestation-required"),
    );
    const proofHeaders = [
      {
        typ: "openid4vci-proof+jwt",
        alg: "ES256",
        kid: undefined,
        jwk: holderA,
        x5c: ["MIIB"],
        proof_type: "jwt" as const,
        key_attestation_present: false,
        source: "proof.header",
      },
    ];
    recordCredentialRequestEvidence({
      captureSession: session,
      request: { credential_configuration_id: session.credential_configuration_id },
      evidence: { body: { from: "evidence" }, raw: "RAW" },
      holderJwks: [holderA],
      proofHeaders,
      proofType: "jwt",
    });
    expect(session.raw).toMatchObject({
      credential_request: { from: "evidence" },
      credential_request_raw: "RAW",
      proof_headers: proofHeaders,
    });
    expect(session.checks).toMatchObject({
      proof_jwt_present: true,
      proof_attestation_present: false,
      nonce_verified: true,
    });
    expect(session.observed.wallet_jwks).toMatchObject({
      jwks: { keys: [holderA] },
      observed_proof_header_fields: ["typ", "alg", "jwk", "x5c"],
    });
  });

  it("keeps allocation indexes and ids stable across retries and failures", async () => {
    const store = new CaptureStore(config);
    const credentialId = mdocCredentialConfigurationId(config, "key-attestation-required");
    const session = sessionFor(store, credentialId, { statusListEnabled: true });
    session.status_list_allocation_ids = ["existing-0", "existing-1"];
    let failIndex: number | null = null;
    let round = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init: { body: URLSearchParams }) => {
        const allocationId = String(new URLSearchParams(String(init.body)).get("allocation_id"));
        const index = Number(
          (allocationId.includes(":") ? allocationId.split(":") : allocationId.split("-")).at(-1),
        );
        if (failIndex === index) return new Response("failed", { status: 500 });
        return new Response(
          JSON.stringify({
            status_list: { uri: `https://status.example.test/${round}`, idx: index },
          }),
          { status: 200 },
        );
      }),
    );
    const options = {
      config,
      captureSession: session,
      credential: credential(store, credentialId),
      holderJwks: [holderA, holderB],
    };
    const references = await allocateStatusListReferences(options);
    expect(session.status_list_references).toEqual([
      { allocation_id: "existing-0", uri: "https://status.example.test/0", idx: 0 },
      { allocation_id: "existing-1", uri: "https://status.example.test/0", idx: 1 },
    ]);
    const mapped = signingOptionsForCredential({
      signingConfig,
      credential: credential(store, credentialId),
      captureSession: session,
      holderJwks: [holderA, holderB],
      statusListReferences: references,
    });
    expect(statusInfo(mapped.credentials[0])).toEqual({
      index: 0,
      uri: "https://status.example.test/0",
    });
    expect(statusInfo(mapped.credentials[1])).toEqual({
      index: 1,
      uri: "https://status.example.test/0",
    });
    const generatedIdsSession = sessionFor(store, credentialId, { statusListEnabled: true });
    await allocateStatusListReferences({
      ...options,
      captureSession: generatedIdsSession,
    });
    expect(generatedIdsSession.status_list_allocation_ids).toEqual([
      `${generatedIdsSession.session_id}:0`,
      `${generatedIdsSession.session_id}:1`,
    ]);
    round = 1;
    await allocateStatusListReferences(options);
    expect(session.status_list_references).toEqual([
      { allocation_id: "existing-0", uri: "https://status.example.test/1", idx: 0 },
      { allocation_id: "existing-1", uri: "https://status.example.test/1", idx: 1 },
    ]);
    failIndex = 1;
    await expect(allocateStatusListReferences(options)).rejects.toThrow(
      "Status List allocation failed with HTTP 500",
    );
    expect(session.status_list_references?.[0]).toEqual({
      allocation_id: "existing-0",
      uri: "https://status.example.test/1",
      idx: 0,
    });
  });
});

describe("credential mapping guards and evidence ordering", () => {
  const issuerPrototype = CredoOpenId4VciIssuer.prototype as unknown as Record<string, unknown>;
  const mapCredentialRequest = issuerPrototype.mapCredentialRequest as (
    this: unknown,
    options: OpenId4VciCredentialRequestToCredentialMapperOptions,
  ) => Promise<unknown>;
  const linkCurrentRequest = issuerPrototype.linkCurrentRequest as (
    ...args: unknown[]
  ) => Promise<void>;

  // Call the private mapper directly because these guards are unreachable through the HTTP endpoint.
  async function map(options: {
    credentialId: string;
    session: SessionCapture;
    holderJwks?: JsonRecord[];
    evidence?: { body: JsonRecord; raw?: unknown };
    store?: CaptureStore;
    issuerId?: string;
  }) {
    const store = options.store ?? new CaptureStore(config);
    const mapIssuer = requireIssuer(config, options.issuerId ?? issuer.id);
    store.sessions.set(options.session.session_id, options.session);
    const fake = {
      config,
      store,
      requestContext: {
        getStore: () => ({
          capture: null,
          dpop: undefined,
          credentialRequestEvidence: options.evidence,
        }),
      },
      requiredIssuer: (id: string) => requireIssuer(config, id),
      linkCurrentRequest,
    };
    const mapperOptions = {
      issuanceSession: {
        issuerId: mapIssuer.id,
        issuanceMetadata: { captureSessionId: options.session.session_id },
      },
      credentialConfigurationId: options.credentialId,
      credentialRequest: {
        credential_configuration_id: options.credentialId,
        proofs: {
          jwt: [proofJwt],
        },
      },
      holderBinding: {
        keys: holderBinding(options.holderJwks ?? [holderA]),
      },
    } as unknown as OpenId4VciCredentialRequestToCredentialMapperOptions;
    return mapCredentialRequest.call(fake, mapperOptions);
  }

  it("keeps exact unsupported and imported status errors", async () => {
    const store = new CaptureStore(config);
    const unknown = sessionFor(store, "unknown.credential");
    await expect(map({ credentialId: "unknown.credential", session: unknown })).rejects.toThrow(
      "Credential configuration is not supported",
    );

    const importedStore = new CaptureStore(config);
    await credentialRegistry(config, importedStore).activate({
      issuerId: "attestbook-experimental",
      origin: importedDefinition.origin,
      rulebookId: importedDefinition.rulebookId,
      version: importedDefinition.version,
      contentDigest: importedDefinition.contentDigest,
      publishedAt: null,
      eventId: null,
      activatedAt: "2026-11-24T00:00:00.000Z",
      definitions: [importedDefinition],
    });
    const imported = sessionFor(importedStore, importedDefinition.credentialConfigurationId, {
      statusListEnabled: true,
      issuerId: "attestbook-experimental",
    });
    await expect(
      map({
        credentialId: importedDefinition.credentialConfigurationId,
        session: imported,
        store: importedStore,
        issuerId: "attestbook-experimental",
      }),
    ).rejects.toThrow("Imported credentials do not support Token Status List references");
  });

  it("keeps evidence when allocation fails", async () => {
    const store = new CaptureStore(config);
    const credentialId = mdocCredentialConfigurationId(config, "key-attestation-required");
    const session = sessionFor(store, credentialId, { statusListEnabled: true });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("failed", { status: 500 })),
    );
    await expect(
      map({
        credentialId,
        session,
        holderJwks: [holderA, holderB],
        evidence: {
          body: { credential_configuration_id: credentialId, from: "evidence" },
          raw: "RAW",
        },
      }),
    ).rejects.toThrow("Status List allocation failed with HTTP 500");
    expect(session.raw).toMatchObject({
      credential_request: { from: "evidence" },
      credential_request_raw: "RAW",
      proof_headers: expect.any(Array),
    });
    expect(session.checks).toMatchObject({ proof_jwt_present: true, nonce_verified: true });
    expect(session.observed.wallet_jwks.observed_proof_header_fields).toContain("x5c");
  });

  it("keeps session evidence visible through the HTTP session endpoint on allocator failure", async () => {
    const appStore = new CaptureStore(environment.config);
    const app = createApp(environment.config, appStore);
    const networkFetch = globalThis.fetch;
    const statusFetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
      String(input).endsWith("/token_status_list/take")
        ? Promise.resolve(new Response("failed", { status: 500 }))
        : networkFetch(input, init),
    );
    vi.stubGlobal("fetch", statusFetch);
    const sessionResponse = await request(app)
      .post("/sessions")
      .send({
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
        flow: "pre_authorized_code",
        status_list_enabled: true,
      });
    expect(sessionResponse.status, JSON.stringify(sessionResponse.body)).toBe(201);
    const session = sessionResponse.body as {
      session_id: string;
      issuer_configuration_id: string;
      credential_configuration_id: string;
    };
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session as never, dpop, config.issuer_base_url);
    const holder = await generateEs256Key();
    const issuerConfig = issuerAppConfig(
      config,
      requireIssuer(config, session.issuer_configuration_id),
    );
    const credentialPath = `${issuerPath(session.issuer_configuration_id)}/credential`;
    const nonce = await credentialNonce(app, session.issuer_configuration_id);
    const proof = await credentialProofJwt(
      holder,
      nonce,
      `${config.issuer_base_url}${issuerPath(session.issuer_configuration_id)}`,
      issuerConfig,
    );
    const response = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set(
        "DPoP",
        await dpopProof(dpop, {
          method: "POST",
          url: `${config.issuer_base_url}${credentialPath}`,
          accessToken: token.access_token,
        }),
      )
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
        nonce,
      });
    expect(response.status).toBe(500);
    expect(response.body).toEqual({ error: "server_error" });
    expect(
      statusFetch.mock.calls.some(([input]) => String(input).endsWith("/token_status_list/take")),
    ).toBe(true);
    const capture = await request(app).get(`/sessions/${session.session_id}`);
    expect(capture.status).toBe(200);
    expect(capture.body.raw).toMatchObject({
      credential_request: expect.any(Object),
      proof_headers: expect.any(Array),
    });
    expect(capture.body.checks).toMatchObject({ proof_jwt_present: true, nonce_verified: true });
  });
});
