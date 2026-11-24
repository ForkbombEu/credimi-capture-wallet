import type { Express } from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { attestbookIntegration } from "../src/attestbook/integration.js";
import { PID_FIXTURE_IDS } from "../src/configurations/shared/pid-fixtures.js";
import { credentialRegistry } from "../src/credentials/registry.js";
import { credoOpenId4VciIssuer } from "../src/openid4vci/credo-issuer.js";
import {
  mdocCredentialConfigurationId,
  supportedCredentialsForIssuer,
} from "../src/openid4vci/metadata.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import { STATUS_REFERENCE_FIXTURES } from "../src/status-list/reference-fixtures.js";
import { AttestbookFixture } from "./attestbook-fixture.js";
import {
  createIssuerTestEnvironment,
  createTestApp,
  requireIssuer,
} from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";

let environment: IssuerTestEnvironment | undefined;
let app!: Express;
let scenariosApp!: Express;
let attestbookEnvironment: IssuerTestEnvironment | undefined;
let attestbookFixture: AttestbookFixture | undefined;
let attestbookApp!: Express;
let attestbookStore!: CaptureStore;

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "issuance-session-errors-" });
  app = createTestApp(environment.config);
  scenariosApp = createTestApp({ ...environment.config, fcaf_scenarios_enabled: true });
  attestbookFixture = new AttestbookFixture();
  await attestbookFixture.start();
  attestbookEnvironment = await createIssuerTestEnvironment({
    prefix: "issuance-session-errors-attestbook-",
    config: {
      public_base_url: "http://issuer.example.test",
      attestbook: {
        enabled: true,
        base_url: attestbookFixture.origin,
        rulebook_id: attestbookFixture.rulebookId,
        webhook_secret: "atw_test-subscription-secret-0000000000000000",
        admin_token: "test-admin-token",
        allowed_schema_origins: [],
      },
    },
  });
  attestbookFixture.publish("1.0", [
    {
      name: "Membership Card",
      schema: {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        required: ["member_id", "given_name", "family_name"],
        properties: {
          member_id: { type: "string", minLength: 3 },
          given_name: { type: "string" },
          family_name: { type: "string" },
        },
      },
      typeMetadata: {
        vct: "urn:attestbook:membership-card",
        display: [{ locale: "en-US", name: "Membership Card" }],
        claims: [{ path: ["member_id"] }, { path: ["given_name"] }, { path: ["family_name"] }],
      },
    },
  ]);
  attestbookStore = new CaptureStore(attestbookEnvironment.config);
  attestbookIntegration(attestbookEnvironment.config, attestbookStore);
  attestbookApp = createApp(attestbookEnvironment.config, attestbookStore);
  await credoOpenId4VciIssuer(attestbookEnvironment.config, attestbookStore);
  await attestbookIntegration(attestbookEnvironment.config, attestbookStore).idle();
});
afterAll(async () => {
  environment?.cleanup();
  attestbookEnvironment?.cleanup();
  await attestbookFixture?.stop();
});
afterEach(() => vi.restoreAllMocks());
function requiredEnvironment(): IssuerTestEnvironment {
  if (!environment) throw new Error("test environment missing");
  return environment;
}

function requiredAttestbookEnvironment(): IssuerTestEnvironment {
  if (!attestbookEnvironment) throw new Error("Attestbook test environment missing");
  return attestbookEnvironment;
}

type ErrorRow = {
  name: string;
  body: Record<string, unknown>;
  expected: Record<string, unknown>;
  scenarios?: boolean;
};

const rows: ErrorRow[] = [
  {
    name: "removed legacy root issuer",
    body: { broken: true },
    expected: {
      error: "invalid_request",
      error_description: "'broken' is unavailable because the legacy root issuer has been removed",
    },
  },
  {
    name: "unknown issuer configuration",
    body: { issuer_configuration_id: "missing-issuer" },
    expected: {
      error: "unsupported_issuer_configuration",
      supported_issuer_configuration_ids: [
        "eu-pid-device-bound",
        "eu-pid-jwt-key-attestation",
        "eu-pid-jwt-proof-only",
      ],
    },
  },
  {
    name: "unknown flow",
    body: { flow: "implicit" },
    expected: {
      error: "unsupported_issuance_flow",
      supported_flows: ["pre_authorized_code", "authorization_code"],
    },
  },
  {
    name: "unknown offer mode",
    body: { credential_offer_mode: "inline" },
    expected: {
      error: "unsupported_credential_offer_mode",
      supported_credential_offer_modes: ["credential_offer", "credential_offer_uri"],
    },
  },
  {
    name: "non-boolean status list flag",
    body: { status_list_enabled: "maybe" },
    expected: {
      error: "invalid_status_list_enabled",
      error_description: "status_list_enabled must be a boolean",
    },
  },
  {
    name: "unknown credential",
    body: { credential_configuration_id: "not-a-credential" },
    expected: {
      error: "unsupported_credential_configuration",
      issuer_configuration_id: "eu-pid-device-bound",
    },
  },
  {
    name: "unknown status reference",
    body: { status_reference: "not-a-fixture" },
    expected: {
      error: "unsupported_status_reference",
      supported_status_references: STATUS_REFERENCE_FIXTURES,
    },
  },
  {
    name: "disabled non-valid status reference",
    body: { status_reference: "status_without_status_list" },
    expected: { error: "status_reference_not_enabled" },
  },
  {
    name: "status reference without status list",
    body: { status_reference: "status_without_status_list" },
    expected: { error: "status_reference_requires_status_list" },
    scenarios: true,
  },
  {
    name: "unknown PID fixture",
    body: { fixture_id: "not-a-fixture" },
    expected: { error: "unsupported_fixture_id", supported_fixture_ids: PID_FIXTURE_IDS },
  },
  {
    name: "empty document number",
    body: { document_number: "" },
    expected: { error: "invalid_document_number" },
  },
  {
    name: "unknown digest algorithm",
    body: { digest_algorithm: "SHA-999" },
    expected: {
      error: "unsupported_digest_algorithm",
      supported_digest_algorithms: ["sha-256", "sha-384", "sha-512"],
    },
  },
  {
    name: "unsupported evidence mode",
    body: { evidence_mode: "verbose" },
    expected: {
      error: "unsupported_evidence_mode",
      supported_evidence_modes: ["redacted", "full"],
    },
  },
  {
    name: "invalid issuance response scenario",
    body: { issuance_response_scenario: "not-a-scenario" },
    expected: { error: "invalid_issuance_response_scenario" },
  },
  {
    name: "unknown offer scheme",
    body: { offer_scheme: "not-a-scheme" },
    expected: {
      error: "unsupported_offer_scheme",
      supported_offer_schemes: ["openid-credential-offer://", "eu-eaa-offer://", "haip-vci://"],
    },
  },
  {
    name: "invalid offer mutation",
    body: { offer_mutation: [] },
    expected: { error: "invalid_offer_mutation" },
  },
  {
    name: "offer mutation requires by-value offer",
    body: { credential_offer_mode: "credential_offer_uri", offer_mutation: { set: { "/x": 1 } } },
    expected: { error: "offer_mutation_requires_by_value_offer" },
    scenarios: true,
  },
];

describe("POST /sessions error matrix", () => {
  it.each(rows)("rejects $name", async ({ body, expected, scenarios, name }) => {
    const response = await request(scenarios ? scenariosApp : app)
      .post("/sessions")
      .send(body);
    expect(response.status, JSON.stringify(response.body)).toBe(400);
    const exactExpected =
      name === "unknown credential"
        ? {
            ...expected,
            supported_credential_configuration_ids: supportedCredentialsForIssuer(
              requiredEnvironment().config,
              requireIssuer(requiredEnvironment().config, "eu-pid-device-bound"),
            ).map((credential) => credential.id),
          }
        : expected;
    expect(response.body).toEqual(exactExpected);
  });
  it("includes supported values in exact error bodies", async () => {
    const flow = await request(app).post("/sessions").send({ flow: "implicit" });
    expect(flow.body).toEqual({
      error: "unsupported_issuance_flow",
      supported_flows: ["pre_authorized_code", "authorization_code"],
    });

    const fixture = await request(app).post("/sessions").send({ fixture_id: "missing" });
    expect(fixture.body).toEqual({
      error: "unsupported_fixture_id",
      supported_fixture_ids: PID_FIXTURE_IDS,
    });

    const status = await request(app).post("/sessions").send({ status_reference: "missing" });
    expect(status.body).toEqual({
      error: "unsupported_status_reference",
      supported_status_references: STATUS_REFERENCE_FIXTURES,
    });
  });

  it("checks status_reference before fixture_id when both are invalid", async () => {
    const response = await request(app)
      .post("/sessions")
      .send({ status_reference: "missing", fixture_id: "missing" });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "unsupported_status_reference",
      supported_status_references: STATUS_REFERENCE_FIXTURES,
    });
  });

  it("checks status-reference enablement before its status-list requirement", async () => {
    const response = await request(app)
      .post("/sessions")
      .send({ status_reference: "status_without_status_list", status_list_enabled: true });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "status_reference_not_enabled" });

    const enabled = await request(scenariosApp)
      .post("/sessions")
      .send({ status_reference: "status_without_status_list" });
    expect(enabled.status).toBe(400);
    expect(enabled.body).toEqual({ error: "status_reference_requires_status_list" });
  });

  it("rejects non-default digest algorithms for mdoc credentials", async () => {
    const response = await request(app)
      .post("/sessions")
      .send({
        credential_configuration_id: mdocCredentialConfigurationId(
          environment?.config ?? ({} as never),
          "key-attestation-required",
        ),
        digest_algorithm: "sha-512",
      });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "digest_algorithm_unsupported_for_mdoc" });
  });

  it("rejects disabled FCAF options after parsing them", async () => {
    const evidence = await request(app).post("/sessions").send({ evidence_mode: "full" });
    expect(evidence.body).toEqual({ error: "evidence_mode_not_enabled" });
    const response = await request(app)
      .post("/sessions")
      .send({ issuance_response_scenario: { credential: { status: 500 } } });
    expect(response.body).toEqual({ error: "issuance_response_scenario_not_enabled" });
    const mutation = await request(app)
      .post("/sessions")
      .send({ offer_mutation: { set: { "/x": 1 } } });
    expect(mutation.body).toEqual({ error: "offer_mutation_not_enabled" });
  });
});
describe("Attestbook supersession during POST /sessions", () => {
  it("maps a queued active-catalogue replacement to a 409", async () => {
    const registry = credentialRegistry(requiredAttestbookEnvironment().config, attestbookStore);
    const active = registry.activeCatalogue("attestbook-experimental");
    expect(active).not.toBeNull();
    if (!active) throw new Error("active Attestbook catalogue missing");
    const replacement = {
      ...active,
      version: "2.0",
      contentDigest: "x",
      definitions: active.definitions.map((definition) => ({
        ...definition,
        version: "2.0",
        contentDigest: "x",
      })),
    };
    let activation: Promise<void> | undefined;
    const originalCredentialById = registry.credentialById.bind(registry);
    vi.spyOn(registry, "credentialById").mockImplementation((issuer, id) => {
      const result = originalCredentialById(issuer, id);
      activation ??= registry.activate(replacement);
      return result;
    });
    const response = await request(attestbookApp).post("/sessions").send({
      issuer_configuration_id: "attestbook-experimental",
      credential_configuration_id: "urn:attestbook:membership-card",
      flow: "pre_authorized_code",
    });
    await activation;
    expect(response.status).toBe(409);
    expect(response.body).toEqual({
      error: "credential_configuration_superseded",
      error_description:
        "credential configuration 'urn:attestbook:membership-card' was replaced by a newer rulebook version",
    });
  });
  it("rejects PID options for an imported credential before status-reference validation", async () => {
    const response = await request(attestbookApp).post("/sessions").send({
      issuer_configuration_id: "attestbook-experimental",
      credential_configuration_id: "urn:attestbook:membership-card",
      status_reference: "not-a-fixture",
      fixture_id: "not-a-fixture",
    });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "unsupported_for_imported_credential",
      error_description: "these parameters are not supported for an imported Attestbook credential",
      unsupported_parameters: ["status_reference", "fixture_id"],
    });
  });
});
