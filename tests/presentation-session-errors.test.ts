import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Express } from "express";
import { decodeJwt, decodeProtectedHeader } from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifierCaCertificatePath } from "../src/config/paths.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import { createIssuerTestEnvironment, createTestApp } from "./support/environment.js";
import { getJson } from "./support/http.js";
import type { VpSessionResponse } from "./support/presentation.js";

let environment: IssuerTestEnvironment | undefined;
let app!: Express;
let scenariosApp!: Express;

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "presentation-session-errors-" });
  app = createTestApp(environment.config);
  scenariosApp = createTestApp({ ...environment.config, fcaf_scenarios_enabled: true });
});

afterAll(() => environment?.cleanup());
function requiredEnvironment(): IssuerTestEnvironment {
  if (!environment) throw new Error("test environment missing");
  return environment;
}

type ErrorRow = {
  name: string;
  body: Record<string, unknown>;
  expected: Record<string, unknown>;
  scenarios?: boolean;
};

const rows: ErrorRow[] = [
  {
    name: "request URI method",
    body: { request_uri_method: 42 },
    expected: { error: "unsupported_request_uri_method" },
  },
  {
    name: "request delivery",
    body: { request_delivery: "unknown" },
    expected: { error: "unsupported_request_delivery" },
  },
  {
    name: "client identifier scheme",
    body: { client_id_scheme: "unknown" },
    expected: { error: "unsupported_client_id_scheme" },
  },
  {
    name: "request URI method with plain delivery",
    body: { request_uri_method: "post", request_delivery: "plain" },
    expected: { error: "request_uri_method_requires_by_reference_delivery" },
  },
  {
    name: "response mode",
    body: { response_mode: "query" },
    expected: { error: "unsupported_response_mode" },
  },
  {
    name: "deeplink scheme",
    body: { scheme: "not a scheme" },
    expected: { error: "invalid_deeplink_scheme" },
  },
  {
    name: "redirect URI",
    body: { redirect_uri: "not a URL" },
    expected: { error: "invalid_redirect_uri" },
  },
  {
    name: "client metadata",
    body: { client_metadata: [] },
    expected: { error: "invalid_client_metadata" },
  },
  {
    name: "allow undecryptable response",
    body: { allow_undecryptable_response: "maybe" },
    expected: { error: "invalid_allow_undecryptable_response" },
  },
  {
    name: "request mutation",
    body: { request_mutation: [] },
    expected: { error: "invalid_request_mutation" },
  },
  {
    name: "request behavior",
    body: { request_behavior: [] },
    expected: { error: "invalid_request_behavior" },
  },
  {
    name: "verifier attestation",
    body: { verifier_attestation: { claims: [] } },
    expected: { error: "invalid_verifier_attestation" },
  },
  {
    name: "verifier attestation redirect URIs",
    body: { verifier_attestation: { redirect_uris: [4] } },
    expected: { error: "invalid_verifier_attestation" },
  },
  {
    name: "response scenario",
    body: { response_scenario: [] },
    expected: { error: "invalid_response_scenario" },
  },
  {
    name: "request mutation disabled",
    body: { request_mutation: { request_object: { set: { "/x": 1 } } } },
    expected: { error: "request_mutation_not_enabled" },
  },
  {
    name: "request behavior disabled",
    body: { request_behavior: { wallet_nonce: "echo" } },
    expected: { error: "request_behavior_not_enabled" },
  },
  {
    name: "response scenario disabled",
    body: { response_scenario: { status: 500 } },
    expected: { error: "response_scenario_not_enabled" },
  },
  {
    name: "DC API request delivery",
    body: { response_mode: "dc_api.jwt", request_delivery: "by_reference" },
    expected: { error: "request_delivery_unsupported_for_dc_api" },
  },
  {
    name: "DC API client ID scheme",
    body: { response_mode: "dc_api.jwt", client_id_scheme: "redirect_uri" },
    expected: { error: "client_id_scheme_unsupported_for_dc_api" },
  },
  {
    name: "DC API request URI method",
    body: { response_mode: "dc_api.jwt", request_uri_method: "post" },
    expected: { error: "request_uri_method_unsupported_for_dc_api" },
  },
  {
    name: "DC API redirect URI",
    body: { response_mode: "dc_api.jwt", redirect_uri: "https://rp.example.test/callback" },
    expected: { error: "redirect_uri_unsupported_for_dc_api" },
  },
  {
    name: "DC API verifier-attestation redirect URI placeholder",
    body: {
      response_mode: "dc_api.jwt",
      client_id_scheme: "verifier_attestation",
      verifier_attestation: { redirect_uris: ["{{response_uri}}"] },
    },
    expected: { error: "response_uri_placeholder_unsupported_for_dc_api" },
  },
  {
    name: "signature behavior and redirect client",
    body: {
      request_behavior: { signature: "corrupt" },
      client_id_scheme: "redirect_uri",
      request_delivery: "plain",
    },
    expected: { error: "signature_behavior_requires_a_signed_request" },
    scenarios: true,
  },
  {
    name: "certificate behavior and redirect client",
    body: {
      request_behavior: { certificate_chain: "incomplete_chain" },
      client_id_scheme: "redirect_uri",
      request_delivery: "plain",
    },
    expected: { error: "signature_behavior_requires_a_signed_request" },
    scenarios: true,
  },
  {
    name: "certificate behavior scheme",
    body: {
      request_behavior: { certificate_chain: "incomplete_chain" },
      client_id_scheme: "decentralized_identifier",
    },
    expected: { error: "certificate_chain_requires_x509_hash_client_id" },
    scenarios: true,
  },
  {
    name: "attestation client scheme",
    body: { verifier_attestation: {}, client_id_scheme: "x509_hash" },
    expected: { error: "verifier_attestation_requires_verifier_attestation_client_id" },
  },
  {
    name: "redirect client delivery",
    body: { client_id_scheme: "redirect_uri", request_delivery: "by_value" },
    expected: { error: "redirect_uri_client_id_requires_plain_delivery" },
  },
  {
    name: "multisigned without DC API",
    body: { request_delivery: "multisigned" },
    expected: { error: "multisigned_request_delivery_requires_dc_api" },
  },
  {
    name: "multisigned client scheme",
    body: {
      response_mode: "dc_api.jwt",
      request_delivery: "multisigned",
      client_id_scheme: "verifier_attestation",
    },
    expected: { error: "client_id_scheme_unsupported_for_multisigned" },
  },
  {
    name: "multisigned signature behavior",
    body: {
      response_mode: "dc_api.jwt",
      request_delivery: "multisigned",
      request_behavior: { signature: "corrupt" },
    },
    expected: { error: "signature_behavior_unsupported_for_multisigned" },
    scenarios: true,
  },
  {
    name: "encrypted response metadata",
    body: { client_metadata: null },
    expected: { error: "client_metadata_required_for_encrypted_response" },
  },
  {
    name: "undecryptable response metadata",
    body: { allow_undecryptable_response: true },
    expected: { error: "allow_undecryptable_response_requires_client_metadata" },
  },
  { name: "state", body: { state: "provided" }, expected: { error: "invalid_state" } },
  {
    name: "multisigned verifier info",
    body: {
      response_mode: "dc_api.jwt",
      request_delivery: "multisigned",
      verifier_info: "provided",
    },
    expected: { error: "verifier_info_unsupported_for_multisigned" },
  },
];

describe("POST /openid4vp/sessions error matrix", () => {
  it.each(rows)("rejects $name", async ({ body, expected, scenarios }) => {
    const response = await request(scenarios ? scenariosApp : app)
      .post("/openid4vp/sessions")
      .send(body);
    expect(response.status, JSON.stringify(response.body)).toBe(400);
    expect(response.body).toEqual(expected);
  });

  it("preserves validation order when two VP inputs are invalid", async () => {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        request_uri_method: 42,
        client_id_scheme: "unknown",
        verifier_attestation: { claims: [] },
      });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "unsupported_request_uri_method" });
    const dcApi = await request(scenariosApp)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "dc_api.jwt",
        request_delivery: "by_reference",
        request_behavior: { signature: "corrupt" },
      });
    expect(dcApi.status).toBe(400);
    expect(dcApi.body).toEqual({ error: "request_delivery_unsupported_for_dc_api" });
  });

  it("maps downstream client metadata errors", async () => {
    const metadata = await request(app)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "direct_post.jwt",
        client_metadata: { jwks: null },
      });
    expect(metadata.status).toBe(400);
    expect(metadata.body).toEqual({ error: "invalid_client_metadata" });
  });

  it("returns the duplicated request_behavior_not_enabled mapping for verifier-attestation signatures", async () => {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        client_id_scheme: "verifier_attestation",
        verifier_attestation: { signature: "corrupt" },
      });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "request_behavior_not_enabled" });
  });

  it("rejects a trust-anchor request when the verifier CA is not configured", async () => {
    const response = await request(scenariosApp)
      .post("/openid4vp/sessions")
      .send({ request_behavior: { certificate_chain: "with_trust_anchor" } });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "verifier_ca_certificate_not_configured",
      error_description:
        "certificate_chain with_trust_anchor needs the CA certificate at verifier/verifier-ca-certificate.pem in the data directory",
    });
  });
  it("rejects an invalid configured verifier CA certificate", async () => {
    const path = verifierCaCertificatePath(requiredEnvironment().config.data_dir);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "not-a-certificate");
    try {
      const response = await request(scenariosApp)
        .post("/openid4vp/sessions")
        .send({ request_behavior: { certificate_chain: "with_trust_anchor" } });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: "verifier_ca_certificate_invalid",
        error_description:
          "verifier/verifier-ca-certificate.pem is not a parseable certificate: Argument 'base64Text' is not Base64 encoded",
      });
    } finally {
      rmSync(path, { force: true });
    }
  });

  it("documents that ResponseModeError cannot be reached over HTTP", async () => {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ presentation_request: { response_mode: "bogus" } });
    expect(response.status).toBe(201);
    // createVpSession overwrites request.response_mode with the parsed selected mode.
  });
  it("rejects parsed FCAF options when the feature is disabled", async () => {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        request_behavior: { wallet_nonce: "echo" },
      });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "request_behavior_not_enabled" });

    const enabled = await request(scenariosApp)
      .post("/openid4vp/sessions")
      .send({
        request_behavior: { wallet_nonce: "echo" },
      });
    expect(enabled.status).toBe(201);
  });

  it("re-signs a POST request object with wallet_nonce and records evidence", async () => {
    const session = await request(scenariosApp)
      .post("/openid4vp/sessions")
      .send({
        request_uri_method: "post",
        request_mutation: { request_object_header: { set: { "/typ": "jwt" } } },
      });
    expect(session.status).toBe(201);
    const path = new URL(String(session.body.request_uri)).pathname;
    const response = await request(scenariosApp)
      .post(path)
      .set("content-type", "application/json")
      .send({ wallet_nonce: "n-1" });
    expect(response.status).toBe(200);
    expect(response.type).toBe("application/oauth-authz-req+jwt");
    expect(decodeJwt(response.text).wallet_nonce).toBe("n-1");
    expect(decodeProtectedHeader(response.text).typ).toBe("jwt");

    const capture = await getJson<VpSessionResponse>(
      scenariosApp,
      `/openid4vp/sessions/${session.body.session_id}`,
    );
    expect(capture.raw?.request_uri_http).toMatchObject({ method: "POST" });
    expect(capture.observed.request_uri_payload.value).toEqual({
      wallet_nonce: "n-1",
    });
    expect(capture.events.map((event) => event.type)).toContain("vp_request_retrieved");
  });

  it("rejects wallet metadata advertising only unsupported request encryption algorithms", async () => {
    const session = await request(scenariosApp).post("/openid4vp/sessions").send({});
    expect(session.status).toBe(201);
    const path = new URL(String(session.body.request_uri)).pathname;
    const response = await request(scenariosApp)
      .post(path)
      .send({
        wallet_metadata: {
          jwks: { keys: [] },
          request_object_encryption_alg_values_supported: ["RSA-OAEP"],
        },
      });
    expect(response.status).toBe(400);
    expect(response.type).toBe("application/json");
    expect(response.body).toEqual({
      error: "invalid_request",
      error_description: "request_object_encryption_alg_values_supported does not include ECDH-ES",
    });
    const capture = await getJson<VpSessionResponse>(
      scenariosApp,
      `/openid4vp/sessions/${session.body.session_id}`,
    );
    expect(capture.events.at(-1)).toMatchObject({
      type: "vp_request_object_encryption_unsupported",
      detail: { reason: expect.stringContaining("does not include ECDH-ES") },
    });
  });
});
