import { readFileSync } from "node:fs";
import type { Express } from "express";
import { decodeJwt, decodeProtectedHeader, flattenedVerify, importJWK } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { verifierJwksPath } from "../src/config/paths.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { JsonRecord } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  dcqlForClaims,
  encryptedAuthorizationResponse,
  sdJwtPresentation,
} from "./support/presentation.js";
import { serverTestSuite } from "./support/server.js";
const { config, pidSdJwtCredential } = serverTestSuite("fake-issuer-test-");
describe("OpenID4VP over the Digital Credentials API", () => {
  const dcApiOrigin = "https://wallet-capture.example.test";
  const dcApiConfig = { ...config, public_base_url: `${dcApiOrigin}/` };

  async function dcApiSession(
    app: Express,
    body: JsonRecord = {},
  ): Promise<VpSessionCreateResponse & { dc_api_request: { protocol: string; data: JsonRecord } }> {
    return postJson(app, "/openid4vp/sessions", {
      response_mode: "dc_api.jwt",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      ...body,
    });
  }

  it("returns the presentation page URL as the deeplink and omits redirect-only members", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    expect(session.deeplink).toBe(
      `${dcApiOrigin}/ui/openid4vp/sessions/${session.session_id}/dc_api_presentation`,
    );
    expect(session.request_delivery).toBe("by_value");
    expect(session).not.toHaveProperty("request_uri");
    expect(session).not.toHaveProperty("response_uri");
    expect(session).not.toHaveProperty("request_uri_method");
    expect(session).not.toHaveProperty("scheme");
    expect(JSON.stringify(session)).not.toContain('"undefined"');
  });

  it("signs a Request Object carrying client_id and the configured expected_origins", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    expect(session.dc_api_request.protocol).toBe("openid4vp-v1-signed");
    const requestObject = session.dc_api_request.data.request as string;
    expect(decodeProtectedHeader(requestObject).typ).toBe("oauth-authz-req+jwt");
    const payload = decodeJwt(requestObject) as JsonRecord;
    expect(payload.client_id).toMatch(/^x509_hash:/);
    expect(payload.expected_origins).toEqual([dcApiOrigin]);
    expect(payload.response_mode).toBe("dc_api.jwt");
    expect(payload).not.toHaveProperty("aud");
    expect(payload).not.toHaveProperty("state");
    expect(payload).not.toHaveProperty("response_uri");
    expect(payload).not.toHaveProperty("request_uri");
  });

  it("sends unsigned request parameters without client_id for plain request delivery", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, {
      response_mode: "dc_api",
      request_delivery: "plain",
    });

    expect(session.dc_api_request.protocol).toBe("openid4vp-v1-unsigned");
    expect(session.dc_api_request.data).not.toHaveProperty("client_id");
    expect(session.dc_api_request.data).not.toHaveProperty("expected_origins");
    expect(session.dc_api_request.data).not.toHaveProperty("request");
    expect(session.dc_api_request.data).toMatchObject({
      response_type: "vp_token",
      response_mode: "dc_api",
      nonce: expect.any(String),
    });
  });

  it("does not serve a request_uri for a DC API session", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const served = await request(app).get(`/openid4vp/sessions/${session.session_id}/request`);
    const posted = await request(app).post(`/openid4vp/sessions/${session.session_id}/request`);

    expect(served.status).toBe(404);
    expect(served.body).toEqual({ error: "vp_request_uri_not_available_for_dc_api" });
    expect(posted.status).toBe(404);

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("created");
    expect(capture.observed.request_uri_payload.value).toBeNull();
  });

  it.each([
    [
      "request_delivery",
      { request_delivery: "by_reference" },
      "request_delivery_unsupported_for_dc_api",
    ],
    [
      "client_id_scheme",
      { client_id_scheme: "redirect_uri" },
      "client_id_scheme_unsupported_for_dc_api",
    ],
    [
      "request_uri_method",
      { request_uri_method: "post" },
      "request_uri_method_unsupported_for_dc_api",
    ],
  ])("rejects %s inputs that a DC API request cannot carry", async (_label, body, error) => {
    const app = createApp(dcApiConfig);

    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ response_mode: "dc_api.jwt", ...body });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error });
  });

  it("rejects unknown response modes instead of falling back to direct_post.jwt", async () => {
    const app = createApp(dcApiConfig);

    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ response_mode: "dc-api" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "unsupported_response_mode" });
  });

  it("serves a presentation page that invokes the wallet from the button only", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const page = await request(app).get(
      `/ui/openid4vp/sessions/${session.session_id}/dc_api_presentation`,
    );

    expect(page.status).toBe(200);
    expect(page.headers["cache-control"]).toBe("no-store");
    expect(page.text).toContain(">Present credential</button>");
    expect(page.text).toContain(session.dc_api_request.data.request as string);
    expect(page.text).toContain('button.addEventListener("click"');
    expect(page.text).toContain(
      "navigator.credentials.get({ digital: { requests: [config.request]",
    );
    expect(page.text).not.toContain("presentation_validation");
  });

  it("accepts an encrypted DC API presentation bound to the browser origin", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks).toMatchObject({
      presentation_valid: true,
      nonce_verified: true,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
    expect(capture.raw?.presentation_response_decrypted?.vp_token).toEqual({
      query_0: [presentation],
    });
  });

  it("does not require state for an unbound credential requested over the DC API", async () => {
    const app = createApp(dcApiConfig);
    const dcqlQuery = dcqlForClaims(["family_name"]);
    (dcqlQuery.credentials as JsonRecord[])[0].require_cryptographic_holder_binding = false;
    const session = await dcApiSession(app, {
      presentation_request: { state: null, dcql_query: dcqlQuery },
    });
    const presentation = await sdJwtPresentation({
      credential: await pidSdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status, response.text).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks).toMatchObject({ presentation_valid: true, errors: [] });
  });

  it("signs one DC API request under both Client Identifiers for multisigned delivery", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, { request_delivery: "multisigned" });

    expect(session.request_delivery).toBe("multisigned");
    expect(session.dc_api_request.protocol).toBe("openid4vp-v1-multisigned");
    const jws = session.dc_api_request.data.request as {
      payload: string;
      signatures: { protected: string; signature: string }[];
    };
    expect(jws.signatures).toHaveLength(2);
    const payload = JSON.parse(Buffer.from(jws.payload, "base64url").toString("utf8"));
    expect(payload).not.toHaveProperty("client_id");
    expect(payload).toMatchObject({
      expected_origins: [dcApiOrigin],
      response_mode: "dc_api.jwt",
      nonce: session.authorization_request.nonce,
    });

    const verifierJwks = JSON.parse(readFileSync(verifierJwksPath(config.data_dir), "utf8"));
    const didDocument = (await request(app).get("/openid4vp/did.json")).body;
    const keys = [
      await importJWK(verifierJwks.keys[0], "ES256"),
      await importJWK(didDocument.verificationMethod[0].publicKeyJwk, "ES256"),
    ];
    const headers = await Promise.all(
      jws.signatures.map(async (signature, index) => {
        const verified = await flattenedVerify({ payload: jws.payload, ...signature }, keys[index]);
        return verified.protectedHeader;
      }),
    );
    expect(headers[0]).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      client_id: session.authorization_request.client_id,
      x5c: [expect.any(String)],
    });
    expect(headers[1]).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      client_id: `decentralized_identifier:${didDocument.id}`,
      kid: `${didDocument.id}#credimi-fake-verifier-did-key`,
    });
  });

  it("verifies a presentation answering a multisigned DC API request", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, { request_delivery: "multisigned" });
    const presentation = await sdJwtPresentation({
      credential: await pidSdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
  });

  it.each([
    [
      { response_mode: "direct_post", request_delivery: "multisigned" },
      "multisigned_request_delivery_requires_dc_api",
    ],
    [
      { request_delivery: "multisigned", client_id_scheme: "decentralized_identifier" },
      "client_id_scheme_unsupported_for_multisigned",
    ],
    [
      {
        request_delivery: "multisigned",
        presentation_request: {
          dcql_query: dcqlForClaims(["family_name"]),
          verifier_info: [{ format: "jwt", data: "eyJ.e30.sig" }],
        },
      },
      "verifier_info_unsupported_for_multisigned",
    ],
  ])("rejects a multisigned request it cannot sign faithfully: %o", async (body, error) => {
    const response = await request(createApp(dcApiConfig))
      .post("/openid4vp/sessions")
      .send({ response_mode: "dc_api.jwt", ...body });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error });
  });

  it("rejects a DC API presentation bound to the client_id instead of the origin", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe("invalid_presentation");
  });

  it("captures a wallet refusal as a refusal rather than a verification failure", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, { response_mode: "dc_api" });

    const reported = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/dc_api_invocation`)
      .send({
        outcome: "rejected",
        error_name: "NotAllowedError",
        error_message: "The request is not allowed",
        response_returned: false,
        vp_token_present: false,
      });

    expect(reported.status).toBe(202);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("dc_api_invocation_reported");
    expect(capture.dc_api?.invocation).toMatchObject({
      outcome: "rejected",
      error_name: "NotAllowedError",
      response_returned: false,
      vp_token_present: false,
    });
    expect(capture.checks.presentation_valid).toBeNull();
    expect(capture.events.map((event) => event.type)).toContain("vp_dc_api_invocation_reported");
  });

  it("rejects invocation reports with an unknown outcome", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/dc_api_invocation`)
      .send({ outcome: "wallet_exploded" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "unsupported_dc_api_invocation_outcome" });
  });

  it("keeps the first presentation when a DC API response is replayed", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });
    const submit = async () =>
      request(app)
        .post(`/openid4vp/sessions/${session.session_id}/response`)
        .send({
          response: await encryptedAuthorizationResponse(session.authorization_request, {
            vp_token: { query_0: [presentation] },
          }),
        });

    const first = await submit();
    const replay = await submit();

    expect(first.status).toBe(200);
    expect(replay.status).toBe(409);
    expect(replay.body).toEqual({ error: "vp_session_already_completed" });
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
  });

  it("refuses a submission whose browser Origin is not the session origin", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .set("origin", "https://attacker.example.test")
      .send({ vp_token: { query_0: ["forged"] } });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "unexpected_dc_api_origin" });
  });

  it("closes the presentation window once the session expires", async () => {
    const store = new CaptureStore(dcApiConfig);
    const app = createApp(dcApiConfig, store);
    const session = await dcApiSession(app);
    const stored = store.getVpSession(session.session_id);
    if (!stored?.dc_api) throw new Error("DC API session capture missing");
    stored.dc_api.expires_at = new Date(Date.now() - 1000).toISOString();

    const page = await request(app).get(
      `/ui/openid4vp/sessions/${session.session_id}/dc_api_presentation`,
    );
    const submitted = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: { query_0: ["late"] } });

    expect(page.status).toBe(200);
    expect(page.text).toContain("expired");
    expect(page.text).not.toContain(">Present credential</button>");
    expect(submitted.status).toBe(400);
    expect(submitted.body).toEqual({ error: "vp_session_expired" });
  });

  it("leaves redirect sessions able to record repeated wallet submissions", async () => {
    const app = createApp(dcApiConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
    });

    const first = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: "presentation-token" });
    const second = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: "presentation-token" });

    expect(first.status).toBe(400);
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("invalid_presentation");
  });
});
