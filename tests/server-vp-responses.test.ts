import { createHash } from "node:crypto";
import { X509Certificate } from "@credo-ts/core";
import { type JWK, compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { PID_SD_JWT_VCT } from "../src/credentials/definitions.js";
import { createApp } from "../src/server/app.js";
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

describe("capture issuer server", () => {
  it("serves OpenID4VP request_uri objects and captures invalid wallet presentation responses", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name"]),
      },
    });

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(requestObject.status).toBe(200);
    expect(requestObject.type).toBe("application/oauth-authz-req+jwt");
    const requestObjectHeader = decodeProtectedHeader(requestObject.text);
    const verifierCertificate = X509Certificate.fromEncodedCertificate(
      (requestObjectHeader.x5c as string[])[0],
    );
    expect(requestObjectHeader).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      x5c: [expect.any(String)],
    });
    const verified = await compactVerify(
      requestObject.text,
      await importJWK(verifierCertificate.publicJwk.toJson() as JWK, "ES256"),
    );
    expect(verified.protectedHeader.typ).toBe("oauth-authz-req+jwt");
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    expect(requestObjectClaims.state).toBe(session.authorization_request.state);
    expect(requestObjectClaims.aud).toBe(session.authorization_request.aud);
    expect(requestObjectClaims.presentation_definition).toBeUndefined();
    expect(requestObjectClaims.client_id).toBe(
      `x509_hash:${createHash("sha256")
        .update(Buffer.from((requestObjectHeader.x5c as string[])[0], "base64"))
        .digest("base64url")}`,
    );

    const retrieved = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(retrieved.status).toBe("request_retrieved");

    const presentation = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .type("form")
      .set("DPoP", "wallet-response-dpop-proof")
      .send({
        state: session.authorization_request.state,
        vp_token: "presentation-token",
      });
    expect(presentation.status).toBe(400);
    expect(presentation.body).toMatchObject({ error: "invalid_presentation" });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.observed.vp_token).toBeUndefined();
    expect(capture.observed.wallet_response.value?.vp_token).toBe("presentation-token");
    expect(capture.observed.presentation_submission).toBeUndefined();
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.length).toBeGreaterThan(0);
    expect(capture.raw?.presentation_response?.state).toBe(session.authorization_request.state);
    expect(capture.raw?.presentation_response_http).toMatchObject({
      method: "POST",
      headers: {
        "content-type": expect.stringContaining("application/x-www-form-urlencoded"),
        dpop: { redacted: true, present: true },
      },
    });
    expect(capture.raw?.presentation_response_http?.body).toContain(
      `state=${encodeURIComponent(String(session.authorization_request.state))}`,
    );
    expect(capture.raw?.presentation_response_http?.body).toContain("vp_token=presentation-token");
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 400,
      headers: {
        "content-type": expect.stringContaining("application/json"),
        "cache-control": "no-store",
      },
    });
    expect(capture.raw?.presentation_response_verifier_http?.body).toContain(
      '"error":"invalid_presentation"',
    );
  });

  it("keeps a failed plain direct-post VP token separate from the verifier error", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .type("form")
      .send({
        state: session.authorization_request.state,
        vp_token: "not-a-real-presentation",
      });

    expect(response.status, response.text).toBe(400);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.vp_token_format_valid).toBe(true);
    expect(capture.raw?.presentation_response_decrypted).toEqual({
      state: session.authorization_request.state,
      vp_token: "not-a-real-presentation",
    });
    expect(capture.raw?.presentation_response_decrypted).not.toHaveProperty("error");
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        type: "vp_presentation_response_received",
        detail: expect.objectContaining({ vp_token_observed: true }),
      }),
    );
  });

  it("acknowledges a captured direct-post Authorization Error Response", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .type("form")
      .send({
        error: "invalid_request",
        error_description: "redirect_uri is not allowed with direct_post",
        state: session.authorization_request.state,
      });

    expect(response.status, response.text).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.body).toEqual({});
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.observed.wallet_response.value).toEqual({
      error: "invalid_request",
      error_description: "redirect_uri is not allowed with direct_post",
      state: session.authorization_request.state,
    });
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      headers: {
        "content-type": expect.stringContaining("application/json"),
        "cache-control": "no-store",
      },
      body: "{}",
    });
  });

  it("rejects SD-JWT VC presentations that do not disclose all requested DCQL claims", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: JSON.stringify({ query_0: [presentation] }),
      });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_presentation" });
    expect(JSON.stringify(response.body.errors)).toContain("Presentation submission");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.nonce_verified).toBe(false);
    expect(capture.checks.holder_binding_verified).toBe(false);
    expect(capture.checks.dcql_query_matched).toBe(false);
  });

  it("accepts SD-JWT VC presentations that satisfy holder binding, nonce, and DCQL", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      redirect_uri: "https://rp.example.test/complete",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name", "given_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          state: session.authorization_request.state,
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ redirect_uri: session.redirect_uri });

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
    expect(capture.raw?.presentation_response).toEqual({ response: expect.any(String) });
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      headers: {
        "content-type": expect.stringContaining("application/json"),
        "cache-control": "no-store",
      },
      body: JSON.stringify({ redirect_uri: session.redirect_uri }),
    });
    expect(capture.raw?.presentation_response_decrypted).toMatchObject({
      state: session.authorization_request.state,
      vp_token: { query_0: [presentation] },
    });
    expect(capture.raw?.presentation_response_decrypted_raw).toBe(
      JSON.stringify({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      }),
    );
    expect(capture.decoded_presentations).toMatchObject({
      query_0: [
        {
          format: "dc+sd-jwt",
          claims: {
            vct: PID_SD_JWT_VCT,
            family_name: "Rossi",
            given_name: "Mario",
          },
        },
      ],
    });
    expect(capture.raw?.decoded_presentations).toEqual(capture.decoded_presentations);
    expect(JSON.stringify(capture.decoded_presentations)).not.toContain(presentation);
  });

  it.each(["A128GCM", "A256GCM"])(
    "decrypts a presentation response encrypted with the sole advertised enc value %s",
    async (enc) => {
      const app = createApp(config);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        client_metadata: { encrypted_response_enc_values_supported: [enc] },
        presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      });
      const metadata = session.authorization_request.client_metadata as JsonRecord;
      expect(metadata.encrypted_response_enc_values_supported).toEqual([enc]);

      const credential = await pidSdJwtCredential();
      const presentation = await sdJwtPresentation({
        credential,
        authorizationRequest: session.authorization_request,
        disclosedClaims: ["family_name"],
      });
      const response = await request(app)
        .post(`/openid4vp/sessions/${session.session_id}/response`)
        .send({
          response: await encryptedAuthorizationResponse(
            session.authorization_request,
            {
              state: session.authorization_request.state,
              vp_token: { query_0: [presentation] },
            },
            enc,
          ),
        });

      expect(response.status).toBe(200);
      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.status).toBe("presentation_validated");
      expect(capture.raw?.presentation_response_decrypted).toMatchObject({
        vp_token: { query_0: [presentation] },
      });
      expect(capture.events.map((event) => event.type)).not.toContain(
        "vp_undecryptable_response_allowed",
      );
    },
  );

  it("acknowledges and exposes an encrypted wallet Authorization Error Response", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const errorResponse = {
      error: "access_denied",
      error_description: "The End-User declined the presentation",
      state: session.authorization_request.state,
    };

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(
          session.authorization_request,
          errorResponse,
        ),
      });

    expect(response.status, response.text).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.body).toEqual({});
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks).toMatchObject({
      presentation_valid: false,
      vp_token_format_valid: false,
    });
    expect(capture.raw?.presentation_response).toEqual({ response: expect.any(String) });
    expect(capture.raw?.presentation_response_decrypted).toEqual(errorResponse);
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        type: "vp_presentation_response_received",
        detail: expect.objectContaining({ vp_token_observed: false }),
      }),
    );
  });

  it("retains an encrypted VP token after Credo rejects its DCQL match", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const presentation = await sdJwtPresentation({
      credential: await pidSdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    const walletResponse = {
      state: session.authorization_request.state,
      vp_token: { query_0: [presentation] },
    };

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(
          session.authorization_request,
          walletResponse,
        ),
      });

    expect(response.status, response.text).toBe(400);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.vp_token_format_valid).toBe(true);
    expect(capture.checks.errors).not.toHaveLength(0);
    expect(capture.raw?.presentation_response_decrypted).toEqual(walletResponse);
    expect(capture.raw?.presentation_response_decrypted).not.toHaveProperty("error");
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        type: "vp_presentation_response_received",
        detail: expect.objectContaining({ vp_token_observed: true }),
      }),
    );
  });

  it("accepts SD-JWT VC presentations that satisfy a required DCQL credential_set option", async () => {
    const app = createApp(config);
    const dcqlQuery = {
      credentials: [
        {
          id: "pid_sd",
          format: "dc+sd-jwt",
          meta: { vct_values: [PID_SD_JWT_VCT] },
          claims: [{ path: ["family_name"] }],
        },
        {
          id: "pid_alt",
          format: "dc+sd-jwt",
          meta: { vct_values: [PID_SD_JWT_VCT] },
          claims: [{ path: ["given_name"] }],
        },
      ],
      credential_sets: [
        {
          options: [["pid_sd"], ["pid_alt"]],
        },
      ],
    };
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlQuery,
      },
    });
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: JSON.stringify({ pid_sd: [presentation] }),
      });

    expect(response.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.dcql_query_matched).toBe(true);
    expect(capture.raw?.presentation_response_decrypted?.vp_token).toEqual({
      pid_sd: [presentation],
    });
  });

  it("captures wallet metadata for a client-metadata-free OpenID4VP request_uri POST", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
      response_mode: "direct_post",
      client_metadata: null,
      dcql_query: dcqlForClaims(["family_name"]),
    });

    const requestObject = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/request`)
      .type("form")
      .send({ wallet_nonce: "wallet-nonce-123", wallet_metadata: "present" });

    expect(requestObject.status).toBe(200);
    expect(requestObject.type).toBe("application/oauth-authz-req+jwt");
    const claims = decodeJwt(requestObject.text) as JsonRecord;
    expect(claims.wallet_nonce).toBe("wallet-nonce-123");
    expect(claims.client_metadata).toBeUndefined();

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.observed.request_uri_payload.value).toMatchObject({
      wallet_nonce: "wallet-nonce-123",
      wallet_metadata: "present",
    });
    expect(capture.observed.request_uri_payload.source).toBe("request_uri.post");
    expect(capture.authorization_request.wallet_nonce).toBe("wallet-nonce-123");
    expect(capture.raw?.authorization_request_jwt).toBe(requestObject.text);
    expect(capture.raw?.request_uri_http).toMatchObject({
      method: "POST",
      target: `/openid4vp/sessions/${session.session_id}/request`,
      headers: {
        "content-type": expect.stringContaining("application/x-www-form-urlencoded"),
      },
      body: "wallet_nonce=wallet-nonce-123&wallet_metadata=present",
    });
  });
});
