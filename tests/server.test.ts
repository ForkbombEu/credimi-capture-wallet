import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Kms, X509Certificate } from "@credo-ts/core";
import { IssuerSigned } from "@owf/mdoc";
import type { Express } from "express";
import {
  CompactEncrypt,
  type JWK,
  type KeyLike,
  SignJWT,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG, initIssuer } from "../src/config.js";
import {
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "../src/credential-definitions.js";
import { CREDIMI_LOGO_URL, issueSdJwtCredential } from "../src/credential.js";
import { mdocCredentialConfigurationId } from "../src/metadata.js";
import { createApp } from "../src/server.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { unsignedJwt } from "./helpers.js";

const dataDir = mkdtempSync(join(tmpdir(), "fake-issuer-test-"));
const config = {
  ...DEFAULT_CONFIG,
  issuer_base_url: "http://issuer.example.test",
  data_dir: dataDir,
};

beforeAll(async () => {
  await initIssuer({
    issuer_base_url: config.issuer_base_url,
    data_dir: dataDir,
    credential_configuration_id: config.credential_configuration_id,
    force: true,
  });
});

afterAll(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("capture issuer server", () => {
  it("serves a launcher button that opens new GUI sessions in a new tab", async () => {
    const app = createApp(config);
    const response = await request(app).get("/");

    expect(response.status).toBe(200);
    expect(response.text).toContain(
      "Step 1) Start a one-time fake issuance flow, scan the offer, and inspect the wallet identifiers, callbacks, and proof keys observed by the issuer.",
    );
    expect(response.text).toContain(
      "Step 2) After receiving the credential, start a Presentation session, and inspect the Wallet response as well as the DCQL",
    );
    expect(response.text).toContain("New fake-issuance session");
    expect(response.text).toContain("session-actions");
    expect(response.text).toContain('formaction="/ui/openid4vp/sessions"');
    expect(response.text).toContain("<h2>Captured values</h2>");
    expect(response.text).toContain('<span class="count-chip">10</span>');
    expect(response.text).toContain("<h3>OpenID4VCI</h3>");
    expect(response.text).toContain("<h3>OpenID4VP</h3>");
    expect(response.text).toContain("<dt>wallet_jwks</dt>");
    expect(response.text).toContain("<dt>authorization_request</dt>");
    expect(response.text).toContain("<dt>request_uri_payload</dt>");
    expect(response.text).toContain("<dt>wallet_response</dt>");
    expect(response.text).toContain("<dt>presentation_response_decrypted</dt>");
    expect(response.text).toContain("<dt>decoded_presentations</dt>");
    expect(response.text).toContain("<dt>presentation_validation</dt>");
    expect(response.text).not.toContain("<dt>presentation_submission</dt>");
    expect(response.text).toContain('<select name="credential_configuration_id">');
    expect(response.text).toContain("Credimi Demo PID (SD-JWT VC, proof JWT)");
    expect(response.text).toContain("Credimi Demo PID (MDOC, proof JWT)");
    expect(response.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(response.text).toContain(
      '<span class="status-chip status-issuer">ISSUER READY</span><span class="status-chip status-wallet">VERIFIER READY</span><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/fake-issuer/blob/master/README.md"',
    );
    expect(response.text).toContain('target="_blank"');
    expect(response.text).toContain("Wallet metadata capture%c Credimi capture UI");
    expect(response.text).toContain('href="https://credimi.io/logos/credimi_logo.svg"');
    expect(response.text).toContain('href="https://forkbomb.eu"');
    expect(response.text).toContain("Developed by Forkbomb BV");
    expect(response.text).toContain('href="https://github.com/ForkbombEu/fake-issuer"');
    expect(response.text).toContain("Fork me on GitHub");
    expect(response.text).toContain(
      '<img class="footer-logo" src="/assets/credimi_logo_negative.svg" alt="" aria-hidden="true">',
    );
  });

  it("serves the Credimi logo asset for the launcher topbar", async () => {
    const app = createApp(config);
    const response = await request(app).get("/assets/credimi_logo.svg");

    expect(response.status).toBe(200);
    expect(response.type).toBe("image/svg+xml");
    expect(response.body.toString("utf8")).toContain("<svg");
  });

  it("serves the negative Credimi logo asset for the footer", async () => {
    const app = createApp(config);
    const response = await request(app).get("/assets/credimi_logo_negative.svg");

    expect(response.status).toBe(200);
    expect(response.type).toBe("image/svg+xml");
    expect(response.body.toString("utf8")).toContain("<svg");
  });

  it("renders README help with the GUI stylesheet", async () => {
    const app = createApp(config);
    const response = await request(app).get("/ui/help");

    expect(response.status).toBe(200);
    expect(response.text).toContain("Wallet Metadata Capture Help");
    expect(response.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(response.text).toContain("Credimi Fake VCI Capture Issuer");
    expect(response.text).toContain("readme-card");
  });

  it("can disable GUI routes while leaving API routes available", async () => {
    const app = createApp({ ...config, gui_enabled: false });

    expect((await request(app).get("/")).status).toBe(404);
    expect((await request(app).get("/ui/help")).status).toBe(404);
    expect((await request(app).post("/ui/sessions")).status).toBe(404);

    const apiSession = await request(app).post("/sessions").send({});
    expect(apiSession.status).toBe(201);
  });

  it("creates GUI sessions and renders a QR deeplink page", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);

    expect(created.status).toBe(303);
    expect(created.headers.location).toMatch(/^\/ui\/sessions\//);

    const page = await request(app).get(created.headers.location ?? "");
    expect(page.status).toBe(200);
    expect(page.text).toContain("<svg");
    expect(page.text).toContain("openid-credential-offer://");
    expect(page.text).toContain("Scan the credential offer");
    expect(page.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(page.text).toContain("Scan the offer and accept it in the wallet");
    expect(page.text).toContain("Same content as the QR code");
    expect(page.text).toContain("metadata-pending");
    expect(page.text).toContain("metadata-state-waiting");
    expect(page.text).toContain("metadata-state-receiving");
    expect(page.text).toContain("credentialRequestArrived");
    expect(page.text).toContain("window.clearInterval(pollTimer)");
    expect(page.text).toContain("pollTimer = setInterval");
    expect(page.text).toContain(
      '<span class="status-chip status-issuer" id="status-label">waiting</span><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/fake-issuer/blob/master/README.md"',
    );
    expect(page.text).not.toContain("updated-label");
    expect(page.text).toContain("Wallet metadata");
    expect(page.text).toContain(".metadata-row summary::after { content: '\\02C5'");
    expect(page.text).toContain(".metadata-row[open] summary::after { content: '\\02C4'");
    expect(page.text.match(/<details class="metadata-row"><summary>/g)).toHaveLength(4);
    expect(page.text).toContain("<summary>client_id</summary><code>pending</code>");
    expect(page.text).toContain('querySelectorAll(".metadata-row[open]")');
    expect(page.text).toContain("openFields.has(row[0])");
  });

  it("creates GUI OpenID4VP sessions and renders a presentation QR page", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/openid4vp/sessions").redirects(0);

    expect(created.status).toBe(303);
    expect(created.headers.location).toMatch(/^\/ui\/openid4vp\/sessions\//);

    const page = await request(app).get(created.headers.location ?? "");
    expect(page.status).toBe(200);
    expect(page.text).toContain("<svg");
    expect(page.text).toContain("openid4vp://");
    expect(page.text).toContain("Scan the presentation request");
    expect(page.text).toContain("Presentation response");
    expect(page.text).toContain("authorization_request");
    expect(page.text).toContain("request_uri_payload");
    expect(page.text).toContain("wallet_response");
    expect(page.text).toContain("presentation_response_decrypted");
    expect(page.text).not.toContain("presentation_submission");
    expect(page.text).toContain("formatJsonValue(session.authorization_request)");
    expect(page.text).toContain("formatJsonValue(session.raw.presentation_response_decrypted)");
    expect(page.text).toContain("formatJsonValue(session.raw.decoded_presentations)");
    expect(page.text).toContain("JSON.stringify(parsed, null, 4)");
    expect(page.text).toContain(".metadata-row summary::after { content: '\\02C5'");
    expect(page.text).toContain(".metadata-row[open] summary::after { content: '\\02C4'");
    expect(page.text).toContain("white-space: pre-wrap");
    expect(page.text.indexOf("authorization_request")).toBeLessThan(
      page.text.indexOf("request_uri_payload"),
    );
    expect(page.text.indexOf("request_uri_payload")).toBeLessThan(
      page.text.indexOf("wallet_response"),
    );
    expect(page.text).toContain("window.clearInterval(pollTimer)");
    expect(page.text).toContain("pollTimer = setInterval");
    expect(page.text).toContain("__FAKE_ISSUER_VP_SESSION_ID__");
    expect(page.text.match(/<details class="metadata-row"><summary>/g)).toHaveLength(6);
    expect(page.text).toContain(
      "<summary>presentation_response_decrypted</summary><code>pending</code>",
    );
    expect(page.text).toContain("<summary>decoded_presentations</summary><code>pending</code>");
    expect(page.text).toContain("<summary>presentation_validation</summary><code>pending</code>");
    expect(page.text).toContain('querySelectorAll(".metadata-row[open]")');
    expect(page.text).toContain("openFields.has(row[0])");
  });

  it("creates GUI OpenID4VP sessions for the selected credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = mdocCredentialConfigurationId(config);
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    const dcqlQuery = requestObjectClaims.dcql_query as JsonRecord;
    const dcqlCredentials = dcqlQuery.credentials as JsonRecord[];

    expect(requestObjectClaims.presentation_definition).toBeUndefined();
    expect(dcqlCredentials).toHaveLength(1);
    expect(dcqlCredentials[0]?.format).toBe("mso_mdoc");
    expect(dcqlCredentials[0]?.meta).toEqual({ doctype_value: PID_MDOC_DOCTYPE });
    expect((dcqlCredentials[0]?.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
    );
  });

  it("creates OpenID4VP sessions with a valid presentation request", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });

    expect(session.status).toBe("created");
    expect(session.request_uri_method).toBe("get");
    expect(session.request_uri).toBe(
      `${config.issuer_base_url}/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(session.response_uri).toMatch(
      new RegExp(
        `^${escapeRegExp(
          `${config.issuer_base_url}/openid4vp/sessions/${session.session_id}/response`,
        )}`,
      ),
    );
    expect(session.deeplink).toContain("openid4vp://");
    expect(session.deeplink).toContain(encodeURIComponent(session.request_uri));
    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("client_id")).toMatch(/^x509_hash:/);
    expect(deeplink.searchParams.get("request_uri")).toBe(session.request_uri);
    expect(deeplink.searchParams.has("request_uri_method")).toBe(false);
    expect(deeplink.searchParams.has("response_uri")).toBe(false);
    expect(deeplink.searchParams.has("client_id_scheme")).toBe(false);
    expect(deeplink.searchParams.has("response_type")).toBe(false);
    expect(session.authorization_request.response_type).toBe("vp_token");
    expect(session.authorization_request.response_mode).toBe("direct_post.jwt");
    expect(session.authorization_request.aud).toEqual(
      expect.stringContaining(`/openid4vp/sessions/${session.session_id}/request/`),
    );
    expect(session.authorization_request.request_uri_method).toBeUndefined();
    expect(session.authorization_request.client_id).toMatch(/^x509_hash:/);
    expect(session.authorization_request.client_id_scheme).toBeUndefined();
    expect(session.authorization_request.client_metadata).toMatchObject({
      jwks: { keys: [expect.objectContaining({ use: "enc", alg: "ECDH-ES" })] },
      encrypted_response_enc_values_supported: ["A128GCM", "A256GCM", "A128CBC-HS256"],
      vp_formats_supported: {
        "dc+sd-jwt": expect.objectContaining({
          "sd-jwt_alg_values": expect.arrayContaining(["ES256"]),
          "kb-jwt_alg_values": expect.arrayContaining(["ES256"]),
        }),
      },
    });
    expect(session.authorization_request.presentation_definition).toBeUndefined();
    expect(session.authorization_request.dcql_query).toEqual(expect.any(Object));
    const dcqlQuery = session.authorization_request.dcql_query as JsonRecord;
    const dcqlCredentials = dcqlQuery.credentials as JsonRecord[];
    const sdJwtCredential = dcqlCredentials.find((credential) => credential.format === "dc+sd-jwt");
    expect(sdJwtCredential?.meta).toEqual({ vct_values: [PID_SD_JWT_VCT] });
    expect((sdJwtCredential?.claims as JsonRecord[]).map((claim) => claim.path)).toEqual([
      ["family_name"],
      ["given_name"],
    ]);
  });

  it("creates OpenID4VP sessions that advertise request_uri_method post", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
      dcql_query: dcqlForClaims(["family_name"]),
    });

    const deeplink = new URL(session.deeplink);
    expect(session.request_uri_method).toBe("post");
    expect(deeplink.searchParams.get("request_uri_method")).toBe("post");
    expect(session.authorization_request.request_uri_method).toBeUndefined();
  });

  it("rejects unsupported OpenID4VP request_uri_method values", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ request_uri_method: "put" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "unsupported_request_uri_method" });
  });

  it("passes arbitrary DCQL queries through to OpenID4VP wallets", async () => {
    const app = createApp(config);
    const dcqlQuery = {
      credentials: [],
      credential_sets: [{ options: ["missing_credential"], required: true }],
      unknown_extension: { contradictory: true },
    };

    const response = await request(app).post("/openid4vp/sessions").send({ dcql_query: dcqlQuery });

    expect(response.status).toBe(201);
    expect(response.body.authorization_request.dcql_query).toEqual(dcqlQuery);
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${response.body.session_id}/request`,
    );
    expect(decodeJwt(requestObject.text).dcql_query).toEqual(dcqlQuery);
  });

  it("allows API callers to override the OpenID4VP presentation request", async () => {
    const app = createApp(config);
    const customDcql = {
      credentials: [
        {
          id: "email_credential",
          format: "dc+sd-jwt",
          meta: { vct_values: ["https://example.test/email"] },
          claims: [{ path: ["email"] }],
        },
      ],
    };

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        nonce: "external-nonce",
        dcql_query: customDcql,
      },
    });

    expect(session.authorization_request.nonce).toEqual(expect.any(String));
    expect(session.authorization_request.dcql_query).toEqual(customDcql);
    expect(session.authorization_request.state).toEqual(expect.any(String));
    expect(session.authorization_request.response_uri).toBe(session.response_uri);
  });

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
  });

  it("rejects SD-JWT VC presentations that do not disclose all requested DCQL claims", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const credential = await sdJwtCredential();
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
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const credential = await sdJwtCredential();
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
    expect(response.body).toEqual({});

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
    expect(capture.raw?.presentation_response_decrypted).toMatchObject({
      state: session.authorization_request.state,
      vp_token: { query_0: [presentation] },
    });
    expect(capture.decoded_presentations).toMatchObject({
      query_0: [
        {
          format: "dc+sd-jwt",
          claims: {
            vct: PID_SD_JWT_VCT,
            family_name: "Doe",
            given_name: "Jane",
          },
        },
      ],
    });
    expect(capture.raw?.decoded_presentations).toEqual(capture.decoded_presentations);
    expect(JSON.stringify(capture.decoded_presentations)).not.toContain(presentation);
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
    const credential = await sdJwtCredential();
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

  it("captures OpenID4VP request_uri POST payloads", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
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
  });

  it("marks GUI QR sessions consumed when the wallet retrieves the offer", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    const initial = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(initial.status).toBe("created");

    const offer = await request(app).get(`/sessions/${sessionId}/offer`);
    expect(offer.status).toBe(200);

    const consumed = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(consumed.status).toBe("offer_retrieved");
  });
  it("creates session offers for the requested credential configuration", async () => {
    const app = createApp(config);
    const requestedCredentialConfigurationId = mdocCredentialConfigurationId(config);

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: requestedCredentialConfigurationId,
    });
    const offer = await getJson<CredentialOfferResponse>(
      app,
      `/sessions/${session.session_id}/offer`,
    );

    expect(session.credential_configuration_id).toBe(requestedCredentialConfigurationId);
    expect(offer.credential_configuration_ids).toEqual([requestedCredentialConfigurationId]);
  });

  it("serves issuer JWKS with the self-signed certificate chain", async () => {
    const app = createApp(config);
    const jwks = await getJson<JwksResponse>(app, "/jwks.json");

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]?.x5c).toEqual([expect.any(String)]);
    const certificate = X509Certificate.fromEncodedCertificate((jwks.keys[0]?.x5c as string[])[0]);
    expect(Kms.PublicJwk.fromUnknown(jwks.keys[0]).equals(certificate.publicJwk)).toBe(true);
  });

  it("issues an MDOC PID credential for the selected MDOC configuration", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: mdocCredentialConfigurationId(config),
    });
    const verifier = "mdoc-pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postPar(app, {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: `${config.credential_scope}.mdoc.jwt`,
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const dpop = await dpopKey();
    const token = await postToken(
      app,
      {
        grant_type: "authorization_code",
        code: code ?? "",
        client_id: "wallet-client",
        redirect_uri: "https://wallet.example/callback",
        code_verifier: verifier,
      },
      dpop,
    );
    const walletKey = await dpopKey();
    const refreshedNonce = await request(app).post("/nonce");
    expect(refreshedNonce.status).toBe(200);
    const proof = await credentialProofJwt(walletKey, String(refreshedNonce.body.c_nonce));

    const credential = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", "/credential"))
      .send({ proof: { proof_type: "jwt", jwt: proof } });

    expect(credential.status, JSON.stringify(credential.body)).toBe(200);
    const encodedMdoc = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = IssuerSigned.fromEncodedForOid4Vci(encodedMdoc);

    expect(session.credential_configuration_id).toBe(mdocCredentialConfigurationId(config));
    expect(decoded.issuerAuth.mobileSecurityObject.docType).toBe(PID_MDOC_DOCTYPE);
    const namespace = decoded.getPrettyClaims(PID_MDOC_NAMESPACE) as JsonRecord | undefined;
    expect(namespace?.given_name).toBe("Jane");
    expect(namespace?.resident_country).toBe("IT");
    const portrait = namespace?.portrait;
    expect(portrait).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(portrait as Uint8Array).subarray(0, 3)).toEqual(
      Buffer.from([0xff, 0xd8, 0xff]),
    );
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("credential_issued");
  });

  it("stores PAR and merges it into authorize requests", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "correct horse battery staple";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postPar(app, {
      client_id: "wallet-client",
      redirect_uri: "eudi-wallet://callback",
      response_type: "code",
      state: "wallet-state",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: `${config.credential_scope}.jwt`,
    });

    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);

    expect(authorize.status).toBe(302);
    const location = new URL(authorize.headers.location ?? "");
    expect(location.protocol).toBe("eudi-wallet:");
    expect(location.searchParams.get("state")).toBe("wallet-state");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("iss")).toBe(config.issuer_base_url);

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.observed.client_id.value).toBe("wallet-client");
    expect(capture.observed.redirect_uri.value).toBe("eudi-wallet://callback");
    expect(capture.raw?.authorization_request?.client_id).toBe("wallet-client");
  });

  it("rejects PAR requests without client authentication", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const response = await request(app)
      .post("/par")
      .type("form")
      .send({
        client_id: "wallet-client",
        redirect_uri: "https://wallet.example/callback",
        state: "abc",
        issuer_state: session.session_id,
        code_challenge: createHash("sha256").update("verifier").digest("base64url"),
        code_challenge_method: "S256",
        scope: `${config.credential_scope}.jwt`,
      });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_client" });
  });

  it("logs PAR and authorization resolution without sensitive assertions", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => {
      logs.push(line);
    });
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const par = await postPar(app, {
      client_id: "wallet-client",
      redirect_uri: "eudi-wallet://callback",
      response_type: "code",
      state: "wallet-state",
      issuer_state: session.session_id,
      code_challenge: "challenge",
      code_challenge_method: "S256",
      scope: `${config.credential_scope}.jwt`,
    });

    await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);

    const entries = logs.map((line) => JSON.parse(line) as JsonRecord);
    expect(entries.map((entry) => entry.event)).toEqual([
      "http.request",
      "par.stored",
      "http.request",
      "authorize.received",
      "authorize.redirect",
    ]);
    expect(entries[0]).toMatchObject({
      component: "fake-issuer",
      event: "http.request",
      method: "POST",
      path: "/par",
    });
    expect(entries[1]).toMatchObject({
      component: "fake-issuer",
      request_uri: par.request_uri,
      session_id: session.session_id,
      client_id: "wallet-client",
      has_redirect_uri: true,
      has_client_assertion: false,
      has_pkce: true,
    });
    expect(entries[2]).toMatchObject({
      component: "fake-issuer",
      event: "http.request",
      method: "GET",
      path: "/authorize",
    });
    expect(entries[3]).toMatchObject({
      request_uri: par.request_uri,
      par_resolution: "resolved",
      session_id: session.session_id,
      has_redirect_uri: true,
    });
    expect(entries[4]).toMatchObject({
      request_uri: par.request_uri,
      par_resolution: "resolved",
      session_id: session.session_id,
      redirect_uri: "eudi-wallet://callback",
      state_present: true,
    });
    expect(logs.join("\n")).not.toContain("sensitive.jwt.assertion");
  });

  it("makes credential nonce responses uncacheable", async () => {
    const app = createApp(config);
    const response = await request(app).post("/nonce");

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toMatchObject({
      c_nonce: expect.any(String),
      c_nonce_expires_in: config.nonce_ttl_seconds,
    });
  });

  it("rejects token requests without DPoP", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postPar(app, {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: `${config.credential_scope}.jwt`,
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const response = await request(app)
      .post("/token")
      .set(walletClientAuthenticationHeaders("wallet-client", config.issuer_base_url))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: code ?? "",
        client_id: "wallet-client",
        redirect_uri: "https://wallet.example/callback",
        code_verifier: verifier,
      });

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({ error: "invalid_dpop_proof" });
  });

  it("verifies PKCE and captures credential proof JWKS", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postPar(app, {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: `${config.credential_scope}.jwt`,
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const dpop = await dpopKey();
    const token = await postToken(
      app,
      {
        grant_type: "authorization_code",
        code: code ?? "",
        client_id: "wallet-client",
        redirect_uri: "https://wallet.example/callback",
        code_verifier: verifier,
      },
      dpop,
    );

    const walletKey = await dpopKey();
    const proof = await credentialProofJwt(walletKey, token.c_nonce);
    const credential = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", "/credential"))
      .send({ proof: { proof_type: "jwt", jwt: proof } });

    expect(credential.status).toBe(200);
    expect(credential.body).toEqual({
      credentials: [
        {
          credential: expect.any(String),
        },
      ],
    });
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    expect(compactSdJwt.split("~").length).toBeGreaterThan(2);
    const issuerJwt = compactSdJwt.split("~")[0];
    const issuerPayload = JSON.parse(
      Buffer.from(issuerJwt.split(".")[1], "base64url").toString("utf8"),
    ) as JsonRecord;
    const issuerHeader = JSON.parse(
      Buffer.from(issuerJwt.split(".")[0], "base64url").toString("utf8"),
    ) as JsonRecord;
    const issuerCertificate = X509Certificate.fromEncodedCertificate(
      (issuerHeader.x5c as string[])[0],
    );
    const verified = await compactVerify(
      issuerJwt,
      await importJWK(issuerCertificate.publicJwk.toJson(), "ES256"),
    );
    expect(issuerPayload.iss).toBe(config.issuer_base_url);
    expect(issuerPayload.iss).not.toMatch(/^did:/);
    expect(verified.protectedHeader).toMatchObject({
      alg: "ES256",
      typ: "dc+sd-jwt",
      x5c: expect.any(Array),
    });

    const decoded = new (await import("@credo-ts/core")).SdJwtVcService({} as never).fromCompact(
      compactSdJwt,
    );
    expect(decoded.prettyClaims).toMatchObject({
      vct: PID_SD_JWT_VCT,
      address: {
        country: "IT",
        formatted: "Via Europa 1, 00100 Roma, IT",
        house_number: "1",
        locality: "Roma",
        postal_code: "00100",
        region: "Lazio",
        street_address: "Via Europa",
      },
      birth_family_name: "Doe",
      birth_given_name: "Jane",
      birthdate: "1990-01-01",
      date_of_expiry: "2031-01-01",
      date_of_issuance: "2026-01-01",
      document_number: "CREDIMI-DEMO-001",
      email: "jane.doe@example.test",
      given_name: "Jane",
      family_name: "Doe",
      issuing_authority: "Credimi Fake Issuer",
      issuing_country: "IT",
      issuing_jurisdiction: "IT",
      nationalities: ["IT"],
      personal_administrative_number: "PID-DEMO-001",
      phone_number: "+390600000000",
      picture: expect.stringMatching(/^data:image\/jpeg;base64,\/9j\//),
      place_of_birth: "Roma",
      sex: 2,
      cnf: { jwk: walletKey.publicJwk },
    });
    expect(decoded.holder?.method).toBe("jwk");
    if (decoded.holder?.method !== "jwk") throw new Error("expected JWK holder binding");
    expect(Kms.PublicJwk.fromUnknown(walletKey.publicJwk).equals(decoded.holder.jwk)).toBe(true);
    const walletJwks = await getJson<JwksResponse>(app, `/sessions/${session.session_id}/jwks`);
    expect(walletJwks.keys).toHaveLength(1);
    expect(walletJwks.keys[0]).toMatchObject({ ...walletKey.publicJwk, alg: "ES256", use: "sig" });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.checks.pkce_valid).toBe(true);
    expect(capture.checks.proof_jwt_header_jwk_present).toBe(true);
    expect(capture.status).toBe("credential_issued");
  });

  it("rejects credential issuance without an access token", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/credential")
      .send({ proof: { proof_type: "jwt", jwt: unsignedJwt({ alg: "ES256", kid: "key-1" }) } });

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({ error: "invalid_token" });
  });

  it("captures wallet attestation client authentication on token requests", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postPar(app, {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: `${config.credential_scope}.jwt`,
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const attestation = unsignedJwt(
      { alg: "ES256", typ: "oauth-client-attestation+jwt", kid: "attester-key" },
      { sub: "wallet-client", cnf: { jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" } } },
    );
    const pop = unsignedJwt(
      { alg: "ES256", typ: "oauth-client-attestation-pop+jwt", kid: "instance-key" },
      { iss: "wallet-client", aud: config.issuer_base_url, challenge: "token-nonce" },
    );

    const dpop = await dpopKey();
    const token = await request(app)
      .post("/token")
      .set("OAuth-Client-Attestation", attestation)
      .set("OAuth-Client-Attestation-PoP", pop)
      .set("DPoP", await dpopProof(dpop, "POST", "/token"))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: code ?? "",
        client_id: "wallet-client",
        redirect_uri: "https://wallet.example/callback",
        code_verifier: verifier,
      });

    expect(token.status).toBe(200);
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.observed.client_authentication.method).toBe("wallet_attestation");
    expect(capture.checks.wallet_attestation_present).toBe(true);
    expect(capture.checks.wallet_attestation_pop_present).toBe(true);
    expect(capture.checks.wallet_attestation_client_id_matches).toBe(true);
    expect(capture.checks.wallet_attestation_pop_audience_matches).toBe(true);
  });

  it("returns a clear JWKS failure before a wallet key is observed", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const response = await request(app).get(`/sessions/${session.session_id}/jwks`);

    expect(response.status).toBe(409);
    expect(response.body).toMatchObject({ error: "wallet_jwks_not_observed" });
  });

  it("rejects sessions for unsupported credential configurations", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/sessions")
      .send({ credential_configuration_id: "unknown.credential" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "unsupported_credential_configuration" });
  });
});

async function postJson<T>(app: Express, path: string, body: object): Promise<T> {
  const response = await request(app).post(path).send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function postForm<T>(app: Express, path: string, body: Record<string, string>): Promise<T> {
  const response = await request(app).post(path).type("form").send(body);
  if (path === "/par") expect(response.status).toBe(201);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function postPar(app: Express, body: Record<string, string>): Promise<ParResponse> {
  const response = await request(app)
    .post("/par")
    .set(walletClientAuthenticationHeaders(body.client_id, config.issuer_base_url))
    .type("form")
    .send({ ...body, scope: body.scope ?? config.credential_scope });
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return response.body as ParResponse;
}

async function postToken(
  app: Express,
  body: Record<string, string>,
  dpopKey: DpopKey,
): Promise<TokenResponse> {
  const response = await request(app)
    .post("/token")
    .set(walletClientAuthenticationHeaders(body.client_id, config.issuer_base_url))
    .set("DPoP", await dpopProof(dpopKey, "POST", "/token"))
    .type("form")
    .send(body);
  expect(response.status, JSON.stringify(response.body)).toBeLessThan(400);
  return response.body as TokenResponse;
}

async function getJson<T>(app: Express, path: string): Promise<T> {
  const response = await request(app).get(path);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

function dcqlForClaims(claims: string[]): JsonRecord {
  return {
    credentials: [
      {
        id: "query_0",
        format: "dc+sd-jwt",
        meta: {
          vct_values: [PID_SD_JWT_VCT],
        },
        claims: claims.map((claim) => ({ path: [claim] })),
      },
    ],
  };
}

function endpointUrl(path: string): string {
  return `${config.issuer_base_url}${path}`;
}

function walletClientAuthenticationHeaders(
  clientId: string,
  audience: string,
): Record<string, string> {
  const attestation = unsignedJwt(
    { alg: "ES256", typ: "oauth-client-attestation+jwt", kid: "attester-key" },
    { sub: clientId, cnf: { jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" } } },
  );
  const pop = unsignedJwt(
    { alg: "ES256", typ: "oauth-client-attestation-pop+jwt", kid: "instance-key" },
    { iss: clientId, aud: audience, challenge: "token-nonce" },
  );
  return {
    "OAuth-Client-Attestation": attestation,
    "OAuth-Client-Attestation-PoP": pop,
  };
}

interface DpopKey {
  publicJwk: JsonRecord;
  privateKey: KeyLike | Uint8Array;
}

async function dpopKey(): Promise<DpopKey> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    publicJwk: (await exportJWK(publicKey)) as unknown as JsonRecord,
    privateKey,
  };
}

async function dpopProof(key: DpopKey, method: string, path: string): Promise<string> {
  return new SignJWT({
    htm: method,
    htu: endpointUrl(path),
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: key.publicJwk as unknown as JWK })
    .sign(key.privateKey);
}

async function credentialProofJwt(
  key: DpopKey,
  nonce: string,
  audience = config.issuer_base_url,
): Promise<string> {
  return new SignJWT({
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: key.publicJwk as unknown as JWK,
    })
    .sign(key.privateKey);
}

async function sdJwtCredential(): Promise<{
  compact: string;
  privateKey: Parameters<SignJWT["sign"]>[0];
}> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const holderJwk = (await exportJWK(publicKey)) as unknown as JsonRecord;
  return {
    compact: await issueSdJwtCredential({
      config,
      credentialConfigurationId: config.credential_configuration_id,
      holderJwk,
    }),
    privateKey,
  };
}

async function sdJwtPresentation(options: {
  credential: { compact: string; privateKey: Parameters<SignJWT["sign"]>[0] };
  authorizationRequest: JsonRecord;
  disclosedClaims: string[];
}): Promise<string> {
  const [issuerJwt, ...tail] = options.credential.compact.split("~");
  const selected = tail
    .filter((part) => part.length > 0)
    .filter((disclosure) => options.disclosedClaims.includes(disclosureClaimName(disclosure)));
  const withoutKeyBinding = `${issuerJwt}~${selected.join("~")}~`;
  const keyBindingJwt = await new SignJWT({
    iat: Math.floor(Date.now() / 1000),
    aud: String(options.authorizationRequest.client_id),
    nonce: String(options.authorizationRequest.nonce),
    sd_hash: createHash("sha256").update(withoutKeyBinding).digest("base64url"),
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
    .sign(options.credential.privateKey);
  return `${withoutKeyBinding}${keyBindingJwt}`;
}

async function encryptedAuthorizationResponse(
  authorizationRequest: JsonRecord,
  payload: JsonRecord,
): Promise<string> {
  const clientMetadata = authorizationRequest.client_metadata as JsonRecord;
  const jwks = clientMetadata.jwks as { keys: JsonRecord[] };
  const publicJwk = jwks.keys[0] as unknown as JWK;
  return new CompactEncrypt(Buffer.from(JSON.stringify(payload), "utf8"))
    .setProtectedHeader({
      alg: "ECDH-ES",
      enc: "A256GCM",
      kid: publicJwk.kid,
    })
    .encrypt(await importJWK(publicJwk, "ECDH-ES"));
}

function disclosureClaimName(disclosure: string): string {
  const decoded = JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[];
  return typeof decoded[1] === "string" ? decoded[1] : "";
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

interface SessionCreateResponse extends JsonRecord {
  session_id: string;
  credential_configuration_id: string;
}

interface ParResponse extends JsonRecord {
  request_uri: string;
}

interface TokenResponse extends JsonRecord {
  access_token: string;
  c_nonce: string;
}

interface JwksResponse extends JsonRecord {
  keys: JsonRecord[];
}

interface CredentialOfferResponse extends JsonRecord {
  credential_configuration_ids: string[];
}

interface CredentialResponse extends JsonRecord {
  credentials: Array<{
    credential: string;
  }>;
}

interface VpSessionCreateResponse extends JsonRecord {
  session_id: string;
  request_uri: string;
  request_uri_method: "get" | "post";
  response_uri: string;
  deeplink: string;
  authorization_request: JsonRecord;
  status: string;
}

interface VpSessionResponse extends JsonRecord {
  session_id: string;
  status: string;
  authorization_request: JsonRecord;
  decoded_presentations?: JsonRecord;
  checks: {
    presentation_valid: boolean | null;
    nonce_verified: boolean;
    holder_binding_verified: boolean;
    dcql_query_matched: boolean;
    errors: string[];
  };
  observed: {
    vp_token?: { value: unknown };
    request_uri_payload: { value: JsonRecord | null; source: string | null };
    wallet_response: { value: JsonRecord | null };
    presentation_submission?: { value: unknown };
  };
  raw?: {
    presentation_response?: JsonRecord;
    presentation_response_decrypted?: JsonRecord;
    decoded_presentations?: JsonRecord;
  };
}
