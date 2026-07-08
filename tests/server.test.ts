import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseIssuerSigned } from "@animo-id/mdoc";
import { Kms, X509Certificate } from "@credo-ts/core";
import type { Express } from "express";
import { type JWK, compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, initIssuer } from "../src/config.js";
import { CREDIMI_LOGO_URL, CREDIMI_WEBSITE } from "../src/credential.js";
import { PID_MDOC_DOCTYPE, mdocCredentialConfigurationId } from "../src/metadata.js";
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
    expect(response.text).toContain('<select name="credential_configuration_id">');
    expect(response.text).toContain("Credimi Demo PID (SD-JWT VC, proof JWT)");
    expect(response.text).toContain("Credimi Demo PID (MDOC, proof JWT)");
    expect(response.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(response.text).toContain(
      '<span class="status-chip status-issuer">ISSUER READY</span><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/fake-issuer/blob/master/README.md"',
    );
    expect(response.text).toContain('target="_blank"');
    expect(response.text).toContain("Fake Issuer%c Credimi capture UI");
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
    expect(response.text).toContain("Fake Issuer Help");
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
    expect(page.text).toContain("Scan with an EUDI Wallet");
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
    expect(page.text).not.toContain("presentation_submission");
    expect(page.text).toContain("formatJsonValue(session.authorization_request)");
    expect(page.text).toContain("JSON.stringify(parsed, null, 4)");
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
    const presentationDefinition = requestObjectClaims.presentation_definition as JsonRecord;
    const inputDescriptors = presentationDefinition.input_descriptors as JsonRecord[];
    const dcqlQuery = requestObjectClaims.dcql_query as JsonRecord;
    const dcqlCredentials = dcqlQuery.credentials as JsonRecord[];

    expect(inputDescriptors).toHaveLength(1);
    expect(inputDescriptors[0]?.id).toBe(selectedCredentialConfigurationId);
    expect(dcqlCredentials).toHaveLength(1);
    expect(dcqlCredentials[0]?.format).toBe("mso_mdoc");
  });

  it("creates OpenID4VP sessions with a default presentation request", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {});

    expect(session.status).toBe("created");
    expect(session.request_uri_method).toBe("get");
    expect(session.request_uri).toBe(
      `${config.issuer_base_url}/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(session.response_uri).toBe(
      `${config.issuer_base_url}/openid4vp/sessions/${session.session_id}/response`,
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
    expect(session.authorization_request.response_mode).toBe("direct_post");
    expect(session.authorization_request.request_uri_method).toBeUndefined();
    expect(session.authorization_request.client_id).toMatch(/^x509_hash:/);
    expect(session.authorization_request.client_id_scheme).toBeUndefined();
    expect(session.authorization_request.client_metadata).toMatchObject({
      vp_formats_supported: {
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256"],
          "kb-jwt_alg_values": ["ES256"],
        },
        mso_mdoc: {},
      },
    });
    expect(session.authorization_request.presentation_definition).toEqual(expect.any(Object));
    expect(session.authorization_request.dcql_query).toEqual(expect.any(Object));
  });

  it("creates OpenID4VP sessions that advertise request_uri_method post", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
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

    expect(session.authorization_request.nonce).toBe("external-nonce");
    expect(session.authorization_request.dcql_query).toEqual(customDcql);
    expect(session.authorization_request.state).toBe(session.session_id);
    expect(session.authorization_request.response_uri).toBe(session.response_uri);
  });

  it("serves OpenID4VP request_uri objects and captures wallet presentation responses", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {});

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
      kid: "credimi-fake-verifier-key",
      x5c: [expect.any(String)],
    });
    const verified = await compactVerify(
      requestObject.text,
      await importJWK(verifierCertificate.publicJwk.toJson() as JWK, "ES256"),
    );
    expect(verified.protectedHeader.typ).toBe("oauth-authz-req+jwt");
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    expect(requestObjectClaims.state).toBe(session.session_id);
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
        state: session.session_id,
        vp_token: "presentation-token",
      });
    expect(presentation.status).toBe(200);
    expect(presentation.body).toEqual({ status: "ok" });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_received");
    expect(capture.observed.vp_token).toBeUndefined();
    expect(capture.observed.wallet_response.value?.vp_token).toBe("presentation-token");
    expect(capture.observed.presentation_submission).toBeUndefined();
    expect(capture.raw?.presentation_response?.state).toBe(session.session_id);
  });

  it("captures OpenID4VP request_uri POST payloads", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
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
    const par = await postForm<ParResponse>(app, "/par", {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const token = await postForm<TokenResponse>(app, "/token", {
      grant_type: "authorization_code",
      code: code ?? "",
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      code_verifier: verifier,
    });
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: "PSjSLsRih2uXZQG3yJUkEzIBnWHykzS0sU_vzrdLFoo",
      y: "DPtPmdCGdkUTuhlE-iIl4OKl4hFdMIxgikukk9P-v_U",
    };
    const proof = unsignedJwt({ alg: "ES256", jwk });

    const credential = await request(app)
      .post("/credential")
      .set("authorization", `Bearer ${token.access_token}`)
      .send({ proof: { proof_type: "jwt", jwt: proof } });

    expect(credential.status, JSON.stringify(credential.body)).toBe(200);
    const encodedMdoc = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = parseIssuerSigned(Buffer.from(encodedMdoc, "base64url"), PID_MDOC_DOCTYPE);

    expect(session.credential_configuration_id).toBe(mdocCredentialConfigurationId(config));
    expect(decoded.docType).toBe(PID_MDOC_DOCTYPE);
    expect(decoded.getIssuerNameSpace("eu.europa.ec.eudi.pid.1")?.get("given_name")).toBe("Jane");
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("credential_issued");
  });

  it("stores PAR and merges it into authorize requests", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "correct horse battery staple";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postForm<ParResponse>(app, "/par", {
      client_id: "wallet-client",
      redirect_uri: "eudi-wallet://callback",
      response_type: "code",
      state: "wallet-state",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);

    expect(authorize.status).toBe(302);
    const location = new URL(authorize.headers.location ?? "");
    expect(location.protocol).toBe("eudi-wallet:");
    expect(location.searchParams.get("state")).toBe("wallet-state");
    expect(location.searchParams.get("code")).toBeTruthy();

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.observed.client_id.value).toBe("wallet-client");
    expect(capture.observed.redirect_uri.value).toBe("eudi-wallet://callback");
    expect(capture.raw?.authorization_request?.client_id).toBe("wallet-client");
  });

  it("verifies PKCE and captures credential proof JWKS", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postForm<ParResponse>(app, "/par", {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const token = await postForm<TokenResponse>(app, "/token", {
      grant_type: "authorization_code",
      code: code ?? "",
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      code_verifier: verifier,
    });

    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    };
    const proof = unsignedJwt({ alg: "ES256", jwk });
    const credential = await request(app)
      .post("/credential")
      .set("authorization", `Bearer ${token.access_token}`)
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
      vct: session.credential_configuration_id,
      given_name: "Jane",
      family_name: "Doe",
      website: CREDIMI_WEBSITE,
      logo_uri: CREDIMI_LOGO_URL,
      cnf: { jwk },
    });
    expect(decoded.holder?.method).toBe("jwk");
    if (decoded.holder?.method !== "jwk") throw new Error("expected JWK holder binding");
    expect(Kms.PublicJwk.fromUnknown(jwk).equals(decoded.holder.jwk)).toBe(true);
    const walletJwks = await getJson<JwksResponse>(app, `/sessions/${session.session_id}/jwks`);
    expect(walletJwks.keys).toHaveLength(1);
    expect(walletJwks.keys[0]).toMatchObject({ ...jwk, alg: "ES256", use: "sig" });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.checks.pkce_valid).toBe(true);
    expect(capture.checks.proof_jwt_header_jwk_present).toBe(true);
    expect(capture.status).toBe("credential_issued");
  });

  it("rejects credential issuance when the proof does not expose a holder JWK", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/credential")
      .send({ proof: { proof_type: "jwt", jwt: unsignedJwt({ alg: "ES256", kid: "key-1" }) } });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_proof" });
  });

  it("captures wallet attestation client authentication on token requests", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postForm<ParResponse>(app, "/par", {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
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

    const token = await request(app)
      .post("/token")
      .set("OAuth-Client-Attestation", attestation)
      .set("OAuth-Client-Attestation-PoP", pop)
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

async function getJson<T>(app: Express, path: string): Promise<T> {
  const response = await request(app).get(path);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
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
  observed: {
    vp_token?: { value: unknown };
    request_uri_payload: { value: JsonRecord | null; source: string | null };
    wallet_response: { value: JsonRecord | null };
    presentation_submission?: { value: unknown };
  };
  raw?: {
    presentation_response?: JsonRecord;
  };
}
