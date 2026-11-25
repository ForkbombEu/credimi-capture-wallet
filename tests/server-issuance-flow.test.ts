import { createHash, randomBytes } from "node:crypto";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  mdocCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { unsignedJwt } from "./helpers.js";
import { getJson, postJson } from "./support/http.js";
import {
  type CredentialOfferResponse,
  type CredentialResponse,
  type SessionCreateResponse,
  postToken,
  preAuthorizedToken,
} from "./support/issuance.js";
import { generateEs256Key } from "./support/keys.js";
import { issuerProtocolPath, serverTestSuite } from "./support/server.js";
const {
  config,
  conformingIssuerId,
  conformingIssuerPath,
  jwtOnlyIssuerId,
  jwtOnlyIssuerPath,
  conformingProofJwt,
  postDpopProof,
  walletAttestationJwt,
  walletAttestationPopJwt,
} = serverTestSuite("fake-issuer-test-");

describe("capture issuer server", () => {
  it("does not accept an authorization code at another issuer's OAuth server", async () => {
    const app = createApp(config);
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const authorization = await request(app)
      .get(`/authorization-servers/${conformingIssuerId}/authorize`)
      .query({
        response_type: "code",
        client_id: `credimi-capture-wallet-${conformingIssuerId}`,
        redirect_uri: `${config.issuer_base_url}${conformingIssuerPath}/redirect`,
        state: "issuer-isolation",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        scope: "credimi.capture.eu-pid-device-bound",
      })
      .redirects(0);
    expect(authorization.status).toBe(302);
    const code = new URL(String(authorization.headers.location)).searchParams.get("code");
    expect(code).toEqual(expect.any(String));

    const crossIssuerRedemption = await request(app)
      .post(`/authorization-servers/${jwtOnlyIssuerId}/token`)
      .type("form")
      .send({
        grant_type: "authorization_code",
        client_id: `credimi-capture-wallet-${jwtOnlyIssuerId}`,
        client_secret: `credimi-capture-wallet-test-secret-${jwtOnlyIssuerId}`,
        code,
        redirect_uri: `${config.issuer_base_url}${jwtOnlyIssuerPath}/redirect`,
        code_verifier: codeVerifier,
      });

    expect(crossIssuerRedemption.status).toBe(400);
    expect(crossIssuerRedemption.body).toMatchObject({
      error: "invalid_grant",
      error_description: "authorization code is invalid or expired",
    });
  });
  it("does not accept one issuer's access token at another issuer's credential endpoint", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const credentialPath = `${jwtOnlyIssuerPath}/credential`;

    const response = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
        proofs: { jwt: [unsignedJwt({ alg: "ES256", jwk: dpop.publicJwk })] },
      });

    expect(response.status).toBe(401);
  });

  it("accepts independent wallet-attestation and DPoP keys at PAR", async () => {
    const app = createApp(config);
    const clientId = "https://wallet.example.test";
    const redirectUri = "https://wallet.example.test/callback";
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants.authorization_code;
    const walletInstanceKey = await generateEs256Key();
    const unrelatedWalletInstanceKey = await generateEs256Key();
    const dpop = await generateEs256Key();
    const walletAttestation = await walletAttestationJwt(walletInstanceKey, clientId);
    const parPath = issuerProtocolPath(session, "/par");
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const parRequest = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: session.credential_configuration_id,
      issuer_state: String(grant.issuer_state),
      state: "wallet-state",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    };

    const invalidProof = await request(app)
      .post(parPath)
      .set("DPoP", await postDpopProof(dpop, parPath))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set(
        "OAuth-Client-Attestation-PoP",
        await walletAttestationPopJwt(unrelatedWalletInstanceKey, clientId),
      )
      .type("form")
      .send(parRequest);

    expect(invalidProof.status).toBe(401);
    expect(invalidProof.body).toMatchObject({ error: "invalid_client" });

    const accepted = await request(app)
      .post(parPath)
      .set("DPoP", await postDpopProof(dpop, parPath))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set(
        "OAuth-Client-Attestation-PoP",
        await walletAttestationPopJwt(walletInstanceKey, clientId),
      )
      .type("form")
      .send(parRequest);

    expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
    expect(accepted.body).toMatchObject({
      request_uri: expect.any(String),
      expires_in: expect.any(Number),
    });

    const authorize = await request(app)
      .get(issuerProtocolPath(session, "/authorize"))
      .query({
        client_id: clientId,
        request_uri: String(accepted.body.request_uri),
      })
      .redirects(0);
    expect(authorize.status).toBe(302);

    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    expect(autoApproval.status).toBe(302);

    const credoCallback = new URL(String(autoApproval.headers.location));
    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    expect(walletAuthorizationResponse.status).toBe(302);

    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));
    const authorizationCode = walletCallback.searchParams.get("code");
    expect(authorizationCode).toEqual(expect.any(String));

    const tokenPath = issuerProtocolPath(session, "/token");
    const token = await request(app)
      .post(tokenPath)
      .set("DPoP", await postDpopProof(dpop, tokenPath))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set(
        "OAuth-Client-Attestation-PoP",
        await walletAttestationPopJwt(walletInstanceKey, clientId),
      )
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(authorizationCode),
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      });

    expect(token.status, JSON.stringify(token.body)).toBe(200);
    expect(token.body).toMatchObject({
      access_token: expect.any(String),
      token_type: "DPoP",
    });
  });

  it("accepts a Client Attestation PoP from a wallet clock up to 60 seconds ahead", async () => {
    const app = createApp(config);
    const clientId = "https://wallet.example.test";
    const walletInstanceKey = await generateEs256Key();
    const walletAttestation = await walletAttestationJwt(walletInstanceKey, clientId);

    const pushWithClockAhead = async (seconds: number) => {
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const offer = await getJson<CredentialOfferResponse>(
        app,
        new URL(session.offer_url).pathname,
      );
      const parPath = issuerProtocolPath(session, "/par");
      return request(app)
        .post(parPath)
        .set("DPoP", await postDpopProof(await generateEs256Key(), parPath))
        .set("OAuth-Client-Attestation", walletAttestation)
        .set(
          "OAuth-Client-Attestation-PoP",
          await walletAttestationPopJwt(walletInstanceKey, clientId, seconds),
        )
        .type("form")
        .send({
          response_type: "code",
          client_id: clientId,
          redirect_uri: "https://wallet.example.test/callback",
          scope: session.credential_configuration_id,
          issuer_state: String(offer.grants.authorization_code.issuer_state),
          code_challenge: createHash("sha256")
            .update(randomBytes(48).toString("base64url"))
            .digest("base64url"),
          code_challenge_method: "S256",
        });
    };

    const withinSkew = await pushWithClockAhead(45);
    expect(withinSkew.status, JSON.stringify(withinSkew.body)).toBe(201);

    const beyondSkew = await pushWithClockAhead(75);
    expect(beyondSkew.status).toBe(401);
    expect(beyondSkew.body).toMatchObject({ error: "invalid_client" });
  });

  it("issues the claim set named by fixture_id, end to end", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
      fixture_id: "pid_under_18",
    });
    expect(session.fixture_id).toBe("pid_under_18");

    const walletKey = await generateEs256Key();
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const proof = await conformingProofJwt(walletKey, token.c_nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    const disclosed = compactSdJwt
      .split("~")
      .slice(1)
      .filter((part) => part.length > 0)
      .map((part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown[]);

    expect(disclosed).toEqual(
      expect.arrayContaining([expect.arrayContaining(["age_over_18", false])]),
    );
    expect(disclosed).toEqual(
      expect.arrayContaining([expect.arrayContaining(["birthdate", "2012-03-04"])]),
    );

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.fixture_id).toBe("pid_under_18");
  });

  it("issues the default PID with a caller-selected document number", async () => {
    const app = createApp(config);
    const documentNumber = "caller-selected document 42";
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
      document_number: documentNumber,
    });
    expect(session.fixture_id).toBe("pid_default");
    expect(session.document_number).toBe(documentNumber);

    const walletKey = await generateEs256Key();
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const proof = await conformingProofJwt(walletKey, token.c_nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    const disclosed = compactSdJwt
      .split("~")
      .slice(1)
      .filter((part) => part.length > 0)
      .map((part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown[]);
    expect(disclosed).toEqual(
      expect.arrayContaining([expect.arrayContaining(["document_number", documentNumber])]),
    );

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.document_number).toBe(documentNumber);
  });

  it("digests the disclosures with the algorithm named by digest_algorithm, end to end", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
      digest_algorithm: "sha-512",
    });
    expect(session.digest_algorithm).toBe("sha-512");

    const walletKey = await generateEs256Key();
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const proof = await conformingProofJwt(walletKey, token.c_nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    const payload = JSON.parse(
      Buffer.from(compactSdJwt.split(".")[1] as string, "base64url").toString("utf8"),
    ) as JsonRecord;
    expect(payload._sd_alg).toBe("sha-512");

    // The claim alone proves nothing: a wallet recomputes every digest, so the entries of `_sd`
    // must actually be SHA-512 over the base64url disclosure.
    const digests = payload._sd as string[];
    const disclosures = compactSdJwt
      .split("~")
      .slice(1)
      .filter((part) => part.length > 0);
    expect(disclosures.length).toBeGreaterThan(0);
    for (const disclosure of disclosures) {
      expect(digests).toContain(
        createHash("sha512").update(disclosure, "ascii").digest("base64url"),
      );
    }

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.digest_algorithm).toBe("sha-512");
  });

  it("rejects an unknown fixture_id", async () => {
    const response = await request(createApp(config))
      .post("/sessions")
      .send({ fixture_id: "pid_person_z" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      error: "unsupported_fixture_id",
      supported_fixture_ids: expect.arrayContaining(["pid_default", "pid_under_18"]),
    });
  });

  it.each([
    [
      "an unknown fixture",
      { status_reference: "revoked", status_list_enabled: true },
      { error: "unsupported_status_reference" },
    ],
    [
      "a malformed fixture without status-list allocation",
      { status_reference: "negative_index" },
      { error: "status_reference_requires_status_list" },
    ],
    [
      "a digest algorithm SD-JWT VC does not allow",
      { digest_algorithm: "sha-1" },
      { error: "unsupported_digest_algorithm" },
    ],
    [
      "a digest algorithm for an mdoc configuration",
      {
        digest_algorithm: "sha-512",
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
      },
      { error: "digest_algorithm_unsupported_for_mdoc" },
    ],
    ["an empty document number", { document_number: "" }, { error: "invalid_document_number" }],
  ])("rejects %s", async (_label, body, expected) => {
    const response = await request(createApp({ ...config, fcaf_scenarios_enabled: true }))
      .post("/sessions")
      .send(body);

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject(expected);
  });

  it("refuses a malformed status reference unless the deployment enables FCAF scenarios", async () => {
    const response = await request(createApp(config))
      .post("/sessions")
      .send({ status_reference: "negative_index", status_list_enabled: true });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "status_reference_not_enabled" });
  });

  it("runs the default authorization-code flow through the auto-approving OAuth server", async () => {
    const app = createApp(config);
    const walletClientId = "https://wallet.example.test";
    const walletRedirectUri = "https://wallet.example.test/callback";
    const walletState = "wallet-state";
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const dpop = await generateEs256Key();
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = JSON.parse(
      String(new URL(session.deeplink).searchParams.get("credential_offer")),
    ) as CredentialOfferResponse;
    const grant = offer.grants.authorization_code;

    expect(session.flow).toBe("authorization_code");
    expect(session.credential_offer_mode).toBe("credential_offer");
    expect(grant).toMatchObject({
      issuer_state: expect.any(String),
    });
    expect(grant).not.toHaveProperty("authorization_server");

    const parPath = issuerProtocolPath(session, "/par");
    const pushed = await request(app)
      .post(parPath)
      .set("DPoP", await postDpopProof(dpop, parPath))
      .type("form")
      .send({
        response_type: "code",
        client_id: walletClientId,
        redirect_uri: walletRedirectUri,
        scope: session.credential_configuration_id,
        issuer_state: String(grant.issuer_state),
        state: walletState,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    expect(pushed.body).toMatchObject({
      request_uri: expect.any(String),
      expires_in: expect.any(Number),
    });

    const authorize = await request(app)
      .get(issuerProtocolPath(session, "/authorize"))
      .query({
        client_id: walletClientId,
        request_uri: String(pushed.body.request_uri),
      })
      .redirects(0);
    expect(authorize.status).toBe(302);
    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    expect(externalAuthorizationUrl.pathname).toBe(
      `/authorization-servers/${conformingIssuerId}/authorize`,
    );

    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    expect(autoApproval.status).toBe(302);
    const credoCallback = new URL(String(autoApproval.headers.location));
    expect(credoCallback.pathname).toBe(issuerProtocolPath(session, "/redirect"));
    expect(credoCallback.searchParams.get("code")).toEqual(expect.any(String));

    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    expect(walletAuthorizationResponse.status).toBe(302);
    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));
    expect(walletCallback.origin + walletCallback.pathname).toBe(walletRedirectUri);
    expect(walletCallback.searchParams.get("state")).toBe(walletState);
    expect(walletCallback.searchParams.get("iss")).toBe(
      `${config.issuer_base_url}${conformingIssuerPath}`,
    );
    const authorizationCode = walletCallback.searchParams.get("code");
    expect(authorizationCode).toEqual(expect.any(String));

    const token = await postToken(
      app,
      {
        grant_type: "authorization_code",
        code: String(authorizationCode),
        code_verifier: codeVerifier,
        redirect_uri: walletRedirectUri,
        client_id: walletClientId,
      },
      dpop,
      config.issuer_base_url,
      conformingIssuerId,
    );
    expect(token).toMatchObject({
      access_token: expect.any(String),
      token_type: "DPoP",
      c_nonce: expect.any(String),
    });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("token_issued");
    expect(capture).not.toHaveProperty("initiated_by");
    expect(capture.observed.client_id.value).toBe(walletClientId);
    expect(capture.observed.redirect_uri.value).toBe(walletRedirectUri);
    expect(capture.checks).toMatchObject({
      pkce_present: true,
      pkce_valid: true,
      state_present: true,
      issuer_state_present: true,
    });
    expect(capture.raw?.par_request).toMatchObject({
      client_id: walletClientId,
      redirect_uri: walletRedirectUri,
      code_challenge: codeChallenge,
    });
    expect(capture.raw?.token_request?.code).toMatchObject({
      redacted: true,
      present: true,
    });
  });

  it("enforces the wallet's S256 PKCE at PAR and at the token endpoint", async () => {
    const app = createApp(config);
    const walletClientId = "https://wallet.example.test";
    const walletRedirectUri = "https://wallet.example.test/callback";
    const codeVerifier = randomBytes(48).toString("base64url");
    const dpop = await generateEs256Key();
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = JSON.parse(
      String(new URL(session.deeplink).searchParams.get("credential_offer")),
    ) as CredentialOfferResponse;
    const parPath = issuerProtocolPath(session, "/par");
    const parRequest = {
      response_type: "code",
      client_id: walletClientId,
      redirect_uri: walletRedirectUri,
      scope: session.credential_configuration_id,
      issuer_state: String(offer.grants.authorization_code.issuer_state),
      state: "wallet-state",
    };

    const withoutPkce = await request(app)
      .post(parPath)
      .set("DPoP", await postDpopProof(dpop, parPath))
      .type("form")
      .send(parRequest);
    expect(withoutPkce.status).toBe(400);
    expect(withoutPkce.body).toMatchObject({ error: "invalid_request" });

    const pushed = await request(app)
      .post(parPath)
      .set("DPoP", await postDpopProof(dpop, parPath))
      .type("form")
      .send({
        ...parRequest,
        code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
        code_challenge_method: "S256",
      });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const authorize = await request(app)
      .get(issuerProtocolPath(session, "/authorize"))
      .query({ client_id: walletClientId, request_uri: String(pushed.body.request_uri) })
      .redirects(0);
    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    const credoCallback = new URL(String(autoApproval.headers.location));
    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));

    const tokenPath = issuerProtocolPath(session, "/token");
    const token = await request(app)
      .post(tokenPath)
      .set("DPoP", await postDpopProof(dpop, tokenPath))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(walletCallback.searchParams.get("code")),
        code_verifier: randomBytes(48).toString("base64url"),
        redirect_uri: walletRedirectUri,
        client_id: walletClientId,
      });
    expect(token.status).toBe(400);
    expect(token.body).toMatchObject({ error: "invalid_grant" });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).not.toBe("token_issued");
    expect(capture.checks.pkce_valid).not.toBe(true);
  });

  it("rejects unknown issuance flow presets", async () => {
    const app = createApp(config);
    const response = await request(app).post("/sessions").send({ flow: "implicit" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "unsupported_issuance_flow",
      supported_flows: ["pre_authorized_code", "authorization_code"],
    });
  });

  it("rejects unknown credential-offer modes", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/sessions")
      .send({ credential_offer_mode: "reference" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "unsupported_credential_offer_mode",
      supported_credential_offer_modes: ["credential_offer", "credential_offer_uri"],
    });
  });
  it("captures and correlates pre-authorized requests with secrets redacted", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const preAuthorizedCode = String(grant["pre-authorized_code"]);
    const dpopKeyPair = await generateEs256Key();
    const tokenPath = issuerProtocolPath(session, "/token");
    const dpop = await postDpopProof(dpopKeyPair, tokenPath);

    const token = await request(app).post(tokenPath).set("DPoP", dpop).type("form").send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode,
    });

    expect(token.status).toBe(200);
    const ledger = await getJson<Array<JsonRecord>>(app, "/oid4vci/requests");
    const tokenCapture = ledger.find((entry) => entry.path === tokenPath);
    expect(tokenCapture).toMatchObject({
      method: "POST",
      session_id: session.session_id,
      headers: { dpop: { redacted: true, present: true } },
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": { redacted: true, present: true },
      },
      response: { status: 200 },
    });
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.raw?.oid4vci_requests?.map((entry) => entry.path)).toEqual(
      expect.arrayContaining([new URL(session.offer_url).pathname, tokenPath]),
    );
    expect(JSON.stringify(ledger)).not.toContain(preAuthorizedCode);
    expect(JSON.stringify(ledger)).not.toContain(dpop);
  });
  it("makes credential nonce responses uncacheable", async () => {
    const app = createApp(config);
    const response = await request(app).post(`${conformingIssuerPath}/nonce`);

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toMatchObject({
      c_nonce: expect.any(String),
    });
  });
  it("rejects token requests without DPoP", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const response = await request(app)
      .post(issuerProtocolPath(session, "/token"))
      .type("form")
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": String(grant["pre-authorized_code"]),
      });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_dpop_proof" });
  });
  it("uses Credo to verify a draft-07 wallet attestation PoP without exp", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const walletInstanceKey = await generateEs256Key();
    const clientId = "https://wallet.example.test";
    const walletAttestation = await walletAttestationJwt(walletInstanceKey, clientId);
    const walletAttestationPop = await walletAttestationPopJwt(walletInstanceKey, clientId);
    const dpop = await generateEs256Key();

    const response = await request(app)
      .post(issuerProtocolPath(session, "/token"))
      .set("DPoP", await postDpopProof(dpop, issuerProtocolPath(session, "/token")))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set("OAuth-Client-Attestation-PoP", walletAttestationPop)
      .type("form")
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": String(grant["pre-authorized_code"]),
      });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body).toMatchObject({
      access_token: expect.any(String),
      token_type: "DPoP",
    });
  });
});
