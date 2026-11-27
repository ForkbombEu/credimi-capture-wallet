import { createHash, randomUUID } from "node:crypto";
import type { Express } from "express";
import { CompactEncrypt, type JWK, SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { sdJwtCredentialConfigurationId } from "../src/credentials/catalogue.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord, Oid4vciHttpRequestCapture, SessionCapture } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type CredentialOfferResponse,
  type SessionCreateResponse,
  type TokenResponse,
  credentialNonce,
  keyAttestationJwt,
  preAuthorizedToken,
} from "./support/issuance.js";
import { type TestKey, generateEs256Key } from "./support/keys.js";
import { issuerProtocolPath, serverTestSuite } from "./support/server.js";
const {
  config,
  conformingIssuerPath,
  conformingMetadataPath,
  conformingIssuerConfig,
  conformingProofJwt,
  postDpopProof,
  walletAttestationJwt,
  walletAttestationPopJwt,
} = serverTestSuite("fake-issuer-test-");

describe("capture issuer server", () => {
  describe("FCAF ws_ap evidence", () => {
    const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };
    const walletClientId = "https://wallet.example.test";

    async function pushAuthorization(
      app: Express,
      session: SessionCreateResponse,
      headers: Record<string, string | string[]>,
    ) {
      const offer = JSON.parse(
        String(new URL(session.deeplink).searchParams.get("credential_offer")),
      ) as CredentialOfferResponse;
      const parPath = issuerProtocolPath(session, "/par");
      const pending = request(app)
        .post(parPath)
        .set("DPoP", await postDpopProof(await generateEs256Key(), parPath));
      // The object form passes an array through, which Node sends as repeated header fields.
      for (const [name, value] of Object.entries(headers)) pending.set({ [name]: value });
      return pending.type("form").send({
        response_type: "code",
        client_id: walletClientId,
        redirect_uri: `${walletClientId}/callback`,
        scope: session.credential_configuration_id,
        issuer_state: String(offer.grants.authorization_code.issuer_state),
        code_challenge: createHash("sha256").update("verifier").digest("base64url"),
        code_challenge_method: "S256",
      });
    }

    it.each([
      [config, { evidence_mode: "full" }, "evidence_mode_not_enabled"],
      [scenarioConfig, { evidence_mode: "raw" }, "unsupported_evidence_mode"],
    ])("refuses an unavailable evidence mode", async (appConfig, body, error) => {
      const response = await request(createApp(appConfig)).post("/sessions").send(body);

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ error });
    });

    it("decodes client attestations into a default session while the ledger stays redacted", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const walletInstanceKey = await generateEs256Key();
      const attestation = await walletAttestationJwt(walletInstanceKey, walletClientId);
      const pop = await walletAttestationPopJwt(walletInstanceKey, walletClientId);

      const pushed = await pushAuthorization(app, session, {
        "OAuth-Client-Attestation": attestation,
        "OAuth-Client-Attestation-PoP": pop,
      });

      expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
      expect(session).not.toHaveProperty("evidence_mode");
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture).not.toHaveProperty("evidence_mode");
      expect(capture.observed.client_authentication).toMatchObject({
        method: "wallet_attestation",
        wallet_attestation: {
          present: true,
          source: `${issuerProtocolPath(session, "/par")}.headers.oauth-client-attestation`,
          header: { typ: "oauth-client-attestation+jwt" },
          claims: { sub: walletClientId },
          cnf_jwk: walletInstanceKey.publicJwk,
          client_id_matches: true,
          error: null,
        },
        wallet_attestation_pop: {
          present: true,
          header: { typ: "oauth-client-attestation-pop+jwt" },
          audience_matches: true,
          challenge: null,
        },
      });
      expect(capture.checks).toMatchObject({
        wallet_attestation_present: true,
        wallet_attestation_pop_present: true,
        wallet_attestation_client_id_matches: true,
        wallet_attestation_pop_audience_matches: true,
      });
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture).toMatchObject({
        headers: { "oauth-client-attestation": { redacted: true, present: true } },
        header_counts: { "oauth-client-attestation": 1, "oauth-client-attestation-pop": 1 },
      });
      expect(parCapture).not.toHaveProperty("raw_headers");
      const ledger = await getJson<JsonRecord[]>(app, "/oid4vci/requests");
      expect(JSON.stringify([ledger, capture.raw])).not.toContain(attestation);
    });

    it("keeps every attestation header in clear for a full-evidence session Credo rejects", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
      });
      const walletInstanceKey = await generateEs256Key();
      const attestation = await walletAttestationJwt(walletInstanceKey, walletClientId);
      const otherAttestation = await walletAttestationJwt(await generateEs256Key(), "other-client");
      const pop = await walletAttestationPopJwt(walletInstanceKey, walletClientId);

      const pushed = await pushAuthorization(app, session, {
        "OAuth-Client-Attestation": [attestation, otherAttestation],
        "OAuth-Client-Attestation-PoP": pop,
      });

      expect(pushed.status).toBeGreaterThanOrEqual(400);
      expect(session.evidence_mode).toBe("full");
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      const parPath = issuerProtocolPath(session, "/par");
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) => entry.path === parPath);
      expect(parCapture?.header_counts["oauth-client-attestation"]).toBe(2);
      expect(
        parCapture?.raw_headers?.filter(
          (header) => header.name.toLowerCase() === "oauth-client-attestation",
        ),
      ).toEqual([
        { name: expect.stringMatching(/^oauth-client-attestation$/i), value: attestation },
        { name: expect.stringMatching(/^oauth-client-attestation$/i), value: otherAttestation },
      ]);
      expect(parCapture?.raw_headers).toContainEqual({
        name: expect.stringMatching(/^dpop$/i),
        value: { redacted: true, present: true, length: expect.any(Number) },
      });
      expect(capture.observed.client_authentication.wallet_attestation).toMatchObject({
        present: true,
        source: `${parPath}.headers.oauth-client-attestation[0]`,
        claims: { sub: walletClientId },
      });
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      const ledgerEntry = ledger.find((entry) => entry.id === parCapture?.id);
      expect(ledgerEntry).toMatchObject({
        session_id: session.session_id,
        header_counts: { "oauth-client-attestation": 2 },
      });
      expect(JSON.stringify(ledger)).not.toContain(attestation);
    });

    it("attributes a PoP Credo rejects for its audience", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const walletInstanceKey = await generateEs256Key();
      const pop = await new SignJWT({
        iss: walletClientId,
        aud: "https://elsewhere.example.test",
        iat: Math.floor(Date.now() / 1000),
        jti: randomUUID(),
        challenge: "issuer-challenge",
      })
        .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation-pop+jwt" })
        .sign(walletInstanceKey.privateKey);

      const pushed = await pushAuthorization(app, session, {
        "OAuth-Client-Attestation": await walletAttestationJwt(walletInstanceKey, walletClientId),
        "OAuth-Client-Attestation-PoP": pop,
      });

      expect(pushed.status).toBeGreaterThanOrEqual(400);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.observed.client_authentication.wallet_attestation_pop).toMatchObject({
        present: true,
        audience_matches: false,
        challenge: "issuer-challenge",
      });
      expect(capture.checks.wallet_attestation_pop_audience_matches).toBe(false);
    });

    it("records a missing attestation header as absent", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const walletInstanceKey = await generateEs256Key();

      await pushAuthorization(app, session, {
        "OAuth-Client-Attestation-PoP": await walletAttestationPopJwt(
          walletInstanceKey,
          walletClientId,
        ),
      });

      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.observed.client_authentication).toMatchObject({
        method: "wallet_attestation",
        wallet_attestation: { present: false, source: null },
        wallet_attestation_pop: { present: true },
      });
      expect(capture.checks).toMatchObject({
        wallet_attestation_present: false,
        wallet_attestation_pop_present: true,
      });
      expect(
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/par"))?.header_counts,
      ).not.toHaveProperty("oauth-client-attestation");
    });

    async function requestCredential(
      app: Express,
      session: SessionCreateResponse,
      body: JsonRecord,
      token?: { dpop: TestKey; response: TokenResponse },
    ) {
      const dpop = token?.dpop ?? (await generateEs256Key());
      const tokenResponse =
        token?.response ?? (await preAuthorizedToken(app, session, dpop, config.issuer_base_url));
      const credentialPath = issuerProtocolPath(session, "/credential");
      const response = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${tokenResponse.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, tokenResponse.access_token))
        .send({ credential_configuration_id: session.credential_configuration_id, ...body });
      return {
        response,
        capture: await getJson<SessionCapture>(app, `/sessions/${session.session_id}`),
      };
    }

    async function preAuthorizedFull(app: Express): Promise<SessionCreateResponse> {
      return postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
        evidence_mode: "full",
      });
    }

    it("keeps a jwt proof Credo rejects, with its key attestation decoded", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);
      const dpop = await generateEs256Key();
      const tokenResponse = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const nonce = await credentialNonce(app, session.issuer_configuration_id);
      const holderKey = await generateEs256Key();
      const keyAttestation = await keyAttestationJwt(conformingIssuerConfig, holderKey, nonce);
      const proof = await new SignJWT({
        aud: `${config.issuer_base_url}${conformingIssuerPath}`,
        nonce,
        iat: Math.floor(Date.now() / 1000),
      })
        .setProtectedHeader({
          alg: "ES256",
          typ: "openid4vci-proof+jwt",
          jwk: holderKey.publicJwk as unknown as JWK,
          key_attestation: keyAttestation,
        })
        .sign((await generateEs256Key()).privateKey);

      const { response, capture } = await requestCredential(
        app,
        session,
        { proofs: { jwt: [proof, 42] } },
        { dpop, response: tokenResponse },
      );

      expect(response.status).toBe(400);
      expect(capture.raw?.proof_headers).toBeUndefined();
      const credentialCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/credential"),
      );
      expect(capture.raw?.credential_request_proofs).toEqual({
        request_id: credentialCapture?.id,
        at: credentialCapture?.at,
        proofs: { jwt: [proof, 42] },
        jwt: [
          {
            compact: proof,
            header: expect.objectContaining({
              typ: "openid4vci-proof+jwt",
              key_attestation: keyAttestation,
            }),
            payload: expect.objectContaining({ nonce }),
            error: null,
            source: "proofs.jwt[0]",
            key_attestation: {
              compact: keyAttestation,
              header: expect.objectContaining({
                typ: "key-attestation+jwt",
                x5c: expect.any(Array),
              }),
              payload: expect.objectContaining({
                nonce,
                attested_keys: [holderKey.publicJwk],
              }),
              error: null,
            },
          },
        ],
        attestation: [],
      });
      expect(credentialCapture?.body).toMatchObject({ proofs: { jwt: [proof, 42] } });
      const ledger = await getJson<JsonRecord[]>(app, "/oid4vci/requests");
      expect(JSON.stringify(ledger)).not.toContain(proof);
    });

    it("keeps a proofs.jwt that is not an array exactly as sent", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);

      const { response, capture } = await requestCredential(app, session, {
        proofs: { jwt: "not.a.jwt" },
      });

      expect(response.status).toBe(400);
      expect(capture.raw?.credential_request_proofs).toMatchObject({
        proofs: { jwt: "not.a.jwt" },
        jwt: [
          { compact: "not.a.jwt", source: "proofs.jwt", header: null, error: expect.any(String) },
        ],
      });
    });

    it("keeps an attestation proof and still records the accepted proof headers", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);
      const dpop = await generateEs256Key();
      const tokenResponse = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const nonce = await credentialNonce(app, session.issuer_configuration_id);
      const keyAttestation = await keyAttestationJwt(
        conformingIssuerConfig,
        await generateEs256Key(),
        nonce,
      );

      const { response, capture } = await requestCredential(
        app,
        session,
        { proofs: { attestation: [keyAttestation] } },
        { dpop, response: tokenResponse },
      );

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      expect(capture.raw?.credential_request_proofs?.attestation).toEqual([
        {
          compact: keyAttestation,
          header: expect.objectContaining({ typ: "key-attestation+jwt" }),
          payload: expect.objectContaining({ nonce }),
          error: null,
          source: "proofs.attestation[0]",
        },
      ]);
      expect(capture.raw?.proof_headers).toEqual([
        expect.objectContaining({ proof_type: "attestation", typ: "key-attestation+jwt" }),
      ]);
    });

    it("records no proof evidence for a default session", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
      });

      const { response, capture } = await requestCredential(app, session, {
        proofs: { jwt: ["not.a.jwt"] },
      });

      expect(response.status).toBe(400);
      expect(capture.raw?.credential_request_proofs).toBeUndefined();
      expect(
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/credential"))?.body,
      ).toMatchObject({ proofs: { jwt: { redacted: true, present: true } } });
    });

    async function sendRawCredentialRequest(app: Express, contentType: string, bytes: Buffer) {
      const session = await preAuthorizedFull(app);
      const dpop = await generateEs256Key();
      const tokenResponse = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const credentialPath = issuerProtocolPath(session, "/credential");
      const response = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${tokenResponse.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, tokenResponse.access_token))
        .set("Content-Type", contentType)
        // superagent writes a Buffer as-is once no serializer touches it; its type names strings.
        .serialize((body) => body)
        .send(bytes as unknown as string);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      return {
        session,
        response,
        credentialCapture: capture.raw?.oid4vci_requests?.find(
          (entry) => entry.path === credentialPath,
        ),
      };
    }

    it("keeps the exact Credential Request bytes, including a BOM and duplicate members", async () => {
      const app = createApp(scenarioConfig);
      const configurationId = sdJwtCredentialConfigurationId(config, "key-attestation-required");
      const bytes = Buffer.from(
        `\ufeff{"credential_configuration_id":"x","credential_configuration_id":"${configurationId}","proofs":{"jwt":["a.b.c"]}}`,
      );

      const { credentialCapture } = await sendRawCredentialRequest(app, "application/json", bytes);

      expect(credentialCapture?.raw_body).toEqual({
        content_type: "application/json",
        base64: bytes.toString("base64"),
      });
      expect(credentialCapture?.body).toMatchObject({
        credential_configuration_id: configurationId,
      });
    });

    it("keeps a Credential Request body that is not JSON or not parseable", async () => {
      const app = createApp(scenarioConfig);
      const malformed = Buffer.from('{"credential_configuration_id":');
      const plain = Buffer.from('{"proofs":{}}');

      const rejected = await sendRawCredentialRequest(app, "application/json", malformed);
      const untyped = await sendRawCredentialRequest(app, "text/plain", plain);

      expect(rejected.response.status).toBeGreaterThanOrEqual(400);
      expect(rejected.credentialCapture).toMatchObject({
        session_id: rejected.session.session_id,
        body: null,
        raw_body: { content_type: "application/json", base64: malformed.toString("base64") },
        response: { status: rejected.response.status },
      });
      expect(untyped.response.status).toBeGreaterThanOrEqual(400);
      expect(untyped.credentialCapture?.raw_body).toEqual({
        content_type: "text/plain",
        base64: plain.toString("base64"),
      });
    });

    it("keeps PAR bytes and the authorize request_uri in clear but describes the token body", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
      });
      const pushed = await pushAuthorization(app, session, {});
      const requestUri = String(pushed.body.request_uri);
      await request(app)
        .get(issuerProtocolPath(session, "/authorize"))
        .query({ client_id: walletClientId, request_uri: requestUri })
        .redirects(0);
      const preAuthorized = await preAuthorizedFull(app);
      await preAuthorizedToken(
        app,
        preAuthorized,
        await generateEs256Key(),
        config.issuer_base_url,
      );

      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture?.raw_body?.content_type).toBe("application/x-www-form-urlencoded");
      expect(
        new URLSearchParams(
          Buffer.from(String(parCapture?.raw_body?.base64), "base64").toString(),
        ).get("client_id"),
      ).toBe(walletClientId);
      const authorizeCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/authorize"),
      );
      expect(authorizeCapture?.query).toMatchObject({ request_uri: requestUri });
      expect(authorizeCapture).not.toHaveProperty("raw_body");
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(ledger.find((entry) => entry.id === authorizeCapture?.id)?.query).toMatchObject({
        request_uri: { redacted: true, present: true },
      });
      expect(ledger.some((entry) => "raw_body" in entry)).toBe(false);
      const tokenCapture = (
        await getJson<SessionCapture>(app, `/sessions/${preAuthorized.session_id}`)
      ).raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/token"));
      expect(tokenCapture?.raw_body).toEqual({
        content_type: "application/x-www-form-urlencoded",
        redacted: true,
        length: expect.any(Number),
      });
      expect(tokenCapture?.body).toMatchObject({
        "pre-authorized_code": { redacted: true, present: true },
      });
    });

    it("records delivered response bodies with the ledger's redaction in a default session", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
      });
      const dpop = await generateEs256Key();
      const tokenResponse = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const nonce = await credentialNonce(app, session.issuer_configuration_id);

      const { response, capture } = await requestCredential(
        app,
        session,
        {
          proofs: {
            jwt: [await conformingProofJwt(await generateEs256Key(), nonce)],
          },
        },
        { dpop, response: tokenResponse },
      );

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const byPath = (suffix: string) =>
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith(suffix))?.response;
      expect(
        byPath(`/offers/${new URL(session.offer_url).pathname.split("/").pop()}`),
      ).toMatchObject({
        status: 200,
        body: {
          grants: {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": { redacted: true, present: true },
            },
          },
        },
      });
      expect(byPath("/token")).toMatchObject({
        status: 200,
        body: {
          access_token: { redacted: true, present: true },
          token_type: "DPoP",
        },
      });
      expect(byPath("/token")?.body).not.toHaveProperty("c_nonce");
      expect(byPath("/credential")).toMatchObject({
        status: 200,
        body: { credentials: [{ credential: { redacted: true, present: true } }] },
      });
      const ledger = await getJson<JsonRecord[]>(app, "/oid4vci/requests");
      expect(JSON.stringify(ledger)).not.toContain(tokenResponse.access_token);
      expect(JSON.stringify(ledger)).not.toContain(String(response.body.credentials[0].credential));
    });

    it("keeps PAR, authorize, and credential error responses in a full session", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
      });
      const pushed = await pushAuthorization(app, session, {});
      await request(app)
        .get(issuerProtocolPath(session, "/authorize"))
        .query({ client_id: walletClientId, request_uri: String(pushed.body.request_uri) })
        .redirects(0);

      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture?.response).toEqual({
        status: 201,
        content_type: expect.stringContaining("application/json"),
        body: { request_uri: pushed.body.request_uri, expires_in: pushed.body.expires_in },
      });
      expect(
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/authorize"))?.response,
      ).toMatchObject({ status: 302 });
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(ledger.find((entry) => entry.id === parCapture?.id)?.response.body).toMatchObject({
        request_uri: { redacted: true, present: true },
        expires_in: pushed.body.expires_in,
      });

      const preAuthorized = await preAuthorizedFull(app);
      const rejected = await requestCredential(app, preAuthorized, { proofs: { jwt: ["a.b.c"] } });
      expect(
        rejected.capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/credential"))
          ?.response.body,
      ).toEqual(rejected.response.body);
    });

    it("attributes a Nonce Endpoint response to the session whose proof carries its c_nonce", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);
      const unrelated = await request(app).post(`${conformingIssuerPath}/nonce`);
      const nonce = await request(app).post(`${conformingIssuerPath}/nonce`);
      const cNonce = String(nonce.body.c_nonce);

      const { response, capture } = await requestCredential(app, session, {
        proofs: {
          jwt: [await conformingProofJwt(await generateEs256Key(), cNonce)],
        },
      });

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const nonceCaptures = capture.raw?.oid4vci_requests?.filter((entry) =>
        entry.path.endsWith("/nonce"),
      );
      expect(nonceCaptures).toEqual([
        expect.objectContaining({
          session_id: session.session_id,
          response: expect.objectContaining({ status: 200, body: { c_nonce: cNonce } }),
        }),
      ]);
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(
        ledger.find(
          (entry) =>
            entry.path.endsWith("/nonce") &&
            (entry.response.body as JsonRecord | undefined)?.c_nonce === unrelated.body.c_nonce,
        )?.session_id,
      ).toBeNull();
    });

    it.each([
      [
        config,
        { par: { omit_parameters: ["/request_uri"] } },
        "issuance_response_scenario_not_enabled",
      ],
      [scenarioConfig, { token: { status: 400 } }, "invalid_issuance_response_scenario"],
      [
        scenarioConfig,
        { par: { omit_parameters: ["request_uri"] } },
        "invalid_issuance_response_scenario",
      ],
      [scenarioConfig, { credential: { status: 700 } }, "invalid_issuance_response_scenario"],
      [scenarioConfig, { par: {} }, "invalid_issuance_response_scenario"],
    ])("refuses issuance_response_scenario %j", async (appConfig, scenario, error) => {
      const response = await request(createApp(appConfig))
        .post("/sessions")
        .send({ issuance_response_scenario: scenario });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error });
    });

    it("delivers a PAR response without request_uri while recording Credo's real one", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
        issuance_response_scenario: { par: { omit_parameters: ["/request_uri"] } },
      });

      const pushed = await pushAuthorization(app, session, {});
      const authorize = await request(app)
        .get(issuerProtocolPath(session, "/authorize"))
        .query({ client_id: walletClientId })
        .redirects(0);

      expect(pushed.status).toBe(201);
      expect(pushed.body).toEqual({ expires_in: expect.any(Number) });
      expect(authorize.status).toBeGreaterThanOrEqual(400);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.issuance_response_scenario).toEqual({
        par: { omit_parameters: ["/request_uri"] },
      });
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture?.response).toMatchObject({ status: 201, body: pushed.body });
      expect(
        capture.events.find((event) => event.type === "issuance_response_scenario_applied"),
      ).toMatchObject({
        detail: {
          endpoint: "par",
          request_id: parCapture?.id,
          original: {
            status: 201,
            body: { request_uri: expect.stringMatching(/^urn:ietf:params:oauth:request_uri:/) },
          },
          delivered: { status: 201, body: { expires_in: pushed.body.expires_in } },
        },
      });
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(
        ledger.find((entry) => entry.path.endsWith("/authorize") && entry.id !== parCapture?.id)
          ?.response.status,
      ).toBe(authorize.status);
    });

    it("denies a credential Credo issued and attributes the Wallet's retry", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
        issuance_response_scenario: {
          credential: {
            status: 400,
            content_type: "application/json",
            body: '{"error":"credential_request_denied"}',
          },
        },
      });
      const dpop = await generateEs256Key();
      const tokenResponse = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const nonce = await credentialNonce(app, session.issuer_configuration_id);
      const proofs = async () => ({
        proofs: {
          jwt: [await conformingProofJwt(await generateEs256Key(), nonce)],
        },
      });

      const denied = await requestCredential(app, session, await proofs(), {
        dpop,
        response: tokenResponse,
      });
      const retried = await requestCredential(app, session, await proofs(), {
        dpop,
        response: tokenResponse,
      });

      expect(denied.response.status).toBe(400);
      expect(denied.response.body).toEqual({ error: "credential_request_denied" });
      expect(denied.capture.status).toBe("credential_issued");
      const applied = retried.capture.events.filter(
        (event) => event.type === "issuance_response_scenario_applied",
      );
      expect(applied[0]).toMatchObject({
        detail: {
          endpoint: "credential",
          original: {
            status: 200,
            body: { credentials: [{ credential: { redacted: true, present: true } }] },
          },
          delivered: { status: 400, body: { error: "credential_request_denied" } },
        },
      });
      expect(
        retried.capture.raw?.oid4vci_requests?.filter((entry) => entry.path.endsWith("/credential"))
          .length,
      ).toBe(2);
    });

    it("sends a scenario's Credential Error Response unencrypted when encryption was requested", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
        issuance_response_scenario: {
          credential: {
            status: 400,
            content_type: "application/json",
            body: '{"error":"credential_request_denied"}',
          },
        },
      });
      const dpop = await generateEs256Key();
      const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const nonce = await credentialNonce(app, session.issuer_configuration_id);
      const responseEncryptionKeyPair = await generateKeyPair("ECDH-ES", {
        crv: "P-256",
        extractable: true,
      });
      const metadata = await getJson<JsonRecord>(app, conformingMetadataPath);
      // Shape asserted by the issuer metadata tests; this test only needs the published key.
      const requestEncryption = metadata.credential_request_encryption as {
        jwks: { keys: JWK[] };
      };
      const issuerEncryptionJwk = requestEncryption.jwks.keys[0];
      const credentialRequest = {
        credential_configuration_id: session.credential_configuration_id,
        proofs: {
          jwt: [await conformingProofJwt(await generateEs256Key(), nonce)],
        },
        credential_response_encryption: {
          jwk: {
            ...(await exportJWK(responseEncryptionKeyPair.publicKey)),
            alg: "ECDH-ES",
            use: "enc",
          },
          enc: "A256GCM",
        },
      };
      const encryptedRequest = await new CompactEncrypt(
        Buffer.from(JSON.stringify(credentialRequest), "utf8"),
      )
        .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM", kid: issuerEncryptionJwk.kid })
        .encrypt(await importJWK(issuerEncryptionJwk, "ECDH-ES"));
      const credentialPath = issuerProtocolPath(session, "/credential");

      const response = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
        .type("application/jwt")
        .send(encryptedRequest);

      expect(response.status, response.text).toBe(400);
      expect(response.type).toBe("application/json");
      expect(response.body).toEqual({ error: "credential_request_denied" });
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.status).toBe("credential_issued");
    });

    it.each([
      ["eu-eaa-offer://", "credential_offer"],
      ["haip-vci://", "credential_offer"],
      ["haip-vci://", "credential_offer_uri"],
    ])("delivers the offer with the %s scheme by %s", async (scheme, mode) => {
      const app = createApp(config);

      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        offer_scheme: scheme,
        credential_offer_mode: mode,
      });

      expect(session.offer_scheme).toBe(scheme);
      expect(session.deeplink.startsWith(`${scheme}?`)).toBe(true);
      const deeplink = new URL(session.deeplink);
      if (mode === "credential_offer") {
        expect(JSON.parse(String(deeplink.searchParams.get("credential_offer")))).toEqual(
          await getJson<JsonRecord>(app, `/sessions/${session.session_id}/offer`),
        );
      } else {
        expect(deeplink.searchParams.get("credential_offer_uri")).toBe(session.offer_url);
      }
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.offer_scheme).toBe(scheme);
    });

    it("keeps the default offer scheme out of the response and capture", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});

      expect(session.deeplink.startsWith("openid-credential-offer://?")).toBe(true);
      expect(session).not.toHaveProperty("offer_scheme");
      const unsupported = await request(app).post("/sessions").send({ offer_scheme: "https://" });
      expect(unsupported.status).toBe(400);
      expect(unsupported.body).toMatchObject({
        error: "unsupported_offer_scheme",
        supported_offer_schemes: ["openid-credential-offer://", "eu-eaa-offer://", "haip-vci://"],
      });
    });

    it.each([
      [config, {}, { unset: ["/credential_issuer"] }, "offer_mutation_not_enabled"],
      [scenarioConfig, {}, { unset: ["credential_issuer"] }, "invalid_offer_mutation"],
      [scenarioConfig, {}, { remove: ["/credential_issuer"] }, "invalid_offer_mutation"],
      [
        scenarioConfig,
        { credential_offer_mode: "credential_offer_uri" },
        { unset: ["/credential_issuer"] },
        "offer_mutation_requires_by_value_offer",
      ],
    ])("refuses an offer_mutation it cannot apply", async (appConfig, body, mutation, error) => {
      const response = await request(createApp(appConfig))
        .post("/sessions")
        .send({ ...body, offer_mutation: mutation });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error });
    });

    it.each(["/credential_issuer", "/credential_configuration_ids"])(
      "delivers a by-value offer without %s and keeps the generated one",
      async (pointer) => {
        const app = createApp(scenarioConfig);

        const session = await postJson<SessionCreateResponse>(app, "/sessions", {
          offer_scheme: "eu-eaa-offer://",
          offer_mutation: { unset: [pointer] },
        });

        const delivered = JSON.parse(
          String(new URL(session.deeplink).searchParams.get("credential_offer")),
        ) as JsonRecord;
        const member = pointer.slice(1);
        expect(session.deeplink.startsWith("eu-eaa-offer://?")).toBe(true);
        expect(delivered).not.toHaveProperty(member);
        const generated = await getJson<JsonRecord>(app, `/sessions/${session.session_id}/offer`);
        expect(generated).toHaveProperty(member);
        const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
        expect(capture.offer_mutation).toEqual({ unset: [pointer] });
        expect(capture.raw?.credential_offer).toEqual(generated);
        expect(capture.raw?.credential_offer_delivered).toEqual(delivered);
        expect(capture.events).toContainEqual(
          expect.objectContaining({
            type: "credential_offer_mutation_applied",
            detail: { pointers: [pointer] },
          }),
        );
      },
    );

    it("records unrouted requests, including self-derived metadata URLs, before the normal 404", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const paths = [
        "/.well-known/openid-credential-issuer",
        "/.well-known/openid-credential-issuer/issuers/not-configured",
        "/.well-known/openid-credential-issuer/ui/sessions",
        "/.well-known/oauth-authorization-server",
        `/sessions/${session.session_id}/unknown`,
      ];

      for (const path of paths) {
        const response = await request(app).get(path);
        expect(response.status, path).toBe(404);
      }

      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      const unmatched = ledger.filter((entry) => entry.unmatched);
      expect(
        unmatched.map((entry) => [entry.path, entry.session_id, entry.response.status]),
      ).toEqual([
        [paths[0], null, 404],
        [paths[1], null, 404],
        [paths[2], null, 404],
        [paths[3], null, 404],
        [paths[4], session.session_id, 404],
      ]);
    });

    it("serves only the delivered offer on the engagement page", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        offer_scheme: "eu-eaa-offer://",
        offer_mutation: { unset: ["/credential_issuer"] },
      });

      const page = await request(app).get(`/ui/sessions/${session.session_id}/engage`);
      const withoutGui = await request(createApp({ ...scenarioConfig, gui_enabled: false })).get(
        `/ui/sessions/${session.session_id}/engage`,
      );

      expect(page.status).toBe(200);
      expect(page.text).toContain(
        `<a class="btn btn-primary btn-lg" id="engage-offer" href="${session.deeplink.replaceAll("&", "&amp;").replaceAll('"', "&quot;")}">`,
      );
      expect(page.text).toContain("<svg");
      expect(page.text).not.toContain(session.session_id);
      expect(withoutGui.status).toBe(404);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.events.map((event) => event.type)).toContain(
        "credential_offer_engagement_page_served",
      );
    });

    it("lists a session's requests with every unattributed request since it was created", async () => {
      const app = createApp(config);
      await request(app).get("/.well-known/oauth-authorization-server");
      // The window's millisecond-inclusive `from` needs the next tick to exclude this request.
      const preSessionRequestCompletedAt = Date.now();
      while (Date.now() === preSessionRequestCompletedAt) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        credential_offer_mode: "credential_offer_uri",
      });
      await request(app).get(new URL(session.offer_url).pathname);
      await request(app).get(conformingMetadataPath);
      await request(app).get("/.well-known/openid-credential-issuer");

      const response = await getJson<{
        session_id: string;
        window: { from: string; to: string };
        requests: Oid4vciHttpRequestCapture[];
        unattributed_requests: Oid4vciHttpRequestCapture[];
      }>(app, `/sessions/${session.session_id}/requests`);

      expect(response.session_id).toBe(session.session_id);
      expect(response.requests.map((entry) => entry.path)).toEqual([
        new URL(session.offer_url).pathname,
      ]);
      expect(response.unattributed_requests.map((entry) => [entry.path, entry.unmatched])).toEqual([
        [conformingMetadataPath, undefined],
        ["/.well-known/openid-credential-issuer", true],
      ]);
      expect(response.window.from <= response.unattributed_requests[0].at).toBe(true);
      expect((await request(app).get(`/sessions/${randomUUID()}/requests`)).status).toBe(404);
    });
  });
});
