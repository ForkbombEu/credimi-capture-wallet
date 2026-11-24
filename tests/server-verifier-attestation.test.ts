import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CredoWebCrypto, Kms, X509Certificate, X509KeyUsage } from "@credo-ts/core";
import type { Express } from "express";
import { type JWK, compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createJwkSigningContext, initIssuer } from "../src/config/key-material.js";
import { verifierCertificatePath, verifierPrivateJwkPath } from "../src/config/paths.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  dcqlForClaims,
  sdJwtPresentation,
} from "./support/presentation.js";
import { type JwksResponse, serverTestSuite } from "./support/server.js";
const { config, pidSdJwtCredential } = serverTestSuite("fake-issuer-test-");
describe("verifier attestation requests", () => {
  async function attestationRequest(app: Express, body: JsonRecord = {}) {
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      client_id_scheme: "verifier_attestation",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      ...body,
    });
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const header = decodeProtectedHeader(requestObject.text) as JsonRecord;
    const attestation =
      typeof header.jwt === "string" ? (decodeJwt(header.jwt) as JsonRecord) : undefined;
    return { session, jwt: requestObject.text, header, attestation };
  }

  it("carries an attestation bound to the client identifier and the signing key", async () => {
    const app = createApp(config);
    const { session, jwt, attestation } = await attestationRequest(app);

    expect(session.authorization_request.client_id).toBe(
      `verifier_attestation:${attestation?.sub}`,
    );
    const confirmationKey = (attestation?.cnf as JsonRecord).jwk as JsonRecord;
    await expect(
      compactVerify(jwt, await importJWK(confirmationKey as unknown as JWK, "ES256")),
    ).resolves.toBeDefined();
    // A wallet must not be forced into a redirect URI match when the attestation makes no claim.
    expect(attestation).not.toHaveProperty("redirect_uris");
    expect(decodeProtectedHeader(jwt).x5c).toBeUndefined();
  });

  it("publishes the attestation issuer key so a wallet can be configured to trust it", async () => {
    const app = createApp(config);
    const { attestation } = await attestationRequest(app);
    const jwks = await getJson<JwksResponse>(
      app,
      "/openid4vp/verifier-attestation-issuer/jwks.json",
    );
    expect(attestation?.iss).toBe(
      `${config.issuer_base_url}/openid4vp/verifier-attestation-issuer`,
    );
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("attests a subject that differs from the client identifier when asked", async () => {
    const app = createApp(config);
    const { session, attestation } = await attestationRequest(app, {
      verifier_attestation: { subject: "someone-else.example" },
    });

    expect(attestation?.sub).toBe("someone-else.example");
    expect(session.authorization_request.client_id).not.toBe(
      "verifier_attestation:someone-else.example",
    );
  });

  it("names an issuer outside the wallet's trusted list when asked", async () => {
    const app = createApp(config);
    const { attestation } = await attestationRequest(app, {
      verifier_attestation: { issuer: "https://untrusted-attestation-issuer.invalid" },
    });

    expect(attestation?.iss).toBe("https://untrusted-attestation-issuer.invalid");
  });

  it("breaks only the attestation signature, leaving the request object signed", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const { jwt, header, attestation } = await attestationRequest(app, {
      verifier_attestation: { signature: "corrupt" },
    });

    const issuerJwks = await getJson<JwksResponse>(
      app,
      "/openid4vp/verifier-attestation-issuer/jwks.json",
    );
    await expect(
      compactVerify(
        String(header.jwt),
        await importJWK(issuerJwks.keys[0] as unknown as JWK, "ES256"),
      ),
    ).rejects.toThrow();
    const confirmationKey = (attestation?.cnf as JsonRecord).jwk as JsonRecord;
    await expect(
      compactVerify(jwt, await importJWK(confirmationKey as unknown as JWK, "ES256")),
    ).resolves.toBeDefined();
  });

  it("signs with a key that does not match the confirmation claim when asked", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const { jwt, attestation } = await attestationRequest(app, {
      request_behavior: { signing_key: "unrelated" },
    });

    const confirmationKey = (attestation?.cnf as JsonRecord).jwk as JsonRecord;
    await expect(
      compactVerify(jwt, await importJWK(confirmationKey as unknown as JWK, "ES256")),
    ).rejects.toThrow();
  });

  it("includes redirect_uris in the attestation when asked", async () => {
    const app = createApp(config);
    const { attestation } = await attestationRequest(app, {
      verifier_attestation: { redirect_uris: ["https://relying-party.example/callback"] },
    });

    expect(attestation?.redirect_uris).toEqual(["https://relying-party.example/callback"]);
  });

  it("refuses attestation content without the matching client identifier prefix", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ verifier_attestation: { subject: "someone-else.example" } });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "verifier_attestation_requires_verifier_attestation_client_id",
    });
  });

  it("refuses a corrupt attestation signature when scenarios are disabled", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        client_id_scheme: "verifier_attestation",
        verifier_attestation: { signature: "corrupt" },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "request_behavior_not_enabled" });
  });

  it("verifies a presentation returned for an attestation-based request", async () => {
    const app = createApp(config);
    const { session } = await attestationRequest(app);
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.presentation_valid).toBe(true);
  });
});

describe("verifier attestation requests under a certificate with only a URI SAN", () => {
  // The shipped test certificate also carries a dNSName SAN, which hid the deployed failure:
  // Credo treated the prefix as x509_san_dns and refused a certificate without a matching one.
  const uriSanDataDir = mkdtempSync(join(tmpdir(), "fake-issuer-uri-san-test-"));
  const uriSanConfig = { ...config, data_dir: uriSanDataDir };

  beforeAll(async () => {
    await initIssuer({
      issuer_base_url: uriSanConfig.issuer_base_url,
      data_dir: uriSanDataDir,
      credential_configuration_id: uriSanConfig.credential_configuration_id,
      force: true,
    });
    const privateJwk = JSON.parse(
      readFileSync(verifierPrivateJwkPath(uriSanDataDir), "utf8"),
    ) as JsonRecord;
    const { d: _private, ...publicJwk } = privateJwk;
    const authorityKey = Kms.PublicJwk.fromUnknown(publicJwk);
    authorityKey.keyId = String(privateJwk.kid);
    const certificate = await X509Certificate.create(
      {
        authorityKey,
        issuer: { countryName: "IT", commonName: "Credimi URI SAN Verifier" },
        validity: {
          notBefore: new Date("2024-01-01T00:00:00Z"),
          notAfter: new Date("2034-01-01T00:00:00Z"),
        },
        extensions: {
          keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
          subjectAlternativeName: { name: [{ type: "url", value: uriSanConfig.issuer_base_url }] },
          basicConstraints: { ca: false },
        },
      },
      new CredoWebCrypto(createJwkSigningContext(privateJwk, String(privateJwk.kid)) as never),
    );
    writeFileSync(verifierCertificatePath(uriSanDataDir), certificate.toString("pem"));
  });

  afterAll(() => {
    rmSync(uriSanDataDir, { recursive: true, force: true });
  });

  async function uriSanAttestationSession(app: Express, body: JsonRecord = {}) {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "direct_post",
        client_id_scheme: "verifier_attestation",
        request_uri_method: "post",
        presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
        ...body,
      });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    return response.body as VpSessionCreateResponse;
  }

  it("uses a certificate without any dNSName SAN", () => {
    const certificate = X509Certificate.fromEncodedCertificate(
      readFileSync(verifierCertificatePath(uriSanDataDir), "utf8"),
    );
    expect(certificate.sanDnsNames).toEqual([]);
    expect(certificate.sanUriNames).toEqual([uriSanConfig.issuer_base_url]);
  });

  it("delivers the attestation request by GET and POST request_uri, and on wallet_nonce", async () => {
    const app = createApp(uriSanConfig);
    const session = await uriSanAttestationSession(app);
    const clientId = String(session.authorization_request.client_id);
    expect(clientId).toBe("verifier_attestation:issuer.example.test");

    const requestPath = `/openid4vp/sessions/${session.session_id}/request`;
    const fetched = await request(app).get(requestPath);
    const posted = await request(app).post(requestPath).type("form").send({});
    const resigned = await request(app)
      .post(requestPath)
      .type("form")
      .send({ wallet_nonce: "uri-san-wallet-nonce" });

    for (const [response, walletNonce] of [
      [fetched, undefined],
      [posted, undefined],
      [resigned, "uri-san-wallet-nonce"],
    ] as const) {
      expect(response.status).toBe(200);
      const header = decodeProtectedHeader(response.text) as JsonRecord;
      expect(header).not.toHaveProperty("x5c");
      const attestation = decodeJwt(String(header.jwt)) as JsonRecord;
      expect(`verifier_attestation:${attestation.sub}`).toBe(clientId);
      const confirmationKey = (attestation.cnf as JsonRecord).jwk as JsonRecord;
      const { payload } = await compactVerify(
        response.text,
        await importJWK(confirmationKey as unknown as JWK, "ES256"),
      );
      const delivered = JSON.parse(Buffer.from(payload).toString("utf8")) as JsonRecord;
      expect(delivered.client_id).toBe(clientId);
      expect(delivered.wallet_nonce).toBe(walletNonce);
    }
  });

  it("verifies an Authorization Response under the verifier_attestation client_id", async () => {
    const app = createApp(uriSanConfig);
    const session = await uriSanAttestationSession(app);
    const presentation = await sdJwtPresentation({
      credential: await pidSdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    expect(String(session.authorization_request.client_id)).toMatch(/^verifier_attestation:/);

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ state: session.authorization_request.state, vp_token: { query_0: [presentation] } });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks).toMatchObject({ presentation_valid: true, errors: [] });
  });

  it("replaces {{response_uri}} in redirect_uris with the session's response_uri", async () => {
    const app = createApp(uriSanConfig);
    const session = await uriSanAttestationSession(app, {
      verifier_attestation: {
        redirect_uris: ["{{response_uri}}", "https://relying-party.example/callback"],
      },
    });
    const requestObject = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/request`)
      .type("form")
      .send({});
    const header = decodeProtectedHeader(requestObject.text) as JsonRecord;
    const attestation = decodeJwt(String(header.jwt)) as JsonRecord;
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );

    const expected = [session.response_uri, "https://relying-party.example/callback"];
    expect(session.response_uri).toMatch(/^http:\/\/issuer\.example\.test\/openid4vp\/sessions\//);
    expect(attestation.redirect_uris).toEqual(expected);
    expect(capture.verifier_attestation).toEqual({ redirect_uris: expected });
  });

  it("refuses {{response_uri}} for a DC API session, which has no response_uri", async () => {
    const app = createApp(uriSanConfig);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "dc_api",
        client_id_scheme: "verifier_attestation",
        verifier_attestation: { redirect_uris: ["{{response_uri}}"] },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "response_uri_placeholder_unsupported_for_dc_api" });
  });
});
