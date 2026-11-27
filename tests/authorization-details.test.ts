import { createHash, randomBytes } from "node:crypto";
import type { Express } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  mdocCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type CredentialOfferResponse,
  type SessionCreateResponse,
  type TokenResponse,
  credentialNonce,
  postToken,
  preAuthorizedToken,
  walletAuthorizationCallback,
} from "./support/issuance.js";
import { type TestKey, generateEs256Key } from "./support/keys.js";
import { serverTestSuite } from "./support/server.js";

const {
  config,
  conformingIssuerId,
  conformingIssuerPath,
  conformingMetadataPath,
  conformingAuthorizationServerMetadataPath,
  conformingProofJwt,
  postDpopProof,
} = serverTestSuite("authorization-details-test-");

describe("OpenID4VCI Authorization Details", () => {
  const clientId = "https://wallet.example.test";
  const redirectUri = `${clientId}/callback`;
  const parPath = `${conformingIssuerPath}/par`;
  const credentialPath = `${conformingIssuerPath}/credential`;
  const sdJwtId = sdJwtCredentialConfigurationId(config, "key-attestation-required");
  const mdocId = mdocCredentialConfigurationId(config, "key-attestation-required");

  async function scopeOf(app: Express, credentialConfigurationId: string): Promise<string> {
    const metadata = await getJson<{
      credential_configurations_supported: Record<string, JsonRecord>;
    }>(app, conformingMetadataPath);
    return String(metadata.credential_configurations_supported[credentialConfigurationId]?.scope);
  }

  function details(...credentialConfigurationIds: string[]): string {
    return JSON.stringify(
      credentialConfigurationIds.map((id) => ({
        type: "openid_credential",
        credential_configuration_id: id,
      })),
    );
  }

  /** A wallet-initiated PAR, as the IT-Wallet demo wallet sends it, plus the given parameters. */
  async function pushAuthorizationRequest(app: Express, parameters: Record<string, string>) {
    const codeVerifier = randomBytes(48).toString("base64url");
    const response = await request(app)
      .post(parPath)
      .type("form")
      .send({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        state: "wallet-state",
        code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
        code_challenge_method: "S256",
        ...parameters,
      });
    return { response, codeVerifier };
  }

  async function authorizationCodeToken(
    app: Express,
    requestUri: string,
    codeVerifier: string,
    dpop: TestKey,
  ): Promise<TokenResponse> {
    const callback = await walletAuthorizationCallback(
      app,
      conformingIssuerId,
      clientId,
      requestUri,
    );
    return postToken(
      app,
      {
        grant_type: "authorization_code",
        code: String(callback.searchParams.get("code")),
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      },
      dpop,
      config.issuer_base_url,
      conformingIssuerId,
    );
  }

  async function postCredential(
    app: Express,
    token: TokenResponse,
    dpop: TestKey,
    walletKey: TestKey,
    body: JsonRecord,
  ) {
    const nonce = await credentialNonce(app, conformingIssuerId);
    return request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        ...body,
        proofs: { jwt: [await conformingProofJwt(walletKey, nonce, walletKey, clientId)] },
      });
  }

  it("grants credential_identifiers for Authorization Details and issues by credential_identifier", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);
    const dpop = await generateEs256Key();
    const walletKey = await generateEs256Key();

    const { response: pushed, codeVerifier } = await pushAuthorizationRequest(app, {
      scope: await scopeOf(app, sdJwtId),
      authorization_details: details(sdJwtId),
    });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const token = await authorizationCodeToken(
      app,
      String(pushed.body.request_uri),
      codeVerifier,
      dpop,
    );

    expect(token.authorization_details).toEqual([
      {
        type: "openid_credential",
        credential_configuration_id: sdJwtId,
        credential_identifiers: [expect.any(String)],
      },
    ]);
    const [granted] = token.authorization_details as Array<{ credential_identifiers: string[] }>;
    const identifier = String(granted?.credential_identifiers[0]);
    const tokenCapture = store.oid4vciRequests.find((capture) => capture.path.endsWith("/token"));
    expect(tokenCapture?.response?.body).toMatchObject({
      authorization_details: token.authorization_details,
    });

    // OpenID4VCI 1.0 Section 8.2: once identifiers were returned, the configuration id is refused.
    const byConfiguration = await postCredential(app, token, dpop, walletKey, {
      credential_configuration_id: sdJwtId,
    });
    expect(byConfiguration.status).toBe(400);
    expect(byConfiguration.body).toMatchObject({ error: "invalid_credential_request" });

    const unknown = await postCredential(app, token, dpop, walletKey, {
      credential_identifier: "never-granted",
    });
    expect(unknown.status).toBe(400);
    expect(unknown.body).toMatchObject({ error: "unknown_credential_identifier" });

    const issued = await postCredential(app, token, dpop, walletKey, {
      credential_identifier: identifier,
    });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const [session] = [...store.sessions.values()];
    const capture = await getJson<SessionCapture>(app, `/sessions/${session?.session_id}`);
    expect(capture.status).toBe("credential_issued");
    expect(capture.raw?.credential_request).toMatchObject({ credential_identifier: identifier });
    expect(capture.raw?.credential_request).not.toHaveProperty("credential_configuration_id");
  });

  it("authorizes Authorization Details sent without a scope by their Credential Configuration", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);

    const { response: pushed, codeVerifier } = await pushAuthorizationRequest(app, {
      authorization_details: details(sdJwtId),
    });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const [session] = [...store.sessions.values()];
    expect(session?.credential_configuration_id).toBe(sdJwtId);

    const token = await authorizationCodeToken(
      app,
      String(pushed.body.request_uri),
      codeVerifier,
      await generateEs256Key(),
    );
    expect(token.authorization_details).toMatchObject([{ credential_configuration_id: sdJwtId }]);
  });

  it("refuses invalid Authorization Details at PAR and leaves no session behind", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);
    const mdocScope = await scopeOf(app, mdocId);

    const refusals: Array<[Record<string, string>, string]> = [
      [{ authorization_details: "not-json" }, "must be a non-empty JSON array"],
      [{ authorization_details: "[]" }, "must be a non-empty JSON array"],
      [{ authorization_details: '[{"type":"other"}]' }, "type 'other' is not supported"],
      [{ authorization_details: '[{"type":"openid_credential"}]' }, "must name a"],
      [
        { authorization_details: details("urn:example:unknown") },
        "is not supported by this issuer",
      ],
      [{ scope: mdocScope, authorization_details: details(sdJwtId) }, "scope does not include"],
    ];
    for (const [parameters, description] of refusals) {
      const { response } = await pushAuthorizationRequest(app, parameters);
      expect(response.status, JSON.stringify(response.body)).toBe(400);
      expect(response.body.error).toBe("invalid_authorization_details");
      expect(String(response.body.error_description)).toContain(description);
    }
    expect(store.sessions.size).toBe(0);
  });

  it("grants Authorization Details requested at the token endpoint of a pre-authorized offer", async () => {
    const app = createApp(config);
    const dpop = await generateEs256Key();
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
    const tokenPath = `${conformingIssuerPath}/token`;
    const tokenRequest = (credentialConfigurationId: string) => ({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": String(grant?.["pre-authorized_code"]),
      authorization_details: details(credentialConfigurationId),
    });

    const otherId = session.credential_configuration_id === sdJwtId ? mdocId : sdJwtId;
    const refused = await request(app)
      .post(tokenPath)
      .set("DPoP", await postDpopProof(dpop, tokenPath))
      .type("form")
      .send(tokenRequest(otherId));
    expect(refused.status).toBe(400);
    expect(refused.body).toMatchObject({ error: "invalid_authorization_details" });

    const token = await postToken(
      app,
      tokenRequest(session.credential_configuration_id),
      dpop,
      config.issuer_base_url,
      conformingIssuerId,
    );
    expect(token.authorization_details).toEqual([
      {
        type: "openid_credential",
        credential_configuration_id: session.credential_configuration_id,
        credential_identifiers: [expect.any(String)],
      },
    ]);

    const scopeOnly = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const scopeOnlyToken = await preAuthorizedToken(app, scopeOnly, dpop, config.issuer_base_url);
    expect(scopeOnlyToken).not.toHaveProperty("authorization_details");
  });

  it("advertises the openid_credential Authorization Details type", async () => {
    const app = createApp(config);
    const metadata = await getJson<JsonRecord>(app, conformingAuthorizationServerMetadataPath);
    expect(metadata.authorization_details_types_supported).toEqual(["openid_credential"]);
  });
});
