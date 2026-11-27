import { createHash, randomBytes } from "node:crypto";
import { SdJwtVcService } from "@credo-ts/core";
import type { Express } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  mdocCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { JsonRecord, Oid4vciHttpRequestCapture, SessionCapture } from "../src/types.js";
import { getJson } from "./support/http.js";
import { type CredentialResponse, credentialNonce, postToken } from "./support/issuance.js";
import { type TestKey, generateEs256Key } from "./support/keys.js";
import { serverTestSuite } from "./support/server.js";
const {
  config,
  conformingIssuerId,
  conformingIssuerPath,
  conformingMetadataPath,
  conformingProofJwt,
  postDpopProof,
} = serverTestSuite("fake-issuer-test-");
describe("wallet-initiated issuance", () => {
  const walletClientId = "https://wallet.example.test";
  const walletRedirectUri = `${walletClientId}/callback`;
  const parPath = `${conformingIssuerPath}/par`;
  const sdJwtId = sdJwtCredentialConfigurationId(config, "key-attestation-required");
  const mdocId = mdocCredentialConfigurationId(config, "key-attestation-required");

  async function supportedConfiguration(app: Express, id: string): Promise<JsonRecord> {
    const metadata = await getJson<{
      credential_configurations_supported: Record<string, JsonRecord>;
    }>(app, conformingMetadataPath);
    const configuration = metadata.credential_configurations_supported[id];
    expect(configuration?.scope).toEqual(expect.any(String));
    return configuration;
  }

  /** A PAR naming no `issuer_state`, as a Wallet starting issuance on its own sends it. */
  function walletParBody(scope: unknown, codeVerifier?: string): Record<string, string> {
    return {
      response_type: "code",
      client_id: walletClientId,
      redirect_uri: walletRedirectUri,
      state: "wallet-state",
      ...(scope === undefined ? {} : { scope: String(scope) }),
      ...(codeVerifier
        ? {
            code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
            code_challenge_method: "S256",
          }
        : {}),
    };
  }

  async function postWalletPar(app: Express, body: Record<string, string>, dpop?: TestKey) {
    const pending = request(app).post(parPath);
    if (dpop) pending.set("DPoP", await postDpopProof(dpop, parPath));
    return pending.type("form").send(body);
  }

  async function parLedger(app: Express): Promise<Oid4vciHttpRequestCapture[]> {
    const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
    return ledger.filter((capture) => capture.path === parPath);
  }

  /**
   * Follows the authorization request through the issuer's chained authorization server and
   * returns the authorization code the Wallet receives on its redirect URI.
   */
  async function authorizationCode(app: Express, requestUri: string): Promise<string> {
    const authorize = await request(app)
      .get(`${conformingIssuerPath}/authorize`)
      .query({ client_id: walletClientId, request_uri: requestUri })
      .redirects(0);
    expect(authorize.status).toBe(302);
    const upstream = new URL(String(authorize.headers.location));
    expect(upstream.pathname).toBe(`/authorization-servers/${conformingIssuerId}/authorize`);
    const approved = await request(app).get(`${upstream.pathname}${upstream.search}`).redirects(0);
    const credoCallback = new URL(String(approved.headers.location));
    const walletResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    expect(walletResponse.status).toBe(302);
    const walletCallback = new URL(String(walletResponse.headers.location));
    expect(walletCallback.origin + walletCallback.pathname).toBe(walletRedirectUri);
    expect(walletCallback.searchParams.get("state")).toBe("wallet-state");
    return String(walletCallback.searchParams.get("code"));
  }

  it("issues a credential to a Wallet that starts issuance without a Credential Offer", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);
    const configuration = await supportedConfiguration(app, sdJwtId);
    const dpop = await generateEs256Key();
    const walletKey = await generateEs256Key();
    const codeVerifier = randomBytes(48).toString("base64url");

    const pushed = await postWalletPar(app, walletParBody(configuration.scope, codeVerifier), dpop);
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    expect(pushed.body).toMatchObject({
      request_uri: expect.stringMatching(/^urn:ietf:params:oauth:request_uri:/),
      expires_in: expect.any(Number),
    });

    // The PAR created exactly one capture session, and is attributed to it.
    const sessionIds = [...store.sessions.keys()];
    expect(sessionIds).toHaveLength(1);
    const sessionId = String(sessionIds[0]);
    expect((await parLedger(app)).map((capture) => capture.session_id)).toEqual([sessionId]);
    const pushedCapture = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(pushedCapture).toMatchObject({
      initiated_by: "wallet",
      issuer_configuration_id: conformingIssuerId,
      credential_configuration_id: sdJwtId,
      flow: "authorization_code",
      status: "authorization_requested",
      checks: { pkce_present: true, state_present: true, issuer_state_present: false },
      raw: { par_request: { scope: configuration.scope, client_id: walletClientId } },
    });
    expect(pushedCapture.observed.dpop_jwk.jwk).toMatchObject(dpop.publicJwk);
    expect(pushedCapture.events).toContainEqual(
      expect.objectContaining({
        type: "wallet_initiated_issuance_requested",
        detail: { requested_scopes: [configuration.scope], credential_configuration_id: sdJwtId },
      }),
    );

    // Authorization runs through the issuer's chained authorization server, as for an offer.
    const code = await authorizationCode(app, String(pushed.body.request_uri));

    const token = await postToken(
      app,
      {
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
        redirect_uri: walletRedirectUri,
        client_id: walletClientId,
      },
      dpop,
      config.issuer_base_url,
      conformingIssuerId,
    );
    expect(token.token_type).toBe("DPoP");

    const credentialPath = `${conformingIssuerPath}/credential`;
    const nonce = await credentialNonce(app, conformingIssuerId);
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: sdJwtId,
        proofs: {
          jwt: [await conformingProofJwt(walletKey, nonce, walletKey, walletClientId)],
        },
      });
    expect(credential.status, JSON.stringify(credential.body)).toBe(200);
    const compact = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = new SdJwtVcService({} as never).fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject({
      vct: configuration.vct,
      iss: `${config.issuer_base_url}${conformingIssuerPath}`,
      cnf: { jwk: walletKey.publicJwk },
    });

    const issued = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(issued.status).toBe("credential_issued");
    expect(issued.checks).toMatchObject({
      pkce_valid: true,
      proof_jwt_present: true,
      key_attestation_verified: true,
      nonce_verified: true,
    });
    expect(issued.observed.wallet_jwks.jwks).toEqual({ keys: [walletKey.publicJwk] });
    expect(issued.raw?.credential_request).toMatchObject({ credential_configuration_id: sdJwtId });
    expect(
      (issued.raw?.oid4vci_requests ?? []).map((capture) => capture.path.split("/").pop()),
    ).toEqual(["par", "authorize", "redirect", "token", "credential", "nonce"]);
  });

  it("keeps concurrent wallet-initiated sessions and their evidence apart", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);
    const sdJwt = await supportedConfiguration(app, sdJwtId);
    const mdoc = await supportedConfiguration(app, mdocId);
    const sdJwtDpop = await generateEs256Key();
    const mdocDpop = await generateEs256Key();

    const [sdJwtPar, mdocPar] = await Promise.all([
      postWalletPar(
        app,
        walletParBody(sdJwt.scope, randomBytes(48).toString("base64url")),
        sdJwtDpop,
      ),
      postWalletPar(
        app,
        walletParBody(mdoc.scope, randomBytes(48).toString("base64url")),
        mdocDpop,
      ),
    ]);
    expect(sdJwtPar.status).toBe(201);
    expect(mdocPar.status).toBe(201);

    const sessions = [...store.sessions.values()];
    expect(sessions.map((session) => session.credential_configuration_id).sort()).toEqual(
      [mdocId, sdJwtId].sort(),
    );
    for (const session of sessions) {
      const own = session.credential_configuration_id === sdJwtId ? sdJwt : mdoc;
      const ownDpop = session.credential_configuration_id === sdJwtId ? sdJwtDpop : mdocDpop;
      expect(session.raw?.par_request?.scope).toBe(own.scope);
      expect(session.observed.dpop_jwk.jwk).toMatchObject(ownDpop.publicJwk);
      expect(session.raw?.oid4vci_requests).toHaveLength(1);
    }
  });

  it("refuses wallet-initiated requests it cannot issue and leaves no session behind", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);
    const sdJwt = await supportedConfiguration(app, sdJwtId);
    const mdoc = await supportedConfiguration(app, mdocId);
    const dpop = await generateEs256Key();
    const codeVerifier = randomBytes(48).toString("base64url");

    const refusals = [
      // A scope no credential configuration of this issuer carries.
      [walletParBody("urn:example:not-issued", codeVerifier), "invalid_scope"],
      // Several credential configurations in one session are refused, not narrowed to one.
      [walletParBody(`${sdJwt.scope} ${mdoc.scope}`, codeVerifier), "access_denied"],
      // Malformed: no scope names anything to issue.
      [walletParBody(undefined, codeVerifier), "invalid_scope"],
      // Accepted by the issuer, then refused by Credo's PKCE requirement.
      [walletParBody(sdJwt.scope), "invalid_request"],
    ] as const;
    for (const [body, error] of refusals) {
      const refused = await postWalletPar(app, body, dpop);
      expect(refused.status, JSON.stringify(refused.body)).toBe(400);
      expect(refused.body).toMatchObject({ error });
    }

    expect(store.sessions.size).toBe(0);
    const captures = await parLedger(app);
    expect(captures).toHaveLength(refusals.length);
    expect(captures.map((capture) => capture.session_id)).toEqual(refusals.map(() => null));
  });

  it("accepts a PAR without DPoP and requires DPoP at the token endpoint", async () => {
    const store = new CaptureStore(config);
    const app = createApp(config, store);
    const configuration = await supportedConfiguration(app, sdJwtId);
    const codeVerifier = randomBytes(48).toString("base64url");

    const pushed = await postWalletPar(app, walletParBody(configuration.scope, codeVerifier));
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const [session] = [...store.sessions.values()];
    expect(session?.observed.dpop_jwk.observed).toBe(false);

    const code = await authorizationCode(app, String(pushed.body.request_uri));
    const tokenBody = {
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
      redirect_uri: walletRedirectUri,
      client_id: walletClientId,
    };
    const withoutDpop = await request(app)
      .post(`${conformingIssuerPath}/token`)
      .type("form")
      .send(tokenBody);
    expect(withoutDpop.status, JSON.stringify(withoutDpop.body)).toBe(400);
    expect(withoutDpop.body).toMatchObject({ error: "invalid_dpop_proof" });

    const dpop = await generateEs256Key();
    const token = await postToken(app, tokenBody, dpop, config.issuer_base_url, conformingIssuerId);
    expect(token.token_type).toBe("DPoP");
  });
});
