import type { Express } from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { issuerAppConfig } from "../../src/configurations/resolve-urls.js";
import {
  CONFORMING_ISSUER_ID,
  createIssuerTestEnvironment,
  createTestApp,
  issuerPath,
  requireIssuer,
} from "./environment.js";
import type { IssuerTestEnvironment } from "./environment.js";
import { getJson } from "./http.js";
import {
  type CredentialResponse,
  createIssuanceSession,
  credentialProofJwt,
  preAuthorizedToken,
} from "./issuance.js";
import { dpopProof, generateEs256Key } from "./keys.js";
import {
  type VpSessionResponse,
  createVpSession,
  dcqlForClaims,
  encryptedAuthorizationResponse,
  fetchRequestObject,
  sdJwtCredential,
  sdJwtPresentation,
} from "./presentation.js";

let environment: IssuerTestEnvironment | undefined;
let config!: IssuerTestEnvironment["config"];
let app!: Express;
let issuerConfig!: IssuerTestEnvironment["config"];

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "support-test-" });
  config = environment.config;
  app = createTestApp(config);
  issuerConfig = issuerAppConfig(config, requireIssuer(config, CONFORMING_ISSUER_ID));
});

afterAll(() => environment?.cleanup());

describe("shared protocol test support", () => {
  it("issues a credential through the pre-authorized flow with DPoP and a proof JWT", async () => {
    const session = await createIssuanceSession(app, { flow: "pre_authorized_code" });
    const dpopKey = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpopKey, config.issuer_base_url);
    const walletKey = await generateEs256Key();
    const credentialPath = `${issuerPath(session.issuer_configuration_id)}/credential`;
    const proof = await credentialProofJwt(
      walletKey,
      token.c_nonce,
      `${config.issuer_base_url}${issuerPath(session.issuer_configuration_id)}`,
      issuerConfig,
    );

    const response = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set(
        "DPoP",
        await dpopProof(dpopKey, {
          method: "POST",
          url: `${config.issuer_base_url}${credentialPath}`,
          accessToken: token.access_token,
        }),
      )
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const credential = (response.body as CredentialResponse).credentials[0]?.credential;
    expect(credential).toEqual(expect.any(String));
    expect(credential?.split("~").length).toBeGreaterThan(1);
  });

  it("validates an SD-JWT presentation submitted to a VP session", async () => {
    const session = await createVpSession(app, {
      redirect_uri: "https://rp.example.test/complete",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const requestObject = await fetchRequestObject(app, session);
    const requestParts = requestObject.split(".");
    expect(requestParts).toHaveLength(3);
    expect(requestParts.every((part) => part.length > 0)).toBe(true);

    const credential = await sdJwtCredential(issuerConfig, config.credential_configuration_id);
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
  });
});
