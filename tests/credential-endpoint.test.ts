import type { Express } from "express";
import { CompactEncrypt, exportJWK, generateKeyPair, importJWK } from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { credoOpenId4VciIssuer } from "../src/openid4vci/credo-issuer.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { SessionCredentialDefinition } from "../src/types.js";
import { createIssuerTestEnvironment, issuerPath, requireIssuer } from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import type { SessionCreateResponse } from "./support/issuance.js";
import { credentialProofJwt, preAuthorizedToken } from "./support/issuance.js";
import { dpopProof, generateEs256Key } from "./support/keys.js";

let environment: IssuerTestEnvironment | undefined;
let store!: CaptureStore;
let app!: Express;
let issuerConfig!: IssuerTestEnvironment["config"];

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "credential-endpoint-" });
  store = new CaptureStore(environment.config);
  app = createApp(environment.config, store);
  issuerConfig = issuerAppConfig(
    environment.config,
    requireIssuer(environment.config, "eu-pid-device-bound"),
  );
});

afterAll(() => environment?.cleanup());
afterEach(() => vi.restoreAllMocks());
function requiredEnvironment(): IssuerTestEnvironment {
  if (!environment) throw new Error("test environment missing");
  return environment;
}

async function preparedCredentialRequest() {
  const sessionResponse = await request(app)
    .post("/sessions")
    .send({ flow: "pre_authorized_code" });
  expect(sessionResponse.status).toBe(201);
  const session = sessionResponse.body as SessionCreateResponse;
  const dpop = await generateEs256Key();
  const token = await preAuthorizedToken(
    app,
    session,
    dpop,
    environment?.config.issuer_base_url ?? "",
  );
  const holder = await generateEs256Key();
  const credentialPath = `${issuerPath(session.issuer_configuration_id)}/credential`;
  const proof = await credentialProofJwt(
    holder,
    token.c_nonce,
    `${environment?.config.issuer_base_url}${issuerPath(session.issuer_configuration_id)}`,
    issuerConfig,
  );
  const body = {
    credential_configuration_id: session.credential_configuration_id,
    proofs: { jwt: [proof] },
  };
  const headers = {
    authorization: `DPoP ${token.access_token}`,
    DPoP: await dpopProof(dpop, {
      method: "POST",
      url: `${environment?.config.issuer_base_url}${credentialPath}`,
      accessToken: token.access_token,
    }),
  };
  return { session, token, body, headers, credentialPath };
}

describe("POST /issuers/:issuerConfigurationId/credential", () => {
  it("accepts a plain JSON Credential Request", async () => {
    const prepared = await preparedCredentialRequest();
    const response = await request(app)
      .post(prepared.credentialPath)
      .set(prepared.headers)
      .send(prepared.body);
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.body.credentials).toEqual([{ credential: expect.any(String) }]);
  });

  it("returns invalid_encryption_parameters for an empty application/jwt body", async () => {
    const prepared = await preparedCredentialRequest();
    const response = await request(app)
      .post(prepared.credentialPath)
      .set(prepared.headers)
      .type("application/jwt")
      .send("");
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "invalid_encryption_parameters",
      error_description: "Encrypted Credential Request body must be a compact JWE",
    });
  });

  it("decrypts an application/jwt Credential Request before forwarding it", async () => {
    const prepared = await preparedCredentialRequest();
    const metadataResponse = await request(app).get(
      `/.well-known/openid-credential-issuer/issuers/${prepared.session.issuer_configuration_id}`,
    );
    expect(metadataResponse.status).toBe(200);
    const requestEncryption = metadataResponse.body.credential_request_encryption as {
      jwks: { keys: Record<string, unknown>[] };
    };
    const issuerJwk = requestEncryption.jwks.keys[0];
    const encrypted = await new CompactEncrypt(Buffer.from(JSON.stringify(prepared.body), "utf8"))
      .setProtectedHeader({
        alg: "ECDH-ES",
        enc: "A256GCM",
        kid: typeof issuerJwk.kid === "string" ? issuerJwk.kid : undefined,
      })
      .encrypt(await importJWK(issuerJwk as never, "ECDH-ES"));

    const response = await request(app)
      .post(prepared.credentialPath)
      .set(prepared.headers)
      .type("application/jwt")
      .send(encrypted);
    expect(response.status, response.text).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.body.credentials).toEqual([{ credential: expect.any(String) }]);
  });

  it("rejects response encryption requested on an unencrypted request", async () => {
    const prepared = await preparedCredentialRequest();
    const responseKeyPair = await generateKeyPair("ECDH-ES", { crv: "P-256", extractable: true });
    const responseJwk = {
      ...(await exportJWK(responseKeyPair.publicKey)),
      alg: "ECDH-ES",
      use: "enc",
      kid: "wallet-response-key",
    };
    const response = await request(app)
      .post(prepared.credentialPath)
      .set(prepared.headers)
      .send({
        ...prepared.body,
        credential_response_encryption: { jwk: responseJwk, enc: "A256GCM" },
      });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "invalid_encryption_parameters",
      error_description: "credential_response_encryption requires an encrypted Credential Request",
    });
  });
  it("rejects a request whose pinned Attestbook definition is no longer active", async () => {
    const prepared = await preparedCredentialRequest();
    const session = store.getSession(prepared.session.session_id);
    if (!session) throw new Error("session capture missing");
    const pinned: SessionCredentialDefinition = {
      source: "attestbook",
      origin: requiredEnvironment().config.issuer_base_url,
      rulebook_id: "rulebook-test",
      version: "1.0",
      content_digest: "stale",
      attestation: "Membership Card",
      vct: "urn:attestbook:membership-card",
      vct_source: "attestation_name",
    };
    session.credential_definition = pinned;
    const response = await request(app)
      .post(prepared.credentialPath)
      .set(prepared.headers)
      .send(prepared.body);
    expect(response.status).toBe(400);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toEqual({
      error: "invalid_credential_request",
      error_description:
        "the offer was made under rulebook version 1.0, which is no longer active; request a new offer",
    });
    expect(session.events.at(-1)).toMatchObject({
      type: "credential_definition_superseded",
      detail: { pinned_version: "1.0", active_version: null },
    });
  });

  it("pins the completed-without-response 500 path when Credo calls next without sending", async () => {
    const prepared = await preparedCredentialRequest();
    const issuer = await credoOpenId4VciIssuer(requiredEnvironment().config, store);
    vi.spyOn(issuer, "forward").mockImplementation((_req, _res, next) => next());
    const response = await request(app)
      .post(prepared.credentialPath)
      .set(prepared.headers)
      .send(prepared.body);
    expect(response.status).toBe(500);
    expect(response.body).toEqual({
      error: "internal_error",
      message: "Credo Credential endpoint completed without sending a response",
    });
  });
});
