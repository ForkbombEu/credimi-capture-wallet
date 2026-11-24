import { readFileSync } from "node:fs";
import type { Express } from "express";
import { type JWK, SignJWT, importJWK } from "jose";
import request from "supertest";
import { expect } from "vitest";
import { issuerCertificatePath, privateJwkPath } from "../../src/config.js";
import type { AppConfig, JsonRecord } from "../../src/types.js";
import { issuerPath } from "./environment.js";
import { getJson, postJson } from "./http.js";
import { type TestKey, dpopProof } from "./keys.js";

export interface SessionCreateResponse extends JsonRecord {
  session_id: string;
  issuer_configuration_id: string;
  issuer_identifier: string;
  authorization_server_identifier: string;
  flow: "pre_authorized_code" | "authorization_code";
  credential_offer_mode: "credential_offer" | "credential_offer_uri";
  credential_configuration_id: string;
  status_list_enabled: boolean;
  fixture_id?: string;
  document_number?: string;
  digest_algorithm?: string;
  offer_url: string;
  deeplink: string;
}

export interface TokenResponse extends JsonRecord {
  access_token: string;
  c_nonce: string;
}

export interface CredentialOfferResponse extends JsonRecord {
  credential_configuration_ids: string[];
  grants: Record<string, JsonRecord>;
}

export interface CredentialResponse extends JsonRecord {
  credentials: Array<{ credential: string }>;
}

export async function createIssuanceSession(
  app: Express,
  body: object,
): Promise<SessionCreateResponse> {
  return postJson<SessionCreateResponse>(app, "/sessions", body);
}

export async function postToken(
  app: Express,
  body: Record<string, string>,
  dpopKey: TestKey,
  baseUrl: string,
  issuerConfigurationId: string,
): Promise<TokenResponse> {
  const tokenPath = `${issuerPath(issuerConfigurationId)}/token`;
  const response = await request(app)
    .post(tokenPath)
    .set("DPoP", await dpopProof(dpopKey, { method: "POST", url: `${baseUrl}${tokenPath}` }))
    .type("form")
    .send(body);
  expect(response.status, JSON.stringify(response.body)).toBeLessThan(400);
  return response.body as TokenResponse;
}

export async function preAuthorizedToken(
  app: Express,
  session: SessionCreateResponse,
  dpopKey: TestKey,
  baseUrl: string,
): Promise<TokenResponse> {
  const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
  const grant = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  if (!grant) throw new Error("pre-authorized grant unavailable");
  return postToken(
    app,
    {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": String(grant["pre-authorized_code"]),
    },
    dpopKey,
    baseUrl,
    session.issuer_configuration_id,
  );
}

export async function credentialProofJwt(
  key: TestKey,
  nonce: string,
  audience: string,
  issuerConfig: AppConfig,
  attestedKey = key,
  clientId?: string,
): Promise<string> {
  const keyAttestation = await keyAttestationJwt(issuerConfig, attestedKey, nonce);
  return new SignJWT({
    ...(clientId ? { iss: clientId } : {}),
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: key.publicJwk as unknown as JWK,
      key_attestation: keyAttestation,
    })
    .sign(key.privateKey);
}

async function keyAttestationJwt(
  issuerConfig: AppConfig,
  key: TestKey,
  nonce: string,
): Promise<string> {
  const privateJwk = JSON.parse(readFileSync(privateJwkPath(issuerConfig.data_dir), "utf8")) as JWK;
  const certificate = readFileSync(issuerCertificatePath(issuerConfig.data_dir), "utf8")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iat: now,
    exp: now + 300,
    nonce,
    attested_keys: [key.publicJwk],
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "key-attestation+jwt",
      x5c: [certificate],
    })
    .sign(await importJWK(privateJwk, "ES256"));
}
