import { createHash } from "node:crypto";
import type { Express } from "express";
import { CompactEncrypt, type JWK, SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";
import request from "supertest";
import { expect } from "vitest";
import { PID_SD_JWT_VCT } from "../../src/credentials/definitions.js";
import { issueSdJwtCredential } from "../../src/credentials/signing.js";
import type { AppConfig, JsonRecord } from "../../src/types.js";
import type { TestKey } from "./keys.js";

export function dcqlForClaims(claims: string[]): JsonRecord {
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

export async function sdJwtCredential(
  issuerConfig: AppConfig,
  credentialConfigurationId: string,
): Promise<{ compact: string; privateKey: TestKey["privateKey"] }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const holderJwk = (await exportJWK(publicKey)) as unknown as JsonRecord;
  return {
    compact: await issueSdJwtCredential({
      config: issuerConfig,
      credentialConfigurationId,
      holderJwk,
    }),
    privateKey,
  };
}

export async function sdJwtPresentation(options: {
  credential: { compact: string; privateKey: TestKey["privateKey"] };
  authorizationRequest: JsonRecord;
  disclosedClaims: string[];
  audience?: string;
  transactionDataHashes?: string[];
  transactionDataHashesAlg?: string;
}): Promise<string> {
  const [issuerJwt, ...tail] = options.credential.compact.split("~");
  const selected = tail
    .filter((part) => part.length > 0)
    .filter((disclosure) => options.disclosedClaims.includes(disclosureClaimName(disclosure)));
  const withoutKeyBinding = `${issuerJwt}~${selected.join("~")}~`;
  const keyBindingJwt = await new SignJWT({
    iat: Math.floor(Date.now() / 1000),
    aud: options.audience ?? String(options.authorizationRequest.client_id),
    nonce: String(options.authorizationRequest.nonce),
    sd_hash: createHash("sha256").update(withoutKeyBinding).digest("base64url"),
    ...(options.transactionDataHashes
      ? { transaction_data_hashes: options.transactionDataHashes }
      : {}),
    ...(options.transactionDataHashesAlg
      ? { transaction_data_hashes_alg: options.transactionDataHashesAlg }
      : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
    .sign(options.credential.privateKey);
  return `${withoutKeyBinding}${keyBindingJwt}`;
}

export async function encryptedAuthorizationResponse(
  authorizationRequest: JsonRecord,
  payload: JsonRecord,
  enc = "A256GCM",
): Promise<string> {
  const clientMetadata = authorizationRequest.client_metadata as JsonRecord;
  const jwks = clientMetadata.jwks as { keys: JsonRecord[] };
  const publicJwk = jwks.keys[0] as unknown as JWK;
  return new CompactEncrypt(Buffer.from(JSON.stringify(payload), "utf8"))
    .setProtectedHeader({
      alg: "ECDH-ES",
      enc,
      kid: publicJwk.kid,
    })
    .encrypt(await importJWK(publicJwk, "ECDH-ES"));
}

function disclosureClaimName(disclosure: string): string {
  const decoded = JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[];
  return typeof decoded[1] === "string" ? decoded[1] : "";
}

export interface VpSessionCreateResponse extends JsonRecord {
  session_id: string;
  request_delivery: "by_reference" | "by_value" | "plain";
  request_uri?: string;
  request_uri_method?: string;
  scheme?: string;
  redirect_uri?: string;
  response_uri?: string;
  deeplink: string;
  dc_api_request?: { protocol: string; data: JsonRecord };
  authorization_request: JsonRecord;
  status: string;
}

export interface VpSessionResponse extends JsonRecord {
  session_id: string;
  status: string;
  redirect_uri_visited_at?: string;
  redirect_uri_visit_count?: number;
  authorization_request: JsonRecord;
  decoded_presentations?: JsonRecord;
  request_mutation?: JsonRecord;
  response_scenario?: JsonRecord;
  verifier_attestation?: JsonRecord;
  dc_api?: {
    request: { protocol: string; data: JsonRecord };
    expected_origin: string;
    expires_at: string;
    invocation?: JsonRecord;
  };
  checks: {
    presentation_valid: boolean | null;
    vp_token_format_valid: boolean;
    nonce_verified: boolean;
    transaction_data_verified: boolean | null;
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
  events: Array<{ type: string; detail: JsonRecord }>;
  raw?: {
    authorization_request_jwt?: string;
    authorization_request_jwe?: string;
    authorization_request_delivered?: JsonRecord;
    outer_request_delivered?: JsonRecord;
    request_uri_response_http?: { status: number; headers: JsonRecord; body: string };
    request_uri_http?: {
      method: string;
      target: string;
      headers: JsonRecord;
      body?: string;
    };
    presentation_response?: JsonRecord;
    presentation_response_http?: {
      method: string;
      headers: JsonRecord;
      body: string;
    };
    presentation_response_verifier_http?: {
      status: number;
      headers: JsonRecord;
      body: string;
    };
    redirect_uri_visits?: Array<{ method: string; headers: JsonRecord }>;
    presentation_response_decrypted?: JsonRecord;
    presentation_response_decrypted_raw?: string;
    decoded_presentations?: JsonRecord;
  };
}

export async function createVpSession(
  app: Express,
  body: object,
): Promise<VpSessionCreateResponse> {
  const response = await request(app).post("/openid4vp/sessions").send(body);
  expect(response.status).toBe(201);
  return response.body as VpSessionCreateResponse;
}

export async function fetchRequestObject(
  app: Express,
  session: VpSessionCreateResponse,
): Promise<string> {
  if (!session.request_uri) throw new Error("VP session has no request URI");
  const response = await request(app).get(new URL(session.request_uri).pathname);
  expect(response.status).toBeLessThan(400);
  return response.text;
}
