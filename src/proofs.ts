import {
  type JsonWebKey as NodeJsonWebKey,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from "node:crypto";
import { type AgentContext, JwsService, Kms, X509ModuleConfig } from "@credo-ts/core";
import { type JWK, calculateJwkThumbprint, importJWK, jwtVerify } from "jose";
import type { JsonRecord, ProofHeaderCapture } from "./types.js";

const SUPPORTED_PROOF_ALGORITHM = "ES256";
const PRIVATE_JWK_PARAMETERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

export function decodeJwtHeader(jwt: string): JsonRecord {
  const [header] = jwt.split(".");
  if (!header) throw new Error("proof JWT is missing a JOSE header");
  return JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as JsonRecord;
}

export function extractProofJwts(body: JsonRecord): Array<{ jwt: string; source: string }> {
  const result: Array<{ jwt: string; source: string }> = [];
  const proof = body.proof as JsonRecord | undefined;
  if (proof && typeof proof.jwt === "string") {
    result.push({ jwt: proof.jwt, source: "credential_request.proof.jwt" });
  }

  const proofs = body.proofs as JsonRecord | undefined;
  const jwtProofs = proofs?.jwt;
  if (Array.isArray(jwtProofs)) {
    jwtProofs.forEach((jwt, index) => {
      if (typeof jwt === "string") {
        result.push({ jwt, source: `credential_request.proofs.jwt[${index}]` });
      }
    });
  }
  return result;
}

export function captureProofHeaders(body: JsonRecord): ProofHeaderCapture[] {
  return extractCredentialProofs(body).map(({ jwt, source, proofType }) => {
    const header = decodeJwtHeader(jwt);
    return {
      typ: asString(header.typ),
      alg: asString(header.alg),
      kid: asString(header.kid),
      jwk: asRecord(header.jwk),
      x5c: asStringArray(header.x5c),
      proof_type: proofType,
      key_attestation_present: typeof header.key_attestation === "string",
      source: header.jwk ? `${source}.header.jwk` : `${source}.header`,
    };
  });
}

export function jwkToJwks(jwk: JsonRecord): { keys: JsonRecord[] } {
  const key = { ...jwk };
  if (!key.alg) key.alg = "ES256";
  if (!key.use) key.use = "sig";
  return { keys: [key] };
}

export function firstWalletJwks(headers: ProofHeaderCapture[]): {
  source: string | null;
  jwks: { keys: JsonRecord[] } | null;
  observedFields: string[];
} {
  const observedFields = Array.from(
    new Set(
      headers.flatMap((header) =>
        ["typ", "alg", "kid", "jwk", "x5c"].filter((key) => key in header),
      ),
    ),
  );
  const header = headers.find((candidate) => candidate.jwk);
  if (!header?.jwk) return { source: null, jwks: null, observedFields };
  return { source: header.source, jwks: jwkToJwks(header.jwk), observedFields };
}

export async function decodeDpopHeader(dpop: string | undefined): Promise<{
  jwk: JsonRecord | null;
  thumbprint: string | null;
}> {
  if (!dpop) return { jwk: null, thumbprint: null };
  const header = decodeJwtHeader(dpop);
  const jwk = asRecord(header.jwk);
  if (!jwk) return { jwk: null, thumbprint: null };
  let thumbprint: string | null = null;
  try {
    thumbprint = await calculateJwkThumbprint(jwk as unknown as JWK);
  } catch {
    thumbprint = null;
  }
  return { jwk, thumbprint };
}

export async function verifyDpopProof(input: {
  dpop: string | undefined;
  method: string;
  url: string;
  now?: number;
}): Promise<{
  jwk: JsonRecord;
  thumbprint: string;
  jti: string;
}> {
  if (!input.dpop) throw new Error("DPoP proof is required");
  const header = decodeJwtHeader(input.dpop);
  const jwk = asRecord(header.jwk);
  if (!jwk) throw new Error("DPoP proof must contain header.jwk");
  const alg = asString(header.alg) ?? "ES256";
  const verified = await jwtVerify(input.dpop, await importJWK(jwk as unknown as JWK, alg));
  const payload = verified.payload as JsonRecord;
  if (asString(payload.htm) !== input.method.toUpperCase()) {
    throw new Error("DPoP proof htm does not match request method");
  }
  if (asString(payload.htu) !== input.url) {
    throw new Error("DPoP proof htu does not match request URL");
  }
  const jti = asString(payload.jti);
  if (!jti) throw new Error("DPoP proof must contain jti");
  const iat = typeof payload.iat === "number" ? payload.iat : null;
  const now = input.now ?? Math.floor(Date.now() / 1000);
  if (!iat || Math.abs(now - iat) > 300) throw new Error("DPoP proof iat is outside tolerance");
  const thumbprint = await calculateJwkThumbprint(jwk as unknown as JWK);
  return { jwk, thumbprint, jti };
}

export async function verifyCredentialProof(input: {
  body: JsonRecord;
  expectedNonce: string | ((nonce: string) => boolean);
  expectedAudience: string;
  expectedClientId?: string;
  agentContext?: AgentContext;
}): Promise<{
  holderJwk: JsonRecord;
  source: string;
  nonce: string;
  proofType: "jwt" | "attestation";
}> {
  const proofs = extractCredentialProofs(input.body);
  if (proofs.length === 0) throw new Error("Credential Request must contain a supported proof");
  if (proofs.length !== 1) {
    throw new Error("Exactly one jwt or attestation proof is supported per Credential Request");
  }

  const proof = proofs[0];
  if (proof.proofType === "attestation") {
    const attestation = await verifyKeyAttestation(proof.jwt, {
      expectedNonce: input.expectedNonce,
      use: "attestation",
      agentContext: input.agentContext,
    });
    return {
      holderJwk: attestation.attestedKeys[0],
      source: `${proof.source}.payload.attested_keys[0]`,
      nonce: attestation.nonce,
      proofType: "attestation",
    };
  }

  const { header, payload } = decodeCompactJwt(proof.jwt, "Credential proof JWT");
  requireHeaderValue(header, "typ", "openid4vci-proof+jwt", "Credential proof JWT");
  requireHeaderValue(header, "alg", SUPPORTED_PROOF_ALGORITHM, "Credential proof JWT");
  assertOnlyOneBindingHeader(header);
  const holderJwk = publicJwk(header.jwk, "Credential proof JWT header.jwk");
  const keyAttestation = asString(header.key_attestation);
  if (!keyAttestation) {
    throw new Error("Credential proof JWT must contain header.key_attestation");
  }

  const attestation = await verifyKeyAttestation(keyAttestation, {
    expectedNonce: input.expectedNonce,
    use: "jwt",
    agentContext: input.agentContext,
  });
  await verifyCompactJws(
    proof.jwt,
    {
      method: "jwk",
      jwk: Kms.PublicJwk.fromUnknown(holderJwk),
    },
    input.agentContext,
  );
  validateJwtProofClaims(
    payload,
    input.expectedAudience,
    input.expectedNonce,
    input.expectedClientId,
  );
  if (
    !attestation.attestedKeys.some((candidate) =>
      Kms.PublicJwk.fromUnknown(candidate).equals(Kms.PublicJwk.fromUnknown(holderJwk)),
    )
  ) {
    throw new Error("Credential proof JWT signing key is not listed in attested_keys");
  }

  const nonce = requiredString(payload.nonce, "Credential proof JWT nonce");
  return { holderJwk, source: `${proof.source}.header.jwk`, nonce, proofType: "jwt" };
}

type CredentialProof = {
  jwt: string;
  source: string;
  proofType: "jwt" | "attestation";
};

function extractCredentialProofs(body: JsonRecord): CredentialProof[] {
  const legacyProof = asRecord(body.proof);
  const legacyProofs: CredentialProof[] =
    typeof legacyProof?.jwt === "string"
      ? [
          {
            jwt: legacyProof.jwt,
            source: "credential_request.proof.jwt",
            proofType: "jwt",
          },
        ]
      : [];
  const proofs = asRecord(body.proofs);
  if (!proofs) return legacyProofs;

  const result: CredentialProof[] = [];
  for (const proofType of ["jwt", "attestation"] as const) {
    const values = proofs[proofType];
    if (values === undefined) continue;
    if (
      !Array.isArray(values) ||
      values.length === 0 ||
      values.some((value) => typeof value !== "string")
    ) {
      throw new Error(`Credential Request proofs.${proofType} must be a non-empty string array`);
    }
    values.forEach((jwt, index) => {
      result.push({
        jwt,
        proofType,
        source: `credential_request.proofs.${proofType}[${index}]`,
      });
    });
  }
  return [...legacyProofs, ...result];
}

async function verifyKeyAttestation(
  jwt: string,
  options: {
    expectedNonce: string | ((nonce: string) => boolean);
    use: "jwt" | "attestation";
    agentContext?: AgentContext;
  },
): Promise<{ attestedKeys: JsonRecord[]; nonce: string }> {
  const { header, payload } = decodeCompactJwt(jwt, "Key attestation JWT");
  requireHeaderValue(header, "typ", "key-attestation+jwt", "Key attestation JWT");
  requireHeaderValue(header, "alg", SUPPORTED_PROOF_ALGORITHM, "Key attestation JWT");

  if (
    !Array.isArray(header.x5c) ||
    header.x5c.length === 0 ||
    header.x5c.some((certificate) => typeof certificate !== "string")
  ) {
    throw new Error(
      "Key attestation JWT must use an x5c signing chain; kid and trust_chain are not configured",
    );
  }
  if (header.kid !== undefined || header.trust_chain !== undefined || header.jwk !== undefined) {
    throw new Error("Key attestation JWT must use only header.x5c as its trust mechanism");
  }
  const x5c = header.x5c as string[];
  await verifyCompactJws(
    jwt,
    {
      method: "x5c",
      x5c,
      jwk: undefined,
    },
    options.agentContext,
  );

  if (!Number.isInteger(payload.iat)) {
    throw new Error("Key attestation JWT iat must be an integer");
  }
  const now = Math.floor(Date.now() / 1000);
  if ((payload.iat as number) > now + 300) {
    throw new Error("Key attestation JWT iat is in the future");
  }
  if (options.use === "jwt" && !Number.isInteger(payload.exp)) {
    throw new Error("Key attestation JWT exp is required with the jwt proof type");
  }
  const expiration = payload.exp;
  if (
    expiration !== undefined &&
    (typeof expiration !== "number" || !Number.isInteger(expiration) || expiration <= now)
  ) {
    throw new Error("Key attestation JWT is expired");
  }

  const nonce = requiredString(payload.nonce, "Key attestation JWT nonce");
  if (!nonceMatches(nonce, options.expectedNonce)) {
    throw new Error("Key attestation JWT nonce does not match issued c_nonce");
  }
  const attestedKeys = payload.attested_keys;
  if (!Array.isArray(attestedKeys) || attestedKeys.length === 0) {
    throw new Error("Key attestation JWT attested_keys must be a non-empty array");
  }
  validateOptionalStringArray(payload.key_storage, "Key attestation JWT key_storage");
  validateOptionalStringArray(
    payload.user_authentication,
    "Key attestation JWT user_authentication",
  );
  if (payload.certification !== undefined) {
    if (typeof payload.certification !== "string" || !URL.canParse(payload.certification)) {
      throw new Error("Key attestation JWT certification must be a URL");
    }
  }
  if (payload.status !== undefined && !asRecord(payload.status)) {
    throw new Error("Key attestation JWT status must be an object");
  }
  return {
    attestedKeys: attestedKeys.map((key, index) =>
      publicJwk(key, `Key attestation JWT attested_keys[${index}]`),
    ),
    nonce,
  };
}

function validateJwtProofClaims(
  payload: JsonRecord,
  expectedAudience: string,
  expectedNonce: string | ((nonce: string) => boolean),
  expectedClientId?: string,
): void {
  if (payload.aud !== expectedAudience) {
    throw new Error("Credential proof JWT aud does not match the Credential Issuer");
  }
  if (
    payload.iss !== undefined &&
    (typeof payload.iss !== "string" ||
      expectedClientId === undefined ||
      payload.iss !== expectedClientId)
  ) {
    throw new Error("Credential proof JWT iss does not match the requesting client_id");
  }
  if (!Number.isInteger(payload.iat)) {
    throw new Error("Credential proof JWT iat must be an integer");
  }
  const nonce = requiredString(payload.nonce, "Credential proof JWT nonce");
  if (!nonceMatches(nonce, expectedNonce)) {
    throw new Error("Credential proof JWT nonce does not match issued c_nonce");
  }
}

function nonceMatches(
  nonce: string,
  expectedNonce: string | ((nonce: string) => boolean),
): boolean {
  return typeof expectedNonce === "string" ? nonce === expectedNonce : expectedNonce(nonce);
}

function assertOnlyOneBindingHeader(header: JsonRecord): void {
  const bindingHeaders = ["jwk", "kid", "x5c"].filter((name) => header[name] !== undefined);
  if (bindingHeaders.length !== 1) {
    throw new Error("Credential proof JWT must contain exactly one of header.jwk, kid, or x5c");
  }
  if (!header.jwk) {
    throw new Error("Credential proof JWT must contain header.jwk for JWK holder binding");
  }
}

function decodeCompactJwt(jwt: string, label: string): { header: JsonRecord; payload: JsonRecord } {
  const parts = jwt.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error(`${label} must use compact JWS serialization`);
  }
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!asRecord(header) || !asRecord(payload)) throw new Error("not an object");
    return { header, payload };
  } catch {
    throw new Error(`${label} header and payload must be JSON objects`);
  }
}

function requireHeaderValue(
  header: JsonRecord,
  name: string,
  expected: string,
  label: string,
): void {
  if (header[name] !== expected) {
    throw new Error(`${label} ${name} must be ${expected}`);
  }
}

function publicJwk(value: unknown, label: string): JsonRecord {
  const jwk = asRecord(value);
  if (!jwk) throw new Error(`${label} must be a public JWK`);
  if (PRIVATE_JWK_PARAMETERS.some((parameter) => jwk[parameter] !== undefined)) {
    throw new Error(`${label} must not contain private key material`);
  }
  try {
    return Kms.PublicJwk.fromUnknown(jwk).toJson() as JsonRecord;
  } catch {
    throw new Error(`${label} is not a supported public JWK`);
  }
}

async function verifyCompactJws(
  jwt: string,
  signer: { method: "jwk"; jwk: Kms.PublicJwk } | { method: "x5c"; x5c: string[]; jwk: undefined },
  agentContext?: AgentContext,
): Promise<void> {
  const jwsService = new JwsService();
  const context = agentContext ?? (credentialProofVerificationContext() as never);
  const result =
    signer.method === "jwk"
      ? await jwsService.verifyJws(context, {
          jws: jwt,
          jwsSigner: signer,
          allowedJwsSignerMethods: ["jwk"],
        })
      : await jwsService.verifyJws(context, {
          jws: jwt,
          allowedJwsSignerMethods: ["x5c"],
          trustedCertificates: [signer.x5c.at(-1) as string],
        });
  if (!result.isValid) throw new Error("JWT signature verification failed");
}

function credentialProofVerificationContext(): object {
  const kms = {
    randomBytes: ({ length }: { length: number }) => randomBytes(length),
    verify: async ({
      key,
      algorithm,
      data,
      signature,
    }: {
      key: { publicJwk?: JsonRecord };
      algorithm: string;
      data: Uint8Array;
      signature: Uint8Array;
    }) => {
      const jwk = key.publicJwk;
      if (!jwk || algorithm !== SUPPORTED_PROOF_ALGORITHM) return { verified: false };
      const verified = verifySignature(
        "sha256",
        data,
        {
          key: createPublicKey({ key: jwk as unknown as NodeJsonWebKey, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        },
        signature,
      );
      return verified ? { verified, publicJwk: jwk } : { verified };
    },
  };
  const x509Config = new X509ModuleConfig();
  const resolve = (token: unknown) => {
    if (token === Kms.KeyManagementApi) return kms;
    if (token === X509ModuleConfig) return x509Config;
    throw new Error("Unsupported Credo dependency requested while verifying credential proof");
  };
  return {
    resolve,
    dependencyManager: { resolve },
    config: { validitySkewSeconds: 300 },
  };
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function validateOptionalStringArray(value: unknown, label: string): void {
  if (
    value !== undefined &&
    (!Array.isArray(value) ||
      value.length === 0 ||
      value.some((entry) => typeof entry !== "string"))
  ) {
    throw new Error(`${label} must be a non-empty string array`);
  }
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asRecord(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const strings = value.filter((entry): entry is string => typeof entry === "string");
  return strings.length > 0 ? strings : undefined;
}
