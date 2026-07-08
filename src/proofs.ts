import { type JWK, calculateJwkThumbprint, importJWK, jwtVerify } from "jose";
import type { JsonRecord, ProofHeaderCapture } from "./types.js";

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
  return extractProofJwts(body).map(({ jwt, source }) => {
    const header = decodeJwtHeader(jwt);
    return {
      typ: asString(header.typ),
      alg: asString(header.alg),
      kid: asString(header.kid),
      jwk: asRecord(header.jwk),
      x5c: asStringArray(header.x5c),
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
  expectedNonce: string;
  expectedAudience: string;
}): Promise<{ holderJwk: JsonRecord; source: string }> {
  const proofs = extractProofJwts(input.body);
  if (proofs.length === 0) throw new Error("Credential proof JWT is required");
  const errors: string[] = [];
  for (const proof of proofs) {
    try {
      const header = decodeJwtHeader(proof.jwt);
      const jwk = asRecord(header.jwk);
      if (!jwk) throw new Error("Credential proof JWT must contain header.jwk");
      const alg = asString(header.alg) ?? "ES256";
      const verified = await jwtVerify(proof.jwt, await importJWK(jwk as unknown as JWK, alg), {
        audience: input.expectedAudience,
      });
      const payload = verified.payload as JsonRecord;
      if (payload.nonce !== input.expectedNonce) {
        throw new Error("Credential proof JWT nonce does not match issued c_nonce");
      }
      return { holderJwk: jwk, source: proof.source };
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "proof verification failed");
    }
  }
  throw new Error(errors[0] ?? "Credential proof JWT verification failed");
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
