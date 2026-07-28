import { type JWK, calculateJwkThumbprint } from "jose";
import type { JsonRecord, ProofHeaderCapture } from "./types.js";

export function decodeJwtHeader(jwt: string): JsonRecord {
  const [header] = jwt.split(".");
  if (!header) throw new Error("JWT is missing a JOSE header");
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
  try {
    return {
      jwk,
      thumbprint: await calculateJwkThumbprint(jwk as unknown as JWK),
    };
  } catch {
    return { jwk, thumbprint: null };
  }
}

function extractCredentialProofs(body: JsonRecord): Array<{
  jwt: string;
  source: string;
  proofType: "jwt" | "attestation";
}> {
  const result: Array<{
    jwt: string;
    source: string;
    proofType: "jwt" | "attestation";
  }> = extractProofJwts(body).map(({ jwt, source }) => ({
    jwt,
    source,
    proofType: "jwt" as const,
  }));
  const attestations = (body.proofs as JsonRecord | undefined)?.attestation;
  if (Array.isArray(attestations)) {
    attestations.forEach((jwt, index) => {
      if (typeof jwt === "string") {
        result.push({
          jwt,
          source: `credential_request.proofs.attestation[${index}]`,
          proofType: "attestation",
        });
      }
    });
  }
  return result;
}

function asRecord(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? value
    : undefined;
}
