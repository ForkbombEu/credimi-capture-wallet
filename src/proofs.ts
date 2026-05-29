import { type JWK, calculateJwkThumbprint } from "jose";
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
