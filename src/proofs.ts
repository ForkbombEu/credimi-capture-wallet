import { type JWK, calculateJwkThumbprint } from "jose";
import type {
  CredentialRequestProofsCapture,
  JsonRecord,
  JwtEvidence,
  Oid4vciHttpRequestCapture,
  ProofHeaderCapture,
  ProofJwtEvidence,
} from "./types.js";

export function decodeJwtHeader(jwt: string): JsonRecord {
  const [header] = jwt.split(".");
  if (!header) throw new Error("JWT is missing a JOSE header");
  return JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as JsonRecord;
}

export interface DecodedJwt {
  header: JsonRecord | null;
  payload: JsonRecord | null;
  /** Why the header or payload could not be decoded, with whatever did decode kept. */
  error: string | null;
}

/**
 * Decodes a compact JWT's header and payload without verifying anything, for evidence. Credo-TS's
 * `Jwt.fromSerializedJwt` is not used here because it rejects payloads whose registered claims have
 * the wrong JSON type, which are exactly the defects a conformance test needs to see.
 */
export function decodeJwtForEvidence(jwt: string): DecodedJwt {
  const [header, payload] = jwt.split(".");
  const decoded: DecodedJwt = { header: null, payload: null, error: null };
  try {
    decoded.header = decodeJsonObjectSegment(header, "JOSE header");
    decoded.payload = decodeJsonObjectSegment(payload, "payload");
  } catch (error) {
    decoded.error = error instanceof Error ? error.message : String(error);
  }
  return decoded;
}

function decodeJsonObjectSegment(segment: string | undefined, name: string): JsonRecord {
  if (!segment) throw new Error(`JWT is missing a ${name}`);
  const value: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  const record = asRecord(value);
  if (!record) throw new Error(`JWT ${name} is not a JSON object`);
  return record;
}

/**
 * The proofs of one Credential Request as received, for evidence. Every JWT is decoded and never
 * verified, so a proof Credo-TS goes on to reject is recorded in the same detail as one it
 * accepts. Non-string entries are left to `proofs`, which keeps the member's JSON types.
 */
export function credentialRequestProofsCapture(
  capture: Pick<Oid4vciHttpRequestCapture, "id" | "at">,
  body: JsonRecord,
): CredentialRequestProofsCapture {
  const proofs = asRecord(body.proofs);
  return {
    request_id: capture.id,
    at: capture.at,
    ...(body.proofs === undefined ? {} : { proofs: structuredClone(body.proofs) }),
    jwt: proofJwtStrings(proofs?.jwt, "proofs.jwt").map(({ jwt, source }) => {
      const evidence = jwtEvidence(jwt);
      const keyAttestation = evidence.header?.key_attestation;
      return {
        ...evidence,
        source,
        ...(typeof keyAttestation === "string"
          ? { key_attestation: jwtEvidence(keyAttestation) }
          : {}),
      };
    }),
    attestation: proofJwtStrings(proofs?.attestation, "proofs.attestation").map(
      ({ jwt, source }): ProofJwtEvidence => ({ ...jwtEvidence(jwt), source }),
    ),
  };
}

function proofJwtStrings(value: unknown, source: string): Array<{ jwt: string; source: string }> {
  if (typeof value === "string") return [{ jwt: value, source }];
  if (!Array.isArray(value)) return [];
  return value.flatMap((jwt, index) =>
    typeof jwt === "string" ? [{ jwt, source: `${source}[${index}]` }] : [],
  );
}

function jwtEvidence(compact: string): JwtEvidence {
  return { compact, ...decodeJwtForEvidence(compact) };
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
