import { ClaimFormat } from "@credo-ts/core";
import { asRecord } from "../shared/json.js";
import type { JsonRecord } from "../types.js";

export type DecodedPresentation = {
  format: string;
  document_types?: string[];
  issuer_claims?: unknown;
  device_claims?: unknown;
  claims?: unknown;
  key_binding?: JsonRecord;
  /** SD-JWT VC `_sd_alg`, defaulted to sha-256 when the issuer omitted it. */
  digest_algorithm?: string;
  decoded?: unknown;
  warning?: string;
};

export type DecodedPresentations = Record<string, DecodedPresentation[]>;

export function decodedPresentationsFromDcql(presentations: unknown): DecodedPresentations {
  if (!presentations || typeof presentations !== "object" || Array.isArray(presentations)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(presentations as Record<string, unknown>).map(([queryId, entries]) => [
      queryId,
      Array.isArray(entries) ? entries.map(decodedPresentationFromCredo) : [],
    ]),
  );
}

function decodedPresentationFromCredo(presentation: unknown): DecodedPresentation {
  const presentationRecord = asRecord(presentation);
  const format = String(presentationRecord?.claimFormat ?? "unknown");

  if (format === ClaimFormat.MsoMdoc) {
    const issuerClaims = asRecord(presentationRecord?.issuerClaims) ?? {};
    const deviceClaims = asRecord(presentationRecord?.deviceClaims) ?? {};
    return {
      format,
      document_types: Object.keys(issuerClaims),
      issuer_claims: toJsonSafe(issuerClaims),
      device_claims: toJsonSafe(deviceClaims),
    };
  }

  if (format === ClaimFormat.SdJwtDc) {
    const decoded: DecodedPresentation = {
      format,
      claims: toJsonSafe(presentationRecord?.prettyClaims),
      // SD-JWT VC Section 4.1.1 defaults `_sd_alg` to sha-256 when the issuer omits it. The value
      // is captured because it is the digest algorithm a wallet had to support to present this
      // credential at all, and it is absent from the pretty claims.
      digest_algorithm: String(asRecord(presentationRecord?.payload)?._sd_alg ?? "sha-256"),
    };
    const keyBinding = asRecord(presentationRecord?.kbJwt);
    const keyBindingPayload = asRecord(keyBinding?.payload);
    if (keyBindingPayload) {
      decoded.key_binding = { payload: toJsonSafe(keyBindingPayload) };
    }
    return decoded;
  }

  if (presentationRecord && "prettyClaims" in presentationRecord) {
    return { format, claims: toJsonSafe(presentationRecord.prettyClaims) };
  }

  if (presentationRecord && "resolvedPresentation" in presentationRecord) {
    return { format, decoded: toJsonSafe(presentationRecord.resolvedPresentation) };
  }

  if (presentationRecord && "payload" in presentationRecord) {
    return { format, decoded: toJsonSafe(presentationRecord.payload) };
  }

  return {
    format,
    decoded: null,
    warning: "No supported decoded representation is available",
  };
}

export function toJsonSafe(value: unknown): unknown {
  return toJsonSafeValue(value, new WeakSet<object>());
}

function toJsonSafeValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "number") return value;
  if (typeof value === "boolean") return value;
  if (typeof value === "undefined") return null;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "symbol") return String(value);
  if (typeof value === "function") return null;

  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return { $type: "bytes", base64url: Buffer.from(value).toString("base64url") };
  }

  if (value instanceof Date) return value.toISOString();

  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (value instanceof Map) {
    const normalized = Object.fromEntries(
      [...value.entries()].map(([key, entry]) => [String(key), toJsonSafeValue(entry, seen)]),
    );
    seen.delete(value);
    return normalized;
  }

  if (value instanceof Set) {
    const normalized = [...value.values()].map((entry) => toJsonSafeValue(entry, seen));
    seen.delete(value);
    return normalized;
  }

  const valueRecord = value as Record<string, unknown>;
  if (typeof valueRecord.toJSON === "function") {
    const normalized = toJsonSafeValue(valueRecord.toJSON(), seen);
    seen.delete(value);
    return normalized;
  }

  if (Array.isArray(value)) {
    const normalized = value.map((entry) => toJsonSafeValue(entry, seen));
    seen.delete(value);
    return normalized;
  }

  const normalized = Object.fromEntries(
    Object.entries(valueRecord).map(([key, entry]) => [key, toJsonSafeValue(entry, seen)]),
  );
  seen.delete(value);
  return normalized;
}
