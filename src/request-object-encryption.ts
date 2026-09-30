import {
  ECDH_ES_CONTENT_ENCRYPTION_ALGORITHMS,
  type EcdhEsContentEncryption,
  isEcdhEsContentEncryption,
} from "./kms-encryption.js";
import type { JsonRecord } from "./types.js";

const KEY_AGREEMENT_CURVES: Record<string, readonly string[]> = {
  EC: ["P-256", "P-384", "P-521"],
  OKP: ["X25519"],
};

export interface RequestObjectEncryption {
  /** The Wallet's public key the Request Object is encrypted to, exactly as it was supplied. */
  recipientJwk: JsonRecord;
  alg: "ECDH-ES";
  enc: EcdhEsContentEncryption;
}

export type RequestObjectEncryptionNegotiation =
  | { status: "not_requested" }
  | { status: "negotiated"; encryption: RequestObjectEncryption }
  | { status: "unsupported"; reason: string };

/**
 * OpenID4VP Section 5.10: a Wallet that requires an encrypted Request Object passes its public
 * encryption keys in `wallet_metadata.jwks`. Section 10 defines Wallet Metadata as RFC 8414
 * Authorization Server Metadata, whose registry carries the Request Object algorithms in
 * `request_object_encryption_alg_values_supported` and `..._enc_values_supported`. The
 * `authorization_encryption_*` members describe the Authorization Response instead and are not
 * consulted here.
 *
 * Metadata that does not parse, or that carries no `jwks`, requests no encryption. A `jwks` the
 * Verifier cannot honour is `unsupported` rather than answered with a plain JWS, so the Wallet is
 * never handed an unencrypted object it declared it would not accept.
 */
export function negotiateRequestObjectEncryption(
  walletMetadata: unknown,
): RequestObjectEncryptionNegotiation {
  const metadata = walletMetadataObject(walletMetadata);
  if (!metadata || metadata.jwks === undefined) return { status: "not_requested" };

  const jwks = metadata.jwks;
  const keys = typeof jwks === "object" && jwks !== null && "keys" in jwks ? jwks.keys : undefined;
  if (!Array.isArray(keys)) {
    return { status: "unsupported", reason: "wallet_metadata.jwks has no keys array" };
  }

  const algValues = metadata.request_object_encryption_alg_values_supported;
  if (algValues !== undefined && !(Array.isArray(algValues) && algValues.includes("ECDH-ES"))) {
    return {
      status: "unsupported",
      reason: "request_object_encryption_alg_values_supported does not include ECDH-ES",
    };
  }

  const encValues = metadata.request_object_encryption_enc_values_supported;
  if (!Array.isArray(encValues)) {
    return {
      status: "unsupported",
      reason: "wallet_metadata does not list request_object_encryption_enc_values_supported",
    };
  }
  const enc = encValues.find(isEcdhEsContentEncryption);
  if (!enc) {
    return {
      status: "unsupported",
      reason: `request_object_encryption_enc_values_supported lists none of ${ECDH_ES_CONTENT_ENCRYPTION_ALGORITHMS.join(", ")}`,
    };
  }

  const recipientJwk = keys.find(isKeyAgreementPublicJwk);
  if (!recipientJwk) {
    return {
      status: "unsupported",
      reason: "wallet_metadata.jwks has no public ECDH-ES encryption key",
    };
  }
  return { status: "negotiated", encryption: { recipientJwk, alg: "ECDH-ES", enc } };
}

/**
 * Section 5.10 sends `wallet_metadata` as a string containing a JSON object; a JSON request body
 * may already carry it as an object.
 */
function walletMetadataObject(value: unknown): JsonRecord | null {
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    ? (parsed as JsonRecord)
    : null;
}

/** A public EC or OKP key usable for ECDH-ES and not restricted to another purpose. */
function isKeyAgreementPublicJwk(candidate: unknown): candidate is JsonRecord {
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) return false;
  const value = candidate as JsonRecord;
  if (value.d !== undefined) return false;
  if (value.use !== undefined && value.use !== "enc") return false;
  if (value.alg !== undefined && value.alg !== "ECDH-ES") return false;
  const curves = typeof value.kty === "string" ? KEY_AGREEMENT_CURVES[value.kty] : undefined;
  if (!curves || typeof value.crv !== "string" || !curves.includes(value.crv)) return false;
  return typeof value.x === "string" && (value.kty === "OKP" || typeof value.y === "string");
}
