import {
  ECDH_ES_CONTENT_ENCRYPTION_ALGORITHMS,
  type EcdhEsContentEncryption,
  isEcdhEsContentEncryption,
} from "./kms-encryption.js";
import type { JsonRecord, RequestObjectEncryptionSource } from "./types.js";

const KEY_AGREEMENT_CURVES: Record<string, readonly string[]> = {
  EC: ["P-256", "P-384", "P-521"],
  OKP: ["X25519"],
};

export interface RequestObjectEncryption {
  /** The Wallet's public key the Request Object is encrypted to, exactly as it was supplied. */
  recipientJwk: JsonRecord;
  alg: "ECDH-ES";
  enc: EcdhEsContentEncryption;
  algSource: RequestObjectEncryptionSource;
  encSource: RequestObjectEncryptionSource;
}

export type RequestObjectEncryptionNegotiation =
  | { status: "not_requested" }
  | { status: "negotiated"; encryption: RequestObjectEncryption }
  | { status: "unsupported"; reason: string };

const DEFAULT_CONTENT_ENCRYPTION: EcdhEsContentEncryption = "A128GCM";

/** Wallet Metadata member prefixes, in the order they are consulted. */
const LIST_PREFIXES = {
  request_object: "request_object_encryption",
  authorization_encryption: "authorization_encryption",
} as const;

/**
 * OpenID4VP Section 5.10: a Wallet that requires an encrypted Request Object passes its public
 * encryption keys in `wallet_metadata.jwks`; Section 5.10 names no other parameter for it.
 * Section 10 defines Wallet Metadata as RFC 8414 Authorization Server Metadata, whose registry
 * carries the Request Object algorithms in `request_object_encryption_alg_values_supported` and
 * `..._enc_values_supported`, so those are consulted first.
 *
 * By maintainer decision, a Wallet that lists neither falls back to its
 * `authorization_encryption_*` lists, which OpenID4VP assigns to the Authorization Response, and
 * then to `ECDH-ES` with `A128GCM`. `alg` and `enc` follow that order independently, the list
 * actually present must allow the choice, and the source of each is returned as evidence.
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

  const algList = supportedValuesList(metadata, "alg_values_supported");
  if (
    algList.source !== "default" &&
    !(Array.isArray(algList.values) && algList.values.includes("ECDH-ES"))
  ) {
    return { status: "unsupported", reason: `${algList.member} does not include ECDH-ES` };
  }

  const encList = supportedValuesList(metadata, "enc_values_supported");
  let enc: EcdhEsContentEncryption | undefined = DEFAULT_CONTENT_ENCRYPTION;
  if (encList.source !== "default") {
    if (!Array.isArray(encList.values)) {
      return { status: "unsupported", reason: `${encList.member} is not an array` };
    }
    enc = encList.values.find(isEcdhEsContentEncryption);
    if (!enc) {
      return {
        status: "unsupported",
        reason: `${encList.member} lists none of ${ECDH_ES_CONTENT_ENCRYPTION_ALGORITHMS.join(", ")}`,
      };
    }
  }

  const recipientJwk = keys.find(isKeyAgreementPublicJwk);
  if (!recipientJwk) {
    return {
      status: "unsupported",
      reason: "wallet_metadata.jwks has no public ECDH-ES encryption key",
    };
  }
  return {
    status: "negotiated",
    encryption: {
      recipientJwk,
      alg: "ECDH-ES",
      enc,
      algSource: algList.source,
      encSource: encList.source,
    },
  };
}

/** The first `<prefix>_<suffix>` member present, in `LIST_PREFIXES` order. */
function supportedValuesList(
  metadata: JsonRecord,
  suffix: "alg_values_supported" | "enc_values_supported",
):
  | { source: Exclude<RequestObjectEncryptionSource, "default">; member: string; values: unknown }
  | { source: "default" } {
  for (const [source, prefix] of Object.entries(LIST_PREFIXES) as [
    keyof typeof LIST_PREFIXES,
    string,
  ][]) {
    const member = `${prefix}_${suffix}`;
    if (metadata[member] !== undefined) return { source, member, values: metadata[member] };
  }
  return { source: "default" };
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
