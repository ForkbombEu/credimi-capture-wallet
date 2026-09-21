import type { VpRequestBehavior } from "./types.js";

/**
 * Replaces the signature of an already signed Request Object with one that cannot verify, keeping
 * the JWS structurally intact so the Wallet still parses it and rejects it on the signature rather
 * than on the encoding. The valid signature is produced by the normal Credo signing path first, so
 * no second signing implementation exists for this.
 */
export function corruptJwsSignature(jwt: string): string {
  const segments = jwt.split(".");
  if (segments.length !== 3 || segments[2].length === 0) {
    throw new Error("cannot corrupt the signature of a value that is not a compact JWS");
  }
  // Flipping a base64url character is not enough: the final character of an ES256 signature
  // carries padding bits that decode to the same 64 bytes, so the signature would still verify.
  // Inverting the first signature byte changes the value itself while keeping its length.
  const signature = Buffer.from(segments[2], "base64url");
  signature[0] ^= 0xff;
  return [segments[0], segments[1], signature.toString("base64url")].join(".");
}

/**
 * Validates untrusted behaviour input. Returns `undefined` when absent and `null` when malformed,
 * following the existing `clientMetadataOrNull` convention.
 */
export function requestBehaviorOrNull(value: unknown): VpRequestBehavior | null | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const behavior: VpRequestBehavior = {};
  for (const [member, memberValue] of Object.entries(value)) {
    if (member !== "signature" || memberValue !== "corrupt") return null;
    behavior.signature = memberValue;
  }
  return Object.keys(behavior).length === 0 ? null : behavior;
}
