import type { SdJwtDigestAlgorithm } from "./types.js";

/** Exhaustive over the union, so a new algorithm cannot be added without exposing it here. */
const DIGEST_ALGORITHMS: Record<SdJwtDigestAlgorithm, true> = {
  "sha-256": true,
  "sha-384": true,
  "sha-512": true,
};

export const SD_JWT_DIGEST_ALGORITHMS = Object.keys(DIGEST_ALGORITHMS) as SdJwtDigestAlgorithm[];

export const DEFAULT_SD_JWT_DIGEST_ALGORITHM: SdJwtDigestAlgorithm = "sha-256";

export function sdJwtDigestAlgorithmOrNull(value: unknown): SdJwtDigestAlgorithm | null {
  return typeof value === "string" && Object.hasOwn(DIGEST_ALGORITHMS, value)
    ? (value as SdJwtDigestAlgorithm)
    : null;
}
