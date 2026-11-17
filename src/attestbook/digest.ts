import { Hasher } from "@credo-ts/core";

/** Lowercase hex SHA-256 of exact bytes, computed with Credo-TS. */
export function sha256Hex(bytes: Uint8Array): string {
  return Buffer.from(Hasher.hash(bytes, "sha-256")).toString("hex");
}

const SRI_ALGORITHMS = { sha256: "sha-256", sha384: "sha-384", sha512: "sha-512" } as const;
type SriAlgorithm = keyof typeof SRI_ALGORITHMS;
const SRI_STRENGTH: readonly SriAlgorithm[] = ["sha256", "sha384", "sha512"];

/**
 * W3C Subresource Integrity check of exact bytes. As SRI prescribes, only the tokens of the
 * strongest supported algorithm the metadata names are compared, and any one of them may match.
 * Metadata that names no supported algorithm is not a pin and fails, rather than passing silently.
 */
export function sriMatches(integrity: string, bytes: Uint8Array): boolean {
  const tokens = integrity
    .trim()
    .split(/\s+/)
    .map((token) => /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})(?:\?.*)?$/.exec(token))
    .filter((match): match is RegExpExecArray => match !== null);
  const strongest = SRI_STRENGTH.filter((algorithm) =>
    tokens.some((token) => token[1] === algorithm),
  ).at(-1);
  if (!strongest) return false;
  const digest = Buffer.from(Hasher.hash(bytes, SRI_ALGORITHMS[strongest])).toString("base64");
  return tokens.some((token) => token[1] === strongest && token[2] === digest);
}

/** The RFC 9530 `sha-256=:<base64>:` member of a `Content-Digest` header, if present. */
export function contentDigestSha256(header: string | null): string | null {
  if (!header) return null;
  const match = /(?:^|,)\s*sha-256=:([A-Za-z0-9+/]+={0,2}):/.exec(header);
  return match?.[1] ? Buffer.from(match[1], "base64").toString("hex") : null;
}
