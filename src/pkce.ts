import { createHash } from "node:crypto";

export function verifyPkce(
  codeVerifier: string | null,
  codeChallenge: string | null,
  method: string | null,
): boolean {
  if (!codeVerifier || !codeChallenge) return false;
  if (!method || method === "plain") return codeVerifier === codeChallenge;
  if (method !== "S256") return false;
  const digest = createHash("sha256").update(codeVerifier).digest("base64url");
  return digest === codeChallenge;
}
