import { createHash, randomUUID } from "node:crypto";
import { type JWK, type KeyLike, SignJWT, exportJWK, generateKeyPair } from "jose";
import type { JsonRecord } from "../../src/types.js";

export interface TestKey {
  publicJwk: JsonRecord;
  privateKey: KeyLike | Uint8Array;
}

export async function generateEs256Key(): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    publicJwk: (await exportJWK(publicKey)) as unknown as JsonRecord,
    privateKey,
  };
}

export async function dpopProof(
  key: TestKey,
  options: { method: string; url: string; accessToken?: string; overrides?: JsonRecord },
): Promise<string> {
  return new SignJWT({
    htm: options.method,
    htu: options.url,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(options.accessToken
      ? { ath: createHash("sha256").update(options.accessToken).digest("base64url") }
      : {}),
    ...options.overrides,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: key.publicJwk as unknown as JWK,
    })
    .sign(key.privateKey);
}
