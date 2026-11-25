import {
  type CipherGCMTypes,
  type JsonWebKey,
  createCipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes,
} from "node:crypto";

/**
 * Content-encryption algorithms the Credo KMS backend can produce with ECDH-ES direct key
 * agreement, with the Content Encryption Key length RFC 7518 Section 5.1 assigns to each.
 */
const CONTENT_ENCRYPTION_KEY_BYTES = {
  A128GCM: 16,
  A192GCM: 24,
  A256GCM: 32,
  "A128CBC-HS256": 32,
  "A192CBC-HS384": 48,
  "A256CBC-HS512": 64,
} as const;

export type EcdhEsContentEncryption = keyof typeof CONTENT_ENCRYPTION_KEY_BYTES;

export const ECDH_ES_CONTENT_ENCRYPTION_ALGORITHMS = Object.keys(
  CONTENT_ENCRYPTION_KEY_BYTES,
) as EcdhEsContentEncryption[];

export function isEcdhEsContentEncryption(value: unknown): value is EcdhEsContentEncryption {
  return typeof value === "string" && Object.hasOwn(CONTENT_ENCRYPTION_KEY_BYTES, value);
}

export interface EcdhEsEncryptOptions {
  privateJwk: JsonWebKey;
  recipientPublicJwk: JsonWebKey;
  enc: EcdhEsContentEncryption;
  data: Uint8Array;
  aad: Uint8Array;
  apu?: Uint8Array;
  apv?: Uint8Array;
  iv?: Uint8Array;
}

export interface EcdhEsEncryptResult {
  encrypted: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * JWE ECDH-ES direct key agreement (RFC 7518 Section 4.6) followed by content encryption. The
 * agreed secret goes through the Concat KDF with the `enc` value as AlgorithmID, so the result is
 * the Content Encryption Key itself and the JWE carries no encrypted key.
 */
export function ecdhEsEncrypt(options: EcdhEsEncryptOptions): EcdhEsEncryptResult {
  const sharedSecret = diffieHellman({
    privateKey: createPrivateKey({ key: options.privateJwk, format: "jwk" }),
    publicKey: createPublicKey({ key: options.recipientPublicJwk, format: "jwk" }),
  });
  const contentEncryptionKey = concatKdf(
    sharedSecret,
    options.enc,
    CONTENT_ENCRYPTION_KEY_BYTES[options.enc],
    options.apu,
    options.apv,
  );
  return options.enc.includes("GCM")
    ? encryptGcm(contentEncryptionKey, options.data, options.aad, options.iv)
    : encryptCbcHmac(contentEncryptionKey, options.data, options.aad, options.iv);
}

/** RFC 7518 Section 4.6.2 with SHA-256, as JWA requires for ECDH-ES. */
function concatKdf(
  sharedSecret: Buffer,
  algorithmId: string,
  keyBytes: number,
  apu: Uint8Array = new Uint8Array(),
  apv: Uint8Array = new Uint8Array(),
): Buffer {
  const otherInfo = Buffer.concat([
    lengthPrefixed(Buffer.from(algorithmId, "utf8")),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    uint32(keyBytes * 8),
  ]);
  const rounds: Buffer[] = [];
  for (let counter = 1; rounds.length * 32 < keyBytes; counter += 1) {
    rounds.push(
      createHash("sha256")
        .update(Buffer.concat([uint32(counter), sharedSecret, otherInfo]))
        .digest(),
    );
  }
  return Buffer.concat(rounds).subarray(0, keyBytes);
}

/** RFC 7518 Section 5.3. */
function encryptGcm(
  key: Buffer,
  data: Uint8Array,
  aad: Uint8Array,
  suppliedIv?: Uint8Array,
): EcdhEsEncryptResult {
  const iv = suppliedIv ?? randomBytes(12);
  const cipher = createCipheriv(`aes-${key.length * 8}-gcm` as CipherGCMTypes, key, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return { encrypted, iv, tag: cipher.getAuthTag() };
}

/**
 * RFC 7518 Section 5.2.2: the first half of the key authenticates, the second half encrypts, and
 * the tag is the leading half of the HMAC over AAD, IV, ciphertext, and the AAD bit length.
 */
function encryptCbcHmac(
  key: Buffer,
  data: Uint8Array,
  aad: Uint8Array,
  suppliedIv?: Uint8Array,
): EcdhEsEncryptResult {
  const half = key.length / 2;
  const macKey = key.subarray(0, half);
  const encryptionKey = key.subarray(half);
  const iv = suppliedIv ?? randomBytes(16);
  const cipher = createCipheriv(`aes-${half * 8}-cbc`, encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const aadBits = Buffer.alloc(8);
  aadBits.writeBigUInt64BE(BigInt(aad.length) * 8n);
  const tag = createHmac(`sha${half * 16}`, macKey)
    .update(Buffer.concat([aad, iv, encrypted, aadBits]))
    .digest()
    .subarray(0, half);
  return { encrypted, iv, tag };
}

function lengthPrefixed(value: Uint8Array): Buffer {
  return Buffer.concat([uint32(value.length), value]);
}

function uint32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}
