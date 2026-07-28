import { randomBytes } from "node:crypto";
import { Kms } from "@credo-ts/core";
import { getOid4vcDecryptJweCallback, getOid4vcEncryptJweCallback } from "@credo-ts/openid4vc";
import {
  CompactEncrypt,
  type CompactJWEHeaderParameters,
  type JWK,
  type KeyLike,
  compactDecrypt,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import {
  ISSUER_ENCRYPTION_KEY_ID,
  loadIssuerEncryptionPrivateJwk,
  loadIssuerEncryptionPublicJwk,
} from "./config.js";
import type { AppConfig, JsonRecord } from "./types.js";

export const CREDENTIAL_JWE_ALG = "ECDH-ES";
export const CREDENTIAL_JWE_ENC = "A256GCM";

export interface CredentialResponseEncryption {
  jwk: JsonRecord;
  enc: typeof CREDENTIAL_JWE_ENC;
}

export class CredentialEncryptionError extends Error {}

export async function decryptCredentialRequest(
  config: AppConfig,
  compactJwe: string,
): Promise<JsonRecord> {
  const issuerPublicJwk = loadIssuerEncryptionPublicJwk(config);
  if (!issuerPublicJwk) {
    throw new CredentialEncryptionError("Issuer credential request encryption key is unavailable");
  }

  try {
    const decrypt = getOid4vcDecryptJweCallback(createCredentialEncryptionContext(config) as never);
    const result = (await decrypt(compactJwe, {
      jwk: issuerPublicJwk as never,
    })) as {
      decrypted: boolean;
      payload?: string;
      header?: JsonRecord;
    };
    if (!result.decrypted || typeof result.payload !== "string") {
      throw new CredentialEncryptionError("Credential Request JWE could not be decrypted");
    }
    if (result.header?.alg !== CREDENTIAL_JWE_ALG) {
      throw new CredentialEncryptionError(`Credential Request JWE must use ${CREDENTIAL_JWE_ALG}`);
    }
    if (result.header.enc !== CREDENTIAL_JWE_ENC) {
      throw new CredentialEncryptionError(`Credential Request JWE must use ${CREDENTIAL_JWE_ENC}`);
    }
    if (result.header.kid !== ISSUER_ENCRYPTION_KEY_ID) {
      throw new CredentialEncryptionError(
        "Credential Request JWE kid does not identify the issuer encryption key",
      );
    }
    return parseJsonRecord(result.payload, "Credential Request JWE payload");
  } catch (error) {
    if (error instanceof CredentialEncryptionError) throw error;
    throw new CredentialEncryptionError(errorMessage(error));
  }
}

export function credentialResponseEncryption(
  body: JsonRecord,
): CredentialResponseEncryption | null {
  const value = body.credential_response_encryption;
  if (value === undefined) return null;
  const parameters = asRecord(value);
  const jwk = asRecord(parameters?.jwk);
  if (!parameters || !jwk) {
    throw new CredentialEncryptionError("credential_response_encryption must contain a public jwk");
  }
  if (containsPrivateJwkMaterial(jwk)) {
    throw new CredentialEncryptionError(
      "credential_response_encryption.jwk must not contain private key material",
    );
  }
  if (jwk.alg !== CREDENTIAL_JWE_ALG) {
    throw new CredentialEncryptionError(
      `credential_response_encryption.jwk.alg must be ${CREDENTIAL_JWE_ALG}`,
    );
  }
  if (parameters.enc !== CREDENTIAL_JWE_ENC) {
    throw new CredentialEncryptionError(
      `credential_response_encryption.enc must be ${CREDENTIAL_JWE_ENC}`,
    );
  }
  if (parameters.zip !== undefined) {
    throw new CredentialEncryptionError("Credential Response compression is not supported");
  }

  let publicJwk: Kms.PublicJwk;
  try {
    publicJwk = Kms.PublicJwk.fromUnknown(jwk);
  } catch (error) {
    throw new CredentialEncryptionError(
      `credential_response_encryption.jwk is invalid: ${errorMessage(error)}`,
    );
  }
  const publicJwkJson = publicJwk.toJson();
  const supportedKey =
    (publicJwkJson.kty === "EC" &&
      ["P-256", "P-384", "P-521"].includes(String(publicJwkJson.crv))) ||
    (publicJwkJson.kty === "OKP" && publicJwkJson.crv === "X25519");
  if (!supportedKey) {
    throw new CredentialEncryptionError(
      "credential_response_encryption.jwk must use P-256, P-384, P-521, or X25519",
    );
  }
  if (!publicJwk.hasKeyId) publicJwk.keyId = publicJwk.legacyKeyId;

  return {
    jwk: publicJwk.toJson(),
    enc: CREDENTIAL_JWE_ENC,
  };
}

export async function encryptCredentialResponse(
  config: AppConfig,
  encryption: CredentialResponseEncryption,
  response: JsonRecord,
): Promise<string> {
  try {
    const encrypt = getOid4vcEncryptJweCallback(createCredentialEncryptionContext(config) as never);
    const result = await encrypt(
      {
        method: "jwk",
        publicJwk: encryption.jwk as never,
        alg: CREDENTIAL_JWE_ALG,
        enc: encryption.enc,
      },
      JSON.stringify(response),
    );
    return result.jwe;
  } catch (error) {
    throw new CredentialEncryptionError(errorMessage(error));
  }
}

function createCredentialEncryptionContext(config: AppConfig): object {
  const issuerPrivateJwk = loadIssuerEncryptionPrivateJwk(config);
  if (!issuerPrivateJwk) {
    throw new CredentialEncryptionError("Issuer credential request encryption key is unavailable");
  }
  const kms = new CredentialEncryptionKms(issuerPrivateJwk);
  const resolve = (token: unknown) => {
    if (token === Kms.KeyManagementApi) return kms;
    throw new CredentialEncryptionError("Unsupported Credo credential encryption dependency");
  };
  return {
    resolve,
    dependencyManager: { resolve },
    config: {
      logger: { error: () => undefined },
    },
  };
}

class CredentialEncryptionKms {
  private readonly privateJwks = new Map<string, JWK>();

  constructor(issuerPrivateJwk: JsonRecord) {
    this.privateJwks.set(ISSUER_ENCRYPTION_KEY_ID, issuerPrivateJwk as unknown as JWK);
  }

  async createKey({ type }: { type: JsonRecord }): Promise<{
    keyId: string;
    publicJwk: JsonRecord;
  }> {
    const curve = typeof type.crv === "string" ? type.crv : "P-256";
    const { publicKey, privateKey } = await generateKeyPair(CREDENTIAL_JWE_ALG, {
      crv: curve,
      extractable: true,
    } as never);
    const keyId = randomBytes(16).toString("base64url");
    const exportedPublicJwk = await exportJWK(publicKey);
    const publicJwk = {
      x: exportedPublicJwk.x,
      crv: exportedPublicJwk.crv,
      kty: exportedPublicJwk.kty,
      ...(exportedPublicJwk.y ? { y: exportedPublicJwk.y } : {}),
    };
    const privateJwk = { ...(await exportJWK(privateKey)), kid: keyId };
    this.privateJwks.set(keyId, privateJwk);
    return { keyId, publicJwk };
  }

  async deleteKey({ keyId }: { keyId: string }): Promise<boolean> {
    return this.privateJwks.delete(keyId);
  }

  async getPublicKey({ keyId }: { keyId: string }): Promise<JsonRecord | null> {
    const privateJwk = this.privateJwks.get(keyId);
    return privateJwk ? publicJwk(privateJwk) : null;
  }

  async encrypt(options: {
    key: {
      keyAgreement: {
        keyId: string;
        externalPublicJwk: JsonRecord;
        apu?: Uint8Array;
        apv?: Uint8Array;
      };
    };
    data: Uint8Array;
    encryption: { algorithm: string; aad: Uint8Array };
  }): Promise<{
    encrypted: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
  }> {
    const keyAgreement = options.key.keyAgreement;
    const privateJwk = this.requiredPrivateJwk(keyAgreement.keyId);
    const encodedHeader = Buffer.from(options.encryption.aad).toString("utf8");
    const header = parseJsonRecord(
      Buffer.from(encodedHeader, "base64url").toString("utf8"),
      "JWE protected header",
    );
    if (typeof header.alg !== "string" || typeof header.enc !== "string") {
      throw new CredentialEncryptionError("JWE protected header must contain alg and enc");
    }
    const compact = await new CompactEncrypt(options.data)
      .setProtectedHeader(header as unknown as CompactJWEHeaderParameters)
      .setKeyManagementParameters({
        epk: (await importJWK(privateJwk, CREDENTIAL_JWE_ALG)) as KeyLike,
        apu: keyAgreement.apu,
        apv: keyAgreement.apv,
      })
      .encrypt(
        await importJWK(keyAgreement.externalPublicJwk as unknown as JWK, CREDENTIAL_JWE_ALG),
      );
    const [actualHeader, encryptedKey, iv, ciphertext, tag] = compact.split(".");
    if (actualHeader !== encodedHeader || encryptedKey !== "" || !iv || !ciphertext || !tag) {
      throw new CredentialEncryptionError("Credo KMS produced an unexpected JWE serialization");
    }
    return {
      encrypted: Buffer.from(ciphertext, "base64url"),
      iv: Buffer.from(iv, "base64url"),
      tag: Buffer.from(tag, "base64url"),
    };
  }

  async decrypt(options: {
    encrypted: Uint8Array;
    decryption: {
      aad: Uint8Array;
      iv: Uint8Array;
      tag: Uint8Array;
    };
    key: { keyAgreement: { keyId: string } };
  }): Promise<{ data: Uint8Array }> {
    const privateJwk = this.requiredPrivateJwk(options.key.keyAgreement.keyId);
    const compact = [
      Buffer.from(options.decryption.aad).toString("utf8"),
      "",
      Buffer.from(options.decryption.iv).toString("base64url"),
      Buffer.from(options.encrypted).toString("base64url"),
      Buffer.from(options.decryption.tag).toString("base64url"),
    ].join(".");
    const decrypted = await compactDecrypt(
      compact,
      await importJWK(privateJwk, CREDENTIAL_JWE_ALG),
    );
    return { data: decrypted.plaintext };
  }

  private requiredPrivateJwk(keyId: string): JWK {
    const privateJwk = this.privateJwks.get(keyId);
    if (!privateJwk) throw new CredentialEncryptionError(`Unknown KMS key '${keyId}'`);
    return privateJwk;
  }
}

function publicJwk(privateJwk: JWK): JsonRecord {
  const {
    d: _d,
    p: _p,
    q: _q,
    dp: _dp,
    dq: _dq,
    qi: _qi,
    oth: _oth,
    ...publicKey
  } = privateJwk as unknown as JsonRecord;
  return publicKey;
}

function containsPrivateJwkMaterial(jwk: JsonRecord): boolean {
  return ["d", "k", "p", "q", "dp", "dq", "qi", "oth"].some((name) => jwk[name] !== undefined);
}

function parseJsonRecord(value: string, label: string): JsonRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new CredentialEncryptionError(`${label} must be valid JSON`);
  }
  const record = asRecord(parsed);
  if (!record) throw new CredentialEncryptionError(`${label} must be a JSON object`);
  return record;
}

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
