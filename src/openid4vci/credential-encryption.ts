import { type AgentContext, Kms } from "@credo-ts/core";
import { getOid4vcDecryptJweCallback, getOid4vcEncryptJweCallback } from "@credo-ts/openid4vc";
import { loadIssuerEncryptionPublicJwk } from "../config/key-material.js";
import { errorMessage } from "../shared/errors.js";
import { asRecord } from "../shared/json.js";
import type { AppConfig, JsonRecord } from "../types.js";

const CREDENTIAL_JWE_ALG = "ECDH-ES";
const CREDENTIAL_JWE_ENC = "A256GCM";

export interface CredentialResponseEncryption {
  jwk: JsonRecord;
  enc: typeof CREDENTIAL_JWE_ENC;
}

export class CredentialEncryptionError extends Error {}

/**
 * Decrypts a Credential Request JWE (OpenID4VCI 1.0 Section 10) with the issuer encryption key the
 * Credo agent imported under its own `kid`.
 */
export async function decryptCredentialRequest(
  config: AppConfig,
  agentContext: AgentContext,
  compactJwe: string,
): Promise<JsonRecord> {
  const issuerPublicJwk = loadIssuerEncryptionPublicJwk(config);
  if (!issuerPublicJwk || typeof issuerPublicJwk.kid !== "string") {
    throw new CredentialEncryptionError("Issuer credential request encryption key is unavailable");
  }

  try {
    const decrypt = getOid4vcDecryptJweCallback(agentContext, {
      [issuerPublicJwk.kid]: { keyId: issuerPublicJwk.kid },
    });
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
    if (result.header.kid !== issuerPublicJwk.kid) {
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

/** Encrypts a Credential Response to the Wallet's key with the Credo agent's KMS. */
export async function encryptCredentialResponse(
  agentContext: AgentContext,
  encryption: CredentialResponseEncryption,
  response: JsonRecord,
): Promise<string> {
  try {
    const encrypt = getOid4vcEncryptJweCallback(agentContext);
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
