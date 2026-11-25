import { readFileSync } from "node:fs";
import type { AppConfig, JsonRecord } from "../types.js";
import { verifierAttestationIssuerPrivateJwkPath, verifierDidPrivateJwkPath } from "./paths.js";

export const VERIFIER_KEY_ID = "credimi-fake-verifier-key";
export const VERIFIER_DID_KEY_ID = "credimi-fake-verifier-did-key";
export const VERIFIER_ATTESTATION_ISSUER_KEY_ID = "credimi-fake-verifier-attestation-issuer-key";

export function verifierAttestationIssuerPublicJwk(config: AppConfig): JsonRecord {
  const { d: _private, ...publicJwk } = JSON.parse(
    readFileSync(verifierAttestationIssuerPrivateJwkPath(config.data_dir), "utf8"),
  ) as JsonRecord;
  return publicJwk;
}

/** The identifier this service attests to, and the part of `verifier_attestation:<sub>`. */
export function verifierAttestationSubject(config: AppConfig): string {
  return new URL(config.issuer_base_url).host;
}

export function verifierAttestationIssuer(config: AppConfig): string {
  return `${config.issuer_base_url}/openid4vp/verifier-attestation-issuer`;
}

export function verifierDid(config: AppConfig): string {
  const url = new URL(config.issuer_base_url);
  const authority = url.port ? `${url.hostname}%3A${url.port}` : url.hostname;
  return `did:web:${authority}:openid4vp`;
}

export function verifierDidDocument(config: AppConfig): JsonRecord {
  const did = verifierDid(config);
  const privateJwk = JSON.parse(
    readFileSync(verifierDidPrivateJwkPath(config.data_dir), "utf8"),
  ) as JsonRecord;
  const { d: _private, ...publicJwk } = privateJwk;
  const keyId = `${did}#${VERIFIER_DID_KEY_ID}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: publicJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}
