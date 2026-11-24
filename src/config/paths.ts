import { join } from "node:path";

const ACCESS_TOKEN_PRIVATE_JWK_FILE = "access-token-private-jwk.json";
const FEDERATION_PRIVATE_JWK_FILE = "private.jwk";
const FEDERATION_JWKS_FILE = "jwks.json";

export function configPath(dataDir: string): string {
  return join(dataDir, "config.yaml");
}

export function jwksPath(dataDir: string): string {
  return join(dataDir, "jwks.json");
}

export function privateJwkPath(dataDir: string): string {
  return join(dataDir, "issuer-private-jwk.json");
}

export function issuerCertificatePath(dataDir: string): string {
  return join(dataDir, "issuer-certificate.pem");
}

export function issuerEncryptionPrivateJwkPath(dataDir: string): string {
  return join(dataDir, "issuer-encryption-private-jwk.json");
}

export function issuerFederationPrivateJwkPath(materialDirectory: string): string {
  return join(materialDirectory, "federation", FEDERATION_PRIVATE_JWK_FILE);
}

export function issuerFederationJwksPath(materialDirectory: string): string {
  return join(materialDirectory, "federation", FEDERATION_JWKS_FILE);
}

export function verifierPrivateJwkPath(dataDir: string): string {
  return join(dataDir, "verifier", "verifier-private-jwk.json");
}

export function verifierJwksPath(dataDir: string): string {
  return join(dataDir, "verifier", "verifier-jwks.json");
}

export function verifierCertificatePath(dataDir: string): string {
  return join(dataDir, "verifier", "verifier-certificate.pem");
}

/**
 * Optional CA certificate that issued the verifier certificate, typically the trust anchor a
 * Wallet is configured with. Operator-supplied; `init` never generates it.
 */
export function verifierCaCertificatePath(dataDir: string): string {
  return join(dataDir, "verifier", "verifier-ca-certificate.pem");
}

export function verifierDidPrivateJwkPath(dataDir: string): string {
  return join(dataDir, "verifier", "verifier-did-private-jwk.json");
}

/**
 * The key of the fixture issuer of Verifier Attestation JWTs. It is a separate key from the request
 * signing key on purpose: the attestation is a statement made *about* this verifier by a third
 * party, and a wallet is expected to trust the issuer, not the verifier it attests to.
 */
export function verifierAttestationIssuerPrivateJwkPath(dataDir: string): string {
  return join(dataDir, "verifier", "verifier-attestation-issuer-private-jwk.json");
}

export function accessTokenPrivateJwkPath(materialDirectory: string): string {
  return join(materialDirectory, ACCESS_TOKEN_PRIVATE_JWK_FILE);
}
