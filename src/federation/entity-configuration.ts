import { type JWK, SignJWT, importJWK } from "jose";
import {
  loadIssuerFederationJwks,
  loadIssuerFederationPrivateJwk,
} from "../config/key-material.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { JsonRecord } from "../types.js";

export const ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt";

const ENTITY_CONFIGURATION_LIFETIME_SECONDS = 60 * 60;

/** JWK members that carry private or symmetric key material (RFC 7517 §8.1.1, RFC 7518 §6). */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/**
 * The Credential Issuer's protocol signing keys, published as
 * `metadata.openid_credential_issuer.jwks` (OpenID Federation for Wallet Architectures 1.0,
 * draft 06, §6.3.1). They are distinct from the Entity Configuration's top-level `jwks`, which
 * holds only the federation signing keys, so a malformed set fails instead of being published.
 */
function credentialIssuerSigningJwks(
  issuer: ResolvedIssuerConfiguration,
  issuerJwks: { keys: readonly JsonRecord[] },
): { keys: JsonRecord[] } {
  if (issuerJwks.keys.length === 0) {
    throw new Error(`Issuer '${issuer.id}' has no credential signing keys to publish`);
  }
  for (const jwk of issuerJwks.keys) {
    if (PRIVATE_JWK_MEMBERS.some((member) => member in jwk)) {
      throw new Error(
        `Issuer '${issuer.id}' credential signing JWKS contains private key material`,
      );
    }
  }
  return { keys: [...issuerJwks.keys] };
}

function isPrivateEcJwk(value: unknown): value is JWK {
  if (typeof value !== "object" || value === null) return false;
  const jwk = value as Record<string, unknown>;
  return jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.d === "string";
}

function validateMetadataIdentifiers(
  issuer: ResolvedIssuerConfiguration,
  issuerMetadata: JsonRecord,
  authorizationServerMetadata: JsonRecord,
): void {
  if (issuerMetadata.credential_issuer !== issuer.issuerIdentifier) {
    throw new Error(
      `Issuer '${issuer.id}' credential issuer metadata identifier does not match its federation Entity Identifier`,
    );
  }
  if (authorizationServerMetadata.issuer !== issuer.issuerIdentifier) {
    throw new Error(
      `Issuer '${issuer.id}' authorization server metadata identifier does not match its federation Entity Identifier`,
    );
  }
}

export async function signIssuerEntityConfiguration(options: {
  issuer: ResolvedIssuerConfiguration;
  authorityHints: readonly string[];
  issuerMetadata: JsonRecord;
  /** The issuer's own credential and metadata signing JWKS, never the federation keys. */
  issuerJwks: { keys: readonly JsonRecord[] };
  authorizationServerMetadata: JsonRecord;
  now?: Date;
}): Promise<string> {
  const {
    issuer,
    authorityHints,
    issuerMetadata,
    issuerJwks,
    authorizationServerMetadata,
    now = new Date(),
  } = options;
  validateMetadataIdentifiers(issuer, issuerMetadata, authorizationServerMetadata);
  const issuerSigningJwks = credentialIssuerSigningJwks(issuer, issuerJwks);
  const privateJwk = loadIssuerFederationPrivateJwk(issuer);
  const jwks = loadIssuerFederationJwks(issuer);
  if (!isPrivateEcJwk(privateJwk)) {
    throw new Error(`Issuer '${issuer.id}' federation signing key is not an ES256 private JWK`);
  }
  const key = await importJWK(privateJwk, "ES256");
  const kid = privateJwk.kid;
  if (typeof kid !== "string" || kid.length === 0) {
    throw new Error(`Issuer '${issuer.id}' federation signing key is missing a kid`);
  }
  const issuedAt = Math.floor(now.getTime() / 1000);

  return new SignJWT({
    iss: issuer.issuerIdentifier,
    sub: issuer.issuerIdentifier,
    jwks,
    authority_hints: [...authorityHints],
    metadata: {
      openid_credential_issuer: { ...issuerMetadata, jwks: issuerSigningJwks },
      oauth_authorization_server: authorizationServerMetadata,
    },
  })
    .setProtectedHeader({ alg: "ES256", typ: "entity-statement+jwt", kid })
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ENTITY_CONFIGURATION_LIFETIME_SECONDS)
    .sign(key);
}
