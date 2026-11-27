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
 * A protocol JWK Set published by value in the Entity Configuration's metadata, distinct from its
 * top-level `jwks`, which holds only the federation signing keys, so a malformed set fails
 * instead of being published.
 */
function publishedProtocolJwks(
  issuer: ResolvedIssuerConfiguration,
  jwks: { keys: readonly JsonRecord[] },
  label: string,
): { keys: JsonRecord[] } {
  if (jwks.keys.length === 0) {
    throw new Error(`Issuer '${issuer.id}' has no ${label} keys to publish`);
  }
  for (const jwk of jwks.keys) {
    if (PRIVATE_JWK_MEMBERS.some((member) => member in jwk)) {
      throw new Error(`Issuer '${issuer.id}' ${label} JWKS contains private key material`);
    }
  }
  return { keys: [...jwks.keys] };
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
  /** The authorization server's access-token signing JWKS, as its jwks endpoint serves it. */
  authorizationServerJwks: { keys: readonly JsonRecord[] };
  authorizationServerMetadata: JsonRecord;
  now?: Date;
}): Promise<string> {
  const {
    issuer,
    authorityHints,
    issuerMetadata,
    issuerJwks,
    authorizationServerJwks,
    authorizationServerMetadata,
    now = new Date(),
  } = options;
  validateMetadataIdentifiers(issuer, issuerMetadata, authorizationServerMetadata);
  // OpenID Federation for Wallet Architectures 1.0, draft 06, §6.3.1.
  const issuerSigningJwks = publishedProtocolJwks(issuer, issuerJwks, "credential signing");
  // OpenID Federation 1.0 §5.2.1 `jwks`, by value, so an access token verifies from the Trust
  // Chain alone; Credo's metadata keeps its `jwks_uri` to the same keys.
  const accessTokenJwks = publishedProtocolJwks(
    issuer,
    authorizationServerJwks,
    "access-token signing",
  );
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
      oauth_authorization_server: { ...authorizationServerMetadata, jwks: accessTokenJwks },
    },
  })
    .setProtectedHeader({ alg: "ES256", typ: "entity-statement+jwt", kid })
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ENTITY_CONFIGURATION_LIFETIME_SECONDS)
    .sign(key);
}
