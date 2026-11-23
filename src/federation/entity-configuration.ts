import { type JWK, SignJWT, importJWK } from "jose";
import { loadIssuerFederationJwks, loadIssuerFederationPrivateJwk } from "../config.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { JsonRecord } from "../types.js";

export const ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt";

const ENTITY_CONFIGURATION_LIFETIME_SECONDS = 60 * 60;

function isPrivateEcJwk(value: unknown): value is JWK {
  if (typeof value !== "object" || value === null) return false;
  const jwk = value as Record<string, unknown>;
  return jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.d === "string";
}

export async function signIssuerEntityConfiguration(options: {
  issuer: ResolvedIssuerConfiguration;
  authorityHints: readonly string[];
  metadata: JsonRecord;
  now?: Date;
}): Promise<string> {
  const { issuer, authorityHints, metadata, now = new Date() } = options;
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
    metadata: { openid_credential_issuer: metadata },
  })
    .setProtectedHeader({ alg: "ES256", typ: "entity-statement+jwt", kid })
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ENTITY_CONFIGURATION_LIFETIME_SECONDS)
    .sign(key);
}
