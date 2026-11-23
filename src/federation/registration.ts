import { loadIssuerFederationJwks } from "../config.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { JsonRecord } from "../types.js";

export function issuerFederationJwks(issuer: ResolvedIssuerConfiguration): JsonRecord {
  return loadIssuerFederationJwks(issuer);
}

export function issuerFederationRegistration(
  issuer: ResolvedIssuerConfiguration,
  enabled = true,
): JsonRecord {
  return {
    entity_id: issuer.issuerIdentifier,
    enabled,
    entity_types: ["openid_credential_issuer"],
    jwks: issuerFederationJwks(issuer),
    constraints: { max_path_length: 0 },
  };
}
