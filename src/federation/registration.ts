import { loadIssuerFederationJwks } from "../config.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { JsonRecord } from "../types.js";

export function issuerFederationRegistration(issuer: ResolvedIssuerConfiguration): JsonRecord {
  return {
    entity_id: issuer.issuerIdentifier,
    enabled: true,
    entity_types: ["openid_credential_issuer", "oauth_authorization_server"],
    jwks: loadIssuerFederationJwks(issuer),
    constraints: { max_path_length: 0 },
  };
}
