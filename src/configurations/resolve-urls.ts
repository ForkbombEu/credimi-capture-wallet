import { join } from "node:path";
import type { AppConfig } from "../types.js";
import type { IssuerConfiguration, ResolvedIssuerConfiguration } from "./types.js";

export function resolveIssuerConfiguration(
  config: AppConfig,
  issuer: IssuerConfiguration,
): ResolvedIssuerConfiguration {
  const issuerIdentifier = `${config.issuer_base_url}/issuers/${issuer.routeSlug}`;
  const upstreamAuthorizationServerIdentifier = `${config.issuer_base_url}/authorization-servers/${issuer.routeSlug}`;

  return {
    ...issuer,
    issuerIdentifier,
    issuerMetadataUrl: `${config.issuer_base_url}/.well-known/openid-credential-issuer/issuers/${issuer.routeSlug}`,
    authorizationServerMetadataUrl: `${config.issuer_base_url}/.well-known/oauth-authorization-server/issuers/${issuer.routeSlug}`,
    upstreamAuthorizationServerIdentifier,
    upstreamAuthorizationServerMetadataUrl: `${config.issuer_base_url}/.well-known/oauth-authorization-server/authorization-servers/${issuer.routeSlug}`,
    materialDirectory: join(config.data_dir, "issuers", issuer.routeSlug),
    issuerKeyId: `credimi-${issuer.routeSlug}-issuer-key`,
    issuerEncryptionKeyId: `credimi-${issuer.routeSlug}-issuer-encryption-key`,
    accessTokenKeyId: `credimi-${issuer.routeSlug}-access-token-key`,
    endpoints: {
      authorization: `${issuerIdentifier}/authorize`,
      credential: `${issuerIdentifier}/credential`,
      credentialJwks: `${issuerIdentifier}/credential-jwks.json`,
      credentialOffer: `${issuerIdentifier}/offers`,
      jwks: `${issuerIdentifier}/jwks.json`,
      nonce: `${issuerIdentifier}/nonce`,
      par: `${issuerIdentifier}/par`,
      redirect: `${issuerIdentifier}/redirect`,
      token: `${issuerIdentifier}/token`,
    },
  };
}

export function issuerAppConfig(
  rootConfig: AppConfig,
  issuer: ResolvedIssuerConfiguration,
): AppConfig {
  return {
    ...rootConfig,
    issuer_base_url: issuer.issuerIdentifier,
    data_dir: issuer.materialDirectory,
  };
}
