import type { AppConfig } from "../types.js";
import { euPidDeviceBound } from "./eu-pid-device-bound/index.js";
import { euPidJwtProofOnly } from "./eu-pid-jwt-proof-only/index.js";
import { resolveIssuerConfiguration } from "./resolve-urls.js";
import type {
  IssuerCatalogueEntry,
  IssuerConfiguration,
  IssuerConfigurationId,
  ResolvedIssuerConfiguration,
} from "./types.js";
import { validateIssuerConfigurations } from "./validate.js";

export const issuerConfigurations = [euPidDeviceBound, euPidJwtProofOnly] as const;

export const DEFAULT_ISSUER_CONFIGURATION_ID: IssuerConfigurationId = "eu-pid-device-bound";

validateIssuerConfigurations(issuerConfigurations);

export function issuerConfigurationById(id: string): (typeof issuerConfigurations)[number] | null {
  return issuerConfigurations.find((configuration) => configuration.id === id) ?? null;
}

export function resolvedIssuerConfigurations(
  config: AppConfig,
): readonly ResolvedIssuerConfiguration[] {
  return issuerConfigurations.map((configuration) =>
    resolveIssuerConfiguration(config, configuration),
  );
}

export function resolvedIssuerConfigurationById(
  config: AppConfig,
  id: string,
): ResolvedIssuerConfiguration | null {
  const configuration = issuerConfigurationById(id);
  return configuration ? resolveIssuerConfiguration(config, configuration) : null;
}

export function issuerCatalogue(
  config: AppConfig,
  credentialIds: (configuration: IssuerConfiguration) => readonly string[],
): readonly IssuerCatalogueEntry[] {
  return resolvedIssuerConfigurations(config).map((issuer) => ({
    id: issuer.id,
    compliance: issuer.compliance,
    credential_issuer: issuer.issuerIdentifier,
    credential_issuer_metadata: issuer.issuerMetadataUrl,
    authorization_server_metadata: issuer.authorizationServerMetadataUrl,
    upstream_authorization_server: issuer.upstreamAuthorizationServerIdentifier,
    name: issuer.display.name,
    description: issuer.display.description,
    ...(issuer.display.warning ? { warning: issuer.display.warning } : {}),
    credential_configuration_ids: credentialIds(issuer),
  }));
}
