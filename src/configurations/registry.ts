import type { AppConfig } from "../types.js";
import { attestbookExperimental } from "./attestbook-experimental/index.js";
import { euPidDeviceBound } from "./eu-pid-device-bound/index.js";
import { euPidJwtKeyAttestation } from "./eu-pid-jwt-key-attestation/index.js";
import { euPidJwtProofOnly } from "./eu-pid-jwt-proof-only/index.js";
import { resolveIssuerConfiguration } from "./resolve-urls.js";
import type {
  IssuerCatalogueEntry,
  IssuerConfiguration,
  IssuerConfigurationId,
  ResolvedIssuerConfiguration,
} from "./types.js";
import { validateIssuerConfigurations } from "./validate.js";

/** @internal */
export const issuerConfigurations = [
  euPidDeviceBound,
  euPidJwtKeyAttestation,
  euPidJwtProofOnly,
  attestbookExperimental,
] as const;

export const DEFAULT_ISSUER_CONFIGURATION_ID: IssuerConfigurationId = "eu-pid-device-bound";

validateIssuerConfigurations(issuerConfigurations);

/** Whether an issuer is served: always, or only when its opt-in feature is enabled. */
function issuerConfigurationEnabled(
  config: AppConfig,
  configuration: IssuerConfiguration,
): boolean {
  return configuration.feature === undefined || config.attestbook.enabled;
}

function enabledIssuerConfigurationById(config: AppConfig, id: string): IssuerConfiguration | null {
  const configuration = issuerConfigurations.find((candidate) => candidate.id === id);
  return configuration && issuerConfigurationEnabled(config, configuration) ? configuration : null;
}

export function resolvedIssuerConfigurations(
  config: AppConfig,
): readonly ResolvedIssuerConfiguration[] {
  return issuerConfigurations
    .filter((configuration) => issuerConfigurationEnabled(config, configuration))
    .map((configuration) => resolveIssuerConfiguration(config, configuration));
}

/** Every configured issuer, served or not; used only to provision key material. */
export function allResolvedIssuerConfigurations(
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
  const configuration = enabledIssuerConfigurationById(config, id);
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
