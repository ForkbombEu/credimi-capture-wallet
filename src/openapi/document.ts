import { resolvedIssuerConfigurations } from "../configurations/registry.js";
import type { AppConfig, JsonRecord } from "../types.js";
import { issuerConfigurationIdParameterFor } from "./common.js";
import { components } from "./components.js";
import { attestbookPaths } from "./paths-attestbook.js";
import { federationPaths } from "./paths-federation.js";
import { issuanceSessionPaths } from "./paths-issuance.js";
import { oid4vciPaths } from "./paths-openid4vci.js";
import { presentationPaths } from "./paths-presentation.js";
import { healthAndCredentialIssuerPaths, serviceDiscoveryPaths } from "./paths-service.js";

/**
 * The service's public REST and OpenID protocol surface. This deliberately
 * describes the wire contracts without attempting to make stateful wallet
 * flows executable from the documentation UI.
 */
export function openApiDocument(config: AppConfig): JsonRecord {
  const issuerIds = resolvedIssuerConfigurations(config).map((issuer) => issuer.id);
  const issuerConfigurationIdParameter = issuerConfigurationIdParameterFor(issuerIds);
  return {
    openapi: "3.1.0",
    info: {
      title: "Credimi Capture Wallet API",
      version: "1.0.0",
      description:
        "Stateful OpenID4VCI issuer and OpenID4VP verifier used to capture wallet protocol evidence. Protocol endpoints require a conforming wallet; use the session endpoints to start a flow.",
    },
    servers: [{ url: config.issuer_base_url, description: "Configured capture service" }],
    tags: [
      { name: "Service", description: "Service discovery and initialization." },
      { name: "Issuance sessions", description: "Capture sessions and credential offers." },
      {
        name: "Presentation sessions",
        description: "Create sessions and retrieve captured presentation evidence.",
      },
      { name: "OpenID4VCI", description: "OpenID for Verifiable Credential Issuance endpoints." },
      { name: "OpenID4VP", description: "OpenID for Verifiable Presentations wallet endpoints." },
      {
        name: "Fake OAuth",
        description:
          "Test-only auto-approving OAuth server used by Credo's chained authorization-code flow.",
      },
      ...(config.attestbook.enabled
        ? [
            {
              name: "Attestbook",
              description:
                "Opt-in import of SD-JWT VC credential definitions from one subscribed Attestbook rulebook.",
            },
          ]
        : []),
      ...(config.federation.enabled
        ? [
            {
              name: "OpenID Federation",
              description:
                "OpenID Federation 1.0 leaf Entity Configurations for enabled Credential Issuers.",
            },
          ]
        : []),
    ],
    paths: {
      ...healthAndCredentialIssuerPaths(issuerConfigurationIdParameter),
      ...federationPaths(config, issuerConfigurationIdParameter),
      ...serviceDiscoveryPaths(issuerConfigurationIdParameter),
      ...attestbookPaths(config),
      ...issuanceSessionPaths(),
      ...presentationPaths(),
      ...oid4vciPaths(config, issuerConfigurationIdParameter),
    },
    components: components(issuerIds),
  };
}
