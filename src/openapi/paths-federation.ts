import type { AppConfig, JsonRecord } from "../types.js";
import { response } from "./common.js";

export function federationPaths(
  config: AppConfig,
  issuerConfigurationIdParameter: JsonRecord,
): JsonRecord {
  return {
    ...(config.federation.enabled
      ? {
          "/issuers/{issuerConfigurationId}/.well-known/openid-federation": {
            get: {
              tags: ["OpenID Federation"],
              operationId: "issuerFederationEntityConfiguration",
              summary: "Get a Credential Issuer OpenID Federation Entity Configuration",
              parameters: [issuerConfigurationIdParameter],
              responses: {
                "200": {
                  description: "Self-signed OpenID Federation Entity Configuration.",
                  content: {
                    "application/entity-statement+jwt": {
                      schema: {
                        type: "string",
                        description: "Compact JWS Entity Configuration.",
                      },
                    },
                  },
                },
                "404": response("The issuer configuration is unknown or disabled.", {
                  type: "object",
                  additionalProperties: true,
                }),
              },
            },
          },
        }
      : {}),
  };
}
