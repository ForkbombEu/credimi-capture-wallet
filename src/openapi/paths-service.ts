import type { JsonRecord } from "../types.js";
import { response } from "./common.js";

export function healthAndCredentialIssuerPaths(
  issuerConfigurationIdParameter: JsonRecord,
): JsonRecord {
  return {
    "/healthz": {
      get: {
        tags: ["Service"],
        operationId: "health",
        summary: "Check service health",
        responses: {
          "200": response("The service is ready.", { $ref: "#/components/schemas/Health" }),
        },
      },
    },
    "/.well-known/openid-credential-issuer/issuers/{issuerConfigurationId}": {
      get: {
        tags: ["Service"],
        operationId: "credentialIssuerMetadata",
        summary: "Get credential issuer metadata",
        parameters: [
          issuerConfigurationIdParameter,
          {
            name: "Accept",
            in: "header",
            required: false,
            description:
              "Request application/jwt for signed metadata; application/json is returned otherwise.",
            schema: {
              type: "string",
              enum: ["application/json", "application/jwt"],
              default: "application/json",
            },
          },
        ],
        responses: {
          "200": {
            description: "OpenID4VCI credential issuer metadata.",
            content: {
              "application/json": {
                schema: { type: "object", additionalProperties: true },
              },
              "application/jwt": {
                schema: {
                  type: "string",
                  description: "Compact JWS with the signed metadata as top-level claims.",
                },
              },
            },
          },
        },
      },
    },
  };
}

export function serviceDiscoveryPaths(issuerConfigurationIdParameter: JsonRecord): JsonRecord {
  return {
    "/.well-known/oauth-authorization-server/issuers/{issuerConfigurationId}": {
      get: {
        tags: ["Service"],
        operationId: "authorizationServerMetadata",
        summary: "Get authorization server metadata",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "200": response("OAuth authorization server metadata.", {
            type: "object",
            additionalProperties: true,
          }),
        },
      },
    },
    "/.well-known/oauth-authorization-server/authorization-servers/{issuerConfigurationId}": {
      get: {
        tags: ["Fake OAuth"],
        operationId: "fakeAuthorizationServerMetadata",
        summary: "Get fake OAuth server metadata",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "200": response("Auto-approving OAuth authorization server metadata.", {
            type: "object",
            additionalProperties: true,
          }),
        },
      },
    },
    "/.well-known/jwt-vc-issuer/issuers/{issuerConfigurationId}": {
      get: {
        tags: ["Service"],
        operationId: "jwtVcIssuerMetadata",
        summary: "Get JWT VC issuer metadata",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "200": response("JWT VC issuer metadata.", {
            type: "object",
            additionalProperties: true,
          }),
        },
      },
    },
    "/issuers/{issuerConfigurationId}/jwks.json": {
      get: {
        tags: ["Service"],
        operationId: "authorizationServerJwks",
        summary: "Get authorization-server signing keys",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "200": response("Authorization-server JSON Web Key Set.", {
            $ref: "#/components/schemas/Jwks",
          }),
        },
      },
    },
    "/issuers/{issuerConfigurationId}/credential-jwks.json": {
      get: {
        tags: ["Service"],
        operationId: "credentialIssuerJwks",
        summary: "Get credential-signing keys",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "200": response("Credential issuer JSON Web Key Set.", {
            $ref: "#/components/schemas/Jwks",
          }),
        },
      },
    },
    "/oid4vci/requests": {
      get: {
        tags: ["OpenID4VCI"],
        operationId: "getOid4vciRequests",
        summary: "Get redacted OpenID4VCI HTTP evidence",
        description:
          "Returns the bounded chronological request ledger. Security-sensitive headers and fields are replaced with presence and length metadata, whatever a session's evidence_mode: unredacted evidence is only ever exposed through the session that selected it.",
        responses: {
          "200": response("Redacted OpenID4VCI request evidence.", {
            type: "array",
            items: { $ref: "#/components/schemas/Oid4vciHttpRequestCapture" },
          }),
        },
      },
    },
    "/issuers": {
      get: {
        tags: ["Service"],
        operationId: "issuerCatalogue",
        summary: "List the served credential issuers",
        responses: {
          "200": response("Public issuer catalogue.", {
            type: "array",
            items: { $ref: "#/components/schemas/IssuerCatalogueEntry" },
          }),
        },
      },
    },
    "/integrations/attestbook/status": {
      get: {
        tags: ["Service"],
        operationId: "attestbookIntegrationStatus",
        summary: "Inspect the Attestbook integration",
        description:
          "Non-sensitive synchronization status: never a webhook secret, management or administrator token, key, or claim value. Answers { enabled: false } when the integration is disabled.",
        responses: {
          "200": response("Integration status.", {
            $ref: "#/components/schemas/AttestbookIntegrationStatus",
          }),
        },
      },
    },
  };
}
