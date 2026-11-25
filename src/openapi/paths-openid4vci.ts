import type { AppConfig, JsonRecord } from "../types.js";
import { errorResponses, form, json, response } from "./common.js";

export function oid4vciPaths(
  config: AppConfig,
  issuerConfigurationIdParameter: JsonRecord,
): JsonRecord {
  return {
    "/issuers/{issuerConfigurationId}/offers/{credentialOfferId}": {
      get: {
        tags: ["OpenID4VCI"],
        operationId: "credentialOffer",
        summary: "Retrieve a Credo credential offer",
        parameters: [
          issuerConfigurationIdParameter,
          {
            name: "credentialOfferId",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
          },
        ],
        responses: {
          "200": response("OpenID4VCI credential offer.", {
            type: "object",
            additionalProperties: true,
          }),
          "404": errorResponses["404"],
        },
      },
    },
    "/issuers/{issuerConfigurationId}/par": {
      post: {
        tags: ["OpenID4VCI"],
        operationId: "pushedAuthorizationRequest",
        summary: "Submit an authorization-code request",
        parameters: [
          issuerConfigurationIdParameter,
          { name: "DPoP", in: "header", required: true, schema: { type: "string" } },
        ],
        requestBody: {
          required: true,
          ...form({
            type: "object",
            required: [
              "response_type",
              "client_id",
              "redirect_uri",
              "scope",
              "code_challenge",
              "code_challenge_method",
            ],
            properties: {
              response_type: { type: "string", const: "code" },
              client_id: { type: "string" },
              redirect_uri: { type: "string", format: "uri" },
              scope: { type: "string" },
              issuer_state: { type: "string" },
              state: { type: "string" },
              code_challenge: { type: "string" },
              code_challenge_method: { type: "string", const: "S256" },
            },
          }),
        },
        responses: {
          "201": response("Short-lived pushed authorization request URI.", {
            type: "object",
            required: ["request_uri", "expires_in"],
            properties: {
              request_uri: { type: "string" },
              expires_in: { type: "integer" },
            },
          }),
          "400": errorResponses["400"],
        },
      },
    },
    "/issuers/{issuerConfigurationId}/authorize": {
      get: {
        tags: ["OpenID4VCI"],
        operationId: "authorize",
        summary: "Start auto-approved authorization",
        parameters: [
          issuerConfigurationIdParameter,
          { name: "client_id", in: "query", required: true, schema: { type: "string" } },
          { name: "request_uri", in: "query", required: true, schema: { type: "string" } },
        ],
        responses: {
          "302": {
            description:
              "Redirect through the chained fake OAuth server and ultimately back to the Wallet.",
          },
          "400": errorResponses["400"],
        },
      },
    },
    "/issuers/{issuerConfigurationId}/redirect": {
      get: {
        tags: ["OpenID4VCI"],
        operationId: "chainedAuthorizationCallback",
        summary: "Complete the chained OAuth authorization",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "302": {
            description: "Redirect to the Wallet with Credo's authorization code.",
          },
          "400": errorResponses["400"],
        },
      },
    },
    "/authorization-servers/{issuerConfigurationId}/authorize": {
      get: {
        tags: ["Fake OAuth"],
        operationId: "fakeAuthorize",
        summary: "Automatically approve Credo's authorization request",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "302": {
            description: "Immediate redirect to Credo's registered callback with a code.",
          },
          "400": errorResponses["400"],
        },
      },
    },
    "/authorization-servers/{issuerConfigurationId}/token": {
      post: {
        tags: ["Fake OAuth"],
        operationId: "fakeToken",
        summary: "Exchange Credo's chained authorization code",
        parameters: [issuerConfigurationIdParameter],
        requestBody: {
          required: true,
          ...form({
            type: "object",
            required: [
              "grant_type",
              "code",
              "code_verifier",
              "redirect_uri",
              "client_id",
              "client_secret",
            ],
            properties: {
              grant_type: { type: "string", const: "authorization_code" },
              code: { type: "string" },
              code_verifier: { type: "string" },
              redirect_uri: { type: "string", format: "uri" },
              client_id: { type: "string" },
              client_secret: { type: "string", format: "password" },
            },
          }),
        },
        responses: {
          "200": response("Short-lived token used only by Credo's chained flow.", {
            type: "object",
            required: ["access_token", "token_type", "expires_in"],
            properties: {
              access_token: { type: "string" },
              token_type: { type: "string", const: "Bearer" },
              expires_in: { type: "integer" },
              scope: { type: "string" },
            },
          }),
          "400": errorResponses["400"],
          "401": errorResponses["400"],
        },
      },
    },
    "/issuers/{issuerConfigurationId}/token": {
      post: {
        tags: ["OpenID4VCI"],
        operationId: "token",
        summary: "Exchange an issuance grant for a DPoP-bound token",
        parameters: [
          issuerConfigurationIdParameter,
          { name: "DPoP", in: "header", required: true, schema: { type: "string" } },
        ],
        requestBody: {
          required: true,
          ...form({
            oneOf: [
              {
                type: "object",
                required: ["grant_type", "pre-authorized_code"],
                properties: {
                  grant_type: {
                    type: "string",
                    const: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                  },
                  "pre-authorized_code": { type: "string" },
                  tx_code: { type: "string" },
                },
              },
              {
                type: "object",
                required: ["grant_type", "code", "code_verifier", "redirect_uri"],
                properties: {
                  grant_type: { type: "string", const: "authorization_code" },
                  code: { type: "string" },
                  code_verifier: { type: "string" },
                  redirect_uri: { type: "string", format: "uri" },
                  client_id: { type: "string" },
                },
              },
            ],
          }),
        },
        responses: {
          "200": response("DPoP access token and credential nonce.", {
            $ref: "#/components/schemas/TokenResponse",
          }),
          "400": errorResponses["400"],
          "401": response("DPoP validation failed.", {
            $ref: "#/components/schemas/Error",
          }),
        },
      },
    },
    "/issuers/{issuerConfigurationId}/nonce": {
      post: {
        tags: ["OpenID4VCI"],
        operationId: "credentialNonce",
        summary: "Request a credential nonce",
        parameters: [issuerConfigurationIdParameter],
        responses: {
          "200": response("Fresh credential nonce.", {
            type: "object",
            required: ["c_nonce"],
            properties: { c_nonce: { type: "string" } },
          }),
        },
      },
    },
    "/issuers/{issuerConfigurationId}/credential": {
      post: {
        tags: ["OpenID4VCI"],
        operationId: "credential",
        summary: "Request a credential",
        parameters: [
          issuerConfigurationIdParameter,
          {
            name: "Authorization",
            in: "header",
            required: true,
            schema: { type: "string", description: "DPoP access token." },
          },
          { name: "DPoP", in: "header", required: true, schema: { type: "string" } },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["credential_configuration_id", "proofs"],
                properties: {
                  credential_configuration_id: { type: "string" },
                  proofs: {
                    type: "object",
                    minProperties: 1,
                    maxProperties: 1,
                    properties: {
                      jwt: {
                        type: "array",
                        minItems: 1,
                        maxItems: 1,
                        items: { type: "string" },
                        description:
                          "openid4vci-proof+jwt with a required key_attestation JOSE header.",
                      },
                      attestation: {
                        type: "array",
                        minItems: 1,
                        maxItems: 1,
                        items: { type: "string" },
                        description: "One key-attestation+jwt proof.",
                      },
                    },
                  },
                },
                additionalProperties: true,
              },
            },
            "application/jwt": {
              schema: {
                type: "string",
                description:
                  "Compact JWE Credential Request. Required when credential_response_encryption is present.",
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Issued credential, optionally encrypted as a compact JWE.",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["credentials"],
                  properties: {
                    credentials: {
                      type: "array",
                      items: {
                        type: "object",
                        required: ["credential"],
                        properties: { credential: { type: "string" } },
                      },
                    },
                    notification_id: {
                      type: "string",
                      description:
                        "Present with OID4VCI_NOTIFICATIONS_ENABLED: identifies every Credential of this response at the Notification Endpoint.",
                    },
                  },
                },
              },
              "application/jwt": {
                schema: {
                  type: "string",
                  description: "Compact JWE containing the Credential Response JSON object.",
                },
              },
            },
          },
          "400": errorResponses["400"],
          "401": response("Access token or DPoP validation failed.", {
            $ref: "#/components/schemas/Error",
          }),
        },
      },
    },
    ...(config.oid4vci_notifications_enabled
      ? {
          "/issuers/{issuerConfigurationId}/notification": {
            post: {
              tags: ["OpenID4VCI"],
              operationId: "credentialNotification",
              summary: "Report the Wallet's outcome for issued Credentials",
              description:
                "OpenID4VCI 1.0 Section 11. Authenticated with the DPoP-bound access token used at the Credential endpoint and a DPoP proof for this endpoint. The notification_id must come from a Credential Response of the same issuer and issuance session. Identical repeats are accepted without new evidence.",
              parameters: [
                issuerConfigurationIdParameter,
                {
                  name: "Authorization",
                  in: "header",
                  required: true,
                  schema: { type: "string", description: "DPoP access token." },
                },
                { name: "DPoP", in: "header", required: true, schema: { type: "string" } },
              ],
              requestBody: {
                required: true,
                ...json({
                  type: "object",
                  required: ["notification_id", "event"],
                  properties: {
                    notification_id: { type: "string", minLength: 1 },
                    event: {
                      type: "string",
                      enum: ["credential_accepted", "credential_failure", "credential_deleted"],
                    },
                    event_description: {
                      type: "string",
                      pattern: "^[\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]*$",
                    },
                  },
                  additionalProperties: true,
                }),
              },
              responses: {
                "204": { description: "The notification was processed." },
                "400": response(
                  "invalid_notification_request for a malformed request, invalid_notification_id for an unknown id or one of another issuer or issuance session.",
                  {
                    type: "object",
                    required: ["error"],
                    properties: {
                      error: {
                        type: "string",
                        enum: ["invalid_notification_request", "invalid_notification_id"],
                      },
                    },
                  },
                ),
                "401": {
                  description:
                    "Missing, invalid, or expired access token, or missing or invalid DPoP proof; the WWW-Authenticate header carries the RFC 6750 challenge.",
                },
                "404": errorResponses["404"],
              },
            },
          },
        }
      : {}),
  };
}
