import type { AppConfig, JsonRecord } from "./types.js";

const json = (schema: JsonRecord = { type: "object" }): JsonRecord => ({
  content: { "application/json": { schema } },
});

const form = (schema: JsonRecord): JsonRecord => ({
  content: { "application/x-www-form-urlencoded": { schema } },
});

const response = (description: string, schema?: JsonRecord): JsonRecord => ({
  description,
  ...(schema ? json(schema) : {}),
});

const errorResponses: JsonRecord = {
  "400": response("The request is invalid for the current protocol state.", {
    $ref: "#/components/schemas/Error",
  }),
  "404": response("The requested session or protocol resource was not found.", {
    $ref: "#/components/schemas/Error",
  }),
};

const sessionIdParameter: JsonRecord = {
  name: "sessionId",
  in: "path",
  required: true,
  description: "Capture session identifier returned when the session was created.",
  schema: { type: "string", format: "uuid" },
};

/**
 * The service's public REST and OpenID protocol surface. This deliberately
 * describes the wire contracts without attempting to make stateful wallet
 * flows executable from the documentation UI.
 */
export function openApiDocument(config: AppConfig): JsonRecord {
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
    ],
    paths: {
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
      "/.well-known/openid-credential-issuer": {
        get: {
          tags: ["Service"],
          operationId: "credentialIssuerMetadata",
          summary: "Get credential issuer metadata",
          parameters: [
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
      "/.well-known/oauth-authorization-server": {
        get: {
          tags: ["Service"],
          operationId: "authorizationServerMetadata",
          summary: "Get authorization server metadata",
          responses: {
            "200": response("OAuth authorization server metadata.", {
              type: "object",
              additionalProperties: true,
            }),
          },
        },
      },
      "/.well-known/jwt-vc-issuer": {
        get: {
          tags: ["Service"],
          operationId: "jwtVcIssuerMetadata",
          summary: "Get JWT VC issuer metadata",
          responses: {
            "200": response("JWT VC issuer metadata.", {
              type: "object",
              additionalProperties: true,
            }),
          },
        },
      },
      "/jwks.json": {
        get: {
          tags: ["Service"],
          operationId: "issuerJwks",
          summary: "Get issuer signing keys",
          responses: {
            "200": response("Issuer JSON Web Key Set.", { $ref: "#/components/schemas/Jwks" }),
          },
        },
      },
      "/sessions": {
        post: {
          tags: ["Issuance sessions"],
          operationId: "createIssuanceSession",
          summary: "Create an issuance capture session",
          requestBody: {
            required: false,
            ...json({ $ref: "#/components/schemas/IssuanceSessionRequest" }),
          },
          responses: {
            "201": response("New issuance session and credential-offer deeplink.", {
              $ref: "#/components/schemas/IssuanceSessionCreated",
            }),
            "400": errorResponses["400"],
          },
        },
      },
      "/sessions/{sessionId}": {
        get: {
          tags: ["Issuance sessions"],
          operationId: "getIssuanceSession",
          summary: "Get issuance capture evidence",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("Current issuance capture.", {
              $ref: "#/components/schemas/IssuanceSession",
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/sessions/{sessionId}/offer": {
        get: {
          tags: ["Issuance sessions"],
          operationId: "getCredentialOffer",
          summary: "Get the credential offer",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("OpenID4VCI credential offer.", {
              type: "object",
              additionalProperties: true,
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/sessions/{sessionId}/deeplink": {
        get: {
          tags: ["Issuance sessions"],
          operationId: "getCredentialOfferDeeplink",
          summary: "Get credential-offer deeplink",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("Credential offer and its deeplink.", {
              type: "object",
              required: ["deeplink", "credential_offer"],
              properties: {
                deeplink: { type: "string" },
                credential_offer: { type: "object", additionalProperties: true },
              },
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/sessions/{sessionId}/jwks": {
        get: {
          tags: ["Issuance sessions"],
          operationId: "getWalletJwks",
          summary: "Get observed holder-binding keys",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("Observed wallet JWKS.", { $ref: "#/components/schemas/Jwks" }),
            "404": errorResponses["404"],
            "409": response("The wallet has not supplied a proof header JWK.", {
              $ref: "#/components/schemas/Error",
            }),
          },
        },
      },
      "/sessions/{sessionId}/events": {
        get: {
          tags: ["Issuance sessions"],
          operationId: "getIssuanceEvents",
          summary: "Get issuance event evidence",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("Chronological capture events.", {
              type: "array",
              items: { $ref: "#/components/schemas/Event" },
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/openid4vp/sessions": {
        post: {
          tags: ["Presentation sessions"],
          operationId: "createPresentationSession",
          summary: "Create an OpenID4VP presentation session",
          requestBody: {
            required: false,
            ...json({ $ref: "#/components/schemas/PresentationSessionRequest" }),
          },
          responses: {
            "201": response("New presentation session and OpenID4VP deeplink.", {
              $ref: "#/components/schemas/PresentationSessionCreated",
            }),
            "400": errorResponses["400"],
          },
        },
      },
      "/openid4vp/sessions/{sessionId}": {
        get: {
          tags: ["Presentation sessions"],
          operationId: "getPresentationSession",
          summary: "Get presentation capture evidence",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("Current presentation capture.", {
              $ref: "#/components/schemas/PresentationSession",
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/openid4vp/sessions/{sessionId}/request": {
        get: {
          tags: ["OpenID4VP"],
          operationId: "getPresentationRequest",
          summary: "Retrieve signed presentation request",
          parameters: [sessionIdParameter],
          responses: {
            "200": {
              description: "Signed authorization request object.",
              content: { "application/oauth-authz-req+jwt": { schema: { type: "string" } } },
            },
            "404": errorResponses["404"],
          },
        },
        post: {
          tags: ["OpenID4VP"],
          operationId: "postPresentationRequest",
          summary: "Retrieve request using request_uri POST",
          description:
            "Used only when the session was created with `request_uri_method: post`. A wallet may supply `wallet_nonce`.",
          parameters: [sessionIdParameter],
          requestBody: {
            required: false,
            ...form({
              type: "object",
              properties: { wallet_nonce: { type: "string" } },
              additionalProperties: true,
            }),
          },
          responses: {
            "200": {
              description: "Signed authorization request object.",
              content: { "application/oauth-authz-req+jwt": { schema: { type: "string" } } },
            },
            "404": errorResponses["404"],
          },
        },
      },
      "/openid4vp/sessions/{sessionId}/deeplink": {
        get: {
          tags: ["Presentation sessions"],
          operationId: "getPresentationDeeplink",
          summary: "Get presentation deeplink",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("OpenID4VP deeplink and request claims.", {
              type: "object",
              required: ["deeplink", "authorization_request"],
              properties: {
                deeplink: { type: "string" },
                authorization_request: { type: "object", additionalProperties: true },
              },
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/openid4vp/sessions/{sessionId}/response": {
        post: {
          tags: ["OpenID4VP"],
          operationId: "submitPresentationResponse",
          summary: "Submit a presentation response for a session",
          parameters: [sessionIdParameter],
          requestBody: { required: true, ...form({ type: "object", additionalProperties: true }) },
          responses: {
            "200": response("Presentation was captured and verified."),
            "400": errorResponses["400"],
            "404": errorResponses["404"],
          },
        },
      },
      "/openid4vp/response": {
        post: {
          tags: ["OpenID4VP"],
          operationId: "submitPresentationResponseByState",
          summary: "Submit a presentation response using state",
          description:
            "Alternative direct-post response endpoint. The `state` form parameter identifies the presentation session.",
          requestBody: {
            required: true,
            ...form({
              type: "object",
              required: ["state"],
              properties: { state: { type: "string" } },
              additionalProperties: true,
            }),
          },
          responses: {
            "200": response("Presentation was captured and verified."),
            "400": errorResponses["400"],
            "404": errorResponses["404"],
          },
        },
      },
      "/openid4vp/sessions/{sessionId}/events": {
        get: {
          tags: ["Presentation sessions"],
          operationId: "getPresentationEvents",
          summary: "Get presentation event evidence",
          parameters: [sessionIdParameter],
          responses: {
            "200": response("Chronological capture events.", {
              type: "array",
              items: { $ref: "#/components/schemas/Event" },
            }),
            "404": errorResponses["404"],
          },
        },
      },
      "/par": {
        post: {
          tags: ["OpenID4VCI"],
          operationId: "pushedAuthorizationRequest",
          summary: "Submit a pushed authorization request",
          requestBody: {
            required: true,
            ...form({
              type: "object",
              required: [
                "issuer_state",
                "client_id",
                "redirect_uri",
                "scope",
                "code_challenge",
                "code_challenge_method",
              ],
              properties: {
                issuer_state: { type: "string" },
                client_id: { type: "string" },
                redirect_uri: { type: "string", format: "uri" },
                scope: { type: "string" },
                code_challenge: { type: "string" },
                code_challenge_method: { type: "string", const: "S256" },
              },
              additionalProperties: true,
            }),
          },
          responses: {
            "201": response("PAR request URI.", {
              type: "object",
              required: ["request_uri", "expires_in"],
              properties: { request_uri: { type: "string" }, expires_in: { type: "integer" } },
            }),
            "400": errorResponses["400"],
          },
        },
      },
      "/authorize": {
        get: {
          tags: ["OpenID4VCI"],
          operationId: "authorize",
          summary: "Authorize a credential request",
          description:
            "Resolves a valid PAR `request_uri` and redirects the wallet to its registered redirect URI with an authorization code.",
          parameters: [
            { name: "request_uri", in: "query", required: true, schema: { type: "string" } },
          ],
          responses: {
            "302": { description: "Redirect to the wallet callback with code, state, and iss." },
            "400": errorResponses["400"],
          },
        },
      },
      "/token": {
        post: {
          tags: ["OpenID4VCI"],
          operationId: "token",
          summary: "Exchange an authorization code for a DPoP-bound token",
          parameters: [
            { name: "DPoP", in: "header", required: true, schema: { type: "string" } },
            {
              name: "OAuth-Client-Attestation",
              in: "header",
              required: false,
              schema: { type: "string" },
            },
            {
              name: "OAuth-Client-Attestation-PoP",
              in: "header",
              required: false,
              schema: { type: "string" },
            },
          ],
          requestBody: {
            required: true,
            ...form({
              type: "object",
              required: ["code", "code_verifier"],
              properties: {
                grant_type: { type: "string", const: "authorization_code" },
                code: { type: "string" },
                code_verifier: { type: "string" },
                redirect_uri: { type: "string", format: "uri" },
                client_id: { type: "string" },
                client_assertion: { type: "string" },
                client_assertion_type: { type: "string" },
              },
              additionalProperties: true,
            }),
          },
          responses: {
            "200": response("DPoP access token and credential nonce.", {
              $ref: "#/components/schemas/TokenResponse",
            }),
            "400": errorResponses["400"],
            "401": response("Client authentication or DPoP validation failed.", {
              $ref: "#/components/schemas/Error",
            }),
          },
        },
      },
      "/nonce": {
        post: {
          tags: ["OpenID4VCI"],
          operationId: "credentialNonce",
          summary: "Request a credential nonce",
          responses: {
            "200": response("Fresh credential nonce.", {
              type: "object",
              required: ["c_nonce", "c_nonce_expires_in"],
              properties: { c_nonce: { type: "string" }, c_nonce_expires_in: { type: "integer" } },
            }),
          },
        },
      },
      "/credential": {
        post: {
          tags: ["OpenID4VCI"],
          operationId: "credential",
          summary: "Request a credential",
          parameters: [
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
              required: ["credential_configuration_id", "proofs"],
              properties: {
                credential_configuration_id: { type: "string" },
                proofs: {
                  type: "object",
                  properties: { jwt: { type: "array", items: { type: "string" } } },
                },
              },
              additionalProperties: true,
            }),
          },
          responses: {
            "200": response("Issued credential.", {
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
              },
            }),
            "400": errorResponses["400"],
            "401": response("Access token or DPoP validation failed.", {
              $ref: "#/components/schemas/Error",
            }),
          },
        },
      },
    },
    components: {
      schemas: {
        Health: {
          type: "object",
          required: ["status"],
          properties: { status: { type: "string", const: "ok" } },
        },
        Error: {
          type: "object",
          required: ["error"],
          properties: {
            error: { type: "string" },
            error_description: { type: "string" },
            message: { type: "string" },
          },
          additionalProperties: true,
        },
        Jwks: {
          type: "object",
          required: ["keys"],
          properties: {
            keys: { type: "array", items: { type: "object", additionalProperties: true } },
          },
        },
        Event: {
          type: "object",
          required: ["at", "type", "detail"],
          properties: {
            at: { type: "string", format: "date-time" },
            type: { type: "string" },
            detail: { type: "object", additionalProperties: true },
          },
        },
        IssuanceSessionRequest: {
          type: "object",
          properties: {
            credential_configuration_id: {
              type: "string",
              description: "One of the IDs advertised by credential issuer metadata.",
            },
            broken: {
              type: "boolean",
              default: false,
              description:
                "Issue the intentionally malformed legacy PID test fixture instead of the conforming fixture.",
            },
          },
        },
        IssuanceSessionCreated: {
          type: "object",
          required: [
            "session_id",
            "credential_configuration_id",
            "broken",
            "offer_url",
            "deeplink",
            "status",
          ],
          properties: {
            session_id: { type: "string", format: "uuid" },
            credential_configuration_id: { type: "string" },
            broken: { type: "boolean" },
            offer_url: { type: "string", format: "uri" },
            deeplink: { type: "string" },
            status: { type: "string", const: "created" },
          },
        },
        IssuanceSession: {
          type: "object",
          required: [
            "session_id",
            "status",
            "credential_configuration_id",
            "broken",
            "observed",
            "checks",
            "events",
          ],
          additionalProperties: true,
        },
        PresentationSessionRequest: {
          type: "object",
          properties: {
            scheme: {
              type: "string",
              pattern: "^[A-Za-z][A-Za-z0-9+.-]*://$",
              default: "openid4vp://",
              description: "Custom URL-scheme prefix for the returned deeplink.",
            },
            request_uri_method: { type: "string", enum: ["get", "post"], default: "get" },
            request_delivery: {
              type: "string",
              enum: ["by_reference", "by_value"],
              default: "by_reference",
            },
            response_type: {
              type: "string",
              enum: ["vp_token", "vp_token id_token", "code"],
              default: "vp_token",
            },
            response_mode: {
              type: "string",
              enum: ["direct_post", "direct_post.jwt"],
              default: "direct_post.jwt",
            },
            presentation_request: { type: "object", additionalProperties: true },
            dcql_query: { type: "object", additionalProperties: true },
            scopes: { oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
            transaction_data: {},
            verifier_info: {},
          },
          additionalProperties: true,
        },
        PresentationSessionCreated: {
          type: "object",
          required: [
            "session_id",
            "request_delivery",
            "request_uri",
            "request_uri_method",
            "response_mode",
            "scheme",
            "response_uri",
            "deeplink",
            "authorization_request",
            "status",
          ],
          properties: {
            session_id: { type: "string", format: "uuid" },
            request_delivery: { type: "string" },
            request_uri: { type: "string", format: "uri" },
            request_uri_method: { type: "string" },
            response_mode: { type: "string" },
            scheme: { type: "string" },
            response_uri: { type: "string", format: "uri" },
            deeplink: { type: "string" },
            authorization_request: { type: "object", additionalProperties: true },
            status: { type: "string", const: "created" },
          },
        },
        PresentationSession: {
          type: "object",
          required: [
            "session_id",
            "status",
            "authorization_request",
            "observed",
            "checks",
            "events",
          ],
          additionalProperties: true,
        },
        TokenResponse: {
          type: "object",
          required: ["access_token", "token_type", "expires_in", "c_nonce", "c_nonce_expires_in"],
          properties: {
            access_token: { type: "string" },
            token_type: { type: "string", const: "DPoP" },
            expires_in: { type: "integer" },
            c_nonce: { type: "string" },
            c_nonce_expires_in: { type: "integer" },
          },
        },
      },
    },
  };
}

export function apiDocsPage(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Credimi Capture Wallet API</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="stylesheet" href="https://unpkg.com/@stoplight/elements@9.0.0/styles.min.css">
  </head>
  <body>
    <elements-api apiDescriptionUrl="/openapi.json" layout="responsive" router="hash"></elements-api>
    <script src="https://unpkg.com/@stoplight/elements@9.0.0/web-components.min.js"></script>
  </body>
</html>`;
}
