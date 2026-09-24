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

const issuerConfigurationIdParameter: JsonRecord = {
  name: "issuerConfigurationId",
  in: "path",
  required: true,
  description: "Always-on issuer configuration identifier returned by GET /issuers.",
  schema: {
    type: "string",
    enum: ["eu-pid-device-bound", "eu-pid-jwt-proof-only"],
  },
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
      {
        name: "Fake OAuth",
        description:
          "Test-only auto-approving OAuth server used by Credo's chained authorization-code flow.",
      },
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
            "Returns the bounded chronological request ledger. Security-sensitive headers and fields are replaced with presence and length metadata.",
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
          summary: "List all always-on credential issuers",
          responses: {
            "200": response("Public issuer catalogue.", {
              type: "array",
              items: { $ref: "#/components/schemas/IssuerCatalogueEntry" },
            }),
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
      "/openid4vp/did.json": {
        get: {
          tags: ["OpenID4VP"],
          operationId: "getVerifierDidDocument",
          summary: "Get the verifier did:web Document",
          responses: {
            "200": response("Verifier DID Document.", {
              type: "object",
              additionalProperties: true,
            }),
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
          description:
            "Accepts the Authorization Response for the addressed session. A DC API presentation is forwarded here by the presentation page and needs no state parameter; such a submission is refused once the session holds a presentation (409), after the presentation window closes (400), or when the browser Origin header disagrees with the session origin (403).",
          parameters: [sessionIdParameter],
          requestBody: { required: true, ...form({ type: "object", additionalProperties: true }) },
          responses: {
            "200": response("Presentation was captured and verified."),
            "400": errorResponses["400"],
            "403": errorResponses["400"],
            "404": errorResponses["404"],
            "409": errorResponses["400"],
          },
        },
      },
      "/openid4vp/sessions/{sessionId}/dc_api_invocation": {
        post: {
          tags: ["OpenID4VP"],
          operationId: "reportDcApiInvocation",
          summary: "Report a DC API invocation that returned no presentation",
          description:
            "Records why a Digital Credentials API invocation produced no Authorization Response. This is the evidence a wallet's refusal leaves behind — for example when a HAIP wallet rejects the unencrypted dc_api response mode — and it is kept distinct from a verification failure over a real response. A wallet refusal and an End-User cancellation are not distinguishable at the browser API, so `rejected` records what the browser reported without asserting which occurred.",
          parameters: [sessionIdParameter],
          requestBody: {
            required: true,
            ...form({
              type: "object",
              required: ["outcome"],
              properties: {
                outcome: {
                  type: "string",
                  enum: ["api_unavailable", "rejected", "no_vp_token", "failed"],
                },
                error_name: {
                  type: "string",
                  description: "DOMException name, when there was one.",
                },
                error_message: { type: "string" },
                response_returned: { type: "boolean" },
                vp_token_present: { type: "boolean" },
              },
              additionalProperties: false,
            }),
          },
          responses: {
            "202": response("Invocation outcome was captured.", {
              type: "object",
              required: ["status"],
              properties: { status: { type: "string", const: "dc_api_invocation_reported" } },
            }),
            "400": errorResponses["400"],
            "404": errorResponses["404"],
            "409": errorResponses["400"],
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
        Oid4vciHttpRequestCapture: {
          type: "object",
          required: [
            "id",
            "at",
            "method",
            "path",
            "session_id",
            "issuer_configuration_id",
            "headers",
            "query",
            "body",
            "response",
          ],
          properties: {
            id: { type: "string", format: "uuid" },
            at: { type: "string", format: "date-time" },
            method: { type: "string" },
            path: { type: "string" },
            session_id: { type: ["string", "null"] },
            issuer_configuration_id: { type: ["string", "null"] },
            headers: { type: "object", additionalProperties: true },
            query: {},
            body: {},
            response: {
              type: "object",
              properties: {
                status: { type: ["integer", "null"] },
                content_type: { type: ["string", "null"] },
              },
            },
          },
        },
        IssuanceSessionRequest: {
          type: "object",
          properties: {
            issuer_configuration_id: {
              type: "string",
              enum: ["eu-pid-device-bound", "eu-pid-jwt-proof-only"],
              default: "eu-pid-device-bound",
              description: "Selects one of the always-on isolated issuer configurations.",
            },
            flow: {
              type: "string",
              enum: ["pre_authorized_code", "authorization_code"],
              default: "authorization_code",
              description: "Issuance flow preset.",
            },
            credential_offer_mode: {
              type: "string",
              enum: ["credential_offer", "credential_offer_uri"],
              default: "credential_offer",
              description:
                "Encode the offer directly in the deeplink or provide its hosted URI by reference.",
            },
            status_reference: {
              type: "string",
              enum: [
                "valid",
                "status_without_status_list",
                "negative_index",
                "missing_index",
                "malformed_uri",
                "missing_uri",
              ],
              default: "valid",
              description:
                "Shape of the status claim in the issued SD-JWT VC. Anything other than valid is test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED, and requires status_list_enabled so the malformed structure reshapes a genuinely allocated reference. Not available for mdoc configurations, where the status claim is built by the COSE library and these structures cannot be produced.",
            },
            digest_algorithm: {
              type: "string",
              enum: ["sha-256", "sha-384", "sha-512"],
              default: "sha-256",
              description:
                "Hash function the issued SD-JWT VC digests its disclosures with, placed in the _sd_alg claim. Credential Issuer Metadata keeps advertising SHA-256 only, so a value other than sha-256 produces a credential a Wallet can present only if it supports that hash function. Not available for mdoc configurations, where the digests belong to the Mobile Security Object.",
            },
            fixture_id: {
              type: "string",
              default: "pid_default",
              description:
                "Predefined PID claim set the issued credential carries. Fixtures differ from the baseline along one value axis each, so a DCQL value constraint matches one and withholds the others. No caller-supplied claim override exists, so an issued credential always corresponds to a named fixture.",
            },
            credential_configuration_id: {
              type: "string",
              description: "One of the IDs advertised by credential issuer metadata.",
            },
            status_list_enabled: {
              type: "boolean",
              default: false,
              description:
                "When true, allocate and embed a Token Status List reference in each issued credential.",
            },
          },
        },
        IssuanceSessionCreated: {
          type: "object",
          required: [
            "session_id",
            "issuer_configuration_id",
            "issuer_identifier",
            "authorization_server_identifier",
            "flow",
            "credential_offer_mode",
            "credential_configuration_id",
            "status_list_enabled",
            "offer_url",
            "deeplink",
            "status",
          ],
          properties: {
            session_id: { type: "string", format: "uuid" },
            issuer_configuration_id: { type: "string" },
            issuer_identifier: { type: "string", format: "uri" },
            authorization_server_identifier: { type: "string", format: "uri" },
            flow: {
              type: "string",
              enum: ["pre_authorized_code", "authorization_code"],
            },
            credential_offer_mode: {
              type: "string",
              enum: ["credential_offer", "credential_offer_uri"],
            },
            credential_configuration_id: { type: "string" },
            status_list_enabled: { type: "boolean" },
            fixture_id: { type: "string" },
            status_reference: { type: "string" },
            digest_algorithm: { type: "string" },
            offer_url: { type: "string", format: "uri" },
            deeplink: { type: "string" },
            status: { type: "string", const: "created" },
          },
        },
        IssuanceSession: {
          type: "object",
          required: [
            "session_id",
            "issuer_configuration_id",
            "issuer_identifier",
            "authorization_server_identifier",
            "status",
            "flow",
            "credential_offer_mode",
            "credential_configuration_id",
            "observed",
            "checks",
            "events",
          ],
          additionalProperties: true,
        },
        IssuerCatalogueEntry: {
          type: "object",
          required: [
            "id",
            "compliance",
            "credential_issuer",
            "credential_issuer_metadata",
            "authorization_server_metadata",
            "upstream_authorization_server",
            "name",
            "description",
            "credential_configuration_ids",
          ],
          properties: {
            id: { type: "string" },
            compliance: { type: "string" },
            credential_issuer: { type: "string", format: "uri" },
            credential_issuer_metadata: { type: "string", format: "uri" },
            authorization_server_metadata: { type: "string", format: "uri" },
            upstream_authorization_server: { type: "string", format: "uri" },
            name: { type: "string" },
            description: { type: "string" },
            warning: { type: "string" },
            credential_configuration_ids: {
              type: "array",
              items: { type: "string" },
            },
          },
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
            request_uri_method: {
              type: "string",
              default: "get",
              description:
                "HTTP method advertised for request_uri retrieval. OpenID4VP defines case-sensitive get and post; other values are preserved only for wallet negative tests.",
            },
            client_id_scheme: {
              type: "string",
              enum: [
                "x509_hash",
                "x509_san_dns",
                "redirect_uri",
                "decentralized_identifier",
                "verifier_attestation",
              ],
              default: "x509_hash",
              description:
                "Verifier client identifier prefix. redirect_uri is delivered only as a plain, unsigned Authorization Request.",
            },
            request_delivery: {
              type: "string",
              enum: ["by_reference", "by_value", "plain"],
              default: "by_reference",
              description:
                "Deliver a signed request object by reference or value, or a plain URL-encoded Authorization Request without request or request_uri. For the dc_api response modes this selects how the request reaches the browser instead: by_value produces a signed openid4vp-v1-signed request, plain an unsigned openid4vp-v1-unsigned one, by_reference is rejected, and the default becomes by_value.",
            },
            response_type: {
              type: "string",
              enum: ["vp_token", "vp_token id_token", "code"],
              default: "vp_token",
            },
            response_mode: {
              type: "string",
              enum: ["direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt"],
              default: "direct_post.jwt",
              description:
                "Selects the presentation flow. direct_post and direct_post.jwt are redirect-based and return a wallet deeplink. dc_api and dc_api.jwt travel over the W3C Digital Credentials API: the response carries dc_api_request, deeplink points at the verifier's presentation page instead of a wallet, and request_uri, response_uri, and state are absent. The .jwt modes return the Authorization Response encrypted.",
            },
            presentation_request: {
              type: "object",
              additionalProperties: true,
              description:
                "Request Object claim overrides. Only response_type, dcql_query, nonce, scopes, transaction_data, and verifier_info are honoured here; delivery, response_mode, client_id_scheme, scheme, redirect_uri, and client_metadata are top-level fields and are ignored when nested.",
            },
            dcql_query: {
              oneOf: [{ type: "object", additionalProperties: true }, { type: "null" }],
              description:
                "DCQL query, or null to omit dcql_query from the wallet-facing Authorization Request. The verifier keeps a query for verification either way, because the Authorization Response is matched against the request object this service signs; use null together with scopes for a Section 5.1 scope-based request.",
            },
            scopes: { oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
            verifier_attestation: {
              type: "object",
              additionalProperties: false,
              description:
                'Content of the Verifier Attestation JWT delivered in the request object\'s jwt JOSE header. Requires client_id_scheme: "verifier_attestation". The attestation is signed by a fixture issuer whose public key is published at /openid4vp/verifier-attestation-issuer/jwks.json, confirms the request signing key in cnf, and by default carries no redirect_uris claim.',
              properties: {
                subject: {
                  type: "string",
                  description:
                    "Attestation sub. The Client Identifier keeps the real subject, so setting this makes the two disagree.",
                },
                issuer: {
                  type: "string",
                  description: "Attestation iss, for an issuer outside a wallet's trusted list.",
                },
                redirect_uris: {
                  type: "array",
                  items: { type: "string" },
                  description: "redirect_uris claim. Omitted from the attestation when absent.",
                },
                claims: { type: "object", additionalProperties: true },
                signature: {
                  type: "string",
                  enum: ["corrupt"],
                  description:
                    "Breaks the attestation signature while leaving the request object validly signed. Gated by FCAF_SCENARIOS_ENABLED.",
                },
              },
            },
            transaction_data: {
              description:
                "Transaction data. Array entries that are JSON objects are base64url-encoded as OpenID4VP Section 5.1 requires; entries of any other type, strings included, are delivered exactly as supplied, and a value that is not an array is passed through untouched.",
            },
            verifier_info: {
              description:
                "Verifier Info array, delivered exactly as supplied. OpenID4VP Section 5.11 leaves the format and semantics to ecosystems and profiles, so this service signs no attestation of its own; bind a key-bound attestation by choosing the nonce and reading the Client Identifier from /openid4vp/client-identifiers.",
            },
            client_metadata: {
              oneOf: [{ type: "object", additionalProperties: true }, { type: "null" }],
              description:
                'Overrides individual members of the generated verifier metadata: a supplied member wins, an omitted member keeps its generated value, and a member set to null is dropped. The merge is one level deep, so supplying jwks replaces the whole key set. Use null for the whole object to omit the parameter, which is supported only with direct_post. Top-level only; a value inside presentation_request is ignored. Narrow the advertised response encryption with {"encrypted_response_enc_values_supported":["A128GCM"]} to give the Wallet a single JWE enc choice. For direct_post.jwt the merged metadata must keep the session\'s generated encryption public key, compared by RFC 7638 thumbprint so that alg, use, and kid may be altered or omitted; replacing or dropping jwks requires allow_undecryptable_response.',
            },
            allow_undecryptable_response: {
              type: "boolean",
              default: false,
              description:
                "Test-only. Publish a jwks that is not the verifier's encryption public key for direct_post.jwt, so the service cannot decrypt a response. Requires a client_metadata object. Any direct_post.jwt request sent without the verifier encryption key records a vp_undecryptable_response_allowed session event.",
            },
            redirect_uri: {
              oneOf: [
                { type: "string", format: "uri" },
                { type: "string", const: "{{base_url}}/openid4vp/redirect" },
              ],
              description:
                "Absolute URI returned to the Wallet after a successful presentation. The service appends a fresh response_code parameter. The capture template creates a service-hosted confirmation page and records valid visits.",
            },
            request_mutation: { $ref: "#/components/schemas/RequestMutation" },
            request_behavior: { $ref: "#/components/schemas/RequestBehavior" },
            response_scenario: { $ref: "#/components/schemas/ResponseScenario" },
          },
          additionalProperties: true,
        },
        RequestMutation: {
          type: "object",
          description:
            "Test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED. Deliberate edits to the wallet-facing Authorization Request, addressed by RFC 6901 JSON Pointer because protocol object keys contain dots and plus signs. The verifier keeps verifying against the request it generated: a mutation changes only the copy the Wallet receives, and both are recorded in the session capture.",
          properties: {
            outer_request: { $ref: "#/components/schemas/RequestMutationEdits" },
            request_object: { $ref: "#/components/schemas/RequestMutationEdits" },
            request_object_header: { $ref: "#/components/schemas/RequestMutationEdits" },
            verification_applies: {
              type: "boolean",
              description:
                "Recorded as evidence, never enforced: whether the caller still expects normal presentation verification to succeed.",
            },
          },
          additionalProperties: false,
        },
        RequestMutationEdits: {
          type: "object",
          description:
            "Writes are applied before removals. A member set to null is sent as null, which is a different wire outcome from removing it.",
          properties: {
            set: {
              type: "object",
              description: "JSON Pointer to the value written there, of any JSON type.",
              additionalProperties: true,
            },
            unset: {
              type: "array",
              items: { type: "string" },
              description: "JSON Pointers whose member is removed entirely.",
            },
          },
          additionalProperties: false,
        },
        RequestBehavior: {
          type: "object",
          description:
            "Test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED. Request-delivery behaviours that are not payload values, so a request_mutation pointer cannot express them.",
          properties: {
            signing_key: {
              type: "string",
              enum: ["unrelated"],
              description:
                "Sign the Request Object with a key that is not the one bound to the advertised client identifier, leaving the certificate or DID document untouched. Requires a signed request.",
            },
            certificate_chain: {
              type: "string",
              enum: ["unrelated_self_signed", "untrusted_root", "incomplete_chain"],
              description:
                "Present a different X.509 chain in x5c, generated through the same Credo X.509 path the service uses for its own material. The request stays validly signed by that chain's leaf key and the x509_hash Client Identifier is recomputed from it, so the chain is the only defect. Requires the x509_hash client identifier prefix.",
            },
            wallet_nonce: {
              type: "string",
              enum: ["echo", "mismatch", "omit"],
              default: "echo",
              description:
                "How the POST Request URI flow answers the wallet_nonce the Wallet supplied: echo it, return a different one, or omit it. The received and returned values are both recorded in the vp_request_retrieved event.",
            },
            request_uri_response: {
              type: "object",
              description:
                "Serve the Request URI with a deliberately wrong HTTP response. The signed Request Object is still generated and captured; only what the endpoint returns changes.",
              properties: {
                status: { type: "integer", minimum: 100, maximum: 599 },
                content_type: { type: "string" },
                body: { type: "string" },
              },
              additionalProperties: false,
            },
            signature: {
              type: "string",
              enum: ["corrupt"],
              description:
                "Deliver a Request Object whose signature does not verify. The request is signed normally first and the signature value is then invalidated, so the JWS stays well formed and the Wallet rejects it on the signature. Requires a signed request, so it is refused with the redirect_uri client identifier prefix.",
            },
          },
          additionalProperties: false,
        },
        ResponseScenario: {
          type: "object",
          description:
            "Test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED. Controls the HTTP response returned to the Wallet after it submits an Authorization Response. It changes only what the Wallet is told: the recorded verification result, session status, and checks are unaffected, so a test-selected 400 never marks a valid presentation invalid and a test-selected 200 never marks an invalid one verified.",
          properties: {
            status: { type: "integer", minimum: 100, maximum: 599 },
            content_type: { type: "string" },
            body: {
              type: "string",
              description: "Exact response body, replacing the normal JSON body.",
            },
            extra_parameters: {
              type: "object",
              additionalProperties: true,
              description:
                "Members merged into the normal JSON body, for an unrecognised response parameter or an error member.",
            },
          },
          additionalProperties: false,
        },
        PresentationSessionCreated: {
          type: "object",
          required: [
            "session_id",
            "request_delivery",
            "response_mode",
            "deeplink",
            "authorization_request",
            "status",
          ],
          properties: {
            session_id: { type: "string", format: "uuid" },
            request_delivery: { type: "string" },
            request_uri: {
              type: "string",
              format: "uri",
              description: "Redirect flows only; absent for the dc_api response modes.",
            },
            request_uri_method: {
              type: "string",
              description: "Redirect flows only; absent for the dc_api response modes.",
            },
            response_mode: { type: "string" },
            scheme: {
              type: "string",
              description: "Redirect flows only; absent for the dc_api response modes.",
            },
            response_uri: {
              type: "string",
              format: "uri",
              description: "Redirect flows only; absent for the dc_api response modes.",
            },
            redirect_uri: { type: "string", format: "uri" },
            deeplink: {
              type: "string",
              description:
                "Wallet invocation URL for the redirect flows. For the dc_api response modes it is the HTTPS URL of this service's presentation page at /ui/openid4vp/sessions/{sessionId}/dc_api_presentation, built from the configured public base URL. Scanning it opens a webpage, it does not invoke a wallet.",
            },
            dc_api_request: {
              $ref: "#/components/schemas/DcApiRequest",
            },
            authorization_request: { type: "object", additionalProperties: true },
            status: { type: "string", const: "created" },
          },
        },
        DcApiRequest: {
          type: "object",
          required: ["protocol", "data"],
          description:
            "Present for the dc_api response modes. Pass as one entry of navigator.credentials.get({ digital: { requests: [ ... ] } }).",
          properties: {
            protocol: {
              type: "string",
              enum: ["openid4vp-v1-signed", "openid4vp-v1-unsigned"],
            },
            data: {
              type: "object",
              additionalProperties: true,
              description:
                "For openid4vp-v1-signed a single request member holding the signed Request Object. For openid4vp-v1-unsigned the Authorization Request parameters themselves, without client_id or expected_origins.",
            },
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
          properties: {
            redirect_uri_visited_at: { type: "string", format: "date-time" },
            redirect_uri_visit_count: { type: "integer", minimum: 1 },
            raw: {
              type: "object",
              properties: {
                authorization_request_jwt: {
                  type: "string",
                  description: "Exact signed request object returned to the Wallet.",
                },
                request_uri_http: {
                  $ref: "#/components/schemas/RequestUriHttpCapture",
                },
                presentation_response_http: {
                  $ref: "#/components/schemas/PresentationResponseHttpCapture",
                },
                presentation_response_verifier_http: {
                  $ref: "#/components/schemas/VerifierResponseHttpCapture",
                },
                redirect_uri_visits: {
                  type: "array",
                  items: { $ref: "#/components/schemas/RedirectUriVisitHttpCapture" },
                },
              },
              additionalProperties: true,
            },
          },
          additionalProperties: true,
        },
        PresentationResponseHttpCapture: {
          type: "object",
          required: ["method", "headers", "body"],
          description:
            "Machine-readable wallet presentation response evidence. Sensitive header values are redacted.",
          properties: {
            method: { type: "string" },
            headers: { type: "object", additionalProperties: true },
            body: { type: "string" },
          },
        },
        RequestUriHttpCapture: {
          type: "object",
          required: ["method", "headers"],
          description:
            "Machine-readable wallet request to retrieve the request object. Sensitive header values are redacted; body is present only when received.",
          properties: {
            method: { type: "string" },
            headers: { type: "object", additionalProperties: true },
            body: { type: "string" },
          },
        },
        VerifierResponseHttpCapture: {
          type: "object",
          required: ["status", "headers", "body"],
          description:
            "Machine-readable verifier response to the Wallet. Sensitive header values are redacted.",
          properties: {
            status: { type: "integer" },
            headers: { type: "object", additionalProperties: true },
            body: { type: "string" },
          },
        },
        RedirectUriVisitHttpCapture: {
          type: "object",
          required: ["method", "headers"],
          description: "Redirect-page visit evidence. Sensitive header values are redacted.",
          properties: {
            method: { type: "string" },
            headers: { type: "object", additionalProperties: true },
          },
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
