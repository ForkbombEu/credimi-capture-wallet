import type { JsonRecord } from "../types.js";
import { errorResponses, form, json, response, sessionIdParameter } from "./common.js";

export function presentationPaths(): JsonRecord {
  return {
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
          "Used only when the session was created with `request_uri_method: post`. A wallet may supply `wallet_nonce` and `wallet_metadata`. When `wallet_metadata` carries `jwks`, the signed Request Object is returned encrypted (ECDH-ES) to the first usable key. OpenID4VP 1.0 Section 5.10 names only `jwks`; by maintainer decision `enc` and `alg` are each taken from the `request_object_encryption_*` list if present, else the `authorization_encryption_*` list, else the default (`A128GCM`, `ECDH-ES`). The list used must allow the choice, otherwise the request is answered with `400 invalid_request`. The chosen values and their sources are recorded in the session's `request_object_encryption` and the `vp_request_object_encrypted` event.",
        parameters: [sessionIdParameter],
        requestBody: {
          required: false,
          ...form({
            type: "object",
            properties: {
              wallet_nonce: { type: "string" },
              wallet_metadata: {
                type: "string",
                description:
                  "JSON object of OpenID4VP Section 10 Wallet Metadata. jwks requests Request Object encryption; request_object_encryption_alg_values_supported and request_object_encryption_enc_values_supported, or failing those authorization_encryption_alg_values_supported and authorization_encryption_enc_values_supported, constrain it.",
              },
            },
            additionalProperties: true,
          }),
        },
        responses: {
          "200": {
            description: "Signed authorization request object, encrypted when requested.",
            content: { "application/oauth-authz-req+jwt": { schema: { type: "string" } } },
          },
          "400": {
            description:
              "The Wallet requires an encrypted Request Object this verifier cannot produce.",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    error: { type: "string", enum: ["invalid_request"] },
                    error_description: { type: "string" },
                  },
                },
              },
            },
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
          "200": response(
            "Presentation was captured and verified, or a Wallet Authorization Error Response was captured and acknowledged.",
          ),
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
          "200": response(
            "Presentation was captured and verified, or a Wallet Authorization Error Response was captured and acknowledged.",
          ),
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
  };
}
