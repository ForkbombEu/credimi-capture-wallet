import type { JsonRecord } from "../types.js";
import { errorResponses, json, response, sessionIdParameter } from "./common.js";

export function issuanceSessionPaths(): JsonRecord {
  return {
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
          "400": response(
            "Invalid input, or a test-only value refused because FCAF_SCENARIOS_ENABLED is off, such as evidence_mode_not_enabled.",
            { $ref: "#/components/schemas/Error" },
          ),
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
    "/sessions/{sessionId}/requests": {
      get: {
        tags: ["Issuance sessions"],
        operationId: "getIssuanceRequests",
        summary: "Get issuance HTTP request evidence",
        description:
          "Returns every request attributed to the session, in its evidence mode, and every unattributed ledger entry recorded from session creation to the response time. The latter includes metadata, nonce, and unmatched requests that have no session context; the consumer identifies which belong to the Wallet under test.",
        parameters: [sessionIdParameter],
        responses: {
          "200": response("Session and contemporaneous unattributed request evidence.", {
            $ref: "#/components/schemas/IssuanceSessionRequests",
          }),
          "404": errorResponses["404"],
        },
      },
    },
    "/sessions/{sessionId}/status": {
      post: {
        tags: ["Issuance sessions"],
        operationId: "updateIssuedCredentialStatus",
        summary: "Revoke the session's issued credentials",
        description:
          "Test-only, refused with status_update_not_enabled unless the deployment sets FCAF_SCENARIOS_ENABLED. Calls the configured Status List service's POST /token_status_list/set (form uri, idx, status=1, X-Api-Key) for every reference allocated to the session, recorded in status_list_references. It is separate from issuance so that a test can revoke after the Wallet has stored the credential. Each call is appended to status_list_updates and logged as a status_list_status_updated event. The Status List service serves its tokens with Cache-Control max-age (43200 seconds in ForkbombEu/capture-status-list) and an ETag, so a Wallet or Verifier holding a cached list sees the revocation only after that max-age elapses or it revalidates.",
        parameters: [sessionIdParameter],
        requestBody: {
          required: true,
          ...json({
            type: "object",
            required: ["status"],
            properties: { status: { type: "string", enum: ["revoked"] } },
          }),
        },
        responses: {
          "200": response("Every allocated reference was revoked.", {
            $ref: "#/components/schemas/StatusListUpdate",
          }),
          "400": response(
            "status_update_not_enabled, unsupported_status, or status_list_not_enabled for a session issued without a status list.",
            { $ref: "#/components/schemas/Error" },
          ),
          "404": errorResponses["404"],
          "409": response(
            "status_list_references_not_allocated: no credential has been issued yet.",
            { $ref: "#/components/schemas/Error" },
          ),
          "502": response(
            "status_list_update_failed: the Status List service refused or did not answer at least one reference. The body also carries every per-reference result.",
            { $ref: "#/components/schemas/StatusListUpdate" },
          ),
        },
      },
    },
  };
}
