import type { AppConfig, JsonRecord } from "../types.js";
import { json, response } from "./common.js";

export function attestbookPaths(config: AppConfig): JsonRecord {
  return {
    ...(config.attestbook.enabled
      ? {
          "/integrations/attestbook/webhook": {
            post: {
              tags: ["Attestbook"],
              operationId: "attestbookWebhook",
              summary: "Receive Attestbook subscription callbacks",
              description:
                "Answers an attestbook.subscription.verification@1 challenge with the exact challenge, and accepts a signed rulebook.published notification. A notification is verified (X-AttestBook-Signature over attestbook.webhook-signing-input@1, delivery timestamp within 300 seconds, header and body event id agreement, configured rulebook), durably recorded and acknowledged before reconciliation runs against the authoritative event feed.",
              parameters: [
                "X-AttestBook-Event-Id",
                "X-AttestBook-Event-Type",
                "X-AttestBook-Timestamp",
                "X-AttestBook-Signature",
              ].map((name) => ({
                name,
                in: "header",
                required: false,
                description: "Required on a rulebook.published notification.",
                schema: { type: "string" },
              })),
              requestBody: { required: true, ...json() },
              responses: {
                "200": response(
                  "The verification challenge answer, or a duplicate notification acknowledged again.",
                ),
                "202": response("Notification recorded; reconciliation is queued."),
                "400": response("Malformed message or event.", {
                  $ref: "#/components/schemas/Error",
                }),
                "401": response("Invalid signature or stale delivery timestamp.", {
                  $ref: "#/components/schemas/Error",
                }),
                "403": response("Notification for a rulebook that is not configured.", {
                  $ref: "#/components/schemas/Error",
                }),
                "413": response("Body larger than 16 KiB."),
                "503": response(
                  "Webhook secret not configured, or the notification could not be recorded.",
                  {
                    $ref: "#/components/schemas/Error",
                  },
                ),
              },
            },
          },
          "/integrations/attestbook/sync": {
            post: {
              tags: ["Attestbook"],
              operationId: "attestbookManualSync",
              summary: "Manually reconcile the subscribed rulebook",
              description:
                "Recovery operation requiring Authorization: Bearer <ATTESTBOOK_ADMIN_TOKEN>. It reconciles the configured rulebook against the event feed, waits for the outcome and returns the integration status. Unavailable (404) when no administrator token is configured.",
              responses: {
                "200": response("Reconciled; the latest compatible publication is active.", {
                  $ref: "#/components/schemas/AttestbookIntegrationStatus",
                }),
                "401": response("Missing or wrong administrator token."),
                "404": response("Manual synchronization is not configured."),
                "502": response("Reconciliation failed; the last-known-good catalogue is kept.", {
                  $ref: "#/components/schemas/AttestbookIntegrationStatus",
                }),
              },
            },
          },
        }
      : {}),
  };
}
