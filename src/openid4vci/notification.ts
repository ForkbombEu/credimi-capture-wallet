import { type AgentContext, injectable } from "@credo-ts/core";
import type {
  OpenId4VcIssuanceSessionRecord,
  OpenId4VciCreateCredentialResponseOptions,
} from "@credo-ts/openid4vc";
import type { CredentialResponse, NotificationEvent } from "@openid4vc/openid4vci";
import { isRecord } from "../shared/json.js";
import type { CredentialNotificationEvent } from "../types.js";
import { EudiKeyAttestationIssuerService } from "./key-attestation.js";

/** OpenID4VCI 1.0 Section 11.1: the exact, case-sensitive `event` values. */
const NOTIFICATION_EVENTS = [
  "credential_accepted",
  "credential_failure",
  "credential_deleted",
] as const satisfies readonly (NotificationEvent & CredentialNotificationEvent)[];

/** OpenID4VCI 1.0 Section 11.1: `event_description` is limited to `%x20-21 / %x23-5B / %x5D-7E`. */
const EVENT_DESCRIPTION = /^[\x20-\x21\x23-\x5B\x5D-\x7E]*$/;

export interface NotificationRequest {
  notification_id: string;
  event: CredentialNotificationEvent;
  event_description?: string;
}

/**
 * The recognized parameters of a Notification Request body (OpenID4VCI 1.0 Section 11.1), or null
 * when it is malformed: not a JSON object, `notification_id` missing or not a non-empty string,
 * `event` not one of the three values, or `event_description` outside the allowed characters.
 * Unrecognized parameters are ignored, as the specification requires.
 */
export function parseNotificationRequest(body: unknown): NotificationRequest | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const { notification_id, event, event_description } = body as Record<string, unknown>;
  if (typeof notification_id !== "string" || notification_id.length === 0) return null;
  const knownEvent = NOTIFICATION_EVENTS.find((candidate) => candidate === event);
  if (!knownEvent) return null;
  if (event_description === undefined) return { notification_id, event: knownEvent };
  if (typeof event_description !== "string" || !EVENT_DESCRIPTION.test(event_description)) {
    return null;
  }
  return { notification_id, event: knownEvent, event_description };
}

/**
 * The RFC 6750 Section 3 challenge of an access token or DPoP proof Credo-TS's resource server
 * refused, or null for any other error. The pinned `@openid4vc/oauth2` error class is not a
 * dependency of this package, so the error is recognized by the challenges it carries. They are
 * encoded here rather than with the error's own encoder, which keeps line breaks of Credo's error
 * descriptions that no HTTP header may contain: every value is limited to the characters RFC 6750
 * Section 3 allows in `error_description`.
 */
export function wwwAuthenticateChallenge(error: unknown): string | null {
  if (!(error instanceof Error) || !("wwwAuthenticateHeaders" in error)) return null;
  const challenges = error.wwwAuthenticateHeaders;
  if (!Array.isArray(challenges)) return null;
  const encoded = challenges.flatMap((challenge: unknown) => {
    if (!isRecord(challenge) || typeof challenge.scheme !== "string") return [];
    const parameters = (["error", "error_description", "scope"] as const).flatMap((name) => {
      const value = challenge[name];
      if (typeof value !== "string") return [];
      return [`${name}="${value.replace(/[^\x20\x21\x23-\x5B\x5D-\x7E]/g, " ")}"`];
    });
    return [
      parameters.length > 0 ? `${challenge.scheme} ${parameters.join(", ")}` : challenge.scheme,
    ];
  });
  return encoded.length > 0 ? encoded.join(", ") : null;
}

/**
 * Decides the `notification_id` of one successful immediate Credential Response, or returns
 * undefined to send none.
 */
export type CredentialResponseNotifier = (
  issuanceSession: OpenId4VcIssuanceSessionRecord,
  credentialCount: number,
) => string | undefined;

/**
 * Credo-TS's OpenID4VCI issuer service with the `notification_id` of OpenID4VCI 1.0 Section 8.3,
 * which the pinned Credo-TS does not set itself. The id is added to the Credential Response object
 * Credo built, before Credo serializes it, so the response encryption and FCAF scenario
 * interceptors downstream see it as part of the generated response. It is only set when the
 * response carries `credentials`, never with `transaction_id`.
 */
@injectable()
export class NotifyingIssuerService extends EudiKeyAttestationIssuerService {
  notifier: CredentialResponseNotifier | undefined;

  public override async createCredentialResponse(
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialResponseOptions & {
      issuanceSession: OpenId4VcIssuanceSessionRecord;
    },
  ): Promise<{
    issuanceSession: OpenId4VcIssuanceSessionRecord;
    credentialResponse: CredentialResponse;
  }> {
    const result = await super.createCredentialResponse(agentContext, options);
    const { credentialResponse } = result;
    const credentialCount = credentialResponse.credentials?.length ?? 0;
    if (credentialCount > 0 && credentialResponse.transaction_id === undefined) {
      const notificationId = this.notifier?.(result.issuanceSession, credentialCount);
      if (notificationId) credentialResponse.notification_id = notificationId;
    }
    return result;
  }
}
