import { createHmac, timingSafeEqual } from "node:crypto";
import { sha256Hex } from "./digest.js";

export const WEBHOOK_PATH = "/integrations/attestbook/webhook";
export const WEBHOOK_MAX_BODY_BYTES = 16 * 1024;
const VERIFICATION_MESSAGE_TYPE = "attestbook.subscription.verification@1";
export const PUBLICATION_EVENT_TYPE = "rulebook.published";
/** Accepted distance between `X-AttestBook-Timestamp` and the receiver's clock. */
const WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS = 300;

const SIGNING_CONTEXT = "attestbook.webhook-signing-input@1";
const SIGNATURE = /^v1=([0-9a-f]{64})$/;

export interface SignedDelivery {
  readonly secret: string;
  readonly timestamp: string;
  readonly eventId: string;
  readonly body: Uint8Array;
  /** The whole `X-AttestBook-Signature` header value. */
  readonly signature: string;
}

/**
 * Attestbook's documented canonical signing input (API §3.15.2): four LF-separated lines, no
 * trailing newline, committing to the delivery timestamp, the event id and the exact body bytes.
 */
function webhookSigningInput(timestamp: string, eventId: string, body: Uint8Array): string {
  if (/[\r\n]/.test(timestamp) || /[\r\n]/.test(eventId)) {
    throw new Error("webhook timestamp and event id must be single-line values");
  }
  return [SIGNING_CONTEXT, timestamp, eventId, sha256Hex(body)].join("\n");
}

/** `v1=` followed by the lowercase hex HMAC-SHA-256 of the signing input. */
export function webhookSignature(
  secret: string,
  timestamp: string,
  eventId: string,
  body: Uint8Array,
): string {
  const mac = createHmac("sha256", secret).update(
    webhookSigningInput(timestamp, eventId, body),
    "utf8",
  );
  return `v1=${mac.digest("hex")}`;
}

/** Constant-time check of a delivered signature; a malformed header or input is simply invalid. */
export function webhookSignatureValid(delivery: SignedDelivery): boolean {
  const presented = SIGNATURE.exec(delivery.signature)?.[1];
  if (!presented) return false;
  let expected: string;
  try {
    expected = webhookSignature(
      delivery.secret,
      delivery.timestamp,
      delivery.eventId,
      delivery.body,
    ).slice(3);
  } catch {
    return false;
  }
  return timingSafeEqual(Buffer.from(presented, "utf8"), Buffer.from(expected, "utf8"));
}

/** Whether a delivery timestamp is an ISO 8601 instant within the tolerance window. */
export function webhookTimestampFresh(timestamp: string, now: number): boolean {
  const at = Date.parse(timestamp);
  return (
    /^\d{4}-\d{2}-\d{2}T/.test(timestamp) &&
    Number.isFinite(at) &&
    Math.abs(now - at) <= WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS * 1000
  );
}

/** The challenge of a well-formed, unexpired callback verification message, or null. */
export function verificationChallengeOrNull(
  body: Record<string, unknown>,
  now: number,
): string | null {
  const { type, challenge, expiresAt } = body;
  if (
    type !== VERIFICATION_MESSAGE_TYPE ||
    typeof challenge !== "string" ||
    !/^atv_[A-Za-z0-9_-]{16,256}$/.test(challenge) ||
    typeof expiresAt !== "string" ||
    !(Date.parse(expiresAt) > now)
  ) {
    return null;
  }
  return challenge;
}
