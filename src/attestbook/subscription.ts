import { isRecord } from "./snapshot.js";
import { WEBHOOK_PATH } from "./webhook.js";

const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

/** The subscription as Attestbook reports it, without any secret. */
export interface SubscriptionState {
  readonly id: string;
  readonly rulebookId: string;
  readonly callbackUrl: string;
  readonly state: string;
}

/** The one-time registration result. The two secrets are returned exactly once by Attestbook. */
export interface RegisteredSubscription extends SubscriptionState {
  readonly managementToken: string;
  readonly webhookSecret: string | null;
}

export interface SubscriptionTarget {
  readonly origin: string;
  readonly rulebookId: string;
  readonly fetch?: typeof fetch;
}

/** The externally reachable callback, from the configured public origin, never a request header. */
export function webhookCallbackUrl(publicBaseUrl: string): string {
  return `${publicBaseUrl}${WEBHOOK_PATH}`;
}

/**
 * Registers the callback with Attestbook (API §3.15). It is an explicit, one-time operator step;
 * the service never registers itself at startup. The caller must store the returned
 * `managementToken` and `webhookSecret` securely: Attestbook will not return them again.
 */
export async function registerSubscription(
  target: SubscriptionTarget,
  callbackUrl: string,
): Promise<RegisteredSubscription> {
  const body = await subscriptionRequest(
    target,
    "POST",
    `/api/v1/rulebooks/${encodeURIComponent(target.rulebookId)}/subscriptions`,
    null,
    { callbackUrl },
    201,
  );
  const state = subscriptionState(body);
  const data = isRecord(body) && isRecord(body.data) ? body.data : {};
  if (typeof data.managementToken !== "string") {
    throw new Error("Attestbook did not return a management token");
  }
  return {
    ...state,
    managementToken: data.managementToken,
    webhookSecret: typeof data.webhookSecret === "string" ? data.webhookSecret : null,
  };
}

/** Asks Attestbook to send the verification challenge to the callback and activate it (§3.15.1). */
export async function verifySubscription(
  target: SubscriptionTarget,
  subscriptionId: string,
  managementToken: string,
): Promise<SubscriptionState> {
  return subscriptionState(
    await subscriptionRequest(
      target,
      "POST",
      `/api/v1/subscriptions/${encodeURIComponent(subscriptionId)}/verify`,
      managementToken,
      null,
      200,
    ),
  );
}

/** Reads the subscription's current state with its management token. */
export async function readSubscription(
  target: SubscriptionTarget,
  subscriptionId: string,
  managementToken: string,
): Promise<SubscriptionState> {
  return subscriptionState(
    await subscriptionRequest(
      target,
      "GET",
      `/api/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
      managementToken,
      null,
      200,
    ),
  );
}

async function subscriptionRequest(
  target: SubscriptionTarget,
  method: "GET" | "POST",
  path: string,
  managementToken: string | null,
  body: Record<string, unknown> | null,
  expectedStatus: number,
): Promise<unknown> {
  const response = await (target.fetch ?? fetch)(`${target.origin}${path}`, {
    method,
    redirect: "manual",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    headers: {
      accept: "application/json",
      ...(body ? { "content-type": "application/json" } : {}),
      ...(managementToken ? { authorization: `Bearer ${managementToken}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new Error("Attestbook response is too large");
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  if (response.status !== expectedStatus) {
    const error = isRecord(parsed) && isRecord(parsed.error) ? parsed.error : {};
    throw new Error(
      `Attestbook answered HTTP ${response.status}${typeof error.code === "string" ? ` ${error.code}` : ""}${
        typeof error.message === "string" ? `: ${error.message}` : ""
      }`,
    );
  }
  return parsed;
}

function subscriptionState(body: unknown): SubscriptionState {
  const data = isRecord(body) ? body.data : undefined;
  if (
    !isRecord(data) ||
    typeof data.id !== "string" ||
    typeof data.rulebookId !== "string" ||
    typeof data.callbackUrl !== "string" ||
    typeof data.state !== "string"
  ) {
    throw new Error("Attestbook returned a malformed subscription");
  }
  return {
    id: data.id,
    rulebookId: data.rulebookId,
    callbackUrl: data.callbackUrl,
    state: data.state,
  };
}
