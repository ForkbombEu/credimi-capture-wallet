import { createHash, createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { attestbookIntegration } from "../src/attestbook/integration.js";
import { attestbookStatePath } from "../src/attestbook/persistence.js";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { initIssuer } from "../src/config/key-material.js";
import { credoOpenId4VciIssuer } from "../src/openid4vci/credo-issuer.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { AppConfig, JsonRecord } from "../src/types.js";
import { AttestbookFixture, type FixtureEvent, signedDelivery } from "./attestbook-fixture.js";

const webhookSecret = "atw_webhook-test-secret-0000000000000000";
const issuerBaseUrl = "http://issuer.example.test";
const fixture = new AttestbookFixture();
const dataDirs: string[] = [];

interface Harness {
  app: Express;
  store: CaptureStore;
  dataDir: string;
  config: AppConfig;
  logs: { event: string; fields: JsonRecord }[];
}

let config: AppConfig;

async function createHarness(options: { secret?: string | null } = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), "attestbook-webhook-"));
  dataDirs.push(dataDir);
  await initIssuer({ issuer_base_url: issuerBaseUrl, data_dir: dataDir, force: true });
  const localConfig: AppConfig = {
    ...config,
    data_dir: dataDir,
    attestbook: {
      ...config.attestbook,
      webhook_secret: options.secret === undefined ? webhookSecret : options.secret,
    },
  };
  const store = new CaptureStore(localConfig);
  const logs: Harness["logs"] = [];
  attestbookIntegration(localConfig, store, {
    logger: (event, fields) => logs.push({ event, fields }),
  });
  const app = createApp(localConfig, store);
  await credoOpenId4VciIssuer(localConfig, store);
  await attestbookIntegration(localConfig, store).idle();
  logs.length = 0;
  return { app, store, config: localConfig, logs, dataDir } satisfies Harness;
}

function rawDelivery(
  secret: string,
  body: Buffer,
  eventId: string,
  timestamp = new Date().toISOString(),
  eventType = "rulebook.published",
): { body: Buffer; headers: Record<string, string> } {
  const input = [
    "attestbook.webhook-signing-input@1",
    timestamp,
    eventId,
    createHash("sha256").update(body).digest("hex"),
  ].join("\n");
  return {
    body,
    headers: {
      "content-type": "application/json",
      "x-attestbook-event-id": eventId,
      "x-attestbook-event-type": eventType,
      "x-attestbook-timestamp": timestamp,
      "x-attestbook-signature": `v1=${createHmac("sha256", secret).update(input).digest("hex")}`,
    },
  };
}

async function postDelivery(
  harness: Harness,
  delivery: { body: Buffer; headers: Record<string, string> },
) {
  return request(harness.app)
    .post("/integrations/attestbook/webhook")
    .set(delivery.headers)
    .send(delivery.body.toString("utf8"));
}

function eventFor(version: string): FixtureEvent {
  return fixture.publish(version, [
    {
      name: "Webhook Membership",
      schema: {
        type: "object",
        properties: { member_id: { type: "string" } },
      },
      typeMetadata: { vct: `urn:attestbook:webhook:${version}`, display: [], claims: [] },
    },
  ]);
}

beforeAll(async () => {
  await fixture.start();
  const dataDir = mkdtempSync(join(tmpdir(), "attestbook-webhook-base-"));
  dataDirs.push(dataDir);
  config = {
    ...DEFAULT_CONFIG,
    issuer_base_url: issuerBaseUrl,
    public_base_url: issuerBaseUrl,
    data_dir: dataDir,
    attestbook: {
      enabled: true,
      base_url: fixture.origin,
      rulebook_id: fixture.rulebookId,
      webhook_secret: webhookSecret,
      admin_token: "admin-token",
      allowed_schema_origins: [],
    },
  };
});

afterAll(async () => {
  await fixture.stop();
  for (const dataDir of dataDirs) rmSync(dataDir, { recursive: true, force: true });
});

describe("Attestbook webhook HTTP contract", () => {
  it.each([
    ["not JSON", Buffer.from("not-json"), "body is not JSON"],
    ["a JSON scalar", Buffer.from("null"), "body is not a JSON object"],
  ])("rejects %s", async (_name, body, message) => {
    const harness = await createHarness();
    const response = await request(harness.app)
      .post("/integrations/attestbook/webhook")
      .set("content-type", "text/plain")
      .send(body);
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request", error_description: message });
  });

  it("rejects missing signature headers and malformed event bodies", async () => {
    const harness = await createHarness();
    const event = eventFor("missing-headers");
    const signed = signedDelivery(webhookSecret, event);
    const missingHeaders = {
      ...signed,
      headers: Object.fromEntries(
        Object.entries(signed.headers).filter(([name]) => name !== "x-attestbook-signature"),
      ),
    };
    const missing = await postDelivery(harness, missingHeaders);
    expect(missing.status).toBe(400);
    expect(missing.body).toEqual({
      error: "invalid_request",
      error_description: "signature headers are missing",
    });

    const missingTimestampHeaders = {
      ...signed,
      headers: Object.fromEntries(
        Object.entries(signed.headers).filter(([name]) => name !== "x-attestbook-timestamp"),
      ),
    };
    const missingTimestamp = await postDelivery(harness, missingTimestampHeaders);
    expect(missingTimestamp.status).toBe(400);
    expect(missingTimestamp.body).toEqual({
      error: "invalid_request",
      error_description: "signature headers are missing",
    });
    const missingEventIdHeaders = {
      ...signed,
      headers: Object.fromEntries(
        Object.entries(signed.headers).filter(([name]) => name !== "x-attestbook-event-id"),
      ),
    };
    const missingEventId = await postDelivery(harness, missingEventIdHeaders);
    expect(missingEventId.status).toBe(400);
    expect(missingEventId.body).toEqual({
      error: "invalid_request",
      error_description: "signature headers are missing",
    });

    const invalid = rawDelivery(
      webhookSecret,
      Buffer.from('{"type":"rulebook.published"}'),
      "event-invalid",
    );
    const invalidResponse = await postDelivery(harness, invalid);
    expect(invalidResponse.status).toBe(400);
    expect(invalidResponse.body).toEqual({
      error: "invalid_event",
      error_description: "the body is not a rulebook publication event",
    });
  });

  it("rejects unsupported types, absent secrets, invalid signatures and stale timestamps", async () => {
    const harness = await createHarness();
    const event = eventFor("rejections");
    const unsupported = rawDelivery(
      webhookSecret,
      Buffer.from(JSON.stringify(event)),
      event.id,
      new Date().toISOString(),
      "rulebook.deleted",
    );
    const unsupportedResponse = await postDelivery(harness, unsupported);
    expect(unsupportedResponse.status).toBe(400);
    expect(unsupportedResponse.body).toEqual({
      error: "unsupported_event_type",
      error_description: "only rulebook.published notifications are accepted",
    });

    const noSecret = await createHarness({ secret: null });
    const noSecretDelivery = signedDelivery(webhookSecret, event);
    const noSecretMissingHeaders = {
      ...noSecretDelivery,
      headers: Object.fromEntries(
        Object.entries(noSecretDelivery.headers).filter(
          ([name]) => name !== "x-attestbook-signature",
        ),
      ),
    };
    const noSecretResponse = await postDelivery(noSecret, noSecretMissingHeaders);
    expect(noSecretResponse.status).toBe(503);
    expect(noSecretResponse.body).toEqual({
      error: "webhook_secret_not_configured",
      error_description: "the subscription webhook secret is not configured",
    });
    expect(noSecret.logs).toEqual([
      { event: "notification_refused", fields: { reason: "webhook_secret_not_configured" } },
    ]);
    expect(JSON.stringify({ body: noSecretResponse.body, logs: noSecret.logs })).not.toContain(
      webhookSecret,
    );

    const invalidSignature = signedDelivery("wrong-secret", event);
    const invalidSignatureResponse = await postDelivery(harness, invalidSignature);
    expect(invalidSignatureResponse.status).toBe(401);
    expect(invalidSignatureResponse.body).toEqual({
      error: "invalid_signature",
      error_description: "the notification signature is not valid",
    });
    expect(harness.logs).toEqual([
      { event: "notification_rejected", fields: { reason: "invalid_signature" } },
    ]);
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);

    const staleWrongSecret = signedDelivery("wrong-secret", event, "2020-01-01T00:00:00.000Z");
    const staleWrongSecretResponse = await postDelivery(harness, staleWrongSecret);
    expect(staleWrongSecretResponse.status).toBe(401);
    expect(staleWrongSecretResponse.body).toEqual({
      error: "invalid_signature",
      error_description: "the notification signature is not valid",
    });

    const stale = signedDelivery(webhookSecret, event, "2020-01-01T00:00:00.000Z");
    const staleResponse = await postDelivery(harness, stale);
    expect(staleResponse.status).toBe(401);
    expect(staleResponse.body).toEqual({
      error: "stale_timestamp",
      error_description: "the delivery timestamp is outside the accepted window",
    });
    expect(harness.logs).toEqual([
      { event: "notification_rejected", fields: { reason: "invalid_signature" } },
      { event: "notification_rejected", fields: { reason: "invalid_signature" } },
      { event: "notification_rejected", fields: { reason: "stale_timestamp" } },
    ]);
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
  });

  it("rejects event-id and rulebook mismatches", async () => {
    const harness = await createHarness();
    const event = eventFor("mismatch");
    const mismatch = rawDelivery(
      webhookSecret,
      Buffer.from(JSON.stringify(event)),
      "header-event-id",
    );
    const mismatchResponse = await postDelivery(harness, mismatch);
    expect(mismatchResponse.status).toBe(400);
    expect(mismatchResponse.body).toEqual({
      error: "event_id_mismatch",
      error_description: "the event id header and body disagree",
    });

    const otherRulebook = { ...event, id: "other-rulebook-event", rulebookId: "other-rulebook" };
    const rulebookResponse = await postDelivery(
      harness,
      signedDelivery(webhookSecret, otherRulebook),
    );
    expect(rulebookResponse.status).toBe(403);
    expect(rulebookResponse.body).toEqual({
      error: "rulebook_not_subscribed",
      error_description: "the notification is for a rulebook that is not configured",
    });
    expect(harness.logs).toEqual([
      {
        event: "notification_rejected",
        fields: { reason: "rulebook_not_subscribed", event_id: otherRulebook.id },
      },
    ]);
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
  });

  it("answers a verification challenge without requiring signature headers", async () => {
    const harness = await createHarness();
    const challenge = {
      type: "attestbook.subscription.verification@1",
      challenge: "atv_webhook_challenge",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const response = await request(harness.app)
      .post("/integrations/attestbook/webhook")
      .set("content-type", "application/json")
      .send(JSON.stringify(challenge));
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ challenge: challenge.challenge });
    const invalid = await request(harness.app)
      .post("/integrations/attestbook/webhook")
      .set("content-type", "application/json")
      .send(JSON.stringify({}));
    expect(invalid.status).toBe(400);
    expect(invalid.body).toEqual({
      error: "invalid_request",
      error_description: "not a valid verification challenge",
    });
  });

  it("returns notification_not_recorded when durable persistence fails", async () => {
    const harness = await createHarness();
    rmSync(attestbookStatePath(harness.dataDir));
    mkdirSync(attestbookStatePath(harness.dataDir), { recursive: true });
    const event = eventFor("persistence-failure");
    const response = await postDelivery(harness, signedDelivery(webhookSecret, event));
    expect(response.status).toBe(503);
    expect(response.body).toEqual({
      error: "notification_not_recorded",
      error_description: "the notification could not be recorded durably",
    });
    expect(harness.logs).toEqual([
      { event: "notification_not_recorded", fields: { event_id: event.id } },
    ]);
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
  });

  it("acknowledges an accepted notification once and then reports a duplicate", async () => {
    const harness = await createHarness();
    const event = eventFor("accepted");
    const delivery = signedDelivery(webhookSecret, event);
    const accepted = await postDelivery(harness, delivery);
    expect(accepted.status).toBe(202);
    expect(accepted.body).toEqual({ status: "accepted", event_id: event.id });
    await attestbookIntegration(harness.config, harness.store).idle();
    harness.logs.length = 0;

    const duplicate = await postDelivery(harness, delivery);
    expect(duplicate.status).toBe(200);
    expect(duplicate.body).toEqual({ status: "duplicate", event_id: event.id });
    expect(harness.logs).toEqual([
      { event: "notification_duplicate", fields: { event_id: event.id } },
    ]);

    const observed = JSON.stringify({
      response: accepted.body,
      duplicate: duplicate.body,
      logs: harness.logs,
    });
    expect(observed).not.toContain(webhookSecret);
  });
});
