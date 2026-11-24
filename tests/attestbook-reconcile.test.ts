import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { attestbookIntegration } from "../src/attestbook/integration.js";
import { attestbookStatePath } from "../src/attestbook/persistence.js";
import { DEFAULT_CONFIG, initIssuer } from "../src/config.js";
import { credentialRegistry } from "../src/credential-registry.js";
import { credoOpenId4VciIssuer } from "../src/credo-openid4vci.js";
import { createApp } from "../src/server.js";
import { CaptureStore } from "../src/state.js";
import type { AppConfig, JsonRecord } from "../src/types.js";
import { AttestbookFixture, type FixtureEvent, signedDelivery } from "./attestbook-fixture.js";
const fixture = new AttestbookFixture();
const issuerBaseUrl = "http://issuer.example.test";
const webhookSecret = "atw_reconcile-test-secret-0000000000000000";
const dataDirs: string[] = [];
let baseConfig: AppConfig;

interface Harness {
  config: AppConfig;
  store: CaptureStore;
  dataDir: string;
  logs: { event: string; fields: JsonRecord }[];
}

async function createHarness(options: { fetch?: typeof fetch } = {}): Promise<Harness> {
  const dataDir = mkdtempSync(join(tmpdir(), "attestbook-reconcile-"));
  dataDirs.push(dataDir);
  await initIssuer({ issuer_base_url: issuerBaseUrl, data_dir: dataDir, force: true });
  const config: AppConfig = { ...baseConfig, data_dir: dataDir };
  const store = new CaptureStore(config);
  const logs: Harness["logs"] = [];
  attestbookIntegration(config, store, {
    fetch: options.fetch,
    logger: (event, fields) => logs.push({ event, fields }),
  });
  await credoOpenId4VciIssuer(config, store);
  await attestbookIntegration(config, store).idle();
  logs.length = 0;
  return { config, store, logs, dataDir };
}

function membership(version: string, vct = `urn:attestbook:reconcile-${version}`) {
  return {
    name: `Reconcile ${version}`,
    schema: {
      type: "object",
      required: ["member_id"],
      properties: { member_id: { type: "string", minLength: 3 } },
    },
    typeMetadata: {
      vct,
      display: [{ locale: "en-US", name: `Reconcile ${version}` }],
      claims: [{ path: ["member_id"], sd: "always" }],
    },
  };
}

function eventWithMembership(version: string, vct?: string): FixtureEvent {
  return fixture.publish(version, [membership(version, vct)]);
}

beforeAll(async () => {
  await fixture.start();
  const dataDir = mkdtempSync(join(tmpdir(), "attestbook-reconcile-base-"));
  dataDirs.push(dataDir);
  baseConfig = {
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
  vi.useRealTimers();
  await fixture.stop();
  for (const dataDir of dataDirs) rmSync(dataDir, { recursive: true, force: true });
});
afterEach(() => {
  vi.useRealTimers();
});

async function status(harness: Harness): Promise<JsonRecord> {
  return attestbookIntegration(harness.config, harness.store).status();
}

describe("Attestbook reconciliation failures", () => {
  it("records activation_rolled_back with the activate stage when registry activation fails", async () => {
    const harness = await createHarness();
    let synchronizerCalls = 0;
    credentialRegistry(harness.config, harness.store).attachIssuerSynchronizer(async () => {
      synchronizerCalls += 1;
      if (synchronizerCalls === 1) throw new Error("injected activation failure");
    });
    const event = eventWithMembership("activation-failure");
    await expect(
      attestbookIntegration(harness.config, harness.store).reconcile("manual"),
    ).rejects.toThrow("injected activation failure");
    const integrationStatus = await status(harness);
    expect(integrationStatus.sync).toEqual({
      state: "failed",
      last_trigger: "manual",
      failure: {
        stage: "activate",
        code: "activation_failed",
        message: "injected activation failure",
        at: expect.any(String),
        version: event.version,
        content_digest: event.contentDigest,
      },
      diagnostics: [],
    });
    expect(integrationStatus.active).toBeNull();
    expect(harness.logs.at(-1)?.event).toBe("activation_rolled_back");
    expect(JSON.stringify(integrationStatus)).not.toContain(webhookSecret);
    expect(JSON.stringify(integrationStatus)).not.toContain("admin-token");
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
    expect(JSON.stringify(harness.logs)).not.toContain("admin-token");
  });

  it("records persistence failure after activation", async () => {
    const harness = await createHarness();
    rmSync(attestbookStatePath(harness.dataDir));
    mkdirSync(attestbookStatePath(harness.dataDir), { recursive: true });
    const event = eventWithMembership("persistence-failure");
    await expect(
      attestbookIntegration(harness.config, harness.store).reconcile("manual"),
    ).rejects.toThrow();
    const integrationStatus = await status(harness);
    expect(integrationStatus.sync).toEqual({
      state: "failed",
      last_trigger: "manual",
      failure: {
        stage: "persist",
        code: "persist_failed",
        message: expect.stringMatching(/^EISDIR: illegal operation on a directory/),
        at: expect.any(String),
        version: event.version,
        content_digest: event.contentDigest,
      },
      diagnostics: [],
    });
    expect(JSON.stringify(integrationStatus)).not.toContain(webhookSecret);
    expect(JSON.stringify(integrationStatus)).not.toContain("admin-token");
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
    expect(JSON.stringify(harness.logs)).not.toContain("admin-token");
  });

  it("skips a rejected digest for automatic triggers but retries it manually", async () => {
    const event = fixture.publish("rejected-digest", [
      {
        name: "Rejected schema",
        schema: { type: "object", properties: { broken: { type: "null" } } },
        typeMetadata: {
          vct: "urn:attestbook:rejected-schema",
          display: [{ locale: "en-US", name: "Rejected schema" }],
          claims: [],
        },
      },
    ]);
    const schemaUri = fixture.documentPaths().at(-2);
    if (!schemaUri) throw new Error("fixture did not host the rejected schema");
    const schemaUrl = `${fixture.origin}${schemaUri}`;
    const harness = await createHarness();
    await attestbookIntegration(harness.config, harness.store).reconcile("webhook");
    const automatic = await status(harness);
    expect(automatic.sync).toEqual({
      state: "failed",
      last_trigger: "webhook",
      failure: {
        stage: "compile",
        code: "credential_unsupported",
        message: "rulebook rejected-digest has no issuable SD-JWT VC credential definition",
        at: expect.any(String),
        version: event.version,
        content_digest: event.contentDigest,
      },
      diagnostics: [
        {
          severity: "error",
          code: "unsupported_claim_type",
          attestation: "Rejected schema",
          field: `${schemaUrl}#/properties/broken/type`,
          message: "claim 'broken' must declare one type",
        },
      ],
    });
    expect(automatic.pending_notifications).toBe(0);
    await expect(
      attestbookIntegration(harness.config, harness.store).reconcile("manual"),
    ).rejects.toThrow();
    const manual = await status(harness);
    expect(manual.sync).toEqual({
      state: "failed",
      last_trigger: "manual",
      failure: {
        stage: "compile",
        code: "credential_unsupported",
        message: "rulebook rejected-digest has no issuable SD-JWT VC credential definition",
        at: expect.any(String),
        version: event.version,
        content_digest: event.contentDigest,
      },
      diagnostics: [
        {
          severity: "error",
          code: "unsupported_claim_type",
          attestation: "Rejected schema",
          field: `${schemaUrl}#/properties/broken/type`,
          message: "claim 'broken' must declare one type",
        },
      ],
    });
    expect(JSON.stringify({ automatic, manual })).not.toContain(webhookSecret);
    expect(JSON.stringify({ automatic, manual })).not.toContain("admin-token");
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
    expect(JSON.stringify(harness.logs)).not.toContain("admin-token");
  });

  it("caps automatic retry scheduling at eight attempts", async () => {
    eventWithMembership("retry-seed");
    vi.useFakeTimers();
    let failEvents = false;
    const fetcher: typeof fetch = async (input, init) => {
      if (failEvents && new URL(input.toString()).pathname.endsWith("/events")) {
        return new Response(JSON.stringify({ malformed: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return fetch(input, init);
    };
    const harness = await createHarness({ fetch: fetcher });
    const event = eventWithMembership("retry-cap");
    failEvents = true;
    const app = createApp(harness.config, harness.store);
    const delivery = signedDelivery(webhookSecret, event);
    const accepted = await request(app)
      .post("/integrations/attestbook/webhook")
      .set(delivery.headers)
      .send(delivery.body.toString("utf8"));
    expect(accepted.status).toBe(202);
    const integration = attestbookIntegration(harness.config, harness.store);
    await integration.idle();

    for (let attempt = 0; attempt < 8; attempt += 1) {
      await vi.advanceTimersByTimeAsync(Math.min(5_000 * 2 ** attempt, 5 * 60_000));
      await integration.idle();
    }
    expect(
      harness.logs
        .filter(({ event: name }) => name === "sync_retry_scheduled")
        .map(({ fields }) => fields.delay_ms),
    ).toEqual([5000, 10000, 20000, 40000, 80000, 160000, 300000, 300000]);
    const beforeCap = await status(harness);
    expect(beforeCap.sync).toEqual({
      state: "failed",
      last_trigger: "retry",
      failure: {
        stage: "fetch",
        code: "contract_violation",
        message: "event feed page is malformed",
        at: expect.any(String),
        version: null,
        content_digest: null,
      },
      diagnostics: [],
    });
    expect(beforeCap.pending_notifications).toBe(1);
    expect(JSON.stringify(beforeCap)).not.toContain(webhookSecret);
    expect(JSON.stringify(beforeCap)).not.toContain("admin-token");
    expect(JSON.stringify(harness.logs)).not.toContain(webhookSecret);
    expect(JSON.stringify(harness.logs)).not.toContain("admin-token");
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(harness.logs.filter(({ event: name }) => name === "sync_retry_scheduled")).toHaveLength(
      8,
    );
    const afterCap = await status(harness);
    expect(afterCap.sync).toEqual({
      state: "failed",
      last_trigger: "retry",
      failure: {
        stage: "fetch",
        code: "contract_violation",
        message: "event feed page is malformed",
        at: expect.any(String),
        version: null,
        content_digest: null,
      },
      diagnostics: [],
    });
  });
});
