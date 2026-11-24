import request from "supertest";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import { AttestbookFixture, signedDelivery } from "./attestbook-fixture.js";
import { createIssuerTestEnvironment } from "./support/environment.js";

const issuerId = "eu-pid-device-bound";

async function harness(config: Parameters<typeof createApp>[0] = DEFAULT_CONFIG) {
  const { data_dir: _dataDir, ...options } = config;
  const environment = await createIssuerTestEnvironment({
    prefix: "server-routing-",
    config: { ...options, issuer_base_url: "http://issuer.example.test" },
  });
  const store = new CaptureStore(environment.config);
  return { environment, store, app: createApp(environment.config, store) };
}

describe("server composition routing", () => {
  it("returns parser error shapes and captures malformed protocol bodies", async () => {
    const { environment, app, store } = await harness();
    try {
      for (const contentType of [
        "application/json",
        "application/x-www-form-urlencoded",
        "application/jwt",
      ]) {
        const response = await request(app)
          .post(`/issuers/${issuerId}/par`)
          .set("content-type", `${contentType}; charset=bogus`)
          .send(contentType === "application/json" ? '{"broken":' : "broken");
        expect(response.status).toBe(500);
        expect(response.body).toMatchObject({ error: "internal_error" });
        expect(response.body.message).toEqual(expect.any(String));
        expect(store.oid4vciRequests.at(-1)).toMatchObject({
          path: `/issuers/${issuerId}/par`,
        });
      }
    } finally {
      environment.cleanup();
    }
  });

  it("captures unmatched OPTIONS requests and attributes issuer and session paths", async () => {
    const { environment, app, store } = await harness();
    try {
      const issuerOptions = await request(app).options(`/issuers/${issuerId}/credential`);
      expect(issuerOptions.status).toBe(200);
      expect(store.oid4vciRequests.at(-1)).toMatchObject({
        path: `/issuers/${issuerId}/credential`,
        issuer_configuration_id: issuerId,
        unmatched: true,
      });
      const session = await request(app)
        .post("/sessions")
        .send({ issuer_configuration_id: issuerId });
      expect(session.status).toBe(201);
      const sessionOptions = await request(app).options(
        `/sessions/${session.body.session_id}/offer`,
      );
      expect(sessionOptions.status).toBe(200);
      expect(store.oid4vciRequests.at(-1)).toMatchObject({
        path: `/sessions/${session.body.session_id}/offer`,
        session_id: session.body.session_id,
        unmatched: true,
      });
      const nonProtocolOptions = await request(app).options("/healthz");
      expect(nonProtocolOptions.status).toBe(200);
      expect(nonProtocolOptions.headers.allow).toEqual(expect.any(String));
      expect(store.oid4vciRequests.at(-1)).toMatchObject({
        path: "/healthz",
        unmatched: true,
      });
    } finally {
      environment.cleanup();
    }
  });

  it("captures unmatched protocol requests before returning 404", async () => {
    const { environment, app, store } = await harness();
    try {
      const response = await request(app).get(`/issuers/${issuerId}/not-a-route`);
      expect(response.status).toBe(404);
      expect(store.oid4vciRequests.at(-1)).toMatchObject({
        path: `/issuers/${issuerId}/not-a-route`,
        unmatched: true,
      });
    } finally {
      environment.cleanup();
    }
  });

  it("falls through the issuer UI route when GUI is disabled or the issuer is unknown", async () => {
    const { environment, app, store } = await harness();
    try {
      const unknownHtml = await request(app).get("/issuers/not-known").set("accept", "text/html");
      expect(unknownHtml.text).toContain("Cannot GET /issuers/not-known");
      expect(store.oid4vciRequests.at(-1)).toMatchObject({
        path: "/issuers/not-known",
        unmatched: true,
      });
      expect(unknownHtml.status).toBe(404);
      expect(unknownHtml.body).toEqual({});
      const unknownJson = await request(app)
        .get("/issuers/not-known")
        .set("accept", "application/json");
      expect(unknownJson.status).toBe(404);
      expect(unknownJson.body).toEqual({});
      expect(store.oid4vciRequests.at(-1)).toMatchObject({
        path: "/issuers/not-known",
        unmatched: true,
      });

      const disabledConfig = { ...environment.config, gui_enabled: false };
      const disabledApp = createApp(disabledConfig, new CaptureStore(disabledConfig));
      const disabled = await request(disabledApp)
        .get(`/issuers/${issuerId}`)
        .set("accept", "text/html");
      expect(disabled.status).toBe(404);
      expect(disabled.body).toEqual({});
    } finally {
      environment.cleanup();
    }
  });

  it("passes raw webhook bytes through the signature verifier", async () => {
    const secret = "server-routing-webhook-secret";
    const fixture = new AttestbookFixture();
    await fixture.start();
    const { environment, app } = await harness({
      ...DEFAULT_CONFIG,
      attestbook: {
        enabled: true,
        base_url: fixture.origin,
        rulebook_id: fixture.rulebookId,
        webhook_secret: secret,
        admin_token: null,
        allowed_schema_origins: [],
      },
    });
    try {
      const event = fixture.publish("1.0", [
        {
          name: "Routing membership",
          schema: { type: "object", properties: { member_id: { type: "string" } } },
          typeMetadata: { vct: "urn:attestbook:routing:1.0", display: [], claims: [] },
        },
      ]);
      const delivery = signedDelivery(secret, event);
      const response = await request(app)
        .post("/integrations/attestbook/webhook")
        .set(delivery.headers)
        .send(delivery.body.toString("utf8"));
      expect(response.status).toBe(202);
      expect(response.body).toMatchObject({ status: "accepted", event_id: event.id });
    } finally {
      environment.cleanup();
      await fixture.stop();
    }
  });

  it("returns the unmatched 404 response shape", async () => {
    const { environment, app } = await harness();
    try {
      const response = await request(app).get("/not-found");
      expect(response.status).toBe(404);
      expect(response.body).toEqual({});
    } finally {
      environment.cleanup();
    }
  });
});
