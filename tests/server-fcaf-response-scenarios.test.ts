import type { Express } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import type { JsonRecord } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  dcqlForClaims,
  sdJwtPresentation,
} from "./support/presentation.js";
import { serverTestSuite } from "./support/server.js";
const { config, pidSdJwtCredential } = serverTestSuite("fake-issuer-test-");
describe("FCAF verifier response scenarios", () => {
  const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };

  async function submitValidPresentation(app: Express, responseScenario?: JsonRecord) {
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      ...(responseScenario ? { response_scenario: responseScenario } : {}),
    });
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    return { session, response, capture };
  }

  it("returns a plain-text body with HTTP 200 without touching the verification result", async () => {
    const { response, capture } = await submitValidPresentation(createApp(scenarioConfig), {
      content_type: "text/plain",
      body: "OK",
    });

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/plain");
    expect(response.text).toBe("OK");
    expect(capture.checks.presentation_valid).toBe(true);
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      body: "OK",
    });
  });

  it("returns a test-selected 400 while still recording the presentation as verified", async () => {
    const { response, capture } = await submitValidPresentation(createApp(scenarioConfig), {
      status: 400,
      extra_parameters: { error: "invalid_request" },
    });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request" });
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks).toMatchObject({ presentation_valid: true, errors: [] });
  });

  it("adds an unrecognised parameter to the normal response body", async () => {
    const { session, response } = await submitValidPresentation(createApp(scenarioConfig), {
      extra_parameters: { unknown_parameter: "present" },
    });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ unknown_parameter: "present" });
    expect(session.response_mode).toBe("direct_post");
  });

  it("keeps an invalid presentation invalid even when the scenario returns 200", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      response_scenario: { status: 200, extra_parameters: { redirect_uri: "https://rp.test/ok" } },
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ state: session.authorization_request.state, vp_token: "not-a-presentation" });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ redirect_uri: "https://rp.test/ok" });
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.response_scenario).toMatchObject({ status: 200 });
    expect(capture.events.map((event) => event.type)).toContain("vp_response_scenario_selected");
  });

  it("returns the normal response when no scenario is selected", async () => {
    const { response } = await submitValidPresentation(createApp(scenarioConfig));

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("application/json");
    expect(response.body).toEqual({});
  });

  it("returns and captures a direct-post response without redirect_uri", async () => {
    const { response, capture } = await submitValidPresentation(createApp(scenarioConfig));

    expect(response.status).toBe(200);
    expect(response.body).toEqual({});
    expect(response.body).not.toHaveProperty("redirect_uri");
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      body: "{}",
    });
  });

  it.each([
    ["an out-of-range status", { status: 600 }],
    ["a non-string body", { body: {} }],
    ["array extra parameters", { extra_parameters: [] }],
    ["an unknown member", { headers: { location: "https://rp.test" } }],
    ["an empty scenario", {}],
  ])("rejects %s", async (_label, scenario) => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({ response_scenario: scenario });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_response_scenario" });
  });

  it("refuses a scenario unless the deployment enables FCAF scenarios", async () => {
    const response = await request(createApp(config))
      .post("/openid4vp/sessions")
      .send({ response_scenario: { status: 400 } });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "response_scenario_not_enabled" });
  });
});
