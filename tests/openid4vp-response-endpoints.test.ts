import type { Express } from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import {
  CONFORMING_ISSUER_ID,
  createIssuerTestEnvironment,
  createTestApp,
  requireIssuer,
} from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import { getJson } from "./support/http.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  createVpSession,
  dcqlForClaims,
  sdJwtCredential,
  sdJwtPresentation,
} from "./support/presentation.js";

let environment: IssuerTestEnvironment | undefined;
let config!: IssuerTestEnvironment["config"];
let app!: Express;
let issuerConfig!: IssuerTestEnvironment["config"];

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "openid4vp-response-endpoints-" });
  config = environment.config;
  app = createTestApp(config);
  issuerConfig = issuerAppConfig(config, requireIssuer(config, CONFORMING_ISSUER_ID));
});

afterAll(() => environment?.cleanup());

async function submitValidSdJwt(
  targetApp: Express,
  session: VpSessionCreateResponse,
  path: string,
): Promise<{ response: request.Response; presentation: string }> {
  const credential = await sdJwtCredential(issuerConfig, config.credential_configuration_id);
  const presentation = await sdJwtPresentation({
    credential,
    authorizationRequest: session.authorization_request,
    disclosedClaims: ["family_name", "given_name"],
  });
  const responseBody = {
    state: session.session_id,
    vp_token: JSON.stringify({ query_0: [presentation] }),
  };
  const response = await request(targetApp).post(path).type("form").send(responseBody);
  return { response, presentation };
}

describe("OpenID4VP response endpoints", () => {
  it.each([
    ["missing state", undefined],
    ["unknown state", "unknown-vp-state"],
  ])("rejects %s on the alternative response endpoint", async (_label, state) => {
    const body =
      state === undefined
        ? { vp_token: "not-a-presentation" }
        : { state, vp_token: "not-a-presentation" };
    const response = await request(app).post("/openid4vp/response").type("form").send(body);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "vp_session_not_found" });
  });

  it("accepts an SD-JWT presentation selected by state and records the same evidence as the session route", async () => {
    const directSession = await createVpSession(app, {
      response_mode: "direct_post",
      redirect_uri: "https://rp.example.test/complete",
      presentation_request: {
        state: null,
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const directSubmission = await submitValidSdJwt(app, directSession, "/openid4vp/response");

    expect(directSubmission.response.status).toBe(200);
    expect(directSubmission.response.body).toEqual({ redirect_uri: directSession.redirect_uri });
    const directCapture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${directSession.session_id}`,
    );
    expect(directCapture.status).toBe("presentation_validated");
    expect(directCapture.checks).toMatchObject({
      presentation_valid: true,
      nonce_verified: true,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
    expect(directCapture.raw?.presentation_response).toEqual({
      state: directSession.session_id,
      vp_token: JSON.stringify({ query_0: [directSubmission.presentation] }),
    });
    expect(directCapture.raw?.presentation_response_http).toMatchObject({
      method: "POST",
      headers: {
        "content-type": expect.stringContaining("application/x-www-form-urlencoded"),
      },
    });
    expect(directCapture.raw?.presentation_response_http?.body).toContain(
      `state=${encodeURIComponent(directSession.session_id)}`,
    );
    expect(directCapture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      headers: {
        "cache-control": "no-store",
        "content-type": expect.stringContaining("application/json"),
      },
      body: JSON.stringify({ redirect_uri: directSession.redirect_uri }),
    });
    expect(directCapture.raw?.presentation_response_decrypted).toEqual({
      state: directSession.session_id,
      vp_token: { query_0: [directSubmission.presentation] },
    });
    expect(directCapture.raw?.decoded_presentations).toEqual(directCapture.decoded_presentations);
    expect(directCapture.events.map((event) => event.type)).toEqual([
      "vp_session_created",
      "vp_deeplink_generated",
      "vp_presentation_response_received",
    ]);

    const scopedSession = await createVpSession(app, {
      response_mode: "direct_post",
      redirect_uri: "https://rp.example.test/complete",
      presentation_request: {
        state: null,
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const scopedSubmission = await submitValidSdJwt(
      app,
      scopedSession,
      `/openid4vp/sessions/${scopedSession.session_id}/response`,
    );
    expect(scopedSubmission.response.status).toBe(200);
    expect(scopedSubmission.response.body).toEqual({ redirect_uri: scopedSession.redirect_uri });
    const scopedCapture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${scopedSession.session_id}`,
    );
    expect(scopedCapture.status).toBe("presentation_validated");
    expect(scopedCapture.checks).toMatchObject({
      presentation_valid: true,
      nonce_verified: true,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
    expect(scopedCapture.raw?.presentation_response).toEqual({
      state: scopedSession.session_id,
      vp_token: JSON.stringify({ query_0: [scopedSubmission.presentation] }),
    });
    expect(scopedCapture.raw?.presentation_response_decrypted).toEqual({
      state: scopedSession.session_id,
      vp_token: { query_0: [scopedSubmission.presentation] },
    });
    expect(scopedCapture.raw?.decoded_presentations).toEqual(scopedCapture.decoded_presentations);
    expect(scopedCapture.events.map((event) => event.type)).toEqual([
      "vp_session_created",
      "vp_deeplink_generated",
      "vp_presentation_response_received",
    ]);
    expect(directCapture.events.at(-1)?.detail).toMatchObject({
      vp_token_observed: true,
      presentation_valid: true,
      errors: [],
    });
    expect(scopedCapture.events.at(-1)?.detail).toMatchObject({
      vp_token_observed: true,
      presentation_valid: true,
      errors: [],
    });
  });
  it("distinguishes the generated request state from the session id on the alternative route", async () => {
    const session = await createVpSession(app, {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const requestState = String(session.authorization_request.state);
    const requestStateResponse = await request(app)
      .post("/openid4vp/response")
      .type("form")
      .send({ state: requestState, vp_token: "not-a-presentation" });
    expect(requestStateResponse.status).toBe(404);
    expect(requestStateResponse.body).toEqual({ error: "vp_session_not_found" });

    const sessionIdResponse = await request(app)
      .post("/openid4vp/response")
      .type("form")
      .send({ state: session.session_id, vp_token: "not-a-presentation" });
    const mismatchDescription =
      "The 'state' parameter in the authorization response does not match the 'state' parameter in the authorization request.";
    const mismatchMessage = `${mismatchDescription} Expected '${requestState}' but received '${session.session_id}'.`;
    expect(sessionIdResponse.status).toBe(400);
    expect(sessionIdResponse.body).toEqual({
      error: "invalid_presentation",
      errors: [
        `${mismatchMessage}\n${JSON.stringify(
          {
            error: "invalid_request",
            error_description: mismatchDescription,
          },
          null,
          2,
        )}`,
      ],
    });
  });

  it("acknowledges a wallet Authorization Error Response on the alternative endpoint", async () => {
    const session = await createVpSession(app, {
      response_mode: "direct_post",
      presentation_request: { state: null, dcql_query: dcqlForClaims(["family_name"]) },
    });
    const response = await request(app)
      .post("/openid4vp/response")
      .type("form")
      .send({ state: session.session_id, error: "access_denied" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({});
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.raw?.presentation_response).toEqual({
      state: session.session_id,
      error: "access_denied",
    });
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      headers: {
        "cache-control": "no-store",
        "content-type": expect.stringContaining("application/json"),
      },
      body: "{}",
    });
    expect(capture.events.at(-1)).toMatchObject({
      type: "vp_presentation_response_received",
      detail: { vp_token_observed: false, presentation_valid: false },
    });
  });

  it("captures an invalid presentation submitted to the alternative response endpoint", async () => {
    const session = await createVpSession(app, {
      response_mode: "direct_post",
      presentation_request: {
        state: null,
        dcql_query: dcqlForClaims(["family_name"]),
      },
    });
    const response = await request(app)
      .post("/openid4vp/response")
      .type("form")
      .send({ state: session.session_id, vp_token: "not-a-presentation" });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe("invalid_presentation");
    expect(response.body.errors).toEqual([
      "Could not parse dcql vp_token. Expected an object where the values are encoded presentations\n" +
        "✖ Dcql vp_token must be an object with keys referencing the dcql credential query id, and values a non-empty array of strings and objects, or string, or object",
    ]);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.observed.wallet_response.value).toEqual({
      state: session.session_id,
      vp_token: "not-a-presentation",
    });
    expect(capture.raw?.presentation_response).toEqual({
      state: session.session_id,
      vp_token: "not-a-presentation",
    });
    expect(capture.raw?.presentation_response_http?.body).toContain("vp_token=not-a-presentation");
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 400,
      body: expect.stringContaining('"error":"invalid_presentation"'),
    });
    expect(capture.events.at(-1)).toMatchObject({
      type: "vp_presentation_response_received",
      detail: expect.objectContaining({ vp_token_observed: true, presentation_valid: false }),
    });
  });

  it("keeps DC API completion and origin guards on the session-scoped route only", async () => {
    const completedSession = await createVpSession(app, { response_mode: "dc_api" });
    const first = await request(app)
      .post(`/openid4vp/sessions/${completedSession.session_id}/response`)
      .send({ vp_token: "not-a-presentation" });
    expect(first.status).toBe(400);
    expect(first.body.error).toBe("invalid_presentation");

    const second = await request(app)
      .post(`/openid4vp/sessions/${completedSession.session_id}/response`)
      .send({ vp_token: "not-a-presentation" });
    expect(second.status).toBe(409);
    expect(second.body).toEqual({ error: "vp_session_already_completed" });
    const alternativeCompleted = await request(app)
      .post("/openid4vp/response")
      .send({ state: completedSession.session_id, vp_token: "overwrite" });
    expect(alternativeCompleted.status).toBe(400);
    expect(alternativeCompleted.body.error).toBe("invalid_presentation");
    const completedCapture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${completedSession.session_id}`,
    );
    expect(completedCapture.raw?.presentation_response).toEqual({
      state: completedSession.session_id,
      vp_token: "overwrite",
    });

    const originSession = await createVpSession(app, { response_mode: "dc_api" });
    const scopedOrigin = await request(app)
      .post(`/openid4vp/sessions/${originSession.session_id}/response`)
      .set("Origin", "https://wallet.example.test")
      .send({ vp_token: "not-a-presentation" });
    expect(scopedOrigin.status).toBe(403);
    expect(scopedOrigin.body).toEqual({ error: "unexpected_dc_api_origin" });

    const alternative = await request(app)
      .post("/openid4vp/response")
      .set("Origin", "https://wallet.example.test")
      .send({ state: originSession.session_id, vp_token: "not-a-presentation" });
    expect(alternative.status).toBe(400);
    expect(alternative.body.error).toBe("invalid_presentation");
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${originSession.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.raw?.presentation_response).toEqual({
      state: originSession.session_id,
      vp_token: "not-a-presentation",
    });
    expect(capture.raw?.presentation_response_http).toMatchObject({
      method: "POST",
      body: expect.stringContaining(`"state":"${originSession.session_id}"`),
    });
  });

  it("applies an enabled FCAF response scenario at the alternative response endpoint", async () => {
    const scenarioApp = createTestApp({ ...config, fcaf_scenarios_enabled: true });
    const session = await createVpSession(scenarioApp, {
      response_mode: "direct_post",
      response_scenario: { status: 400, extra_parameters: { error: "invalid_request" } },
      presentation_request: {
        state: null,
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const submission = await submitValidSdJwt(scenarioApp, session, "/openid4vp/response");

    expect(submission.response.status).toBe(400);
    expect(submission.response.body).toEqual({ error: "invalid_request" });
    const capture = await getJson<VpSessionResponse>(
      scenarioApp,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks.presentation_valid).toBe(true);
    expect(capture.response_scenario).toEqual({
      status: 400,
      extra_parameters: { error: "invalid_request" },
    });
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 400,
      headers: {
        "cache-control": "no-store",
        "content-type": expect.stringContaining("application/json"),
      },
      body: JSON.stringify({ error: "invalid_request" }),
    });
    expect(capture.events.map((event) => event.type)).toEqual([
      "vp_session_created",
      "vp_response_scenario_selected",
      "vp_deeplink_generated",
      "vp_presentation_response_received",
    ]);
  });

  it("refuses an FCAF response scenario when the deployment disables scenarios", async () => {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "direct_post",
        response_scenario: { status: 400 },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "response_scenario_not_enabled" });
  });

  it("returns the chronological event list before and after a presentation submission", async () => {
    const session = await createVpSession(app, {
      response_mode: "direct_post",
      presentation_request: {
        state: null,
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const createdEvents = await getJson<Array<{ type: string; detail: Record<string, unknown> }>>(
      app,
      `/openid4vp/sessions/${session.session_id}/events`,
    );
    expect(createdEvents).toHaveLength(2);
    expect(createdEvents.map((event) => event.type)).toEqual([
      "vp_session_created",
      "vp_deeplink_generated",
    ]);
    expect(createdEvents[0]?.detail).toEqual({});
    expect(createdEvents[1]?.detail).toEqual({});

    await submitValidSdJwt(app, session, "/openid4vp/response");
    const submittedEvents = await getJson<Array<{ type: string; detail: Record<string, unknown> }>>(
      app,
      `/openid4vp/sessions/${session.session_id}/events`,
    );
    expect(submittedEvents.map((event) => event.type)).toEqual([
      "vp_session_created",
      "vp_deeplink_generated",
      "vp_presentation_response_received",
    ]);
  });

  it("returns a not-found JSON error for an unknown presentation session event list", async () => {
    const response = await request(app).get("/openid4vp/sessions/unknown-vp-session/events");
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "vp_session_not_found" });
  });

  it.each([
    [
      "unknown code",
      "/openid4vp/redirect?response_code=unknown-response-code",
      "unknown-response-code",
    ],
    ["missing code", "/openid4vp/redirect", "No response code received"],
  ])("returns an HTML 404 page for a redirect with %s", async (_label, path, fragment) => {
    const response = await request(app).get(path);
    expect(response.status).toBe(404);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain("Redirect page not found");
    expect(response.text).toContain(fragment);
  });

  it("serves the known capture redirect code and records its visit", async () => {
    const session = await createVpSession(app, {
      redirect_uri: "{{base_url}}/openid4vp/redirect",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const redirect = new URL(String(session.redirect_uri));
    const response = await request(app).get(`${redirect.pathname}${redirect.search}`);

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain("Presentation complete");
    expect(response.text).toContain(redirect.searchParams.get("response_code"));
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.redirect_uri_visit_count).toBe(1);
    expect(capture.raw?.redirect_uri_visits).toHaveLength(1);
    expect(capture.events.at(-1)).toMatchObject({
      type: "vp_redirect_uri_visited",
      detail: { visit_count: 1 },
    });
  });
});
