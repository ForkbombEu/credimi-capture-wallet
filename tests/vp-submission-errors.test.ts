import type { Express } from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { credoOpenId4VpVerifier } from "../src/openid4vp/credo-verifier.js";
import { createIssuerTestEnvironment, createTestApp } from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import { createVpSession, dcqlForClaims } from "./support/presentation.js";

let environment: IssuerTestEnvironment | undefined;
let app!: Express;
let config!: IssuerTestEnvironment["config"];

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "vp-submission-errors-" });
  config = environment.config;
  app = createTestApp(config);
});

afterEach(() => vi.restoreAllMocks());
afterAll(() => environment?.cleanup());

describe("VP submission errors", () => {
  it("passes verifier failures to the Express error handler on both response routes", async () => {
    const scopedSession = await createVpSession(app, {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const alternativeSession = await createVpSession(app, {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const verifier = await credoOpenId4VpVerifier(config);
    vi.spyOn(verifier, "verifyResponse").mockRejectedValue(new Error("verification exploded"));

    const scopedResponse = await request(app)
      .post(`/openid4vp/sessions/${scopedSession.session_id}/response`)
      .type("form")
      .send({ state: scopedSession.session_id, vp_token: "not-a-presentation" });
    const alternativeResponse = await request(app)
      .post("/openid4vp/response")
      .type("form")
      .send({ state: alternativeSession.session_id, vp_token: "not-a-presentation" });

    expect(scopedResponse.status).toBe(500);
    expect(scopedResponse.body).toEqual({
      error: "internal_error",
      message: "verification exploded",
    });
    expect(alternativeResponse.status).toBe(500);
    expect(alternativeResponse.body).toEqual({
      error: "internal_error",
      message: "verification exploded",
    });
  });
});
