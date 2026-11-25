import { readFileSync } from "node:fs";
import type { Express } from "express";
import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifierPrivateJwkPath } from "../src/config/paths.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord } from "../src/types.js";
import { type IssuerTestEnvironment, createIssuerTestEnvironment } from "./support/environment.js";
import {
  type VpSessionCreateResponse,
  createVpSession,
  fetchRequestObject,
} from "./support/presentation.js";

let environment: IssuerTestEnvironment | undefined;
let config!: IssuerTestEnvironment["config"];
let app!: Express;

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "vp-request-construction-" });
  config = environment.config;
  app = createApp(config);
});

afterAll(() => environment?.cleanup());

function deliveredRequestJwt(session: VpSessionCreateResponse): string | undefined {
  if (session.dc_api_request?.protocol === "openid4vp-v1-signed") {
    return session.dc_api_request.data.request as string;
  }
  if (session.request_delivery === "by_reference") return undefined;
  const request = new URL(session.deeplink).searchParams.get("request");
  return request ?? undefined;
}

async function deliveredRequest(
  targetApp: Express,
  session: VpSessionCreateResponse,
): Promise<JsonRecord> {
  if (session.dc_api_request?.protocol === "openid4vp-v1-unsigned") {
    return session.dc_api_request.data;
  }
  if (session.dc_api_request?.protocol === "openid4vp-v1-multisigned") {
    const request = session.dc_api_request.data.request as { payload: string };
    return JSON.parse(Buffer.from(request.payload, "base64url").toString("utf8")) as JsonRecord;
  }
  if (session.request_delivery === "plain") {
    return Object.fromEntries(new URL(session.deeplink).searchParams.entries());
  }
  const jwt =
    session.request_delivery === "by_reference"
      ? await fetchRequestObject(targetApp, session)
      : deliveredRequestJwt(session);
  if (!jwt) throw new Error("signed VP request was not delivered");
  return decodeJwt(jwt) as JsonRecord;
}

describe("OpenID4VP request construction", () => {
  const deliveryCases: Array<[string, { response_mode?: string; request_delivery?: string }]> = [
    ["by_reference", {}],
    ["by_value", {}],
    ["plain", {}],
    ["dc_api signed", { response_mode: "dc_api.jwt", request_delivery: "by_value" }],
    ["dc_api unsigned", { response_mode: "dc_api", request_delivery: "plain" }],
    ["multisigned", { response_mode: "dc_api.jwt", request_delivery: "multisigned" }],
  ];

  it.each(deliveryCases)(
    "preserves the authorization request shape for %s delivery",
    async (_name, options) => {
      const session = await createVpSession(app, {
        ...options,
        presentation_request: { state: null, dcql_query: null },
      });
      const delivered = await deliveredRequest(app, session);

      expect(session.authorization_request).not.toHaveProperty("state");
      expect(delivered).not.toHaveProperty("state");
      expect(session.authorization_request.dcql_query).toBeDefined();
      expect(delivered).not.toHaveProperty("dcql_query");
      expect(delivered.response_mode).toBe(options.response_mode ?? "direct_post.jwt");
      if (
        session.dc_api_request?.protocol === "openid4vp-v1-unsigned" ||
        session.dc_api_request?.protocol === "openid4vp-v1-multisigned"
      ) {
        expect(delivered).not.toHaveProperty("client_id");
      } else {
        expect(delivered.client_id).toMatch(/^(x509_hash|x509_san_dns):/);
      }

      if (session.dc_api_request?.protocol === "openid4vp-v1-multisigned") {
        const request = session.dc_api_request.data.request as {
          payload: string;
          signatures: Array<{ protected: string }>;
        };
        const payload = JSON.parse(
          Buffer.from(request.payload, "base64url").toString("utf8"),
        ) as JsonRecord;
        expect(payload).toMatchObject({ response_mode: "dc_api.jwt" });
        expect(request.signatures).toHaveLength(2);
        expect(
          request.signatures.map(
            ({ protected: encoded }) => decodeProtectedHeader(`${encoded}..`).typ,
          ),
        ).toEqual(["oauth-authz-req+jwt", "oauth-authz-req+jwt"]);
      } else if (options.response_mode !== "dc_api") {
        const jwt =
          session.request_delivery === "by_reference"
            ? await fetchRequestObject(app, session)
            : deliveredRequestJwt(session);
        if (!jwt) throw new Error("missing delivered request JWT");
        expect(decodeProtectedHeader(jwt).typ).toBe("oauth-authz-req+jwt");
        expect(decodeProtectedHeader(jwt).x5c).toEqual([expect.any(String)]);
      }
    },
  );

  it("applies request mutations before independently signing the delivered request", async () => {
    const scenarioApp = createApp({ ...config, fcaf_scenarios_enabled: true });
    const session = await createVpSession(scenarioApp, {
      request_mutation: { request_object: { set: { "/nonce": "mutated-nonce" } } },
      request_behavior: { signature: "corrupt" },
    });
    const jwt = await fetchRequestObject(scenarioApp, session);
    const delivered = decodeJwt(jwt) as JsonRecord;

    expect(delivered.nonce).toBe("mutated-nonce");
    expect(session.authorization_request.nonce).not.toBe("mutated-nonce");
    await expect(
      compactVerify(
        jwt,
        await importJWK(
          JSON.parse(readFileSync(verifierPrivateJwkPath(config.data_dir), "utf8")),
          "ES256",
        ),
      ),
    ).rejects.toThrow();
  });
});
