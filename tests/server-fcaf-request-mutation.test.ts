import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CredoWebCrypto, Kms, X509Certificate, X509KeyUsage } from "@credo-ts/core";
import type { Express } from "express";
import {
  type JWK,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { createJwkSigningContext, initIssuer } from "../src/config/key-material.js";
import {
  verifierCaCertificatePath,
  verifierCertificatePath,
  verifierJwksPath,
  verifierPrivateJwkPath,
} from "../src/config/paths.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  dcqlForClaims,
  sdJwtPresentation,
} from "./support/presentation.js";
import {
  encryptingWalletMetadata,
  serverTestSuite,
  walletEncryptionKey,
} from "./support/server.js";
const { dataDir, config, pidSdJwtCredential } = serverTestSuite("fake-issuer-test-");
function verifierPublicJwk(): JWK {
  const jwks = JSON.parse(readFileSync(verifierJwksPath(dataDir), "utf8")) as { keys: JWK[] };
  return jwks.keys[0];
}
describe("FCAF request mutation", () => {
  const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };

  async function mutatedSession(
    app: Express,
    mutation: JsonRecord,
    body: JsonRecord = {},
  ): Promise<VpSessionCreateResponse> {
    return postJson(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_delivery: "by_reference",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      request_mutation: mutation,
      ...body,
    });
  }

  async function deliveredRequestObject(
    app: Express,
    session: VpSessionCreateResponse,
  ): Promise<string> {
    const served = await request(app).get(new URL(String(session.request_uri)).pathname);
    expect(served.status).toBe(200);
    return served.text;
  }

  it("refuses mutations unless the deployment enables FCAF scenarios", async () => {
    const response = await request(createApp(config))
      .post("/openid4vp/sessions")
      .send({ request_mutation: { request_object: { unset: ["/response_uri"] } } });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "request_mutation_not_enabled" });
  });

  it.each([
    ["an unknown target", { signed_request: { unset: ["/state"] } }],
    ["a dotted path", { request_object: { unset: ["client_metadata.jwks"] } }],
    ["a pointer without a leading slash", { request_object: { set: { state: "x" } } }],
    ["an empty edit set", { request_object: {} }],
    ["an unknown edit operation", { request_object: { replace: { "/state": "x" } } }],
    ["a non-boolean verification_applies", { verification_applies: "yes" }],
  ])("rejects %s", async (_label, mutation) => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({ request_mutation: mutation });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request_mutation" });
  });

  it("removes a member from the delivered Request Object while keeping the verifier's own view", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, { request_object: { unset: ["/response_uri"] } });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect(payload).not.toHaveProperty("response_uri");
    expect(session.authorization_request.response_uri).toBe(session.response_uri);

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.authorization_request.response_uri).toBe(session.response_uri);
    expect(capture.raw?.authorization_request_delivered).not.toHaveProperty("response_uri");
    expect(capture.request_mutation).toEqual({ request_object: { unset: ["/response_uri"] } });
    expect(capture.events.map((event) => event.type)).toContain("vp_request_mutation_applied");
  });

  it("distinguishes a member set to null from a removed member", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, { request_object: { set: { "/state": null } } });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect(payload).toHaveProperty("state");
    expect(payload.state).toBeNull();
  });

  it("delivers a controlled Request Object audience while retaining the generated static audience", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, {
      request_object: { set: { "/aud": "https://wallet.example.invalid" } },
    });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect(payload.aud).toBe("https://wallet.example.invalid");
    expect(session.authorization_request.aud).toBe("https://self-issued.me/v2");
  });

  it("writes nested members and values of the wrong JSON type", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, {
      request_object: {
        set: { "/client_metadata/vp_formats_supported/dc+sd-jwt": 42, "/nonce": [] },
      },
    });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    const metadata = payload.client_metadata as JsonRecord;
    expect((metadata.vp_formats_supported as JsonRecord)["dc+sd-jwt"]).toBe(42);
    expect(payload.nonce).toEqual([]);
  });
  it("delivers defined and unrecognised client metadata members", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      client_metadata: { client_name: "ignored-by-wallet" },
    });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect((payload.client_metadata as JsonRecord).client_name).toBe("ignored-by-wallet");
    expect((payload.client_metadata as JsonRecord).vp_formats_supported).toBeDefined();
  });

  it("delivers a non-object client_metadata value only to the Wallet", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, {
      request_object: { set: { "/client_metadata": "not-a-json-object" } },
    });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect(payload.client_metadata).toBe("not-a-json-object");
    expect(session.authorization_request.client_metadata).toBeDefined();

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.authorization_request_delivered?.client_metadata).toBe("not-a-json-object");
  });

  it.each(["WS_RP_MS_Metadata__109", "WS_RP_SM_RpIntegrity__021"])(
    "delivers non-key verifier metadata outside client_metadata for %s",
    async () => {
      const app = createApp(scenarioConfig);
      const session = await mutatedSession(app, {
        request_object: { set: { "/client_name": "outside-client-metadata" } },
      });

      const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
      expect(payload.client_name).toBe("outside-client-metadata");
      expect(payload.client_metadata).toBeDefined();
      expect(session.authorization_request.client_name).toBeUndefined();

      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.raw?.authorization_request_delivered?.client_name).toBe(
        "outside-client-metadata",
      );
    },
  );

  it("mutates the JOSE header of the signed Request Object", async () => {
    const app = createApp(scenarioConfig);
    const invalidTyp = await mutatedSession(app, {
      request_object_header: { set: { "/typ": "jwt" } },
    });
    const missingTyp = await mutatedSession(app, { request_object_header: { unset: ["/typ"] } });

    expect(decodeProtectedHeader(await deliveredRequestObject(app, invalidTyp)).typ).toBe("jwt");
    const header = decodeProtectedHeader(await deliveredRequestObject(app, missingTyp));
    expect(header).not.toHaveProperty("typ");
    expect(header.alg).toBe("ES256");
  });

  it("makes an outer parameter disagree with the signed Request Object", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, {
      outer_request: { set: { "/client_id": "x509_hash:other", "/unknown_parameter": "present" } },
    });

    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("client_id")).toBe("x509_hash:other");
    expect(deeplink.searchParams.get("unknown_parameter")).toBe("present");
    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect(payload.client_id).not.toBe("x509_hash:other");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.outer_request_delivered).toMatchObject({
      client_id: "x509_hash:other",
      unknown_parameter: "present",
    });
  });
  it.each([
    ["redirect_uri", "redirect_uri:https://rp.example.test/callback"],
    ["origin", "origin:https://rp.example.test"],
    ["unsupported", "unsupported:client"],
  ])(
    "delivers a signed Request Object and outer request with the %s client identifier prefix",
    async (_name, clientId) => {
      const app = createApp(scenarioConfig);
      const session = await mutatedSession(app, {
        request_object: { set: { "/client_id": clientId } },
        outer_request: { set: { "/client_id": clientId } },
      });

      expect(new URL(session.deeplink).searchParams.get("client_id")).toBe(clientId);
      const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
      expect(payload.client_id).toBe(clientId);

      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.raw?.authorization_request_delivered?.client_id).toBe(clientId);
      expect(capture.raw?.outer_request_delivered?.client_id).toBe(clientId);
    },
  );

  it("delivers an unsigned HTTPS client identifier in a plain Authorization Request", async () => {
    const app = createApp(scenarioConfig);
    const clientId = "https://rp.example.test/client";
    const session = await mutatedSession(
      app,
      { outer_request: { set: { "/client_id": clientId } } },
      { request_delivery: "plain" },
    );

    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("client_id")).toBe(clientId);
    expect(deeplink.searchParams.has("request")).toBe(false);
    expect(deeplink.searchParams.has("request_uri")).toBe(false);

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.outer_request_delivered?.client_id).toBe(clientId);
  });

  it("keeps verification bound to the generated request, not to the mutated one", async () => {
    const app = createApp(scenarioConfig);
    const session = await mutatedSession(app, {
      request_object: { set: { "/nonce": "nonce-the-wallet-must-not-use" } },
      verification_applies: true,
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

    expect(response.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.presentation_valid).toBe(true);
    expect(capture.raw?.authorization_request_delivered?.nonce).toBe(
      "nonce-the-wallet-must-not-use",
    );
  });

  it("delivers a Request Object whose signature does not verify", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_behavior: { signature: "corrupt" },
    });

    const served = await deliveredRequestObject(app, session);
    expect(served.split(".")).toHaveLength(3);
    expect(decodeJwt(served).response_uri).toBe(session.response_uri);
    await expect(
      compactVerify(served, await importJWK(verifierPublicJwk(), "ES256")),
    ).rejects.toThrow();

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.request_behavior).toEqual({ signature: "corrupt" });
    expect(capture.events.map((event) => event.type)).toContain("vp_request_behavior_applied");
  });

  it("keeps serving the corrupted signature after a wallet_nonce re-sign", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_uri_method: "post",
      request_behavior: { signature: "corrupt" },
    });

    const served = await request(app)
      .post(new URL(String(session.request_uri)).pathname)
      .type("form")
      .send({ wallet_nonce: "wallet-supplied-nonce" });

    expect(served.status).toBe(200);
    expect(decodeJwt(served.text).wallet_nonce).toBe("wallet-supplied-nonce");
    await expect(
      compactVerify(served.text, await importJWK(verifierPublicJwk(), "ES256")),
    ).rejects.toThrow();
  });

  it.each([
    ["an unknown behaviour", { unknown: "corrupt" }],
    ["an unknown signature value", { signature: "invalid" }],
    ["an empty behaviour", {}],
  ])("rejects %s", async (_label, behavior) => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({ request_behavior: behavior });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request_behavior" });
  });

  it("refuses a behaviour unless the deployment enables FCAF scenarios", async () => {
    const response = await request(createApp(config))
      .post("/openid4vp/sessions")
      .send({ request_behavior: { signature: "corrupt" } });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "request_behavior_not_enabled" });
  });

  it("refuses to corrupt a signature on an unsigned request", async () => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({
        client_id_scheme: "redirect_uri",
        request_delivery: "plain",
        request_behavior: { signature: "corrupt" },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "signature_behavior_requires_a_signed_request" });
  });

  it.each([
    ["mismatch", true],
    ["omit", false],
  ])("answers a wallet_nonce with the %s behaviour", async (behavior, expectPresent) => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_uri_method: "post",
      request_behavior: { wallet_nonce: behavior },
    });

    const served = await request(app)
      .post(new URL(String(session.request_uri)).pathname)
      .type("form")
      .send({ wallet_nonce: "wallet-supplied-nonce" });

    expect(served.status).toBe(200);
    const returned = decodeJwt(served.text).wallet_nonce;
    expect(returned === undefined).toBe(!expectPresent);
    expect(returned).not.toBe("wallet-supplied-nonce");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    const retrieved = capture.events.find((event) => event.type === "vp_request_retrieved");
    expect(retrieved?.detail).toMatchObject({
      wallet_nonce_behavior: behavior,
      wallet_nonce_returned: returned ?? null,
    });
    expect(capture.observed.request_uri_payload.value?.wallet_nonce).toBe("wallet-supplied-nonce");
  });

  it("echoes the wallet_nonce by default", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_uri_method: "post",
    });

    const served = await request(app)
      .post(new URL(String(session.request_uri)).pathname)
      .type("form")
      .send({ wallet_nonce: "wallet-supplied-nonce" });

    expect(decodeJwt(served.text).wallet_nonce).toBe("wallet-supplied-nonce");
  });

  it.each([
    ["a certificate_chain fixture", { request_behavior: { certificate_chain: "untrusted_root" } }],
    ["an omitted dcql_query", { scopes: "openid", presentation_request: { dcql_query: null } }],
    ["a request_object mutation", { request_mutation: { request_object: { unset: ["/state"] } } }],
    ["a verifier_attestation Client Identifier", { client_id_scheme: "verifier_attestation" }],
  ])(
    "re-signs a wallet_nonce Request Object delivered with %s unchanged but for the nonce",
    async (_label, body) => {
      const app = createApp(scenarioConfig);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        response_mode: "direct_post",
        request_uri_method: "post",
        ...body,
      });
      const requestUriPath = new URL(String(session.request_uri)).pathname;
      const original = await request(app).post(requestUriPath).type("form").send({});
      const resigned = await request(app)
        .post(requestUriPath)
        .type("form")
        .send({ wallet_nonce: "wallet-supplied-nonce" });

      expect(decodeJwt(resigned.text)).toEqual({
        ...decodeJwt(original.text),
        wallet_nonce: "wallet-supplied-nonce",
      });
      expect(decodeProtectedHeader(resigned.text)).toEqual(decodeProtectedHeader(original.text));
    },
  );

  it("lets a request_object mutation override the echoed wallet_nonce", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_uri_method: "post",
      request_mutation: { request_object: { set: { "/wallet_nonce": "mutated-nonce" } } },
    });

    const served = await request(app)
      .post(new URL(String(session.request_uri)).pathname)
      .type("form")
      .send({ wallet_nonce: "wallet-supplied-nonce" });

    expect(decodeJwt(served.text).wallet_nonce).toBe("mutated-nonce");
  });

  it("serves a plain signed Request Object to a Wallet that requires encryption", async () => {
    const app = createApp(scenarioConfig);
    const walletKey = await walletEncryptionKey("P-256");
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_uri_method: "post",
      request_behavior: { request_object_encryption: "none" },
    });

    const served = await request(app)
      .post(new URL(String(session.request_uri)).pathname)
      .type("form")
      .send({ wallet_metadata: encryptingWalletMetadata(walletKey.publicJwk, "A128GCM") });

    expect(served.status).toBe(200);
    expect(served.text.split(".")).toHaveLength(3);
    expect(decodeProtectedHeader(served.text).typ).toBe("oauth-authz-req+jwt");
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw).not.toHaveProperty("authorization_request_jwe");
    expect(capture.events.map((event) => event.type)).toContain(
      "vp_request_object_encryption_skipped",
    );
  });

  it("serves the Request URI with a deliberately wrong status, media type, and body", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_behavior: {
        request_uri_response: {
          status: 404,
          content_type: "text/plain",
          body: "not a request object",
        },
      },
    });

    const served = await request(app).get(new URL(String(session.request_uri)).pathname);

    expect(served.status).toBe(404);
    expect(served.headers["content-type"]).toContain("text/plain");
    expect(served.text).toBe("not a request object");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.request_uri_response_http).toMatchObject({
      status: 404,
      body: "not a request object",
    });
    expect(capture.raw?.authorization_request_jwt).toMatch(/^ey/);
  });

  it("serves a configured HTTP error after POST Request URI retrieval and captures both sides", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_uri_method: "post",
      request_behavior: {
        request_uri_response: {
          status: 404,
          content_type: "text/plain",
          body: "request unavailable",
        },
      },
    });

    const served = await request(app)
      .post(new URL(String(session.request_uri)).pathname)
      .send({});

    expect(served.status).toBe(404);
    expect(served.headers["content-type"]).toContain("text/plain");
    expect(served.text).toBe("request unavailable");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.request_uri_http).toMatchObject({ method: "POST" });
    expect(capture.raw?.request_uri_response_http).toMatchObject({
      status: 404,
      body: "request unavailable",
    });
    expect(capture.events.map((event) => event.type)).toContain("vp_request_retrieved");
  });

  it("serves the normal Request URI response when no behaviour is selected", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
    });

    const served = await request(app).get(new URL(String(session.request_uri)).pathname);

    expect(served.status).toBe(200);
    expect(served.headers["content-type"]).toContain("application/oauth-authz-req+jwt");
    expect(decodeJwt(served.text).response_uri).toBe(session.response_uri);
  });

  it.each([
    ["an out-of-range status", { request_uri_response: { status: 99 } }],
    ["a non-integer status", { request_uri_response: { status: 200.5 } }],
    ["a non-string body", { request_uri_response: { body: 1 } }],
    ["an empty retrieval response", { request_uri_response: {} }],
    ["an unknown wallet_nonce behaviour", { wallet_nonce: "rotate" }],
  ])("rejects %s", async (_label, behavior) => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({ request_behavior: behavior });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request_behavior" });
  });

  it("signs with a key that does not match the certificate in x5c", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_behavior: { signing_key: "unrelated" },
    });

    const served = await deliveredRequestObject(app, session);
    const header = decodeProtectedHeader(served);
    const certificate = X509Certificate.fromEncodedCertificate((header.x5c as string[])[0]);
    expect((header.x5c as string[])[0]).toBe(
      readFileSync(verifierCertificatePath(dataDir), "utf8")
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, ""),
    );
    await expect(
      compactVerify(served, await importJWK(certificate.publicJwk.toJson() as JWK, "ES256")),
    ).rejects.toThrow();
    expect(decodeJwt(served).client_id).toBe(session.authorization_request.client_id);
  });

  it.each([
    ["unrelated_self_signed", 1],
    ["untrusted_root", 2],
    ["incomplete_chain", 1],
  ])("presents the %s chain and signs with its leaf key", async (fixture, chainLength) => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_behavior: { certificate_chain: fixture },
    });

    const served = await deliveredRequestObject(app, session);
    const chain = decodeProtectedHeader(served).x5c as string[];
    expect(chain).toHaveLength(chainLength);
    const leaf = X509Certificate.fromEncodedCertificate(chain[0]);
    expect(leaf.subject).toContain("unrelated-verifier.invalid");

    // The chain is the only defect: the signature verifies against the presented leaf, and the
    // delivered client_id is the hash of that leaf rather than of the service's own certificate.
    await expect(
      compactVerify(served, await importJWK(leaf.publicJwk.toJson() as JWK, "ES256")),
    ).resolves.toBeDefined();
    const delivered = decodeJwt(served).client_id as string;
    expect(delivered).toMatch(/^x509_hash:/);
    expect(delivered).not.toBe(session.authorization_request.client_id);
    expect(session.authorization_request.client_id).toMatch(/^x509_hash:/);
  });

  it("chains the untrusted root to the leaf it issued", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      request_behavior: { certificate_chain: "untrusted_root" },
    });

    const chain = decodeProtectedHeader(await deliveredRequestObject(app, session)).x5c as string[];
    const leaf = X509Certificate.fromEncodedCertificate(chain[0]);
    const root = X509Certificate.fromEncodedCertificate(chain[1]);

    expect(root.subject).toContain("untrusted-test-root.invalid");
    expect(leaf.issuer).toBe(root.subject);
    expect(root.issuer).toBe(root.subject);
  });

  it("keeps the generated request signed by the real certificate for verification", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      request_behavior: { certificate_chain: "unrelated_self_signed" },
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

    expect(response.status).toBe(200);
  });

  it.each([
    ["an unknown chain fixture", { certificate_chain: "expired" }],
    ["an unknown signing key", { signing_key: "rotated" }],
  ])("rejects %s", async (_label, behavior) => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({ request_behavior: behavior });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request_behavior" });
  });

  it("refuses a certificate chain fixture for a client identifier that is not x509_hash", async () => {
    const response = await request(createApp(scenarioConfig))
      .post("/openid4vp/sessions")
      .send({
        client_id_scheme: "decentralized_identifier",
        request_behavior: { certificate_chain: "untrusted_root" },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "certificate_chain_requires_x509_hash_client_id" });
  });

  describe("with_trust_anchor", () => {
    const validity = {
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2034-01-01T00:00:00Z"),
    };
    // The shared verifier certificate is self-signed; this data directory's is issued by a
    // generated CA, as a registry-issued access certificate is by the registry's CA.
    const anchoredDataDir = mkdtempSync(join(tmpdir(), "fake-issuer-trust-anchor-test-"));
    const anchoredConfig = { ...scenarioConfig, data_dir: anchoredDataDir };
    const sharedCaPath = verifierCaCertificatePath(dataDir);
    let caDer = "";

    async function testCa(commonName: string) {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true });
      const privateJwk = { ...(await exportJWK(privateKey)), kid: commonName } as JsonRecord;
      const { d: _private, ...publicJwk } = privateJwk;
      const authorityKey = Kms.PublicJwk.fromUnknown(publicJwk);
      authorityKey.keyId = commonName;
      const webCrypto = new CredoWebCrypto(
        createJwkSigningContext(privateJwk, commonName) as never,
      );
      const certificate = await X509Certificate.create(
        {
          authorityKey,
          issuer: { countryName: "IT", commonName },
          validity,
          extensions: {
            subjectKeyIdentifier: { include: true },
            keyUsage: { usages: [X509KeyUsage.KeyCertSign] },
            basicConstraints: { ca: true },
          },
        },
        webCrypto,
      );
      return { authorityKey, webCrypto, certificate };
    }

    beforeAll(async () => {
      await initIssuer({
        issuer_base_url: anchoredConfig.issuer_base_url,
        data_dir: anchoredDataDir,
        credential_configuration_id: anchoredConfig.credential_configuration_id,
        force: true,
      });
      const ca = await testCa("FCAF Test Trust Anchor");
      const { d: _private, ...verifierPublicJwk } = JSON.parse(
        readFileSync(verifierPrivateJwkPath(anchoredDataDir), "utf8"),
      ) as JsonRecord;
      const leaf = await X509Certificate.create(
        {
          authorityKey: ca.authorityKey,
          subjectPublicKey: Kms.PublicJwk.fromUnknown(verifierPublicJwk),
          issuer: { countryName: "IT", commonName: "FCAF Test Trust Anchor" },
          subject: { countryName: "IT", commonName: "issuer.example.test" },
          validity,
          extensions: {
            subjectKeyIdentifier: { include: true },
            authorityKeyIdentifier: { include: true },
            keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
            basicConstraints: { ca: false },
            subjectAlternativeName: { name: [{ type: "url", value: config.issuer_base_url }] },
          },
        },
        ca.webCrypto,
      );
      writeFileSync(verifierCertificatePath(anchoredDataDir), leaf.toString("pem"));
      writeFileSync(verifierCaCertificatePath(anchoredDataDir), ca.certificate.toString("pem"));
      caDer = Buffer.from(ca.certificate.rawCertificate).toString("base64");
    });

    afterEach(() => {
      rmSync(sharedCaPath, { force: true });
    });

    afterAll(() => {
      rmSync(anchoredDataDir, { recursive: true, force: true });
    });

    it("delivers the deployed leaf followed by the CA that issued it, under the same client_id", async () => {
      const app = createApp(anchoredConfig);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        response_mode: "direct_post",
        request_uri_method: "post",
        request_behavior: { certificate_chain: "with_trust_anchor" },
      });
      const deployedLeaf = readFileSync(verifierCertificatePath(anchoredDataDir), "utf8")
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, "");
      const requestPath = `/openid4vp/sessions/${session.session_id}/request`;
      const served = await request(app).post(requestPath).type("form").send({});
      const resigned = await request(app)
        .post(requestPath)
        .type("form")
        .send({ wallet_nonce: "trust-anchor-nonce" });

      expect(session.authorization_request.client_id).toBe(
        `x509_hash:${createHash("sha256").update(Buffer.from(deployedLeaf, "base64")).digest("base64url")}`,
      );
      for (const requestObject of [served.text, resigned.text]) {
        const chain = decodeProtectedHeader(requestObject).x5c as string[];
        expect(chain).toEqual([deployedLeaf, caDer]);
        const leaf = X509Certificate.fromEncodedCertificate(chain[0]);
        expect(leaf.issuer).toBe(X509Certificate.fromEncodedCertificate(chain[1]).subject);
        await expect(
          compactVerify(requestObject, await importJWK(leaf.publicJwk.toJson() as JWK, "ES256")),
        ).resolves.toBeDefined();
        expect(decodeJwt(requestObject).client_id).toBe(session.authorization_request.client_id);
      }
      expect(decodeJwt(resigned.text).wallet_nonce).toBe("trust-anchor-nonce");

      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.request_behavior).toEqual({ certificate_chain: "with_trust_anchor" });
      expect(decodeProtectedHeader(String(capture.raw?.authorization_request_jwt)).x5c).toEqual([
        deployedLeaf,
        caDer,
      ]);
    });

    it("still verifies a presentation a wallet sends anyway", async () => {
      const app = createApp(anchoredConfig);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        response_mode: "direct_post",
        presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
        request_behavior: { certificate_chain: "with_trust_anchor" },
      });
      const delivered = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
      const presentation = await sdJwtPresentation({
        credential: await pidSdJwtCredential(),
        authorizationRequest: delivered,
        disclosedClaims: ["family_name"],
      });

      const response = await request(app)
        .post(`/openid4vp/sessions/${session.session_id}/response`)
        .send({ state: delivered.state, vp_token: { query_0: [presentation] } });

      expect(response.status, JSON.stringify(response.body)).toBe(200);
    });

    it("refuses the control when no CA certificate is configured", async () => {
      const response = await request(createApp(scenarioConfig))
        .post("/openid4vp/sessions")
        .send({ request_behavior: { certificate_chain: "with_trust_anchor" } });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ error: "verifier_ca_certificate_not_configured" });
    });

    it("refuses a CA that did not issue the deployed verifier certificate", async () => {
      writeFileSync(sharedCaPath, (await testCa("Unrelated CA")).certificate.toString("pem"));
      const response = await request(createApp(scenarioConfig))
        .post("/openid4vp/sessions")
        .send({ request_behavior: { certificate_chain: "with_trust_anchor" } });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        error: "verifier_ca_certificate_invalid",
        error_description: expect.stringContaining(
          "the configured CA certificate does not validate the deployed verifier certificate",
        ),
      });
    });

    it("refuses a CA file that is not a certificate", async () => {
      writeFileSync(sharedCaPath, "not a certificate");
      const response = await request(createApp(scenarioConfig))
        .post("/openid4vp/sessions")
        .send({ request_behavior: { certificate_chain: "with_trust_anchor" } });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ error: "verifier_ca_certificate_invalid" });
    });

    it("still requires the x509_hash client identifier", async () => {
      const response = await request(createApp(anchoredConfig))
        .post("/openid4vp/sessions")
        .send({
          client_id_scheme: "decentralized_identifier",
          request_behavior: { certificate_chain: "with_trust_anchor" },
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: "certificate_chain_requires_x509_hash_client_id" });
    });
  });

  it("leaves ordinary sessions unmutated", async () => {
    const app = createApp(scenarioConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
    });

    const payload = decodeJwt(await deliveredRequestObject(app, session)) as JsonRecord;
    expect(payload.response_uri).toBe(session.response_uri);
    expect(payload.state).toBe(session.authorization_request.state);

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture).not.toHaveProperty("request_mutation");
    expect(capture.raw).not.toHaveProperty("authorization_request_delivered");
    expect(capture.events.map((event) => event.type)).not.toContain("vp_request_mutation_applied");
  });
});
