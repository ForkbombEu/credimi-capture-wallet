import { compactDecrypt, compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { PID_SD_JWT_VCT } from "../src/credentials/definitions.js";
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
const { config, pidSdJwtCredential } = serverTestSuite("fake-issuer-test-");
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

describe("capture issuer server", () => {
  it("creates OpenID4VP sessions with a valid presentation request", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });

    expect(session.status).toBe("created");
    expect(session.request_delivery).toBe("by_reference");
    expect(session.request_uri_method).toBe("get");
    expect(session.scheme).toBe("openid4vp://");
    expect(session.request_uri).toBe(
      `${config.issuer_base_url}/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(session.response_uri).toMatch(
      new RegExp(
        `^${escapeRegExp(
          `${config.issuer_base_url}/openid4vp/sessions/${session.session_id}/response`,
        )}`,
      ),
    );
    expect(session.deeplink).toContain("openid4vp://");
    expect(session.deeplink).toContain(encodeURIComponent(String(session.request_uri)));
    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("client_id")).toMatch(/^x509_hash:/);
    expect(deeplink.searchParams.get("request_uri")).toBe(session.request_uri);
    expect(deeplink.searchParams.has("request_uri_method")).toBe(false);
    expect(deeplink.searchParams.has("response_uri")).toBe(false);
    expect(deeplink.searchParams.has("client_id_scheme")).toBe(false);
    expect(deeplink.searchParams.has("response_type")).toBe(false);
    expect(session.authorization_request.response_type).toBe("vp_token");
    expect(session.authorization_request.response_mode).toBe("direct_post.jwt");
    expect(session.authorization_request.aud).toBe("https://self-issued.me/v2");
    expect(session.authorization_request.request_uri_method).toBeUndefined();
    expect(session.authorization_request.client_id).toMatch(/^x509_hash:/);
    expect(session.authorization_request.client_id_scheme).toBeUndefined();
    expect(session.authorization_request.scheme).toBeUndefined();
    expect(session.authorization_request.client_metadata).toMatchObject({
      jwks: { keys: [expect.objectContaining({ use: "enc", alg: "ECDH-ES" })] },
      encrypted_response_enc_values_supported: ["A128GCM", "A256GCM", "A128CBC-HS256"],
      vp_formats_supported: {
        "dc+sd-jwt": expect.objectContaining({
          "sd-jwt_alg_values": expect.arrayContaining(["ES256"]),
          "kb-jwt_alg_values": expect.arrayContaining(["ES256"]),
        }),
      },
    });
    expect(session.authorization_request.presentation_definition).toBeUndefined();
    expect(session.authorization_request.dcql_query).toEqual(expect.any(Object));
    const dcqlQuery = session.authorization_request.dcql_query as JsonRecord;
    const dcqlCredentials = dcqlQuery.credentials as JsonRecord[];
    const sdJwtCredential = dcqlCredentials.find((credential) => credential.format === "dc+sd-jwt");
    expect(sdJwtCredential?.meta).toEqual({ vct_values: [PID_SD_JWT_VCT] });
    expect((sdJwtCredential?.claims as JsonRecord[]).map((claim) => claim.path)).toEqual([
      ["family_name"],
      ["given_name"],
    ]);
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const delivered = decodeJwt(requestObject.text) as JsonRecord;
    expect(delivered.response_uri).toBe(session.response_uri);
    expect(delivered.redirect_uri).toBeUndefined();
  });

  it("delivers the holder-binding requirement in the signed DCQL query", async () => {
    const app = createApp(config);
    const dcqlQuery = dcqlForClaims(["family_name"]);
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];
    credential.require_cryptographic_holder_binding = false;

    const created = await request(app).post("/openid4vp/sessions").send({ dcql_query: dcqlQuery });
    expect(created.status, created.text).toBe(201);
    const session = created.body as VpSessionCreateResponse;
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const deliveredDcql = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;

    expect((deliveredDcql.credentials as JsonRecord[])[0]).toMatchObject({
      require_cryptographic_holder_binding: false,
    });
  });

  it("omits state from a signed request and verifies a response without it", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { state: null, dcql_query: dcqlForClaims(["family_name"]) },
    });

    expect(session.authorization_request).not.toHaveProperty("state");
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(decodeJwt(requestObject.text)).not.toHaveProperty("state");

    const presentation = await sdJwtPresentation({
      credential: await pidSdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: JSON.stringify({ query_0: [presentation] }) });

    expect(response.status, response.text).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks).toMatchObject({ presentation_valid: true, errors: [] });
  });

  it("omits state from an unsigned plain request", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      client_id_scheme: "redirect_uri",
      request_delivery: "plain",
      response_mode: "direct_post",
      state: null,
    });

    expect(session.authorization_request).not.toHaveProperty("state");
    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("nonce")).toBe(session.authorization_request.nonce);
    expect(deeplink.searchParams.has("state")).toBe(false);
  });

  it.each([
    ["with state", {}, 200],
    ["without state", { state: null }, 400],
  ])(
    "enforces Section 5.3 for an unbound credential requested %s",
    async (_label, override, status) => {
      const app = createApp(config);
      const dcqlQuery = dcqlForClaims(["family_name"]);
      (dcqlQuery.credentials as JsonRecord[])[0].require_cryptographic_holder_binding = false;
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        response_mode: "direct_post",
        presentation_request: { ...override, dcql_query: dcqlQuery },
      });
      const presentation = await sdJwtPresentation({
        credential: await pidSdJwtCredential(),
        authorizationRequest: session.authorization_request,
        disclosedClaims: ["family_name"],
      });

      const response = await request(app)
        .post(`/openid4vp/sessions/${session.session_id}/response`)
        .send({
          ...(session.authorization_request.state === undefined
            ? {}
            : { state: session.authorization_request.state }),
          vp_token: JSON.stringify({ query_0: [presentation] }),
        });

      expect(response.status, response.text).toBe(status);
      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      const stateRequired = capture.checks.errors.some((error) => error.includes("Section 5.3"));
      expect(capture.checks.presentation_valid).toBe(status === 200);
      expect(stateRequired).toBe(status === 400);
    },
  );

  it("rejects a state value other than null", async () => {
    const response = await request(createApp(config))
      .post("/openid4vp/sessions")
      .send({ state: "caller-chosen" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_state" });
  });

  it("creates OpenID4VP sessions that advertise request_uri_method post", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
      dcql_query: dcqlForClaims(["family_name"]),
    });

    const deeplink = new URL(session.deeplink);
    expect(session.request_uri_method).toBe("post");
    expect(deeplink.searchParams.get("request_uri_method")).toBe("post");
    expect(session.authorization_request.request_uri_method).toBeUndefined();
  });

  it("creates a signed x509_san_dns OpenID4VP request using the verifier certificate", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      client_id_scheme: "x509_san_dns",
    });

    expect(session.authorization_request.client_id).toBe("x509_san_dns:issuer.example.test");
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(decodeJwt(requestObject.text).client_id).toBe("x509_san_dns:issuer.example.test");
    expect(decodeProtectedHeader(requestObject.text).x5c).toEqual([expect.any(String)]);
  });

  it("creates an unsigned plain redirect_uri OpenID4VP request", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      client_id_scheme: "redirect_uri",
      request_delivery: "plain",
    });

    expect(session.authorization_request.client_id).toBe(
      `redirect_uri:${session.authorization_request.response_uri}`,
    );
    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("client_id")).toBe(session.authorization_request.client_id);
    expect(deeplink.searchParams.has("request")).toBe(false);
    expect(deeplink.searchParams.has("request_uri")).toBe(false);
  });

  it("creates a decentralized_identifier request signed by the verifier did:web key", async () => {
    const app = createApp(config);
    const didDocument = await request(app).get("/openid4vp/did.json");
    expect(didDocument.status).toBe(200);
    expect(didDocument.body.id).toBe("did:web:issuer.example.test:openid4vp");
    const created = await request(app)
      .post("/openid4vp/sessions")
      .send({ client_id_scheme: "decentralized_identifier" });
    expect(created.status).toBe(201);
    const session = created.body as VpSessionCreateResponse;
    expect(session.authorization_request.client_id).toBe(
      "decentralized_identifier:did:web:issuer.example.test:openid4vp",
    );
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(decodeProtectedHeader(requestObject.text)).toMatchObject({
      kid: "did:web:issuer.example.test:openid4vp#credimi-fake-verifier-did-key",
    });
    expect(decodeProtectedHeader(requestObject.text).x5c).toBeUndefined();
  });

  it.each(["x509_hash", "decentralized_identifier", "verifier_attestation"] as const)(
    "re-signs a wallet_nonce Request Object with the session's %s signer",
    async (clientIdScheme) => {
      const app = createApp(config);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        request_uri_method: "post",
        client_id_scheme: clientIdScheme,
      });
      const requestUriPath = new URL(String(session.request_uri)).pathname;
      const original = await request(app).post(requestUriPath).type("form").send({});
      const resigned = await request(app)
        .post(requestUriPath)
        .type("form")
        .send({ wallet_nonce: "wallet-supplied-nonce" });

      expect(decodeJwt(resigned.text).wallet_nonce).toBe("wallet-supplied-nonce");
      expect(decodeProtectedHeader(resigned.text)).toEqual(decodeProtectedHeader(original.text));
      if (clientIdScheme === "decentralized_identifier") {
        const didDocument = (await request(app).get("/openid4vp/did.json")).body;
        const didKey = await importJWK(didDocument.verificationMethod[0].publicKeyJwk, "ES256");
        await expect(compactVerify(resigned.text, didKey)).resolves.toBeDefined();
      }
    },
  );

  it("rejects signed delivery for redirect_uri OpenID4VP requests", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ client_id_scheme: "redirect_uri" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "redirect_uri_client_id_requires_plain_delivery" });
  });

  it("uses the requested custom scheme for a by-reference OpenID4VP deeplink", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      scheme: "eudi-wallet://",
    });

    expect(session.scheme).toBe("eudi-wallet://");
    expect(session.deeplink.startsWith("eudi-wallet://?")).toBe(true);
    const dcqlQuery = session.authorization_request.dcql_query as JsonRecord;
    expect((dcqlQuery.credentials as JsonRecord[]).map((credential) => credential.format)).toEqual([
      "dc+sd-jwt",
      "mso_mdoc",
    ]);
    expect(session.authorization_request.scheme).toBeUndefined();
  });

  it("creates OpenID4VP sessions that deliver the signed request object by value", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "by_value",
      dcql_query: dcqlForClaims(["family_name"]),
    });

    const deeplink = new URL(session.deeplink);
    const requestObject = deeplink.searchParams.get("request");
    expect(session.request_delivery).toBe("by_value");
    expect(deeplink.searchParams.get("client_id")).toBe(session.authorization_request.client_id);
    expect(deeplink.searchParams.has("request_uri")).toBe(false);
    expect(deeplink.searchParams.has("request_uri_method")).toBe(false);
    expect(requestObject).toEqual(expect.any(String));
    expect(decodeJwt(requestObject ?? "")).toMatchObject(session.authorization_request);
    expect(decodeProtectedHeader(requestObject ?? "")).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      x5c: [expect.any(String)],
    });
  });

  it("creates OpenID4VP sessions with a plain authorization request in the deeplink", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "plain",
      dcql_query: dcqlForClaims(["family_name"]),
    });

    const deeplink = new URL(session.deeplink);
    expect(session.request_delivery).toBe("plain");
    expect(deeplink.searchParams.get("client_id")).toBe(session.authorization_request.client_id);
    expect(deeplink.searchParams.get("response_type")).toBe("vp_token");
    expect(deeplink.searchParams.get("response_mode")).toBe("direct_post.jwt");
    expect(deeplink.searchParams.get("response_uri")).toBe(session.response_uri);
    expect(deeplink.searchParams.get("state")).toBe(session.authorization_request.state);
    expect(deeplink.searchParams.get("nonce")).toBe(session.authorization_request.nonce);
    expect(JSON.parse(String(deeplink.searchParams.get("dcql_query")))).toEqual(
      session.authorization_request.dcql_query,
    );
    expect(JSON.parse(String(deeplink.searchParams.get("client_metadata")))).toEqual(
      session.authorization_request.client_metadata,
    );
    expect(deeplink.searchParams.has("aud")).toBe(false);
    expect(deeplink.searchParams.has("request")).toBe(false);
    expect(deeplink.searchParams.has("request_uri")).toBe(false);
    expect(deeplink.searchParams.has("request_uri_method")).toBe(false);
  });

  it("omits DCQL from signed and plain authorization requests when requested", async () => {
    const app = createApp(config);
    const byReference = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      dcql_query: null,
    });
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${byReference.session_id}/request`,
    );
    const plain = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "plain",
      dcql_query: null,
    });
    const nested = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: null },
    });

    // The query is omitted from what the wallet receives, not from the verifier's own copy: the
    // response is matched against the request object this service signs.
    expect(decodeJwt(requestObject.text).dcql_query).toBeUndefined();
    expect(new URL(plain.deeplink).searchParams.has("dcql_query")).toBe(false);
    for (const session of [byReference, plain, nested]) {
      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.raw?.authorization_request_delivered?.dcql_query).toBeUndefined();
      expect(session.authorization_request.dcql_query).toBeDefined();
    }
  });

  it("uses caller-provided client metadata in the authorization request", async () => {
    const app = createApp(config);
    const clientMetadata = {
      vp_formats_supported: { "dc+sd-jwt": {} },
      wallet_test_extension: "custom",
    };
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      client_metadata: clientMetadata,
    });

    expect(session.authorization_request.client_metadata).toEqual(clientMetadata);
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect((decodeJwt(requestObject.text) as JsonRecord).client_metadata).toEqual(clientMetadata);
  });

  it("merges caller client metadata over the generated verifier metadata", async () => {
    const app = createApp(config);
    const generated = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {});
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      client_metadata: { encrypted_response_enc_values_supported: ["A128GCM"] },
    });

    const metadata = session.authorization_request.client_metadata as JsonRecord;
    expect(metadata.encrypted_response_enc_values_supported).toEqual(["A128GCM"]);
    expect(metadata.vp_formats_supported).toEqual(
      (generated.authorization_request.client_metadata as JsonRecord).vp_formats_supported,
    );
    expect(metadata.jwks).toMatchObject({
      keys: [expect.objectContaining({ kty: "EC", use: "enc", alg: "ECDH-ES" })],
    });
  });

  it("drops a client metadata member supplied as null", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      client_metadata: { encrypted_response_enc_values_supported: null },
    });

    const metadata = session.authorization_request.client_metadata as JsonRecord;
    expect(metadata).not.toHaveProperty("encrypted_response_enc_values_supported");
    expect(metadata.jwks).toMatchObject({ keys: [expect.objectContaining({ use: "enc" })] });
  });

  it("omits client metadata from a plain direct-post authorization request", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "plain",
      response_mode: "direct_post",
      client_metadata: null,
    });

    expect(session.authorization_request.client_metadata).toBeUndefined();
    expect(new URL(session.deeplink).searchParams.has("client_metadata")).toBe(false);
  });

  it("rejects omitted client metadata for encrypted presentation responses", async () => {
    const app = createApp(config);
    const response = await request(app).post("/openid4vp/sessions").send({
      client_metadata: null,
    });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      error: "client_metadata_required_for_encrypted_response",
    });
  });

  it("rejects encrypted response metadata that drops the verifier encryption key", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        client_metadata: { jwks: null },
      });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_client_metadata" });
  });

  it("publishes an encryption JWK without alg when undecryptable responses are allowed", async () => {
    const app = createApp(config);
    const clientMetadata = {
      jwks: {
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "zX1fqEBuE2Y-hQV4kXeudq4YmvE_k-hYl4Pk0CNBejI",
            y: "2DvtHPup4y8ob4tGqLGJwigMO5LdDBQ_hfzF8PBQwYQ",
            use: "enc",
          },
        ],
      },
      encrypted_response_enc_values_supported: ["A128GCM"],
    };
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post.jwt",
      client_metadata: clientMetadata,
      allow_undecryptable_response: true,
    });

    const published = session.authorization_request.client_metadata as JsonRecord;
    expect(published).toMatchObject(clientMetadata);
    expect((published.jwks as JsonRecord).keys).toEqual(clientMetadata.jwks.keys);
    expect(published).toHaveProperty("vp_formats_supported");
    const requestObject = await request(app).get(new URL(String(session.request_uri)).pathname);
    expect(decodeJwt(requestObject.text).client_metadata).toEqual(published);

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "vp_undecryptable_response_allowed",
          detail: { verifier_encryption_key_published: false },
        }),
      ]),
    );
  });

  it("rejects allowing undecryptable responses without replacement client metadata", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ allow_undecryptable_response: true });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      error: "allow_undecryptable_response_requires_client_metadata",
    });
  });

  it("rejects a non-boolean allow_undecryptable_response value", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ allow_undecryptable_response: "maybe", client_metadata: { jwks: { keys: [] } } });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_allow_undecryptable_response" });
  });

  it.each(["direct_post", "direct_post.jwt"] as const)(
    "keeps the post-submission redirect URI out of a %s Request Object",
    async (responseMode) => {
      const app = createApp(config);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        response_mode: responseMode,
        redirect_uri: "https://rp.example.test/complete?flow=wallet",
      });

      const redirectUri = new URL(String(session.redirect_uri));
      expect(redirectUri.origin).toBe("https://rp.example.test");
      expect(redirectUri.pathname).toBe("/complete");
      expect(redirectUri.searchParams.get("flow")).toBe("wallet");
      expect(
        Buffer.from(String(redirectUri.searchParams.get("response_code")), "base64url"),
      ).toHaveLength(16);
      const requestObject = await request(app).get(
        `/openid4vp/sessions/${session.session_id}/request`,
      );
      expect(decodeJwt(requestObject.text) as JsonRecord).not.toHaveProperty("redirect_uri");
    },
  );

  it("records visits to the capture redirect URI template and its concrete URI", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      redirect_uri: "{{base_url}}/openid4vp/redirect",
    });
    const redirectUri = new URL(String(session.redirect_uri));

    expect(redirectUri.origin).toBe(config.issuer_base_url);
    expect(redirectUri.pathname).toBe("/openid4vp/redirect");

    const visited = await request(app)
      .get(`${redirectUri.pathname}${redirectUri.search}`)
      .set("User-Agent", "capture-wallet-test");
    expect(visited.status).toBe(200);
    expect(visited.type).toBe("text/html");
    expect(visited.headers["cache-control"]).toBe("no-store");
    expect(visited.text).toContain("Presentation complete");
    expect(visited.text).toContain(
      `response_code</dt><dd><code>${redirectUri.searchParams.get("response_code")}</code>`,
    );
    expect(visited.text).toContain("This app is part of <strong>Credimi Extras</strong>");
    expect(visited.text).toContain('<header class="topbar">');
    expect(visited.text).toContain('<footer class="footer">');

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.redirect_uri_visited_at).toEqual(expect.any(String));
    expect(capture.redirect_uri_visit_count).toBe(1);
    expect(capture.events.at(-1)).toMatchObject({
      type: "vp_redirect_uri_visited",
      detail: { visit_count: 1 },
    });
    expect(capture.raw?.redirect_uri_visits).toEqual([
      {
        method: "GET",
        headers: expect.objectContaining({ "user-agent": "capture-wallet-test" }),
      },
    ]);

    const rejected = await request(app).get(`${redirectUri.pathname}?response_code=incorrect`);
    expect(rejected.status).toBe(404);
    expect(rejected.text).toContain("Redirect page not found");
    expect(rejected.text).toContain("response_code</dt><dd><code>incorrect</code>");
    const unchangedCapture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(unchangedCapture.redirect_uri_visit_count).toBe(1);

    const concreteSession = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      redirect_uri: `${config.issuer_base_url}/openid4vp/redirect`,
    });
    const concreteRedirectUri = new URL(String(concreteSession.redirect_uri));
    const concreteVisit = await request(app).get(
      `${concreteRedirectUri.pathname}${concreteRedirectUri.search}`,
    );
    expect(concreteVisit.status).toBe(200);
  });

  it("uses the requested custom scheme for a by-value OpenID4VP deeplink", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "by_value",
      scheme: "eudi-wallet://",
    });

    expect(session.scheme).toBe("eudi-wallet://");
    expect(session.deeplink.startsWith("eudi-wallet://?")).toBe(true);
  });

  it.each(["vp_token id_token", "code"])(
    "passes the requested response_type %s through to the authorization request",
    async (responseType) => {
      const app = createApp(config);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        response_type: responseType,
      });

      expect(session.authorization_request.response_type).toBe(responseType);
      const requestObject = await request(app).get(
        `/openid4vp/sessions/${session.session_id}/request`,
      );
      expect(decodeJwt(requestObject.text).response_type).toBe(responseType);
    },
  );

  it("lets the endpoint response_type override a presentation_request default", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_type: "code",
      presentation_request: { response_type: "vp_token" },
    });

    expect(session.authorization_request.response_type).toBe("code");
  });

  it("creates OpenID4VP sessions with unsupported request_uri_method values for wallet negative tests", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ request_uri_method: "put" });

    expect(response.status).toBe(201);
    expect(response.body.request_uri_method).toBe("put");
    expect(new URL(response.body.deeplink).searchParams.get("request_uri_method")).toBe("put");
  });

  it("rejects invalid OpenID4VP deeplink schemes", async () => {
    const app = createApp(config);
    const response = await request(app).post("/openid4vp/sessions").send({ scheme: "wallet" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_deeplink_scheme" });
  });

  it.each(["by_value", "plain"])(
    "rejects request_uri_method for %s OpenID4VP request delivery",
    async (requestDelivery) => {
      const app = createApp(config);
      const response = await request(app).post("/openid4vp/sessions").send({
        request_delivery: requestDelivery,
        request_uri_method: "post",
      });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        error: "request_uri_method_requires_by_reference_delivery",
      });
    },
  );

  it("rejects unsupported OpenID4VP request delivery values", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ request_delivery: "direct" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "unsupported_request_delivery" });
  });

  it("passes arbitrary DCQL queries through to OpenID4VP wallets", async () => {
    const app = createApp(config);
    const dcqlQuery = {
      credentials: [],
      credential_sets: [{ options: ["missing_credential"], required: true }],
      unknown_extension: { contradictory: true },
    };

    const response = await request(app).post("/openid4vp/sessions").send({ dcql_query: dcqlQuery });

    expect(response.status).toBe(201);
    expect(response.body.authorization_request.dcql_query).toEqual(dcqlQuery);
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${response.body.session_id}/request`,
    );
    expect(decodeJwt(requestObject.text).dcql_query).toEqual(dcqlQuery);
  });

  it("allows API callers to override the OpenID4VP presentation request", async () => {
    const app = createApp(config);
    const customDcql = {
      credentials: [
        {
          id: "email_credential",
          format: "dc+sd-jwt",
          meta: { vct_values: ["https://example.test/email"] },
          claims: [{ path: ["email"] }],
        },
      ],
    };

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        nonce: "external-nonce",
        dcql_query: customDcql,
      },
    });

    expect(session.authorization_request.nonce).toBe("external-nonce");
    expect(session.authorization_request.dcql_query).toEqual(customDcql);
    expect(session.authorization_request.state).toEqual(expect.any(String));
    expect(session.authorization_request.response_uri).toBe(session.response_uri);
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(decodeJwt(requestObject.text).nonce).toBe("external-nonce");
  });
  it("sets optional scope, transaction data, and verifier info in OpenID4VP requests", async () => {
    const app = createApp(config);
    const transactionData = ["eyJ0eXBlIjoiZXhhbXBsZSJ9"];
    const verifierInfo = [
      {
        format: "jwt",
        data: "example-verifier-attestation",
        credential_ids: ["query_0"],
      },
    ];

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      scopes: ["org.example.pid", "org.example.age_over_18"],
      transaction_data: transactionData,
      verifier_info: verifierInfo,
    });

    expect(session.authorization_request.scope).toBe("org.example.pid org.example.age_over_18");
    expect(session.authorization_request.transaction_data).toEqual(transactionData);
    expect(session.authorization_request.verifier_info).toEqual(verifierInfo);

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    expect(requestObjectClaims.scope).toBe("org.example.pid org.example.age_over_18");
    expect(requestObjectClaims.transaction_data).toEqual(transactionData);
    expect(requestObjectClaims.verifier_info).toEqual(verifierInfo);
  });
  it("encodes transaction data objects and delivers other entries unchanged", async () => {
    const app = createApp(config);
    const entry = {
      type: "qes_authorization",
      credential_ids: ["query_0"],
      transaction_data_hashes_alg: ["sha-256"],
      unknown_field: "kept so the Wallet can reject the decoded entry",
    };

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      transaction_data: [entry, "already.encoded.entry"],
    });

    const delivered = session.authorization_request.transaction_data as unknown[];
    expect(typeof delivered[0]).toBe("string");
    expect(JSON.parse(Buffer.from(delivered[0] as string, "base64url").toString())).toEqual(entry);
    expect(delivered[1]).toBe("already.encoded.entry");

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect((decodeJwt(requestObject.text) as JsonRecord).transaction_data).toEqual(delivered);
  });
  it("leaves a transaction data parameter that is not an array untouched", async () => {
    const app = createApp(config);

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      transaction_data: { type: "qes_authorization" },
    });

    expect(session.authorization_request.transaction_data).toEqual({
      type: "qes_authorization",
    });
  });
  it("delivers unencoded transaction data when a request mutation replaces the parameter", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      transaction_data: [{ type: "qes_authorization", credential_ids: ["query_0"] }],
      request_mutation: {
        request_object: { set: { "/transaction_data": [{ type: "qes_authorization" }] } },
      },
    });

    expect(typeof (session.authorization_request.transaction_data as unknown[])[0]).toBe("string");

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect((decodeJwt(requestObject.text) as JsonRecord).transaction_data).toEqual([
      { type: "qes_authorization" },
    ]);
  });
  it.each([
    ["A128GCM", "P-256"],
    ["A256GCM", "P-384"],
    ["A128CBC-HS256", "P-256"],
    ["A256GCM", "X25519"],
  ] as const)(
    "encrypts the Request Object with %s to a %s Wallet key from wallet_metadata",
    async (enc, crv) => {
      const app = createApp(config);
      const walletKey = await walletEncryptionKey(crv);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        request_uri_method: "post",
        response_mode: "direct_post",
        dcql_query: dcqlForClaims(["family_name"]),
      });

      const served = await request(app)
        .post(`/openid4vp/sessions/${session.session_id}/request`)
        .type("form")
        .send({
          wallet_nonce: "wallet-nonce-123",
          wallet_metadata: encryptingWalletMetadata(walletKey.publicJwk, enc),
        });

      expect(served.status).toBe(200);
      expect(served.type).toBe("application/oauth-authz-req+jwt");
      expect(served.text.split(".")).toHaveLength(5);
      const header = decodeProtectedHeader(served.text);
      expect(header).toMatchObject({ alg: "ECDH-ES", enc, cty: "JWT", kid: "wallet-enc-1" });
      expect(header.epk).toMatchObject({ crv });
      expect(header.epk).not.toHaveProperty("d");
      const { plaintext } = await compactDecrypt(served.text, walletKey.privateKey);
      const signedRequestObject = new TextDecoder().decode(plaintext);
      expect(decodeProtectedHeader(signedRequestObject).typ).toBe("oauth-authz-req+jwt");
      expect(decodeJwt(signedRequestObject).wallet_nonce).toBe("wallet-nonce-123");

      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.raw?.authorization_request_jwt).toBe(signedRequestObject);
      expect(capture.raw?.authorization_request_jwe).toBe(served.text);
      expect(
        capture.events.find((event) => event.type === "vp_request_object_encrypted"),
      ).toMatchObject({
        detail: {
          alg: "ECDH-ES",
          enc,
          kid: "wallet-enc-1",
          alg_source: "request_object",
          enc_source: "request_object",
        },
      });
    },
  );
  it.each([
    [
      "jwks alone, using the default",
      {},
      { enc: "A128GCM", alg_source: "default", enc_source: "default" },
    ],
    [
      "only authorization_encryption lists",
      {
        authorization_encryption_alg_values_supported: ["ECDH-ES"],
        authorization_encryption_enc_values_supported: ["XC20P", "A256GCM"],
      },
      {
        enc: "A256GCM",
        alg_source: "authorization_encryption",
        enc_source: "authorization_encryption",
      },
    ],
    [
      "request_object lists ahead of authorization_encryption ones, member by member",
      {
        request_object_encryption_enc_values_supported: ["A128CBC-HS256"],
        authorization_encryption_alg_values_supported: ["ECDH-ES"],
        authorization_encryption_enc_values_supported: ["A256GCM"],
      },
      {
        enc: "A128CBC-HS256",
        alg_source: "authorization_encryption",
        enc_source: "request_object",
      },
    ],
  ] as const)("negotiates Request Object encryption from %s", async (_label, lists, expected) => {
    const app = createApp(config);
    const walletKey = await walletEncryptionKey("P-256");
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
      response_mode: "direct_post",
    });

    const served = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/request`)
      .type("form")
      .send({
        wallet_metadata: JSON.stringify({ jwks: { keys: [walletKey.publicJwk] }, ...lists }),
      });

    expect(served.status).toBe(200);
    expect(decodeProtectedHeader(served.text)).toMatchObject({ alg: "ECDH-ES", enc: expected.enc });
    const { plaintext } = await compactDecrypt(served.text, walletKey.privateKey);
    expect(decodeProtectedHeader(new TextDecoder().decode(plaintext)).typ).toBe(
      "oauth-authz-req+jwt",
    );
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    const recorded = { alg: "ECDH-ES", kid: "wallet-enc-1", ...expected };
    expect(capture.request_object_encryption).toEqual(recorded);
    expect(
      capture.events.find((event) => event.type === "vp_request_object_encrypted")?.detail,
    ).toEqual(recorded);
  });
  it.each([
    [
      "an authorization_encryption alg list without ECDH-ES",
      {
        request_object_encryption_alg_values_supported: undefined,
        authorization_encryption_alg_values_supported: ["ECDH-ES+A256KW"],
      },
      "authorization_encryption_alg_values_supported does not include ECDH-ES",
    ],
    [
      "an authorization_encryption enc list without a supported value",
      {
        request_object_encryption_enc_values_supported: undefined,
        authorization_encryption_enc_values_supported: ["XC20P"],
      },
      "authorization_encryption_enc_values_supported lists none of A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512",
    ],
    [
      "no ECDH-ES key agreement",
      { request_object_encryption_alg_values_supported: ["ECDH-ES+A256KW"] },
      "request_object_encryption_alg_values_supported does not include ECDH-ES",
    ],
    [
      "only unsupported content encryption",
      { request_object_encryption_enc_values_supported: ["XC20P"] },
      "request_object_encryption_enc_values_supported lists none of A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512",
    ],
  ])(
    "refuses a Request Object encryption requirement with %s",
    async (_label, override, reason) => {
      const app = createApp(config);
      const walletKey = await walletEncryptionKey("P-256");
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        request_uri_method: "post",
        response_mode: "direct_post",
      });
      const metadata = {
        ...JSON.parse(encryptingWalletMetadata(walletKey.publicJwk, "A128GCM")),
        ...override,
      };

      const served = await request(app)
        .post(`/openid4vp/sessions/${session.session_id}/request`)
        .type("form")
        .send({ wallet_metadata: JSON.stringify(metadata) });

      expect(served.status).toBe(400);
      expect(served.body).toEqual({ error: "invalid_request", error_description: reason });
      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.raw?.request_uri_response_http).toMatchObject({ status: 400 });
      expect(
        capture.events.find((event) => event.type === "vp_request_object_encryption_unsupported"),
      ).toMatchObject({ detail: { reason } });
    },
  );
  it("captures the signed authorization request and wallet GET request_uri retrieval", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {});

    const requestObject = await request(app)
      .get(`/openid4vp/sessions/${session.session_id}/request?wallet=probe&x=%20y`)
      .set("User-Agent", "wallet-test-agent")
      .set("DPoP", "wallet-request-dpop-proof");

    expect(requestObject.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.authorization_request_jwt).toBe(requestObject.text);
    expect(capture.raw?.request_uri_http).toMatchObject({
      method: "GET",
      target: `/openid4vp/sessions/${session.session_id}/request?wallet=probe&x=%20y`,
      headers: {
        "user-agent": "wallet-test-agent",
        dpop: { redacted: true, present: true },
      },
    });
    expect(capture.raw?.request_uri_http?.body).toBeUndefined();
  });
});
