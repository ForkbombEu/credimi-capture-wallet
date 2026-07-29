import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Kms, X509Certificate } from "@credo-ts/core";
import { IssuerSigned } from "@owf/mdoc";
import type { Express } from "express";
import {
  CompactEncrypt,
  type JWK,
  type KeyLike,
  SignJWT,
  compactDecrypt,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CONFIG,
  initIssuer,
  issuerCertificatePath,
  jwksPath,
  privateJwkPath,
  verifierCertificatePath,
} from "../src/config.js";
import {
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "../src/credential-definitions.js";
import { CREDIMI_LOGO_URL, issueSdJwtCredential } from "../src/credential.js";
import { mdocCredentialConfigurationId } from "../src/metadata.js";
import { createApp } from "../src/server.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { unsignedJwt } from "./helpers.js";

const dataDir = mkdtempSync(join(tmpdir(), "fake-issuer-test-"));
const config = {
  ...DEFAULT_CONFIG,
  issuer_base_url: "http://issuer.example.test",
  data_dir: dataDir,
};

beforeAll(async () => {
  await initIssuer({
    issuer_base_url: config.issuer_base_url,
    data_dir: dataDir,
    credential_configuration_id: config.credential_configuration_id,
    force: true,
  });
});

afterAll(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("capture issuer server", () => {
  it("serves a Stoplight API documentation page and its OpenAPI contract", async () => {
    const app = createApp(config);

    const [docs, openApi] = await Promise.all([
      request(app).get("/docs"),
      request(app).get("/openapi.json"),
    ]);

    expect(docs.status).toBe(200);
    expect(docs.type).toBe("text/html");
    expect(docs.text).toContain("@stoplight/elements@9.0.0");
    expect(docs.text).toContain('apiDescriptionUrl="/openapi.json"');
    expect(openApi.status).toBe(200);
    expect(openApi.body).toMatchObject({
      openapi: "3.1.0",
      servers: [{ url: config.issuer_base_url }],
    });
    expect(openApi.body.tags).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "OpenID4VP" })]),
    );
    expect(openApi.body.paths["/openid4vp/sessions/{sessionId}/request"].get.tags).toEqual([
      "OpenID4VP",
    ]);
    expect(openApi.body.paths["/openid4vp/sessions/{sessionId}/request"].post.tags).toEqual([
      "OpenID4VP",
    ]);
    expect(openApi.body.paths["/openid4vp/sessions/{sessionId}/response"].post.tags).toEqual([
      "OpenID4VP",
    ]);
    expect(openApi.body.paths["/openid4vp/response"].post.tags).toEqual(["OpenID4VP"]);
    expect(
      openApi.body.paths["/.well-known/openid-credential-issuer"].get.responses["200"].content,
    ).toHaveProperty("application/jwt");
    expect(openApi.body.paths["/credential"].post.requestBody.content).toHaveProperty(
      "application/jwt",
    );
    expect(
      openApi.body.paths["/credential"].post.requestBody.content["application/json"].schema
        .properties.proofs.properties,
    ).toEqual(
      expect.objectContaining({
        jwt: expect.objectContaining({ minItems: 1, maxItems: 1 }),
        attestation: expect.objectContaining({ minItems: 1, maxItems: 1 }),
      }),
    );
    expect(openApi.body.paths["/credential"].post.responses["200"].content).toHaveProperty(
      "application/jwt",
    );
    expect(openApi.body.components.schemas.IssuanceSessionRequest.properties.broken).toMatchObject({
      type: "boolean",
      default: false,
    });
    expect(openApi.body.components.schemas.IssuanceSessionRequest.properties.flow).toMatchObject({
      enum: ["pre_authorized_code", "authorization_code"],
      default: "pre_authorized_code",
    });
    expect(Object.keys(openApi.body.paths)).toEqual(
      expect.arrayContaining([
        "/sessions",
        "/openid4vp/sessions",
        "/offers/{credentialOfferId}",
        "/par",
        "/authorize",
        "/redirect",
        "/fake-oauth/authorize",
        "/fake-oauth/token",
        "/token",
        "/credential",
      ]),
    );
    expect(openApi.body.paths).not.toHaveProperty("/init");
    expect((await request(app).post("/init").send({ force: true })).status).toBe(404);
  });

  it("returns signed issuer metadata when the wallet requests application/jwt", async () => {
    const app = createApp(config);
    const [defaultMetadata, unsignedMetadata, signedMetadata] = await Promise.all([
      request(app).get("/.well-known/openid-credential-issuer"),
      request(app).get("/.well-known/openid-credential-issuer").set("Accept", "application/json"),
      request(app).get("/.well-known/openid-credential-issuer").set("Accept", "application/jwt"),
    ]);

    expect(defaultMetadata.status).toBe(200);
    expect(defaultMetadata.type).toBe("application/json");
    expect(defaultMetadata.headers.vary).toBe("Accept");
    expect(defaultMetadata.body).toEqual(unsignedMetadata.body);
    expect(unsignedMetadata.body).not.toHaveProperty("authorization_servers");
    expect(unsignedMetadata.body.credential_request_encryption).toMatchObject({
      jwks: {
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            alg: "ECDH-ES",
            use: "enc",
            kid: "credimi-fake-issuer-encryption-key",
          },
        ],
      },
      enc_values_supported: ["A256GCM"],
      encryption_required: false,
    });
    expect(unsignedMetadata.body.credential_request_encryption.jwks.keys[0]).not.toHaveProperty(
      "d",
    );
    expect(unsignedMetadata.body.credential_response_encryption).toEqual({
      alg_values_supported: ["ECDH-ES"],
      enc_values_supported: ["A256GCM"],
      encryption_required: false,
    });
    expect(signedMetadata.status).toBe(200);
    expect(signedMetadata.type).toBe("application/jwt");

    const protectedHeader = decodeProtectedHeader(signedMetadata.text);
    expect(protectedHeader).toMatchObject({
      alg: "ES256",
      typ: "openidvci-issuer-metadata+jwt",
      x5c: [expect.any(String)],
    });
    expect(protectedHeader.kid).toBeUndefined();
    const leafCertificate = Array.isArray(protectedHeader.x5c) ? protectedHeader.x5c[0] : undefined;
    if (typeof leafCertificate !== "string") throw new Error("expected x5c leaf certificate");
    const certificate = X509Certificate.fromEncodedCertificate(leafCertificate);
    const verified = await compactVerify(
      signedMetadata.text,
      await importJWK(certificate.publicJwk.toJson(), "ES256"),
    );
    const { iss, sub, iat, ...metadataClaims } = JSON.parse(
      Buffer.from(verified.payload).toString("utf8"),
    ) as JsonRecord;

    expect(iss).toBe(config.issuer_base_url);
    expect(sub).toBe(config.issuer_base_url);
    expect(iat).toEqual(expect.any(Number));
    expect(metadataClaims).toEqual(unsignedMetadata.body);
    expect(metadataClaims.authorization_servers).toBeUndefined();
  });

  it("advertises the implemented pre-authorized and authorization-code grants", async () => {
    const app = createApp(config);
    const metadata = await getJson<JsonRecord>(app, "/.well-known/oauth-authorization-server");

    expect(metadata.grant_types_supported).toEqual([
      "authorization_code",
      "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ]);
    expect(metadata.token_endpoint).toBe(`${config.issuer_base_url}/token`);
    expect(metadata.authorization_endpoint).toBe(`${config.issuer_base_url}/authorize`);
    expect(metadata.pushed_authorization_request_endpoint).toBe(`${config.issuer_base_url}/par`);
    expect(metadata.require_pushed_authorization_requests).toBe(true);
    expect(metadata.response_types_supported).toEqual(["code"]);
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
    expect(metadata.token_endpoint_auth_methods_supported).toEqual([
      "none",
      "attest_jwt_client_auth",
    ]);
    expect(metadata.client_attestation_signing_alg_values_supported).toEqual(["ES256"]);
    expect(metadata.client_attestation_pop_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("publishes metadata for the auto-approving chained OAuth server", async () => {
    const app = createApp(config);
    const metadata = await getJson<JsonRecord>(
      app,
      "/.well-known/oauth-authorization-server/fake-oauth",
    );

    expect(metadata).toMatchObject({
      issuer: `${config.issuer_base_url}/fake-oauth`,
      authorization_endpoint: `${config.issuer_base_url}/fake-oauth/authorize`,
      token_endpoint: `${config.issuer_base_url}/fake-oauth/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post"],
    });
  });

  it("selects the signed metadata certificate chain by issuer public key", async () => {
    const isolatedDataDir = mkdtempSync(join(tmpdir(), "signed-metadata-test-"));
    try {
      const isolatedConfig = await initIssuer({
        issuer_base_url: config.issuer_base_url,
        data_dir: isolatedDataDir,
        force: true,
      });
      const jwks = JSON.parse(readFileSync(jwksPath(isolatedDataDir), "utf8")) as {
        keys: JsonRecord[];
      };
      const { kid: _kid, ...issuerJwk } = jwks.keys[0] ?? {};
      const additionalCertificate = readFileSync(verifierCertificatePath(isolatedDataDir), "utf8")
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s+/g, "");
      const issuerCertificateChain = Array.isArray(issuerJwk.x5c)
        ? issuerJwk.x5c.filter(
            (certificate): certificate is string => typeof certificate === "string",
          )
        : [];
      expect(issuerCertificateChain).not.toHaveLength(0);
      const certificateChain = [...issuerCertificateChain, additionalCertificate];
      issuerJwk.x5c = certificateChain;

      const { publicKey } = await generateKeyPair("ES256");
      const unrelatedJwk = (await exportJWK(publicKey)) as unknown as JsonRecord;
      unrelatedJwk.kid = "unrelated-key";
      unrelatedJwk.x5c = [additionalCertificate];
      writeFileSync(jwksPath(isolatedDataDir), JSON.stringify({ keys: [unrelatedJwk, issuerJwk] }));

      const response = await request(createApp(isolatedConfig))
        .get("/.well-known/openid-credential-issuer")
        .set("Accept", "application/jwt");

      expect(response.status).toBe(200);
      const protectedHeader = decodeProtectedHeader(response.text);
      expect(protectedHeader.kid).toBeUndefined();
      expect(protectedHeader.x5c).toEqual(certificateChain);
    } finally {
      rmSync(isolatedDataDir, { recursive: true, force: true });
    }
  });

  it("serves a launcher button that opens new GUI sessions in a new tab", async () => {
    const app = createApp(config);
    const response = await request(app).get("/");

    expect(response.status).toBe(200);
    expect(response.text).toContain('<main><section class="hero-band">');
    expect(response.text).toContain(
      "Step 1) Start a one-time fake issuance flow, scan the offer, and inspect the wallet identifiers, callbacks, and proof keys observed by the issuer.",
    );
    expect(response.text).toContain(
      "Step 2) After receiving the credential, start a Presentation session, and inspect the Wallet response as well as the DCQL",
    );
    expect(response.text).toContain("New fake-issuance session");
    expect(response.text).toContain('<a class="btn btn-outline btn-md" href="/docs">API docs</a>');
    expect(response.text).toContain("session-actions");
    expect(response.text).toContain('formaction="/ui/openid4vp/sessions"');
    expect(response.text).toContain("<h2>Captured values</h2>");
    expect(response.text).toContain('<span class="count-chip">10</span>');
    expect(response.text).toContain("<h3>OpenID4VCI</h3>");
    expect(response.text).toContain("<h3>OpenID4VP</h3>");
    expect(response.text).toContain("<dt>wallet_jwks</dt>");
    expect(response.text).toContain("<dt>authorization_request</dt>");
    expect(response.text).toContain("<dt>request_uri_payload</dt>");
    expect(response.text).toContain("<dt>wallet_response</dt>");
    expect(response.text).toContain("<dt>presentation_response_decrypted</dt>");
    expect(response.text).toContain("<dt>decoded_presentations</dt>");
    expect(response.text).toContain("<dt>presentation_validation</dt>");
    expect(response.text).not.toContain("<dt>presentation_submission</dt>");
    expect(response.text).toContain('<select name="credential_configuration_id">');
    expect(response.text).toContain("Credimi Demo PID (SD-JWT VC, JWT or attestation proof)");
    expect(response.text).toContain("Credimi Demo PID (MDOC, JWT or attestation proof)");
    expect(response.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="Credimi"><span>Wallet metadata capture</span>',
    );
    expect(response.text).toContain(
      '<span class="status-chip status-issuer">ISSUER READY</span><span class="status-chip status-wallet">VERIFIER READY</span><a class="btn btn-outline btn-md" href="/docs">API docs</a><a class="btn btn-outline btn-md" href="/openapi.json" download="openapi.json">OpenAPI</a><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/credimi-capture-wallet"',
    );
    expect(response.text).toContain('target="_blank"');
    expect(response.text).toContain("Wallet metadata capture%c Credimi capture UI");
    expect(response.text).toContain('href="/favicon.svg"');
    expect(response.text).not.toContain("Developed by Forkbomb BV");
    expect(response.text).toContain('href="https://github.com/ForkbombEu/credimi-capture-wallet"');
    expect(response.text).toContain("Repository");
    expect(response.text).toContain(
      '<img class="footer-logo" src="/assets/credimi_logo_negative.svg" alt="" aria-hidden="true">',
    );
  });

  it("serves the Credimi logo asset for the launcher topbar", async () => {
    const app = createApp(config);
    const response = await request(app).get("/assets/credimi_logo.svg");

    expect(response.status).toBe(200);
    expect(response.type).toBe("image/svg+xml");
    expect(response.body.toString("utf8")).toContain("<svg");
  });

  it("serves the negative Credimi logo asset for the footer", async () => {
    const app = createApp(config);
    const response = await request(app).get("/assets/credimi_logo_negative.svg");

    expect(response.status).toBe(200);
    expect(response.type).toBe("image/svg+xml");
    expect(response.body.toString("utf8")).toContain("<svg");
  });

  it("renders README help with the GUI stylesheet", async () => {
    const app = createApp(config);
    const response = await request(app).get("/ui/help");

    expect(response.status).toBe(200);
    expect(response.text).toContain("Wallet Metadata Capture Help");
    expect(response.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(response.text).toContain("Credimi Capture Wallet Metadata");
    expect(response.text).toContain("readme-card");
  });

  it("can disable GUI routes while leaving API routes available", async () => {
    const app = createApp({ ...config, gui_enabled: false });

    expect((await request(app).get("/")).status).toBe(404);
    expect((await request(app).get("/ui/help")).status).toBe(404);
    expect((await request(app).post("/ui/sessions")).status).toBe(404);
    expect((await request(app).get("/docs")).status).toBe(200);
    expect((await request(app).get("/openapi.json")).status).toBe(200);

    const apiSession = await request(app).post("/sessions").send({});
    expect(apiSession.status).toBe(201);
  });

  it("creates GUI sessions and renders a QR deeplink page", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);

    expect(created.status).toBe(303);
    expect(created.headers.location).toMatch(/^\/ui\/sessions\//);

    const page = await request(app).get(created.headers.location ?? "");
    expect(page.status).toBe(200);
    expect(page.text).toContain("<svg");
    expect(page.text).toContain("openid-credential-offer://");
    expect(page.text).toContain("Scan the credential offer");
    expect(page.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(page.text).toContain("Scan the offer and accept it in the wallet");
    expect(page.text).toContain('<a class="btn btn-outline btn-md" href="/docs">API docs</a>');
    expect(page.text).toContain(
      '<a class="btn btn-outline btn-md" href="/openapi.json" download="openapi.json">OpenAPI</a>',
    );
    expect(page.text).toContain("Same content as the QR code");
    expect(page.text).toContain("metadata-pending");
    expect(page.text).toContain("metadata-state-waiting");
    expect(page.text).toContain("metadata-state-receiving");
    expect(page.text).toContain("credentialRequestArrived");
    expect(page.text).toContain("window.clearInterval(pollTimer)");
    expect(page.text).toContain("pollTimer = setInterval");
    expect(page.text).toContain(
      '<span class="status-chip status-issuer" id="status-label">waiting</span><a class="btn btn-outline btn-md" href="/docs">API docs</a><a class="btn btn-outline btn-md" href="/openapi.json" download="openapi.json">OpenAPI</a><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/credimi-capture-wallet"',
    );
    expect(page.text).not.toContain("updated-label");
    expect(page.text).toContain("Wallet metadata");
    expect(page.text).toContain(".metadata-row summary::after { content: '\\02C5'");
    expect(page.text).toContain(".metadata-row[open] summary::after { content: '\\02C4'");
    expect(page.text.match(/<details class="metadata-row"><summary>/g)).toHaveLength(4);
    expect(page.text).toContain("<summary>client_id</summary><code>pending</code>");
    expect(page.text).toContain('querySelectorAll(".metadata-row[open]")');
    expect(page.text).toContain("openFields.has(row[0])");
  });

  it("creates GUI OpenID4VP sessions and renders a presentation QR page", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/openid4vp/sessions").redirects(0);

    expect(created.status).toBe(303);
    expect(created.headers.location).toMatch(/^\/ui\/openid4vp\/sessions\//);

    const page = await request(app).get(created.headers.location ?? "");
    expect(page.status).toBe(200);
    expect(page.text).toContain("<svg");
    expect(page.text).toContain("openid4vp://");
    expect(page.text).toContain("Scan the presentation request");
    expect(page.text).toContain("Presentation response");
    expect(page.text).toContain("authorization_request");
    expect(page.text).toContain("request_uri_payload");
    expect(page.text).toContain("wallet_response");
    expect(page.text).toContain("presentation_response_decrypted");
    expect(page.text).not.toContain("presentation_submission");
    expect(page.text).toContain("formatJsonValue(session.authorization_request)");
    expect(page.text).toContain("formatJsonValue(session.raw.presentation_response_decrypted)");
    expect(page.text).toContain("formatJsonValue(session.raw.decoded_presentations)");
    expect(page.text).toContain("JSON.stringify(parsed, null, 4)");
    expect(page.text).toContain(".metadata-row summary::after { content: '\\02C5'");
    expect(page.text).toContain(".metadata-row[open] summary::after { content: '\\02C4'");
    expect(page.text).toContain("white-space: pre-wrap");
    expect(page.text.indexOf("authorization_request")).toBeLessThan(
      page.text.indexOf("request_uri_payload"),
    );
    expect(page.text.indexOf("request_uri_payload")).toBeLessThan(
      page.text.indexOf("wallet_response"),
    );
    expect(page.text).toContain("window.clearInterval(pollTimer)");
    expect(page.text).toContain("pollTimer = setInterval");
    expect(page.text).toContain("__FAKE_ISSUER_VP_SESSION_ID__");
    expect(page.text.match(/<details class="metadata-row"><summary>/g)).toHaveLength(6);
    expect(page.text).toContain(
      "<summary>presentation_response_decrypted</summary><code>pending</code>",
    );
    expect(page.text).toContain("<summary>decoded_presentations</summary><code>pending</code>");
    expect(page.text).toContain("<summary>presentation_validation</summary><code>pending</code>");
    expect(page.text).toContain('querySelectorAll(".metadata-row[open]")');
    expect(page.text).toContain("openFields.has(row[0])");
  });

  it("creates GUI OpenID4VP sessions for the selected credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = mdocCredentialConfigurationId(config);
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    const dcqlQuery = requestObjectClaims.dcql_query as JsonRecord;
    const dcqlCredentials = dcqlQuery.credentials as JsonRecord[];

    expect(requestObjectClaims.presentation_definition).toBeUndefined();
    expect(dcqlCredentials).toHaveLength(1);
    expect(dcqlCredentials[0]?.format).toBe("mso_mdoc");
    expect(dcqlCredentials[0]?.meta).toEqual({ doctype_value: PID_MDOC_DOCTYPE });
    expect((dcqlCredentials[0]?.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
    );
  });

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
    expect(session.deeplink).toContain(encodeURIComponent(session.request_uri));
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

  it("uses the requested custom scheme for a by-reference OpenID4VP deeplink", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      scheme: "eudi-wallet://",
    });

    expect(session.scheme).toBe("eudi-wallet://");
    expect(session.deeplink.startsWith("eudi-wallet://?")).toBe(true);
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

  it("rejects unsupported OpenID4VP request_uri_method values", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ request_uri_method: "put" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "unsupported_request_uri_method" });
  });

  it("rejects invalid OpenID4VP deeplink schemes", async () => {
    const app = createApp(config);
    const response = await request(app).post("/openid4vp/sessions").send({ scheme: "wallet" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_deeplink_scheme" });
  });

  it("rejects request_uri_method for by-value OpenID4VP request delivery", async () => {
    const app = createApp(config);
    const response = await request(app).post("/openid4vp/sessions").send({
      request_delivery: "by_value",
      request_uri_method: "post",
    });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      error: "request_uri_method_requires_by_reference_delivery",
    });
  });

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

    expect(session.authorization_request.nonce).toEqual(expect.any(String));
    expect(session.authorization_request.dcql_query).toEqual(customDcql);
    expect(session.authorization_request.state).toEqual(expect.any(String));
    expect(session.authorization_request.response_uri).toBe(session.response_uri);
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

  it("serves OpenID4VP request_uri objects and captures invalid wallet presentation responses", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name"]),
      },
    });

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect(requestObject.status).toBe(200);
    expect(requestObject.type).toBe("application/oauth-authz-req+jwt");
    const requestObjectHeader = decodeProtectedHeader(requestObject.text);
    const verifierCertificate = X509Certificate.fromEncodedCertificate(
      (requestObjectHeader.x5c as string[])[0],
    );
    expect(requestObjectHeader).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      x5c: [expect.any(String)],
    });
    const verified = await compactVerify(
      requestObject.text,
      await importJWK(verifierCertificate.publicJwk.toJson() as JWK, "ES256"),
    );
    expect(verified.protectedHeader.typ).toBe("oauth-authz-req+jwt");
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    expect(requestObjectClaims.state).toBe(session.authorization_request.state);
    expect(requestObjectClaims.aud).toBe(session.authorization_request.aud);
    expect(requestObjectClaims.presentation_definition).toBeUndefined();
    expect(requestObjectClaims.client_id).toBe(
      `x509_hash:${createHash("sha256")
        .update(Buffer.from((requestObjectHeader.x5c as string[])[0], "base64"))
        .digest("base64url")}`,
    );

    const retrieved = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(retrieved.status).toBe("request_retrieved");

    const presentation = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: "presentation-token",
      });
    expect(presentation.status).toBe(400);
    expect(presentation.body).toMatchObject({ error: "invalid_presentation" });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.observed.vp_token).toBeUndefined();
    expect(capture.observed.wallet_response.value?.vp_token).toBe("presentation-token");
    expect(capture.observed.presentation_submission).toBeUndefined();
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.length).toBeGreaterThan(0);
    expect(capture.raw?.presentation_response?.state).toBe(session.authorization_request.state);
  });

  it("rejects SD-JWT VC presentations that do not disclose all requested DCQL claims", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: JSON.stringify({ query_0: [presentation] }),
      });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_presentation" });
    expect(JSON.stringify(response.body.errors)).toContain("Presentation submission");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.nonce_verified).toBe(false);
    expect(capture.checks.holder_binding_verified).toBe(false);
    expect(capture.checks.dcql_query_matched).toBe(false);
  });

  it("accepts SD-JWT VC presentations that satisfy holder binding, nonce, and DCQL", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name", "given_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          state: session.authorization_request.state,
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({});

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks).toMatchObject({
      presentation_valid: true,
      nonce_verified: true,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
    expect(capture.raw?.presentation_response).toEqual({ response: expect.any(String) });
    expect(capture.raw?.presentation_response_decrypted).toMatchObject({
      state: session.authorization_request.state,
      vp_token: { query_0: [presentation] },
    });
    expect(capture.decoded_presentations).toMatchObject({
      query_0: [
        {
          format: "dc+sd-jwt",
          claims: {
            vct: PID_SD_JWT_VCT,
            family_name: "Rossi",
            given_name: "Mario",
          },
        },
      ],
    });
    expect(capture.raw?.decoded_presentations).toEqual(capture.decoded_presentations);
    expect(JSON.stringify(capture.decoded_presentations)).not.toContain(presentation);
  });

  it("accepts SD-JWT VC presentations that satisfy a required DCQL credential_set option", async () => {
    const app = createApp(config);
    const dcqlQuery = {
      credentials: [
        {
          id: "pid_sd",
          format: "dc+sd-jwt",
          meta: { vct_values: [PID_SD_JWT_VCT] },
          claims: [{ path: ["family_name"] }],
        },
        {
          id: "pid_alt",
          format: "dc+sd-jwt",
          meta: { vct_values: [PID_SD_JWT_VCT] },
          claims: [{ path: ["given_name"] }],
        },
      ],
      credential_sets: [
        {
          options: [["pid_sd"], ["pid_alt"]],
        },
      ],
    };
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlQuery,
      },
    });
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: JSON.stringify({ pid_sd: [presentation] }),
      });

    expect(response.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.dcql_query_matched).toBe(true);
    expect(capture.raw?.presentation_response_decrypted?.vp_token).toEqual({
      pid_sd: [presentation],
    });
  });

  it("captures OpenID4VP request_uri POST payloads", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
      dcql_query: dcqlForClaims(["family_name"]),
    });

    const requestObject = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/request`)
      .type("form")
      .send({ wallet_nonce: "wallet-nonce-123", wallet_metadata: "present" });

    expect(requestObject.status).toBe(200);
    expect(requestObject.type).toBe("application/oauth-authz-req+jwt");
    const claims = decodeJwt(requestObject.text) as JsonRecord;
    expect(claims.wallet_nonce).toBe("wallet-nonce-123");

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.observed.request_uri_payload.value).toMatchObject({
      wallet_nonce: "wallet-nonce-123",
      wallet_metadata: "present",
    });
    expect(capture.observed.request_uri_payload.source).toBe("request_uri.post");
    expect(capture.authorization_request.wallet_nonce).toBe("wallet-nonce-123");
  });

  it("creates GUI sessions backed by a Credo credential offer", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    const initial = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(initial.status).toBe("created");
    expect(initial.broken).toBe(false);

    const deeplink = await getJson<{ deeplink: string }>(app, `/sessions/${sessionId}/deeplink`);
    const offerUri = new URL(deeplink.deeplink).searchParams.get("credential_offer_uri");
    const offer = await request(app).get(new URL(offerUri ?? "").pathname);
    expect(offer.status).toBe(200);

    const consumed = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(consumed.status).toBe("offer_retrieved");
  });
  it("creates session offers for the requested credential configuration", async () => {
    const app = createApp(config);
    const requestedCredentialConfigurationId = mdocCredentialConfigurationId(config);

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: requestedCredentialConfigurationId,
    });
    const offer = await getJson<CredentialOfferResponse>(
      app,
      `/sessions/${session.session_id}/offer`,
    );

    expect(session.credential_configuration_id).toBe(requestedCredentialConfigurationId);
    expect(session.flow).toBe("pre_authorized_code");
    expect(session.broken).toBe(false);
    expect(offer.credential_configuration_ids).toEqual([requestedCredentialConfigurationId]);
  });

  it("records the requested broken credential fixture and rejects non-boolean values", async () => {
    const app = createApp(config);

    const brokenSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      broken: true,
    });
    const capture = await getJson<SessionCapture>(app, `/sessions/${brokenSession.session_id}`);
    const invalid = await request(app).post("/sessions").send({ broken: "true" });

    expect(brokenSession.broken).toBe(true);
    expect(capture.broken).toBe(true);
    expect(capture.events[0]?.detail.broken).toBe(true);
    expect(invalid.status).toBe(400);
    expect(invalid.body).toEqual({
      error: "invalid_request",
      error_description: "'broken' must be a boolean",
    });
  });

  it("serves Credo authorization-server JWKS without private material", async () => {
    const app = createApp(config);
    const jwks = await getJson<JwksResponse>(app, "/jwks.json");

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("issues an MDOC PID credential for the selected MDOC configuration", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: mdocCredentialConfigurationId(config),
    });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const walletKey = await dpopKey();
    const refreshedNonce = await request(app).post("/nonce");
    expect(refreshedNonce.status).toBe(200);
    const proof = await keyAttestationJwt(walletKey, String(refreshedNonce.body.c_nonce));

    const credential = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", "/credential", token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { attestation: [proof] },
      });

    expect(
      credential.status,
      JSON.stringify({ body: credential.body, headers: credential.headers, text: credential.text }),
    ).toBe(200);
    const encodedMdoc = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = IssuerSigned.fromEncodedForOid4Vci(encodedMdoc);

    expect(session.credential_configuration_id).toBe(mdocCredentialConfigurationId(config));
    expect(decoded.issuerAuth.mobileSecurityObject.docType).toBe(PID_MDOC_DOCTYPE);
    const namespace = decoded.getPrettyClaims(PID_MDOC_NAMESPACE) as JsonRecord | undefined;
    expect(namespace?.given_name).toBe("Mario");
    expect(namespace?.family_name).toBe("Rossi");
    expect(namespace?.place_of_birth).toEqual(new Map([["locality", "Roma"]]));
    expect(namespace?.resident_country).toBe("IT");
    const portrait = namespace?.portrait;
    expect(portrait).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(portrait as Uint8Array).subarray(0, 3)).toEqual(
      Buffer.from([0xff, 0xd8, 0xff]),
    );
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("credential_issued");
    expect(capture.checks.proof_attestation_present).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(true);
    expect(capture.observed.wallet_jwks.source).toBe("credo.verified_holder_binding");
  });

  it("captures and correlates pre-authorized requests with secrets redacted", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const preAuthorizedCode = String(grant["pre-authorized_code"]);
    const dpopKeyPair = await dpopKey();
    const dpop = await dpopProof(dpopKeyPair, "POST", "/token");

    const token = await request(app).post("/token").set("DPoP", dpop).type("form").send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode,
    });

    expect(token.status).toBe(200);
    const ledger = await getJson<Array<JsonRecord>>(app, "/oid4vci/requests");
    const tokenCapture = ledger.find((entry) => entry.path === "/token");
    expect(tokenCapture).toMatchObject({
      method: "POST",
      session_id: session.session_id,
      headers: { dpop: { redacted: true, present: true } },
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": { redacted: true, present: true },
      },
      response: { status: 200 },
    });
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.raw?.oid4vci_requests?.map((entry) => entry.path)).toEqual(
      expect.arrayContaining([new URL(session.offer_url).pathname, "/token"]),
    );
    expect(JSON.stringify(ledger)).not.toContain(preAuthorizedCode);
    expect(JSON.stringify(ledger)).not.toContain(dpop);
  });

  it("makes credential nonce responses uncacheable", async () => {
    const app = createApp(config);
    const response = await request(app).post("/nonce");

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toMatchObject({
      c_nonce: expect.any(String),
    });
  });

  it("rejects token requests without DPoP", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const response = await request(app)
      .post("/token")
      .type("form")
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": String(grant["pre-authorized_code"]),
      });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "invalid_dpop_proof" });
  });

  it("uses Credo to verify a draft-07 wallet attestation PoP without exp", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const walletInstanceKey = await dpopKey();
    const clientId = "https://wallet.example.test";
    const walletAttestation = await walletAttestationJwt(walletInstanceKey, clientId);
    const walletAttestationPop = await walletAttestationPopJwt(walletInstanceKey, clientId);
    const dpop = await dpopKey();

    const response = await request(app)
      .post("/token")
      .set("DPoP", await dpopProof(dpop, "POST", "/token"))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set("OAuth-Client-Attestation-PoP", walletAttestationPop)
      .type("form")
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": String(grant["pre-authorized_code"]),
      });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body).toMatchObject({
      access_token: expect.any(String),
      token_type: "DPoP",
    });
  });

  it("uses Credo to verify JWT proof, key attestation, nonce, and holder binding", async () => {
    const app = createApp(config);
    const invalidSession = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const invalidDpop = await dpopKey();
    const invalidToken = await preAuthorizedToken(app, invalidSession, invalidDpop);
    const walletKey = await dpopKey();
    const unrelatedAttestedKey = await dpopKey();
    const mismatchedProof = await credentialProofJwt(
      walletKey,
      invalidToken.c_nonce,
      config.issuer_base_url,
      unrelatedAttestedKey,
    );
    const mismatchedCredential = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${invalidToken.access_token}`)
      .set("DPoP", await dpopProof(invalidDpop, "POST", "/credential", invalidToken.access_token))
      .send({
        credential_configuration_id: invalidSession.credential_configuration_id,
        proofs: { jwt: [mismatchedProof] },
      });
    expect(mismatchedCredential.status).toBe(400);
    expect(mismatchedCredential.body).toMatchObject({ error: "invalid_proof" });

    const session = await postJson<SessionCreateResponse>(app, "/sessions", { broken: true });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const proof = await credentialProofJwt(walletKey, token.c_nonce);
    const credential = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", "/credential", token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    expect(credential.body).toMatchObject({
      credentials: [
        {
          credential: expect.any(String),
        },
      ],
    });
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    expect(compactSdJwt.split("~").length).toBeGreaterThan(2);
    const issuerJwt = compactSdJwt.split("~")[0];
    const issuerPayload = JSON.parse(
      Buffer.from(issuerJwt.split(".")[1], "base64url").toString("utf8"),
    ) as JsonRecord;
    const issuerHeader = JSON.parse(
      Buffer.from(issuerJwt.split(".")[0], "base64url").toString("utf8"),
    ) as JsonRecord;
    const issuerCertificate = X509Certificate.fromEncodedCertificate(
      (issuerHeader.x5c as string[])[0],
    );
    const verified = await compactVerify(
      issuerJwt,
      await importJWK(issuerCertificate.publicJwk.toJson(), "ES256"),
    );
    expect(issuerPayload.iss).toBe(config.issuer_base_url);
    expect(issuerPayload.iss).not.toMatch(/^did:/);
    expect(verified.protectedHeader).toMatchObject({
      alg: "ES256",
      typ: "dc+sd-jwt",
      x5c: expect.any(Array),
    });

    const decoded = new (await import("@credo-ts/core")).SdJwtVcService({} as never).fromCompact(
      compactSdJwt,
    );
    expect(decoded.prettyClaims).toMatchObject({
      vct: PID_SD_JWT_VCT,
      address: {
        country: "IT",
        formatted: "Via Europa 1, 00100 Roma, IT",
        house_number: "1",
        locality: "Roma",
        postal_code: "00100",
        region: "Lazio",
        street_address: "Via Europa",
      },
      birth_family_name: "Doe",
      birth_given_name: "Jane",
      birthdate: "1990-01-01",
      date_of_expiry: "2031-01-01",
      date_of_issuance: "2026-01-01",
      document_number: "CREDIMI-DEMO-001",
      email: "jane.doe@example.test",
      given_name: "Jane",
      family_name: "Doe",
      issuing_authority: "Credimi Fake Issuer",
      issuing_country: "IT",
      issuing_jurisdiction: "IT-RM",
      nationalities: ["IT"],
      personal_administrative_number: "PID-DEMO-001",
      phone_number: "+390600000000",
      picture: expect.stringMatching(/^data:image\/jpeg;base64,\/9j\//),
      place_of_birth: "Roma",
      sex: 2,
      cnf: { jwk: walletKey.publicJwk },
    });
    expect(decoded.holder?.method).toBe("jwk");
    if (decoded.holder?.method !== "jwk") throw new Error("expected JWK holder binding");
    expect(Kms.PublicJwk.fromUnknown(walletKey.publicJwk).equals(decoded.holder.jwk)).toBe(true);
    const walletJwks = await getJson<JwksResponse>(app, `/sessions/${session.session_id}/jwks`);
    expect(walletJwks.keys).toHaveLength(1);
    expect(walletJwks.keys[0]).toMatchObject(walletKey.publicJwk);

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.flow).toBe("pre_authorized_code");
    expect(capture.checks.nonce_verified).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(true);
    expect(capture.checks.proof_jwt_header_jwk_present).toBe(true);
    expect(capture.status).toBe("credential_issued");
  });

  it("decrypts the Credential Request and encrypts the Credential Response", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const holderKey = await dpopKey();
    const proof = await credentialProofJwt(holderKey, token.c_nonce);
    const responseEncryptionKeyPair = await generateKeyPair("ECDH-ES", {
      crv: "P-256",
      extractable: true,
    });
    const responseEncryptionJwk = {
      ...(await exportJWK(responseEncryptionKeyPair.publicKey)),
      alg: "ECDH-ES",
      use: "enc",
      kid: "wallet-credential-response-key",
    };
    const credentialRequest = {
      credential_configuration_id: session.credential_configuration_id,
      proofs: { jwt: [proof] },
      credential_response_encryption: {
        jwk: responseEncryptionJwk,
        enc: "A256GCM",
      },
    };

    const plaintextResponseEncryptionRequest = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", "/credential", token.access_token))
      .send(credentialRequest);
    expect(plaintextResponseEncryptionRequest.status).toBe(400);
    expect(plaintextResponseEncryptionRequest.body).toMatchObject({
      error: "invalid_encryption_parameters",
      error_description: "credential_response_encryption requires an encrypted Credential Request",
    });

    const metadata = await getJson<JsonRecord>(app, "/.well-known/openid-credential-issuer");
    const requestEncryption = metadata.credential_request_encryption as {
      jwks: { keys: JWK[] };
    };
    const issuerEncryptionJwk = requestEncryption.jwks.keys[0];
    const encryptedRequest = await new CompactEncrypt(
      Buffer.from(JSON.stringify(credentialRequest), "utf8"),
    )
      .setProtectedHeader({
        alg: "ECDH-ES",
        enc: "A256GCM",
        kid: issuerEncryptionJwk.kid,
      })
      .encrypt(await importJWK(issuerEncryptionJwk, "ECDH-ES"));

    const credentialResponse = await request(app)
      .post("/credential")
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", "/credential", token.access_token))
      .type("application/jwt")
      .send(encryptedRequest);

    expect(credentialResponse.status, credentialResponse.text).toBe(200);
    expect(credentialResponse.type, credentialResponse.text).toBe("application/jwt");
    const decryptedResponse = await compactDecrypt(
      credentialResponse.text,
      responseEncryptionKeyPair.privateKey,
    );
    expect(decryptedResponse.protectedHeader).toMatchObject({
      alg: "ECDH-ES",
      enc: "A256GCM",
      kid: "wallet-credential-response-key",
    });
    const responsePayload = JSON.parse(
      Buffer.from(decryptedResponse.plaintext).toString("utf8"),
    ) as CredentialResponse;
    expect(responsePayload.credentials).toEqual([{ credential: expect.any(String) }]);

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.raw?.credential_request_raw).toMatchObject({
      redacted: true,
      present: true,
      length: encryptedRequest.length,
    });
    expect(capture.raw?.credential_request).toMatchObject({
      credential_configuration_id: session.credential_configuration_id,
      proofs: {
        jwt: { redacted: true, present: true },
      },
      credential_response_encryption: credentialRequest.credential_response_encryption,
    });
    expect(capture.status).toBe("credential_issued");
  });

  it("rejects credential issuance without an access token", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/credential")
      .send({ proof: { proof_type: "jwt", jwt: unsignedJwt({ alg: "ES256", kid: "key-1" }) } });

    expect(response.status).toBe(403);
    expect(response.headers["www-authenticate"]).toContain("DPoP");
  });

  it("returns a clear JWKS failure before a wallet key is observed", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const response = await request(app).get(`/sessions/${session.session_id}/jwks`);

    expect(response.status).toBe(409);
    expect(response.body).toMatchObject({ error: "wallet_jwks_not_observed" });
  });

  it("rejects sessions for unsupported credential configurations", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/sessions")
      .send({ credential_configuration_id: "unknown.credential" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "unsupported_credential_configuration" });
  });

  it("runs the authorization-code flow through the auto-approving chained OAuth server", async () => {
    const app = createApp(config);
    const walletClientId = "https://wallet.example.test";
    const walletRedirectUri = "https://wallet.example.test/callback";
    const walletState = "wallet-state";
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const dpop = await dpopKey();
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "authorization_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants.authorization_code;

    expect(session.flow).toBe("authorization_code");
    expect(grant).toMatchObject({
      issuer_state: expect.any(String),
    });
    expect(grant).not.toHaveProperty("authorization_server");

    const pushed = await request(app)
      .post("/par")
      .set("DPoP", await dpopProof(dpop, "POST", "/par"))
      .type("form")
      .send({
        response_type: "code",
        client_id: walletClientId,
        redirect_uri: walletRedirectUri,
        scope: session.credential_configuration_id,
        issuer_state: String(grant.issuer_state),
        state: walletState,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    expect(pushed.body).toMatchObject({
      request_uri: expect.any(String),
      expires_in: expect.any(Number),
    });

    const authorize = await request(app)
      .get("/authorize")
      .query({
        client_id: walletClientId,
        request_uri: String(pushed.body.request_uri),
      })
      .redirects(0);
    expect(authorize.status).toBe(302);
    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    expect(externalAuthorizationUrl.pathname).toBe("/fake-oauth/authorize");

    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    expect(autoApproval.status).toBe(302);
    const credoCallback = new URL(String(autoApproval.headers.location));
    expect(credoCallback.pathname).toBe("/redirect");
    expect(credoCallback.searchParams.get("code")).toEqual(expect.any(String));

    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    expect(walletAuthorizationResponse.status).toBe(302);
    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));
    expect(walletCallback.origin + walletCallback.pathname).toBe(walletRedirectUri);
    expect(walletCallback.searchParams.get("state")).toBe(walletState);
    expect(walletCallback.searchParams.get("iss")).toBe(config.issuer_base_url);
    const authorizationCode = walletCallback.searchParams.get("code");
    expect(authorizationCode).toEqual(expect.any(String));

    const token = await postToken(
      app,
      {
        grant_type: "authorization_code",
        code: String(authorizationCode),
        code_verifier: codeVerifier,
        redirect_uri: walletRedirectUri,
        client_id: walletClientId,
      },
      dpop,
    );
    expect(token).toMatchObject({
      access_token: expect.any(String),
      token_type: "DPoP",
      c_nonce: expect.any(String),
    });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("token_issued");
    expect(capture.observed.client_id.value).toBe(walletClientId);
    expect(capture.observed.redirect_uri.value).toBe(walletRedirectUri);
    expect(capture.checks).toMatchObject({
      pkce_present: true,
      pkce_valid: true,
      state_present: true,
      issuer_state_present: true,
    });
    expect(capture.raw?.par_request).toMatchObject({
      client_id: walletClientId,
      redirect_uri: walletRedirectUri,
      code_challenge: codeChallenge,
    });
    expect(capture.raw?.token_request?.code).toMatchObject({
      redacted: true,
      present: true,
    });
  });

  it("rejects unknown issuance flow presets", async () => {
    const app = createApp(config);
    const response = await request(app).post("/sessions").send({ flow: "implicit" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "unsupported_issuance_flow",
      supported_flows: ["pre_authorized_code", "authorization_code"],
    });
  });
});

async function postJson<T>(app: Express, path: string, body: object): Promise<T> {
  const response = await request(app).post(path).send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function postForm<T>(app: Express, path: string, body: Record<string, string>): Promise<T> {
  const response = await request(app).post(path).type("form").send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function postToken(
  app: Express,
  body: Record<string, string>,
  dpopKey: DpopKey,
): Promise<TokenResponse> {
  const response = await request(app)
    .post("/token")
    .set("DPoP", await dpopProof(dpopKey, "POST", "/token"))
    .type("form")
    .send(body);
  expect(response.status, JSON.stringify(response.body)).toBeLessThan(400);
  return response.body as TokenResponse;
}

async function preAuthorizedToken(
  app: Express,
  session: SessionCreateResponse,
  dpopKey: DpopKey,
): Promise<TokenResponse> {
  const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
  const grant = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] as JsonRecord;
  return postToken(
    app,
    {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": String(grant["pre-authorized_code"]),
    },
    dpopKey,
  );
}

async function getJson<T>(app: Express, path: string): Promise<T> {
  const response = await request(app).get(path);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

function dcqlForClaims(claims: string[]): JsonRecord {
  return {
    credentials: [
      {
        id: "query_0",
        format: "dc+sd-jwt",
        meta: {
          vct_values: [PID_SD_JWT_VCT],
        },
        claims: claims.map((claim) => ({ path: [claim] })),
      },
    ],
  };
}

function endpointUrl(path: string): string {
  return `${config.issuer_base_url}${path}`;
}

interface DpopKey {
  publicJwk: JsonRecord;
  privateKey: KeyLike | Uint8Array;
}

async function dpopKey(): Promise<DpopKey> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    publicJwk: (await exportJWK(publicKey)) as unknown as JsonRecord,
    privateKey,
  };
}

async function dpopProof(
  key: DpopKey,
  method: string,
  path: string,
  accessToken?: string,
): Promise<string> {
  return new SignJWT({
    htm: method,
    htu: endpointUrl(path),
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: key.publicJwk as unknown as JWK })
    .sign(key.privateKey);
}

async function credentialProofJwt(
  key: DpopKey,
  nonce: string,
  audience = config.issuer_base_url,
  attestedKey = key,
): Promise<string> {
  const keyAttestation = await keyAttestationJwt(attestedKey, nonce);
  return new SignJWT({
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: key.publicJwk as unknown as JWK,
      key_attestation: keyAttestation,
    })
    .sign(key.privateKey);
}

async function keyAttestationJwt(key: DpopKey, nonce: string): Promise<string> {
  const privateJwk = JSON.parse(readFileSync(privateJwkPath(dataDir), "utf8")) as JWK;
  const certificate = readFileSync(issuerCertificatePath(dataDir), "utf8")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iat: now,
    exp: now + 300,
    nonce,
    attested_keys: [key.publicJwk],
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "key-attestation+jwt",
      x5c: [certificate],
    })
    .sign(await importJWK(privateJwk, "ES256"));
}

async function walletAttestationJwt(key: DpopKey, clientId: string): Promise<string> {
  const privateJwk = JSON.parse(readFileSync(privateJwkPath(dataDir), "utf8")) as JWK;
  const certificate = readFileSync(issuerCertificatePath(dataDir), "utf8")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: "https://wallet-provider.example.test",
    sub: clientId,
    iat: now,
    exp: now + 300,
    cnf: { jwk: key.publicJwk },
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-client-attestation+jwt",
      x5c: [certificate],
    })
    .sign(await importJWK(privateJwk, "ES256"));
}

async function walletAttestationPopJwt(key: DpopKey, clientId: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: clientId,
    aud: config.issuer_base_url,
    iat: now,
    jti: randomUUID(),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-client-attestation-pop+jwt",
    })
    .sign(key.privateKey);
}

async function sdJwtCredential(): Promise<{
  compact: string;
  privateKey: Parameters<SignJWT["sign"]>[0];
}> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const holderJwk = (await exportJWK(publicKey)) as unknown as JsonRecord;
  return {
    compact: await issueSdJwtCredential({
      config,
      credentialConfigurationId: config.credential_configuration_id,
      holderJwk,
    }),
    privateKey,
  };
}

async function sdJwtPresentation(options: {
  credential: { compact: string; privateKey: Parameters<SignJWT["sign"]>[0] };
  authorizationRequest: JsonRecord;
  disclosedClaims: string[];
}): Promise<string> {
  const [issuerJwt, ...tail] = options.credential.compact.split("~");
  const selected = tail
    .filter((part) => part.length > 0)
    .filter((disclosure) => options.disclosedClaims.includes(disclosureClaimName(disclosure)));
  const withoutKeyBinding = `${issuerJwt}~${selected.join("~")}~`;
  const keyBindingJwt = await new SignJWT({
    iat: Math.floor(Date.now() / 1000),
    aud: String(options.authorizationRequest.client_id),
    nonce: String(options.authorizationRequest.nonce),
    sd_hash: createHash("sha256").update(withoutKeyBinding).digest("base64url"),
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
    .sign(options.credential.privateKey);
  return `${withoutKeyBinding}${keyBindingJwt}`;
}

async function encryptedAuthorizationResponse(
  authorizationRequest: JsonRecord,
  payload: JsonRecord,
): Promise<string> {
  const clientMetadata = authorizationRequest.client_metadata as JsonRecord;
  const jwks = clientMetadata.jwks as { keys: JsonRecord[] };
  const publicJwk = jwks.keys[0] as unknown as JWK;
  return new CompactEncrypt(Buffer.from(JSON.stringify(payload), "utf8"))
    .setProtectedHeader({
      alg: "ECDH-ES",
      enc: "A256GCM",
      kid: publicJwk.kid,
    })
    .encrypt(await importJWK(publicJwk, "ECDH-ES"));
}

function disclosureClaimName(disclosure: string): string {
  const decoded = JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[];
  return typeof decoded[1] === "string" ? decoded[1] : "";
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

interface SessionCreateResponse extends JsonRecord {
  session_id: string;
  flow: "pre_authorized_code" | "authorization_code";
  credential_configuration_id: string;
  broken: boolean;
  offer_url: string;
}

interface TokenResponse extends JsonRecord {
  access_token: string;
  c_nonce: string;
}

interface JwksResponse extends JsonRecord {
  keys: JsonRecord[];
}

interface CredentialOfferResponse extends JsonRecord {
  credential_configuration_ids: string[];
  grants: Record<string, JsonRecord>;
}

interface CredentialResponse extends JsonRecord {
  credentials: Array<{
    credential: string;
  }>;
}

interface VpSessionCreateResponse extends JsonRecord {
  session_id: string;
  request_delivery: "by_reference" | "by_value";
  request_uri: string;
  request_uri_method: "get" | "post";
  scheme: string;
  response_uri: string;
  deeplink: string;
  authorization_request: JsonRecord;
  status: string;
}

interface VpSessionResponse extends JsonRecord {
  session_id: string;
  status: string;
  authorization_request: JsonRecord;
  decoded_presentations?: JsonRecord;
  checks: {
    presentation_valid: boolean | null;
    nonce_verified: boolean;
    holder_binding_verified: boolean;
    dcql_query_matched: boolean;
    errors: string[];
  };
  observed: {
    vp_token?: { value: unknown };
    request_uri_payload: { value: JsonRecord | null; source: string | null };
    wallet_response: { value: JsonRecord | null };
    presentation_submission?: { value: unknown };
  };
  raw?: {
    presentation_response?: JsonRecord;
    presentation_response_decrypted?: JsonRecord;
    decoded_presentations?: JsonRecord;
  };
}
