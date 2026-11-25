import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "@credo-ts/core";
import { compactVerify, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { initIssuer } from "../src/config/key-material.js";
import { jwksPath, privateJwkPath, verifierCertificatePath } from "../src/config/paths.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import {
  degreeSdJwtCredentialConfigurationId,
  domesticPidCredentialConfigurationId,
  mdocCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import { PID_MDOC_DOCTYPE, PID_SD_JWT_VCT } from "../src/credentials/definitions.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord, Oid4vciHttpRequestCapture } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import { type JwksResponse, serverTestSuite } from "./support/server.js";
const {
  config,
  conformingIssuerId,
  jwtKeyAttestationIssuerId,
  jwtOnlyIssuerId,
  conformingIssuerPath,
  jwtKeyAttestationIssuerPath,
  jwtOnlyIssuerPath,
  conformingMetadataPath,
  conformingAuthorizationServerMetadataPath,
  conformingUpstreamAuthorizationServerMetadataPath,
} = serverTestSuite("fake-issuer-test-");

/** Each page section's intro title, as `tag#id title`, in page order. */
function sectionIntroTitles(html: string): string[] {
  return Array.from(
    html.matchAll(/<(h[12]) class="section-intro-title" id="([^"]+)">([^<]+)</g),
    ([, tag, id, title]) => `${tag}#${id} ${title}`,
  );
}

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
      openApi.body.paths["/.well-known/openid-credential-issuer/issuers/{issuerConfigurationId}"]
        .get.responses["200"].content,
    ).toHaveProperty("application/jwt");
    expect(
      openApi.body.paths["/issuers/{issuerConfigurationId}/credential"].post.requestBody.content,
    ).toHaveProperty("application/jwt");
    expect(
      openApi.body.paths["/issuers/{issuerConfigurationId}/credential"].post.requestBody.content[
        "application/json"
      ].schema.properties.proofs.properties,
    ).toEqual(
      expect.objectContaining({
        jwt: expect.objectContaining({ minItems: 1, maxItems: 1 }),
        attestation: expect.objectContaining({ minItems: 1, maxItems: 1 }),
      }),
    );
    expect(
      openApi.body.paths["/issuers/{issuerConfigurationId}/credential"].post.responses["200"]
        .content,
    ).toHaveProperty("application/jwt");
    expect(
      openApi.body.components.schemas.IssuanceSessionRequest.properties.issuer_configuration_id,
    ).toMatchObject({
      enum: [conformingIssuerId, jwtKeyAttestationIssuerId, jwtOnlyIssuerId],
      default: conformingIssuerId,
    });
    expect(
      openApi.body.components.schemas.IssuanceSessionRequest.properties.broken,
    ).toBeUndefined();
    expect(openApi.body.components.schemas.IssuanceSessionRequest.properties.flow).toMatchObject({
      enum: ["pre_authorized_code", "authorization_code"],
      default: "authorization_code",
    });
    expect(
      openApi.body.components.schemas.IssuanceSessionRequest.properties.credential_offer_mode,
    ).toMatchObject({
      enum: ["credential_offer", "credential_offer_uri"],
      default: "credential_offer",
    });
    expect(
      openApi.body.components.schemas.IssuanceSessionRequest.properties.document_number,
    ).toMatchObject({ type: "string", minLength: 1 });
    expect(Object.keys(openApi.body.paths)).toEqual(
      expect.arrayContaining([
        "/sessions",
        "/openid4vp/sessions",
        "/issuers/{issuerConfigurationId}/offers/{credentialOfferId}",
        "/issuers/{issuerConfigurationId}/par",
        "/issuers/{issuerConfigurationId}/authorize",
        "/issuers/{issuerConfigurationId}/redirect",
        "/authorization-servers/{issuerConfigurationId}/authorize",
        "/authorization-servers/{issuerConfigurationId}/token",
        "/issuers/{issuerConfigurationId}/credential-jwks.json",
        "/issuers/{issuerConfigurationId}/token",
        "/issuers/{issuerConfigurationId}/credential",
      ]),
    );
    expect(openApi.body.paths).not.toHaveProperty("/init");
    expect((await request(app).post("/init").send({ force: true })).status).toBe(404);
  });

  it("returns signed issuer metadata when the wallet requests application/jwt", async () => {
    const app = createApp(config);
    const [defaultMetadata, unsignedMetadata, signedMetadata] = await Promise.all([
      request(app).get(conformingMetadataPath),
      request(app).get(conformingMetadataPath).set("Accept", "application/json"),
      request(app).get(conformingMetadataPath).set("Accept", "application/jwt"),
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
            kid: "credimi-eu-pid-device-bound-issuer-encryption-key",
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

    expect(iss).toBe(`${config.issuer_base_url}${conformingIssuerPath}`);
    expect(sub).toBe(`${config.issuer_base_url}${conformingIssuerPath}`);
    expect(iat).toEqual(expect.any(Number));
    expect(metadataClaims).toEqual(unsignedMetadata.body);
    expect(metadataClaims.authorization_servers).toBeUndefined();
  });

  it("signs issuer metadata using an externally supplied private JWK kid", async () => {
    const isolatedDataDir = mkdtempSync(join(tmpdir(), "external-issuer-kid-test-"));
    try {
      const isolatedConfig = await initIssuer({
        issuer_base_url: config.issuer_base_url,
        data_dir: isolatedDataDir,
        force: true,
      });
      const issuer = resolvedIssuerConfigurationById(isolatedConfig, conformingIssuerId);
      if (!issuer) throw new Error("conforming issuer unavailable");
      const secretPath = privateJwkPath(issuer.materialDirectory);
      const privateJwk = JSON.parse(readFileSync(secretPath, "utf8")) as JsonRecord;
      privateJwk.kid = "externally-managed-issuer-key";
      writeFileSync(secretPath, `${JSON.stringify(privateJwk, null, 2)}\n`);

      await initIssuer({
        issuer_base_url: isolatedConfig.issuer_base_url,
        data_dir: isolatedDataDir,
      });
      const response = await request(createApp(isolatedConfig))
        .get(conformingMetadataPath)
        .set("Accept", "application/jwt");
      const jwks = JSON.parse(
        readFileSync(jwksPath(issuer.materialDirectory), "utf8"),
      ) as JwksResponse;

      expect(response.status, response.text).toBe(200);
      expect(response.type).toBe("application/jwt");
      expect(jwks.keys[0]?.kid).toBe(privateJwk.kid);
    } finally {
      rmSync(isolatedDataDir, { recursive: true, force: true });
    }
  });

  it("exposes only the three path-based issuers and removes the legacy root issuer", async () => {
    const app = createApp(config);
    const catalogue = await getJson<JsonRecord[]>(app, "/issuers");

    expect(catalogue).toEqual([
      expect.objectContaining({
        id: conformingIssuerId,
        compliance: "eudi-pid-device-bound",
        credential_issuer: `${config.issuer_base_url}${conformingIssuerPath}`,
      }),
      expect.objectContaining({
        id: jwtKeyAttestationIssuerId,
        compliance: "eudi-pid-device-bound",
        credential_issuer: `${config.issuer_base_url}${jwtKeyAttestationIssuerPath}`,
      }),
      expect.objectContaining({
        id: jwtOnlyIssuerId,
        compliance: "deliberately-nonconforming",
        credential_issuer: `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
      }),
    ]);
    expect((await request(app).get("/.well-known/openid-credential-issuer")).status).toBe(404);
    expect((await request(app).get("/.well-known/oauth-authorization-server")).status).toBe(404);
    expect((await request(app).get("/credential")).status).toBe(404);
    expect((await request(app).post("/token")).status).toBe(404);
  });

  it("partitions otherwise identical PID metadata by proof policy", async () => {
    const app = createApp(config);
    const deviceBoundMetadata = await getJson<JsonRecord>(app, conformingMetadataPath);
    const jwtKeyAttestationMetadata = await getJson<JsonRecord>(
      app,
      `/.well-known/openid-credential-issuer/issuers/${jwtKeyAttestationIssuerId}`,
    );
    const jwtOnlyMetadata = await getJson<JsonRecord>(
      app,
      `/.well-known/openid-credential-issuer/issuers/${jwtOnlyIssuerId}`,
    );
    const deviceBoundConfigurations =
      deviceBoundMetadata.credential_configurations_supported as Record<string, JsonRecord>;
    const jwtKeyAttestationConfigurations =
      jwtKeyAttestationMetadata.credential_configurations_supported as Record<string, JsonRecord>;
    const jwtOnlyConfigurations = jwtOnlyMetadata.credential_configurations_supported as Record<
      string,
      JsonRecord
    >;

    expect(Object.keys(deviceBoundConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(config, "key-attestation-required"),
      mdocCredentialConfigurationId(config, "key-attestation-required"),
      degreeSdJwtCredentialConfigurationId(config, "key-attestation-required"),
      numericSdJwtCredentialConfigurationId(config, "key-attestation-required"),
      domesticPidCredentialConfigurationId("dc+sd-jwt", "key-attestation-required"),
      domesticPidCredentialConfigurationId("mso_mdoc", "key-attestation-required"),
    ]);
    expect(Object.keys(jwtKeyAttestationConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(config, "jwt-key-attestation-required"),
      mdocCredentialConfigurationId(config, "jwt-key-attestation-required"),
    ]);
    expect(Object.keys(jwtOnlyConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(config, "jwt-proof"),
      mdocCredentialConfigurationId(config, "jwt-proof"),
      degreeSdJwtCredentialConfigurationId(config, "jwt-proof"),
      numericSdJwtCredentialConfigurationId(config, "jwt-proof"),
      domesticPidCredentialConfigurationId("dc+sd-jwt", "jwt-proof"),
      domesticPidCredentialConfigurationId("mso_mdoc", "jwt-proof"),
    ]);
    expect(
      deviceBoundConfigurations[sdJwtCredentialConfigurationId(config, "key-attestation-required")]
        ?.vct,
    ).toBe(PID_SD_JWT_VCT);
    expect(jwtOnlyConfigurations[sdJwtCredentialConfigurationId(config, "jwt-proof")]?.vct).toBe(
      PID_SD_JWT_VCT,
    );
    expect(
      deviceBoundConfigurations[mdocCredentialConfigurationId(config, "key-attestation-required")]
        ?.doctype,
    ).toBe(PID_MDOC_DOCTYPE);
    expect(jwtOnlyConfigurations[mdocCredentialConfigurationId(config, "jwt-proof")]?.doctype).toBe(
      PID_MDOC_DOCTYPE,
    );
    expect(
      deviceBoundConfigurations[sdJwtCredentialConfigurationId(config, "key-attestation-required")]
        ?.proof_types_supported,
    ).toEqual({
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
      attestation: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
    });
    const jwtKeyAttestationProofTypes = {
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
    };
    expect(
      jwtKeyAttestationConfigurations[
        sdJwtCredentialConfigurationId(config, "jwt-key-attestation-required")
      ]?.proof_types_supported,
    ).toEqual(jwtKeyAttestationProofTypes);
    expect(
      jwtKeyAttestationConfigurations[
        mdocCredentialConfigurationId(config, "jwt-key-attestation-required")
      ]?.proof_types_supported,
    ).toEqual(jwtKeyAttestationProofTypes);
    expect(
      jwtOnlyConfigurations[sdJwtCredentialConfigurationId(config, "jwt-proof")]
        ?.proof_types_supported,
    ).toEqual({
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
      },
    });
  });

  it("advertises the implemented pre-authorized and authorization-code grants", async () => {
    const app = createApp(config);
    const metadata = await getJson<JsonRecord>(app, conformingAuthorizationServerMetadataPath);

    expect(metadata.grant_types_supported).toEqual([
      "authorization_code",
      "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ]);
    expect(metadata.token_endpoint).toBe(`${config.issuer_base_url}${conformingIssuerPath}/token`);
    expect(metadata.authorization_endpoint).toBe(
      `${config.issuer_base_url}${conformingIssuerPath}/authorize`,
    );
    expect(metadata.pushed_authorization_request_endpoint).toBe(
      `${config.issuer_base_url}${conformingIssuerPath}/par`,
    );
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
      conformingUpstreamAuthorizationServerMetadataPath,
    );

    expect(metadata).toMatchObject({
      issuer: `${config.issuer_base_url}/authorization-servers/${conformingIssuerId}`,
      authorization_endpoint: `${config.issuer_base_url}/authorization-servers/${conformingIssuerId}/authorize`,
      token_endpoint: `${config.issuer_base_url}/authorization-servers/${conformingIssuerId}/token`,
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
      const isolatedIssuer = resolvedIssuerConfigurationById(isolatedConfig, conformingIssuerId);
      if (!isolatedIssuer) throw new Error("conforming issuer unavailable");
      const jwks = JSON.parse(readFileSync(jwksPath(isolatedIssuer.materialDirectory), "utf8")) as {
        keys: JsonRecord[];
      };
      const issuerJwk = { ...(jwks.keys[0] ?? {}) };
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
      writeFileSync(
        jwksPath(isolatedIssuer.materialDirectory),
        JSON.stringify({ keys: [unrelatedJwk, issuerJwk] }),
      );

      const response = await request(createApp(isolatedConfig))
        .get(conformingMetadataPath)
        .set("Accept", "application/jwt");

      expect(response.status).toBe(200);
      const protectedHeader = decodeProtectedHeader(response.text);
      expect(protectedHeader.kid).toBeUndefined();
      expect(protectedHeader.x5c).toEqual(certificateChain);
    } finally {
      rmSync(isolatedDataDir, { recursive: true, force: true });
    }
  });

  it("serves a launcher whose credential choices create sessions the API accepts", async () => {
    const app = createApp(config);
    const response = await request(app).get("/");

    expect(response.status).toBe(200);
    expect(response.text).toContain(
      '<main><section class="page-section hero-band" aria-labelledby="hero-title">',
    );
    // Every section opens with the same intro: its title over a rule, then a description.
    expect(response.text.match(/<section class="page-section/g)).toHaveLength(3);
    expect(sectionIntroTitles(response.text)).toEqual([
      "h1#hero-title Wallet metadata capture",
      "h2#launcher-title Issue and verify",
      "h2#captured-values-title Captured values",
    ]);
    expect(response.text.match(/<div class="section-intro-description"><p>/g)).toHaveLength(3);
    expect(response.text).toContain(
      "Step 1) Start a one-time issuance flow, scan the offer, and inspect the wallet identifiers, callbacks, and proof keys observed by the issuer.",
    );
    expect(response.text).toContain('<form class="launcher-form session-launcher" novalidate>');
    expect(response.text).toContain(
      'id="captured-values-title">Captured values</h2><span class="count-chip">11</span>',
    );
    expect(response.text).toContain("<dt>wallet_notification</dt>");
    expect(response.text).toContain(
      '<h3 class="subsection-heading" id="capture-more-title">Also recorded</h3>',
    );
    // The protocol groups are sub-headings like "Issuers", in their own casing.
    expect(response.text.match(/<h3 class="subsection-heading">OpenID4VCI<\/h3>/g)).toHaveLength(2);
    expect(response.text.match(/<h3 class="subsection-heading">OpenID4VP<\/h3>/g)).toHaveLength(2);
    expect(response.text).toContain('<span class="subsection-heading">Credential</span>');
    for (const value of [
      "client_id",
      "redirect_uri",
      "wallet_jwks",
      "dpop_jwk",
      "authorization_request",
      "request_uri_payload",
      "wallet_response",
      "presentation_response_decrypted",
      "decoded_presentations",
      "presentation_validation",
    ]) {
      expect(response.text).toContain(`<dt>${value}</dt>`);
    }
    // No placeholder: the credential select opens on the first issuer's first credential.
    expect(response.text).toContain('<select data-credential-picker autocomplete="off"><optgroup');
    expect(response.text).toContain('data-param="status_list_enabled"');
    expect(response.text).toContain('<optgroup label="EUDI PID — device-bound conforming">');
    expect(response.text).toContain('<optgroup label="EUDI PID — JWT key attestation">');
    expect(response.text).toContain(
      '<optgroup label="EUDI PID — JWT proof only — deliberately non-conforming">',
    );
    // The issuer and verifier pages are no longer linked from the launcher.
    expect(response.text).not.toContain('class="issuer-card');
    expect(response.text).not.toContain("Customize");

    // The bodies the launcher script builds from an option are sessions the API accepts.
    const options = Array.from(
      response.text.matchAll(/<option value="([^"]+)" data-issuer="([^"]+)" data-dcql="([^"]+)"/g),
      ([, credentialId, issuerId, dcql]) => ({
        issue: { issuer_configuration_id: issuerId, credential_configuration_id: credentialId },
        verify: { dcql_query: JSON.parse((dcql ?? "").replaceAll("&quot;", '"')) as JsonRecord },
      }),
    );
    expect(options.map((option) => option.issue)).toContainEqual({
      issuer_configuration_id: jwtOnlyIssuerId,
      credential_configuration_id: mdocCredentialConfigurationId(config, "jwt-proof"),
    });
    const [first] = options;
    if (!first) throw new Error("launcher offers no credential");
    const issued = await request(app)
      .post("/sessions")
      .send({ ...first.issue, status_list_enabled: true });
    expect(issued.status).toBe(201);
    expect(issued.body).toMatchObject({ ...first.issue, status_list_enabled: true });
    const presentation = await postJson<{ authorization_request: JsonRecord }>(
      app,
      "/openid4vp/sessions",
      first.verify,
    );
    expect(presentation.authorization_request.dcql_query).toEqual(first.verify.dcql_query);
    expect(response.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="Credimi"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(response.text).toContain(
      '<span class="status-chip status-issuer">ISSUER READY</span><span class="status-chip status-wallet">VERIFIER READY</span><a class="btn btn-outline btn-md" href="/docs">API docs</a><a class="btn btn-outline btn-md" href="/openapi.json" download="openapi.json">OpenAPI</a><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/credimi-capture-wallet"',
    );
    expect(response.text).toContain("Wallet metadata capture%c Credimi capture UI");
    expect(response.text).toContain('href="/favicon.svg"');
    expect(response.text).toContain(
      '<img class="footer-logo" src="/assets/credimi_logo_negative.svg" alt="" aria-hidden="true">',
    );
  });

  it("serves the issuer page at the Credential Issuer Identifier to a browser only", async () => {
    const app = createApp(config);
    const page = await request(app)
      .get(conformingIssuerPath)
      .set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");

    expect(page.status).toBe(200);
    expect(page.type).toBe("text/html");
    expect(page.headers.vary).toContain("Accept");
    expect(page.text).toContain('data-endpoint="/sessions" data-session-page="/ui/sessions/"');
    expect(sectionIntroTitles(page.text)).toEqual([
      "h1#issuer-title EUDI PID — device-bound conforming",
      "h2#issue-title Issue a credential",
      "h2#issuer-metadata-title Metadata",
    ]);
    expect(page.text).toContain(
      `<input type="hidden" data-param="issuer_configuration_id" data-type="string" value="${conformingIssuerId}">`,
    );
    expect(page.text).toContain(
      "Credimi Demo PID (SD-JWT VC, JWT or attestation proof, key attestation required)",
    );
    expect(page.text).toContain(
      "Credimi Demo PID (MDOC, JWT or attestation proof, key attestation required)",
    );
    expect(page.text).not.toContain("Credimi Demo PID (SD-JWT VC, JWT proof, no key attestation)");
    expect(page.text).toContain(
      `href="${config.issuer_base_url}${conformingAuthorizationServerMetadataPath}" target="_blank" rel="noreferrer"><h3>Authorization server metadata</h3>`,
    );
    expect(page.text).toContain(
      `href="${config.issuer_base_url}${conformingMetadataPath}" target="_blank" rel="noreferrer"><h3>OpenID4VCI credential issuer metadata</h3>`,
    );
    expect(page.text).not.toContain("OpenID Federation entity configuration");
    expect(page.text).not.toContain('data-param="offer_mutation"');

    // Any other client, a Wallet probing the identifier included, keeps the captured 404.
    for (const accept of [undefined, "*/*", "application/json"]) {
      const probe = request(app).get(conformingIssuerPath);
      const response = accept ? await probe.set("Accept", accept) : await probe;
      expect(response.status, accept).toBe(404);
    }
    const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
    expect(
      ledger
        .filter((entry) => entry.path === conformingIssuerPath)
        .map((entry) => [entry.unmatched, entry.response.status]),
    ).toEqual([
      [true, 404],
      [true, 404],
      [true, 404],
    ]);

    const unknown = await request(app).get("/issuers/not-configured").set("Accept", "text/html");
    expect(unknown.status).toBe(404);
  });

  it("offers every issuer's credentials, with its DCQL query, on the verifier page", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const page = await request(app).get("/openid4vp");

    expect(page.status).toBe(200);
    expect(page.text).toContain(
      'data-endpoint="/openid4vp/sessions" data-session-page="/ui/openid4vp/sessions/"',
    );
    expect(sectionIntroTitles(page.text)).toEqual([
      "h1#verifier-title OpenID4VP verifier",
      "h2#request-title Request a presentation",
    ]);
    expect(page.text).toContain('<optgroup label="EUDI PID — device-bound conforming">');
    expect(page.text).toContain('<optgroup label="EUDI PID — JWT key attestation">');
    expect(page.text).toContain(
      '<optgroup label="EUDI PID — JWT proof only — deliberately non-conforming">',
    );
    expect(page.text).toContain('data-param="request_mutation"');

    // The query the page sends is the one the session is created with.
    const dcql = /data-dcql="([^"]+)"/.exec(page.text)?.[1];
    if (!dcql) throw new Error("verifier page carries no DCQL query");
    const dcqlQuery = JSON.parse(dcql.replaceAll("&quot;", '"')) as JsonRecord;
    const session = await postJson<{ authorization_request: JsonRecord }>(
      app,
      "/openid4vp/sessions",
      { dcql_query: dcqlQuery },
    );
    expect(session.authorization_request.dcql_query).toEqual(dcqlQuery);
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
    expect((await request(app).get("/openid4vp")).status).toBe(404);
    expect((await request(app).get(conformingIssuerPath).set("Accept", "text/html")).status).toBe(
      404,
    );
    expect((await request(app).get("/docs")).status).toBe(200);
    expect((await request(app).get("/openapi.json")).status).toBe(200);

    const apiSession = await request(app).post("/sessions").send({});
    expect(apiSession.status).toBe(201);
  });
});
