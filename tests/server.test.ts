import {
  type JsonWebKey as NodeJsonWebKey,
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify,
} from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CredoWebCrypto,
  Kms,
  Mdoc,
  SdJwtVcService,
  X509Certificate,
  X509KeyUsage,
} from "@credo-ts/core";
import { CoseKey, DataItem, DateOnly, Sign1, cborDecode } from "@owf/cose";
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
  flattenedVerify,
  generateKeyPair,
  importJWK,
} from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CONFIG,
  createJwkSigningContext,
  initIssuer,
  issuerCertificatePath,
  jwksPath,
  loadIssuerCertificate,
  privateJwkPath,
  verifierCaCertificatePath,
  verifierCertificatePath,
  verifierJwksPath,
  verifierPrivateJwkPath,
} from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import {
  DEGREE_SD_JWT_CLAIMS,
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_MDOC_NAMESPACE,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_CLAIMS,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "../src/credential-definitions.js";
import { CREDIMI_LOGO_URL, issueSdJwtCredential } from "../src/credential.js";
import {
  degreeSdJwtCredentialConfigurationId,
  domesticPidCredentialConfigurationId,
  mdocCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/metadata.js";
import { createApp } from "../src/server.js";
import { CaptureStore } from "../src/state.js";
import type { JsonRecord, Oid4vciHttpRequestCapture, SessionCapture } from "../src/types.js";
import { unsignedJwt } from "./helpers.js";

const credentialEncryptionTestState = vi.hoisted(() => ({ responseDelayMs: 0 }));
vi.mock("../src/credential-encryption.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/credential-encryption.js")>();
  return {
    ...actual,
    encryptCredentialResponse: async (
      ...args: Parameters<typeof actual.encryptCredentialResponse>
    ) => {
      if (credentialEncryptionTestState.responseDelayMs > 0) {
        await new Promise((resolve) =>
          setTimeout(resolve, credentialEncryptionTestState.responseDelayMs),
        );
      }
      return actual.encryptCredentialResponse(...args);
    },
  };
});

const dataDir = mkdtempSync(join(tmpdir(), "fake-issuer-test-"));
const config = {
  ...DEFAULT_CONFIG,
  issuer_base_url: "http://issuer.example.test",
  data_dir: dataDir,
};
const conformingIssuerId = "eu-pid-device-bound";
const jwtOnlyIssuerId = "eu-pid-jwt-proof-only";
const conformingIssuerPath = `/issuers/${conformingIssuerId}`;
const jwtOnlyIssuerPath = `/issuers/${jwtOnlyIssuerId}`;
const conformingMetadataPath = `/.well-known/openid-credential-issuer/issuers/${conformingIssuerId}`;
const conformingAuthorizationServerMetadataPath = `/.well-known/oauth-authorization-server/issuers/${conformingIssuerId}`;
const conformingUpstreamAuthorizationServerMetadataPath = `/.well-known/oauth-authorization-server/authorization-servers/${conformingIssuerId}`;
const conformingIssuer = resolvedIssuerConfigurationById(config, conformingIssuerId);
if (!conformingIssuer) throw new Error("conforming issuer configuration unavailable");
const conformingMaterialDirectory = conformingIssuer.materialDirectory;
const conformingIssuerConfig = issuerAppConfig(config, conformingIssuer);

function isCoseSign1(
  value: unknown,
): value is [Uint8Array, Map<number, unknown>, Uint8Array | null, Uint8Array] {
  return (
    Array.isArray(value) &&
    value.length === 4 &&
    value[0] instanceof Uint8Array &&
    value[1] instanceof Map &&
    (value[2] === null || value[2] instanceof Uint8Array) &&
    value[3] instanceof Uint8Array
  );
}

function mdocStatusAndSignature(encoded: string): {
  signature: Sign1;
  status: Map<unknown, unknown>;
} {
  const issuerSigned = cborDecode(Buffer.from(encoded, "base64url"));
  if (!(issuerSigned instanceof Map)) throw new Error("Issued mdoc is not a CBOR map");
  const issuerAuth = issuerSigned.get("issuerAuth");
  if (!isCoseSign1(issuerAuth)) throw new Error("Issued mdoc issuerAuth is not a COSE Sign1");
  const signature = Sign1.fromEncodedStructure(issuerAuth);
  if (!signature.payload) throw new Error("Issued mdoc COSE Sign1 has no payload");
  const mobileSecurityObject = cborDecode(signature.payload, { unwrapTopLevelDataItem: false });
  if (!(mobileSecurityObject instanceof DataItem) || !(mobileSecurityObject.data instanceof Map)) {
    throw new Error("Issued mdoc Mobile Security Object is not an encoded CBOR map");
  }
  const status = mobileSecurityObject.data.get("status");
  if (!(status instanceof Map)) throw new Error("Issued mdoc Mobile Security Object has no status");
  return { signature, status };
}

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
  credentialEncryptionTestState.responseDelayMs = 0;
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
      enum: [conformingIssuerId, jwtOnlyIssuerId],
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

  it("exposes only the two path-based issuers and removes the legacy root issuer", async () => {
    const app = createApp(config);
    const catalogue = await getJson<JsonRecord[]>(app, "/issuers");

    expect(catalogue).toEqual([
      expect.objectContaining({
        id: conformingIssuerId,
        compliance: "eudi-pid-device-bound",
        credential_issuer: `${config.issuer_base_url}${conformingIssuerPath}`,
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
    const jwtOnlyMetadata = await getJson<JsonRecord>(
      app,
      `/.well-known/openid-credential-issuer/issuers/${jwtOnlyIssuerId}`,
    );
    const deviceBoundConfigurations =
      deviceBoundMetadata.credential_configurations_supported as Record<string, JsonRecord>;
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

  it("does not accept an authorization code at another issuer's OAuth server", async () => {
    const app = createApp(config);
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const authorization = await request(app)
      .get(`/authorization-servers/${conformingIssuerId}/authorize`)
      .query({
        response_type: "code",
        client_id: `credimi-capture-wallet-${conformingIssuerId}`,
        redirect_uri: `${config.issuer_base_url}${conformingIssuerPath}/redirect`,
        state: "issuer-isolation",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        scope: "credimi.capture.eu-pid-device-bound",
      })
      .redirects(0);
    expect(authorization.status).toBe(302);
    const code = new URL(String(authorization.headers.location)).searchParams.get("code");
    expect(code).toEqual(expect.any(String));

    const crossIssuerRedemption = await request(app)
      .post(`/authorization-servers/${jwtOnlyIssuerId}/token`)
      .type("form")
      .send({
        grant_type: "authorization_code",
        client_id: `credimi-capture-wallet-${jwtOnlyIssuerId}`,
        client_secret: `credimi-capture-wallet-test-secret-${jwtOnlyIssuerId}`,
        code,
        redirect_uri: `${config.issuer_base_url}${jwtOnlyIssuerPath}/redirect`,
        code_verifier: codeVerifier,
      });

    expect(crossIssuerRedemption.status).toBe(400);
    expect(crossIssuerRedemption.body).toMatchObject({
      error: "invalid_grant",
      error_description: "authorization code is invalid or expired",
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
    expect(response.text).toContain('<optgroup label="EUDI PID — device-bound conforming">');
    expect(response.text).toContain(
      '<optgroup label="EUDI PID — JWT proof only — deliberately non-conforming">',
    );
    expect(response.text).toContain(
      '<section class="issuer-catalogue" aria-labelledby="issuer-catalogue-title">',
    );
    expect(response.text).toContain('<h2 id="issuer-catalogue-title">Available issuers</h2>');
    expect(response.text.match(/<article class="issuer-card">/g)).toHaveLength(2);
    expect(response.text).toContain("EUDI PID — device-bound conforming");
    expect(response.text).not.toContain('class="issuer-compliance');
    expect(response.text).not.toContain('class="issuer-warning"');
    expect(response.text).not.toContain(
      "Deliberately non-conforming for a device-bound EUDI PID; a conforming wallet may reject issuance.",
    );
    expect(response.text).not.toContain(
      "PID issuer advertising JWT and attestation proofs with key attestation required.",
    );
    expect(response.text).toContain("EUDI PID — JWT proof only");
    expect(response.text).toContain(
      "PID interoperability test issuer advertising JWT proof without key attestation.",
    );
    expect(response.text).toContain(
      '<a href="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731" target="_blank" rel="noreferrer">Commission Implementing Regulation (EU) 2026/1731</a>',
    );
    expect(response.text).toContain(
      "in particular <code>TR_KA-4</code>: both <code>jwt</code> and <code>attestation</code> proof types are present and both include <code>key_attestations_required</code>.",
    );
    expect(response.text.match(/class="issuer-link"/g)).toHaveLength(6);

    for (const issuerId of [conformingIssuerId, jwtOnlyIssuerId]) {
      expect(response.text).toContain(
        `href="${config.issuer_base_url}/issuers/${issuerId}" target="_blank" rel="noreferrer">Issuer</a>`,
      );
      expect(response.text).toContain(
        `href="${config.issuer_base_url}/.well-known/openid-credential-issuer/issuers/${issuerId}" target="_blank" rel="noreferrer">Credential issuer well-known</a>`,
      );
      expect(response.text).toContain(
        `href="${config.issuer_base_url}/.well-known/oauth-authorization-server/issuers/${issuerId}" target="_blank" rel="noreferrer">Authorization server well-known</a>`,
      );
    }

    expect(response.text).not.toContain(
      "/.well-known/oauth-authorization-server/authorization-servers/",
    );
    expect(response.text).toContain(
      "Credimi Demo PID (SD-JWT VC, JWT or attestation proof, key attestation required)",
    );
    expect(response.text).toContain("Credimi Demo PID (SD-JWT VC, JWT proof, no key attestation)");
    expect(response.text).toContain(
      "Credimi Demo PID (MDOC, JWT or attestation proof, key attestation required)",
    );
    expect(response.text).toContain("Credimi Demo PID (MDOC, JWT proof, no key attestation)");
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
    const selectedCredentialConfigurationId = mdocCredentialConfigurationId(
      config,
      "key-attestation-required",
    );
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

  it("creates OpenID4VP requests for the degree credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = degreeSdJwtCredentialConfigurationId(
      config,
      "key-attestation-required",
    );
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const dcqlQuery = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];

    expect(credential).toMatchObject({
      format: "dc+sd-jwt",
      meta: { vct_values: [DEGREE_SD_JWT_VCT] },
    });
    expect((credential.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      DEGREE_SD_JWT_CLAIMS.map((claim) => claim.split(".")),
    );
  });

  it("creates OpenID4VP requests for the numeric credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = numericSdJwtCredentialConfigurationId(
      config,
      "key-attestation-required",
    );
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const dcqlQuery = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];

    expect(credential).toMatchObject({
      format: "dc+sd-jwt",
      meta: { vct_values: [NUMERIC_SD_JWT_VCT] },
    });
    expect((credential.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      NUMERIC_SD_JWT_CLAIMS.map((claim) => claim.split(".")),
    );
  });

  it("creates OpenID4VP requests for the domestic PID mdoc across both namespaces", async () => {
    const app = createApp(config);
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({
        credential_configuration_id: domesticPidCredentialConfigurationId("mso_mdoc", "jwt-proof"),
      })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const dcqlQuery = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];

    expect(credential).toMatchObject({
      format: "mso_mdoc",
      meta: { doctype_value: PID_MDOC_DOCTYPE },
    });
    expect((credential.claims as JsonRecord[]).map((claim) => claim.path)).toEqual([
      ...PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
      [DOMESTIC_PID_MDOC_NAMESPACE, "credimi_domestic_claim"],
    ]);
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
      credential: await sdJwtCredential(),
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
        credential: await sdJwtCredential(),
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
      .type("form")
      .set("DPoP", "wallet-response-dpop-proof")
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
    expect(capture.raw?.presentation_response_http).toMatchObject({
      method: "POST",
      headers: {
        "content-type": expect.stringContaining("application/x-www-form-urlencoded"),
        dpop: { redacted: true, present: true },
      },
    });
    expect(capture.raw?.presentation_response_http?.body).toContain(
      `state=${encodeURIComponent(String(session.authorization_request.state))}`,
    );
    expect(capture.raw?.presentation_response_http?.body).toContain("vp_token=presentation-token");
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 400,
      headers: {
        "content-type": expect.stringContaining("application/json"),
        "cache-control": "no-store",
      },
    });
    expect(capture.raw?.presentation_response_verifier_http?.body).toContain(
      '"error":"invalid_presentation"',
    );
  });

  it("keeps a failed plain direct-post VP token separate from the verifier error", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .type("form")
      .send({
        state: session.authorization_request.state,
        vp_token: "not-a-real-presentation",
      });

    expect(response.status, response.text).toBe(400);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.vp_token_format_valid).toBe(true);
    expect(capture.raw?.presentation_response_decrypted).toEqual({
      state: session.authorization_request.state,
      vp_token: "not-a-real-presentation",
    });
    expect(capture.raw?.presentation_response_decrypted).not.toHaveProperty("error");
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        type: "vp_presentation_response_received",
        detail: expect.objectContaining({ vp_token_observed: true }),
      }),
    );
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
      redirect_uri: "https://rp.example.test/complete",
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
    expect(response.body).toEqual({ redirect_uri: session.redirect_uri });

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
    expect(capture.raw?.presentation_response_verifier_http).toMatchObject({
      status: 200,
      headers: {
        "content-type": expect.stringContaining("application/json"),
        "cache-control": "no-store",
      },
      body: JSON.stringify({ redirect_uri: session.redirect_uri }),
    });
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

  it.each(["A128GCM", "A256GCM"])(
    "decrypts a presentation response encrypted with the sole advertised enc value %s",
    async (enc) => {
      const app = createApp(config);
      const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
        client_metadata: { encrypted_response_enc_values_supported: [enc] },
        presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      });
      const metadata = session.authorization_request.client_metadata as JsonRecord;
      expect(metadata.encrypted_response_enc_values_supported).toEqual([enc]);

      const credential = await sdJwtCredential();
      const presentation = await sdJwtPresentation({
        credential,
        authorizationRequest: session.authorization_request,
        disclosedClaims: ["family_name"],
      });
      const response = await request(app)
        .post(`/openid4vp/sessions/${session.session_id}/response`)
        .send({
          response: await encryptedAuthorizationResponse(
            session.authorization_request,
            {
              state: session.authorization_request.state,
              vp_token: { query_0: [presentation] },
            },
            enc,
          ),
        });

      expect(response.status).toBe(200);
      const capture = await getJson<VpSessionResponse>(
        app,
        `/openid4vp/sessions/${session.session_id}`,
      );
      expect(capture.status).toBe("presentation_validated");
      expect(capture.raw?.presentation_response_decrypted).toMatchObject({
        vp_token: { query_0: [presentation] },
      });
      expect(capture.events.map((event) => event.type)).not.toContain(
        "vp_undecryptable_response_allowed",
      );
    },
  );

  it("exposes the decrypted error of an encrypted wallet error response", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const errorResponse = {
      error: "access_denied",
      error_description: "The End-User declined the presentation",
      state: session.authorization_request.state,
    };

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(
          session.authorization_request,
          errorResponse,
        ),
      });

    expect(response.status, response.text).toBe(400);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks).toMatchObject({
      presentation_valid: false,
      vp_token_format_valid: false,
    });
    expect(capture.raw?.presentation_response).toEqual({ response: expect.any(String) });
    expect(capture.raw?.presentation_response_decrypted).toEqual(errorResponse);
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        type: "vp_presentation_response_received",
        detail: expect.objectContaining({ vp_token_observed: false }),
      }),
    );
  });

  it("retains an encrypted VP token after Credo rejects its DCQL match", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name", "given_name"]),
      },
    });
    const presentation = await sdJwtPresentation({
      credential: await sdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    const walletResponse = {
      state: session.authorization_request.state,
      vp_token: { query_0: [presentation] },
    };

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(
          session.authorization_request,
          walletResponse,
        ),
      });

    expect(response.status, response.text).toBe(400);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks.vp_token_format_valid).toBe(true);
    expect(capture.checks.errors).not.toHaveLength(0);
    expect(capture.raw?.presentation_response_decrypted).toEqual(walletResponse);
    expect(capture.raw?.presentation_response_decrypted).not.toHaveProperty("error");
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        type: "vp_presentation_response_received",
        detail: expect.objectContaining({ vp_token_observed: true }),
      }),
    );
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

  it("captures wallet metadata for a client-metadata-free OpenID4VP request_uri POST", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_uri_method: "post",
      response_mode: "direct_post",
      client_metadata: null,
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
    expect(claims.client_metadata).toBeUndefined();

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
    expect(capture.raw?.authorization_request_jwt).toBe(requestObject.text);
    expect(capture.raw?.request_uri_http).toMatchObject({
      method: "POST",
      target: `/openid4vp/sessions/${session.session_id}/request`,
      headers: {
        "content-type": expect.stringContaining("application/x-www-form-urlencoded"),
      },
      body: "wallet_nonce=wallet-nonce-123&wallet_metadata=present",
    });
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

  it("creates GUI sessions backed by a Credo credential offer", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    const initial = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(initial.status).toBe("created");
    expect(initial.flow).toBe("authorization_code");
    expect(initial).not.toHaveProperty("broken");
    expect(initial.issuer_configuration_id).toBe(conformingIssuerId);
    expect(initial.issuer_identifier).toBe(`${config.issuer_base_url}${conformingIssuerPath}`);
    expect(initial.credential_offer_mode).toBe("credential_offer");

    const deeplink = await getJson<{ deeplink: string }>(app, `/sessions/${sessionId}/deeplink`);
    const deeplinkUrl = new URL(deeplink.deeplink);
    expect(deeplinkUrl.searchParams.get("credential_offer_uri")).toBeNull();
    expect(JSON.parse(String(deeplinkUrl.searchParams.get("credential_offer")))).toMatchObject({
      credential_configuration_ids: expect.any(Array),
    });

    const unchanged = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(unchanged.status).toBe("created");
  });

  it("embeds credential offers by value by default", async () => {
    const app = createApp(config);
    const requestedCredentialConfigurationId = mdocCredentialConfigurationId(
      config,
      "key-attestation-required",
    );

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: requestedCredentialConfigurationId,
    });
    const offer = await getJson<CredentialOfferResponse>(
      app,
      `/sessions/${session.session_id}/offer`,
    );

    expect(session.credential_configuration_id).toBe(requestedCredentialConfigurationId);
    expect(session.flow).toBe("authorization_code");
    expect(session.credential_offer_mode).toBe("credential_offer");
    expect(session.issuer_configuration_id).toBe(conformingIssuerId);
    expect(offer.credential_configuration_ids).toEqual([requestedCredentialConfigurationId]);
    expect(offer.grants.authorization_code).toMatchObject({
      issuer_state: expect.any(String),
    });
    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("credential_offer_uri")).toBeNull();
    expect(JSON.parse(String(deeplink.searchParams.get("credential_offer")))).toEqual(offer);
  });
  it("keeps status-list references opt-in per issuance session", async () => {
    const app = createApp(config);

    const defaultSession = await postJson<SessionCreateResponse>(app, "/sessions", {});
    expect(defaultSession.status_list_enabled).toBe(false);
    expect(
      (await getJson<SessionCapture>(app, `/sessions/${defaultSession.session_id}`))
        .status_list_enabled,
    ).toBe(false);

    const enabledSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      status_list_enabled: true,
    });
    expect(enabledSession.status_list_enabled).toBe(true);
    expect(
      (await getJson<SessionCapture>(app, `/sessions/${enabledSession.session_id}`))
        .status_list_enabled,
    ).toBe(true);

    const invalid = await request(app).post("/sessions").send({ status_list_enabled: "sometimes" });
    expect(invalid.status).toBe(400);
    expect(invalid.body).toMatchObject({ error: "invalid_status_list_enabled" });
  });

  it("creates credential-offer URI deeplinks when requested", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_offer_mode: "credential_offer_uri",
    });
    const deeplink = new URL(session.deeplink);

    expect(session.credential_offer_mode).toBe("credential_offer_uri");
    expect(deeplink.searchParams.get("credential_offer")).toBeNull();
    expect(deeplink.searchParams.get("credential_offer_uri")).toBe(session.offer_url);

    const offer = await request(app).get(new URL(session.offer_url).pathname);
    expect(offer.status).toBe(200);
    expect(offer.type).toBe("application/json");
    const consumed = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(consumed.status).toBe("offer_retrieved");
  });

  it("rejects the removed legacy broken credential fixture", async () => {
    const app = createApp(config);

    const removed = await request(app).post("/sessions").send({
      broken: true,
    });
    const invalid = await request(app).post("/sessions").send({ broken: "true" });

    expect(removed.status).toBe(400);
    expect(invalid.status).toBe(400);
    expect(removed.body).toEqual({
      error: "invalid_request",
      error_description: "'broken' is unavailable because the legacy root issuer has been removed",
    });
    expect(invalid.body).toEqual(removed.body);
  });

  it("serves Credo authorization-server JWKS without private material", async () => {
    const app = createApp(config);
    const jwks = await getJson<JwksResponse>(app, `${conformingIssuerPath}/jwks.json`);

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("publishes distinct authorization and credential-signing JWKS for each issuer", async () => {
    const app = createApp(config);
    const [deviceBoundAuthorizationJwks, jwtOnlyAuthorizationJwks, deviceBoundCredentialJwks] =
      await Promise.all([
        getJson<JwksResponse>(app, `${conformingIssuerPath}/jwks.json`),
        getJson<JwksResponse>(app, `${jwtOnlyIssuerPath}/jwks.json`),
        getJson<JwksResponse>(app, `${conformingIssuerPath}/credential-jwks.json`),
      ]);
    const jwtVcMetadata = await getJson<JsonRecord>(
      app,
      `/.well-known/jwt-vc-issuer/issuers/${conformingIssuerId}`,
    );

    expect(deviceBoundAuthorizationJwks.keys[0]).not.toEqual(jwtOnlyAuthorizationJwks.keys[0]);
    expect(deviceBoundCredentialJwks.keys[0]).not.toHaveProperty("d");
    expect(deviceBoundCredentialJwks.keys[0]?.x5c).toEqual([expect.any(String)]);
    expect(deviceBoundCredentialJwks.keys[0]).not.toEqual(deviceBoundAuthorizationJwks.keys[0]);
    expect(jwtVcMetadata).toEqual({
      issuer: `${config.issuer_base_url}${conformingIssuerPath}`,
      jwks_uri: `${config.issuer_base_url}${conformingIssuerPath}/credential-jwks.json`,
    });
  });

  it("issues an MDOC PID credential for the selected MDOC configuration", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: mdocCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
      flow: "pre_authorized_code",
    });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const walletKey = await dpopKey();
    const credentialPath = issuerProtocolPath(session, "/credential");
    const refreshedNonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
    expect(refreshedNonce.status).toBe(200);
    const proof = await keyAttestationJwt(walletKey, String(refreshedNonce.body.c_nonce));

    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
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
    const credoDecoded = Mdoc.fromBase64Url(encodedMdoc);

    expect(session.credential_configuration_id).toBe(
      mdocCredentialConfigurationId(config, "key-attestation-required"),
    );
    expect(decoded.issuerAuth.mobileSecurityObject.docType).toBe(PID_MDOC_DOCTYPE);
    const namespace = decoded.getPrettyClaims(PID_MDOC_NAMESPACE) as JsonRecord | undefined;
    expect(Object.keys(namespace ?? {}).sort()).toEqual([...PID_MDOC_CLAIMS].sort());
    expect(namespace).toMatchObject({
      document_number: "CREDIMI-DEMO-001",
      email_address: "jane.doe@example.test",
      family_name: "Rossi",
      family_name_birth: "Rossi",
      given_name: "Mario",
      given_name_birth: "Mario",
      issuing_authority: "Credimi Fake Issuer",
      issuing_country: "IT",
      issuing_jurisdiction: "IT-RM",
      mobile_phone_number: "+390600000000",
      nationality: ["IT"],
      personal_administrative_number: "PID-DEMO-001",
      resident_address: "Via Europa 1, 00100 Roma, IT",
      resident_city: "Roma",
      resident_country: "IT",
      resident_house_number: "1",
      resident_postal_code: "00100",
      resident_state: "Lazio",
      resident_street: "Via Europa",
      sex: 2,
    });
    expect(namespace?.birth_date).toBeInstanceOf(DateOnly);
    expect(String(namespace?.birth_date)).toBe("1990-01-01");
    expect(namespace?.expiry_date).toBeInstanceOf(DateOnly);
    expect(String(namespace?.expiry_date)).toBe("2031-01-01");
    expect(namespace?.issuance_date).toBeInstanceOf(DateOnly);
    expect(String(namespace?.issuance_date)).toBe("2026-01-01");
    expect(namespace?.place_of_birth).toEqual(
      new Map([
        ["country", "IT"],
        ["locality", "Roma"],
        ["region", "Lazio"],
      ]),
    );
    const portrait = namespace?.portrait;
    expect(portrait).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(portrait as Uint8Array).subarray(0, 3)).toEqual(
      Buffer.from([0xff, 0xd8, 0xff]),
    );
    expect(credoDecoded.issuerSignedNamespaces[PID_MDOC_NAMESPACE]).toEqual(namespace);
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("credential_issued");
    expect(capture.checks.proof_attestation_present).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(true);
    expect(capture.observed.wallet_jwks.source).toBe("credo.verified_holder_binding");
  });

  it.each([
    ["status_without_status_list", new Map()],
    [
      "negative_index",
      new Map<unknown, unknown>([
        [
          "status_list",
          new Map<unknown, unknown>([
            ["uri", "https://status.example.test/1"],
            ["idx", -1],
          ]),
        ],
      ]),
    ],
    [
      "missing_index",
      new Map<unknown, unknown>([
        ["status_list", new Map<unknown, unknown>([["uri", "https://status.example.test/1"]])],
      ]),
    ],
    [
      "malformed_uri",
      new Map<unknown, unknown>([
        [
          "status_list",
          new Map<unknown, unknown>([
            ["uri", "not a uri"],
            ["idx", 42],
          ]),
        ],
      ]),
    ],
    [
      "missing_uri",
      new Map<unknown, unknown>([["status_list", new Map<unknown, unknown>([["idx", 42]])]]),
    ],
    ...(
      [
        ["uri_missing_scheme", "//status.example.test/1"],
        ["uri_space_in_host", "https://status.ex ample.test/1"],
        ["uri_invalid_percent_encoding", "https://status.example.test/1%GG"],
        ["uri_illegal_characters", "https://status.example.test/1<token>|1"],
        ["uri_empty", ""],
      ] as const
    ).map(
      ([statusReference, uri]) =>
        [
          statusReference,
          new Map<unknown, unknown>([
            [
              "status_list",
              new Map<unknown, unknown>([
                ["uri", uri],
                ["idx", 42],
              ]),
            ],
          ]),
        ] as const,
    ),
  ] as const)(
    "issues a signed mdoc with the %s status fixture",
    async (statusReference, expectedStatus) => {
      const allocation = vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ status_list: { uri: "https://status.example.test/1", idx: 42 } }),
            { headers: { "content-type": "application/json" }, status: 200 },
          ),
        );
      vi.stubGlobal("fetch", allocation);
      const app = createApp({ ...config, fcaf_scenarios_enabled: true });
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
        flow: "pre_authorized_code",
        status_list_enabled: true,
        status_reference: statusReference,
      });
      const dpop = await dpopKey();
      const token = await preAuthorizedToken(app, session, dpop);
      const walletKey = await dpopKey();
      const credentialPath = issuerProtocolPath(session, "/credential");
      const nonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
      const proof = await keyAttestationJwt(walletKey, String(nonce.body.c_nonce));
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: { attestation: [proof] },
        });

      expect(credential.status, JSON.stringify(credential.body)).toBe(200);
      expect(allocation).toHaveBeenCalledOnce();
      const encodedMdoc = (credential.body as CredentialResponse).credentials[0].credential;
      const { signature, status } = mdocStatusAndSignature(encodedMdoc);
      const issuerKey = CoseKey.fromJwk(
        loadIssuerCertificate(conformingIssuerConfig).publicJwk.toJson(),
      );

      expect(status).toEqual(expectedStatus);
      expect(
        await signature.verifySignature(
          { key: issuerKey },
          {
            verify: async ({ key, signature: value, toBeVerified }) =>
              verify(
                "sha256",
                toBeVerified,
                {
                  dsaEncoding: "ieee-p1363",
                  key: createPublicKey({
                    format: "jwk",
                    key: key.jwk as unknown as NodeJsonWebKey,
                  }),
                },
                value,
              ),
          },
        ),
      ).toBe(true);
    },
  );

  it.each([
    ["uri_missing_scheme", "//status.example.test/1"],
    ["uri_space_in_host", "https://status.ex ample.test/1"],
    ["uri_invalid_percent_encoding", "https://status.example.test/1%GG"],
    ["uri_illegal_characters", "https://status.example.test/1<token>|1"],
    ["uri_empty", ""],
  ])("issues an SD-JWT VC with the %s status reference", async (statusReference, uri) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ status_list: { uri: "https://status.example.test/1", idx: 42 } }),
            { headers: { "content-type": "application/json" }, status: 200 },
          ),
        ),
    );
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: sdJwtCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
      flow: "pre_authorized_code",
      status_list_enabled: true,
      status_reference: statusReference,
    });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const nonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
    const proof = await keyAttestationJwt(await dpopKey(), String(nonce.body.c_nonce));
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { attestation: [proof] },
      });

    expect(credential.status, JSON.stringify(credential.body)).toBe(200);
    const compact = (credential.body as CredentialResponse).credentials[0].credential;
    const claims = new SdJwtVcService({} as never).fromCompact(compact).prettyClaims as JsonRecord;
    expect(claims.status).toEqual({ status_list: { uri, idx: 42 } });
  });

  describe("revocation through POST /sessions/{sessionId}/status", () => {
    const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };
    const allocated = { uri: "https://status.example.test/token_status_list/EU/pid/1", idx: 42 };

    function stubStatusList(setResponse: () => Response) {
      const statusList = vi.fn<typeof fetch>(async (input) =>
        String(input).endsWith("/token_status_list/take")
          ? new Response(JSON.stringify({ status_list: allocated }), {
              headers: { "content-type": "application/json" },
              status: 200,
            })
          : setResponse(),
      );
      vi.stubGlobal("fetch", statusList);
      return statusList;
    }

    async function issuedMdocSession(app: Express, statusListEnabled = true) {
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
        flow: "pre_authorized_code",
        status_list_enabled: statusListEnabled,
      });
      const dpop = await dpopKey();
      const token = await preAuthorizedToken(app, session, dpop);
      const credentialPath = issuerProtocolPath(session, "/credential");
      const nonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: {
            attestation: [await keyAttestationJwt(await dpopKey(), String(nonce.body.c_nonce))],
          },
        });
      expect(credential.status, JSON.stringify(credential.body)).toBe(200);
      return session;
    }

    it("records the allocated reference and revokes it through the Status List service", async () => {
      const statusList = stubStatusList(() => new Response("Status Changed\n", { status: 200 }));
      const app = createApp(scenarioConfig);
      const session = await issuedMdocSession(app);
      const issued = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(issued.status_list_references).toEqual([
        { allocation_id: `${session.session_id}:0`, ...allocated },
      ]);

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const setCall = statusList.mock.calls.find(([input]) =>
        String(input).endsWith("/token_status_list/set"),
      );
      expect(String(setCall?.[0])).toBe("http://localhost:8000/token_status_list/set");
      expect(setCall?.[1]?.method).toBe("POST");
      expect(new Headers(setCall?.[1]?.headers).get("x-api-key")).toBe(config.status_list_api_key);
      expect(Object.fromEntries(new URLSearchParams(String(setCall?.[1]?.body)))).toEqual({
        uri: allocated.uri,
        idx: "42",
        status: "1",
      });
      const expectedResult = {
        ...allocated,
        status: 1,
        ok: true,
        http_status: 200,
        response_body: "Status Changed\n",
      };
      expect(response.body).toMatchObject({
        session_id: session.session_id,
        requested_status: "revoked",
        results: [expectedResult],
      });
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.status_list_updates).toEqual([
        { at: expect.any(String), requested_status: "revoked", results: [expectedResult] },
      ]);
      expect(
        capture.events.find((event) => event.type === "status_list_status_updated"),
      ).toMatchObject({
        detail: {
          requested_status: "revoked",
          results: [{ ...allocated, ok: true, http_status: 200 }],
        },
      });
      expect(JSON.stringify(capture)).not.toContain(`"${config.status_list_api_key}"`);
    });

    it("answers 502 and records the Status List service's refusal", async () => {
      stubStatusList(
        () =>
          new Response(JSON.stringify({ detail: "Wrong Status Change" }), {
            headers: { "content-type": "application/json" },
            status: 400,
          }),
      );
      const app = createApp(scenarioConfig);
      const session = await issuedMdocSession(app);

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status).toBe(502);
      expect(response.body).toMatchObject({
        error: "status_list_update_failed",
        results: [
          {
            ...allocated,
            ok: false,
            http_status: 400,
            response_body: '{"detail":"Wrong Status Change"}',
          },
        ],
      });
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.status_list_updates?.[0]?.results[0]).toMatchObject({
        ok: false,
        http_status: 400,
      });
    });

    it("refuses a session issued without a status list", async () => {
      stubStatusList(() => new Response("unexpected", { status: 500 }));
      const app = createApp(scenarioConfig);
      const session = await issuedMdocSession(app, false);

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: "status_list_not_enabled" });
    });

    it("refuses before any reference was allocated", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        status_list_enabled: true,
      });

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status).toBe(409);
      expect(response.body).toEqual({ error: "status_list_references_not_allocated" });
    });

    it.each([
      ["scenarios are disabled", config, { status: "revoked" }, "status_update_not_enabled"],
      ["the status is not revoked", scenarioConfig, { status: "valid" }, "unsupported_status"],
    ])("refuses the call when %s", async (_label, appConfig, body, error) => {
      const app = createApp(appConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        status_list_enabled: true,
      });

      const response = await request(app).post(`/sessions/${session.session_id}/status`).send(body);

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ error });
    });
  });

  it("captures and correlates pre-authorized requests with secrets redacted", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const preAuthorizedCode = String(grant["pre-authorized_code"]);
    const dpopKeyPair = await dpopKey();
    const tokenPath = issuerProtocolPath(session, "/token");
    const dpop = await dpopProof(dpopKeyPair, "POST", tokenPath);

    const token = await request(app).post(tokenPath).set("DPoP", dpop).type("form").send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode,
    });

    expect(token.status).toBe(200);
    const ledger = await getJson<Array<JsonRecord>>(app, "/oid4vci/requests");
    const tokenCapture = ledger.find((entry) => entry.path === tokenPath);
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
      expect.arrayContaining([new URL(session.offer_url).pathname, tokenPath]),
    );
    expect(JSON.stringify(ledger)).not.toContain(preAuthorizedCode);
    expect(JSON.stringify(ledger)).not.toContain(dpop);
  });

  it("makes credential nonce responses uncacheable", async () => {
    const app = createApp(config);
    const response = await request(app).post(`${conformingIssuerPath}/nonce`);

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toMatchObject({
      c_nonce: expect.any(String),
    });
  });

  it("rejects token requests without DPoP", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as JsonRecord;
    const response = await request(app)
      .post(issuerProtocolPath(session, "/token"))
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
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
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
      .post(issuerProtocolPath(session, "/token"))
      .set("DPoP", await dpopProof(dpop, "POST", issuerProtocolPath(session, "/token")))
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

  describe("FCAF ws_ap evidence", () => {
    const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };
    const walletClientId = "https://wallet.example.test";

    async function pushAuthorization(
      app: Express,
      session: SessionCreateResponse,
      headers: Record<string, string | string[]>,
    ) {
      const offer = JSON.parse(
        String(new URL(session.deeplink).searchParams.get("credential_offer")),
      ) as CredentialOfferResponse;
      const parPath = issuerProtocolPath(session, "/par");
      const pending = request(app)
        .post(parPath)
        .set("DPoP", await dpopProof(await dpopKey(), "POST", parPath));
      // The object form passes an array through, which Node sends as repeated header fields.
      for (const [name, value] of Object.entries(headers)) pending.set({ [name]: value });
      return pending.type("form").send({
        response_type: "code",
        client_id: walletClientId,
        redirect_uri: `${walletClientId}/callback`,
        scope: session.credential_configuration_id,
        issuer_state: String(offer.grants.authorization_code.issuer_state),
        code_challenge: createHash("sha256").update("verifier").digest("base64url"),
        code_challenge_method: "S256",
      });
    }

    it.each([
      [config, { evidence_mode: "full" }, "evidence_mode_not_enabled"],
      [scenarioConfig, { evidence_mode: "raw" }, "unsupported_evidence_mode"],
    ])("refuses an unavailable evidence mode", async (appConfig, body, error) => {
      const response = await request(createApp(appConfig)).post("/sessions").send(body);

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ error });
    });

    it("decodes client attestations into a default session while the ledger stays redacted", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const walletInstanceKey = await dpopKey();
      const attestation = await walletAttestationJwt(walletInstanceKey, walletClientId);
      const pop = await walletAttestationPopJwt(walletInstanceKey, walletClientId);

      const pushed = await pushAuthorization(app, session, {
        "OAuth-Client-Attestation": attestation,
        "OAuth-Client-Attestation-PoP": pop,
      });

      expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
      expect(session).not.toHaveProperty("evidence_mode");
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture).not.toHaveProperty("evidence_mode");
      expect(capture.observed.client_authentication).toMatchObject({
        method: "wallet_attestation",
        wallet_attestation: {
          present: true,
          source: `${issuerProtocolPath(session, "/par")}.headers.oauth-client-attestation`,
          header: { typ: "oauth-client-attestation+jwt" },
          claims: { sub: walletClientId },
          cnf_jwk: walletInstanceKey.publicJwk,
          client_id_matches: true,
          error: null,
        },
        wallet_attestation_pop: {
          present: true,
          header: { typ: "oauth-client-attestation-pop+jwt" },
          audience_matches: true,
          challenge: null,
        },
      });
      expect(capture.checks).toMatchObject({
        wallet_attestation_present: true,
        wallet_attestation_pop_present: true,
        wallet_attestation_client_id_matches: true,
        wallet_attestation_pop_audience_matches: true,
      });
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture).toMatchObject({
        headers: { "oauth-client-attestation": { redacted: true, present: true } },
        header_counts: { "oauth-client-attestation": 1, "oauth-client-attestation-pop": 1 },
      });
      expect(parCapture).not.toHaveProperty("raw_headers");
      const ledger = await getJson<JsonRecord[]>(app, "/oid4vci/requests");
      expect(JSON.stringify([ledger, capture.raw])).not.toContain(attestation);
    });

    it("keeps every attestation header in clear for a full-evidence session Credo rejects", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
      });
      const walletInstanceKey = await dpopKey();
      const attestation = await walletAttestationJwt(walletInstanceKey, walletClientId);
      const otherAttestation = await walletAttestationJwt(await dpopKey(), "other-client");
      const pop = await walletAttestationPopJwt(walletInstanceKey, walletClientId);

      const pushed = await pushAuthorization(app, session, {
        "OAuth-Client-Attestation": [attestation, otherAttestation],
        "OAuth-Client-Attestation-PoP": pop,
      });

      expect(pushed.status).toBeGreaterThanOrEqual(400);
      expect(session.evidence_mode).toBe("full");
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      const parPath = issuerProtocolPath(session, "/par");
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) => entry.path === parPath);
      expect(parCapture?.header_counts["oauth-client-attestation"]).toBe(2);
      expect(
        parCapture?.raw_headers?.filter(
          (header) => header.name.toLowerCase() === "oauth-client-attestation",
        ),
      ).toEqual([
        { name: expect.stringMatching(/^oauth-client-attestation$/i), value: attestation },
        { name: expect.stringMatching(/^oauth-client-attestation$/i), value: otherAttestation },
      ]);
      expect(parCapture?.raw_headers).toContainEqual({
        name: expect.stringMatching(/^dpop$/i),
        value: { redacted: true, present: true, length: expect.any(Number) },
      });
      expect(capture.observed.client_authentication.wallet_attestation).toMatchObject({
        present: true,
        source: `${parPath}.headers.oauth-client-attestation[0]`,
        claims: { sub: walletClientId },
      });
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      const ledgerEntry = ledger.find((entry) => entry.id === parCapture?.id);
      expect(ledgerEntry).toMatchObject({
        session_id: session.session_id,
        header_counts: { "oauth-client-attestation": 2 },
      });
      expect(JSON.stringify(ledger)).not.toContain(attestation);
    });

    it("attributes a PoP Credo rejects for its audience", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const walletInstanceKey = await dpopKey();
      const pop = await new SignJWT({
        iss: walletClientId,
        aud: "https://elsewhere.example.test",
        iat: Math.floor(Date.now() / 1000),
        jti: randomUUID(),
        challenge: "issuer-challenge",
      })
        .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation-pop+jwt" })
        .sign(walletInstanceKey.privateKey);

      const pushed = await pushAuthorization(app, session, {
        "OAuth-Client-Attestation": await walletAttestationJwt(walletInstanceKey, walletClientId),
        "OAuth-Client-Attestation-PoP": pop,
      });

      expect(pushed.status).toBeGreaterThanOrEqual(400);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.observed.client_authentication.wallet_attestation_pop).toMatchObject({
        present: true,
        audience_matches: false,
        challenge: "issuer-challenge",
      });
      expect(capture.checks.wallet_attestation_pop_audience_matches).toBe(false);
    });

    it("records a missing attestation header as absent", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const walletInstanceKey = await dpopKey();

      await pushAuthorization(app, session, {
        "OAuth-Client-Attestation-PoP": await walletAttestationPopJwt(
          walletInstanceKey,
          walletClientId,
        ),
      });

      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.observed.client_authentication).toMatchObject({
        method: "wallet_attestation",
        wallet_attestation: { present: false, source: null },
        wallet_attestation_pop: { present: true },
      });
      expect(capture.checks).toMatchObject({
        wallet_attestation_present: false,
        wallet_attestation_pop_present: true,
      });
      expect(
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/par"))?.header_counts,
      ).not.toHaveProperty("oauth-client-attestation");
    });

    async function requestCredential(
      app: Express,
      session: SessionCreateResponse,
      body: JsonRecord,
      token?: { dpop: DpopKey; response: TokenResponse },
    ) {
      const dpop = token?.dpop ?? (await dpopKey());
      const tokenResponse = token?.response ?? (await preAuthorizedToken(app, session, dpop));
      const credentialPath = issuerProtocolPath(session, "/credential");
      const response = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${tokenResponse.access_token}`)
        .set("DPoP", await dpopProof(dpop, "POST", credentialPath, tokenResponse.access_token))
        .send({ credential_configuration_id: session.credential_configuration_id, ...body });
      return {
        response,
        capture: await getJson<SessionCapture>(app, `/sessions/${session.session_id}`),
      };
    }

    async function preAuthorizedFull(app: Express): Promise<SessionCreateResponse> {
      return postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
        evidence_mode: "full",
      });
    }

    it("keeps a jwt proof Credo rejects, with its key attestation decoded", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);
      const dpop = await dpopKey();
      const tokenResponse = await preAuthorizedToken(app, session, dpop);
      const holderKey = await dpopKey();
      const keyAttestation = await keyAttestationJwt(holderKey, tokenResponse.c_nonce);
      const proof = await new SignJWT({
        aud: `${config.issuer_base_url}${conformingIssuerPath}`,
        nonce: tokenResponse.c_nonce,
        iat: Math.floor(Date.now() / 1000),
      })
        .setProtectedHeader({
          alg: "ES256",
          typ: "openid4vci-proof+jwt",
          jwk: holderKey.publicJwk as unknown as JWK,
          key_attestation: keyAttestation,
        })
        .sign((await dpopKey()).privateKey);

      const { response, capture } = await requestCredential(
        app,
        session,
        { proofs: { jwt: [proof, 42] } },
        { dpop, response: tokenResponse },
      );

      expect(response.status).toBe(400);
      expect(capture.raw?.proof_headers).toBeUndefined();
      const credentialCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/credential"),
      );
      expect(capture.raw?.credential_request_proofs).toEqual({
        request_id: credentialCapture?.id,
        at: credentialCapture?.at,
        proofs: { jwt: [proof, 42] },
        jwt: [
          {
            compact: proof,
            header: expect.objectContaining({
              typ: "openid4vci-proof+jwt",
              key_attestation: keyAttestation,
            }),
            payload: expect.objectContaining({ nonce: tokenResponse.c_nonce }),
            error: null,
            source: "proofs.jwt[0]",
            key_attestation: {
              compact: keyAttestation,
              header: expect.objectContaining({
                typ: "key-attestation+jwt",
                x5c: expect.any(Array),
              }),
              payload: expect.objectContaining({
                nonce: tokenResponse.c_nonce,
                attested_keys: [holderKey.publicJwk],
              }),
              error: null,
            },
          },
        ],
        attestation: [],
      });
      expect(credentialCapture?.body).toMatchObject({ proofs: { jwt: [proof, 42] } });
      const ledger = await getJson<JsonRecord[]>(app, "/oid4vci/requests");
      expect(JSON.stringify(ledger)).not.toContain(proof);
    });

    it("keeps a proofs.jwt that is not an array exactly as sent", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);

      const { response, capture } = await requestCredential(app, session, {
        proofs: { jwt: "not.a.jwt" },
      });

      expect(response.status).toBe(400);
      expect(capture.raw?.credential_request_proofs).toMatchObject({
        proofs: { jwt: "not.a.jwt" },
        jwt: [
          { compact: "not.a.jwt", source: "proofs.jwt", header: null, error: expect.any(String) },
        ],
      });
    });

    it("keeps an attestation proof and still records the accepted proof headers", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);
      const dpop = await dpopKey();
      const tokenResponse = await preAuthorizedToken(app, session, dpop);
      const keyAttestation = await keyAttestationJwt(await dpopKey(), tokenResponse.c_nonce);

      const { response, capture } = await requestCredential(
        app,
        session,
        { proofs: { attestation: [keyAttestation] } },
        { dpop, response: tokenResponse },
      );

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      expect(capture.raw?.credential_request_proofs?.attestation).toEqual([
        {
          compact: keyAttestation,
          header: expect.objectContaining({ typ: "key-attestation+jwt" }),
          payload: expect.objectContaining({ nonce: tokenResponse.c_nonce }),
          error: null,
          source: "proofs.attestation[0]",
        },
      ]);
      expect(capture.raw?.proof_headers).toEqual([
        expect.objectContaining({ proof_type: "attestation", typ: "key-attestation+jwt" }),
      ]);
    });

    it("records no proof evidence for a default session", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
      });

      const { response, capture } = await requestCredential(app, session, {
        proofs: { jwt: ["not.a.jwt"] },
      });

      expect(response.status).toBe(400);
      expect(capture.raw?.credential_request_proofs).toBeUndefined();
      expect(
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/credential"))?.body,
      ).toMatchObject({ proofs: { jwt: { redacted: true, present: true } } });
    });

    async function sendRawCredentialRequest(app: Express, contentType: string, bytes: Buffer) {
      const session = await preAuthorizedFull(app);
      const dpop = await dpopKey();
      const tokenResponse = await preAuthorizedToken(app, session, dpop);
      const credentialPath = issuerProtocolPath(session, "/credential");
      const response = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${tokenResponse.access_token}`)
        .set("DPoP", await dpopProof(dpop, "POST", credentialPath, tokenResponse.access_token))
        .set("Content-Type", contentType)
        // superagent writes a Buffer as-is once no serializer touches it; its type names strings.
        .serialize((body) => body)
        .send(bytes as unknown as string);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      return {
        session,
        response,
        credentialCapture: capture.raw?.oid4vci_requests?.find(
          (entry) => entry.path === credentialPath,
        ),
      };
    }

    it("keeps the exact Credential Request bytes, including a BOM and duplicate members", async () => {
      const app = createApp(scenarioConfig);
      const configurationId = sdJwtCredentialConfigurationId(config, "key-attestation-required");
      const bytes = Buffer.from(
        `\ufeff{"credential_configuration_id":"x","credential_configuration_id":"${configurationId}","proofs":{"jwt":["a.b.c"]}}`,
      );

      const { credentialCapture } = await sendRawCredentialRequest(app, "application/json", bytes);

      expect(credentialCapture?.raw_body).toEqual({
        content_type: "application/json",
        base64: bytes.toString("base64"),
      });
      expect(credentialCapture?.body).toMatchObject({
        credential_configuration_id: configurationId,
      });
    });

    it("keeps a Credential Request body that is not JSON or not parseable", async () => {
      const app = createApp(scenarioConfig);
      const malformed = Buffer.from('{"credential_configuration_id":');
      const plain = Buffer.from('{"proofs":{}}');

      const rejected = await sendRawCredentialRequest(app, "application/json", malformed);
      const untyped = await sendRawCredentialRequest(app, "text/plain", plain);

      expect(rejected.response.status).toBeGreaterThanOrEqual(400);
      expect(rejected.credentialCapture).toMatchObject({
        session_id: rejected.session.session_id,
        body: null,
        raw_body: { content_type: "application/json", base64: malformed.toString("base64") },
        response: { status: rejected.response.status },
      });
      expect(untyped.response.status).toBeGreaterThanOrEqual(400);
      expect(untyped.credentialCapture?.raw_body).toEqual({
        content_type: "text/plain",
        base64: plain.toString("base64"),
      });
    });

    it("keeps PAR bytes and the authorize request_uri in clear but describes the token body", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
      });
      const pushed = await pushAuthorization(app, session, {});
      const requestUri = String(pushed.body.request_uri);
      await request(app)
        .get(issuerProtocolPath(session, "/authorize"))
        .query({ client_id: walletClientId, request_uri: requestUri })
        .redirects(0);
      const preAuthorized = await preAuthorizedFull(app);
      await preAuthorizedToken(app, preAuthorized, await dpopKey());

      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture?.raw_body?.content_type).toBe("application/x-www-form-urlencoded");
      expect(
        new URLSearchParams(
          Buffer.from(String(parCapture?.raw_body?.base64), "base64").toString(),
        ).get("client_id"),
      ).toBe(walletClientId);
      const authorizeCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/authorize"),
      );
      expect(authorizeCapture?.query).toMatchObject({ request_uri: requestUri });
      expect(authorizeCapture).not.toHaveProperty("raw_body");
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(ledger.find((entry) => entry.id === authorizeCapture?.id)?.query).toMatchObject({
        request_uri: { redacted: true, present: true },
      });
      expect(ledger.some((entry) => "raw_body" in entry)).toBe(false);
      const tokenCapture = (
        await getJson<SessionCapture>(app, `/sessions/${preAuthorized.session_id}`)
      ).raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/token"));
      expect(tokenCapture?.raw_body).toEqual({
        content_type: "application/x-www-form-urlencoded",
        redacted: true,
        length: expect.any(Number),
      });
      expect(tokenCapture?.body).toMatchObject({
        "pre-authorized_code": { redacted: true, present: true },
      });
    });

    it("records delivered response bodies with the ledger's redaction in a default session", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
      });
      const dpop = await dpopKey();
      const tokenResponse = await preAuthorizedToken(app, session, dpop);

      const { response, capture } = await requestCredential(
        app,
        session,
        { proofs: { jwt: [await credentialProofJwt(await dpopKey(), tokenResponse.c_nonce)] } },
        { dpop, response: tokenResponse },
      );

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const byPath = (suffix: string) =>
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith(suffix))?.response;
      expect(
        byPath(`/offers/${new URL(session.offer_url).pathname.split("/").pop()}`),
      ).toMatchObject({
        status: 200,
        body: {
          grants: {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": { redacted: true, present: true },
            },
          },
        },
      });
      expect(byPath("/token")).toMatchObject({
        status: 200,
        body: {
          access_token: { redacted: true, present: true },
          token_type: "DPoP",
          c_nonce: tokenResponse.c_nonce,
        },
      });
      expect(byPath("/credential")).toMatchObject({
        status: 200,
        body: { credentials: [{ credential: { redacted: true, present: true } }] },
      });
      const ledger = await getJson<JsonRecord[]>(app, "/oid4vci/requests");
      expect(JSON.stringify(ledger)).not.toContain(tokenResponse.access_token);
      expect(JSON.stringify(ledger)).not.toContain(String(response.body.credentials[0].credential));
    });

    it("keeps PAR, authorize, and credential error responses in a full session", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
      });
      const pushed = await pushAuthorization(app, session, {});
      await request(app)
        .get(issuerProtocolPath(session, "/authorize"))
        .query({ client_id: walletClientId, request_uri: String(pushed.body.request_uri) })
        .redirects(0);

      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture?.response).toEqual({
        status: 201,
        content_type: expect.stringContaining("application/json"),
        body: { request_uri: pushed.body.request_uri, expires_in: pushed.body.expires_in },
      });
      expect(
        capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/authorize"))?.response,
      ).toMatchObject({ status: 302 });
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(ledger.find((entry) => entry.id === parCapture?.id)?.response.body).toMatchObject({
        request_uri: { redacted: true, present: true },
        expires_in: pushed.body.expires_in,
      });

      const preAuthorized = await preAuthorizedFull(app);
      const rejected = await requestCredential(app, preAuthorized, { proofs: { jwt: ["a.b.c"] } });
      expect(
        rejected.capture.raw?.oid4vci_requests?.find((entry) => entry.path.endsWith("/credential"))
          ?.response.body,
      ).toEqual(rejected.response.body);
    });

    it("attributes a Nonce Endpoint response to the session whose proof carries its c_nonce", async () => {
      const app = createApp(scenarioConfig);
      const session = await preAuthorizedFull(app);
      const unrelated = await request(app).post(`${conformingIssuerPath}/nonce`);
      const nonce = await request(app).post(`${conformingIssuerPath}/nonce`);
      const cNonce = String(nonce.body.c_nonce);

      const { response, capture } = await requestCredential(app, session, {
        proofs: { jwt: [await credentialProofJwt(await dpopKey(), cNonce)] },
      });

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const nonceCaptures = capture.raw?.oid4vci_requests?.filter((entry) =>
        entry.path.endsWith("/nonce"),
      );
      expect(nonceCaptures).toEqual([
        expect.objectContaining({
          session_id: session.session_id,
          response: expect.objectContaining({ status: 200, body: { c_nonce: cNonce } }),
        }),
      ]);
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(
        ledger.find(
          (entry) =>
            entry.path.endsWith("/nonce") &&
            (entry.response.body as JsonRecord | undefined)?.c_nonce === unrelated.body.c_nonce,
        )?.session_id,
      ).toBeNull();
    });

    it.each([
      [
        config,
        { par: { omit_parameters: ["/request_uri"] } },
        "issuance_response_scenario_not_enabled",
      ],
      [scenarioConfig, { token: { status: 400 } }, "invalid_issuance_response_scenario"],
      [
        scenarioConfig,
        { par: { omit_parameters: ["request_uri"] } },
        "invalid_issuance_response_scenario",
      ],
      [scenarioConfig, { credential: { status: 700 } }, "invalid_issuance_response_scenario"],
      [scenarioConfig, { par: {} }, "invalid_issuance_response_scenario"],
    ])("refuses issuance_response_scenario %j", async (appConfig, scenario, error) => {
      const response = await request(createApp(appConfig))
        .post("/sessions")
        .send({ issuance_response_scenario: scenario });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error });
    });

    it("delivers a PAR response without request_uri while recording Credo's real one", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        evidence_mode: "full",
        issuance_response_scenario: { par: { omit_parameters: ["/request_uri"] } },
      });

      const pushed = await pushAuthorization(app, session, {});
      const authorize = await request(app)
        .get(issuerProtocolPath(session, "/authorize"))
        .query({ client_id: walletClientId })
        .redirects(0);

      expect(pushed.status).toBe(201);
      expect(pushed.body).toEqual({ expires_in: expect.any(Number) });
      expect(authorize.status).toBeGreaterThanOrEqual(400);
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.issuance_response_scenario).toEqual({
        par: { omit_parameters: ["/request_uri"] },
      });
      const parCapture = capture.raw?.oid4vci_requests?.find((entry) =>
        entry.path.endsWith("/par"),
      );
      expect(parCapture?.response).toMatchObject({ status: 201, body: pushed.body });
      expect(
        capture.events.find((event) => event.type === "issuance_response_scenario_applied"),
      ).toMatchObject({
        detail: {
          endpoint: "par",
          request_id: parCapture?.id,
          original: {
            status: 201,
            body: { request_uri: expect.stringMatching(/^urn:ietf:params:oauth:request_uri:/) },
          },
          delivered: { status: 201, body: { expires_in: pushed.body.expires_in } },
        },
      });
      const ledger = await getJson<Oid4vciHttpRequestCapture[]>(app, "/oid4vci/requests");
      expect(
        ledger.find((entry) => entry.path.endsWith("/authorize") && entry.id !== parCapture?.id)
          ?.response.status,
      ).toBe(authorize.status);
    });

    it("denies a credential Credo issued and attributes the Wallet's retry", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        flow: "pre_authorized_code",
        issuance_response_scenario: {
          credential: {
            status: 400,
            content_type: "application/json",
            body: '{"error":"credential_request_denied"}',
          },
        },
      });
      const dpop = await dpopKey();
      const tokenResponse = await preAuthorizedToken(app, session, dpop);
      const proofs = async () => ({
        proofs: { jwt: [await credentialProofJwt(await dpopKey(), tokenResponse.c_nonce)] },
      });

      const denied = await requestCredential(app, session, await proofs(), {
        dpop,
        response: tokenResponse,
      });
      const retried = await requestCredential(app, session, await proofs(), {
        dpop,
        response: tokenResponse,
      });

      expect(denied.response.status).toBe(400);
      expect(denied.response.body).toEqual({ error: "credential_request_denied" });
      expect(denied.capture.status).toBe("credential_issued");
      const applied = retried.capture.events.filter(
        (event) => event.type === "issuance_response_scenario_applied",
      );
      expect(applied[0]).toMatchObject({
        detail: {
          endpoint: "credential",
          original: {
            status: 200,
            body: { credentials: [{ credential: { redacted: true, present: true } }] },
          },
          delivered: { status: 400, body: { error: "credential_request_denied" } },
        },
      });
      expect(
        retried.capture.raw?.oid4vci_requests?.filter((entry) => entry.path.endsWith("/credential"))
          .length,
      ).toBe(2);
    });

    it.each([
      ["eu-eaa-offer://", "credential_offer"],
      ["haip-vci://", "credential_offer"],
      ["haip-vci://", "credential_offer_uri"],
    ])("delivers the offer with the %s scheme by %s", async (scheme, mode) => {
      const app = createApp(config);

      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        offer_scheme: scheme,
        credential_offer_mode: mode,
      });

      expect(session.offer_scheme).toBe(scheme);
      expect(session.deeplink.startsWith(`${scheme}?`)).toBe(true);
      const deeplink = new URL(session.deeplink);
      if (mode === "credential_offer") {
        expect(JSON.parse(String(deeplink.searchParams.get("credential_offer")))).toEqual(
          await getJson<JsonRecord>(app, `/sessions/${session.session_id}/offer`),
        );
      } else {
        expect(deeplink.searchParams.get("credential_offer_uri")).toBe(session.offer_url);
      }
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.offer_scheme).toBe(scheme);
    });

    it("keeps the default offer scheme out of the response and capture", async () => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});

      expect(session.deeplink.startsWith("openid-credential-offer://?")).toBe(true);
      expect(session).not.toHaveProperty("offer_scheme");
      const unsupported = await request(app).post("/sessions").send({ offer_scheme: "https://" });
      expect(unsupported.status).toBe(400);
      expect(unsupported.body).toMatchObject({
        error: "unsupported_offer_scheme",
        supported_offer_schemes: ["openid-credential-offer://", "eu-eaa-offer://", "haip-vci://"],
      });
    });

    it.each([
      [config, {}, { unset: ["/credential_issuer"] }, "offer_mutation_not_enabled"],
      [scenarioConfig, {}, { unset: ["credential_issuer"] }, "invalid_offer_mutation"],
      [scenarioConfig, {}, { remove: ["/credential_issuer"] }, "invalid_offer_mutation"],
      [
        scenarioConfig,
        { credential_offer_mode: "credential_offer_uri" },
        { unset: ["/credential_issuer"] },
        "offer_mutation_requires_by_value_offer",
      ],
    ])("refuses an offer_mutation it cannot apply", async (appConfig, body, mutation, error) => {
      const response = await request(createApp(appConfig))
        .post("/sessions")
        .send({ ...body, offer_mutation: mutation });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error });
    });

    it.each(["/credential_issuer", "/credential_configuration_ids"])(
      "delivers a by-value offer without %s and keeps the generated one",
      async (pointer) => {
        const app = createApp(scenarioConfig);

        const session = await postJson<SessionCreateResponse>(app, "/sessions", {
          offer_scheme: "eu-eaa-offer://",
          offer_mutation: { unset: [pointer] },
        });

        const delivered = JSON.parse(
          String(new URL(session.deeplink).searchParams.get("credential_offer")),
        ) as JsonRecord;
        const member = pointer.slice(1);
        expect(session.deeplink.startsWith("eu-eaa-offer://?")).toBe(true);
        expect(delivered).not.toHaveProperty(member);
        const generated = await getJson<JsonRecord>(app, `/sessions/${session.session_id}/offer`);
        expect(generated).toHaveProperty(member);
        const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
        expect(capture.offer_mutation).toEqual({ unset: [pointer] });
        expect(capture.raw?.credential_offer).toEqual(generated);
        expect(capture.raw?.credential_offer_delivered).toEqual(delivered);
        expect(capture.events).toContainEqual(
          expect.objectContaining({
            type: "credential_offer_mutation_applied",
            detail: { pointers: [pointer] },
          }),
        );
      },
    );
  });

  it("enforces the selected JWT proof key-attestation policy", async () => {
    const app = createApp(config);
    const requiredSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: sdJwtCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
      flow: "pre_authorized_code",
    });
    const requiredDpop = await dpopKey();
    const requiredToken = await preAuthorizedToken(app, requiredSession, requiredDpop);
    const holderKey = await dpopKey();
    const proofWithoutAttestation = await credentialProofJwtWithoutKeyAttestation(
      holderKey,
      requiredToken.c_nonce,
    );
    const requiredCredentialPath = issuerProtocolPath(requiredSession, "/credential");

    const rejected = await request(app)
      .post(requiredCredentialPath)
      .set("authorization", `DPoP ${requiredToken.access_token}`)
      .set(
        "DPoP",
        await dpopProof(requiredDpop, "POST", requiredCredentialPath, requiredToken.access_token),
      )
      .send({
        credential_configuration_id: requiredSession.credential_configuration_id,
        proofs: { jwt: [proofWithoutAttestation] },
      });

    expect(rejected.status).toBe(400);
    expect(rejected.body).toMatchObject({
      error: "invalid_proof",
      error_description: expect.stringContaining("Missing required key attestation"),
    });

    const jwtProofSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      issuer_configuration_id: jwtOnlyIssuerId,
      credential_configuration_id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
      flow: "pre_authorized_code",
    });
    const jwtProofDpop = await dpopKey();
    const jwtProofToken = await preAuthorizedToken(app, jwtProofSession, jwtProofDpop);
    const acceptedProof = await credentialProofJwtWithoutKeyAttestation(
      holderKey,
      jwtProofToken.c_nonce,
      `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
    );
    const jwtOnlyCredentialPath = issuerProtocolPath(jwtProofSession, "/credential");
    const accepted = await request(app)
      .post(jwtOnlyCredentialPath)
      .set("authorization", `DPoP ${jwtProofToken.access_token}`)
      .set(
        "DPoP",
        await dpopProof(jwtProofDpop, "POST", jwtOnlyCredentialPath, jwtProofToken.access_token),
      )
      .send({
        credential_configuration_id: jwtProofSession.credential_configuration_id,
        proofs: { jwt: [acceptedProof] },
      });

    expect(accepted.status).toBe(200);
    const capture = await getJson<SessionCapture>(app, `/sessions/${jwtProofSession.session_id}`);
    expect(capture.checks.proof_jwt_present).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(false);
    expect(capture.status).toBe("credential_issued");
  });

  it("issues the numeric credential with a floating-point kg claim", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      issuer_configuration_id: jwtOnlyIssuerId,
      credential_configuration_id: numericSdJwtCredentialConfigurationId(config, "jwt-proof"),
      flow: "pre_authorized_code",
    });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const holderKey = await dpopKey();
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: {
          jwt: [
            await credentialProofJwtWithoutKeyAttestation(
              holderKey,
              token.c_nonce,
              `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
            ),
          ],
        },
      });

    expect(credential.status, credential.text).toBe(200);
    const compact = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = new SdJwtVcService({} as never).fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject({ vct: NUMERIC_SD_JWT_VCT, kg: 70.5 });
    expect(typeof decoded.prettyClaims.kg).toBe("number");
  });

  it.each(["dc+sd-jwt", "mso_mdoc"] as const)(
    "issues the %s domestic PID with the PID claims and the domestic claim",
    async (format) => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        issuer_configuration_id: jwtOnlyIssuerId,
        credential_configuration_id: domesticPidCredentialConfigurationId(format, "jwt-proof"),
        flow: "pre_authorized_code",
      });
      const dpop = await dpopKey();
      const token = await preAuthorizedToken(app, session, dpop);
      const holderKey = await dpopKey();
      const credentialPath = issuerProtocolPath(session, "/credential");
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: {
            jwt: [
              await credentialProofJwtWithoutKeyAttestation(
                holderKey,
                token.c_nonce,
                `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
              ),
            ],
          },
        });

      expect(credential.status, credential.text).toBe(200);
      const encoded = (credential.body as CredentialResponse).credentials[0].credential;
      if (format === "dc+sd-jwt") {
        const decoded = new SdJwtVcService({} as never).fromCompact(encoded);
        expect(decoded.prettyClaims).toMatchObject({
          vct: DOMESTIC_PID_SD_JWT_VCT,
          given_name: "Mario",
          credimi_domestic_claim: "credimi-domestic-value",
        });
        expect(decoded.payload).not.toHaveProperty("credimi_domestic_claim");
        return;
      }
      const decoded = Mdoc.fromBase64Url(encoded);
      expect(decoded.docType).toBe(PID_MDOC_DOCTYPE);
      expect(decoded.issuerSignedNamespaces[PID_MDOC_NAMESPACE]).toMatchObject({
        given_name: "Mario",
      });
      expect(decoded.issuerSignedNamespaces[DOMESTIC_PID_MDOC_NAMESPACE]).toEqual({
        credimi_domestic_claim: "credimi-domestic-value",
      });
    },
  );

  it("uses Credo to verify JWT proof, key attestation, nonce, and holder binding", async () => {
    const app = createApp(config);
    const invalidSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
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
    const invalidCredentialPath = issuerProtocolPath(invalidSession, "/credential");
    const mismatchedCredential = await request(app)
      .post(invalidCredentialPath)
      .set("authorization", `DPoP ${invalidToken.access_token}`)
      .set(
        "DPoP",
        await dpopProof(invalidDpop, "POST", invalidCredentialPath, invalidToken.access_token),
      )
      .send({
        credential_configuration_id: invalidSession.credential_configuration_id,
        proofs: { jwt: [mismatchedProof] },
      });
    expect(mismatchedCredential.status).toBe(400);
    expect(mismatchedCredential.body).toMatchObject({ error: "invalid_proof" });

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const proof = await credentialProofJwt(walletKey, token.c_nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
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
    expect(issuerPayload.iss).toBe(`${config.issuer_base_url}${conformingIssuerPath}`);
    expect(issuerPayload.iss).not.toMatch(/^did:/);
    expect(verified.protectedHeader).toMatchObject({
      alg: "ES256",
      typ: "dc+sd-jwt",
      x5c: expect.any(Array),
    });

    const decoded = new SdJwtVcService({} as never).fromCompact(compactSdJwt);
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
      birth_family_name: "Rossi",
      birth_given_name: "Mario",
      birthdate: "1990-01-01",
      date_of_expiry: "2031-01-01",
      date_of_issuance: "2026-01-01",
      document_number: "CREDIMI-DEMO-001",
      email: "jane.doe@example.test",
      given_name: "Mario",
      family_name: "Rossi",
      issuing_authority: "Credimi Fake Issuer",
      issuing_country: "IT",
      issuing_jurisdiction: "IT-RM",
      nationalities: ["IT"],
      personal_administrative_number: "PID-DEMO-001",
      phone_number: "+390600000000",
      picture: expect.stringMatching(/^data:image\/jpeg;base64,\/9j\//),
      place_of_birth: { locality: "Roma" },
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
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
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
    const credentialPath = issuerProtocolPath(session, "/credential");

    const plaintextResponseEncryptionRequest = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .send(credentialRequest);
    expect(plaintextResponseEncryptionRequest.status).toBe(400);
    expect(plaintextResponseEncryptionRequest.body).toMatchObject({
      error: "invalid_encryption_parameters",
      error_description: "credential_response_encryption requires an encrypted Credential Request",
    });

    const metadata = await getJson<JsonRecord>(app, conformingMetadataPath);
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

    credentialEncryptionTestState.responseDelayMs = 25;
    const credentialResponse = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .type("application/jwt")
      .send(encryptedRequest);
    credentialEncryptionTestState.responseDelayMs = 0;

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
      .post(`${conformingIssuerPath}/credential`)
      .send({ proof: { proof_type: "jwt", jwt: unsignedJwt({ alg: "ES256", kid: "key-1" }) } });

    expect(response.status).toBe(401);
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

  it("rejects unknown issuers and credential configurations belonging to another issuer", async () => {
    const app = createApp(config);
    const unknownIssuer = await request(app)
      .post("/sessions")
      .send({ issuer_configuration_id: "missing-issuer" });
    const crossIssuerCredential = await request(app)
      .post("/sessions")
      .send({
        issuer_configuration_id: conformingIssuerId,
        credential_configuration_id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
      });

    expect(unknownIssuer.status).toBe(400);
    expect(unknownIssuer.body).toMatchObject({
      error: "unsupported_issuer_configuration",
      supported_issuer_configuration_ids: [conformingIssuerId, jwtOnlyIssuerId],
    });
    expect(crossIssuerCredential.status).toBe(400);
    expect(crossIssuerCredential.body).toMatchObject({
      error: "unsupported_credential_configuration",
      issuer_configuration_id: conformingIssuerId,
    });
  });

  it("does not accept one issuer's access token at another issuer's credential endpoint", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const credentialPath = `${jwtOnlyIssuerPath}/credential`;

    const response = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .send({
        credential_configuration_id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
        proofs: { jwt: [unsignedJwt({ alg: "ES256", jwk: dpop.publicJwk })] },
      });

    expect(response.status).toBe(401);
  });

  it("accepts independent wallet-attestation and DPoP keys at PAR", async () => {
    const app = createApp(config);
    const clientId = "https://wallet.example.test";
    const redirectUri = "https://wallet.example.test/callback";
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = await getJson<CredentialOfferResponse>(app, new URL(session.offer_url).pathname);
    const grant = offer.grants.authorization_code;
    const walletInstanceKey = await dpopKey();
    const unrelatedWalletInstanceKey = await dpopKey();
    const dpop = await dpopKey();
    const walletAttestation = await walletAttestationJwt(walletInstanceKey, clientId);
    const parPath = issuerProtocolPath(session, "/par");
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const parRequest = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: session.credential_configuration_id,
      issuer_state: String(grant.issuer_state),
      state: "wallet-state",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    };

    const invalidProof = await request(app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, "POST", parPath))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set(
        "OAuth-Client-Attestation-PoP",
        await walletAttestationPopJwt(unrelatedWalletInstanceKey, clientId),
      )
      .type("form")
      .send(parRequest);

    expect(invalidProof.status).toBe(401);
    expect(invalidProof.body).toMatchObject({ error: "invalid_client" });

    const accepted = await request(app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, "POST", parPath))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set(
        "OAuth-Client-Attestation-PoP",
        await walletAttestationPopJwt(walletInstanceKey, clientId),
      )
      .type("form")
      .send(parRequest);

    expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
    expect(accepted.body).toMatchObject({
      request_uri: expect.any(String),
      expires_in: expect.any(Number),
    });

    const authorize = await request(app)
      .get(issuerProtocolPath(session, "/authorize"))
      .query({
        client_id: clientId,
        request_uri: String(accepted.body.request_uri),
      })
      .redirects(0);
    expect(authorize.status).toBe(302);

    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    expect(autoApproval.status).toBe(302);

    const credoCallback = new URL(String(autoApproval.headers.location));
    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    expect(walletAuthorizationResponse.status).toBe(302);

    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));
    const authorizationCode = walletCallback.searchParams.get("code");
    expect(authorizationCode).toEqual(expect.any(String));

    const tokenPath = issuerProtocolPath(session, "/token");
    const token = await request(app)
      .post(tokenPath)
      .set("DPoP", await dpopProof(dpop, "POST", tokenPath))
      .set("OAuth-Client-Attestation", walletAttestation)
      .set(
        "OAuth-Client-Attestation-PoP",
        await walletAttestationPopJwt(walletInstanceKey, clientId),
      )
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(authorizationCode),
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      });

    expect(token.status, JSON.stringify(token.body)).toBe(200);
    expect(token.body).toMatchObject({
      access_token: expect.any(String),
      token_type: "DPoP",
    });
  });

  it("accepts a Client Attestation PoP from a wallet clock up to 60 seconds ahead", async () => {
    const app = createApp(config);
    const clientId = "https://wallet.example.test";
    const walletInstanceKey = await dpopKey();
    const walletAttestation = await walletAttestationJwt(walletInstanceKey, clientId);

    const pushWithClockAhead = async (seconds: number) => {
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
      const offer = await getJson<CredentialOfferResponse>(
        app,
        new URL(session.offer_url).pathname,
      );
      const parPath = issuerProtocolPath(session, "/par");
      return request(app)
        .post(parPath)
        .set("DPoP", await dpopProof(await dpopKey(), "POST", parPath))
        .set("OAuth-Client-Attestation", walletAttestation)
        .set(
          "OAuth-Client-Attestation-PoP",
          await walletAttestationPopJwt(walletInstanceKey, clientId, seconds),
        )
        .type("form")
        .send({
          response_type: "code",
          client_id: clientId,
          redirect_uri: "https://wallet.example.test/callback",
          scope: session.credential_configuration_id,
          issuer_state: String(offer.grants.authorization_code.issuer_state),
          code_challenge: createHash("sha256")
            .update(randomBytes(48).toString("base64url"))
            .digest("base64url"),
          code_challenge_method: "S256",
        });
    };

    const withinSkew = await pushWithClockAhead(45);
    expect(withinSkew.status, JSON.stringify(withinSkew.body)).toBe(201);

    const beyondSkew = await pushWithClockAhead(75);
    expect(beyondSkew.status).toBe(401);
    expect(beyondSkew.body).toMatchObject({ error: "invalid_client" });
  });

  it("issues the claim set named by fixture_id, end to end", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
      fixture_id: "pid_under_18",
    });
    expect(session.fixture_id).toBe("pid_under_18");

    const walletKey = await dpopKey();
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const proof = await credentialProofJwt(walletKey, token.c_nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    const disclosed = compactSdJwt
      .split("~")
      .slice(1)
      .filter((part) => part.length > 0)
      .map((part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown[]);

    expect(disclosed).toEqual(
      expect.arrayContaining([expect.arrayContaining(["age_over_18", false])]),
    );
    expect(disclosed).toEqual(
      expect.arrayContaining([expect.arrayContaining(["birthdate", "2012-03-04"])]),
    );

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.fixture_id).toBe("pid_under_18");
  });

  it("digests the disclosures with the algorithm named by digest_algorithm, end to end", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
      digest_algorithm: "sha-512",
    });
    expect(session.digest_algorithm).toBe("sha-512");

    const walletKey = await dpopKey();
    const dpop = await dpopKey();
    const token = await preAuthorizedToken(app, session, dpop);
    const proof = await credentialProofJwt(walletKey, token.c_nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await dpopProof(dpop, "POST", credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    const payload = JSON.parse(
      Buffer.from(compactSdJwt.split(".")[1] as string, "base64url").toString("utf8"),
    ) as JsonRecord;
    expect(payload._sd_alg).toBe("sha-512");

    // The claim alone proves nothing: a wallet recomputes every digest, so the entries of `_sd`
    // must actually be SHA-512 over the base64url disclosure.
    const digests = payload._sd as string[];
    const disclosures = compactSdJwt
      .split("~")
      .slice(1)
      .filter((part) => part.length > 0);
    expect(disclosures.length).toBeGreaterThan(0);
    for (const disclosure of disclosures) {
      expect(digests).toContain(
        createHash("sha512").update(disclosure, "ascii").digest("base64url"),
      );
    }

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.digest_algorithm).toBe("sha-512");
  });

  it("rejects an unknown fixture_id", async () => {
    const response = await request(createApp(config))
      .post("/sessions")
      .send({ fixture_id: "pid_person_z" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      error: "unsupported_fixture_id",
      supported_fixture_ids: expect.arrayContaining(["pid_default", "pid_under_18"]),
    });
  });

  it.each([
    [
      "an unknown fixture",
      { status_reference: "revoked", status_list_enabled: true },
      { error: "unsupported_status_reference" },
    ],
    [
      "a malformed fixture without status-list allocation",
      { status_reference: "negative_index" },
      { error: "status_reference_requires_status_list" },
    ],
    [
      "a digest algorithm SD-JWT VC does not allow",
      { digest_algorithm: "sha-1" },
      { error: "unsupported_digest_algorithm" },
    ],
    [
      "a digest algorithm for an mdoc configuration",
      {
        digest_algorithm: "sha-512",
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
      },
      { error: "digest_algorithm_unsupported_for_mdoc" },
    ],
  ])("rejects %s", async (_label, body, expected) => {
    const response = await request(createApp({ ...config, fcaf_scenarios_enabled: true }))
      .post("/sessions")
      .send(body);

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject(expected);
  });

  it("refuses a malformed status reference unless the deployment enables FCAF scenarios", async () => {
    const response = await request(createApp(config))
      .post("/sessions")
      .send({ status_reference: "negative_index", status_list_enabled: true });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "status_reference_not_enabled" });
  });

  it("runs the default authorization-code flow through the auto-approving OAuth server", async () => {
    const app = createApp(config);
    const walletClientId = "https://wallet.example.test";
    const walletRedirectUri = "https://wallet.example.test/callback";
    const walletState = "wallet-state";
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const dpop = await dpopKey();
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = JSON.parse(
      String(new URL(session.deeplink).searchParams.get("credential_offer")),
    ) as CredentialOfferResponse;
    const grant = offer.grants.authorization_code;

    expect(session.flow).toBe("authorization_code");
    expect(session.credential_offer_mode).toBe("credential_offer");
    expect(grant).toMatchObject({
      issuer_state: expect.any(String),
    });
    expect(grant).not.toHaveProperty("authorization_server");

    const parPath = issuerProtocolPath(session, "/par");
    const pushed = await request(app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, "POST", parPath))
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
      .get(issuerProtocolPath(session, "/authorize"))
      .query({
        client_id: walletClientId,
        request_uri: String(pushed.body.request_uri),
      })
      .redirects(0);
    expect(authorize.status).toBe(302);
    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    expect(externalAuthorizationUrl.pathname).toBe(
      `/authorization-servers/${conformingIssuerId}/authorize`,
    );

    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    expect(autoApproval.status).toBe(302);
    const credoCallback = new URL(String(autoApproval.headers.location));
    expect(credoCallback.pathname).toBe(issuerProtocolPath(session, "/redirect"));
    expect(credoCallback.searchParams.get("code")).toEqual(expect.any(String));

    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    expect(walletAuthorizationResponse.status).toBe(302);
    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));
    expect(walletCallback.origin + walletCallback.pathname).toBe(walletRedirectUri);
    expect(walletCallback.searchParams.get("state")).toBe(walletState);
    expect(walletCallback.searchParams.get("iss")).toBe(
      `${config.issuer_base_url}${conformingIssuerPath}`,
    );
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

  it("enforces the wallet's S256 PKCE at PAR and at the token endpoint", async () => {
    const app = createApp(config);
    const walletClientId = "https://wallet.example.test";
    const walletRedirectUri = "https://wallet.example.test/callback";
    const codeVerifier = randomBytes(48).toString("base64url");
    const dpop = await dpopKey();
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const offer = JSON.parse(
      String(new URL(session.deeplink).searchParams.get("credential_offer")),
    ) as CredentialOfferResponse;
    const parPath = issuerProtocolPath(session, "/par");
    const parRequest = {
      response_type: "code",
      client_id: walletClientId,
      redirect_uri: walletRedirectUri,
      scope: session.credential_configuration_id,
      issuer_state: String(offer.grants.authorization_code.issuer_state),
      state: "wallet-state",
    };

    const withoutPkce = await request(app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, "POST", parPath))
      .type("form")
      .send(parRequest);
    expect(withoutPkce.status).toBe(400);
    expect(withoutPkce.body).toMatchObject({ error: "invalid_request" });

    const pushed = await request(app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, "POST", parPath))
      .type("form")
      .send({
        ...parRequest,
        code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
        code_challenge_method: "S256",
      });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const authorize = await request(app)
      .get(issuerProtocolPath(session, "/authorize"))
      .query({ client_id: walletClientId, request_uri: String(pushed.body.request_uri) })
      .redirects(0);
    const externalAuthorizationUrl = new URL(String(authorize.headers.location));
    const autoApproval = await request(app)
      .get(`${externalAuthorizationUrl.pathname}${externalAuthorizationUrl.search}`)
      .redirects(0);
    const credoCallback = new URL(String(autoApproval.headers.location));
    const walletAuthorizationResponse = await request(app)
      .get(`${credoCallback.pathname}${credoCallback.search}`)
      .redirects(0);
    const walletCallback = new URL(String(walletAuthorizationResponse.headers.location));

    const tokenPath = issuerProtocolPath(session, "/token");
    const token = await request(app)
      .post(tokenPath)
      .set("DPoP", await dpopProof(dpop, "POST", tokenPath))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(walletCallback.searchParams.get("code")),
        code_verifier: randomBytes(48).toString("base64url"),
        redirect_uri: walletRedirectUri,
        client_id: walletClientId,
      });
    expect(token.status).toBe(400);
    expect(token.body).toMatchObject({ error: "invalid_grant" });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).not.toBe("token_issued");
    expect(capture.checks.pkce_valid).not.toBe(true);
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

  it("rejects unknown credential-offer modes", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/sessions")
      .send({ credential_offer_mode: "reference" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "unsupported_credential_offer_mode",
      supported_credential_offer_modes: ["credential_offer", "credential_offer_uri"],
    });
  });
});

describe("OpenID4VP over the Digital Credentials API", () => {
  const dcApiOrigin = "https://wallet-capture.example.test";
  const dcApiConfig = { ...config, public_base_url: `${dcApiOrigin}/` };

  async function dcApiSession(
    app: Express,
    body: JsonRecord = {},
  ): Promise<VpSessionCreateResponse & { dc_api_request: { protocol: string; data: JsonRecord } }> {
    return postJson(app, "/openid4vp/sessions", {
      response_mode: "dc_api.jwt",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      ...body,
    });
  }

  it("returns the presentation page URL as the deeplink and omits redirect-only members", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    expect(session.deeplink).toBe(
      `${dcApiOrigin}/ui/openid4vp/sessions/${session.session_id}/dc_api_presentation`,
    );
    expect(session.request_delivery).toBe("by_value");
    expect(session).not.toHaveProperty("request_uri");
    expect(session).not.toHaveProperty("response_uri");
    expect(session).not.toHaveProperty("request_uri_method");
    expect(session).not.toHaveProperty("scheme");
    expect(JSON.stringify(session)).not.toContain('"undefined"');
  });

  it("signs a Request Object carrying client_id and the configured expected_origins", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    expect(session.dc_api_request.protocol).toBe("openid4vp-v1-signed");
    const requestObject = session.dc_api_request.data.request as string;
    expect(decodeProtectedHeader(requestObject).typ).toBe("oauth-authz-req+jwt");
    const payload = decodeJwt(requestObject) as JsonRecord;
    expect(payload.client_id).toMatch(/^x509_hash:/);
    expect(payload.expected_origins).toEqual([dcApiOrigin]);
    expect(payload.response_mode).toBe("dc_api.jwt");
    expect(payload).not.toHaveProperty("aud");
    expect(payload).not.toHaveProperty("state");
    expect(payload).not.toHaveProperty("response_uri");
    expect(payload).not.toHaveProperty("request_uri");
  });

  it("sends unsigned request parameters without client_id for plain request delivery", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, {
      response_mode: "dc_api",
      request_delivery: "plain",
    });

    expect(session.dc_api_request.protocol).toBe("openid4vp-v1-unsigned");
    expect(session.dc_api_request.data).not.toHaveProperty("client_id");
    expect(session.dc_api_request.data).not.toHaveProperty("expected_origins");
    expect(session.dc_api_request.data).not.toHaveProperty("request");
    expect(session.dc_api_request.data).toMatchObject({
      response_type: "vp_token",
      response_mode: "dc_api",
      nonce: expect.any(String),
    });
  });

  it("does not serve a request_uri for a DC API session", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const served = await request(app).get(`/openid4vp/sessions/${session.session_id}/request`);
    const posted = await request(app).post(`/openid4vp/sessions/${session.session_id}/request`);

    expect(served.status).toBe(404);
    expect(served.body).toEqual({ error: "vp_request_uri_not_available_for_dc_api" });
    expect(posted.status).toBe(404);

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("created");
    expect(capture.observed.request_uri_payload.value).toBeNull();
  });

  it.each([
    [
      "request_delivery",
      { request_delivery: "by_reference" },
      "request_delivery_unsupported_for_dc_api",
    ],
    [
      "client_id_scheme",
      { client_id_scheme: "redirect_uri" },
      "client_id_scheme_unsupported_for_dc_api",
    ],
    [
      "request_uri_method",
      { request_uri_method: "post" },
      "request_uri_method_unsupported_for_dc_api",
    ],
  ])("rejects %s inputs that a DC API request cannot carry", async (_label, body, error) => {
    const app = createApp(dcApiConfig);

    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ response_mode: "dc_api.jwt", ...body });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error });
  });

  it("rejects unknown response modes instead of falling back to direct_post.jwt", async () => {
    const app = createApp(dcApiConfig);

    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ response_mode: "dc-api" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "unsupported_response_mode" });
  });

  it("serves a presentation page that invokes the wallet from the button only", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const page = await request(app).get(
      `/ui/openid4vp/sessions/${session.session_id}/dc_api_presentation`,
    );

    expect(page.status).toBe(200);
    expect(page.headers["cache-control"]).toBe("no-store");
    expect(page.text).toContain(">Present credential</button>");
    expect(page.text).toContain(session.dc_api_request.data.request as string);
    expect(page.text).toContain('button.addEventListener("click"');
    expect(page.text).toContain(
      "navigator.credentials.get({ digital: { requests: [config.request]",
    );
    expect(page.text).not.toContain("presentation_validation");
  });

  it("accepts an encrypted DC API presentation bound to the browser origin", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(200);
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
    expect(capture.raw?.presentation_response_decrypted?.vp_token).toEqual({
      query_0: [presentation],
    });
  });

  it("does not require state for an unbound credential requested over the DC API", async () => {
    const app = createApp(dcApiConfig);
    const dcqlQuery = dcqlForClaims(["family_name"]);
    (dcqlQuery.credentials as JsonRecord[])[0].require_cryptographic_holder_binding = false;
    const session = await dcApiSession(app, {
      presentation_request: { state: null, dcql_query: dcqlQuery },
    });
    const presentation = await sdJwtPresentation({
      credential: await sdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status, response.text).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks).toMatchObject({ presentation_valid: true, errors: [] });
  });

  it("signs one DC API request under both Client Identifiers for multisigned delivery", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, { request_delivery: "multisigned" });

    expect(session.request_delivery).toBe("multisigned");
    expect(session.dc_api_request.protocol).toBe("openid4vp-v1-multisigned");
    const jws = session.dc_api_request.data.request as {
      payload: string;
      signatures: { protected: string; signature: string }[];
    };
    expect(jws.signatures).toHaveLength(2);
    const payload = JSON.parse(Buffer.from(jws.payload, "base64url").toString("utf8"));
    expect(payload).not.toHaveProperty("client_id");
    expect(payload).toMatchObject({
      expected_origins: [dcApiOrigin],
      response_mode: "dc_api.jwt",
      nonce: session.authorization_request.nonce,
    });

    const verifierJwks = JSON.parse(readFileSync(verifierJwksPath(config.data_dir), "utf8"));
    const didDocument = (await request(app).get("/openid4vp/did.json")).body;
    const keys = [
      await importJWK(verifierJwks.keys[0], "ES256"),
      await importJWK(didDocument.verificationMethod[0].publicKeyJwk, "ES256"),
    ];
    const headers = await Promise.all(
      jws.signatures.map(async (signature, index) => {
        const verified = await flattenedVerify({ payload: jws.payload, ...signature }, keys[index]);
        return verified.protectedHeader;
      }),
    );
    expect(headers[0]).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      client_id: session.authorization_request.client_id,
      x5c: [expect.any(String)],
    });
    expect(headers[1]).toMatchObject({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      client_id: `decentralized_identifier:${didDocument.id}`,
      kid: `${didDocument.id}#credimi-fake-verifier-did-key`,
    });
  });

  it("verifies a presentation answering a multisigned DC API request", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, { request_delivery: "multisigned" });
    const presentation = await sdJwtPresentation({
      credential: await sdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
  });

  it.each([
    [
      { response_mode: "direct_post", request_delivery: "multisigned" },
      "multisigned_request_delivery_requires_dc_api",
    ],
    [
      { request_delivery: "multisigned", client_id_scheme: "decentralized_identifier" },
      "client_id_scheme_unsupported_for_multisigned",
    ],
    [
      {
        request_delivery: "multisigned",
        presentation_request: {
          dcql_query: dcqlForClaims(["family_name"]),
          verifier_info: [{ format: "jwt", data: "eyJ.e30.sig" }],
        },
      },
      "verifier_info_unsupported_for_multisigned",
    ],
  ])("rejects a multisigned request it cannot sign faithfully: %o", async (body, error) => {
    const response = await request(createApp(dcApiConfig))
      .post("/openid4vp/sessions")
      .send({ response_mode: "dc_api.jwt", ...body });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error });
  });

  it("rejects a DC API presentation bound to the client_id instead of the origin", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        response: await encryptedAuthorizationResponse(session.authorization_request, {
          vp_token: { query_0: [presentation] },
        }),
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe("invalid_presentation");
  });

  it("captures a wallet refusal as a refusal rather than a verification failure", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app, { response_mode: "dc_api" });

    const reported = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/dc_api_invocation`)
      .send({
        outcome: "rejected",
        error_name: "NotAllowedError",
        error_message: "The request is not allowed",
        response_returned: false,
        vp_token_present: false,
      });

    expect(reported.status).toBe(202);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("dc_api_invocation_reported");
    expect(capture.dc_api?.invocation).toMatchObject({
      outcome: "rejected",
      error_name: "NotAllowedError",
      response_returned: false,
      vp_token_present: false,
    });
    expect(capture.checks.presentation_valid).toBeNull();
    expect(capture.events.map((event) => event.type)).toContain("vp_dc_api_invocation_reported");
  });

  it("rejects invocation reports with an unknown outcome", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/dc_api_invocation`)
      .send({ outcome: "wallet_exploded" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "unsupported_dc_api_invocation_outcome" });
  });

  it("keeps the first presentation when a DC API response is replayed", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      audience: `origin:${dcApiOrigin}`,
    });
    const submit = async () =>
      request(app)
        .post(`/openid4vp/sessions/${session.session_id}/response`)
        .send({
          response: await encryptedAuthorizationResponse(session.authorization_request, {
            vp_token: { query_0: [presentation] },
          }),
        });

    const first = await submit();
    const replay = await submit();

    expect(first.status).toBe(200);
    expect(replay.status).toBe(409);
    expect(replay.body).toEqual({ error: "vp_session_already_completed" });
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.status).toBe("presentation_validated");
  });

  it("refuses a submission whose browser Origin is not the session origin", async () => {
    const app = createApp(dcApiConfig);
    const session = await dcApiSession(app);

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .set("origin", "https://attacker.example.test")
      .send({ vp_token: { query_0: ["forged"] } });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "unexpected_dc_api_origin" });
  });

  it("closes the presentation window once the session expires", async () => {
    const store = new CaptureStore(dcApiConfig);
    const app = createApp(dcApiConfig, store);
    const session = await dcApiSession(app);
    const stored = store.getVpSession(session.session_id);
    if (!stored?.dc_api) throw new Error("DC API session capture missing");
    stored.dc_api.expires_at = new Date(Date.now() - 1000).toISOString();

    const page = await request(app).get(
      `/ui/openid4vp/sessions/${session.session_id}/dc_api_presentation`,
    );
    const submitted = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: { query_0: ["late"] } });

    expect(page.status).toBe(200);
    expect(page.text).toContain("expired");
    expect(page.text).not.toContain(">Present credential</button>");
    expect(submitted.status).toBe(400);
    expect(submitted.body).toEqual({ error: "vp_session_expired" });
  });

  it("leaves redirect sessions able to record repeated wallet submissions", async () => {
    const app = createApp(dcApiConfig);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
    });

    const first = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: "presentation-token" });
    const second = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ vp_token: "presentation-token" });

    expect(first.status).toBe(400);
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("invalid_presentation");
  });
});
/** A Wallet encryption key pair whose public half a POST Request URI `wallet_metadata` carries. */
async function walletEncryptionKey(
  crv: "P-256" | "P-384" | "X25519",
): Promise<{ publicJwk: JWK; privateKey: KeyLike }> {
  const { publicKey, privateKey } = await generateKeyPair("ECDH-ES", { crv, extractable: true });
  return {
    publicJwk: { ...(await exportJWK(publicKey)), kid: "wallet-enc-1", use: "enc", alg: "ECDH-ES" },
    privateKey,
  };
}

/** OpenID4VP Section 5.10 `wallet_metadata` from a Wallet that requires an encrypted Request Object. */
function encryptingWalletMetadata(publicJwk: JWK, enc: string): string {
  return JSON.stringify({
    vp_formats_supported: { "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] } },
    jwks: { keys: [publicJwk] },
    request_object_encryption_alg_values_supported: ["ECDH-ES"],
    request_object_encryption_enc_values_supported: [enc],
  });
}

async function postJson<T>(app: Express, path: string, body: object): Promise<T> {
  const response = await request(app).post(path).send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
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
        credential: await sdJwtCredential(),
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

describe("scope-based presentation requests", () => {
  const scope = "eu.europa.ec.eudi.pid.1";

  it("delivers the scope without a dcql_query while keeping the query for verification", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: null, scope },
    });

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const delivered = decodeJwt(requestObject.text) as JsonRecord;
    expect(delivered.scope).toBe(scope);
    expect(delivered.dcql_query).toBeUndefined();
    // The verifier keeps a query: Credo matches the response against the request it holds, and a
    // scope value is resolved by the wallet's profile rather than by anything sent on the wire.
    expect(session.authorization_request.dcql_query).toBeDefined();

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.authorization_request_delivered?.dcql_query).toBeUndefined();
  });

  it("omits dcql_query from a plain deeplink while still carrying the scope", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "plain",
      presentation_request: { dcql_query: null, scope },
    });

    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("scope")).toBe(scope);
    expect(deeplink.searchParams.has("dcql_query")).toBe(false);
  });

  it("verifies a presentation returned for a scope-only request", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]), scope },
      request_mutation: { request_object: { unset: ["/dcql_query"] } },
    });
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect((decodeJwt(requestObject.text) as JsonRecord).dcql_query).toBeUndefined();

    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.dcql_query_matched).toBe(true);
    expect(capture.checks.presentation_valid).toBe(true);
  });

  it("sends a scope alongside dcql_query when both are requested", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]), scope },
    });

    const delivered = decodeJwt(
      (await request(app).get(`/openid4vp/sessions/${session.session_id}/request`)).text,
    ) as JsonRecord;
    expect(delivered.scope).toBe(scope);
    expect(delivered.dcql_query).toEqual(dcqlForClaims(["family_name"]));
  });
});

describe("verifier attestation requests", () => {
  async function attestationRequest(app: Express, body: JsonRecord = {}) {
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      client_id_scheme: "verifier_attestation",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      ...body,
    });
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const header = decodeProtectedHeader(requestObject.text) as JsonRecord;
    const attestation =
      typeof header.jwt === "string" ? (decodeJwt(header.jwt) as JsonRecord) : undefined;
    return { session, jwt: requestObject.text, header, attestation };
  }

  it("carries an attestation bound to the client identifier and the signing key", async () => {
    const app = createApp(config);
    const { session, jwt, attestation } = await attestationRequest(app);

    expect(session.authorization_request.client_id).toBe(
      `verifier_attestation:${attestation?.sub}`,
    );
    const confirmationKey = (attestation?.cnf as JsonRecord).jwk as JsonRecord;
    await expect(
      compactVerify(jwt, await importJWK(confirmationKey as unknown as JWK, "ES256")),
    ).resolves.toBeDefined();
    // A wallet must not be forced into a redirect URI match when the attestation makes no claim.
    expect(attestation).not.toHaveProperty("redirect_uris");
    expect(decodeProtectedHeader(jwt).x5c).toBeUndefined();
  });

  it("publishes the attestation issuer key so a wallet can be configured to trust it", async () => {
    const app = createApp(config);
    const { attestation } = await attestationRequest(app);
    const jwks = await getJson<JwksResponse>(
      app,
      "/openid4vp/verifier-attestation-issuer/jwks.json",
    );
    expect(attestation?.iss).toBe(
      `${config.issuer_base_url}/openid4vp/verifier-attestation-issuer`,
    );
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("attests a subject that differs from the client identifier when asked", async () => {
    const app = createApp(config);
    const { session, attestation } = await attestationRequest(app, {
      verifier_attestation: { subject: "someone-else.example" },
    });

    expect(attestation?.sub).toBe("someone-else.example");
    expect(session.authorization_request.client_id).not.toBe(
      "verifier_attestation:someone-else.example",
    );
  });

  it("names an issuer outside the wallet's trusted list when asked", async () => {
    const app = createApp(config);
    const { attestation } = await attestationRequest(app, {
      verifier_attestation: { issuer: "https://untrusted-attestation-issuer.invalid" },
    });

    expect(attestation?.iss).toBe("https://untrusted-attestation-issuer.invalid");
  });

  it("breaks only the attestation signature, leaving the request object signed", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const { jwt, header, attestation } = await attestationRequest(app, {
      verifier_attestation: { signature: "corrupt" },
    });

    const issuerJwks = await getJson<JwksResponse>(
      app,
      "/openid4vp/verifier-attestation-issuer/jwks.json",
    );
    await expect(
      compactVerify(
        String(header.jwt),
        await importJWK(issuerJwks.keys[0] as unknown as JWK, "ES256"),
      ),
    ).rejects.toThrow();
    const confirmationKey = (attestation?.cnf as JsonRecord).jwk as JsonRecord;
    await expect(
      compactVerify(jwt, await importJWK(confirmationKey as unknown as JWK, "ES256")),
    ).resolves.toBeDefined();
  });

  it("signs with a key that does not match the confirmation claim when asked", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const { jwt, attestation } = await attestationRequest(app, {
      request_behavior: { signing_key: "unrelated" },
    });

    const confirmationKey = (attestation?.cnf as JsonRecord).jwk as JsonRecord;
    await expect(
      compactVerify(jwt, await importJWK(confirmationKey as unknown as JWK, "ES256")),
    ).rejects.toThrow();
  });

  it("includes redirect_uris in the attestation when asked", async () => {
    const app = createApp(config);
    const { attestation } = await attestationRequest(app, {
      verifier_attestation: { redirect_uris: ["https://relying-party.example/callback"] },
    });

    expect(attestation?.redirect_uris).toEqual(["https://relying-party.example/callback"]);
  });

  it("refuses attestation content without the matching client identifier prefix", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({ verifier_attestation: { subject: "someone-else.example" } });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "verifier_attestation_requires_verifier_attestation_client_id",
    });
  });

  it("refuses a corrupt attestation signature when scenarios are disabled", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        client_id_scheme: "verifier_attestation",
        verifier_attestation: { signature: "corrupt" },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "request_behavior_not_enabled" });
  });

  it("verifies a presentation returned for an attestation-based request", async () => {
    const app = createApp(config);
    const { session } = await attestationRequest(app);
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.presentation_valid).toBe(true);
  });
});

describe("verifier attestation requests under a certificate with only a URI SAN", () => {
  // The shipped test certificate also carries a dNSName SAN, which hid the deployed failure:
  // Credo treated the prefix as x509_san_dns and refused a certificate without a matching one.
  const uriSanDataDir = mkdtempSync(join(tmpdir(), "fake-issuer-uri-san-test-"));
  const uriSanConfig = { ...config, data_dir: uriSanDataDir };

  beforeAll(async () => {
    await initIssuer({
      issuer_base_url: uriSanConfig.issuer_base_url,
      data_dir: uriSanDataDir,
      credential_configuration_id: uriSanConfig.credential_configuration_id,
      force: true,
    });
    const privateJwk = JSON.parse(
      readFileSync(verifierPrivateJwkPath(uriSanDataDir), "utf8"),
    ) as JsonRecord;
    const { d: _private, ...publicJwk } = privateJwk;
    const authorityKey = Kms.PublicJwk.fromUnknown(publicJwk);
    authorityKey.keyId = String(privateJwk.kid);
    const certificate = await X509Certificate.create(
      {
        authorityKey,
        issuer: { countryName: "IT", commonName: "Credimi URI SAN Verifier" },
        validity: {
          notBefore: new Date("2024-01-01T00:00:00Z"),
          notAfter: new Date("2034-01-01T00:00:00Z"),
        },
        extensions: {
          keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
          subjectAlternativeName: { name: [{ type: "url", value: uriSanConfig.issuer_base_url }] },
          basicConstraints: { ca: false },
        },
      },
      new CredoWebCrypto(createJwkSigningContext(privateJwk, String(privateJwk.kid)) as never),
    );
    writeFileSync(verifierCertificatePath(uriSanDataDir), certificate.toString("pem"));
  });

  afterAll(() => {
    rmSync(uriSanDataDir, { recursive: true, force: true });
  });

  async function uriSanAttestationSession(app: Express, body: JsonRecord = {}) {
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "direct_post",
        client_id_scheme: "verifier_attestation",
        request_uri_method: "post",
        presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
        ...body,
      });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    return response.body as VpSessionCreateResponse;
  }

  it("uses a certificate without any dNSName SAN", () => {
    const certificate = X509Certificate.fromEncodedCertificate(
      readFileSync(verifierCertificatePath(uriSanDataDir), "utf8"),
    );
    expect(certificate.sanDnsNames).toEqual([]);
    expect(certificate.sanUriNames).toEqual([uriSanConfig.issuer_base_url]);
  });

  it("delivers the attestation request by GET and POST request_uri, and on wallet_nonce", async () => {
    const app = createApp(uriSanConfig);
    const session = await uriSanAttestationSession(app);
    const clientId = String(session.authorization_request.client_id);
    expect(clientId).toBe("verifier_attestation:issuer.example.test");

    const requestPath = `/openid4vp/sessions/${session.session_id}/request`;
    const fetched = await request(app).get(requestPath);
    const posted = await request(app).post(requestPath).type("form").send({});
    const resigned = await request(app)
      .post(requestPath)
      .type("form")
      .send({ wallet_nonce: "uri-san-wallet-nonce" });

    for (const [response, walletNonce] of [
      [fetched, undefined],
      [posted, undefined],
      [resigned, "uri-san-wallet-nonce"],
    ] as const) {
      expect(response.status).toBe(200);
      const header = decodeProtectedHeader(response.text) as JsonRecord;
      expect(header).not.toHaveProperty("x5c");
      const attestation = decodeJwt(String(header.jwt)) as JsonRecord;
      expect(`verifier_attestation:${attestation.sub}`).toBe(clientId);
      const confirmationKey = (attestation.cnf as JsonRecord).jwk as JsonRecord;
      const { payload } = await compactVerify(
        response.text,
        await importJWK(confirmationKey as unknown as JWK, "ES256"),
      );
      const delivered = JSON.parse(Buffer.from(payload).toString("utf8")) as JsonRecord;
      expect(delivered.client_id).toBe(clientId);
      expect(delivered.wallet_nonce).toBe(walletNonce);
    }
  });

  it("verifies an Authorization Response under the verifier_attestation client_id", async () => {
    const app = createApp(uriSanConfig);
    const session = await uriSanAttestationSession(app);
    const presentation = await sdJwtPresentation({
      credential: await sdJwtCredential(),
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    expect(String(session.authorization_request.client_id)).toMatch(/^verifier_attestation:/);

    const response = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ state: session.authorization_request.state, vp_token: { query_0: [presentation] } });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks).toMatchObject({ presentation_valid: true, errors: [] });
  });

  it("replaces {{response_uri}} in redirect_uris with the session's response_uri", async () => {
    const app = createApp(uriSanConfig);
    const session = await uriSanAttestationSession(app, {
      verifier_attestation: {
        redirect_uris: ["{{response_uri}}", "https://relying-party.example/callback"],
      },
    });
    const requestObject = await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/request`)
      .type("form")
      .send({});
    const header = decodeProtectedHeader(requestObject.text) as JsonRecord;
    const attestation = decodeJwt(String(header.jwt)) as JsonRecord;
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );

    const expected = [session.response_uri, "https://relying-party.example/callback"];
    expect(session.response_uri).toMatch(/^http:\/\/issuer\.example\.test\/openid4vp\/sessions\//);
    expect(attestation.redirect_uris).toEqual(expected);
    expect(capture.verifier_attestation).toEqual({ redirect_uris: expected });
  });

  it("refuses {{response_uri}} for a DC API session, which has no response_uri", async () => {
    const app = createApp(uriSanConfig);
    const response = await request(app)
      .post("/openid4vp/sessions")
      .send({
        response_mode: "dc_api",
        client_id_scheme: "verifier_attestation",
        verifier_attestation: { redirect_uris: ["{{response_uri}}"] },
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "response_uri_placeholder_unsupported_for_dc_api" });
  });
});

describe("presentation digest algorithms", () => {
  it("records the digest algorithm the presented credential used", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ state: session.authorization_request.state, vp_token: { query_0: [presentation] } });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    const presented = (capture.decoded_presentations?.query_0 as JsonRecord[])[0];
    // Section 4.1.1 defaults an absent _sd_alg to sha-256, so the evidence states it either way.
    expect(presented.digest_algorithm).toBe("sha-256");
    expect(presented.claims).not.toHaveProperty("_sd_alg");
  });
});

describe("caller-supplied verifier info", () => {
  it("publishes the client identifier for every supported prefix", async () => {
    const app = createApp(config);
    const identifiers = await getJson<JsonRecord>(app, "/openid4vp/client-identifiers");
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {});

    expect(identifiers.x509_hash).toBe(session.authorization_request.client_id);
    expect(identifiers.decentralized_identifier).toMatch(/^decentralized_identifier:did:web:/);
    expect(identifiers.verifier_attestation).toMatch(/^verifier_attestation:/);
  });

  it("delivers a caller-signed attestation bound to the caller's own nonce", async () => {
    const app = createApp(config);
    const identifiers = await getJson<JsonRecord>(app, "/openid4vp/client-identifiers");
    const nonce = "caller-chosen-nonce";
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    // The harness signs the attestation and its proof of possession, because the structure is
    // defined by the profile under test rather than by this service.
    const attestation = await new SignJWT({ sub: String(identifiers.x509_hash) })
      .setProtectedHeader({ alg: "ES256", typ: "jwt" })
      .sign(privateKey);
    const proofOfPossession = await new SignJWT({
      nonce,
      client_id: identifiers.x509_hash,
    })
      .setProtectedHeader({ alg: "ES256" })
      .sign(privateKey);
    const verifierInfo = [
      {
        format: "jwt",
        data: attestation,
        proof_of_possession: proofOfPossession,
        credential_ids: ["query_0"],
      },
    ];

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { nonce, verifier_info: verifierInfo },
    });

    expect(session.authorization_request.nonce).toBe(nonce);
    const delivered = decodeJwt(
      (await request(app).get(`/openid4vp/sessions/${session.session_id}/request`)).text,
    ) as JsonRecord;
    expect(delivered.verifier_info).toEqual(verifierInfo);
    const deliveredProof = decodeJwt(
      (delivered.verifier_info as JsonRecord[])[0].proof_of_possession as string,
    );
    expect(deliveredProof.nonce).toBe(nonce);
    expect(deliveredProof.client_id).toBe(identifiers.x509_hash);
  });
});

describe("transaction data binding", () => {
  const entry = {
    type: "qes_authorization",
    credential_ids: ["query_0"],
    transaction_data_hashes_alg: ["sha-256"],
  };

  async function presentWithTransactionData(options: {
    transactionData: unknown[];
    hashes: (delivered: string[]) => string[] | undefined;
    hashesAlg?: string;
  }) {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name"]),
        transaction_data: options.transactionData,
      },
    });
    const delivered = session.authorization_request.transaction_data as string[];
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      transactionDataHashes: options.hashes(delivered),
      // Credo rejects a Key Binding JWT that carries hashes without naming their algorithm.
      transactionDataHashesAlg: options.hashesAlg ?? "sha-256",
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    return capture;
  }

  function hashOf(entry: string, algorithm = "sha256"): string {
    return createHash(algorithm).update(entry, "ascii").digest("base64url");
  }

  it("accepts a presentation whose hashes cover the entries sent", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: (delivered) => delivered.map((value) => hashOf(value)),
    });

    expect(capture.checks.transaction_data_verified).toBe(true);
    expect(capture.checks.presentation_valid).toBe(true);
  });

  it("rejects hashes computed with an algorithm the entry did not offer", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: (delivered) => delivered.map((value) => hashOf(value, "sha384")),
      hashesAlg: "sha-384",
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.join(" ")).toContain("sha-384");
  });

  it("rejects a presentation whose hash covers no entry that was sent", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: () => [hashOf("an entry the verifier never sent")],
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.join(" ")).toContain("invalid_transaction_data");
  });

  it("rejects a presentation that omits the hashes for transaction data that was sent", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: () => undefined,
      hashesAlg: undefined,
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.join(" ")).toContain("invalid_transaction_data");
  });

  it("rejects a presentation leaving an entry for another credential uncovered", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry, { ...entry, credential_ids: ["query_1"] }],
      hashes: (delivered) => [hashOf(delivered[0])],
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
  });

  it("records no transaction data result when the request sent none", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const credential = await sdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.transaction_data_verified).toBeNull();
    expect(capture.checks.presentation_valid).toBe(true);
  });
});

describe("FCAF verifier response scenarios", () => {
  const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };

  async function submitValidPresentation(app: Express, responseScenario?: JsonRecord) {
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
      ...(responseScenario ? { response_scenario: responseScenario } : {}),
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

async function postForm<T>(app: Express, path: string, body: Record<string, string>): Promise<T> {
  const response = await request(app).post(path).type("form").send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function postToken(
  app: Express,
  body: Record<string, string>,
  dpopKey: DpopKey,
  issuerConfigurationId = conformingIssuerId,
): Promise<TokenResponse> {
  const tokenPath = `/issuers/${issuerConfigurationId}/token`;
  const response = await request(app)
    .post(tokenPath)
    .set("DPoP", await dpopProof(dpopKey, "POST", tokenPath))
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
    session.issuer_configuration_id,
  );
}

async function getJson<T>(app: Express, path: string): Promise<T> {
  const response = await request(app).get(path);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

function verifierPublicJwk(): JWK {
  const jwks = JSON.parse(readFileSync(verifierJwksPath(dataDir), "utf8")) as { keys: JWK[] };
  return jwks.keys[0];
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

function issuerProtocolPath(session: SessionCreateResponse, suffix: `/${string}`): string {
  return `/issuers/${session.issuer_configuration_id}${suffix}`;
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
  audience = `${config.issuer_base_url}${conformingIssuerPath}`,
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

async function credentialProofJwtWithoutKeyAttestation(
  key: DpopKey,
  nonce: string,
  audience = `${config.issuer_base_url}${conformingIssuerPath}`,
): Promise<string> {
  return new SignJWT({
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: key.publicJwk as unknown as JWK,
    })
    .sign(key.privateKey);
}

async function keyAttestationJwt(key: DpopKey, nonce: string): Promise<string> {
  const privateJwk = JSON.parse(
    readFileSync(privateJwkPath(conformingMaterialDirectory), "utf8"),
  ) as JWK;
  const certificate = readFileSync(issuerCertificatePath(conformingMaterialDirectory), "utf8")
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
  const privateJwk = JSON.parse(
    readFileSync(privateJwkPath(conformingMaterialDirectory), "utf8"),
  ) as JWK;
  const certificate = readFileSync(issuerCertificatePath(conformingMaterialDirectory), "utf8")
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

async function walletAttestationPopJwt(
  key: DpopKey,
  clientId: string,
  clockAheadSeconds = 0,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000) + clockAheadSeconds;
  return new SignJWT({
    iss: clientId,
    aud: `${config.issuer_base_url}${conformingIssuerPath}`,
    iat: now,
    nbf: now,
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
      config: conformingIssuerConfig,
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
  audience?: string;
  transactionDataHashes?: string[];
  transactionDataHashesAlg?: string;
}): Promise<string> {
  const [issuerJwt, ...tail] = options.credential.compact.split("~");
  const selected = tail
    .filter((part) => part.length > 0)
    .filter((disclosure) => options.disclosedClaims.includes(disclosureClaimName(disclosure)));
  const withoutKeyBinding = `${issuerJwt}~${selected.join("~")}~`;
  const keyBindingJwt = await new SignJWT({
    iat: Math.floor(Date.now() / 1000),
    aud: options.audience ?? String(options.authorizationRequest.client_id),
    nonce: String(options.authorizationRequest.nonce),
    sd_hash: createHash("sha256").update(withoutKeyBinding).digest("base64url"),
    ...(options.transactionDataHashes
      ? { transaction_data_hashes: options.transactionDataHashes }
      : {}),
    ...(options.transactionDataHashesAlg
      ? { transaction_data_hashes_alg: options.transactionDataHashesAlg }
      : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
    .sign(options.credential.privateKey);
  return `${withoutKeyBinding}${keyBindingJwt}`;
}

async function encryptedAuthorizationResponse(
  authorizationRequest: JsonRecord,
  payload: JsonRecord,
  enc = "A256GCM",
): Promise<string> {
  const clientMetadata = authorizationRequest.client_metadata as JsonRecord;
  const jwks = clientMetadata.jwks as { keys: JsonRecord[] };
  const publicJwk = jwks.keys[0] as unknown as JWK;
  return new CompactEncrypt(Buffer.from(JSON.stringify(payload), "utf8"))
    .setProtectedHeader({
      alg: "ECDH-ES",
      enc,
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
  issuer_configuration_id: string;
  issuer_identifier: string;
  authorization_server_identifier: string;
  flow: "pre_authorized_code" | "authorization_code";
  credential_offer_mode: "credential_offer" | "credential_offer_uri";
  credential_configuration_id: string;
  status_list_enabled: boolean;
  fixture_id?: string;
  digest_algorithm?: string;
  offer_url: string;
  deeplink: string;
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
  request_delivery: "by_reference" | "by_value" | "plain";
  request_uri?: string;
  request_uri_method?: string;
  scheme?: string;
  redirect_uri?: string;
  response_uri?: string;
  deeplink: string;
  dc_api_request?: { protocol: string; data: JsonRecord };
  authorization_request: JsonRecord;
  status: string;
}

interface VpSessionResponse extends JsonRecord {
  session_id: string;
  status: string;
  redirect_uri_visited_at?: string;
  redirect_uri_visit_count?: number;
  authorization_request: JsonRecord;
  decoded_presentations?: JsonRecord;
  request_mutation?: JsonRecord;
  response_scenario?: JsonRecord;
  verifier_attestation?: JsonRecord;
  dc_api?: {
    request: { protocol: string; data: JsonRecord };
    expected_origin: string;
    expires_at: string;
    invocation?: JsonRecord;
  };
  checks: {
    presentation_valid: boolean | null;
    vp_token_format_valid: boolean;
    nonce_verified: boolean;
    transaction_data_verified: boolean | null;
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
  events: Array<{ type: string; detail: JsonRecord }>;
  raw?: {
    authorization_request_jwt?: string;
    authorization_request_jwe?: string;
    authorization_request_delivered?: JsonRecord;
    outer_request_delivered?: JsonRecord;
    request_uri_response_http?: { status: number; headers: JsonRecord; body: string };
    request_uri_http?: {
      method: string;
      target: string;
      headers: JsonRecord;
      body?: string;
    };
    presentation_response?: JsonRecord;
    presentation_response_http?: {
      method: string;
      headers: JsonRecord;
      body: string;
    };
    presentation_response_verifier_http?: {
      status: number;
      headers: JsonRecord;
      body: string;
    };
    redirect_uri_visits?: Array<{
      method: string;
      headers: JsonRecord;
    }>;
    presentation_response_decrypted?: JsonRecord;
    decoded_presentations?: JsonRecord;
  };
}
