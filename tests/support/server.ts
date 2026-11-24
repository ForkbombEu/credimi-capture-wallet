import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { type JWK, type KeyLike, SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";
import { afterAll, afterEach, beforeAll, vi } from "vitest";
import { issuerCertificatePath, privateJwkPath } from "../../src/config/paths.js";
import { issuerAppConfig } from "../../src/configurations/resolve-urls.js";
import type { AppConfig, JsonRecord } from "../../src/types.js";
import {
  CONFORMING_ISSUER_ID,
  type IssuerTestEnvironment,
  createIssuerTestEnvironmentFactory,
  requireIssuer,
} from "./environment.js";
import { type SessionCreateResponse, credentialProofJwt } from "./issuance.js";
import { type TestKey, dpopProof } from "./keys.js";
import { sdJwtCredential } from "./presentation.js";
export interface JwksResponse extends JsonRecord {
  keys: JsonRecord[];
}

export function issuerProtocolPath(session: SessionCreateResponse, suffix: `/${string}`): string {
  return `/issuers/${session.issuer_configuration_id}${suffix}`;
}

export async function walletEncryptionKey(
  crv: "P-256" | "P-384" | "X25519",
): Promise<{ publicJwk: JWK; privateKey: KeyLike }> {
  const { publicKey, privateKey } = await generateKeyPair("ECDH-ES", { crv, extractable: true });
  return {
    publicJwk: { ...(await exportJWK(publicKey)), kid: "wallet-enc-1", use: "enc", alg: "ECDH-ES" },
    privateKey,
  };
}

export function encryptingWalletMetadata(publicJwk: JWK, enc: string): string {
  return JSON.stringify({
    vp_formats_supported: { "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] } },
    jwks: { keys: [publicJwk] },
    request_object_encryption_alg_values_supported: ["ECDH-ES"],
    request_object_encryption_enc_values_supported: [enc],
  });
}

interface PidSdJwtCredential {
  compact: string;
  privateKey: TestKey["privateKey"];
}

export interface ServerTestContext {
  dataDir: string;
  config: AppConfig;
  conformingIssuerId: string;
  jwtKeyAttestationIssuerId: string;
  jwtOnlyIssuerId: string;
  conformingIssuerPath: string;
  jwtKeyAttestationIssuerPath: string;
  jwtOnlyIssuerPath: string;
  conformingMetadataPath: string;
  conformingAuthorizationServerMetadataPath: string;
  conformingUpstreamAuthorizationServerMetadataPath: string;
  conformingIssuerConfig: AppConfig;
  pidSdJwtCredential(): Promise<PidSdJwtCredential>;
  conformingProofJwt(
    key: TestKey,
    nonce: string,
    attestedKey?: TestKey,
    clientId?: string,
  ): Promise<string>;
  postDpopProof(key: TestKey, path: string, accessToken?: string): Promise<string>;
  walletAttestationJwt(key: TestKey, clientId: string): Promise<string>;
  walletAttestationPopJwt(
    key: TestKey,
    clientId: string,
    clockAheadSeconds?: number,
  ): Promise<string>;
}

function createServerTestContext(environment: IssuerTestEnvironment): ServerTestContext {
  const { dataDir, config } = environment;
  const conformingIssuerId = CONFORMING_ISSUER_ID;
  const jwtKeyAttestationIssuerId = "eu-pid-jwt-key-attestation";
  const jwtOnlyIssuerId = "eu-pid-jwt-proof-only";
  const conformingIssuerPath = `/issuers/${conformingIssuerId}`;
  const jwtKeyAttestationIssuerPath = `/issuers/${jwtKeyAttestationIssuerId}`;
  const jwtOnlyIssuerPath = `/issuers/${jwtOnlyIssuerId}`;
  const conformingMetadataPath = `/.well-known/openid-credential-issuer/issuers/${conformingIssuerId}`;
  const conformingAuthorizationServerMetadataPath = `/.well-known/oauth-authorization-server/issuers/${conformingIssuerId}`;
  const conformingUpstreamAuthorizationServerMetadataPath = `/.well-known/oauth-authorization-server/authorization-servers/${conformingIssuerId}`;
  const conformingIssuer = requireIssuer(config, conformingIssuerId);
  const conformingMaterialDirectory = conformingIssuer.materialDirectory;
  const conformingIssuerConfig = issuerAppConfig(config, conformingIssuer);

  return {
    dataDir,
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
    conformingIssuerConfig,
    pidSdJwtCredential: () =>
      sdJwtCredential(conformingIssuerConfig, config.credential_configuration_id),
    conformingProofJwt: (
      key: TestKey,
      nonce: string,
      attestedKey: TestKey = key,
      clientId?: string,
    ) =>
      credentialProofJwt(
        key,
        nonce,
        `${config.issuer_base_url}${conformingIssuerPath}`,
        conformingIssuerConfig,
        attestedKey,
        clientId,
      ),
    postDpopProof: (key, path, accessToken) =>
      dpopProof(key, {
        method: "POST",
        url: `${config.issuer_base_url}${path}`,
        ...(accessToken ? { accessToken } : {}),
      }),
    walletAttestationJwt: async (key, clientId) => {
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
    },
    walletAttestationPopJwt: (key, clientId, clockAheadSeconds = 0) => {
      const now = Math.floor(Date.now() / 1000) + clockAheadSeconds;
      return new SignJWT({
        iss: clientId,
        aud: `${config.issuer_base_url}${conformingIssuerPath}`,
        iat: now,
        nbf: now,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation-pop+jwt" })
        .sign(key.privateKey);
    },
  };
}

export function serverTestSuite(prefix: string): ServerTestContext {
  const environment = createIssuerTestEnvironmentFactory({ prefix });
  beforeAll(() => environment.initialize());
  afterAll(() => environment.cleanup());
  afterEach(() => vi.restoreAllMocks());
  return createServerTestContext(environment);
}
