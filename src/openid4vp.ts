import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { type JWK, SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";
import {
  VERIFIER_DID_KEY_ID,
  VERIFIER_KEY_ID,
  verifierCertificatePath,
  verifierDid,
  verifierDidPrivateJwkPath,
  verifierPrivateJwkPath,
} from "./config.js";
import { PID_MDOC_CLAIMS, PID_MDOC_NAMESPACE, PID_SD_JWT_VCT } from "./credential-definitions.js";
import {
  PID_MDOC_DOCTYPE,
  type SupportedCredential,
  supportedCredentialById,
  supportedCredentials,
} from "./metadata.js";
import type { AppConfig, JsonRecord, OpenId4VpResponseMode } from "./types.js";

const REQUEST_OBJECT_AUDIENCE = "https://self-issued.me/v2";

/**
 * How long a DC API session stays presentable. The browser invocation is user-driven and cannot be
 * correlated by `state`, so the window is bounded here rather than left open until process exit.
 */
export const DC_API_PRESENTATION_TTL_SECONDS = 600;

export type { OpenId4VpResponseMode } from "./types.js";
export type OpenId4VpClientIdScheme =
  | "x509_hash"
  | "x509_san_dns"
  | "redirect_uri"
  | "decentralized_identifier";

/** Exhaustive over the union, so adding a response mode without handling it fails to compile. */
const OPENID4VP_RESPONSE_MODES: Record<OpenId4VpResponseMode, true> = {
  direct_post: true,
  "direct_post.jwt": true,
  dc_api: true,
  "dc_api.jwt": true,
};

export function isOpenId4VpResponseMode(value: unknown): value is OpenId4VpResponseMode {
  return typeof value === "string" && Object.hasOwn(OPENID4VP_RESPONSE_MODES, value);
}

/** Whether the request is delivered through the W3C Digital Credentials API instead of a redirect. */
export function isDcApiResponseMode(mode: OpenId4VpResponseMode): boolean {
  return mode === "dc_api" || mode === "dc_api.jwt";
}

/** Whether the wallet returns the Authorization Response encrypted in a `response` JWE. */
export function isEncryptedResponseMode(mode: OpenId4VpResponseMode): boolean {
  return mode === "direct_post.jwt" || mode === "dc_api.jwt";
}

/**
 * Origin the wallet binds a DC API presentation to. Derived from trusted configuration: the
 * presentation page is served from it and a request Host header is never used.
 */
export function verifierOrigin(config: AppConfig): string {
  return new URL(config.public_base_url).origin;
}

export function dcApiPresentationUrl(config: AppConfig, sessionId: string): string {
  const base = config.public_base_url.replace(/\/+$/, "");
  return `${base}/ui/openid4vp/sessions/${encodeURIComponent(sessionId)}/dc_api_presentation`;
}

export function dcApiPresentationExpiresAt(from: Date = new Date()): string {
  return new Date(from.getTime() + DC_API_PRESENTATION_TTL_SECONDS * 1000).toISOString();
}

export function defaultPresentationRequest(
  config: AppConfig,
  credentialConfigurationIds?: string[],
  responseMode: OpenId4VpResponseMode = "direct_post.jwt",
): JsonRecord {
  const credentials = selectedSupportedCredentials(config, credentialConfigurationIds);
  return {
    response_type: "vp_token",
    response_mode: responseMode,
    nonce: randomUUID(),
    dcql_query: defaultDcqlQuery(credentials),
  };
}

export async function createJarmEncryptionJwk(): Promise<{
  publicJwk: JsonRecord;
  privateJwk: JsonRecord;
}> {
  const { publicKey, privateKey } = await generateKeyPair("ECDH-ES", { extractable: true });
  const publicJwk = (await exportJWK(publicKey)) as unknown as JsonRecord;
  const privateJwk = (await exportJWK(privateKey)) as unknown as JsonRecord;
  publicJwk.use = "enc";
  publicJwk.alg = "ECDH-ES";
  publicJwk.kid = randomUUID();
  privateJwk.use = "enc";
  privateJwk.alg = "ECDH-ES";
  privateJwk.kid = publicJwk.kid;
  return { publicJwk, privateJwk };
}

export function buildPresentationAuthorizationRequest(
  config: AppConfig,
  sessionId: string,
  request: JsonRecord,
  jarmEncryptionJwk?: JsonRecord,
): JsonRecord {
  const responseUri = vpResponseUri(config, sessionId);
  const clientId = verifierClientId(config);
  return {
    client_id: clientId,
    aud: REQUEST_OBJECT_AUDIENCE,
    response_uri: responseUri,
    state: sessionId,
    client_metadata: verifierClientMetadata(jarmEncryptionJwk),
    ...request,
  };
}

export async function signPresentationAuthorizationRequest(
  config: AppConfig,
  request: JsonRecord,
  clientIdScheme: Exclude<OpenId4VpClientIdScheme, "redirect_uri"> = "x509_hash",
): Promise<string> {
  const isDid = clientIdScheme === "decentralized_identifier";
  const privateJwk = JSON.parse(
    readFileSync(
      isDid ? verifierDidPrivateJwkPath(config.data_dir) : verifierPrivateJwkPath(config.data_dir),
      "utf8",
    ),
  ) as JWK;
  const key = await importJWK(privateJwk, "ES256");
  return new SignJWT(request)
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      ...(isDid
        ? { kid: `${verifierDid(config)}#${VERIFIER_DID_KEY_ID}` }
        : { kid: VERIFIER_KEY_ID, x5c: [verifierCertificateBase64Der(config)] }),
    })
    .sign(key);
}

export function presentationRequestByReferenceDeeplink(
  config: AppConfig,
  sessionId: string,
  requestUriMethod = "get",
): string {
  const requestUri = vpRequestUri(config, sessionId);
  const params = new URLSearchParams({
    client_id: verifierClientId(config),
    request_uri: requestUri,
  });
  if (requestUriMethod !== "get") params.set("request_uri_method", requestUriMethod);
  return `openid4vp://?${params.toString()}`;
}

export function verifierClientId(config: AppConfig): string {
  return `x509_hash:${verifierCertificateSha256(config)}`;
}

export function verifierCertificateBase64Der(config: AppConfig): string {
  return readFileSync(verifierCertificatePath(config.data_dir), "utf8")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

export function verifierCertificateSha256(config: AppConfig): string {
  return createHash("sha256")
    .update(Buffer.from(verifierCertificateBase64Der(config), "base64"))
    .digest("base64url");
}

export function vpRequestUri(config: AppConfig, sessionId: string): string {
  return `${config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
}

export function vpResponseUri(config: AppConfig, sessionId: string): string {
  return `${config.issuer_base_url}/openid4vp/sessions/${sessionId}/response`;
}

function defaultDcqlQuery(credentials: SupportedCredential[]): JsonRecord {
  return {
    credentials: credentials.map((credential) => ({
      id: dcqlCredentialId(credential.id),
      format: credential.format,
      meta:
        credential.format === "mso_mdoc"
          ? { doctype_value: PID_MDOC_DOCTYPE }
          : { vct_values: [credential.vct ?? PID_SD_JWT_VCT] },
      claims: defaultClaimPaths(credential),
    })),
  };
}

function defaultClaimPaths(credential: SupportedCredential): Array<{ path: string[] }> {
  if (credential.format === "mso_mdoc") {
    return PID_MDOC_CLAIMS.map((claim) => ({ path: [PID_MDOC_NAMESPACE, claim] }));
  }
  return credential.claimPaths.map((claim) => ({ path: claim.split(".") }));
}

function selectedSupportedCredentials(
  config: AppConfig,
  credentialConfigurationIds: string[] | undefined,
): SupportedCredential[] {
  if (!credentialConfigurationIds || credentialConfigurationIds.length === 0) {
    return supportedCredentials(config).filter(
      (credential, index, credentials) =>
        credentials.findIndex((candidate) => candidate.format === credential.format) === index,
    );
  }
  return credentialConfigurationIds
    .map((credentialConfigurationId) => supportedCredentialById(config, credentialConfigurationId))
    .filter((credential): credential is SupportedCredential => credential !== null);
}

function verifierClientMetadata(jarmEncryptionJwk?: JsonRecord): JsonRecord {
  return {
    ...(jarmEncryptionJwk
      ? {
          jwks: { keys: [jarmEncryptionJwk] },
          encrypted_response_enc_values_supported: ["A128GCM", "A256GCM", "A128CBC-HS256"],
        }
      : {}),
    vp_formats_supported: {
      "dc+sd-jwt": {
        "sd-jwt_alg_values": ["ES256"],
        "kb-jwt_alg_values": ["ES256"],
      },
      mso_mdoc: {},
    },
  };
}

function dcqlCredentialId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
}
