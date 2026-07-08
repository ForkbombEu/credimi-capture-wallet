import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { type JWK, SignJWT, importJWK } from "jose";
import { VERIFIER_KEY_ID, verifierCertificatePath, verifierPrivateJwkPath } from "./config.js";
import {
  PID_MDOC_DOCTYPE,
  type SupportedCredential,
  supportedCredentialById,
  supportedCredentials,
} from "./metadata.js";
import type { AppConfig, JsonRecord } from "./types.js";

const REQUEST_OBJECT_AUDIENCE = "https://self-issued.me/v2";
const DEFAULT_CLAIMS = [
  "family_name",
  "given_name",
  "birth_date",
  "issuing_country",
  "issuing_authority",
  "document_number",
];

export function defaultPresentationRequest(
  config: AppConfig,
  credentialConfigurationIds?: string[],
): JsonRecord {
  const credentials = selectedSupportedCredentials(config, credentialConfigurationIds);
  return {
    response_type: "vp_token",
    response_mode: "direct_post",
    nonce: randomUUID(),
    dcql_query: defaultDcqlQuery(credentials),
  };
}

export function buildPresentationAuthorizationRequest(
  config: AppConfig,
  sessionId: string,
  request: JsonRecord,
): JsonRecord {
  const responseUri = vpResponseUri(config, sessionId);
  const clientId = verifierClientId(config);
  return {
    client_id: clientId,
    aud: REQUEST_OBJECT_AUDIENCE,
    response_uri: responseUri,
    state: sessionId,
    client_metadata: verifierClientMetadata(),
    ...request,
  };
}

export async function signPresentationAuthorizationRequest(
  config: AppConfig,
  request: JsonRecord,
): Promise<string> {
  const privateJwk = JSON.parse(
    readFileSync(verifierPrivateJwkPath(config.data_dir), "utf8"),
  ) as JWK;
  const key = await importJWK(privateJwk, "ES256");
  const certificate = verifierCertificateBase64Der(config);
  return new SignJWT(request)
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      kid: VERIFIER_KEY_ID,
      x5c: [certificate],
    })
    .sign(key);
}

export function presentationRequestByReferenceDeeplink(
  config: AppConfig,
  sessionId: string,
  requestUriMethod: "get" | "post" = "get",
): string {
  const requestUri = vpRequestUri(config, sessionId);
  const params = new URLSearchParams({
    client_id: verifierClientId(config),
    request_uri: requestUri,
  });
  if (requestUriMethod === "post") params.set("request_uri_method", "post");
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
          : { vct_values: [credential.id] },
      claims: DEFAULT_CLAIMS.map((claim) => ({
        path: credential.format === "mso_mdoc" ? ["eu.europa.ec.eudi.pid.1", claim] : [claim],
      })),
    })),
  };
}

function selectedSupportedCredentials(
  config: AppConfig,
  credentialConfigurationIds: string[] | undefined,
): SupportedCredential[] {
  if (!credentialConfigurationIds || credentialConfigurationIds.length === 0) {
    return supportedCredentials(config);
  }
  return credentialConfigurationIds
    .map((credentialConfigurationId) => supportedCredentialById(config, credentialConfigurationId))
    .filter((credential): credential is SupportedCredential => credential !== null);
}

function verifierClientMetadata(): JsonRecord {
  return {
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
