import { randomUUID } from "node:crypto";
import { PID_MDOC_DOCTYPE, supportedCredentials } from "./metadata.js";
import type { AppConfig, JsonRecord } from "./types.js";

const DEFAULT_CLAIMS = [
  "family_name",
  "given_name",
  "birth_date",
  "issuing_country",
  "issuing_authority",
  "document_number",
];

export function defaultPresentationRequest(config: AppConfig): JsonRecord {
  return {
    response_type: "vp_token",
    response_mode: "direct_post",
    nonce: randomUUID(),
    presentation_definition: defaultPresentationDefinition(config),
    dcql_query: defaultDcqlQuery(config),
  };
}

export function buildPresentationAuthorizationRequest(
  config: AppConfig,
  sessionId: string,
  request: JsonRecord,
): JsonRecord {
  const responseUri = vpResponseUri(config, sessionId);
  return {
    client_id: responseUri,
    client_id_scheme: "redirect_uri",
    response_uri: responseUri,
    state: sessionId,
    ...request,
  };
}

export function presentationRequestDeeplink(request: JsonRecord): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(request)) {
    if (typeof value === "string") {
      params.set(key, value);
      continue;
    }
    params.set(key, JSON.stringify(value));
  }
  return `openid4vp://?${params.toString()}`;
}

export function presentationRequestByReferenceDeeplink(
  config: AppConfig,
  sessionId: string,
): string {
  const requestUri = vpRequestUri(config, sessionId);
  const responseUri = vpResponseUri(config, sessionId);
  const params = new URLSearchParams({
    client_id: responseUri,
    client_id_scheme: "redirect_uri",
    request_uri: requestUri,
  });
  return `openid4vp://?${params.toString()}`;
}

export function vpRequestUri(config: AppConfig, sessionId: string): string {
  return `${config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
}

export function vpResponseUri(config: AppConfig, sessionId: string): string {
  return `${config.issuer_base_url}/openid4vp/sessions/${sessionId}/response`;
}

function defaultPresentationDefinition(config: AppConfig): JsonRecord {
  return {
    id: "credimi-issued-credentials",
    name: "Credimi issued credentials",
    purpose: "Request credentials issued by this fake issuer.",
    input_descriptors: supportedCredentials(config).map((credential) => ({
      id: credential.id,
      name: credential.displayName,
      format: {
        [credential.format]: {
          alg: credential.format === "mso_mdoc" ? [-7, -9] : ["ES256"],
        },
      },
      constraints: {
        fields: [
          {
            path: credential.format === "mso_mdoc" ? ["$['doctype']"] : ["$.vct", "$['vct']"],
            filter: {
              type: "string",
              const: credential.format === "mso_mdoc" ? PID_MDOC_DOCTYPE : credential.id,
            },
          },
        ],
      },
    })),
  };
}

function defaultDcqlQuery(config: AppConfig): JsonRecord {
  return {
    credentials: supportedCredentials(config).map((credential) => ({
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

function dcqlCredentialId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
}
