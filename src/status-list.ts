import { PID_MDOC_DOCTYPE } from "./credential-definitions.js";
import type { SupportedCredential } from "./metadata.js";
import type { AppConfig, StatusListReference } from "./types.js";

const STATUS_LIST_TAKE_PATH = "/token_status_list/take";
const DEFAULT_COUNTRY = "EU";
const DEFAULT_EXPIRY_DATE = "2099-12-31";

export function statusListCredentialType(credential: SupportedCredential): string {
  if (credential.format === "mso_mdoc") return PID_MDOC_DOCTYPE;
  if (credential.vct) return credential.vct;
  throw new Error(`SD-JWT credential '${credential.id}' is missing its vct`);
}

export async function allocateStatusListReference(options: {
  config: AppConfig;
  allocationId: string;
  doctype: string;
}): Promise<StatusListReference> {
  const baseUrl = options.config.status_list_base_url.endsWith("/")
    ? options.config.status_list_base_url
    : `${options.config.status_list_base_url}/`;
  const endpoint = new URL(STATUS_LIST_TAKE_PATH, baseUrl);
  const body = new URLSearchParams({
    country: DEFAULT_COUNTRY,
    doctype: options.doctype,
    expiry_date: DEFAULT_EXPIRY_DATE,
    allocation_id: options.allocationId,
  });
  const debugContext = {
    endpoint: endpoint.toString(),
    country: DEFAULT_COUNTRY,
    doctype: options.doctype,
    expiry_date: DEFAULT_EXPIRY_DATE,
    allocation_id: options.allocationId,
    api_key_configured: Boolean(options.config.status_list_api_key),
  };
  console.info("Status List allocation request", debugContext);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.config.status_list_timeout_ms);

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-api-key": options.config.status_list_api_key,
      },
      body,
      signal: controller.signal,
    });
  } catch (error) {
    throw new Error(
      `Status List allocation failed: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  } finally {
    clearTimeout(timeout);
  }

  console.info("Status List allocation response", {
    ...debugContext,
    status: response.status,
    status_text: response.statusText,
    content_type: response.headers.get("content-type"),
    server: response.headers.get("server"),
    cf_ray: response.headers.get("cf-ray"),
  });

  if (!response.ok) {
    throw new Error(`Status List allocation failed with HTTP ${response.status}`);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error(
      `Status List allocation returned invalid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }

  const reference = statusListReference(payload);
  if (!reference) {
    throw new Error(
      "Status List allocation response did not contain a valid status_list reference",
    );
  }
  return reference;
}

function statusListReference(value: unknown): StatusListReference | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const statusList = (value as Record<string, unknown>).status_list;
  if (!statusList || typeof statusList !== "object" || Array.isArray(statusList)) return null;
  const uri = (statusList as Record<string, unknown>).uri;
  const idx = (statusList as Record<string, unknown>).idx;
  if (
    typeof uri !== "string" ||
    uri.length === 0 ||
    typeof idx !== "number" ||
    !Number.isInteger(idx) ||
    idx < 0
  ) {
    return null;
  }
  return { uri, idx };
}
