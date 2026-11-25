import { DISABLED_ATTESTBOOK_SETTINGS } from "../attestbook/settings.js";
import type { AppConfig } from "../types.js";

export const DEFAULT_CONFIG: AppConfig = {
  issuer_base_url: "http://localhost:8080",
  public_base_url: "http://localhost:8080",
  fcaf_scenarios_enabled: false,
  oid4vci_notifications_enabled: false,
  listen_addr: ":8080",
  data_dir: "./data",
  credential_configuration_id: "urn:eu.europa.ec.eudi:pid:1",
  credential_format: "dc+sd-jwt",
  credential_scope: "urn:eu.europa.ec.eudi:pid:1",
  authorization_code_ttl_seconds: 300,
  par_request_uri_ttl_seconds: 90,
  access_token_ttl_seconds: 600,
  nonce_ttl_seconds: 300,
  permissive_capture: true,
  gui_enabled: true,
  status_list_base_url: "http://localhost:8000",
  status_list_api_key: "test",
  status_list_timeout_ms: 5000,
  status_list_trusted_certificates: [],
  federation: { enabled: false, authority_hints: [] },
  attestbook: DISABLED_ATTESTBOOK_SETTINGS,
};

export interface InitOptions {
  issuer_base_url?: string;
  public_base_url?: string;
  data_dir?: string;
  credential_configuration_id?: string;
  force?: boolean;
}

export function normalizeBaseUrl(value: string, field = "issuer_base_url"): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  const normalized = trimmed.includes("://")
    ? trimmed
    : `${defaultBaseUrlScheme(trimmed)}://${trimmed}`;
  try {
    new URL(normalized);
  } catch {
    throw new Error(`${field} must be an absolute URL or host, got '${value}'`);
  }
  return normalized;
}

function defaultBaseUrlScheme(value: string): "http" | "https" {
  const host = value.split("/")[0]?.toLowerCase() ?? "";
  if (
    host === "localhost" ||
    host.startsWith("localhost:") ||
    host.startsWith("127.") ||
    host.startsWith("0.0.0.0") ||
    host.startsWith("[::1]")
  ) {
    return "http";
  }
  return "https";
}
