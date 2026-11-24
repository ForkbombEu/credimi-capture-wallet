import { existsSync, readFileSync } from "node:fs";
import { X509Certificate } from "@credo-ts/core";
import { resolveAttestbookSettings } from "../attestbook/settings.js";
import type { AppConfig, JsonRecord } from "../types.js";
import { DEFAULT_CONFIG, normalizeBaseUrl } from "./defaults.js";
import {
  PUBLIC_BASE_URL_ENV_VAR,
  STATUS_LIST_API_KEY_ENV_VAR,
  STATUS_LIST_BASE_URL_ENV_VAR,
  loadEnvFile,
  resolveFcafScenariosEnabled,
  resolveFederationSettings,
  resolveGuiEnabled,
  resolveOid4vciNotificationsEnabled,
  validateFederationEntityIdentifier,
} from "./environment.js";
import { configPath } from "./paths.js";

export function stringifyYaml(record: JsonRecord): string {
  return `${Object.entries(record)
    .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
    .join("\n")}\n`;
}

export function parseYamlConfig(text: string): Record<string, unknown> {
  const result: JsonRecord = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf(":");
    if (separator < 1) continue;
    const key = trimmed.slice(0, separator).trim();
    const raw = trimmed.slice(separator + 1).trim();
    if (raw === "true" || raw === "false") {
      result[key] = raw === "true";
      continue;
    }
    const numberValue = Number(raw);
    if (raw !== "" && Number.isFinite(numberValue)) {
      result[key] = numberValue;
      continue;
    }
    try {
      result[key] = JSON.parse(raw);
    } catch {
      result[key] = raw.replace(/^"|"$/g, "");
    }
  }
  return result;
}

export function loadConfig(
  dataDir = DEFAULT_CONFIG.data_dir,
  env: NodeJS.ProcessEnv = loadEnvFile(),
): AppConfig {
  const path = configPath(dataDir);
  const fileConfig: Record<string, unknown> = existsSync(path)
    ? parseYamlConfig(readFileSync(path, "utf8"))
    : {};
  const fileValues = fileConfig as Partial<AppConfig>; // F-03: config.yaml values pass through unvalidated
  const config: AppConfig = {
    ...DEFAULT_CONFIG,
    ...fileValues,
    issuer_base_url: normalizeBaseUrl(fileValues.issuer_base_url ?? DEFAULT_CONFIG.issuer_base_url),
    public_base_url: normalizeBaseUrl(
      env[PUBLIC_BASE_URL_ENV_VAR]?.trim() ||
        fileValues.public_base_url ||
        fileValues.issuer_base_url ||
        DEFAULT_CONFIG.issuer_base_url,
      "public_base_url",
    ),
    data_dir: fileValues.data_dir ?? dataDir,
    gui_enabled: resolveGuiEnabled(env),
    fcaf_scenarios_enabled: resolveFcafScenariosEnabled(env),
    oid4vci_notifications_enabled: resolveOid4vciNotificationsEnabled(env),
    status_list_base_url:
      env[STATUS_LIST_BASE_URL_ENV_VAR]?.trim() ||
      fileValues.status_list_base_url ||
      DEFAULT_CONFIG.status_list_base_url,
    status_list_api_key:
      env[STATUS_LIST_API_KEY_ENV_VAR]?.trim() ||
      fileValues.status_list_api_key ||
      DEFAULT_CONFIG.status_list_api_key,
    status_list_trusted_certificates: statusListTrustedCertificates(
      fileValues.status_list_trusted_certificates ??
        DEFAULT_CONFIG.status_list_trusted_certificates,
    ),
    federation: resolveFederationSettings(env),
    attestbook: resolveAttestbookSettings(env),
  };
  if (config.federation.enabled) {
    validateFederationEntityIdentifier(config.issuer_base_url, "issuer_base_url");
  }
  return config;
}

function statusListTrustedCertificates(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((certificate) => typeof certificate !== "string")) {
    throw new Error("status_list_trusted_certificates must be an array of certificates");
  }

  for (const certificate of value) {
    try {
      X509Certificate.fromEncodedCertificate(certificate);
    } catch {
      throw new Error("status_list_trusted_certificates must contain valid X.509 certificates");
    }
  }
  return value;
}
