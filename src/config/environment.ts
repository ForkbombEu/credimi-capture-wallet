import { existsSync, readFileSync } from "node:fs";
import type { AppConfig } from "../types.js";
import { DEFAULT_CONFIG } from "./defaults.js";
const PORT_ENV_VAR = "PORT";
const GUI_ENABLED_ENV_VAR = "GUI_ENABLED";
export const PUBLIC_BASE_URL_ENV_VAR = "PUBLIC_BASE_URL";
const FCAF_SCENARIOS_ENABLED_ENV_VAR = "FCAF_SCENARIOS_ENABLED";
const OID4VCI_NOTIFICATIONS_ENABLED_ENV_VAR = "OID4VCI_NOTIFICATIONS_ENABLED";
export const STATUS_LIST_BASE_URL_ENV_VAR = "STATUS_LIST_BASE_URL";
export const STATUS_LIST_API_KEY_ENV_VAR = "STATUS_LIST_API_KEY";
const FEDERATION_ENABLED_ENV_VAR = "FEDERATION_ENABLED";
const FEDERATION_AUTHORITY_HINTS_ENV_VAR = "FEDERATION_AUTHORITY_HINTS";

function parseListenAddr(addr: string): { host?: string; port: number } {
  if (addr.startsWith(":")) return { port: Number.parseInt(addr.slice(1), 10) };
  const url = new URL(addr.includes("://") ? addr : `http://${addr}`);
  return { host: url.hostname, port: Number.parseInt(url.port || "8080", 10) };
}

export function resolveListenAddr(
  config: AppConfig,
  env: NodeJS.ProcessEnv = process.env,
): { host?: string; port: number } {
  const listenAddr = parseListenAddr(config.listen_addr);
  const rawPort = env[PORT_ENV_VAR]?.trim();
  if (!rawPort) return listenAddr;
  return { ...listenAddr, port: parsePortEnv(rawPort) };
}

function parsePortEnv(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error(`${PORT_ENV_VAR} must be an integer between 1 and 65535`);
  }
  const port = Number.parseInt(value, 10);
  if (port < 1 || port > 65535) {
    throw new Error(`${PORT_ENV_VAR} must be an integer between 1 and 65535`);
  }
  return port;
}

export function loadEnvFile(
  path = ".env",
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  if (!existsSync(path)) return env;
  return { ...parseEnvText(readFileSync(path, "utf8")), ...env };
}

/** @internal */
export function parseEnvText(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const source = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
    const separator = source.indexOf("=");
    if (separator < 1) continue;
    const key = source.slice(0, separator).trim();
    const rawValue = source.slice(separator + 1).trim();
    result[key] = rawValue.replace(/^(["'])(.*)\1$/, "$2");
  }
  return result;
}

export function resolveGuiEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return resolveBooleanEnv(env, GUI_ENABLED_ENV_VAR, DEFAULT_CONFIG.gui_enabled);
}

export function resolveFcafScenariosEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return resolveBooleanEnv(
    env,
    FCAF_SCENARIOS_ENABLED_ENV_VAR,
    DEFAULT_CONFIG.fcaf_scenarios_enabled,
  );
}

export function resolveOid4vciNotificationsEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return resolveBooleanEnv(
    env,
    OID4VCI_NOTIFICATIONS_ENABLED_ENV_VAR,
    DEFAULT_CONFIG.oid4vci_notifications_enabled,
  );
}

function resolveBooleanEnv(env: NodeJS.ProcessEnv, variable: string, fallback: boolean): boolean {
  const raw = env[variable]?.trim().toLowerCase();
  if (!raw) return fallback;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  throw new Error(`${variable} must be true or false`);
}

export function resolveFederationSettings(env: NodeJS.ProcessEnv = process.env): {
  enabled: boolean;
  authority_hints: string[];
} {
  const enabled = resolveBooleanEnv(env, FEDERATION_ENABLED_ENV_VAR, false);
  if (!enabled) return { enabled: false, authority_hints: [] };

  const rawAuthorityHints = env[FEDERATION_AUTHORITY_HINTS_ENV_VAR]?.trim();
  if (!rawAuthorityHints) {
    throw new Error(
      `${FEDERATION_AUTHORITY_HINTS_ENV_VAR} must be a JSON array of HTTPS Entity Identifiers when federation is enabled`,
    );
  }

  let authorityHints: unknown;
  try {
    authorityHints = JSON.parse(rawAuthorityHints);
  } catch {
    throw new Error(`${FEDERATION_AUTHORITY_HINTS_ENV_VAR} must be a JSON array`);
  }
  if (!Array.isArray(authorityHints) || authorityHints.length === 0) {
    throw new Error(
      `${FEDERATION_AUTHORITY_HINTS_ENV_VAR} must be a non-empty JSON array of HTTPS Entity Identifiers`,
    );
  }
  if (authorityHints.some((hint) => typeof hint !== "string")) {
    throw new Error(
      `${FEDERATION_AUTHORITY_HINTS_ENV_VAR} must contain only HTTPS Entity Identifiers`,
    );
  }

  const uniqueHints = new Set(authorityHints);
  if (uniqueHints.size !== authorityHints.length) {
    throw new Error(
      `${FEDERATION_AUTHORITY_HINTS_ENV_VAR} must not contain duplicate Entity Identifiers`,
    );
  }
  for (const authorityHint of authorityHints) {
    validateFederationEntityIdentifier(authorityHint, FEDERATION_AUTHORITY_HINTS_ENV_VAR);
  }
  return { enabled: true, authority_hints: authorityHints };
}

export function validateFederationEntityIdentifier(value: string, field: string): void {
  let identifier: URL;
  try {
    identifier = new URL(value);
  } catch {
    throw new Error(`${field} must contain HTTPS Entity Identifiers`);
  }
  if (
    identifier.protocol !== "https:" ||
    !identifier.hostname ||
    identifier.username ||
    identifier.password ||
    identifier.search ||
    identifier.hash
  ) {
    throw new Error(
      `${field} must contain HTTPS Entity Identifiers without credentials, query, or fragment`,
    );
  }
}
