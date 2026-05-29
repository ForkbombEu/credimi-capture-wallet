import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { exportJWK, generateKeyPair } from "jose";
import type { AppConfig, JsonRecord } from "./types.js";

export const DEFAULT_CONFIG: AppConfig = {
  issuer_base_url: "http://localhost:8080",
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
};

export interface InitOptions {
  issuer_base_url?: string;
  data_dir?: string;
  credential_configuration_id?: string;
  force?: boolean;
}

export function parseArgs(argv: string[]): Record<string, string | boolean> {
  const parsed: Record<string, string | boolean> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2).replaceAll("-", "_");
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = true;
      continue;
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

export function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

export function parseListenAddr(addr: string): { host?: string; port: number } {
  if (addr.startsWith(":")) return { port: Number.parseInt(addr.slice(1), 10) };
  const url = new URL(addr.includes("://") ? addr : `http://${addr}`);
  return { host: url.hostname, port: Number.parseInt(url.port || "8080", 10) };
}

export function stringifyYaml(record: JsonRecord): string {
  return `${Object.entries(record)
    .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
    .join("\n")}\n`;
}

export function parseYamlConfig(text: string): Partial<AppConfig> {
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
  return result as Partial<AppConfig>;
}

export function configPath(dataDir: string): string {
  return join(dataDir, "config.yaml");
}

export function jwksPath(dataDir: string): string {
  return join(dataDir, "jwks.json");
}

export function privateJwkPath(dataDir: string): string {
  return join(dataDir, "issuer-private-jwk.json");
}

export function loadConfig(dataDir = DEFAULT_CONFIG.data_dir): AppConfig {
  const path = configPath(dataDir);
  if (!existsSync(path)) return DEFAULT_CONFIG;
  const fileConfig = parseYamlConfig(readFileSync(path, "utf8"));
  return {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    issuer_base_url: normalizeBaseUrl(fileConfig.issuer_base_url ?? DEFAULT_CONFIG.issuer_base_url),
    data_dir: fileConfig.data_dir ?? dataDir,
  };
}

export async function initIssuer(options: InitOptions): Promise<AppConfig> {
  const dataDir = options.data_dir ?? DEFAULT_CONFIG.data_dir;
  const force = options.force === true;
  const config: AppConfig = {
    ...DEFAULT_CONFIG,
    issuer_base_url: normalizeBaseUrl(options.issuer_base_url ?? DEFAULT_CONFIG.issuer_base_url),
    data_dir: dataDir,
    credential_configuration_id:
      options.credential_configuration_id ?? DEFAULT_CONFIG.credential_configuration_id,
    credential_scope: options.credential_configuration_id ?? DEFAULT_CONFIG.credential_scope,
  };

  mkdirSync(dataDir, { recursive: true });
  const cfgPath = configPath(dataDir);
  const publicPath = jwksPath(dataDir);
  const secretPath = privateJwkPath(dataDir);

  if (!force && existsSync(cfgPath) && existsSync(publicPath) && existsSync(secretPath)) {
    return loadConfig(dataDir);
  }

  if (force || !existsSync(secretPath) || !existsSync(publicPath)) {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    privateJwk.alg = "ES256";
    privateJwk.use = "sig";
    writeJson(publicPath, { keys: [publicJwk] });
    writeJson(secretPath, privateJwk);
  }

  if (force || !existsSync(cfgPath)) {
    writeFileSync(cfgPath, stringifyYaml(config as unknown as JsonRecord), { mode: 0o600 });
  }

  return loadConfig(dataDir);
}

export function loadIssuerJwks(config: AppConfig): { keys: JsonRecord[] } {
  const path = jwksPath(config.data_dir);
  if (!existsSync(path)) return { keys: [] };
  return JSON.parse(readFileSync(path, "utf8")) as { keys: JsonRecord[] };
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
