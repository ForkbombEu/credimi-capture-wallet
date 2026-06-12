import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { CredoWebCrypto, Kms, X509Certificate, X509KeyUsage } from "@credo-ts/core";
import { exportJWK, generateKeyPair } from "jose";
import type { AppConfig, JsonRecord } from "./types.js";

export const ISSUER_KEY_ID = "credimi-fake-issuer-key";

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
  gui_enabled: true,
};

export const PORT_ENV_VAR = "PORT";
export const GUI_ENABLED_ENV_VAR = "GUI_ENABLED";

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
  const raw = env[GUI_ENABLED_ENV_VAR]?.trim().toLowerCase();
  if (!raw) return DEFAULT_CONFIG.gui_enabled;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  throw new Error(`${GUI_ENABLED_ENV_VAR} must be true or false`);
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

export function issuerCertificatePath(dataDir: string): string {
  return join(dataDir, "issuer-certificate.pem");
}

export function loadConfig(dataDir = DEFAULT_CONFIG.data_dir): AppConfig {
  const env = loadEnvFile();
  const path = configPath(dataDir);
  const fileConfig = existsSync(path) ? parseYamlConfig(readFileSync(path, "utf8")) : {};
  return {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    issuer_base_url: normalizeBaseUrl(fileConfig.issuer_base_url ?? DEFAULT_CONFIG.issuer_base_url),
    data_dir: fileConfig.data_dir ?? dataDir,
    gui_enabled: resolveGuiEnabled(env),
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
  const certificatePath = issuerCertificatePath(dataDir);

  if (!force && existsSync(cfgPath) && existsSync(publicPath) && existsSync(secretPath)) {
    if (!existsSync(certificatePath)) {
      await writeIssuerCertificate(certificatePath, loadConfig(dataDir));
    }
    return loadConfig(dataDir);
  }

  if (force || !existsSync(secretPath) || !existsSync(publicPath)) {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    publicJwk.kid = ISSUER_KEY_ID;
    privateJwk.alg = "ES256";
    privateJwk.use = "sig";
    privateJwk.kid = ISSUER_KEY_ID;
    writeJson(publicPath, { keys: [publicJwk] });
    writeJson(secretPath, privateJwk);
  }

  if (force || !existsSync(cfgPath)) {
    writeFileSync(cfgPath, stringifyYaml(config as unknown as JsonRecord), { mode: 0o600 });
  }

  const loadedConfig = loadConfig(dataDir);
  if (force || !existsSync(certificatePath)) {
    await writeIssuerCertificate(certificatePath, loadedConfig);
  }

  return loadedConfig;
}

export function loadIssuerJwks(config: AppConfig): { keys: JsonRecord[] } {
  const path = jwksPath(config.data_dir);
  if (!existsSync(path)) return { keys: [] };
  return JSON.parse(readFileSync(path, "utf8")) as { keys: JsonRecord[] };
}

export function loadIssuerCertificate(config: AppConfig): X509Certificate {
  return X509Certificate.fromEncodedCertificate(
    readFileSync(issuerCertificatePath(config.data_dir), "utf8"),
  );
}

async function writeIssuerCertificate(path: string, config: AppConfig): Promise<void> {
  const privateJwk = JSON.parse(
    readFileSync(privateJwkPath(config.data_dir), "utf8"),
  ) as JsonRecord;
  const publicJwk = Kms.PublicJwk.fromUnknown(toPublicJwk(privateJwk));
  publicJwk.keyId = ISSUER_KEY_ID;
  const certificate = await X509Certificate.create(
    {
      authorityKey: publicJwk,
      issuer: {
        commonName: new URL(config.issuer_base_url).hostname,
        organizationalUnit: "Credimi Fake Issuer",
      },
      validity: {
        notBefore: new Date("2024-01-01T00:00:00Z"),
        notAfter: new Date("2034-01-01T00:00:00Z"),
      },
      extensions: {
        subjectKeyIdentifier: { include: true },
        authorityKeyIdentifier: { include: true },
        keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
        subjectAlternativeName: {
          name: [
            { type: "url", value: config.issuer_base_url },
            { type: "dns", value: new URL(config.issuer_base_url).hostname },
          ],
        },
        basicConstraints: { ca: false },
      },
    },
    new CredoWebCrypto(createSigningContext(privateJwk) as never),
  );
  certificate.keyId = ISSUER_KEY_ID;
  writeFileSync(path, certificate.toString("pem"), { mode: 0o600 });
}

function toPublicJwk(privateJwk: JsonRecord): JsonRecord {
  const { d: _d, ...publicJwk } = privateJwk;
  return publicJwk;
}

function createSigningContext(privateJwk: JsonRecord): object {
  const kms = {
    randomBytes: ({ length }: { length: number }) => randomBytes(length),
    sign: async ({ keyId, data }: { keyId: string; data: Uint8Array }) => {
      if (keyId !== ISSUER_KEY_ID) throw new Error(`Unknown issuer key id '${keyId}'`);
      const { createPrivateKey, sign } = await import("node:crypto");
      return {
        signature: sign("sha256", data, {
          key: createPrivateKey({ key: privateJwk as never, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        }),
      };
    },
  };
  const resolve = (token: unknown) => {
    if (token === Kms.KeyManagementApi) return kms;
    throw new Error("Unsupported Credo dependency requested while creating issuer certificate");
  };

  return { resolve, dependencyManager: { resolve } };
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
