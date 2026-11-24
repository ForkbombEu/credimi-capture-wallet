import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import { DEFAULT_CONFIG, initIssuer } from "../../src/config.js";
import { resolvedIssuerConfigurationById } from "../../src/configurations/registry.js";
import type { ResolvedIssuerConfiguration } from "../../src/configurations/types.js";
import { createApp } from "../../src/server.js";
import { CaptureStore } from "../../src/state.js";
import type { AppConfig } from "../../src/types.js";
export const CONFORMING_ISSUER_ID = "eu-pid-device-bound";
export interface IssuerTestEnvironment {
  dataDir: string;
  config: AppConfig;
  cleanup(): void;
}

export async function createIssuerTestEnvironment(options: {
  prefix: string;
  config?: Partial<Omit<AppConfig, "data_dir">>;
}): Promise<IssuerTestEnvironment> {
  const dataDir = mkdtempSync(join(tmpdir(), options.prefix));
  const config: AppConfig = {
    ...DEFAULT_CONFIG,
    issuer_base_url: "http://issuer.example.test",
    data_dir: dataDir,
    ...options.config,
  };

  try {
    await initIssuer({
      issuer_base_url: config.issuer_base_url,
      data_dir: dataDir,
      credential_configuration_id: config.credential_configuration_id,
      force: true,
    });
  } catch (error) {
    rmSync(dataDir, { recursive: true, force: true });
    throw error;
  }

  return {
    dataDir,
    config,
    cleanup: () => rmSync(dataDir, { recursive: true, force: true }),
  };
}

export function issuerPath(issuerId: string): string {
  return `/issuers/${issuerId}`;
}

export function requireIssuer(config: AppConfig, issuerId: string): ResolvedIssuerConfiguration {
  const issuer = resolvedIssuerConfigurationById(config, issuerId);
  if (!issuer) throw new Error(`issuer configuration unavailable: ${issuerId}`);
  return issuer;
}

export function createTestApp(config: AppConfig): Express {
  return createApp(config, new CaptureStore(config));
}
