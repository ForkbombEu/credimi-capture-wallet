#!/usr/bin/env node
import { createServer } from "node:http";
import { initIssuer, loadConfig, parseArgs, resolveListenAddr } from "./config.js";
import { resolvedIssuerConfigurations } from "./configurations/registry.js";
import { credoOpenId4VciIssuer } from "./credo-openid4vci.js";
import { createApp } from "./server.js";
import { CaptureStore } from "./state.js";
import type { AppConfig, JsonRecord } from "./types.js";

const ASCII_HEADER = `
 ██████╗██████╗ ███████╗██████╗ ██╗███╗   ███╗██╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██║████╗ ████║██║
██║     ██████╔╝█████╗  ██║  ██║██║██╔████╔██║██║
██║     ██╔══██╗██╔══╝  ██║  ██║██║██║╚██╔╝██║██║
╚██████╗██║  ██║███████╗██████╔╝██║██║ ╚═╝ ██║██║
 ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝     ╚═╝╚═╝

 ██████╗ █████╗ ██████╗ ████████╗██╗   ██╗██████╗ ███████╗
██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██╔════╝
██║     ███████║██████╔╝   ██║   ██║   ██║██████╔╝█████╗
██║     ██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗██╔══╝
╚██████╗██║  ██║██║        ██║   ╚██████╔╝██║  ██║███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝

██╗    ██╗ █████╗ ██╗     ██╗     ███████╗████████╗
██║    ██║██╔══██╗██║     ██║     ██╔════╝╚══██╔══╝
██║ █╗ ██║███████║██║     ██║     █████╗     ██║
██║███╗██║██╔══██║██║     ██║     ██╔══╝     ██║
╚███╔███╔╝██║  ██║███████╗███████╗███████╗   ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝
`;

async function main(): Promise<void> {
  const [command = "serve", ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);

  if (command === "init") {
    const config = await initIssuer({
      issuer_base_url:
        typeof args.services_base_url === "string" ? args.services_base_url : undefined,
      data_dir: typeof args.data_dir === "string" ? args.data_dir : undefined,
      credential_configuration_id:
        typeof args.credential_configuration_id === "string"
          ? args.credential_configuration_id
          : undefined,
      force: args.force === true,
    });
    console.log(ASCII_HEADER);
    console.log(JSON.stringify(initSummary(config), null, 2));
    return;
  }

  if (command === "serve") {
    const dataDir = typeof args.data_dir === "string" ? args.data_dir : undefined;
    const config = loadConfig(dataDir);
    const store = new CaptureStore(config);
    await credoOpenId4VciIssuer(config, store);
    const app = createApp(config, store);
    const { host, port } = resolveListenAddr(config);
    const server = createServer(app);
    server.listen(port, host, () => {
      console.log(ASCII_HEADER);
      console.log(`capture services listening on ${host ?? "0.0.0.0"}:${port}`);
    });
    return;
  }

  throw new Error(`unknown command: ${command}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

function initSummary(config: AppConfig): JsonRecord {
  return {
    services_base_url: config.issuer_base_url,
    issuers: resolvedIssuerConfigurations(config).map((issuer) => ({
      issuer_configuration_id: issuer.id,
      credential_issuer: issuer.issuerIdentifier,
      credential_issuer_metadata_url: issuer.issuerMetadataUrl,
      authorization_server_metadata_url: issuer.authorizationServerMetadataUrl,
      upstream_authorization_server: issuer.upstreamAuthorizationServerIdentifier,
      upstream_authorization_server_metadata_url: issuer.upstreamAuthorizationServerMetadataUrl,
      authorization_server_jwks_url: issuer.endpoints.jwks,
      credential_jwks_url: issuer.endpoints.credentialJwks,
    })),
    issuer_catalogue_url: `${config.issuer_base_url}/issuers`,
    health_url: `${config.issuer_base_url}/healthz`,
  };
}
