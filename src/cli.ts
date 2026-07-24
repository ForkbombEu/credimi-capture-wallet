#!/usr/bin/env node
import { createServer } from "node:http";
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
  await import("./webcrypto-globals.js");
  const [{ initIssuer, loadConfig, loadEnvFile, parseArgs, resolveListenAddr }, { createApp }] =
    await Promise.all([import("./config.js"), import("./server.js")]);
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
    const app = createApp(config);
    const { host, port } = resolveListenAddr(config, loadEnvFile());
    const server = createServer(app);
    server.once("error", (error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
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
    issuer_base_url: config.issuer_base_url,
    credential_issuer_metadata_url: `${config.issuer_base_url}/.well-known/openid-credential-issuer`,
    authorization_server_metadata_url: `${config.issuer_base_url}/.well-known/oauth-authorization-server`,
    jwt_vc_issuer_metadata_url: `${config.issuer_base_url}/.well-known/jwt-vc-issuer`,
    jwks_url: `${config.issuer_base_url}/jwks.json`,
    health_url: `${config.issuer_base_url}/healthz`,
  };
}
