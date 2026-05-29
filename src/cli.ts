#!/usr/bin/env node
import { createServer } from "node:http";
import { initIssuer, loadConfig, parseArgs, resolveListenAddr } from "./config.js";
import { createApp, initSummary } from "./server.js";

const ASCII_HEADER = String.raw`
 _________        __              ____              __
|_   ___  |      [  |            |_   \            [  |
  | |_  \_| ,--.  | |  _ .--.     |   \  _ .--.    | |
  |  _|    \`'_\ : | | [ \`/'\`\]    | |\ \[ \`/'\`\]   | |
 _| |_     // | |,| |  | |       _| |_\ \| |       | |
|_____|    \'-;__/[___][___]     |_____||___]     [___]
`;

async function main(): Promise<void> {
  const [command = "serve", ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);

  if (command === "init") {
    const config = await initIssuer({
      issuer_base_url: typeof args.issuer_base_url === "string" ? args.issuer_base_url : undefined,
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
    const { host, port } = resolveListenAddr(config);
    const server = createServer(app);
    server.listen(port, host, () => {
      console.log(ASCII_HEADER);
      console.log(`fake issuer listening on ${host ?? "0.0.0.0"}:${port}`);
    });
    return;
  }

  throw new Error(`unknown command: ${command}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
