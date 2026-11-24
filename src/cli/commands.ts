import { writeFileSync } from "node:fs";
import { createServer } from "node:http";
import {
  type SubscriptionTarget,
  readSubscription,
  registerSubscription,
  verifySubscription,
  webhookCallbackUrl,
} from "../attestbook/subscription.js";
import { initIssuer, loadConfig, loadIssuerFederationJwks, resolveListenAddr } from "../config.js";
import {
  allResolvedIssuerConfigurations,
  resolvedIssuerConfigurations,
} from "../configurations/registry.js";
import { issuerFederationRegistration } from "../federation/registration.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import { createApp } from "../server/app.js";
import { CaptureStore } from "../state.js";
import type { AppConfig, JsonRecord } from "../types.js";

export interface CliOutput {
  log(message: string): void;
  error(message: string): void;
}

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

export async function runCli(argv: readonly string[], output: CliOutput): Promise<void> {
  const [command = "serve", ...rest] = argv;
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
    output.log(ASCII_HEADER);
    output.log(JSON.stringify(initSummary(config), null, 2));
    return;
  }

  if (command === "federation-jwks" || command === "federation-registration") {
    const config = loadConfig(typeof args.data_dir === "string" ? args.data_dir : undefined);
    const issuerConfigurationId =
      typeof args.issuer_configuration_id === "string" ? args.issuer_configuration_id : undefined;
    if (command === "federation-registration" && !config.federation.enabled) {
      throw new Error(
        "Enable federation with FEDERATION_ENABLED=true before exporting registration entries",
      );
    }
    const issuers =
      command === "federation-jwks"
        ? allResolvedIssuerConfigurations(config)
        : resolvedIssuerConfigurations(config);
    const selectedIssuers = issuerConfigurationId
      ? issuers.filter((issuer) => issuer.id === issuerConfigurationId)
      : issuers;
    if (selectedIssuers.length === 0) {
      throw new Error(`Unknown or disabled issuer configuration '${issuerConfigurationId ?? ""}'`);
    }
    const entries = selectedIssuers.map((issuer) =>
      command === "federation-jwks"
        ? {
            issuer_configuration_id: issuer.id,
            entity_id: issuer.issuerIdentifier,
            jwks: loadIssuerFederationJwks(issuer),
          }
        : issuerFederationRegistration(issuer),
    );
    output.log(JSON.stringify(issuerConfigurationId ? entries[0] : entries, null, 2));
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
      output.log(ASCII_HEADER);
      output.log(`capture services listening on ${host ?? "0.0.0.0"}:${port}`);
    });
    return;
  }
  if (command.startsWith("attestbook-")) {
    await attestbookCommand(command, args, output);
    return;
  }

  throw new Error(`unknown command: ${command}`);
}

/**
 * The one-time Attestbook subscription procedure, run by an operator against the deployed
 * callback: `attestbook-subscribe` registers it once, `attestbook-verify` has Attestbook deliver
 * the challenge the running service answers, and `attestbook-subscription` confirms it is active.
 * The management token is read from ATTESTBOOK_MANAGEMENT_TOKEN, never from the command line.
 */
async function attestbookCommand(
  command: string,
  args: Record<string, string | boolean>,
  output: CliOutput,
): Promise<void> {
  const config = loadConfig(typeof args.data_dir === "string" ? args.data_dir : undefined);
  const { base_url: origin, rulebook_id: rulebookId } = config.attestbook;
  if (!config.attestbook.enabled || !origin || !rulebookId) {
    throw new Error(
      "Enable the Attestbook integration (ATTESTBOOK_ENABLED, ATTESTBOOK_BASE_URL, ATTESTBOOK_RULEBOOK_ID)",
    );
  }
  const target: SubscriptionTarget = { origin, rulebookId };

  if (command === "attestbook-subscribe") {
    const registered = await registerSubscription(
      target,
      webhookCallbackUrl(config.public_base_url),
    );
    const secrets = JSON.stringify(registered, null, 2);
    if (typeof args.output === "string") {
      writeFileSync(args.output, `${secrets}\n`, { mode: 0o600, flag: "wx" });
      output.log(
        JSON.stringify(
          {
            id: registered.id,
            state: registered.state,
            callbackUrl: registered.callbackUrl,
            secrets_written_to: args.output,
          },
          null,
          2,
        ),
      );
    } else {
      output.log(secrets);
    }
    output.error(
      "Store managementToken and webhookSecret now: Attestbook returns them only once. Configure ATTESTBOOK_WEBHOOK_SECRET, restart the service, then run attestbook-verify.",
    );
    return;
  }

  const subscriptionId = typeof args.subscription_id === "string" ? args.subscription_id : null;
  const managementToken = process.env.ATTESTBOOK_MANAGEMENT_TOKEN?.trim();
  if (!subscriptionId || !managementToken) {
    throw new Error("Pass --subscription-id and set ATTESTBOOK_MANAGEMENT_TOKEN");
  }
  if (command === "attestbook-verify") {
    output.log(
      JSON.stringify(await verifySubscription(target, subscriptionId, managementToken), null, 2),
    );
    return;
  }
  if (command === "attestbook-subscription") {
    output.log(
      JSON.stringify(await readSubscription(target, subscriptionId, managementToken), null, 2),
    );
    return;
  }
  throw new Error(`unknown command: ${command}`);
}

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
