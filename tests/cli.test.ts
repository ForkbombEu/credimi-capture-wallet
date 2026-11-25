import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

type JsonRecord = Record<string, unknown>;
type CliResult = { status: number | null; stdout: string; stderr: string };
type EnvOverrides = Record<string, string>;

const worktree = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tsx = join(worktree, "node_modules/.bin/tsx");
const blockedEnvironment = new Set([
  "FEDERATION_ENABLED",
  "FEDERATION_AUTHORITY_HINTS",
  "ATTESTBOOK_ENABLED",
  "ATTESTBOOK_BASE_URL",
  "ATTESTBOOK_RULEBOOK_ID",
  "ATTESTBOOK_ADMIN_TOKEN",
  "ATTESTBOOK_MANAGEMENT_TOKEN",
  "ATTESTBOOK_WEBHOOK_SECRET",
  "ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS",
]);
let cliSymlink = "";

function cliEnvironment(overrides: EnvOverrides = {}): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !blockedEnvironment.has(key)) environment[key] = value;
  }
  Object.assign(environment, {
    FEDERATION_ENABLED: "false",
    FEDERATION_AUTHORITY_HINTS: "",
    ATTESTBOOK_ENABLED: "false",
    ATTESTBOOK_BASE_URL: "",
    ATTESTBOOK_RULEBOOK_ID: "",
    ATTESTBOOK_ADMIN_TOKEN: "",
    ATTESTBOOK_MANAGEMENT_TOKEN: "",
    ATTESTBOOK_WEBHOOK_SECRET: "",
    ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS: "",
    ...overrides,
  });
  return environment;
}

function runCli(args: string[], env: EnvOverrides = {}): CliResult {
  const result = spawnSync(tsx, ["src/cli.ts", ...args], {
    cwd: worktree,
    encoding: "utf8",
    env: cliEnvironment(env),
    timeout: 60_000,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? ""),
  };
}

function runPackageScript(args: string[], env: EnvOverrides = {}): CliResult {
  const result = spawnSync("pnpm", ["--silent", "capture-services", ...args], {
    cwd: worktree,
    encoding: "utf8",
    env: cliEnvironment(env),
    timeout: 60_000,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? ""),
  };
}

// tsx receives the symlink as argv[1]; import.meta.url resolves the real target path.
function runCliSymlink(args: string[], env: EnvOverrides = {}): CliResult {
  const environment = cliEnvironment(env);
  environment.PATH = `${join(worktree, "node_modules/.bin")}:${environment.PATH ?? ""}`;
  const result = spawnSync("tsx", [cliSymlink, ...args], {
    cwd: worktree,
    encoding: "utf8",
    env: environment,
    timeout: 60_000,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? ""),
  };
}

function parseJson(stdout: string): JsonRecord | JsonRecord[] {
  const starts = [stdout.indexOf("{"), stdout.indexOf("[")].filter((index) => index >= 0);
  if (starts.length === 0) throw new Error(`CLI output did not contain JSON: ${stdout}`);
  return JSON.parse(stdout.slice(Math.min(...starts))) as JsonRecord | JsonRecord[];
}

function assertCanonicalJsonOutput(stdout: string): JsonRecord | JsonRecord[] {
  const parsed = parseJson(stdout);
  expect(stdout).toBe(`${JSON.stringify(parsed, null, 2)}\n`);
  return parsed;
}

function asRecord(value: unknown): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected a JSON object");
  }
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("expected a JSON array");
  return value;
}

function sortedKeys(value: JsonRecord): string[] {
  return Object.keys(value).sort();
}

function assertFederationJwks(value: unknown, entityId: string): void {
  const entry = asRecord(value);
  expect(sortedKeys(entry)).toEqual(["entity_id", "issuer_configuration_id", "jwks"].sort());
  expect(entry.entity_id).toBe(entityId);
  const jwks = asRecord(entry.jwks);
  expect(sortedKeys(jwks)).toEqual(["keys"]);
  const keys = asArray(jwks.keys);
  expect(keys).toHaveLength(1);
  const key = asRecord(keys[0]);
  expect(sortedKeys(key)).toEqual(["alg", "crv", "kid", "kty", "use", "x", "y"].sort());
  expect(key).toMatchObject({ alg: "ES256", crv: "P-256", kty: "EC", use: "sig" });
  for (const field of ["x", "y", "kid"]) {
    expect(key[field]).toEqual(expect.any(String));
    expect(key[field]).toMatch(/^[A-Za-z0-9_-]+$/);
  }
}

function assertFederationRegistration(value: unknown, entityId: string): void {
  const entry = asRecord(value);
  expect(sortedKeys(entry)).toEqual(
    ["constraints", "enabled", "entity_id", "entity_types", "jwks"].sort(),
  );
  expect(entry.entity_id).toBe(entityId);
  expect(entry.enabled).toBe(true);
  expect(entry.entity_types).toEqual(["openid_credential_issuer", "oauth_authorization_server"]);
  expect(entry.constraints).toEqual({ max_path_length: 0 });
  assertFederationJwks(
    { issuer_configuration_id: "unused", entity_id: entityId, jwks: entry.jwks },
    entityId,
  );
}

const INIT_BANNER = `
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

describe("CLI subprocess behaviour", () => {
  let dataDir: string;
  let initResult: CliResult;
  let initSummary: JsonRecord;

  beforeAll(() => {
    dataDir = mkdtempSync(join(tmpdir(), "capture-services-cli-"));
    const symlinkDir = mkdtempSync(join(dataDir, "capture-services-symlink-"));
    cliSymlink = join(symlinkDir, "capture-services");
    symlinkSync(join(worktree, "src/cli.ts"), cliSymlink);
    initResult = runCli([
      "init",
      "--data-dir",
      dataDir,
      "--services-base-url",
      "https://issuer.example.test",
      "--force",
    ]);
    expect(initResult.status, initResult.stderr).toBe(0);
    expect(initResult.stderr).toBe("");
    initSummary = asRecord(parseJson(initResult.stdout));
  }, 60_000);

  afterAll(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  const federationEnvironment: EnvOverrides = {
    FEDERATION_ENABLED: "true",
    FEDERATION_AUTHORITY_HINTS: '["https://authority.example.test"]',
  };
  const issuerId = "eu-pid-device-bound";
  const issuerEntityId = `https://issuer.example.test/issuers/${issuerId}`;

  it("initializes with the documented summary shape and stable values", () => {
    const summaryJson = `${JSON.stringify(initSummary, null, 2)}\n`;
    const jsonStart = initResult.stdout.indexOf("{");
    expect(initResult.stdout.slice(0, jsonStart)).toBe(`${INIT_BANNER}\n`);
    expect(initResult.stdout.endsWith(summaryJson)).toBe(true);
    expect(sortedKeys(initSummary)).toEqual(
      ["health_url", "issuer_catalogue_url", "issuers", "services_base_url"].sort(),
    );
    expect(initSummary.services_base_url).toBe("https://issuer.example.test");
    expect(initSummary.issuer_catalogue_url).toBe("https://issuer.example.test/issuers");
    expect(initSummary.health_url).toBe("https://issuer.example.test/healthz");
    expect(initSummary.issuers).toEqual([
      {
        issuer_configuration_id: "eu-pid-device-bound",
        credential_issuer: "https://issuer.example.test/issuers/eu-pid-device-bound",
        credential_issuer_metadata_url:
          "https://issuer.example.test/.well-known/openid-credential-issuer/issuers/eu-pid-device-bound",
        authorization_server_metadata_url:
          "https://issuer.example.test/.well-known/oauth-authorization-server/issuers/eu-pid-device-bound",
        upstream_authorization_server:
          "https://issuer.example.test/authorization-servers/eu-pid-device-bound",
        upstream_authorization_server_metadata_url:
          "https://issuer.example.test/.well-known/oauth-authorization-server/authorization-servers/eu-pid-device-bound",
        authorization_server_jwks_url:
          "https://issuer.example.test/issuers/eu-pid-device-bound/jwks.json",
        credential_jwks_url:
          "https://issuer.example.test/issuers/eu-pid-device-bound/credential-jwks.json",
      },
      {
        issuer_configuration_id: "eu-pid-jwt-key-attestation",
        credential_issuer: "https://issuer.example.test/issuers/eu-pid-jwt-key-attestation",
        credential_issuer_metadata_url:
          "https://issuer.example.test/.well-known/openid-credential-issuer/issuers/eu-pid-jwt-key-attestation",
        authorization_server_metadata_url:
          "https://issuer.example.test/.well-known/oauth-authorization-server/issuers/eu-pid-jwt-key-attestation",
        upstream_authorization_server:
          "https://issuer.example.test/authorization-servers/eu-pid-jwt-key-attestation",
        upstream_authorization_server_metadata_url:
          "https://issuer.example.test/.well-known/oauth-authorization-server/authorization-servers/eu-pid-jwt-key-attestation",
        authorization_server_jwks_url:
          "https://issuer.example.test/issuers/eu-pid-jwt-key-attestation/jwks.json",
        credential_jwks_url:
          "https://issuer.example.test/issuers/eu-pid-jwt-key-attestation/credential-jwks.json",
      },
      {
        issuer_configuration_id: "eu-pid-jwt-proof-only",
        credential_issuer: "https://issuer.example.test/issuers/eu-pid-jwt-proof-only",
        credential_issuer_metadata_url:
          "https://issuer.example.test/.well-known/openid-credential-issuer/issuers/eu-pid-jwt-proof-only",
        authorization_server_metadata_url:
          "https://issuer.example.test/.well-known/oauth-authorization-server/issuers/eu-pid-jwt-proof-only",
        upstream_authorization_server:
          "https://issuer.example.test/authorization-servers/eu-pid-jwt-proof-only",
        upstream_authorization_server_metadata_url:
          "https://issuer.example.test/.well-known/oauth-authorization-server/authorization-servers/eu-pid-jwt-proof-only",
        authorization_server_jwks_url:
          "https://issuer.example.test/issuers/eu-pid-jwt-proof-only/jwks.json",
        credential_jwks_url:
          "https://issuer.example.test/issuers/eu-pid-jwt-proof-only/credential-jwks.json",
      },
    ]);
  });

  it("keeps the generated summary stable when init is rerun without force", () => {
    const before = runCli(["federation-jwks", "--data-dir", dataDir], federationEnvironment);
    expect(before.status).toBe(0);
    expect(before.stderr).toBe("");
    const result = runCli([
      "init",
      "--data-dir",
      dataDir,
      "--services-base-url",
      "https://issuer.example.test",
    ]);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(parseJson(result.stdout)).toEqual(initSummary);
    const after = runCli(["federation-jwks", "--data-dir", dataDir], federationEnvironment);
    expect(after.status).toBe(0);
    expect(after.stderr).toBe("");
    expect(after.stdout).toBe(before.stdout);
  });

  it("exports all federation JWKS entries and filters by issuer configuration", () => {
    const all = runCli(["federation-jwks", "--data-dir", dataDir], federationEnvironment);
    expect(all.status).toBe(0);
    expect(all.stderr).toBe("");
    const entries = asArray(assertCanonicalJsonOutput(all.stdout));
    expect(entries).toHaveLength(4);
    expect(entries.map((entry) => asRecord(entry).issuer_configuration_id)).toEqual([
      "eu-pid-device-bound",
      "eu-pid-jwt-key-attestation",
      "eu-pid-jwt-proof-only",
      "attestbook-experimental",
    ]);
    expect(entries.map((entry) => asRecord(entry).entity_id)).toEqual([
      "https://issuer.example.test/issuers/eu-pid-device-bound",
      "https://issuer.example.test/issuers/eu-pid-jwt-key-attestation",
      "https://issuer.example.test/issuers/eu-pid-jwt-proof-only",
      "https://issuer.example.test/issuers/attestbook-experimental",
    ]);
    for (const entry of entries) assertFederationJwks(entry, asRecord(entry).entity_id as string);

    const filtered = runCli(
      ["federation-jwks", "--data-dir", dataDir, "--issuer-configuration-id", issuerId],
      federationEnvironment,
    );
    expect(filtered.status).toBe(0);
    expect(filtered.stderr).toBe("");
    assertFederationJwks(assertCanonicalJsonOutput(filtered.stdout), issuerEntityId);
  });

  it("exports federation registration entries with filtering", () => {
    const all = runCli(["federation-registration", "--data-dir", dataDir], federationEnvironment);
    expect(all.status).toBe(0);
    expect(all.stderr).toBe("");
    const entries = asArray(assertCanonicalJsonOutput(all.stdout));
    expect(entries).toHaveLength(3);
    expect(entries.map((entry) => asRecord(entry).entity_id)).toEqual([
      "https://issuer.example.test/issuers/eu-pid-device-bound",
      "https://issuer.example.test/issuers/eu-pid-jwt-key-attestation",
      "https://issuer.example.test/issuers/eu-pid-jwt-proof-only",
    ]);
    for (const entry of entries) {
      const record = asRecord(entry);
      assertFederationRegistration(record, record.entity_id as string);
    }

    const filtered = runCli(
      ["federation-registration", "--data-dir", dataDir, "--issuer-configuration-id", issuerId],
      federationEnvironment,
    );
    expect(filtered.status).toBe(0);
    expect(filtered.stderr).toBe("");
    assertFederationRegistration(assertCanonicalJsonOutput(filtered.stdout), issuerEntityId);
  });

  it("pins pnpm script and real CLI symlink execution", { timeout: 20_000 }, () => {
    const args = ["federation-jwks", "--data-dir", dataDir, "--issuer-configuration-id", issuerId];
    const direct = runCli(args, federationEnvironment);
    const packageScript = runPackageScript(args, federationEnvironment);
    const symlink = runCliSymlink(args, federationEnvironment);
    expect(packageScript).toEqual(direct);
    expect(symlink).toEqual(direct);
  });

  it("reports unknown and unavailable federation configurations exactly", () => {
    const unknown = runCli(
      ["federation-jwks", "--data-dir", dataDir, "--issuer-configuration-id", "not-configured"],
      federationEnvironment,
    );
    expect(unknown.status).toBe(1);
    expect(unknown.stdout).toBe("");
    expect(unknown.stderr).toBe("Unknown or disabled issuer configuration 'not-configured'\n");

    const disabled = runCli([
      "federation-registration",
      "--data-dir",
      dataDir,
      "--issuer-configuration-id",
      issuerId,
    ]);
    expect(disabled.status).toBe(1);
    expect(disabled.stdout).toBe("");
    expect(disabled.stderr).toBe(
      "Enable federation with FEDERATION_ENABLED=true before exporting registration entries\n",
    );
  });

  it("reports unknown commands with exit code 1", () => {
    const result = runCli(["not-a-command"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("unknown command: not-a-command\n");
  });

  it("validates disabled Attestbook commands without making network requests", () => {
    const result = runCli(["attestbook-subscribe", "--data-dir", dataDir]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(
      "Enable the Attestbook integration (ATTESTBOOK_ENABLED, ATTESTBOOK_BASE_URL, ATTESTBOOK_RULEBOOK_ID)\n",
    );
  });

  it.each([
    ["attestbook-verify", []],
    ["attestbook-verify", ["--subscription-id", "subscription-1"]],
    ["attestbook-subscription", ["--subscription-id", "subscription-1"]],
  ] as const)(
    "rejects %s before network access when the management token is missing",
    (command, extraArgs) => {
      const result = runCli([command, "--data-dir", dataDir, ...extraArgs], {
        ATTESTBOOK_ENABLED: "true",
        ATTESTBOOK_BASE_URL: "https://attestbook.example.test",
        ATTESTBOOK_RULEBOOK_ID: "pid-rulebook",
      });
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("Pass --subscription-id and set ATTESTBOOK_MANAGEMENT_TOKEN\n");
    },
  );

  it("rejects Attestbook verification without a subscription id even with a management token", () => {
    const result = runCli(["attestbook-verify", "--data-dir", dataDir], {
      ATTESTBOOK_ENABLED: "true",
      ATTESTBOOK_BASE_URL: "https://attestbook.example.test",
      ATTESTBOOK_RULEBOOK_ID: "pid-rulebook",
      ATTESTBOOK_MANAGEMENT_TOKEN: "management-token",
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Pass --subscription-id and set ATTESTBOOK_MANAGEMENT_TOKEN\n");
  });
});
