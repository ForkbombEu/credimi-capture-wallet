import { describe, expect, it } from "vitest";
import { parseArgs, runCli } from "../src/cli/commands.js";
import { createIssuerTestEnvironment } from "./support/environment.js";

type CapturedOutput = { logs: string[]; errors: string[] };

function capturingOutput(): CapturedOutput {
  return { logs: [], errors: [] };
}

describe("CLI commands", () => {
  it("parses command-line flags as currently supported", () => {
    expect(
      parseArgs([
        "positional",
        "--flag",
        "value",
        "--boolean",
        "--kebab-case",
        "first",
        "--kebab-case",
        "second",
        "--equals=value",
        "x",
        "--data-dir",
        "",
      ]),
    ).toEqual({
      flag: "value",
      boolean: true,
      kebab_case: "second",
      "equals=value": "x",
      data_dir: true,
    });
  });

  it("runs federation-jwks with captured output", async () => {
    const environment = await createIssuerTestEnvironment({ prefix: "capture-services-cli-" });
    try {
      const captured = capturingOutput();
      await runCli(["federation-jwks", "--data-dir", environment.dataDir], {
        log: (message) => captured.logs.push(message),
        error: (message) => captured.errors.push(message),
      });

      expect(captured.errors).toEqual([]);
      expect(captured.logs).toHaveLength(1);
      const entries = JSON.parse(captured.logs[0] ?? "null") as unknown;
      expect(Array.isArray(entries)).toBe(true);
      expect(entries).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            issuer_configuration_id: "eu-pid-device-bound",
            entity_id: `${environment.config.issuer_base_url}/issuers/eu-pid-device-bound`,
            jwks: expect.objectContaining({ keys: expect.any(Array) }),
          }),
        ]),
      );
    } finally {
      environment.cleanup();
    }
  }, 60_000);

  it("rejects an unknown command without logging", async () => {
    const captured = capturingOutput();
    await expect(
      runCli(["not-a-command"], {
        log: (message) => captured.logs.push(message),
        error: (message) => captured.errors.push(message),
      }),
    ).rejects.toThrow(/^unknown command: not-a-command$/);
    expect(captured.logs).toEqual([]);
    expect(captured.errors).toEqual([]);
  });
});
