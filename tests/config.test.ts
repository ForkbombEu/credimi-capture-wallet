import { describe, expect, it } from "vitest";
import {
  DEFAULT_CONFIG,
  parseEnvText,
  resolveGuiEnabled,
  resolveListenAddr,
} from "../src/config.js";

describe("configuration", () => {
  it("uses listen_addr when PORT is not set", () => {
    expect(resolveListenAddr({ ...DEFAULT_CONFIG, listen_addr: "127.0.0.1:8181" }, {})).toEqual({
      host: "127.0.0.1",
      port: 8181,
    });
  });

  it("overrides the configured port from PORT", () => {
    expect(
      resolveListenAddr({ ...DEFAULT_CONFIG, listen_addr: "127.0.0.1:8181" }, { PORT: "9090" }),
    ).toEqual({
      host: "127.0.0.1",
      port: 9090,
    });
  });

  it("rejects invalid PORT values", () => {
    expect(() => resolveListenAddr(DEFAULT_CONFIG, { PORT: "not-a-port" })).toThrow(
      "PORT must be an integer between 1 and 65535",
    );
    expect(() => resolveListenAddr(DEFAULT_CONFIG, { PORT: "70000" })).toThrow(
      "PORT must be an integer between 1 and 65535",
    );
  });
  it("parses GUI_ENABLED values from env text", () => {
    const parsed = parseEnvText(`
# comment
GUI_ENABLED=false
export PORT=3000
QUOTED="value"
`);

    expect(parsed).toEqual({ GUI_ENABLED: "false", PORT: "3000", QUOTED: "value" });
    expect(resolveGuiEnabled(parsed)).toBe(false);
    expect(resolveGuiEnabled({ GUI_ENABLED: "true" })).toBe(true);
    expect(resolveGuiEnabled({})).toBe(true);
  });

  it("rejects invalid GUI_ENABLED values", () => {
    expect(() => resolveGuiEnabled({ GUI_ENABLED: "maybe" })).toThrow(
      "GUI_ENABLED must be true or false",
    );
  });
});
