import { describe, expect, it } from "vitest";
import {
  ATTESTBOOK_ADMIN_TOKEN_ENV_VAR,
  ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR,
  ATTESTBOOK_BASE_URL_ENV_VAR,
  ATTESTBOOK_ENABLED_ENV_VAR,
  ATTESTBOOK_RULEBOOK_ID_ENV_VAR,
  ATTESTBOOK_WEBHOOK_SECRET_ENV_VAR,
  DISABLED_ATTESTBOOK_SETTINGS,
  isLoopbackHost,
  resolveAttestbookSettings,
  trustedOrigin,
} from "../src/attestbook/settings.js";

describe("Attestbook settings", () => {
  it("returns the shared disabled settings object for every false token", () => {
    for (const token of [undefined, "", "0", "false", "no", "off", " FALSE "]) {
      const settings = resolveAttestbookSettings({
        [ATTESTBOOK_ENABLED_ENV_VAR]: token,
        [ATTESTBOOK_BASE_URL_ENV_VAR]: "not a URL",
      });
      expect(settings).toBe(DISABLED_ATTESTBOOK_SETTINGS);
    }
  });

  it("rejects an enabled token that is not a boolean spelling", () => {
    expect(() => resolveAttestbookSettings({ [ATTESTBOOK_ENABLED_ENV_VAR]: "maybe" })).toThrow(
      `${ATTESTBOOK_ENABLED_ENV_VAR} must be true or false`,
    );
  });

  it.each([
    [
      "base URL",
      { [ATTESTBOOK_ENABLED_ENV_VAR]: "true" },
      `${ATTESTBOOK_BASE_URL_ENV_VAR} is required when Attestbook is enabled`,
    ],
    [
      "rulebook id",
      {
        [ATTESTBOOK_ENABLED_ENV_VAR]: "true",
        [ATTESTBOOK_BASE_URL_ENV_VAR]: "https://book.example",
      },
      `${ATTESTBOOK_RULEBOOK_ID_ENV_VAR} is required when Attestbook is enabled`,
    ],
  ])("requires an enabled %s", (_name, env, message) => {
    expect(() => resolveAttestbookSettings(env)).toThrow(message);
  });

  it("rejects unsafe rulebook identifiers", () => {
    expect(() =>
      resolveAttestbookSettings({
        [ATTESTBOOK_ENABLED_ENV_VAR]: "yes",
        [ATTESTBOOK_BASE_URL_ENV_VAR]: "https://book.example",
        [ATTESTBOOK_RULEBOOK_ID_ENV_VAR]: "rulebook/../../secret",
      }),
    ).toThrow(`${ATTESTBOOK_RULEBOOK_ID_ENV_VAR} contains unsupported characters`);
  });

  it("accepts enabled settings, trims secrets and splits trusted schema origins", () => {
    const settings = resolveAttestbookSettings({
      [ATTESTBOOK_ENABLED_ENV_VAR]: " ON ",
      [ATTESTBOOK_BASE_URL_ENV_VAR]: " https://book.example/ ",
      [ATTESTBOOK_RULEBOOK_ID_ENV_VAR]: " rulebook-main ",
      [ATTESTBOOK_WEBHOOK_SECRET_ENV_VAR]: " secret ",
      [ATTESTBOOK_ADMIN_TOKEN_ENV_VAR]: " token ",
      [ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR]:
        " https://schemas.example, ,https://schemas-two.example/ ",
    });
    expect(settings).toEqual({
      enabled: true,
      base_url: "https://book.example",
      rulebook_id: "rulebook-main",
      webhook_secret: "secret",
      admin_token: "token",
      allowed_schema_origins: ["https://schemas.example", "https://schemas-two.example"],
    });
  });

  it.each([
    [
      "path",
      "https://example.test/path",
      "ORIGIN must be an origin without credentials, path, query or fragment",
    ],
    [
      "query",
      "https://example.test?query=1",
      "ORIGIN must be an origin without credentials, path, query or fragment",
    ],
    [
      "fragment",
      "https://example.test#fragment",
      "ORIGIN must be an origin without credentials, path, query or fragment",
    ],
    [
      "credentials",
      "https://user:password@example.test",
      "ORIGIN must be an origin without credentials, path, query or fragment",
    ],
    [
      "not absolute",
      "not-an-absolute-url",
      "ORIGIN must be an absolute origin, got 'not-an-absolute-url'",
    ],
    [
      "plain HTTP",
      "http://example.test",
      "ORIGIN must use https (plain http is accepted only for loopback hosts)",
    ],
  ])("rejects an unsafe trusted origin (%s)", (_name, value, message) => {
    expect(() => trustedOrigin(value, "ORIGIN")).toThrow(message);
  });

  it("reports a missing rulebook id before validating an invalid base URL", () => {
    expect(() =>
      resolveAttestbookSettings({
        [ATTESTBOOK_ENABLED_ENV_VAR]: "true",
        [ATTESTBOOK_BASE_URL_ENV_VAR]: "not-an-origin",
      }),
    ).toThrow(`${ATTESTBOOK_RULEBOOK_ID_ENV_VAR} is required when Attestbook is enabled`);
  });

  it.each([
    "http://localhost",
    "http://127.0.0.1:8080",
    "http://[::1]:9000",
    "https://example.test",
  ])("accepts trusted origin %s", (value) => {
    expect(trustedOrigin(value, "ORIGIN")).toBe(new URL(value).origin);
  });

  it("validates every allowed schema origin with the same origin rules", () => {
    expect(() =>
      resolveAttestbookSettings({
        [ATTESTBOOK_ENABLED_ENV_VAR]: "1",
        [ATTESTBOOK_BASE_URL_ENV_VAR]: "https://book.example",
        [ATTESTBOOK_RULEBOOK_ID_ENV_VAR]: "book",
        [ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR]:
          "https://ok.example, http://schemas.example/path",
      }),
    ).toThrow(
      `${ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR} must be an origin without credentials, path, query or fragment`,
    );
  });

  it("normalizes absent webhook and admin credentials to null", () => {
    expect(
      resolveAttestbookSettings({
        [ATTESTBOOK_ENABLED_ENV_VAR]: "true",
        [ATTESTBOOK_BASE_URL_ENV_VAR]: "https://book.example",
        [ATTESTBOOK_RULEBOOK_ID_ENV_VAR]: "book",
        [ATTESTBOOK_WEBHOOK_SECRET_ENV_VAR]: "  ",
        [ATTESTBOOK_ADMIN_TOKEN_ENV_VAR]: "",
      }),
    ).toMatchObject({ webhook_secret: null, admin_token: null });
  });

  it.each([
    ["localhost", true],
    ["127.0.0.1", true],
    ["[::1]", true],
    ["::1", false],
    ["127.0.0.2", false],
    ["localhost.example", false],
    ["example.test", false],
  ])("recognizes literal loopback host %s", (hostname, expected) => {
    expect(isLoopbackHost(hostname)).toBe(expected);
  });
});
