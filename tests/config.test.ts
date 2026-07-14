import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Kms, X509Certificate } from "@credo-ts/core";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_CONFIG,
  initIssuer,
  loadIssuerJwks,
  normalizeBaseUrl,
  parseEnvText,
  privateJwkPath,
  resolveGuiEnabled,
  resolveListenAddr,
  verifierCertificatePath,
  verifierPrivateJwkPath,
} from "../src/config.js";

describe("configuration", () => {
  it("normalizes issuer base URLs from hosts and absolute URLs", () => {
    expect(normalizeBaseUrl("beta-capture-wallet.credimi.io")).toBe(
      "https://beta-capture-wallet.credimi.io",
    );
    expect(normalizeBaseUrl("localhost:8080")).toBe("http://localhost:8080");
    expect(normalizeBaseUrl("https://issuer.example.test/")).toBe("https://issuer.example.test");
  });

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

  it("adds the self-signed issuer certificate chain to the issuer JWKS", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "fake-issuer-config-test-"));
    try {
      const config = await initIssuer({
        issuer_base_url: "http://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });

      const jwks = loadIssuerJwks(config);
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0]?.x5c).toEqual([expect.any(String)]);
      const certificate = X509Certificate.fromEncodedCertificate(
        (jwks.keys[0]?.x5c as string[])[0],
      );
      expect(Kms.PublicJwk.fromUnknown(jwks.keys[0]).equals(certificate.publicJwk)).toBe(true);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("creates separate verifier key material for OpenID4VP", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "fake-verifier-config-test-"));
    try {
      await initIssuer({
        issuer_base_url: "http://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });

      expect(existsSync(verifierPrivateJwkPath(dataDir))).toBe(true);
      expect(existsSync(verifierCertificatePath(dataDir))).toBe(true);
      expect(readFileSync(verifierPrivateJwkPath(dataDir), "utf8")).not.toBe(
        readFileSync(privateJwkPath(dataDir), "utf8"),
      );

      const verifierPrivateJwk = JSON.parse(
        readFileSync(verifierPrivateJwkPath(dataDir), "utf8"),
      ) as Record<string, unknown>;
      const verifierCertificate = X509Certificate.fromEncodedCertificate(
        readFileSync(verifierCertificatePath(dataDir), "utf8"),
      );
      const { d: _d, ...verifierPublicJwk } = verifierPrivateJwk;
      expect(
        Kms.PublicJwk.fromUnknown(verifierPublicJwk).equals(verifierCertificate.publicJwk),
      ).toBe(true);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
});
