import { X509Certificate as NodeX509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Kms, X509Certificate } from "@credo-ts/core";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_CONFIG,
  accessTokenPrivateJwkPath,
  initIssuer,
  issuerCertificatePath,
  issuerEncryptionPrivateJwkPath,
  jwksPath,
  loadIssuerEncryptionPublicJwk,
  loadIssuerJwks,
  normalizeBaseUrl,
  parseEnvText,
  privateJwkPath,
  resolveGuiEnabled,
  resolveListenAddr,
  validateIssuerCertificateSubjectAlternativeName,
  validateIssuerMaterial,
  verifierCertificatePath,
  verifierPrivateJwkPath,
} from "../src/config.js";
import {
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";

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

      const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
      expect(issuer).not.toBeNull();
      if (!issuer) throw new Error("device-bound issuer unavailable");
      const issuerConfig = issuerAppConfig(config, issuer);
      const jwks = loadIssuerJwks(issuerConfig);
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
      const config = await initIssuer({
        issuer_base_url: "http://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });

      expect(existsSync(verifierPrivateJwkPath(dataDir))).toBe(true);
      expect(existsSync(verifierCertificatePath(dataDir))).toBe(true);
      const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
      expect(issuer).not.toBeNull();
      if (!issuer) throw new Error("device-bound issuer unavailable");
      expect(readFileSync(verifierPrivateJwkPath(dataDir), "utf8")).not.toBe(
        readFileSync(privateJwkPath(issuer.materialDirectory), "utf8"),
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

  it("creates a dedicated issuer credential request encryption key", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "fake-issuer-encryption-config-test-"));
    try {
      const config = await initIssuer({
        issuer_base_url: "http://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });

      const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
      expect(issuer).not.toBeNull();
      if (!issuer) throw new Error("device-bound issuer unavailable");
      const issuerConfig = issuerAppConfig(config, issuer);
      expect(existsSync(issuerEncryptionPrivateJwkPath(issuer.materialDirectory))).toBe(true);
      expect(
        readFileSync(issuerEncryptionPrivateJwkPath(issuer.materialDirectory), "utf8"),
      ).not.toBe(readFileSync(privateJwkPath(issuer.materialDirectory), "utf8"));
      expect(loadIssuerEncryptionPublicJwk(issuerConfig)).toMatchObject({
        kty: "EC",
        crv: "P-256",
        alg: "ECDH-ES",
        use: "enc",
        kid: issuer.issuerEncryptionKeyId,
      });
      expect(loadIssuerEncryptionPublicJwk(issuerConfig)).not.toHaveProperty("d");
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("creates isolated signing, encryption, access-token, and certificate material per issuer", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "multi-issuer-config-test-"));
    try {
      const config = await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });
      const [deviceBound, jwtOnly] = resolvedIssuerConfigurations(config);
      expect(deviceBound).toBeDefined();
      expect(jwtOnly).toBeDefined();
      if (!deviceBound || !jwtOnly) throw new Error("issuer configurations unavailable");

      const materialPaths = (materialDirectory: string) => ({
        signing: privateJwkPath(materialDirectory),
        encryption: issuerEncryptionPrivateJwkPath(materialDirectory),
        accessToken: accessTokenPrivateJwkPath(materialDirectory),
        certificate: issuerCertificatePath(materialDirectory),
      });
      const deviceBoundPaths = materialPaths(deviceBound.materialDirectory);
      const jwtOnlyPaths = materialPaths(jwtOnly.materialDirectory);

      for (const path of [...Object.values(deviceBoundPaths), ...Object.values(jwtOnlyPaths)]) {
        expect(existsSync(path)).toBe(true);
      }
      expect(readFileSync(deviceBoundPaths.signing, "utf8")).not.toBe(
        readFileSync(jwtOnlyPaths.signing, "utf8"),
      );
      expect(readFileSync(deviceBoundPaths.encryption, "utf8")).not.toBe(
        readFileSync(jwtOnlyPaths.encryption, "utf8"),
      );
      expect(readFileSync(deviceBoundPaths.accessToken, "utf8")).not.toBe(
        readFileSync(jwtOnlyPaths.accessToken, "utf8"),
      );
      expect(readFileSync(deviceBoundPaths.certificate, "utf8")).not.toBe(
        readFileSync(jwtOnlyPaths.certificate, "utf8"),
      );

      const deviceBoundCertificate = new NodeX509Certificate(
        readFileSync(deviceBoundPaths.certificate, "utf8"),
      );
      const jwtOnlyCertificate = new NodeX509Certificate(
        readFileSync(jwtOnlyPaths.certificate, "utf8"),
      );
      expect(deviceBoundCertificate.subjectAltName).toContain(
        `URI:${deviceBound.issuerIdentifier}`,
      );
      expect(jwtOnlyCertificate.subjectAltName).toContain(`URI:${jwtOnly.issuerIdentifier}`);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("keeps every issuer key and certificate stable when init runs without force", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "multi-issuer-restart-test-"));
    try {
      const config = await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });
      const paths = resolvedIssuerConfigurations(config).flatMap((issuer) => [
        privateJwkPath(issuer.materialDirectory),
        issuerEncryptionPrivateJwkPath(issuer.materialDirectory),
        accessTokenPrivateJwkPath(issuer.materialDirectory),
        issuerCertificatePath(issuer.materialDirectory),
        jwksPath(issuer.materialDirectory),
      ]);
      const before = paths.map((path) => readFileSync(path, "utf8"));

      await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
      });

      expect(paths.map((path) => readFileSync(path, "utf8"))).toEqual(before);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("rebuilds an issuer JWKS with the private JWK kid without rotating the private key", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "issuer-jwks-kid-test-"));
    try {
      const config = await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });
      const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
      if (!issuer) throw new Error("device-bound issuer unavailable");
      const secretPath = privateJwkPath(issuer.materialDirectory);
      const publicPath = jwksPath(issuer.materialDirectory);
      const privateJwk = JSON.parse(readFileSync(secretPath, "utf8")) as Record<string, unknown>;
      privateJwk.kid = "externally-managed-issuer-key";
      writeFileSync(secretPath, `${JSON.stringify(privateJwk, null, 2)}\n`);
      rmSync(publicPath);

      await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
      });

      const privateAfterInit = JSON.parse(readFileSync(secretPath, "utf8")) as Record<
        string,
        unknown
      >;
      const publicAfterInit = JSON.parse(readFileSync(publicPath, "utf8")) as {
        keys: Array<Record<string, unknown>>;
      };
      expect(privateAfterInit.kid).toBe("externally-managed-issuer-key");
      expect(publicAfterInit.keys[0]?.kid).toBe(privateAfterInit.kid);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("rejects incomplete or reused issuer material before startup", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "multi-issuer-validation-test-"));
    try {
      const config = await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
        force: true,
      });
      const [deviceBound, jwtOnly] = resolvedIssuerConfigurations(config);
      if (!deviceBound || !jwtOnly) throw new Error("issuer configurations unavailable");
      const jwtOnlyAccessTokenPath = accessTokenPrivateJwkPath(jwtOnly.materialDirectory);
      const originalJwtOnlyAccessToken = readFileSync(jwtOnlyAccessTokenPath, "utf8");

      writeFileSync(
        jwtOnlyAccessTokenPath,
        readFileSync(accessTokenPrivateJwkPath(deviceBound.materialDirectory), "utf8"),
      );
      expect(() => validateIssuerMaterial(config)).toThrow("Issuer key reuse detected");

      writeFileSync(jwtOnlyAccessTokenPath, originalJwtOnlyAccessToken);
      const jwtOnlyJwksPath = jwksPath(jwtOnly.materialDirectory);
      const jwtOnlyJwks = JSON.parse(readFileSync(jwtOnlyJwksPath, "utf8")) as {
        keys: Array<Record<string, unknown>>;
      };
      if (!jwtOnlyJwks.keys[0]) throw new Error("JWT-only issuer signing JWK unavailable");
      jwtOnlyJwks.keys[0].kid = "mismatched-public-key-id";
      writeFileSync(jwtOnlyJwksPath, `${JSON.stringify(jwtOnlyJwks, null, 2)}\n`);
      expect(() => validateIssuerMaterial(config)).toThrow(
        "JWKS kid does not match its private signing JWK kid",
      );

      await initIssuer({
        issuer_base_url: "https://issuer.example.test",
        data_dir: dataDir,
      });
      rmSync(issuerEncryptionPrivateJwkPath(jwtOnly.materialDirectory));
      expect(() => validateIssuerMaterial(config)).toThrow("is missing encryption material");
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("accepts an issuer certificate URI SAN without a deployment-hostname DNS SAN", () => {
    const issuerIdentifier = "https://issuer.example.test/issuers/eu-pid-device-bound";

    expect(() =>
      validateIssuerCertificateSubjectAlternativeName(
        `URI:${issuerIdentifier}`,
        issuerIdentifier,
        "eu-pid-device-bound",
      ),
    ).not.toThrow();
    expect(() =>
      validateIssuerCertificateSubjectAlternativeName(
        "DNS:issuer.example.test",
        issuerIdentifier,
        "eu-pid-device-bound",
      ),
    ).toThrow(`certificate is missing URI SAN '${issuerIdentifier}'`);
  });
});
