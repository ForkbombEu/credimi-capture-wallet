import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair, importJWK } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { issuerEncryptionPrivateJwkPath, loadIssuerEncryptionPublicJwk } from "../src/config.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import type { ResolvedIssuerConfiguration } from "../src/configurations/types.js";
import {
  CredentialEncryptionError,
  credentialResponseEncryption,
  decryptCredentialRequest,
  encryptCredentialResponse,
} from "../src/credential-encryption.js";
import type { AppConfig, JsonRecord } from "../src/types.js";
import {
  CONFORMING_ISSUER_ID,
  createIssuerTestEnvironment,
  requireIssuer,
} from "./support/environment.js";

const mockState = vi.hoisted(() => ({
  decryptResult: undefined as Record<string, unknown> | undefined,
  encryptMode: "real" as
    | "real"
    | "missingHeader"
    | "unexpectedSerialization"
    | "unsupportedDependency",
  externalPublicJwk: undefined as JsonRecord | undefined,
  keyId: undefined as string | undefined,
}));
const RESPONSE_PUBLIC_JWK: JsonRecord = {
  kty: "EC",
  x: "TQiVz21oKjTcJ42QPlD4XaSdm-Rj_JCG2MZRdeRdkqY",
  y: "QR2sFlu6dvNgJ2DITgC_OkYfRSJiJ1IgNYnvaa9rZ_s",
  crv: "P-256",
};
const RESPONSE_PRIVATE_JWK: JsonRecord = {
  ...RESPONSE_PUBLIC_JWK,
  d: "x9EJv6h0j4zlSaL1PM_oGFaO--m19RAXfbZtmM9FCNY",
};

vi.mock("@credo-ts/openid4vc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@credo-ts/openid4vc")>();
  const core = await import("@credo-ts/core");
  return {
    ...actual,
    getOid4vcDecryptJweCallback: (
      context: Parameters<typeof actual.getOid4vcDecryptJweCallback>[0],
    ) => {
      const real = actual.getOid4vcDecryptJweCallback(context);
      return async (...args: Parameters<typeof real>) => {
        if (mockState.decryptResult) {
          return mockState.decryptResult as Awaited<ReturnType<typeof real>>;
        }
        return real(...args);
      };
    },
    getOid4vcEncryptJweCallback: (
      context: Parameters<typeof actual.getOid4vcEncryptJweCallback>[0],
    ) => {
      const real = actual.getOid4vcEncryptJweCallback(context);
      if (mockState.encryptMode === "real") return real;
      return async (...args: Parameters<typeof real>) => {
        const [, compact] = args;
        if (mockState.encryptMode === "unsupportedDependency") {
          context.resolve(undefined as never);
        }
        const encodedHeader = Buffer.from(
          mockState.encryptMode === "missingHeader"
            ? JSON.stringify({})
            : '{ "alg": "ECDH-ES", "enc": "A256GCM" }',
        ).toString("base64url");
        const kms = context.resolve(core.Kms.KeyManagementApi);
        await kms.encrypt({
          key: {
            keyAgreement: {
              keyId: mockState.keyId as string,
              algorithm: "ECDH-ES",
              externalPublicJwk: mockState.externalPublicJwk as never,
            },
          },
          data: Buffer.from(compact),
          encryption: { algorithm: "A256GCM", aad: Buffer.from(encodedHeader) },
        });
        return { encryptionJwk: mockState.externalPublicJwk, jwe: "" } as Awaited<
          ReturnType<typeof real>
        >;
      };
    },
  };
});
describe("credential encryption", () => {
  let environment: Awaited<ReturnType<typeof createIssuerTestEnvironment>>;
  let config: AppConfig;
  let issuer: ResolvedIssuerConfiguration;
  const temporaryDirectories: string[] = [];

  beforeAll(async () => {
    environment = await createIssuerTestEnvironment({ prefix: "credential-encryption-test-" });
    issuer = requireIssuer(environment.config, CONFORMING_ISSUER_ID);
    config = issuerAppConfig(environment.config, issuer);
    mockState.keyId = loadIssuerEncryptionPublicJwk(config)?.kid as string;
  });

  beforeEach(() => {
    mockState.decryptResult = undefined;
    mockState.encryptMode = "real";
  });

  afterAll(() => {
    for (const directory of temporaryDirectories)
      rmSync(directory, { recursive: true, force: true });
    environment.cleanup();
  });

  function configWithDataDir(dataDir: string): AppConfig {
    return { ...config, data_dir: dataDir };
  }

  function configWithPrivateJwk(privateJwk: JsonRecord): AppConfig {
    const dataDir = mkdtempSync(join(tmpdir(), "credential-encryption-material-"));
    temporaryDirectories.push(dataDir);
    writeFileSync(issuerEncryptionPrivateJwkPath(dataDir), JSON.stringify(privateJwk));
    return configWithDataDir(dataDir);
  }

  async function requestJwe(
    requestConfig: AppConfig,
    payload: string,
    header: Record<string, unknown> = {},
  ): Promise<string> {
    const loadedIssuerPublicJwk = loadIssuerEncryptionPublicJwk(requestConfig);
    if (!loadedIssuerPublicJwk) throw new Error("issuer encryption public JWK unavailable");
    const issuerPublicJwk = loadedIssuerPublicJwk;
    const algorithm = typeof header.alg === "string" ? header.alg : "ECDH-ES";
    return new CompactEncrypt(Buffer.from(payload))
      .setProtectedHeader({
        alg: "ECDH-ES",
        enc: "A256GCM",
        kid: typeof issuerPublicJwk.kid === "string" ? issuerPublicJwk.kid : undefined,
        ...header,
      })
      .encrypt(await importJWK(issuerPublicJwk as never, algorithm));
  }

  async function expectCredentialError(
    operation: Promise<unknown>,
    message: string,
  ): Promise<void> {
    await expect(operation).rejects.toBeInstanceOf(CredentialEncryptionError);
    await expect(operation).rejects.toMatchObject({ message });
  }

  it("decrypts a credential request JWE", async () => {
    const request = await requestJwe(
      config,
      JSON.stringify({ credential_configuration_id: "eu.pid" }),
    );
    await expect(decryptCredentialRequest(config, request)).resolves.toEqual({
      credential_configuration_id: "eu.pid",
    });
  });

  it("rejects unavailable issuer encryption material", async () => {
    const missingConfig = configWithDataDir(join(environment.dataDir, "missing"));
    await expectCredentialError(
      decryptCredentialRequest(missingConfig, "not-a-jwe"),
      "Issuer credential request encryption key is unavailable",
    );
    await expectCredentialError(
      encryptCredentialResponse(missingConfig, { jwk: {}, enc: "A256GCM" }, {}),
      "Issuer credential request encryption key is unavailable",
    );
  });

  it("wraps malformed request JWE errors", async () => {
    await expectCredentialError(
      decryptCredentialRequest(config, "not-a-jwe"),
      "Jwt is not a valid jwt, unable to decode",
    );
  });

  it("rejects an undecryptable request JWE", async () => {
    const request = await requestJwe(config, JSON.stringify({ ok: true }));
    const segments = request.split(".");
    const tag = Buffer.from(segments[4] ?? "", "base64url");
    tag[0] ^= 0x01;
    segments[4] = tag.toString("base64url");
    await expectCredentialError(
      decryptCredentialRequest(config, segments.join(".")),
      "Credential Request JWE could not be decrypted",
    );
  });

  it("rejects a request with an unsupported content encryption algorithm", async () => {
    const request = await requestJwe(config, JSON.stringify({ ok: true }), { enc: "A128GCM" });
    await expectCredentialError(
      decryptCredentialRequest(config, request),
      "Credential Request JWE must use A256GCM",
    );
  });

  it("rejects an unsupported request key management algorithm", async () => {
    const request = await requestJwe(config, JSON.stringify({ ok: true }), {
      alg: "ECDH-ES+A256KW",
    });
    await expectCredentialError(
      decryptCredentialRequest(config, request),
      "Only 'ECDH-ES' is supported as 'alg' value for JARM response decryption",
    );
  });

  it("rejects a request algorithm mismatch after decryption", async () => {
    mockState.decryptResult = {
      decrypted: true,
      payload: JSON.stringify({ ok: true }),
      header: { alg: "ECDH-ES+A256KW", enc: "A256GCM" },
    };
    await expectCredentialError(
      decryptCredentialRequest(config, "synthetic-jwe"),
      "Credential Request JWE must use ECDH-ES",
    );
  });

  it("rejects a request whose kid names another issuer key", async () => {
    const otherIssuer = requireIssuer(environment.config, "eu-pid-jwt-proof-only");
    const otherConfig = issuerAppConfig(environment.config, otherIssuer);
    const otherPublicJwk = loadIssuerEncryptionPublicJwk(otherConfig);
    if (!otherPublicJwk?.kid) throw new Error("second issuer encryption key unavailable");
    const request = await requestJwe(config, JSON.stringify({ ok: true }), {
      kid: otherPublicJwk.kid,
    });
    await expectCredentialError(
      decryptCredentialRequest(config, request),
      "Credential Request JWE kid does not identify the issuer encryption key",
    );
  });

  it("rejects an invalid JSON request payload", async () => {
    const request = await requestJwe(config, "not-json");
    await expectCredentialError(
      decryptCredentialRequest(config, request),
      "Credential Request JWE payload must be valid JSON",
    );
  });
  it("rejects a non-object JSON request payload", async () => {
    const request = await requestJwe(config, "[]");
    await expectCredentialError(
      decryptCredentialRequest(config, request),
      "Credential Request JWE payload must be a JSON object",
    );
  });

  const validJwk = { ...RESPONSE_PUBLIC_JWK, alg: "ECDH-ES", use: "enc" };
  const cases: Array<[string, JsonRecord, string]> = [
    [
      "missing jwk",
      { credential_response_encryption: { enc: "A256GCM" } },
      "credential_response_encryption must contain a public jwk",
    ],
    [
      "private key material",
      {
        credential_response_encryption: {
          jwk: { ...RESPONSE_PRIVATE_JWK, alg: "ECDH-ES" },
          enc: "A256GCM",
        },
      },
      "credential_response_encryption.jwk must not contain private key material",
    ],
    [
      "bad jwk alg",
      {
        credential_response_encryption: {
          jwk: { ...RESPONSE_PUBLIC_JWK, alg: "RSA-OAEP" },
          enc: "A256GCM",
        },
      },
      "credential_response_encryption.jwk.alg must be ECDH-ES",
    ],
    [
      "unsupported enc",
      { credential_response_encryption: { jwk: validJwk, enc: "A128GCM" } },
      "credential_response_encryption.enc must be A256GCM",
    ],
    [
      "zip",
      { credential_response_encryption: { jwk: validJwk, enc: "A256GCM", zip: "DEF" } },
      "Credential Response compression is not supported",
    ],
    [
      "invalid public JWK",
      {
        credential_response_encryption: {
          jwk: { kty: "EC", crv: "P-256", alg: "ECDH-ES" },
          enc: "A256GCM",
        },
      },
      "credential_response_encryption.jwk is invalid: jwk is not a valid jwk\n✖ expected string, received undefined\n  → at x\n✖ expected string, received undefined\n  → at y",
    ],
  ];

  it.each(cases)("rejects %s response encryption metadata", (_label, body, message) => {
    try {
      credentialResponseEncryption(body);
      throw new Error("expected credential response encryption rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialEncryptionError);
      expect(error).toMatchObject({ message });
    }
  });

  it.each([
    ["RSA", { kty: "RSA", n: "AQ", e: "AQ", alg: "ECDH-ES" }],
    ["unsupported EC curve", { kty: "EC", crv: "secp256k1", x: "AQ", y: "AQ", alg: "ECDH-ES" }],
  ] as const)("rejects %s response encryption keys", (_label, jwk) => {
    try {
      credentialResponseEncryption({ credential_response_encryption: { jwk, enc: "A256GCM" } });
      throw new Error("expected unsupported key rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialEncryptionError);
      expect(error).toMatchObject({
        message: "credential_response_encryption.jwk must use P-256, P-384, P-521, or X25519",
      });
    }
  });

  it("fills a missing response key id from the legacy key id", async () => {
    const keys = await generateKeyPair("ECDH-ES", { crv: "P-256", extractable: true });
    const jwk = { ...(await exportJWK(keys.publicKey)), alg: "ECDH-ES", use: "enc" } as JsonRecord;
    const { Kms } = await import("@credo-ts/core");
    const expectedLegacyKeyId = Kms.PublicJwk.fromUnknown(jwk).legacyKeyId;
    const result = credentialResponseEncryption({
      credential_response_encryption: { jwk, enc: "A256GCM" },
    });
    expect(result?.jwk.kid).toBe(expectedLegacyKeyId);
    expect(result?.jwk).not.toHaveProperty("d");
  });

  it("encrypts a credential response that the wallet can decrypt", async () => {
    const keys = await generateKeyPair("ECDH-ES", { crv: "P-256", extractable: true });
    const jwk = { ...(await exportJWK(keys.publicKey)), alg: "ECDH-ES", use: "enc" } as JsonRecord;
    const encryption = credentialResponseEncryption({
      credential_response_encryption: { jwk, enc: "A256GCM" },
    });
    if (!encryption) throw new Error("response encryption metadata was not accepted");
    const response = { credentials: [{ credential: "test" }] };
    const compact = await encryptCredentialResponse(config, encryption, response);
    const decrypted = await compactDecrypt(compact, keys.privateKey);
    expect(JSON.parse(Buffer.from(decrypted.plaintext).toString("utf8"))).toEqual(response);
  });

  it("wraps credential response encryption errors", async () => {
    const keys = await generateKeyPair("ECDH-ES", { crv: "P-256", extractable: true });
    const jwk = { ...(await exportJWK(keys.publicKey)), alg: "ECDH-ES", use: "enc" } as JsonRecord;
    const encryption = credentialResponseEncryption({
      credential_response_encryption: { jwk, enc: "A256GCM" },
    });
    if (!encryption) throw new Error("response encryption metadata was not accepted");
    await expectCredentialError(
      encryptCredentialResponse(config, { jwk, enc: "A256GCM" }, {}),
      "Expected kid to be defined on the JWK",
    );
    mockState.externalPublicJwk = encryption.jwk;
    mockState.encryptMode = "missingHeader";
    await expectCredentialError(
      encryptCredentialResponse(config, encryption, {}),
      "JWE protected header must contain alg and enc",
    );

    mockState.encryptMode = "unexpectedSerialization";
    await expectCredentialError(
      encryptCredentialResponse(config, encryption, {}),
      "Credo KMS produced an unexpected JWE serialization",
    );
    mockState.encryptMode = "unsupportedDependency";
    await expectCredentialError(
      encryptCredentialResponse(config, encryption, {}),
      "Unsupported Credo credential encryption dependency",
    );
  });
  it("rejects issuer encryption material without a kid", async () => {
    const privateJwk = JSON.parse(
      readFileSync(issuerEncryptionPrivateJwkPath(config.data_dir), "utf8"),
    ) as JsonRecord;
    privateJwk.kid = undefined;
    const noKidConfig = configWithPrivateJwk(privateJwk);
    await expectCredentialError(
      encryptCredentialResponse(noKidConfig, { jwk: {}, enc: "A256GCM" }, {}),
      "Issuer encryption key is missing a kid",
    );
  });
});
