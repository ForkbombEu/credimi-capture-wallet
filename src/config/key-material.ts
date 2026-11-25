import { randomBytes } from "node:crypto";
import { X509Certificate as NodeX509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  CredoWebCrypto,
  Kms,
  SdJwtVcModuleConfig,
  X509Certificate,
  X509KeyUsage,
} from "@credo-ts/core";
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
import {
  allResolvedIssuerConfigurations,
  resolvedIssuerConfigurations,
} from "../configurations/registry.js";
import { issuerAppConfig } from "../configurations/resolve-urls.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { AppConfig, JsonRecord } from "../types.js";
import { DEFAULT_CONFIG, type InitOptions, normalizeBaseUrl } from "./defaults.js";
import { loadConfig, stringifyYaml } from "./load.js";
import {
  accessTokenPrivateJwkPath,
  configPath,
  issuerCertificatePath,
  issuerEncryptionPrivateJwkPath,
  issuerFederationJwksPath,
  issuerFederationPrivateJwkPath,
  jwksPath,
  privateJwkPath,
  verifierAttestationIssuerPrivateJwkPath,
  verifierCertificatePath,
  verifierDidPrivateJwkPath,
  verifierJwksPath,
  verifierPrivateJwkPath,
} from "./paths.js";
import {
  VERIFIER_ATTESTATION_ISSUER_KEY_ID,
  VERIFIER_DID_KEY_ID,
  VERIFIER_KEY_ID,
} from "./verifier-identity.js";

export async function initIssuer(options: InitOptions): Promise<AppConfig> {
  const dataDir = options.data_dir ?? DEFAULT_CONFIG.data_dir;
  const force = options.force === true;
  const config: AppConfig = {
    ...DEFAULT_CONFIG,
    issuer_base_url: normalizeBaseUrl(options.issuer_base_url ?? DEFAULT_CONFIG.issuer_base_url),
    public_base_url: normalizeBaseUrl(
      options.public_base_url ?? options.issuer_base_url ?? DEFAULT_CONFIG.issuer_base_url,
      "public_base_url",
    ),
    data_dir: dataDir,
    credential_configuration_id:
      options.credential_configuration_id ?? DEFAULT_CONFIG.credential_configuration_id,
    credential_scope: options.credential_configuration_id ?? DEFAULT_CONFIG.credential_scope,
  };

  mkdirSync(dataDir, { recursive: true });
  const cfgPath = configPath(dataDir);

  if (force || !existsSync(cfgPath)) {
    const { attestbook: _environmentOnly, federation: _federation, ...persisted } = config;
    writeFileSync(cfgPath, stringifyYaml(persisted as unknown as JsonRecord), { mode: 0o600 });
  }

  const loadedConfig = loadConfig(dataDir);
  // Material is generated for every issuer, including the opt-in experimental one, so enabling a
  // feature flag later never requires another `init`. Only enabled issuers are served.
  for (const issuer of allResolvedIssuerConfigurations(loadedConfig)) {
    await ensureIssuerMaterial(loadedConfig, issuer, force);
  }
  const verifierSecretPath = verifierPrivateJwkPath(dataDir);
  const verifierPublicPath = verifierJwksPath(dataDir);
  const verifierCertPath = verifierCertificatePath(dataDir);
  mkdirSync(dirname(verifierSecretPath), { recursive: true });
  await ensureVerifierMaterial({
    config: loadedConfig,
    force,
    secretPath: verifierSecretPath,
    publicPath: verifierPublicPath,
    certificatePath: verifierCertPath,
  });
  const verifierDidSecretPath = verifierDidPrivateJwkPath(dataDir);
  if (force || !existsSync(verifierDidSecretPath)) {
    await writeGeneratedPrivateJwk(verifierDidSecretPath, VERIFIER_DID_KEY_ID);
  }
  const attestationIssuerSecretPath = verifierAttestationIssuerPrivateJwkPath(dataDir);
  if (force || !existsSync(attestationIssuerSecretPath)) {
    await writeGeneratedPrivateJwk(attestationIssuerSecretPath, VERIFIER_ATTESTATION_ISSUER_KEY_ID);
  }
  validateIssuerMaterial(loadedConfig);

  return loadedConfig;
}

export function validateIssuerMaterial(config: AppConfig): void {
  const publicKeyOwners = new Map<string, string>();

  for (const issuer of resolvedIssuerConfigurations(config)) {
    const material = issuerAppConfig(config, issuer);
    const paths = {
      signing: privateJwkPath(issuer.materialDirectory),
      encryption: issuerEncryptionPrivateJwkPath(issuer.materialDirectory),
      accessToken: accessTokenPrivateJwkPath(issuer.materialDirectory),
      certificate: issuerCertificatePath(issuer.materialDirectory),
      jwks: jwksPath(issuer.materialDirectory),
      ...(config.federation.enabled
        ? {
            federation: issuerFederationPrivateJwkPath(issuer.materialDirectory),
            federationJwks: issuerFederationJwksPath(issuer.materialDirectory),
          }
        : {}),
    };
    for (const [role, path] of Object.entries(paths)) {
      if (!existsSync(path)) {
        throw new Error(`Issuer '${issuer.id}' is missing ${role} material at '${path}'`);
      }
    }

    const signingPrivateJwk = readJwk(paths.signing, issuer.id, "signing");
    const encryptionPrivateJwk = readJwk(paths.encryption, issuer.id, "encryption");
    const accessTokenPrivateJwk = readJwk(paths.accessToken, issuer.id, "access-token");
    const federationPrivateJwk = config.federation.enabled
      ? readJwk(issuerFederationPrivateJwkPath(issuer.materialDirectory), issuer.id, "federation")
      : null;
    const signingKeyId = requiredJwkKeyId(signingPrivateJwk, `Issuer '${issuer.id}' signing key`);
    const certificatePem = readFileSync(paths.certificate, "utf8");
    const certificate = X509Certificate.fromEncodedCertificate(certificatePem);
    if (!Kms.PublicJwk.fromUnknown(toPublicJwk(signingPrivateJwk)).equals(certificate.publicJwk)) {
      throw new Error(`Issuer '${issuer.id}' certificate does not match its signing key`);
    }
    const nodeCertificate = new NodeX509Certificate(certificatePem);
    validateIssuerCertificateSubjectAlternativeName(
      nodeCertificate.subjectAltName,
      issuer.issuerIdentifier,
      issuer.id,
    );

    const publishedJwks = loadIssuerJwks(material);
    const signingPublicJwk = Kms.PublicJwk.fromUnknown(toPublicJwk(signingPrivateJwk));
    const publishedSigningJwk = publishedJwks.keys.find((jwk) => {
      try {
        return Kms.PublicJwk.fromUnknown(jwk).equals(signingPublicJwk);
      } catch {
        return false;
      }
    });
    if (!publishedSigningJwk) {
      throw new Error(`Issuer '${issuer.id}' JWKS does not publish its signing key`);
    }
    if (publishedSigningJwk.kid !== signingKeyId) {
      throw new Error(`Issuer '${issuer.id}' JWKS kid does not match its private signing JWK kid`);
    }

    if (federationPrivateJwk) {
      if (
        federationPrivateJwk.kty !== "EC" ||
        federationPrivateJwk.crv !== "P-256" ||
        federationPrivateJwk.alg !== "ES256" ||
        federationPrivateJwk.use !== "sig" ||
        typeof federationPrivateJwk.d !== "string"
      ) {
        throw new Error(`Issuer '${issuer.id}' federation key must be an ES256 P-256 private JWK`);
      }
      const federationKeyId = requiredJwkKeyId(
        federationPrivateJwk,
        `Issuer '${issuer.id}' federation key`,
      );
      const federationJwks = loadIssuerFederationJwks(issuer);
      if (federationJwks.keys.some((jwk) => "d" in jwk)) {
        throw new Error(
          `Issuer '${issuer.id}' federation JWKS must not contain private key material`,
        );
      }
      const federationPublicJwk = Kms.PublicJwk.fromUnknown(toPublicJwk(federationPrivateJwk));
      const publishedFederationJwk = federationJwks.keys.find((jwk) => {
        try {
          return Kms.PublicJwk.fromUnknown(jwk).equals(federationPublicJwk);
        } catch {
          return false;
        }
      });
      if (!publishedFederationJwk) {
        throw new Error(`Issuer '${issuer.id}' federation JWKS does not publish its signing key`);
      }
      if (publishedFederationJwk.kid !== federationKeyId) {
        throw new Error(
          `Issuer '${issuer.id}' federation JWKS kid does not match its private signing JWK kid`,
        );
      }
      registerUniquePublicKey(publicKeyOwners, issuer.id, "federation", federationPrivateJwk);
    }

    registerUniquePublicKey(publicKeyOwners, issuer.id, "signing", signingPrivateJwk);
    registerUniquePublicKey(publicKeyOwners, issuer.id, "encryption", encryptionPrivateJwk);
    registerUniquePublicKey(publicKeyOwners, issuer.id, "access-token", accessTokenPrivateJwk);
  }
}

/** @internal */
export function validateIssuerCertificateSubjectAlternativeName(
  subjectAlternativeName: string | undefined,
  issuerIdentifier: string,
  issuerId: string,
): void {
  const names = subjectAlternativeName?.split(", ") ?? [];
  if (!names.includes(`URI:${issuerIdentifier}`)) {
    throw new Error(`Issuer '${issuerId}' certificate is missing URI SAN '${issuerIdentifier}'`);
  }
}

function readJwk(path: string, issuerId: string, role: string): JsonRecord {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as JsonRecord;
  } catch (error) {
    throw new Error(
      `Issuer '${issuerId}' has invalid ${role} JWK material: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function registerUniquePublicKey(
  owners: Map<string, string>,
  issuerId: string,
  role: string,
  privateJwk: JsonRecord,
): void {
  const publicJwk = Kms.PublicJwk.fromUnknown(toPublicJwk(privateJwk));
  const identity = publicJwk.fingerprint;
  const owner = owners.get(identity);
  if (owner) {
    throw new Error(`Issuer key reuse detected between '${owner}' and '${issuerId}:${role}'`);
  }
  owners.set(identity, `${issuerId}:${role}`);
}

async function ensureIssuerMaterial(
  rootConfig: AppConfig,
  issuer: ResolvedIssuerConfiguration,
  force: boolean,
): Promise<void> {
  const materialDirectory = issuer.materialDirectory;
  const publicPath = jwksPath(materialDirectory);
  const secretPath = privateJwkPath(materialDirectory);
  const certificatePath = issuerCertificatePath(materialDirectory);
  const encryptionSecretPath = issuerEncryptionPrivateJwkPath(materialDirectory);
  const accessTokenSecretPath = accessTokenPrivateJwkPath(materialDirectory);
  const federationSecretPath = issuerFederationPrivateJwkPath(materialDirectory);
  const federationPublicPath = issuerFederationJwksPath(materialDirectory);

  mkdirSync(materialDirectory, { recursive: true });
  if (force || !existsSync(secretPath)) {
    await writeGeneratedJwkPair(secretPath, publicPath, issuer.issuerKeyId);
  }
  if (force || !existsSync(certificatePath)) {
    await writeIssuerCertificate(
      certificatePath,
      issuerAppConfig(rootConfig, issuer),
      issuer.issuerKeyId,
    );
  }
  writePublicJwksFromPrivate(publicPath, secretPath);
  writeIssuerJwksCertificate(publicPath, certificatePath);
  await ensureIssuerEncryptionMaterial({
    force,
    secretPath: encryptionSecretPath,
    keyId: issuer.issuerEncryptionKeyId,
  });
  if (force || !existsSync(accessTokenSecretPath)) {
    await writeGeneratedPrivateJwk(accessTokenSecretPath, issuer.accessTokenKeyId);
  }
  await ensureIssuerFederationMaterial({
    force,
    secretPath: federationSecretPath,
    publicPath: federationPublicPath,
  });
}

async function ensureIssuerFederationMaterial({
  force,
  secretPath,
  publicPath,
}: {
  force: boolean;
  secretPath: string;
  publicPath: string;
}): Promise<void> {
  if (force || !existsSync(secretPath)) {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const kid = await calculateJwkThumbprint(publicJwk);
    const common = { alg: "ES256", use: "sig", kid };
    writeJson(secretPath, { ...privateJwk, ...common });
    writeJson(publicPath, { keys: [{ ...publicJwk, ...common }] });
    return;
  }
  writePublicJwksFromPrivate(publicPath, secretPath);
}

export function loadIssuerJwks(config: AppConfig): { keys: JsonRecord[] } {
  const path = jwksPath(config.data_dir);
  if (!existsSync(path)) return { keys: [] };
  const jwks = JSON.parse(readFileSync(path, "utf8")) as { keys: JsonRecord[] };
  const certificatePath = issuerCertificatePath(config.data_dir);
  if (!existsSync(certificatePath)) return jwks;
  return withIssuerCertificate(jwks, readFileSync(certificatePath, "utf8"));
}

export function loadIssuerFederationPrivateJwk(issuer: ResolvedIssuerConfiguration): JsonRecord {
  return readJwk(issuerFederationPrivateJwkPath(issuer.materialDirectory), issuer.id, "federation");
}

export function loadIssuerFederationJwks(issuer: ResolvedIssuerConfiguration): {
  keys: JsonRecord[];
} {
  const path = issuerFederationJwksPath(issuer.materialDirectory);
  if (!existsSync(path)) return { keys: [] };
  return JSON.parse(readFileSync(path, "utf8")) as { keys: JsonRecord[] };
}

export function loadIssuerCertificate(config: AppConfig): X509Certificate {
  return X509Certificate.fromEncodedCertificate(
    readFileSync(issuerCertificatePath(config.data_dir), "utf8"),
  );
}

export function loadIssuerPublicJwk(config: AppConfig): JsonRecord {
  const privateJwk = JSON.parse(
    readFileSync(privateJwkPath(config.data_dir), "utf8"),
  ) as JsonRecord;
  return toPublicJwk(privateJwk);
}

export function issuerSigningKeyId(config: AppConfig): string {
  const privateJwk = JSON.parse(
    readFileSync(privateJwkPath(config.data_dir), "utf8"),
  ) as JsonRecord;
  return requiredJwkKeyId(privateJwk, `Issuer signing key in '${config.data_dir}'`);
}

export function loadIssuerEncryptionPrivateJwk(config: AppConfig): JsonRecord | null {
  const path = issuerEncryptionPrivateJwkPath(config.data_dir);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as JsonRecord;
}

export function loadIssuerEncryptionPublicJwk(config: AppConfig): JsonRecord | null {
  const privateJwk = loadIssuerEncryptionPrivateJwk(config);
  return privateJwk ? toPublicJwk(privateJwk) : null;
}

export function createIssuerSigningContext(config: AppConfig): object {
  const privateJwk = JSON.parse(
    readFileSync(privateJwkPath(config.data_dir), "utf8"),
  ) as JsonRecord;
  return {
    ...createSigningContext(privateJwk, issuerSigningKeyId(config)),
    config: {
      allowInsecureHttpUrls: true,
      agentDependencies: { fetch: globalThis.fetch },
    },
  };
}

async function ensureIssuerEncryptionMaterial({
  force,
  secretPath,
  keyId,
}: {
  force: boolean;
  secretPath: string;
  keyId: string;
}): Promise<void> {
  if (!force && existsSync(secretPath)) return;
  const { privateKey } = await generateKeyPair("ECDH-ES", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const common = {
    alg: "ECDH-ES",
    use: "enc",
    kid: keyId,
  };
  writeJson(secretPath, { ...privateJwk, ...common });
}

async function writeIssuerCertificate(
  path: string,
  config: AppConfig,
  keyId: string,
): Promise<void> {
  await writeCertificate({
    path,
    privateJwkPath: privateJwkPath(config.data_dir),
    keyId,
    organizationalUnit: "Credimi Fake Issuer",
    config,
  });
}

async function ensureVerifierMaterial({
  config,
  force,
  secretPath,
  publicPath,
  certificatePath,
}: {
  config: AppConfig;
  force: boolean;
  secretPath: string;
  publicPath: string;
  certificatePath: string;
}): Promise<void> {
  if (force || !existsSync(secretPath)) {
    await writeGeneratedJwkPair(secretPath, publicPath, VERIFIER_KEY_ID);
  }
  if (force || !existsSync(certificatePath)) {
    await writeCertificate({
      path: certificatePath,
      privateJwkPath: secretPath,
      keyId: VERIFIER_KEY_ID,
      organizationalUnit: "Credimi Fake Verifier",
      config,
    });
  }
  writePublicJwksFromPrivate(publicPath, secretPath, VERIFIER_KEY_ID);
  writeIssuerJwksCertificate(publicPath, certificatePath);
}

async function writeGeneratedJwkPair(
  secretPath: string,
  publicPath: string,
  keyId: string,
): Promise<void> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  publicJwk.alg = "ES256";
  publicJwk.use = "sig";
  publicJwk.kid = keyId;
  privateJwk.alg = "ES256";
  privateJwk.use = "sig";
  privateJwk.kid = keyId;
  writeJson(publicPath, { keys: [publicJwk] });
  writeJson(secretPath, privateJwk);
}

async function writeGeneratedPrivateJwk(secretPath: string, keyId: string): Promise<void> {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  writeJson(secretPath, {
    ...privateJwk,
    alg: "ES256",
    use: "sig",
    kid: keyId,
  });
}

async function writeCertificate({
  path,
  privateJwkPath: keyPath,
  keyId,
  organizationalUnit,
  config,
}: {
  path: string;
  privateJwkPath: string;
  keyId: string;
  organizationalUnit: string;
  config: AppConfig;
}): Promise<void> {
  const privateJwk = JSON.parse(readFileSync(keyPath, "utf8")) as JsonRecord;
  const publicJwk = Kms.PublicJwk.fromUnknown(toPublicJwk(privateJwk));
  publicJwk.keyId = keyId;
  const certificate = await X509Certificate.create(
    {
      authorityKey: publicJwk,
      issuer: {
        countryName: "IT",
        commonName: new URL(config.issuer_base_url).hostname,
        organizationalUnit,
      },
      validity: {
        notBefore: new Date("2024-01-01T00:00:00Z"),
        notAfter: new Date("2034-01-01T00:00:00Z"),
      },
      extensions: {
        subjectKeyIdentifier: { include: true },
        authorityKeyIdentifier: { include: true },
        keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
        subjectAlternativeName: {
          name: [
            { type: "url", value: config.issuer_base_url },
            { type: "dns", value: new URL(config.issuer_base_url).hostname },
          ],
        },
        basicConstraints: { ca: false },
      },
    },
    new CredoWebCrypto(createSigningContext(privateJwk, keyId) as never),
  );
  certificate.keyId = keyId;
  writeFileSync(path, certificate.toString("pem"), { mode: 0o600 });
}

function toPublicJwk(privateJwk: JsonRecord): JsonRecord {
  const { d: _d, ...publicJwk } = privateJwk;
  return publicJwk;
}

export function createJwkSigningContext(privateJwk: JsonRecord, keyId: string): object {
  return createSigningContext(privateJwk, keyId);
}

function createSigningContext(privateJwk: JsonRecord, keyId: string): object {
  const publicJwk = toPublicJwk(privateJwk);
  const kms = {
    // A plain Uint8Array, as the KMS contract states, not Node's Buffer subclass: @peculiar/x509
    // strips a random serial number's leading zero bytes with slice(), which on a Buffer is a view,
    // so about one certificate in 512 kept a non-minimal DER INTEGER that Node refuses to parse.
    randomBytes: ({ length }: { length: number }) => new Uint8Array(randomBytes(length)),
    getPublicKey: async ({ keyId: requestedKeyId }: { keyId: string }) => {
      if (requestedKeyId !== keyId) throw new Error(`Unknown key id '${requestedKeyId}'`);
      return publicJwk;
    },
    sign: async ({ keyId: requestedKeyId, data }: { keyId: string; data: Uint8Array }) => {
      if (requestedKeyId !== keyId) throw new Error(`Unknown key id '${requestedKeyId}'`);
      const { createPrivateKey, sign } = await import("node:crypto");
      return {
        signature: sign("sha256", data, {
          key: createPrivateKey({ key: privateJwk as never, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        }),
      };
    },
  };
  const sdJwtVcConfig = new SdJwtVcModuleConfig();
  const resolve = (token: unknown) => {
    if (token === Kms.KeyManagementApi) return kms;
    if (token === SdJwtVcModuleConfig) return sdJwtVcConfig;
    throw new Error("Unsupported Credo dependency requested while creating issuer certificate");
  };

  return { resolve, dependencyManager: { resolve } };
}

function writePublicJwksFromPrivate(
  publicPath: string,
  secretPath: string,
  keyIdOverride?: string,
): void {
  const privateJwk = JSON.parse(readFileSync(secretPath, "utf8")) as JsonRecord;
  const publicJwk = toPublicJwk(privateJwk);
  publicJwk.alg = "ES256";
  publicJwk.use = "sig";
  publicJwk.kid = keyIdOverride ?? requiredJwkKeyId(privateJwk, `Private JWK '${secretPath}'`);
  writeJson(publicPath, { keys: [publicJwk] });
}

function requiredJwkKeyId(jwk: JsonRecord, description: string): string {
  if (typeof jwk.kid !== "string" || jwk.kid.length === 0) {
    throw new Error(`${description} is missing a kid`);
  }
  return jwk.kid;
}

function writeIssuerJwksCertificate(jwksFilePath: string, certificatePath: string): void {
  const jwks = JSON.parse(readFileSync(jwksFilePath, "utf8")) as { keys: JsonRecord[] };
  writeJson(jwksFilePath, withIssuerCertificate(jwks, readFileSync(certificatePath, "utf8")));
}

function withIssuerCertificate(
  jwks: { keys: JsonRecord[] },
  certificatePem: string,
): { keys: JsonRecord[] } {
  const certificate = pemToBase64Der(certificatePem);
  return {
    keys: jwks.keys.map((key) => (key.x5c === undefined ? { ...key, x5c: [certificate] } : key)),
  };
}

function pemToBase64Der(certificatePem: string): string {
  return certificatePem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
