import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signData,
  verify as verifyData,
} from "node:crypto";
import { EventEmitter as NodeEventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  Agent,
  type AgentContext,
  type AgentDependencies,
  type BaseRecord,
  type BaseRecordConstructor,
  ConsoleLogger,
  type DependencyManager,
  type FileSystem,
  InjectionSymbols,
  Kms,
  LogLevel,
  type Module,
  type Query,
  type QueryOptions,
  RecordDuplicateError,
  RecordNotFoundError,
  type StorageService,
  X509Certificate,
  X509Module,
} from "@credo-ts/core";
import { OpenId4VcModule } from "@credo-ts/openid4vc";
import express from "express";
import { type JWK, compactDecrypt, exportJWK, generateKeyPair, importJWK } from "jose";
import { VERIFIER_KEY_ID, verifierCertificatePath, verifierPrivateJwkPath } from "./config.js";
import type { AppConfig, JsonRecord, VpSessionCapture } from "./types.js";

const CREDO_VERIFIER_BASE_PATH = "/openid4vp/sessions";
const CREDO_KMS_BACKEND = "fake-issuer-node";

export interface CredoVpSession {
  sessionId: string;
  authorizationRequest: JsonRecord;
  authorizationRequestJwt: string;
  verificationSessionId: string;
  requestUri: string;
  responseUri: string;
  deeplink: string;
}

export interface CredoVpVerification {
  valid: boolean;
  vp_token_format_valid: boolean;
  nonce_verified: boolean;
  holder_binding_verified: boolean;
  dcql_query_matched: boolean;
  authorization_response?: JsonRecord;
  errors: string[];
}

const verifierPromises = new Map<string, Promise<CredoOpenId4VpVerifier>>();

export async function credoOpenId4VpVerifier(config: AppConfig): Promise<CredoOpenId4VpVerifier> {
  const key = `${config.issuer_base_url}|${config.data_dir}`;
  let verifierPromise = verifierPromises.get(key);
  if (!verifierPromise) {
    verifierPromise = CredoOpenId4VpVerifier.create(config);
    verifierPromises.set(key, verifierPromise);
  }
  return verifierPromise;
}

export class CredoOpenId4VpVerifier {
  private readonly verifierIds = new Set<string>();

  private constructor(
    private readonly config: AppConfig,
    private readonly agent: Agent,
  ) {}

  static async create(config: AppConfig): Promise<CredoOpenId4VpVerifier> {
    const kms = new NodeKmsBackend();
    const app = express();
    const agent = new Agent({
      config: {
        allowInsecureHttpUrls: true,
        autoUpdateStorageOnStartup: false,
        logger: new ConsoleLogger(LogLevel.Error),
      },
      dependencies: nodeAgentDependencies(config),
      modules: {
        storage: new InMemoryStorageModule(),
        kms: new Kms.KeyManagementModule({
          backends: [kms],
          defaultBackend: CREDO_KMS_BACKEND,
        }),
        x509: new X509Module({
          getTrustedCertificatesForVerification: (_agentContext, verificationContext) =>
            verificationContext.certificateChain.map((certificate) => certificate.toString("pem")),
        }),
        openid4vc: new OpenId4VcModule({
          verifier: {
            app,
            baseUrl: `${config.issuer_base_url}${CREDO_VERIFIER_BASE_PATH}`,
            endpoints: {
              authorization: "/response",
              authorizationRequest: "/request",
            },
          },
        }),
      },
    });

    const verifier = new CredoOpenId4VpVerifier(config, agent);
    await verifier.importRequestSigningKey();
    return verifier;
  }

  async createSession(
    sessionId: string,
    request: JsonRecord,
    requestUriMethod: "get" | "post",
  ): Promise<CredoVpSession> {
    await this.ensureVerifier(sessionId);
    const responseMode = responseModeFromRequest(request);
    const dcqlQuery = asRecord(request.dcql_query);
    if (!dcqlQuery) throw new Error("dcql_query is required");

    const created = await this.verifierApi().createAuthorizationRequest({
      verifierId: sessionId,
      requestSigner: {
        method: "x5c",
        clientIdPrefix: "x509_hash",
        x5c: [this.verifierCertificate()],
      },
      responseMode,
      version: "v1",
      dcql: { query: dcqlQuery as never },
    });
    const authorizationRequest = created.verificationSession.requestPayload as JsonRecord;
    const requestUri = `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
    const responseUri = String(authorizationRequest.response_uri);
    const deeplink = presentationRequestByReferenceDeeplink(
      authorizationRequest,
      requestUri,
      requestUriMethod,
    );

    return {
      sessionId,
      authorizationRequest,
      authorizationRequestJwt: created.verificationSession.authorizationRequestJwt ?? "",
      verificationSessionId: created.verificationSession.id,
      requestUri,
      responseUri,
      deeplink,
    };
  }

  async verifyResponse(
    _session: VpSessionCapture,
    body: JsonRecord,
    verificationSessionId: string,
  ): Promise<CredoVpVerification> {
    try {
      const verified = await this.verifierApi().verifyAuthorizationResponse({
        verificationSessionId,
        authorizationResponse: body,
      });
      return {
        valid: true,
        vp_token_format_valid: true,
        nonce_verified: true,
        holder_binding_verified: true,
        dcql_query_matched: Boolean(verified.dcql),
        authorization_response: verified.verificationSession.authorizationResponsePayload as
          | JsonRecord
          | undefined,
        errors: [],
      };
    } catch (error) {
      const verificationSession =
        await this.verifierApi().getVerificationSessionById(verificationSessionId);
      const authorizationResponse = verificationSession.authorizationResponsePayload as
        | JsonRecord
        | undefined;
      return {
        valid: false,
        vp_token_format_valid: authorizationResponse?.vp_token !== undefined,
        nonce_verified: false,
        holder_binding_verified: false,
        dcql_query_matched: false,
        authorization_response: authorizationResponse,
        errors: [credoErrorMessage(error, verificationSession.errorMessage)],
      };
    }
  }

  private async ensureVerifier(verifierId: string): Promise<void> {
    if (this.verifierIds.has(verifierId)) return;
    try {
      await this.verifierApi().getVerifierByVerifierId(verifierId);
    } catch {
      await this.verifierApi().createVerifier({ verifierId });
    }
    this.verifierIds.add(verifierId);
  }

  private async importRequestSigningKey(): Promise<void> {
    const privateJwk = JSON.parse(
      await readFile(verifierPrivateJwkPath(this.config.data_dir), "utf8"),
    ) as JsonRecord;
    privateJwk.kid = VERIFIER_KEY_ID;
    await this.agent.kms.importKey({ privateJwk: privateJwk as never });
  }

  private verifierApi() {
    const verifier = this.agent.openid4vc?.verifier;
    if (!verifier) throw new Error("Credo OpenID4VC verifier API is not available");
    return verifier;
  }

  private verifierCertificate(): X509Certificate {
    const certificate = X509Certificate.fromEncodedCertificate(
      readCertificate(this.config.data_dir),
    );
    certificate.keyId = VERIFIER_KEY_ID;
    return certificate;
  }
}

function presentationRequestByReferenceDeeplink(
  authorizationRequest: JsonRecord,
  requestUri: string,
  requestUriMethod: "get" | "post",
): string {
  const params = new URLSearchParams({
    client_id: String(authorizationRequest.client_id),
    request_uri: requestUri,
  });
  if (requestUriMethod === "post") params.set("request_uri_method", "post");
  return `openid4vp://?${params.toString()}`;
}

function readCertificate(dataDir: string): string {
  return readFileSync(verifierCertificatePath(dataDir), "utf8");
}

function responseModeFromRequest(request: JsonRecord): "direct_post" | "direct_post.jwt" {
  return request.response_mode === "direct_post" ? "direct_post" : "direct_post.jwt";
}

function credoErrorMessage(error: unknown, fallback?: string): string {
  if (error instanceof Error) return error.message;
  return fallback ?? String(error);
}

class InMemoryStorageModule implements Module {
  register(dependencyManager: DependencyManager): void {
    dependencyManager.registerInstance(
      InjectionSymbols.StorageService,
      new InMemoryStorage() as StorageService<BaseRecord>,
    );
  }
}

class InMemoryStorage<T extends BaseRecord = BaseRecord> implements StorageService<T> {
  readonly supportsCursorPagination = false;
  private readonly records = new Map<string, T>();

  async save(_agentContext: AgentContext, record: T): Promise<void> {
    const key = this.key(record.type, record.id);
    if (this.records.has(key)) {
      throw new RecordDuplicateError(`Record ${record.type} ${record.id} already exists`, {
        recordType: record.type,
      });
    }
    this.records.set(key, record);
  }

  async update(_agentContext: AgentContext, record: T): Promise<void> {
    const key = this.key(record.type, record.id);
    if (!this.records.has(key)) {
      throw new RecordNotFoundError(`Record ${record.type} ${record.id} not found`, {
        recordType: record.type,
      });
    }
    this.records.set(key, record);
  }

  async delete(_agentContext: AgentContext, record: T): Promise<void> {
    await this.deleteById(_agentContext, record.constructor as BaseRecordConstructor<T>, record.id);
  }

  async deleteById(
    _agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string,
  ): Promise<void> {
    const key = this.key(recordClass.type, id);
    if (!this.records.delete(key)) {
      throw new RecordNotFoundError(`Record ${recordClass.type} ${id} not found`, {
        recordType: recordClass.type,
      });
    }
  }

  async getById(
    _agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string,
  ): Promise<T> {
    const record = this.records.get(this.key(recordClass.type, id));
    if (!record) {
      throw new RecordNotFoundError(`Record ${recordClass.type} ${id} not found`, {
        recordType: recordClass.type,
      });
    }
    return record;
  }

  async getAll(_agentContext: AgentContext, recordClass: BaseRecordConstructor<T>): Promise<T[]> {
    return [...this.records.values()].filter((record) => record.type === recordClass.type);
  }

  async findByQuery(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    query: Query<T>,
    _queryOptions?: QueryOptions,
  ): Promise<T[]> {
    const records = await this.getAll(agentContext, recordClass);
    return records.filter((record) => recordMatchesQuery(record, query as JsonRecord));
  }

  private key(type: string, id: string): string {
    return `${type}:${id}`;
  }
}

function recordMatchesQuery(record: BaseRecord, query: JsonRecord): boolean {
  const tags = record.getTags();
  return Object.entries(query).every(([key, value]) => {
    if (key === "$or") {
      return Array.isArray(value) && value.some((entry) => recordMatchesQuery(record, entry));
    }
    const tagValue = tags[key];
    return Array.isArray(value) ? value.includes(tagValue) : tagValue === value;
  });
}

class NodeKmsBackend implements Kms.KeyManagementService {
  readonly backend = CREDO_KMS_BACKEND;
  private readonly keys = new Map<string, JWK>();

  isOperationSupported(): boolean {
    return true;
  }

  async getPublicKey(_agentContext: AgentContext, keyId: string): Promise<Kms.KmsJwkPublic | null> {
    const privateJwk = this.keys.get(keyId);
    if (!privateJwk) return null;
    return publicJwk(privateJwk) as Kms.KmsJwkPublic;
  }

  async createKey<Type extends Kms.KmsCreateKeyType>(
    _agentContext: AgentContext,
    options: Kms.KmsCreateKeyOptions<Type>,
  ): Promise<Kms.KmsCreateKeyReturn<Type>> {
    const algorithm = keyPairAlgorithm(options.type);
    const { publicKey, privateKey } = await generateKeyPair(algorithm, { extractable: true });
    const privateJwk = (await exportJWK(privateKey)) as JWK;
    const exportedPublicJwk = (await exportJWK(publicKey)) as JWK;
    const keyId = cryptoRandomId();
    privateJwk.kid = keyId;
    exportedPublicJwk.kid = keyId;
    this.keys.set(keyId, privateJwk);
    return { keyId, publicJwk: exportedPublicJwk } as Kms.KmsCreateKeyReturn<Type>;
  }

  async importKey<Jwk extends Kms.KmsJwkPrivate>(
    _agentContext: AgentContext,
    options: Kms.KmsImportKeyOptions<Jwk>,
  ): Promise<Kms.KmsImportKeyReturn<Jwk>> {
    const keyId = options.privateJwk.kid ?? cryptoRandomId();
    const privateJwk = { ...(options.privateJwk as JWK), kid: keyId };
    this.keys.set(keyId, privateJwk);
    return { keyId, publicJwk: publicJwk(privateJwk) } as Kms.KmsImportKeyReturn<Jwk>;
  }

  async deleteKey(_agentContext: AgentContext, options: Kms.KmsDeleteKeyOptions): Promise<boolean> {
    return this.keys.delete(options.keyId);
  }

  async sign(_agentContext: AgentContext, options: Kms.KmsSignOptions): Promise<Kms.KmsSignReturn> {
    const privateJwk = this.requiredKey(options.keyId);
    return {
      signature: signData(signatureHash(options.algorithm), options.data, {
        key: createPrivateKey({ key: privateJwk as unknown as JsonRecord, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      }),
    };
  }

  async verify(
    _agentContext: AgentContext,
    options: Kms.KmsVerifyOptions,
  ): Promise<Kms.KmsVerifyReturn> {
    const jwk =
      typeof options.key === "string"
        ? publicJwk(this.requiredKey(options.key))
        : options.key.publicJwk;
    if (!jwk) return { verified: false };
    const verified = verifyData(
      signatureHash(options.algorithm),
      options.data,
      {
        key: createPublicKey({ key: jwk as unknown as JsonRecord, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      options.signature,
    );
    return verified ? { verified: true, publicJwk: jwk as Kms.KmsJwkPublic } : { verified: false };
  }

  async encrypt(): Promise<Kms.KmsEncryptReturn> {
    throw new Error("KMS encryption is not used by the verifier");
  }

  async decrypt(
    _agentContext: AgentContext,
    options: Kms.KmsDecryptOptions,
  ): Promise<Kms.KmsDecryptReturn> {
    const keyAgreement = "keyAgreement" in options.key ? options.key.keyAgreement : undefined;
    if (!keyAgreement) {
      throw new Error("Only key agreement JWE decryption is supported");
    }
    const decryption = options.decryption as {
      aad: Uint8Array;
      iv: Uint8Array;
      tag: Uint8Array;
    };
    const privateJwk = this.requiredKey(keyAgreement.keyId);
    const compact = [
      Buffer.from(decryption.aad).toString("utf8"),
      "",
      Buffer.from(decryption.iv).toString("base64url"),
      Buffer.from(options.encrypted).toString("base64url"),
      Buffer.from(decryption.tag).toString("base64url"),
    ].join(".");
    const { plaintext } = await compactDecrypt(compact, await importJWK(privateJwk, "ECDH-ES"));
    return { data: plaintext };
  }

  randomBytes(_agentContext: AgentContext, options: Kms.KmsRandomBytesOptions): Uint8Array {
    return randomBytes(options.length);
  }

  private requiredKey(keyId: string): JWK {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`KMS key '${keyId}' not found`);
    return key;
  }
}

function keyPairAlgorithm(type: Kms.KmsCreateKeyType): "ECDH-ES" | "ES256" | "EdDSA" {
  if (typeof type === "object" && "crv" in type && type.crv === "Ed25519") return "EdDSA";
  if (typeof type === "object" && "use" in type && type.use === "sig") return "ES256";
  return "ECDH-ES";
}

function publicJwk(privateJwk: JWK): JWK & { kid: string } {
  const {
    d: _d,
    p: _p,
    q: _q,
    dp: _dp,
    dq: _dq,
    qi: _qi,
    oth: _oth,
    ...publicKey
  } = privateJwk as unknown as JsonRecord;
  if (!publicKey.kid) publicKey.kid = cryptoRandomId();
  return publicKey as unknown as JWK & { kid: string };
}

function signatureHash(algorithm: string): string | null {
  return algorithm === "EdDSA" || algorithm === "Ed25519" ? null : "sha256";
}

function cryptoRandomId(): string {
  return randomBytes(16).toString("base64url");
}

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : null;
}

function nodeAgentDependencies(config: AppConfig): AgentDependencies {
  return {
    FileSystem: class NodeFileSystem implements FileSystem {
      readonly dataPath = config.data_dir;
      readonly cachePath = join(config.data_dir, "credo-cache");
      readonly tempPath = join(config.data_dir, "credo-tmp");

      async exists(path: string): Promise<boolean> {
        try {
          await readFile(path);
          return true;
        } catch {
          return false;
        }
      }

      async createDirectory(path: string): Promise<void> {
        await mkdir(path, { recursive: true });
      }

      async copyFile(sourcePath: string, destinationPath: string): Promise<void> {
        await mkdir(dirname(destinationPath), { recursive: true });
        await cp(sourcePath, destinationPath);
      }

      async write(path: string, data: string): Promise<void> {
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, data);
      }

      async read(path: string): Promise<string> {
        return readFile(path, "utf8");
      }

      async delete(path: string): Promise<void> {
        await rm(path, { force: true, recursive: true });
      }

      async downloadToFile(url: string, path: string): Promise<void> {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`Failed to download ${url}`);
        await this.write(path, await response.text());
      }
    },
    EventEmitterClass: NodeEventEmitter,
    fetch: globalThis.fetch,
    WebSocketClass: class WebSocketPlaceholder {} as unknown as AgentDependencies["WebSocketClass"],
  };
}
