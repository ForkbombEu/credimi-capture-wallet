import {
  type JsonWebKey as NodeJsonWebKey,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signData,
  verify as verifyData,
} from "node:crypto";
import { EventEmitter as NodeEventEmitter } from "node:events";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  type AgentContext,
  type AgentDependencies,
  type BaseRecord,
  type BaseRecordConstructor,
  type DependencyManager,
  type FileSystem,
  InjectionSymbols,
  type Kms,
  type Module,
  type Query,
  type QueryOptions,
  RecordDuplicateError,
  RecordNotFoundError,
  type StorageService,
} from "@credo-ts/core";
import { type JWK, compactDecrypt, exportJWK, generateKeyPair, importJWK } from "jose";
import type { AppConfig, JsonRecord } from "../types.js";
import { ecdhEsEncrypt, isEcdhEsContentEncryption } from "./kms-encryption.js";

const CREDO_KMS_BACKEND = "fake-issuer-node";

export class InMemoryStorageModule implements Module {
  constructor(
    private readonly queryAliases: Readonly<Record<string, Readonly<Record<string, string>>>> = {},
  ) {}

  register(dependencyManager: DependencyManager): void {
    dependencyManager.registerInstance(
      InjectionSymbols.StorageService,
      new InMemoryStorage(this.queryAliases) as StorageService<BaseRecord>,
    );
  }
}

class InMemoryStorage<T extends BaseRecord = BaseRecord> implements StorageService<T> {
  readonly supportsCursorPagination = false;
  private readonly records = new Map<string, T>();

  constructor(
    private readonly queryAliases: Readonly<Record<string, Readonly<Record<string, string>>>>,
  ) {}

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
    const normalizedQuery = Object.fromEntries(
      Object.entries(query as JsonRecord).map(([key, value]) => [
        key,
        typeof value === "string" ? (this.queryAliases[key]?.[value] ?? value) : value,
      ]),
    );
    return records.filter((record) => recordMatchesQuery(record, normalizedQuery));
  }

  private key(type: string, id: string): string {
    return `${type}:${id}`;
  }
}

function recordMatchesQuery(record: BaseRecord, query: JsonRecord): boolean {
  const tags = record.getTags();
  return Object.entries(query).every(([key, value]) => {
    if (value === undefined) return true;
    if (key === "$or") {
      return Array.isArray(value) && value.some((entry) => recordMatchesQuery(record, entry));
    }
    const tagValue = tags[key];
    return Array.isArray(value) ? value.includes(tagValue) : tagValue === value;
  });
}

export class NodeKmsBackend implements Kms.KeyManagementService {
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
    // An ephemeral ECDH-ES key must share the recipient's curve.
    const crv =
      algorithm === "ECDH-ES" && "crv" in options.type && typeof options.type.crv === "string"
        ? options.type.crv
        : undefined;
    const { publicKey, privateKey } = await generateKeyPair(algorithm, {
      extractable: true,
      ...(crv ? { crv } : {}),
    });
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

  /**
   * ECDH-ES direct key agreement with the ephemeral key `keyAgreement.keyId`, which is what
   * Credo's JWE encryption asks a backend for. Key wrapping is not implemented.
   */
  async encrypt(
    _agentContext: AgentContext,
    options: Kms.KmsEncryptOptions,
  ): Promise<Kms.KmsEncryptReturn> {
    const keyAgreement = "keyAgreement" in options.key ? options.key.keyAgreement : undefined;
    if (keyAgreement?.algorithm !== "ECDH-ES") {
      throw new Error("Only ECDH-ES key agreement encryption is supported");
    }
    const encryption = options.encryption;
    if (!isEcdhEsContentEncryption(encryption.algorithm)) {
      throw new Error(`Content encryption '${encryption.algorithm}' is not supported`);
    }
    return ecdhEsEncrypt({
      privateJwk: this.requiredKey(keyAgreement.keyId) as NodeJsonWebKey,
      recipientPublicJwk: keyAgreement.externalPublicJwk as NodeJsonWebKey,
      enc: encryption.algorithm,
      data: options.data,
      aad: ("aad" in encryption ? encryption.aad : undefined) ?? new Uint8Array(),
      apu: keyAgreement.apu,
      apv: keyAgreement.apv,
      iv: "iv" in encryption ? encryption.iv : undefined,
    });
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

export function nodeAgentDependencies(config: AppConfig): AgentDependencies {
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
