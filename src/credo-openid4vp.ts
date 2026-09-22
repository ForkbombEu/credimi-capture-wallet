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
  ClaimFormat,
  ConsoleLogger,
  type DependencyManager,
  DidDocument,
  DidsModule,
  type FileSystem,
  InjectionSymbols,
  JsonEncoder,
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
import type { TrustedIssuerX509 } from "@credo-ts/core";
import { OpenId4VcModule } from "@credo-ts/openid4vc";
import express from "express";
import {
  type JWK,
  calculateJwkThumbprint,
  compactDecrypt,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import {
  VERIFIER_DID_KEY_ID,
  VERIFIER_KEY_ID,
  verifierCertificatePath,
  verifierDid,
  verifierDidDocument,
  verifierDidPrivateJwkPath,
  verifierPrivateJwkPath,
} from "./config.js";
import {
  type OpenId4VpClientIdScheme,
  dcApiPresentationUrl,
  isDcApiResponseMode,
  isEncryptedResponseMode,
  isOpenId4VpResponseMode,
  signPresentationAuthorizationRequest,
  verifierOrigin,
} from "./openid4vp.js";
import { corruptJwsSignature } from "./request-behavior.js";
import { x509HashClientId } from "./request-certificates.js";
import { applyRequestMutationEdits } from "./request-mutation.js";
import type {
  AppConfig,
  JsonRecord,
  OpenId4VpResponseMode,
  RequestSigningMaterial,
  VpDcApiRequest,
  VpRequestBehavior,
  VpRequestMutation,
  VpSessionCapture,
} from "./types.js";

const CREDO_VERIFIER_BASE_PATH = "/openid4vp/sessions";
const CREDO_KMS_BACKEND = "fake-issuer-node";

export interface CredoVpSession {
  sessionId: string;
  authorizationRequest: JsonRecord;
  authorizationRequestJwt?: string;
  verificationSessionId: string;
  /** Absent for DC API sessions: the request is not fetched and the response is not posted. */
  requestUri?: string;
  responseUri?: string;
  deeplink: string;
  /** The Request Object payload actually signed and delivered; differs under a mutation. */
  deliveredAuthorizationRequest: JsonRecord;
  /** The signed Request Object actually served to the wallet; differs under a mutation. */
  deliveredAuthorizationRequestJwt?: string;
  /** Deeplink query parameters, or the DC API `data` member, as delivered. */
  outerRequest: JsonRecord;
  /** Present for DC API sessions: the payload for `navigator.credentials.get()`. */
  dcApiRequest?: VpDcApiRequest;
  /** Present for DC API sessions: the origin the response is bound to. */
  expectedOrigin?: string;
  /** Whether the wallet-facing `client_metadata` still advertises the verifier's encryption key. */
  verifierEncryptionKeyPublished: boolean;
}

export class ResponseModeError extends Error {}

export class ClientMetadataError extends Error {}

export interface CredoVpVerification {
  valid: boolean;
  vp_token_format_valid: boolean;
  nonce_verified: boolean;
  holder_binding_verified: boolean;
  dcql_query_matched: boolean;
  /** Null when the request sent no transaction data, or the format's binding is not checked. */
  transaction_data_verified: boolean | null;
  authorization_response?: JsonRecord;
  decoded_presentations?: DecodedPresentations;
  errors: string[];
}

export type DecodedPresentation = {
  format: string;
  document_types?: string[];
  issuer_claims?: unknown;
  device_claims?: unknown;
  claims?: unknown;
  key_binding?: JsonRecord;
  decoded?: unknown;
  warning?: string;
};

export type DecodedPresentations = Record<string, DecodedPresentation[]>;

const verifierPromises = new Map<string, Promise<CredoOpenId4VpVerifier>>();

export async function credoOpenId4VpVerifier(config: AppConfig): Promise<CredoOpenId4VpVerifier> {
  const key = `${config.issuer_base_url}|${config.public_base_url}|${config.data_dir}`;
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
        getTrustedIssuersForVerification: async (_agentContext, context) => {
          if (context.signer.method !== "x509") return undefined;
          return {
            trustedIssuers: [
              trustedIssuerForX509Credential(
                config,
                context.signer.certificateChain.map((certificate) =>
                  certificate.toString("base64"),
                ),
              ),
            ],
          };
        },
        logger: new ConsoleLogger(LogLevel.Error),
      },
      dependencies: nodeAgentDependencies(config),
      modules: {
        storage: new InMemoryStorageModule(),
        dids: new DidsModule(),
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
    await verifier.importDidSigningKey();
    return verifier;
  }

  async createSession(
    sessionId: string,
    request: JsonRecord,
    verifierDcqlQuery: JsonRecord,
    requestUriMethod: string,
    requestDelivery: "by_reference" | "by_value" | "plain",
    deeplinkScheme: string,
    clientMetadata: JsonRecord | null | undefined,
    clientIdScheme: OpenId4VpClientIdScheme,
    allowUndecryptableResponse = false,
    requestMutation?: VpRequestMutation,
    requestBehavior?: VpRequestBehavior,
    requestSigningMaterial?: RequestSigningMaterial,
  ): Promise<CredoVpSession> {
    await this.ensureVerifier(sessionId);
    if (clientIdScheme === "decentralized_identifier") await this.importDidSigningKey(true);
    const responseMode = responseModeFromRequest(request);
    const dcApi = isDcApiResponseMode(responseMode);
    const unsignedDcApi = dcApi && requestDelivery === "plain";
    const expectedOrigin = verifierOrigin(this.config);
    const createAuthorizationRequest = (dcqlQuery: JsonRecord) =>
      this.verifierApi().createAuthorizationRequest({
        verifierId: sessionId,
        requestSigner: unsignedDcApi ? { method: "none" } : this.requestSigner(clientIdScheme),
        responseMode,
        version: "v1",
        dcql: { query: dcqlQuery as never },
        ...(dcApi && !unsignedDcApi ? { expectedOrigins: [expectedOrigin] } : {}),
      });
    const dcqlQuery = asRecord(request.dcql_query);
    const created = await (dcqlQuery
      ? createAuthorizationRequest(dcqlQuery).catch(() =>
          createAuthorizationRequest(verifierDcqlQuery),
        )
      : createAuthorizationRequest(verifierDcqlQuery));
    const { dcql_query: generatedDcqlQuery, ...createdAuthorizationRequest } = created
      .verificationSession.requestPayload as JsonRecord;
    // Section 5.1 lets a request carry a `scope` representing a DCQL Query instead of the query
    // itself. The query is dropped from the delivered copy only: the verifier keeps it, because
    // Credo matches the Authorization Response against the request object this service signs, and
    // a scope value is resolved by the wallet's profile rather than by anything sent on the wire.
    const omitDcqlFromDelivery = request.dcql_query === null;
    const authorizationRequest: JsonRecord = {
      ...createdAuthorizationRequest,
      dcql_query: omitDcqlFromDelivery ? generatedDcqlQuery : request.dcql_query,
      ...(request.nonce !== undefined ? { nonce: request.nonce } : {}),
      ...optionalAuthorizationRequestParameters(request),
    };
    // The request object Credo produces carries the JAR audience `https://self-issued.me/v2`,
    // which Section 5.8 defines for discovery-based delivery. Appendix A.2 does not list `aud`
    // among the parameters supported over the DC API, so it is dropped there rather than sent as
    // an undefined claim to a HAIP-strict wallet.
    if (dcApi) authorizationRequest.aud = undefined;
    const generatedClientMetadata = authorizationRequest.client_metadata;
    if (clientMetadata === null) {
      authorizationRequest.client_metadata = undefined;
    } else if (clientMetadata) {
      authorizationRequest.client_metadata = mergeClientMetadata(
        asRecord(generatedClientMetadata),
        clientMetadata,
      );
    }
    const verifierEncryptionKeyPublished = await containsVerifierEncryptionKey(
      asRecord(authorizationRequest.client_metadata),
      generatedClientMetadata,
    );
    if (
      isEncryptedResponseMode(responseMode) &&
      !allowUndecryptableResponse &&
      !verifierEncryptionKeyPublished
    ) {
      throw new ClientMetadataError(
        `client_metadata must retain the verifier encryption public key for ${responseMode}`,
      );
    }
    const requestUri = dcApi
      ? undefined
      : `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
    const responseUri =
      typeof authorizationRequest.response_uri === "string"
        ? authorizationRequest.response_uri
        : undefined;
    // Mutations are applied here, after every internal check: `authorizationRequest` stays the
    // message this service generated and verifies against, `deliveredRequest` is the copy the
    // wallet receives. Both are signed separately because Credo derives the nonce, state, and
    // client identifier it expects in the Authorization Response from the Request Object JWT it
    // holds — handing it the mutated one would move the verifier's own expectations with it.
    const deliveredRequest = applyRequestMutationEdits(
      authorizationRequest,
      requestMutation?.request_object,
    );
    if (omitDcqlFromDelivery) deliveredRequest.dcql_query = undefined;
    const signRequest = !(clientIdScheme === "redirect_uri" || unsignedDcApi);
    const authorizationRequestJwt = signRequest
      ? await signPresentationAuthorizationRequest(
          this.config,
          authorizationRequest,
          clientIdScheme,
        )
      : undefined;
    // A certificate-chain fixture replaces the leaf the wallet sees, so the `x509_hash` Client
    // Identifier is recomputed from it: the chain becomes the only defect instead of also
    // disagreeing with the identifier. Credo keeps the request generated above, so the verifier's
    // own expectations stay on the real certificate.
    if (requestSigningMaterial?.x5c && clientIdScheme === "x509_hash") {
      deliveredRequest.client_id = x509HashClientId(requestSigningMaterial.x5c[0]);
    }
    const mutatesRequestObject = Boolean(
      requestMutation?.request_object ?? requestMutation?.request_object_header,
    );
    const signedDeliveredRequest =
      signRequest && (mutatesRequestObject || requestSigningMaterial || omitDcqlFromDelivery)
        ? await signPresentationAuthorizationRequest(
            this.config,
            deliveredRequest,
            clientIdScheme,
            {
              ...(requestMutation?.request_object_header
                ? { headerEdits: requestMutation.request_object_header }
                : {}),
              ...(requestSigningMaterial ? { material: requestSigningMaterial } : {}),
            },
          )
        : authorizationRequestJwt;
    const deliveredAuthorizationRequestJwt =
      signedDeliveredRequest && requestBehavior?.signature === "corrupt"
        ? corruptJwsSignature(signedDeliveredRequest)
        : signedDeliveredRequest;
    if (authorizationRequestJwt)
      created.verificationSession.authorizationRequestJwt = authorizationRequestJwt;
    const outerRequest = applyRequestMutationEdits(
      dcApi
        ? dcApiBrowserRequest(deliveredRequest, deliveredAuthorizationRequestJwt).data
        : outerRequestParameters(
            deliveredRequest,
            requestDelivery,
            requestUri ?? "",
            requestUriMethod,
            deliveredAuthorizationRequestJwt,
          ),
      requestMutation?.outer_request,
    );
    const deeplink = dcApi
      ? dcApiPresentationUrl(this.config, sessionId)
      : `${deeplinkScheme}?${outerRequestQuery(outerRequest)}`;

    return {
      sessionId,
      authorizationRequest,
      authorizationRequestJwt,
      verificationSessionId: created.verificationSession.id,
      ...(requestUri === undefined ? {} : { requestUri }),
      ...(responseUri === undefined ? {} : { responseUri }),
      deeplink,
      deliveredAuthorizationRequest: deliveredRequest,
      deliveredAuthorizationRequestJwt,
      outerRequest,
      ...(dcApi
        ? {
            dcApiRequest: {
              ...dcApiBrowserRequest(deliveredRequest, deliveredAuthorizationRequestJwt),
              data: outerRequest,
            },
            expectedOrigin,
          }
        : {}),
      verifierEncryptionKeyPublished,
    };
  }

  /**
   * Verifies an Authorization Response. DC API responses are bound to the browser origin rather
   * than to the Client Identifier, so the session's trusted origin is handed to Credo, which
   * derives the expected `origin:<origin>` presentation audience from it.
   */
  async verifyResponse(
    session: VpSessionCapture,
    body: JsonRecord,
    verificationSessionId: string,
  ): Promise<CredoVpVerification> {
    const origin = session.dc_api?.expected_origin;
    try {
      const verified = await this.verifierApi().verifyAuthorizationResponse({
        verificationSessionId,
        authorizationResponse: body,
        ...(origin === undefined ? {} : { origin }),
      });
      return {
        valid: true,
        vp_token_format_valid: true,
        nonce_verified: true,
        holder_binding_verified: true,
        dcql_query_matched: Boolean(verified.dcql),
        // Credo verifies the request object this service signed, transaction data included, so a
        // successful verification is also a successful Section 8.4 binding check.
        transaction_data_verified:
          session.authorization_request.transaction_data === undefined ? null : true,
        authorization_response: normalizeAuthorizationResponse(
          verified.verificationSession.authorizationResponsePayload as JsonRecord | undefined,
        ),
        decoded_presentations: verified.dcql
          ? decodedPresentationsFromDcql(verified.dcql.presentations)
          : undefined,
        errors: [],
      };
    } catch (error) {
      const verificationSession =
        await this.verifierApi().getVerificationSessionById(verificationSessionId);
      const authorizationResponse = verificationSession.authorizationResponsePayload as
        | JsonRecord
        | undefined;
      const message = credoErrorMessage(error, verificationSession.errorMessage);
      return {
        valid: false,
        vp_token_format_valid: authorizationResponse?.vp_token !== undefined,
        nonce_verified: false,
        holder_binding_verified: false,
        dcql_query_matched: false,
        // A failure naming invalid_transaction_data is Credo rejecting the Section 8.4 binding;
        // any other failure says nothing about the binding, so the check stays unanswered.
        transaction_data_verified: message.includes("invalid_transaction_data") ? false : null,
        authorization_response: normalizeAuthorizationResponse(authorizationResponse),
        errors: [message],
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

  private async importDidSigningKey(overwrite = false): Promise<void> {
    const privateJwk = JSON.parse(
      await readFile(verifierDidPrivateJwkPath(this.config.data_dir), "utf8"),
    ) as JsonRecord;
    privateJwk.kid = VERIFIER_DID_KEY_ID;
    await this.agent.kms.importKey({ privateJwk: privateJwk as never });
    const did = verifierDid(this.config);
    await this.agent.dids.import({
      did,
      didDocument: DidDocument.fromJSON(verifierDidDocument(this.config)),
      keys: [
        { kmsKeyId: VERIFIER_DID_KEY_ID, didDocumentRelativeKeyId: `#${VERIFIER_DID_KEY_ID}` },
      ],
      overwrite,
    });
  }

  private requestSigner(clientIdScheme: OpenId4VpClientIdScheme) {
    if (clientIdScheme === "redirect_uri") return { method: "none" as const };
    if (clientIdScheme === "decentralized_identifier") {
      return {
        method: "did" as const,
        didUrl: `${verifierDid(this.config)}#${VERIFIER_DID_KEY_ID}`,
      };
    }
    return {
      method: "x5c" as const,
      clientIdPrefix: clientIdScheme,
      x5c: [this.verifierCertificate()],
    };
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

function normalizeAuthorizationResponse(response: JsonRecord | undefined): JsonRecord | undefined {
  if (!response || typeof response.vp_token !== "string") return response;
  try {
    const vpToken = JSON.parse(response.vp_token) as unknown;
    if (!vpToken || typeof vpToken !== "object" || Array.isArray(vpToken)) return response;
    return { ...response, vp_token: vpToken as JsonRecord };
  } catch {
    return response;
  }
}

/**
 * The outer Authorization Request: the parameters a wallet sees before it opens anything signed.
 * It is built as an object so that a mutation can address its members, and so a test can make the
 * outer value of a parameter disagree with the value inside the signed Request Object.
 */
function outerRequestParameters(
  authorizationRequest: JsonRecord,
  requestDelivery: "by_reference" | "by_value" | "plain",
  requestUri: string,
  requestUriMethod: string,
  authorizationRequestJwt: string | undefined,
): JsonRecord {
  if (requestDelivery === "by_reference") {
    return {
      client_id: String(authorizationRequest.client_id),
      request_uri: requestUri,
      ...(requestUriMethod === "get" ? {} : { request_uri_method: requestUriMethod }),
    };
  }
  if (requestDelivery === "by_value") {
    return {
      client_id: String(authorizationRequest.client_id),
      request: authorizationRequestJwt ?? "",
    };
  }
  const parameters: JsonRecord = {};
  for (const [name, value] of Object.entries(authorizationRequest)) {
    if (name === "aud" || value === undefined) continue;
    parameters[name] = value;
  }
  return parameters;
}

function outerRequestQuery(parameters: JsonRecord): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(parameters)) {
    if (value === undefined) continue;
    query.set(name, typeof value === "string" ? value : JSON.stringify(value));
  }
  return query.toString();
}

/**
 * Caller-supplied `client_metadata` overrides individual members of the generated verifier
 * metadata: an omitted member keeps its generated value and a member set to `null` is dropped
 * from the wallet-facing request. The merge is one level deep, so supplying `jwks` replaces the
 * whole key set rather than editing individual JWK members.
 */
function mergeClientMetadata(generated: JsonRecord | null, overrides: JsonRecord): JsonRecord {
  const merged: JsonRecord = { ...generated };
  for (const [member, value] of Object.entries(overrides)) {
    if (value === null) delete merged[member];
    else merged[member] = value;
  }
  return merged;
}

/**
 * The wallet-facing `client_metadata` must still publish the verifier's own encryption public key,
 * because the service decrypts a `direct_post.jwt` response with the matching private key. Keys
 * are compared by RFC 7638 thumbprint, which covers the public key material only, so optional
 * JOSE members such as `alg`, `use`, and `kid` may be altered or omitted to build the malformed
 * requests that wallet response-encryption negative tests require.
 */
async function containsVerifierEncryptionKey(
  clientMetadata: JsonRecord | null,
  generatedClientMetadata: unknown,
): Promise<boolean> {
  const generatedKeys = asRecord(generatedClientMetadata)?.jwks;
  const clientKeys = asRecord(clientMetadata?.jwks)?.keys;
  const [generated, client] = await Promise.all([
    jwkThumbprints(asRecord(generatedKeys)?.keys),
    jwkThumbprints(clientKeys),
  ]);
  return client.some((thumbprint) => generated.includes(thumbprint));
}

async function jwkThumbprints(keys: unknown): Promise<string[]> {
  if (!Array.isArray(keys)) return [];
  const thumbprints = await Promise.all(keys.map(jwkThumbprintOrNull));
  return thumbprints.filter((thumbprint): thumbprint is string => thumbprint !== null);
}

async function jwkThumbprintOrNull(key: unknown): Promise<string | null> {
  const jwk = asRecord(key);
  if (!jwk) return null;
  return calculateJwkThumbprint(jwk as unknown as JWK, "sha256").catch(() => null);
}

function readCertificate(dataDir: string): string {
  return readFileSync(verifierCertificatePath(dataDir), "utf8");
}

/**
 * An omitted `response_mode` keeps the historical `direct_post.jwt` default. An unrecognised value
 * is rejected rather than collapsed into that default, so a mode the verifier cannot honour never
 * reaches the wallet as a different one.
 */
function responseModeFromRequest(request: JsonRecord): OpenId4VpResponseMode {
  if (request.response_mode === undefined) return "direct_post.jwt";
  if (!isOpenId4VpResponseMode(request.response_mode)) {
    throw new ResponseModeError(
      `unsupported OpenID4VP response_mode '${String(request.response_mode)}'`,
    );
  }
  return request.response_mode;
}

/**
 * Appendix A.3: a signed request travels as a `request` JWS member, an unsigned one as the
 * Authorization Request parameters themselves. `client_id` and `expected_origins` are dropped from
 * the unsigned form, which Appendix A.2 requires a wallet to ignore there.
 */
function dcApiBrowserRequest(
  authorizationRequest: JsonRecord,
  authorizationRequestJwt: string | undefined,
): VpDcApiRequest {
  if (authorizationRequestJwt) {
    return { protocol: "openid4vp-v1-signed", data: { request: authorizationRequestJwt } };
  }
  const data: JsonRecord = {};
  for (const [name, value] of Object.entries(authorizationRequest)) {
    if (value === undefined || name === "client_id" || name === "expected_origins") continue;
    data[name] = value;
  }
  return { protocol: "openid4vp-v1-unsigned", data };
}

function optionalAuthorizationRequestParameters(request: JsonRecord): JsonRecord {
  const parameters: JsonRecord = {};
  if (request.response_type !== undefined) parameters.response_type = request.response_type;
  const scope = authorizationRequestScope(request);
  if (scope !== undefined) parameters.scope = scope;
  if (request.transaction_data !== undefined) {
    parameters.transaction_data = encodedTransactionData(request.transaction_data);
  }
  if (request.verifier_info !== undefined) parameters.verifier_info = request.verifier_info;
  return parameters;
}

/**
 * Section 5.1 carries each transaction data entry as a base64url-encoded JSON string. An entry
 * supplied as an object is encoded here so that a caller can express the defect a test is about —
 * an unknown field, a wrong field type, a mismatched `credential_ids` — inside an entry a Wallet
 * can still decode. Any other entry, a string included, is delivered exactly as supplied, which
 * keeps a deliberately undecodable entry expressible; `request_mutation` can replace the whole
 * parameter when even the array has to be malformed.
 */
function encodedTransactionData(transactionData: unknown): unknown {
  if (!Array.isArray(transactionData)) return transactionData;
  return transactionData.map((entry) =>
    entry !== null && typeof entry === "object" && !Array.isArray(entry)
      ? JsonEncoder.toBase64Url(entry)
      : entry,
  );
}

function authorizationRequestScope(request: JsonRecord): unknown {
  if (request.scope !== undefined) return request.scope;
  if (!Array.isArray(request.scopes)) return request.scopes;
  return request.scopes.map(String).join(" ");
}

function credoErrorMessage(error: unknown, fallback?: string): string {
  if (error instanceof Error) return error.message;
  return fallback ?? String(error);
}

function decodedPresentationsFromDcql(presentations: unknown): DecodedPresentations {
  if (!presentations || typeof presentations !== "object" || Array.isArray(presentations)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(presentations as Record<string, unknown>).map(([queryId, entries]) => [
      queryId,
      Array.isArray(entries) ? entries.map(decodedPresentationFromCredo) : [],
    ]),
  );
}

function decodedPresentationFromCredo(presentation: unknown): DecodedPresentation {
  const presentationRecord = asRecord(presentation);
  const format = String(presentationRecord?.claimFormat ?? "unknown");

  if (format === ClaimFormat.MsoMdoc) {
    const issuerClaims = asRecord(presentationRecord?.issuerClaims) ?? {};
    const deviceClaims = asRecord(presentationRecord?.deviceClaims) ?? {};
    return {
      format,
      document_types: Object.keys(issuerClaims),
      issuer_claims: toJsonSafe(issuerClaims),
      device_claims: toJsonSafe(deviceClaims),
    };
  }

  if (format === ClaimFormat.SdJwtDc) {
    const decoded: DecodedPresentation = {
      format,
      claims: toJsonSafe(presentationRecord?.prettyClaims),
    };
    const keyBinding = asRecord(presentationRecord?.kbJwt);
    const keyBindingPayload = asRecord(keyBinding?.payload);
    if (keyBindingPayload) {
      decoded.key_binding = { payload: toJsonSafe(keyBindingPayload) };
    }
    return decoded;
  }

  if (presentationRecord && "prettyClaims" in presentationRecord) {
    return { format, claims: toJsonSafe(presentationRecord.prettyClaims) };
  }

  if (presentationRecord && "resolvedPresentation" in presentationRecord) {
    return { format, decoded: toJsonSafe(presentationRecord.resolvedPresentation) };
  }

  if (presentationRecord && "payload" in presentationRecord) {
    return { format, decoded: toJsonSafe(presentationRecord.payload) };
  }

  return {
    format,
    decoded: null,
    warning: "No supported decoded representation is available",
  };
}

export function toJsonSafe(value: unknown): unknown {
  return toJsonSafeValue(value, new WeakSet<object>());
}

export function trustedIssuerForX509Credential(
  config: AppConfig,
  credentialCertificateChain: string[],
): TrustedIssuerX509 {
  return {
    method: "x509",
    issuance: credentialCertificateChain,
    ...(config.status_list_trusted_certificates.length > 0
      ? { status: config.status_list_trusted_certificates }
      : {}),
  };
}

function toJsonSafeValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "number") return value;
  if (typeof value === "boolean") return value;
  if (typeof value === "undefined") return null;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "symbol") return String(value);
  if (typeof value === "function") return null;

  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return { $type: "bytes", base64url: Buffer.from(value).toString("base64url") };
  }

  if (value instanceof Date) return value.toISOString();

  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (value instanceof Map) {
    const normalized = Object.fromEntries(
      [...value.entries()].map(([key, entry]) => [String(key), toJsonSafeValue(entry, seen)]),
    );
    seen.delete(value);
    return normalized;
  }

  if (value instanceof Set) {
    const normalized = [...value.values()].map((entry) => toJsonSafeValue(entry, seen));
    seen.delete(value);
    return normalized;
  }

  const valueRecord = value as Record<string, unknown>;
  if (typeof valueRecord.toJSON === "function") {
    const normalized = toJsonSafeValue(valueRecord.toJSON(), seen);
    seen.delete(value);
    return normalized;
  }

  if (Array.isArray(value)) {
    const normalized = value.map((entry) => toJsonSafeValue(entry, seen));
    seen.delete(value);
    return normalized;
  }

  const normalized = Object.fromEntries(
    Object.entries(valueRecord).map(([key, entry]) => [key, toJsonSafeValue(entry, seen)]),
  );
  seen.delete(value);
  return normalized;
}

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
    throw new Error("KMS encryption is not supported by this backend");
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
