import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import {
  Agent,
  ConsoleLogger,
  DidDocument,
  DidsModule,
  JsonEncoder,
  JweService,
  JwsService,
  Kms,
  LogLevel,
  TypedArrayEncoder,
  X509Certificate,
  X509Module,
} from "@credo-ts/core";
import type { TrustedIssuerX509 } from "@credo-ts/core";
import { OpenId4VcModule, getOid4vcDecryptJweCallback } from "@credo-ts/openid4vc";
import express from "express";
import { decodeJwt } from "jose";
import {
  verifierCertificatePath,
  verifierDidPrivateJwkPath,
  verifierPrivateJwkPath,
} from "../config/paths.js";
import {
  VERIFIER_DID_KEY_ID,
  VERIFIER_KEY_ID,
  verifierDid,
  verifierDidDocument,
} from "../config/verifier-identity.js";
import { InMemoryStorageModule, NodeKmsBackend, nodeAgentDependencies } from "../credo/agent.js";
import { asRecord } from "../shared/json.js";
import type {
  AppConfig,
  JsonRecord,
  RequestSigningMaterial,
  VpDcApiRequest,
  VpRequestBehavior,
  VpRequestDelivery,
  VpRequestMutation,
  VpSessionCapture,
  VpVerifierAttestation,
} from "../types.js";
import {
  type OpenId4VpClientIdScheme,
  type VpDeliveredRequestRecipe,
  isDcApiResponseMode,
  isEncryptedResponseMode,
  signPresentationAuthorizationRequest,
  verifierCertificateBase64Der,
  verifierClientIdentifiers,
  verifierOrigin,
  vpRequestUri,
} from "./authorization-request.js";
import {
  type DecodedPresentations,
  decodedPresentationsFromDcql,
} from "./presentation-decoding.js";
import { x509HashClientId } from "./request-certificates.js";
import {
  authorizationRequestForVerifier,
  requestEnvelope,
  responseModeFromRequest,
  signedDeliveryPlan,
} from "./request-construction.js";
import type { RequestObjectEncryption } from "./request-object-encryption.js";
import {
  createVerifierAttestation,
  resolveVerifierAttestation,
  verifierAttestationClientId,
} from "./verifier-attestation.js";

const CREDO_VERIFIER_BASE_PATH = "/openid4vp/sessions";

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
  /** How `deliveredAuthorizationRequest` was derived and signed, for a `wallet_nonce` re-sign. */
  deliveredRequestRecipe: VpDeliveredRequestRecipe;
  /** Deeplink query parameters, or the DC API `data` member, as delivered. */
  outerRequest: JsonRecord;
  /** Present for DC API sessions: the payload for `navigator.credentials.get()`. */
  dcApiRequest?: VpDcApiRequest;
  /** Present for DC API sessions: the origin the response is bound to. */
  expectedOrigin?: string;
  /** Whether the wallet-facing `client_metadata` still advertises the verifier's encryption key. */
  verifierEncryptionKeyPublished: boolean;
  /** The attestation content as signed, `{{response_uri}}` resolved; absent if none was supplied. */
  verifierAttestation?: VpVerifierAttestation;
}

export interface CredoVpVerification {
  valid: boolean;
  vp_token_format_valid: boolean;
  nonce_verified: boolean;
  holder_binding_verified: boolean;
  dcql_query_matched: boolean;
  /** Null when the request sent no transaction data, or the format's binding is not checked. */
  transaction_data_verified: boolean | null;
  authorization_response?: JsonRecord;
  /** Exact UTF-8 plaintext of an encrypted Authorization Response, before JSON/JWT decoding. */
  authorization_response_raw?: string;
  decoded_presentations?: DecodedPresentations;
  errors: string[];
}

type WalletAuthorizationResponse = {
  response: JsonRecord;
  raw?: string;
};

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

function optionalSessionFields(
  requestUri: string | undefined,
  responseUri: string | undefined,
  dcApi: boolean,
  expectedOrigin: string,
  dcApiRequest: VpDcApiRequest | undefined,
  verifierAttestation: VpVerifierAttestation | undefined,
): Partial<CredoVpSession> {
  return {
    ...(requestUri === undefined ? {} : { requestUri }),
    ...(responseUri === undefined ? {} : { responseUri }),
    ...(dcApi ? { dcApiRequest, expectedOrigin } : {}),
    ...(verifierAttestation ? { verifierAttestation } : {}),
  };
}

function adjustStoredAuthorizationRequest(
  verificationSession: {
    authorizationRequestJwt?: string;
    authorizationRequestPayload?: JsonRecord;
  },
  authorizationRequestJwt: string | undefined,
  state: unknown,
): void {
  if (authorizationRequestJwt) {
    verificationSession.authorizationRequestJwt = authorizationRequestJwt;
  } else if (state === null) {
    // An unsigned request leaves Credo holding its own payload, which still carries `state`.
    const stored = verificationSession.authorizationRequestPayload;
    if (stored && "state" in stored) {
      const { state: _state, ...withoutState } = stored;
      verificationSession.authorizationRequestPayload = withoutState;
    }
  }
}

function fixtureChainClientId(
  requestSigningMaterial: RequestSigningMaterial | undefined,
  clientIdScheme: OpenId4VpClientIdScheme,
): string | undefined {
  // A generated certificate-chain fixture replaces the leaf the wallet sees, so the `x509_hash`
  // Client Identifier is recomputed from it: the chain becomes the only defect instead of also
  // disagreeing with the identifier. `with_trust_anchor` keeps the deployed leaf, so the
  // recomputed value is the normal one. Credo keeps the request generated above, so the
  // verifier's own expectations stay on the real certificate.
  return requestSigningMaterial?.x5c && clientIdScheme === "x509_hash"
    ? x509HashClientId(requestSigningMaterial.x5c[0])
    : undefined;
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
          defaultBackend: kms.backend,
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
    requestDelivery: VpRequestDelivery,
    deeplinkScheme: string,
    clientMetadata: JsonRecord | null | undefined,
    clientIdScheme: OpenId4VpClientIdScheme,
    allowUndecryptableResponse = false,
    requestMutation?: VpRequestMutation,
    requestBehavior?: VpRequestBehavior,
    requestSigningMaterial?: RequestSigningMaterial,
    verifierAttestation?: VpVerifierAttestation,
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
    const shaped = await authorizationRequestForVerifier(
      created.verificationSession.requestPayload as JsonRecord,
      request,
      responseMode,
      dcApi,
      clientMetadata,
      allowUndecryptableResponse,
    );
    const { authorizationRequest, verifierEncryptionKeyPublished, omitDcqlFromDelivery } = shaped;
    const requestUri = dcApi ? undefined : vpRequestUri(this.config, sessionId);
    const responseUri =
      typeof authorizationRequest.response_uri === "string"
        ? authorizationRequest.response_uri
        : undefined;
    const signer: Exclude<OpenId4VpClientIdScheme, "redirect_uri"> | undefined =
      clientIdScheme === "redirect_uri" || unsignedDcApi ? undefined : clientIdScheme;
    // Credo has no signer for Section 5.10, so the attestation request is built here: the Client
    // Identifier names the attested subject and the attestation itself rides in the JOSE header.
    const resolvedVerifierAttestation = resolveVerifierAttestation(
      verifierAttestation,
      responseUri,
    );
    const verifierAttestationJwt =
      clientIdScheme === "verifier_attestation"
        ? await createVerifierAttestation(this.config, resolvedVerifierAttestation)
        : undefined;
    const attestedClientId = verifierAttestationJwt
      ? verifierAttestationClientId(this.config)
      : undefined;
    if (attestedClientId) authorizationRequest.client_id = attestedClientId;
    const authorizationRequestJwt = signer
      ? await signPresentationAuthorizationRequest(
          this.config,
          authorizationRequest,
          signer,
          verifierAttestationJwt ? { verifierAttestationJwt } : {},
        )
      : undefined;
    const fixtureClientId = fixtureChainClientId(requestSigningMaterial, clientIdScheme);
    const deliveredClientId = attestedClientId ?? fixtureClientId;
    const signed = await signedDeliveryPlan(
      this.config,
      authorizationRequest,
      authorizationRequestJwt,
      signer,
      verifierAttestationJwt,
      deliveredClientId,
      requestMutation,
      requestBehavior,
      requestSigningMaterial,
      omitDcqlFromDelivery,
    );
    adjustStoredAuthorizationRequest(
      created.verificationSession,
      authorizationRequestJwt,
      request.state,
    );
    const multiSignedRequest =
      requestDelivery === "multisigned"
        ? await this.multiSignedRequest(signed.deliveredAuthorizationRequest)
        : undefined;
    const envelope = requestEnvelope(
      this.config,
      sessionId,
      signed.deliveredAuthorizationRequest,
      signed.deliveredAuthorizationRequestJwt,
      requestDelivery,
      requestUri,
      requestUriMethod,
      deeplinkScheme,
      dcApi,
      requestMutation,
      multiSignedRequest,
    );
    return {
      sessionId,
      authorizationRequest,
      authorizationRequestJwt,
      verificationSessionId: created.verificationSession.id,
      deeplink: envelope.deeplink,
      deliveredAuthorizationRequest: signed.deliveredAuthorizationRequest,
      deliveredAuthorizationRequestJwt: signed.deliveredAuthorizationRequestJwt,
      deliveredRequestRecipe: signed.deliveredRequestRecipe,
      outerRequest: envelope.outerRequest,
      verifierEncryptionKeyPublished,
      ...optionalSessionFields(
        requestUri,
        responseUri,
        dcApi,
        expectedOrigin,
        envelope.dcApiRequest,
        resolvedVerifierAttestation,
      ),
    };
  }

  /**
   * Verifies an Authorization Response. A request that omitted `state` while asking for a
   * Presentation without Holder Binding outside the DC API cannot meet Section 5.3, so its
   * response is rejected whatever Credo concluded; Credo's own checks are kept as evidence.
   */
  async verifyResponse(
    session: VpSessionCapture,
    body: JsonRecord,
    verificationSessionId: string,
  ): Promise<CredoVpVerification> {
    const verification = await this.credoVerification(session, body, verificationSessionId);
    if (!unboundPresentationRequestedWithoutState(session)) return verification;
    return {
      ...verification,
      valid: false,
      errors: [
        ...verification.errors,
        "OpenID4VP Section 5.3 requires state when a Presentation without Holder Binding is requested, and the Authorization Request omitted it",
      ],
    };
  }

  /**
   * DC API responses are bound to the browser origin rather than to the Client Identifier, so the
   * session's trusted origin is handed to Credo, which derives the expected `origin:<origin>`
   * presentation audience from it.
   */
  private async credoVerification(
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
      const walletAuthorizationResponse = await this.walletAuthorizationResponse(
        session,
        body,
        session.authorization_request,
        verified.verificationSession.responseEncryptionKey,
      );
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
        authorization_response_raw: walletAuthorizationResponse?.raw,
        decoded_presentations: verified.dcql
          ? decodedPresentationsFromDcql(verified.dcql.presentations)
          : undefined,
        errors: [],
      };
    } catch (error) {
      const verificationSession =
        await this.verifierApi().getVerificationSessionById(verificationSessionId);
      const walletAuthorizationResponse = await this.walletAuthorizationResponse(
        session,
        body,
        verificationSession.requestPayload,
        verificationSession.responseEncryptionKey,
      );
      const authorizationResponse = walletAuthorizationResponse?.response;
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
        authorization_response: authorizationResponse,
        authorization_response_raw: walletAuthorizationResponse?.raw,
        errors: [message],
      };
    }
  }

  /**
   * Captures the Authorization Response from the Wallet, independently of Credo's verification
   * result. Credo retains this payload only after success, while verifier-side failure errors can
   * contain a different, verifier-built `errorResponse`. Credo publishes the response encryption
   * key under its thumbprint, so the published `kid` is mapped to the session's KMS key.
   */
  private async walletAuthorizationResponse(
    session: VpSessionCapture,
    body: JsonRecord,
    authorizationRequestPayload: unknown,
    responseEncryptionKey: Kms.KmsKeyReference | undefined,
  ): Promise<WalletAuthorizationResponse | undefined> {
    if (!isEncryptedResponseMode(session.response_mode)) {
      const response = normalizeAuthorizationResponse(body);
      return response === undefined ? undefined : { response };
    }

    const response = typeof body.response === "string" ? body.response : undefined;
    const encryptionJwk = verifierEncryptionJwk(authorizationRequestPayload);
    if (!response || !encryptionJwk || typeof encryptionJwk.kid !== "string") return undefined;

    try {
      const decrypt = getOid4vcDecryptJweCallback(
        this.agent.context,
        responseEncryptionKey ? { [encryptionJwk.kid]: responseEncryptionKey } : {},
      );
      const decrypted = (await decrypt(response, {
        jwk: encryptionJwk as never,
      })) as { decrypted: boolean; payload?: string };
      if (!decrypted.decrypted || typeof decrypted.payload !== "string") return undefined;
      const authorizationResponse = walletAuthorizationResponsePayload(decrypted.payload);
      const normalizedResponse = normalizeAuthorizationResponse(authorizationResponse);
      return normalizedResponse === undefined
        ? undefined
        : {
            response: normalizedResponse,
            raw: decrypted.payload,
          };
    } catch {
      return undefined;
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

  /**
   * Why `chain` does not validate up to its last certificate as the trust anchor, or `undefined`
   * when it does. Credo's X.509 chain validation checks each signature, the validity periods, the
   * basic constraints, and the key usages. The anchor may be an intermediate, as a Wallet may be
   * configured with one.
   */
  async certificateChainError(chain: string[]): Promise<string | undefined> {
    const trustAnchor = chain.at(-1);
    if (!trustAnchor) return "the certificate chain is empty";
    try {
      await this.agent.x509.validateCertificateChain({
        certificateChain: chain,
        trustedCertificates: [trustAnchor],
        allowNonRootTrustedCertificate: true,
      });
      return undefined;
    } catch (error) {
      return credoErrorMessage(error);
    }
  }

  /**
   * Encrypts a signed Request Object to the Wallet key negotiated from its `wallet_metadata`, as a
   * Nested JWT (RFC 9101 Section 4, RFC 7519 Section 5.2). Credo's OpenID4VP verifier API has no
   * Request Object encryption, so Credo's JWE service is called directly; its KMS performs the
   * ECDH-ES key agreement with a fresh ephemeral key, and the `cty` a Nested JWT requires is added
   * to the protected header.
   */
  async encryptRequestObject(
    requestObject: string,
    encryption: RequestObjectEncryption,
  ): Promise<string> {
    const recipient = encryption.recipientJwk;
    return await this.agent.dependencyManager
      .resolve(JweService)
      .encryptJweCompact(this.agent.context, {
        keyAgreement: {
          algorithm: encryption.alg,
          recipient: { publicJwk: Kms.PublicJwk.fromUnknown(recipient) },
        },
        enc: encryption.enc,
        protectedHeaderOptions: {
          cty: "JWT",
          ...(typeof recipient.kid === "string" ? { kid: recipient.kid } : {}),
        },
        data: TypedArrayEncoder.fromUtf8String(requestObject),
      });
  }

  /**
   * Appendix A.3.2.2: one payload signed under both Client Identifiers this service holds keys
   * for. `client_id` and `verifier_info` travel only in each signature's protected header, so they
   * are removed from the shared payload. Credo's JWS service signs each entry with the key already
   * imported for that identifier.
   */
  private async multiSignedRequest(request: JsonRecord): Promise<JsonRecord> {
    await this.importDidSigningKey(true);
    const { client_id: _clientId, verifier_info: _verifierInfo, ...claims } = request;
    const payload = TypedArrayEncoder.fromUtf8String(JSON.stringify(claims));
    const clientIds = verifierClientIdentifiers(this.config);
    const did = verifierDid(this.config);
    const signers = [
      {
        keyId: VERIFIER_KEY_ID,
        header: {
          x5c: [verifierCertificateBase64Der(this.config)],
          client_id: clientIds.x509_hash,
        },
      },
      {
        keyId: VERIFIER_DID_KEY_ID,
        header: {
          kid: `${did}#${VERIFIER_DID_KEY_ID}`,
          client_id: clientIds.decentralized_identifier,
        },
      },
    ];
    const jwsService = new JwsService();
    const signatures: JsonRecord[] = [];
    let encodedPayload = "";
    for (const signer of signers) {
      const jws = await jwsService.createJws(this.agent.context, {
        payload,
        key: { keyId: signer.keyId },
        header: {},
        protectedHeaderOptions: { alg: "ES256", typ: "oauth-authz-req+jwt", ...signer.header },
      });
      encodedPayload = jws.payload;
      signatures.push({ protected: jws.protected, signature: jws.signature });
    }
    return { payload: encodedPayload, signatures };
  }

  /**
   * The signer Credo creates its own copy of the request with. Credo has no Section 5.10 signer
   * and treats every `x5c` prefix other than `x509_hash` as `x509_san_dns`, which requires a
   * `dNSName` SAN matching the response URI: a deployed certificate with only a URI SAN fails
   * there. A `verifier_attestation` request is therefore created under `x509_hash`; its Client
   * Identifier is replaced and the request re-signed with the attestation header before anything
   * is stored or delivered, so the prefix used here never reaches the wallet.
   */
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
      clientIdPrefix: clientIdScheme === "verifier_attestation" ? "x509_hash" : clientIdScheme,
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

function verifierEncryptionJwk(authorizationRequestPayload: unknown): JsonRecord | undefined {
  const clientMetadata = asRecord(asRecord(authorizationRequestPayload)?.client_metadata);
  const keys = asRecord(clientMetadata?.jwks)?.keys;
  if (!Array.isArray(keys)) return undefined;
  return keys.map(asRecord).find((key) => key?.use === "enc") ?? undefined;
}

function walletAuthorizationResponsePayload(payload: string): JsonRecord | undefined {
  try {
    const response =
      payload.split(".").length === 3 ? (decodeJwt(payload) as unknown) : JSON.parse(payload);
    return asRecord(response) ?? undefined;
  } catch {
    return undefined;
  }
}
function readCertificate(dataDir: string): string {
  return readFileSync(verifierCertificatePath(dataDir), "utf8");
}

function credoErrorMessage(error: unknown, fallback?: string): string {
  if (error instanceof Error) return error.message;
  return fallback ?? String(error);
}

/** @internal */
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

/**
 * Section 5.3 conditions for a mandatory `state`: at least one Credential is requested without
 * cryptographic Holder Binding and the request does not travel over the DC API. The verifier's
 * own request is consulted, not the delivered copy, because that is what it verifies against.
 */
function unboundPresentationRequestedWithoutState(session: VpSessionCapture): boolean {
  const request = session.authorization_request;
  if (request.state !== undefined || isDcApiResponseMode(session.response_mode)) return false;
  const credentials = asRecord(request.dcql_query)?.credentials;
  return (
    Array.isArray(credentials) &&
    credentials.some(
      (credential) => asRecord(credential)?.require_cryptographic_holder_binding === false,
    )
  );
}
