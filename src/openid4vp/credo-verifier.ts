import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import {
  Agent,
  ClaimFormat,
  ConsoleLogger,
  DidDocument,
  DidsModule,
  JsonEncoder,
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
import { type JWK, calculateJwkThumbprint, decodeJwt } from "jose";
import {
  VERIFIER_DID_KEY_ID,
  VERIFIER_KEY_ID,
  verifierCertificatePath,
  verifierDid,
  verifierDidDocument,
  verifierDidPrivateJwkPath,
  verifierPrivateJwkPath,
} from "../config.js";
import { InMemoryStorageModule, NodeKmsBackend, nodeAgentDependencies } from "../credo/agent.js";
import { corruptJwsSignature } from "../fcaf/request-behavior.js";
import { applyRequestMutationEdits } from "../fcaf/request-mutation.js";
import { asRecord } from "../shared/json.js";
import type {
  AppConfig,
  JsonRecord,
  OpenId4VpResponseMode,
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
  dcApiPresentationUrl,
  deliveredAuthorizationRequest,
  isDcApiResponseMode,
  isEncryptedResponseMode,
  isOpenId4VpResponseMode,
  signPresentationAuthorizationRequest,
  verifierCertificateBase64Der,
  verifierClientIdentifiers,
  verifierOrigin,
  vpRequestUri,
} from "./authorization-request.js";
import { x509HashClientId } from "./request-certificates.js";
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
  /** Exact UTF-8 plaintext of an encrypted Authorization Response, before JSON/JWT decoding. */
  authorization_response_raw?: string;
  decoded_presentations?: DecodedPresentations;
  errors: string[];
}

type DecodedPresentation = {
  format: string;
  document_types?: string[];
  issuer_claims?: unknown;
  device_claims?: unknown;
  claims?: unknown;
  key_binding?: JsonRecord;
  /** SD-JWT VC `_sd_alg`, defaulted to sha-256 when the issuer omitted it. */
  digest_algorithm?: string;
  decoded?: unknown;
  warning?: string;
};

type DecodedPresentations = Record<string, DecodedPresentation[]>;

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
    const {
      dcql_query: generatedDcqlQuery,
      state: generatedState,
      ...createdAuthorizationRequest
    } = created.verificationSession.requestPayload as JsonRecord;
    // Section 5.1 makes `state` optional outside the Section 5.3 conditions. It is dropped from
    // the request the verifier holds, not only from the delivered copy, so Credo stops expecting
    // it back; the Section 5.3 consequence is enforced when the response is verified.
    const omitState = request.state === null;
    // Section 5.1 lets a request carry a `scope` representing a DCQL Query instead of the query
    // itself. The query is dropped from the delivered copy only: the verifier keeps it, because
    // Credo matches the Authorization Response against the request object this service signs, and
    // a scope value is resolved by the wallet's profile rather than by anything sent on the wire.
    const omitDcqlFromDelivery = request.dcql_query === null;
    const authorizationRequest: JsonRecord = {
      ...createdAuthorizationRequest,
      ...(omitState || generatedState === undefined ? {} : { state: generatedState }),
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
    const requestUri = dcApi ? undefined : vpRequestUri(this.config, sessionId);
    const responseUri =
      typeof authorizationRequest.response_uri === "string"
        ? authorizationRequest.response_uri
        : undefined;
    const signRequest = !(clientIdScheme === "redirect_uri" || unsignedDcApi);
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
    const authorizationRequestJwt = signRequest
      ? await signPresentationAuthorizationRequest(
          this.config,
          authorizationRequest,
          clientIdScheme,
          verifierAttestationJwt ? { verifierAttestationJwt } : {},
        )
      : undefined;
    // A generated certificate-chain fixture replaces the leaf the wallet sees, so the `x509_hash`
    // Client Identifier is recomputed from it: the chain becomes the only defect instead of also
    // disagreeing with the identifier. `with_trust_anchor` keeps the deployed leaf, so the
    // recomputed value is the normal one. Credo keeps the request generated above, so the
    // verifier's own expectations stay on the real certificate.
    const fixtureChainClientId =
      requestSigningMaterial?.x5c && clientIdScheme === "x509_hash"
        ? x509HashClientId(requestSigningMaterial.x5c[0])
        : undefined;
    const deliveredClientId = attestedClientId ?? fixtureChainClientId;
    const deliveredRequestRecipe: VpDeliveredRequestRecipe = {
      ...(signRequest
        ? {
            signer: {
              clientIdScheme,
              ...(verifierAttestationJwt ? { verifierAttestationJwt } : {}),
            },
          }
        : {}),
      omitDcqlQuery: omitDcqlFromDelivery,
      ...(deliveredClientId ? { clientId: deliveredClientId } : {}),
    };
    // Mutations are applied here, after every internal check: `authorizationRequest` stays the
    // message this service generated and verifies against, `deliveredRequest` is the copy the
    // wallet receives. Both are signed separately because Credo derives the nonce, state, and
    // client identifier it expects in the Authorization Response from the Request Object JWT it
    // holds — handing it the mutated one would move the verifier's own expectations with it.
    const deliveredRequest = deliveredAuthorizationRequest(
      authorizationRequest,
      deliveredRequestRecipe,
      requestMutation?.request_object,
    );
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
              ...(verifierAttestationJwt ? { verifierAttestationJwt } : {}),
            },
          )
        : authorizationRequestJwt;
    const deliveredAuthorizationRequestJwt =
      signedDeliveredRequest && requestBehavior?.signature === "corrupt"
        ? corruptJwsSignature(signedDeliveredRequest)
        : signedDeliveredRequest;
    if (authorizationRequestJwt) {
      created.verificationSession.authorizationRequestJwt = authorizationRequestJwt;
    } else if (omitState) {
      // An unsigned request leaves Credo holding its own payload, which still carries `state`.
      const stored = created.verificationSession.authorizationRequestPayload;
      if (stored && "state" in stored) {
        const { state: _state, ...withoutState } = stored;
        created.verificationSession.authorizationRequestPayload = withoutState;
      }
    }
    const multiSignedRequest =
      requestDelivery === "multisigned"
        ? await this.multiSignedRequest(deliveredRequest)
        : undefined;
    const outerRequest = applyRequestMutationEdits(
      dcApi
        ? dcApiBrowserRequest(
            deliveredRequest,
            deliveredAuthorizationRequestJwt,
            multiSignedRequest,
          ).data
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
      deliveredRequestRecipe,
      outerRequest,
      ...(dcApi
        ? {
            dcApiRequest: {
              ...dcApiBrowserRequest(
                deliveredRequest,
                deliveredAuthorizationRequestJwt,
                multiSignedRequest,
              ),
              data: outerRequest,
            },
            expectedOrigin,
          }
        : {}),
      verifierEncryptionKeyPublished,
      ...(resolvedVerifierAttestation ? { verifierAttestation: resolvedVerifierAttestation } : {}),
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
   * contain a different, verifier-built `errorResponse`.
   */
  private async walletAuthorizationResponse(
    session: VpSessionCapture,
    body: JsonRecord,
    authorizationRequestPayload: unknown,
  ): Promise<WalletAuthorizationResponse | undefined> {
    if (!isEncryptedResponseMode(session.response_mode)) {
      const response = normalizeAuthorizationResponse(body);
      return response === undefined ? undefined : { response };
    }

    const response = typeof body.response === "string" ? body.response : undefined;
    const encryptionJwk = verifierEncryptionJwk(authorizationRequestPayload);
    if (!response || !encryptionJwk) return undefined;

    try {
      const decrypt = getOid4vcDecryptJweCallback(this.agent.context);
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
   * Nested JWT (RFC 9101 Section 4, RFC 7519 Section 5.2). Credo's KMS performs the ECDH-ES key
   * agreement and content encryption with a fresh ephemeral key; its OpenID4VP verifier API has no
   * Request Object encryption, and its JWE callback omits the `cty` a Nested JWT requires, so only
   * the JOSE header and compact serialization are assembled here.
   */
  async encryptRequestObject(
    requestObject: string,
    encryption: RequestObjectEncryption,
  ): Promise<string> {
    const recipient = encryption.recipientJwk;
    const kms = this.agent.kms;
    const ephemeral = await kms.createKey({
      type: { kty: recipient.kty, crv: recipient.crv } as Kms.KmsCreateKeyType,
    });
    try {
      const { kty, crv, x, y } = ephemeral.publicJwk as JsonRecord;
      const header = JsonEncoder.toBase64Url({
        alg: encryption.alg,
        enc: encryption.enc,
        cty: "JWT",
        ...(typeof recipient.kid === "string" ? { kid: recipient.kid } : {}),
        epk: { kty, crv, x, ...(y === undefined ? {} : { y }) },
      });
      const encrypted = await kms.encrypt({
        key: {
          keyAgreement: {
            keyId: ephemeral.keyId,
            algorithm: "ECDH-ES",
            externalPublicJwk: recipient as Kms.KmsJwkPublicEcdh,
          },
        },
        data: TypedArrayEncoder.fromUtf8String(requestObject),
        encryption: {
          algorithm: encryption.enc,
          aad: TypedArrayEncoder.fromUtf8String(header),
        } as Kms.KmsEncryptDataEncryption,
      });
      if (!encrypted.iv || !encrypted.tag) throw new Error("Expected JWE iv and tag");
      return [
        header,
        "",
        TypedArrayEncoder.toBase64Url(encrypted.iv),
        TypedArrayEncoder.toBase64Url(encrypted.encrypted),
        TypedArrayEncoder.toBase64Url(encrypted.tag),
      ].join(".");
    } finally {
      await kms.deleteKey({ keyId: ephemeral.keyId });
    }
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
        keyId: signer.keyId,
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

/**
 * The outer Authorization Request: the parameters a wallet sees before it opens anything signed.
 * It is built as an object so that a mutation can address its members, and so a test can make the
 * outer value of a parameter disagree with the value inside the signed Request Object.
 */
function outerRequestParameters(
  authorizationRequest: JsonRecord,
  requestDelivery: VpRequestDelivery,
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
  multiSignedRequest?: JsonRecord,
): VpDcApiRequest {
  if (multiSignedRequest) {
    return { protocol: "openid4vp-v1-multisigned", data: { request: multiSignedRequest } };
  }
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
      // SD-JWT VC Section 4.1.1 defaults `_sd_alg` to sha-256 when the issuer omits it. The value
      // is captured because it is the digest algorithm a wallet had to support to present this
      // credential at all, and it is absent from the pretty claims.
      digest_algorithm: String(asRecord(presentationRecord?.payload)?._sd_alg ?? "sha-256"),
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
