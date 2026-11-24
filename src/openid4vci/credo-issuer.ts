import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  Agent,
  ClaimFormat,
  ConsoleLogger,
  Kms,
  LogLevel,
  MdocApi,
  X509Module,
} from "@credo-ts/core";
import {
  type OpenId4VcIssuanceSessionRecord,
  OpenId4VcIssuanceSessionRepository,
  OpenId4VcIssuanceSessionState,
  type OpenId4VcIssuanceSessionStateChangedEvent,
  OpenId4VcIssuerEvents,
  OpenId4VcIssuerService,
  OpenId4VcModule,
  type OpenId4VciCredentialRequestToCredentialMapperOptions,
  type OpenId4VciDynamicIssuanceSessionOptions,
  type OpenId4VciGetDynamicIssuanceSessionOptions,
  type OpenId4VciSignCredentials,
} from "@credo-ts/openid4vc";
import express, { type NextFunction, type Request, type Response } from "express";
import { attestbookIntegration } from "../attestbook/integration.js";
import { accessTokenPrivateJwkPath, privateJwkPath, validateIssuerMaterial } from "../config.js";
import {
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../configurations/registry.js";
import { issuerAppConfig } from "../configurations/resolve-urls.js";
import { pidFixtureIdOrNull, pidFixtureSubject } from "../configurations/shared/pid-fixtures.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import { DEGREE_SD_JWT_VCT, NUMERIC_SD_JWT_VCT } from "../credentials/definitions.js";
import { credentialRegistry } from "../credentials/registry.js";
import {
  degreeSdJwtCredentialSignOptions,
  domesticPidMdocCredentialSignOptions,
  domesticPidSdJwtCredentialSignOptions,
  importedSdJwtCredentialSignOptions,
  mdocCredentialSignOptions,
  numericSdJwtCredentialSignOptions,
  sdJwtCredentialSignOptions,
} from "../credentials/signing.js";
import { InMemoryStorageModule, NodeKmsBackend, nodeAgentDependencies } from "../credo/agent.js";
import { applyRequestMutationEdits } from "../fcaf/request-mutation.js";
import { asStringOrNull, isRecord } from "../shared/json.js";
import type { CaptureStore } from "../state.js";
import {
  allocateStatusListReference,
  statusListCredentialType,
} from "../status-list/allocation.js";
import { applyMdocStatusReferenceFixture } from "../status-list/malformed-mdoc-status.js";
import type {
  AppConfig,
  CredentialOfferMode,
  CredentialOfferScheme,
  IssuedCredentialNotification,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  SessionCapture,
  VpRequestMutationEdits,
} from "../types.js";
import { fakeOAuthServer } from "./fake-oauth-server.js";
import {
  type SupportedCredential,
  credentialConfigurationsSupported,
  credentialIssuerMetadata,
  isDomesticPidCredential,
} from "./metadata.js";
import { NotifyingIssuerService, parseNotificationRequest } from "./notification.js";
import { captureProofHeaders, decodeDpopHeader, decodeJwtForEvidence } from "./proofs.js";

const issuers = new WeakMap<CaptureStore, Promise<CredoOpenId4VciIssuer>>();

/**
 * Allowed clock skew for the time claims Credo validates, including Wallet Attestation,
 * Client Attestation PoP, and DPoP proofs at the issuer's authorization server.
 */
const VALIDITY_SKEW_SECONDS = 60;

/** RFC 9126 Section 2.2 prefix of a PAR `request_uri`; Credo-TS issues its reference after it. */
const PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

type IssuanceSessionQuery = {
  issuerState?: string;
  preAuthorizedCode?: string;
  authorizationCode?: string;
  chainedIdentityRequestUriReferenceValue?: string;
  chainedIdentityState?: string;
};

type RequestContext = {
  capture: Oid4vciHttpRequestCapture | null;
  dpop: string | undefined;
  credentialRequestEvidence?: {
    body: JsonRecord;
    raw?: unknown;
  };
  /** The sessions created for this request's wallet-initiated Pushed Authorization Request. */
  walletInitiated?: { captureSessionId: string; credoSessionId: string };
  /** The `notification_id` this request's Credential Response carries, registered once sent. */
  issuedNotification?: IssuedCredentialNotification;
};

/**
 * The answer to a Notification Request (OpenID4VCI 1.0 Section 11): 204 once processed, 400 with
 * a Section 11.3 error code, or 401 with an RFC 6750 Section 3 `WWW-Authenticate` challenge.
 */
export type NotificationOutcome =
  | { status: 204 }
  | { status: 400; error: "invalid_notification_request" | "invalid_notification_id" }
  | { status: 401; wwwAuthenticate: string };

export interface CredoCredentialOffer {
  credentialOffer: string;
  credentialOfferObject: JsonRecord;
  /** The edited by-value offer the deeplink carries, present only for an offer mutation. */
  deliveredCredentialOfferObject?: JsonRecord;
  credentialOfferUri: string;
  issuanceSessionId: string;
}

export async function credoOpenId4VciIssuer(
  config: AppConfig,
  store: CaptureStore,
): Promise<CredoOpenId4VciIssuer> {
  let issuerPromise = issuers.get(store);
  if (!issuerPromise) {
    issuerPromise = CredoOpenId4VciIssuer.create(config, store);
    issuers.set(store, issuerPromise);
  }
  return issuerPromise;
}

export class CredoOpenId4VciIssuer {
  private readonly requestContext = new AsyncLocalStorage<RequestContext>();

  private constructor(
    private readonly config: AppConfig,
    private readonly store: CaptureStore,
    private readonly agent: Agent,
    private readonly app: express.Express,
  ) {}

  static async create(config: AppConfig, store: CaptureStore): Promise<CredoOpenId4VciIssuer> {
    validateIssuerMaterial(config);
    const kms = new NodeKmsBackend();
    const internalApp = express();
    const runtimeRef: { current?: CredoOpenId4VciIssuer } = {};
    const dependencies = nodeAgentDependencies(config);
    const networkFetch = dependencies.fetch;
    const issuerConfigurations = resolvedIssuerConfigurations(config);
    const fakeOAuthServers = issuerConfigurations.map((issuer) =>
      fakeOAuthServer(config, store, issuer),
    );
    dependencies.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const issuer = issuerConfigurations.find((candidate) => url === candidate.endpoints.jwks);
      if (issuer && runtimeRef.current) {
        return new Response(
          JSON.stringify(await runtimeRef.current.authorizationServerJwks(issuer.id)),
          {
            headers: { "content-type": "application/json" },
            status: 200,
          },
        );
      }
      const fakeOAuth = fakeOAuthServers.find((server) => server.handles(input));
      if (fakeOAuth) return fakeOAuth.fetch(input, init);
      return networkFetch(input, init);
    };
    const agent = new Agent({
      config: {
        allowInsecureHttpUrls: true,
        autoUpdateStorageOnStartup: true,
        validitySkewSeconds: VALIDITY_SKEW_SECONDS,
        logger: new ConsoleLogger(LogLevel.Error),
      },
      dependencies,
      modules: {
        storage: new InMemoryStorageModule(),
        kms: new Kms.KeyManagementModule({
          backends: [kms],
          defaultBackend: kms.backend,
        }),
        x509: new X509Module({
          getTrustedCertificatesForVerification: (_agentContext, verificationContext) =>
            verificationContext.certificateChain.map((certificate) => certificate.toString("pem")),
        }),
        openid4vc: new OpenId4VcModule({
          app: internalApp as never,
          issuer: {
            baseUrl: `${config.issuer_base_url}/issuers`,
            cNonceExpiresInSeconds: config.nonce_ttl_seconds,
            authorizationCodeExpiresInSeconds: config.authorization_code_ttl_seconds,
            accessTokenExpiresInSeconds: config.access_token_ttl_seconds,
            requestUriExpiresInSeconds: config.par_request_uri_ttl_seconds,
            dpopRequired: true,
            walletAttestationsRequired: false,
            credentialRequestToCredentialMapper: (options) =>
              runtimeRef.current?.mapCredentialRequest(options) ??
              Promise.reject(new Error("Credo OpenID4VCI issuer is not initialized")),
            getDynamicIssuanceSession: (options) =>
              runtimeRef.current?.walletInitiatedIssuanceSession(options) ??
              Promise.reject(new Error("Credo OpenID4VCI issuer is not initialized")),
            endpoints: {
              authorization: "/authorize",
              authorizationChallenge: "/challenge",
              credential: "/credential",
              credentialOffer: "/offers",
              deferredCredential: "/deferred-credential",
              accessToken: "/token",
              pushedAuthorizationRequest: "/par",
              redirect: "/redirect",
              nonce: "/nonce",
              jwks: "/jwks.json",
            },
          },
        }),
      },
    });

    const runtime = new CredoOpenId4VciIssuer(config, store, agent, internalApp);
    agent.dependencyManager.registerSingleton(OpenId4VcIssuerService, NotifyingIssuerService);
    runtimeRef.current = runtime;
    await agent.initialize();
    runtime.installMdocStatusFixtureSigner();
    runtime.installCredentialResponseNotifier();
    // The last-known-good imported catalogue is restored before the issuer records exist, so they
    // start with it, and without contacting Attestbook.
    const integration = config.attestbook.enabled ? attestbookIntegration(config, store) : null;
    await integration?.restore();
    for (const issuer of issuerConfigurations) {
      await runtime.importIssuerKeys(issuer);
      await runtime.createIssuerRecord(issuer);
    }
    credentialRegistry(config, store).attachIssuerSynchronizer((issuer) =>
      runtime.syncIssuerRecord(issuer),
    );
    runtime.listenForIssuanceEvents();
    integration?.start();
    return runtime;
  }

  private installMdocStatusFixtureSigner(): void {
    const mdocApi = this.agent.dependencyManager.resolve(MdocApi);
    const agent = this.agent;
    this.agent.dependencyManager.registerInstance(
      MdocApi,
      new Proxy(mdocApi, {
        get(target, property, receiver) {
          if (property === "sign") {
            return async (options: Parameters<MdocApi["sign"]>[0]) => {
              const mdoc = await target.sign(options);
              return applyMdocStatusReferenceFixture(mdoc, options, async (signingOptions) => {
                const signed = await agent.kms.sign({
                  algorithm: signingOptions.algorithm as Kms.KnownJwaSignatureAlgorithm,
                  data: signingOptions.data,
                  keyId: signingOptions.keyId,
                });
                return signed.signature;
              });
            };
          }
          const value = Reflect.get(target, property, receiver);
          return typeof value === "function" ? value.bind(target) : value;
        },
      }),
    );
  }

  async createCredentialOffer(options: {
    issuerConfigurationId: string;
    captureSessionId: string;
    credentialConfigurationId: string;
    flow: SessionCapture["flow"];
    credentialOfferMode: CredentialOfferMode;
    offerScheme: CredentialOfferScheme;
    /** JSON Pointer edits to the by-value offer only; Credo keeps serving the generated one. */
    offerMutation?: VpRequestMutationEdits;
  }): Promise<CredoCredentialOffer> {
    const issuer = this.requiredIssuer(options.issuerConfigurationId);
    const credential = credentialRegistry(this.config, this.store).credentialById(
      issuer,
      options.credentialConfigurationId,
    );
    if (!credential) throw new Error("Credential configuration is not supported");
    const fakeOAuth = fakeOAuthServer(this.config, this.store, issuer);
    const created = await this.issuerApi().createCredentialOffer({
      issuerId: issuer.id,
      credentialConfigurationIds: [options.credentialConfigurationId],
      ...(options.flow === "authorization_code"
        ? {
            authorizationCodeFlowConfig: {
              authorizationServerUrl: fakeOAuth.issuer,
              scope: credential.scope,
            },
          }
        : { preAuthorizedCodeFlowConfig: {} }),
      authorization: {
        requireDpop: true,
        requireWalletAttestation: false,
      },
      issuanceMetadata: {
        captureSessionId: options.captureSessionId,
        issuerConfigurationId: issuer.id,
      },
      baseUri: options.offerScheme,
      version: "v1",
    });
    this.store.linkCredoIssuanceSession(
      options.captureSessionId,
      created.issuanceSession.id,
      created.issuanceSession.credentialOfferId,
    );
    const credentialOfferObject = created.issuanceSession.credentialOfferPayload as JsonRecord;
    const deliveredCredentialOfferObject = options.offerMutation
      ? applyRequestMutationEdits(credentialOfferObject, options.offerMutation)
      : undefined;
    return {
      credentialOffer:
        options.credentialOfferMode === "credential_offer"
          ? credentialOfferByValue(
              created.credentialOffer,
              deliveredCredentialOfferObject ?? credentialOfferObject,
            )
          : created.credentialOffer,
      credentialOfferObject,
      ...(deliveredCredentialOfferObject ? { deliveredCredentialOfferObject } : {}),
      credentialOfferUri: created.issuanceSession.credentialOfferUri,
      issuanceSessionId: created.issuanceSession.id,
    };
  }

  get context() {
    return this.agent.context;
  }

  async credentialIssuerMetadata(issuerConfigurationId: string): Promise<JsonRecord> {
    const issuer = this.requiredIssuer(issuerConfigurationId);
    const { credentialIssuer } = await this.issuerApi().getIssuerMetadata(issuer.id);
    const encryptionMetadata = credentialIssuerMetadata(
      issuerAppConfig(this.config, issuer),
      issuer,
    );
    const { deferred_credential_endpoint: _deferredCredentialEndpoint, ...supportedMetadata } =
      credentialIssuer as JsonRecord;
    return {
      ...supportedMetadata,
      ...(this.config.oid4vci_notifications_enabled
        ? { notification_endpoint: issuer.endpoints.notification }
        : {}),
      credential_request_encryption: encryptionMetadata.credential_request_encryption,
      credential_response_encryption: encryptionMetadata.credential_response_encryption,
    };
  }

  async authorizationServerMetadata(issuerConfigurationId: string): Promise<JsonRecord> {
    const issuer = this.requiredIssuer(issuerConfigurationId);
    const { authorizationServers } = await this.issuerApi().getIssuerMetadata(issuer.id);
    const { authorization_challenge_endpoint: _authorizationChallengeEndpoint, ...metadata } =
      authorizationServers[0] as JsonRecord;
    return {
      ...metadata,
      grant_types_supported: [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      ],
      scopes_supported: credentialRegistry(this.config, this.store)
        .credentialsForIssuer(issuer)
        .map((credential) => credential.scope),
      token_endpoint_auth_methods_supported: ["none", "attest_jwt_client_auth"],
      client_attestation_signing_alg_values_supported: ["ES256"],
      client_attestation_pop_signing_alg_values_supported: ["ES256"],
    };
  }

  forward(
    req: Request,
    res: Response,
    next: NextFunction,
    capture: Oid4vciHttpRequestCapture | null,
    credentialRequestEvidence?: RequestContext["credentialRequestEvidence"],
  ): void {
    const context: RequestContext = {
      capture,
      dpop: req.header("DPoP"),
      credentialRequestEvidence,
    };
    res.once("close", () => {
      if (!context.walletInitiated) return;
      void this.settleWalletInitiatedSession(context.walletInitiated).catch(() => undefined);
    });
    // A `notification_id` is usable only once the successful Credential Response carrying it was
    // sent. A response that failed after Credo built it, in encryption or by an FCAF scenario's
    // error status, leaves no id the Wallet could present.
    res.once("finish", () => {
      const notification = context.issuedNotification;
      if (!notification || res.statusCode < 200 || res.statusCode >= 300) return;
      this.store.registerCredentialNotification(notification);
    });
    this.requestContext.run(context, () => this.app(req, res, next));
  }

  /**
   * Processes a Notification Request (OpenID4VCI 1.0 Section 11). The access token and its DPoP
   * proof are verified by Credo-TS's own resource server, exactly as Credo's Credential endpoint
   * verifies them: signature, issuer, audience, expiry, and the DPoP proof's key binding, method,
   * public target URI, and access token hash. The issuer requires DPoP, so a request without a
   * verified proof is refused. The `notification_id` must then have been delivered by this issuer
   * in a Credential Response of the issuance session this access token is bound to.
   */
  async receiveNotification(
    issuer: ResolvedIssuerConfiguration,
    req: Request,
    capture: Oid4vciHttpRequestCapture | null,
  ): Promise<NotificationOutcome> {
    const service = this.agent.dependencyManager.resolve(OpenId4VcIssuerService);
    const issuerRecord = await this.issuerApi().getIssuerByIssuerId(issuer.id);
    const issuerMetadata = await service.getIssuerMetadata(this.agent.context, issuerRecord, true);
    const verified = await service
      .getResourceServer(this.agent.context, issuerRecord, issuerMetadata)
      .verifyResourceRequest({
        authorizationServers: issuerMetadata.authorizationServers,
        resourceServer: issuerMetadata.credentialIssuer.credential_issuer,
        request: {
          headers: requestHeaders(req),
          // Only `POST /issuers/{id}/notification` is routed here; the proof's `htm` must match it.
          method: "POST",
          url: issuer.endpoints.notification,
        },
      })
      .catch((error: unknown) => {
        const challenge = wwwAuthenticateChallenge(error);
        if (challenge === null) throw error;
        return challenge;
      });
    if (typeof verified === "string") return { status: 401, wwwAuthenticate: verified };
    if (!verified.dpop) {
      return {
        status: 401,
        wwwAuthenticate:
          'DPoP error="invalid_dpop_proof", error_description="Missing required DPoP proof"',
      };
    }

    // Section 11.1 requires the `application/json` media type; anything else is malformed.
    const request = parseNotificationRequest(req.is("application/json") ? req.body : undefined);
    if (!request) return { status: 400, error: "invalid_notification_request" };
    const notification = this.store.credentialNotifications.get(request.notification_id);
    if (!notification || notification.issuer_configuration_id !== issuer.id) {
      return { status: 400, error: "invalid_notification_id" };
    }
    const issuanceSession = await this.agent.dependencyManager
      .resolve(OpenId4VcIssuanceSessionRepository)
      .findById(this.agent.context, notification.credo_issuance_session_id);
    if (
      !issuanceSession ||
      issuanceSession.issuerId !== issuer.id ||
      !issuanceSessionAuthorizes(issuanceSession, verified.tokenPayload)
    ) {
      return { status: 400, error: "invalid_notification_id" };
    }
    if (capture) this.store.linkOid4vciRequestToSession(capture, notification.capture_session_id);
    this.store.recordCredentialNotification(notification, request);
    return { status: 204 };
  }

  private installCredentialResponseNotifier(): void {
    const service = this.agent.dependencyManager.resolve(OpenId4VcIssuerService);
    if (!(service instanceof NotifyingIssuerService)) {
      throw new Error("Credo OpenID4VCI issuer service does not support notifications");
    }
    service.notifier = (issuanceSession, credentialCount) =>
      this.credentialResponseNotificationId(issuanceSession, credentialCount);
  }

  /**
   * A fresh, unguessable `notification_id` for the Credential Response the current request is
   * about to receive, held in the request context until that response is sent.
   */
  private credentialResponseNotificationId(
    issuanceSession: OpenId4VcIssuanceSessionRecord,
    credentialCount: number,
  ): string | undefined {
    if (!this.config.oid4vci_notifications_enabled) return undefined;
    const context = this.requestContext.getStore();
    const captureSessionId = captureSessionIdFromCredo(issuanceSession);
    // Credo records the configuration it just issued before returning the response.
    const credentialConfigurationId = issuanceSession.issuedCredentials.at(-1);
    if (!context || !captureSessionId || !credentialConfigurationId) return undefined;
    const notificationId = randomBytes(32).toString("base64url");
    context.issuedNotification = {
      notification_id: notificationId,
      issuer_configuration_id: issuanceSession.issuerId,
      capture_session_id: captureSessionId,
      credo_issuance_session_id: issuanceSession.id,
      credential_configuration_id: credentialConfigurationId,
      credential_count: credentialCount,
    };
    return notificationId;
  }

  /**
   * The capture session an issuer endpoint request belongs to, resolved before Credo-TS handles
   * it, so that a request Credo rejects is still attributed. It looks the Credo issuance session up
   * by the same record tags Credo's own endpoints use: `issuer_state` at PAR, the PAR
   * `request_uri` at authorization, the chained `state` at the redirect, the code at the token
   * endpoint, and the grant the access token names at the Credential endpoint. The access token is
   * decoded, not verified: this only attributes evidence, and Credo still authenticates the
   * request. Returns null when nothing in the request identifies exactly one session.
   */
  async captureSessionIdForRequest(req: Request): Promise<string | null> {
    const endpoint = /^\/issuers\/([^/]+)\/([^/]+)$/.exec(req.path);
    if (!endpoint?.[1] || !endpoint[2]) return null;
    const query = issuanceSessionQuery(endpoint[2], req);
    if (!query) return null;
    const issuanceSessions = await this.agent.dependencyManager
      .resolve(OpenId4VcIssuanceSessionRepository)
      .findByQuery(this.agent.context, {
        issuerId: decodeURIComponent(endpoint[1]),
        ...query,
      });
    const [issuanceSession] = issuanceSessions;
    return issuanceSessions.length === 1 && issuanceSession
      ? captureSessionIdFromCredo(issuanceSession)
      : null;
  }

  private async createIssuerRecord(issuer: ResolvedIssuerConfiguration): Promise<void> {
    const issuerConfig = issuerAppConfig(this.config, issuer);
    const credentials = credentialRegistry(this.config, this.store).credentialsForIssuer(issuer);
    const metadata = credentialIssuerMetadata(issuerConfig, issuer, credentials);
    const createdIssuer = await this.issuerApi().createIssuer({
      issuerId: issuer.id,
      accessTokenSignerKeyType: { kty: "EC", crv: "P-256" },
      display: metadata.display as never,
      dpopSigningAlgValuesSupported: ["ES256"],
      credentialConfigurationsSupported: metadata.credential_configurations_supported as never,
      authorizationServerConfigs: [this.authorizationServerConfig(issuer, credentials)],
    });
    const temporaryAccessTokenKeyId = createdIssuer.resolvedAccessTokenPublicJwk.keyId;
    const accessTokenPrivateJwk = JSON.parse(
      await readFile(accessTokenPrivateJwkPath(issuer.materialDirectory), "utf8"),
    ) as JsonRecord;
    accessTokenPrivateJwk.kid = issuer.accessTokenKeyId;
    const imported = await this.agent.kms.importKey({
      privateJwk: accessTokenPrivateJwk as never,
    });
    createdIssuer.accessTokenPublicJwk = imported.publicJwk;
    await this.issuerApi().updateIssuer(createdIssuer);
    if (temporaryAccessTokenKeyId !== imported.keyId) {
      await this.agent.kms.deleteKey({ keyId: temporaryAccessTokenKeyId });
    }
  }

  /**
   * Brings the issuer's Credo-TS record in line with the registry: its credential configurations
   * and the chained authorization server's scope mapping. The result is read back through Credo's
   * own metadata, and anything other than exactly the registry's credentials is an error, so an
   * activation never reports success while advertising a credential the issuer cannot issue.
   */
  async syncIssuerRecord(issuer: ResolvedIssuerConfiguration): Promise<void> {
    const credentials = credentialRegistry(this.config, this.store).credentialsForIssuer(issuer);
    const record = await this.issuerApi().getIssuerByIssuerId(issuer.id);
    record.credentialConfigurationsSupported = credentialConfigurationsSupported(
      credentials,
    ) as never;
    record.authorizationServerConfigs = [this.authorizationServerConfig(issuer, credentials)];
    await this.issuerApi().updateIssuer(record);

    const { credentialIssuer } = await this.issuerApi().getIssuerMetadata(issuer.id);
    const advertised = credentialIssuer.credential_configurations_supported as Record<
      string,
      JsonRecord
    >;
    const stored = await this.issuerApi().getIssuerByIssuerId(issuer.id);
    const scopes = stored.authorizationServerConfigs?.[0]?.scopesMapping ?? {};
    const consistent =
      Object.keys(advertised).length === credentials.length &&
      credentials.every(
        (credential) =>
          advertised[credential.id]?.scope === credential.scope &&
          advertised[credential.id]?.vct === credential.vct &&
          credential.scope in scopes,
      );
    if (!consistent) {
      throw new Error(
        `Credo issuer '${issuer.id}' does not advertise exactly the activated credentials`,
      );
    }
  }

  private authorizationServerConfig(
    issuer: ResolvedIssuerConfiguration,
    credentials: readonly SupportedCredential[],
  ) {
    const fakeOAuth = fakeOAuthServer(this.config, this.store, issuer);
    return {
      type: "chained" as const,
      issuer: fakeOAuth.issuer,
      clientAuthentication: fakeOAuth.clientAuthentication,
      scopesMapping: Object.fromEntries(
        credentials.map((credential) => [credential.scope, [fakeOAuth.externalScope]]),
      ),
    };
  }

  private async authorizationServerJwks(issuerConfigurationId: string): Promise<JsonRecord> {
    const issuer = await this.issuerApi().getIssuerByIssuerId(issuerConfigurationId);
    return { keys: [issuer.resolvedAccessTokenPublicJwk.toJson()] };
  }

  private async importIssuerKeys(issuer: ResolvedIssuerConfiguration): Promise<void> {
    const privateJwk = JSON.parse(
      await readFile(privateJwkPath(issuer.materialDirectory), "utf8"),
    ) as JsonRecord;
    await this.agent.kms.importKey({ privateJwk: privateJwk as never });
  }

  private listenForIssuanceEvents(): void {
    this.agent.events.on<OpenId4VcIssuanceSessionStateChangedEvent>(
      OpenId4VcIssuerEvents.IssuanceSessionStateChanged,
      async (event) => {
        const captureSessionId = captureSessionIdFromCredo(event.payload.issuanceSession);
        if (!captureSessionId) return;
        this.store.linkCredoIssuanceSession(
          captureSessionId,
          event.payload.issuanceSession.id,
          event.payload.issuanceSession.credentialOfferId,
        );
        await this.linkCurrentRequest(captureSessionId);
        const captureSession = this.store.getSession(captureSessionId);
        if (!captureSession) return;
        if (
          captureSession.flow === "authorization_code" &&
          event.payload.issuanceSession.state === OpenId4VcIssuanceSessionState.AccessTokenCreated
        ) {
          captureSession.checks.pkce_valid = true;
        }
        captureSession.status = captureStatus(event.payload.issuanceSession.state);
        this.store.addEvent(captureSession, "credo_issuance_state_changed", {
          previous_state: event.payload.previousState,
          state: event.payload.issuanceSession.state,
        });
      },
    );
  }

  /**
   * Credo-TS's decision point for wallet-initiated issuance: a Pushed Authorization Request that
   * names a `scope` and no `issuer_state` (OpenID4VCI 1.0 Sections 3.4 and 5.1.2). Credo has
   * already refused a scope matching none of the issuer's credential configurations. One
   * configuration of the active registry is accepted per session; a request naming several, or a
   * scope shared by several, is denied rather than narrowed. An accepted request gets its capture
   * session here, and Credo creates its issuance session from the returned options, chained to
   * the issuer's configured authorization server with the same DPoP and wallet-attestation
   * requirements a Credential Offer sets. Credo's global PKCE requirement applies unchanged.
   * Returning `undefined` makes Credo answer `access_denied`.
   */
  private async walletInitiatedIssuanceSession(
    options: OpenId4VciGetDynamicIssuanceSessionOptions,
  ): Promise<OpenId4VciDynamicIssuanceSessionOptions | undefined> {
    const context = this.requestContext.getStore();
    if (options.origin !== "pushedAuthorizationRequest" || !context) return undefined;
    const issuer = resolvedIssuerConfigurationById(this.config, options.issuer.issuerId);
    const requested = Object.keys(options.requestedCredentialConfigurations);
    const [credentialConfigurationId] = requested;
    if (!issuer || requested.length !== 1 || !credentialConfigurationId) return undefined;
    const registry = credentialRegistry(this.config, this.store);
    // Serialized with activation, so an imported credential is pinned to the active definition.
    return registry.serialize(async () => {
      const credential = registry.credentialById(issuer, credentialConfigurationId);
      if (!credential) return undefined;
      const session = this.store.createSession(issuer, credential.id, "authorization_code");
      const credoSessionId = randomUUID();
      // Registered first, so the session is discarded if anything below or in Credo fails.
      context.walletInitiated = { captureSessionId: session.session_id, credoSessionId };
      session.initiated_by = "wallet";
      this.store.addEvent(session, "wallet_initiated_issuance_requested", {
        requested_scopes: options.requestedScopes,
        credential_configuration_id: credential.id,
      });
      if (credential.attestbook) {
        attestbookIntegration(this.config, this.store).pinSession(session, credential.attestbook);
      }
      return {
        authorizationFlow: "chained" as const,
        authorizationServerUrl: fakeOAuthServer(this.config, this.store, issuer).issuer,
        id: credoSessionId,
        credentialConfigurationIds: [credential.id],
        requireDpop: true,
        requireWalletAttestation: false,
        issuanceMetadata: {
          captureSessionId: session.session_id,
          issuerConfigurationId: issuer.id,
        },
        version: "v1" as const,
      };
    });
  }

  /**
   * Once the response to a wallet-initiated Pushed Authorization Request is sent, discards the
   * sessions created for it unless Credo-TS accepted the request, so a refused request leaves no
   * session the Wallet cannot continue. The request itself stays in the ledger.
   */
  private async settleWalletInitiatedSession(
    walletInitiated: NonNullable<RequestContext["walletInitiated"]>,
  ): Promise<void> {
    const repository = this.agent.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository);
    const issuanceSession = await repository.findById(
      this.agent.context,
      walletInitiated.credoSessionId,
    );
    if (issuanceSession && issuanceSession.state !== OpenId4VcIssuanceSessionState.OfferCreated) {
      return;
    }
    this.store.discardSession(walletInitiated.captureSessionId);
    if (issuanceSession) await repository.delete(this.agent.context, issuanceSession);
  }

  private async mapCredentialRequest(
    options: OpenId4VciCredentialRequestToCredentialMapperOptions,
  ): Promise<OpenId4VciSignCredentials> {
    const captureSessionId = captureSessionIdFromCredo(options.issuanceSession);
    if (!captureSessionId) throw new Error("Capture session is missing from issuance metadata");
    await this.linkCurrentRequest(captureSessionId);
    const captureSession = this.store.getSession(captureSessionId);
    if (!captureSession) throw new Error("Capture session not found");
    const issuer = this.requiredIssuer(options.issuanceSession.issuerId);
    const credential = credentialRegistry(this.config, this.store).credentialById(
      issuer,
      options.credentialConfigurationId,
    );
    if (!credential) throw new Error("Credential configuration is not supported");
    if (credential.attestbook && captureSession.status_list_enabled) {
      throw new Error("Imported credentials do not support Token Status List references");
    }
    const request = options.credentialRequest as JsonRecord;
    const proofHeaders = captureProofHeaders(request);
    const proofType = Object.keys((request.proofs as JsonRecord | undefined) ?? {})[0];
    const holderJwks = options.holderBinding.keys
      .filter((key) => key.method === "jwk")
      .map((key) => key.jwk.toJson() as JsonRecord);
    if (holderJwks.length === 0) throw new Error("Credo did not resolve a JWK holder binding");

    const evidence = this.requestContext.getStore()?.credentialRequestEvidence;
    captureSession.raw ??= {};
    captureSession.raw.credential_request = redactCredentialRequest(evidence?.body ?? request);
    if (evidence?.raw !== undefined) {
      captureSession.raw.credential_request_raw = evidence.raw;
    }
    captureSession.raw.proof_headers = proofHeaders;
    captureSession.checks.proof_jwt_present = proofType === "jwt";
    captureSession.checks.proof_attestation_present = proofType === "attestation";
    captureSession.checks.proof_jwt_header_jwk_present = proofHeaders.some(
      (header) => header.proof_type === "jwt" && Boolean(header.jwk),
    );
    captureSession.checks.key_attestation_verified =
      proofType === "attestation" || proofHeaders.some((header) => header.key_attestation_present);
    captureSession.checks.nonce_verified = true;
    captureSession.observed.wallet_jwks = {
      observed: true,
      source: "credo.verified_holder_binding",
      jwks: { keys: holderJwks },
      observed_proof_header_fields: Array.from(
        new Set(
          proofHeaders.flatMap((header) =>
            ["typ", "alg", "kid", "jwk", "x5c"].filter(
              (field) => header[field as keyof typeof header] !== undefined,
            ),
          ),
        ),
      ),
    };

    const statusListReferences = captureSession.status_list_enabled
      ? await Promise.all(
          holderJwks.map(async (_, index) => {
            const allocationId = statusAllocationId(captureSession, index);
            const reference = await allocateStatusListReference({
              config: this.config,
              allocationId,
              doctype: statusListCredentialType(credential),
            });
            // Kept at the credential's index, so a retried request replaces rather than appends,
            // and `POST /sessions/{id}/status` can revoke exactly what was allocated.
            captureSession.status_list_references ??= [];
            captureSession.status_list_references[index] = {
              allocation_id: allocationId,
              ...reference,
            };
            return reference;
          }),
        )
      : holderJwks.map(() => undefined);

    const signingConfig = issuerAppConfig(this.config, issuer);
    const definition = credential.attestbook;
    if (definition) {
      // Refused earlier at the Credential Endpoint with `invalid_credential_request`; this guards
      // a newer version activated between that check and signing.
      if (captureSession.credential_definition?.content_digest !== definition.contentDigest) {
        throw new Error("Capture session was created under a superseded credential definition");
      }
      const generated = captureSession.generated_claims;
      if (!generated) throw new Error("Capture session has no generated claims");
      return {
        type: "credentials" as const,
        format: ClaimFormat.SdJwtDc,
        credentials: holderJwks.map((holderJwk) =>
          importedSdJwtCredentialSignOptions({
            config: signingConfig,
            holderJwk,
            definition,
            claims: generated.claims,
            digestAlgorithm: captureSession.digest_algorithm,
          }),
        ),
      };
    }
    const fixtureSubject = pidFixtureSubject(
      pidFixtureIdOrNull(captureSession.fixture_id) ?? undefined,
    );
    const subject =
      captureSession.document_number === undefined
        ? fixtureSubject
        : { ...fixtureSubject, documentNumber: captureSession.document_number };
    const domesticPid = isDomesticPidCredential(credential);
    if (credential.format === "mso_mdoc") {
      return {
        type: "credentials" as const,
        format: ClaimFormat.MsoMdoc,
        credentials: holderJwks.map((holderJwk, index) => {
          const signingOptions = {
            config: signingConfig,
            holderJwk,
            statusListReference: statusListReferences[index],
            statusReference: captureSession.status_reference,
            subject,
          };
          return domesticPid
            ? domesticPidMdocCredentialSignOptions(signingOptions)
            : mdocCredentialSignOptions(signingOptions);
        }),
      };
    }
    return {
      type: "credentials" as const,
      format: ClaimFormat.SdJwtDc,
      credentials: holderJwks.map((holderJwk, index) => {
        const signingOptions = {
          config: signingConfig,
          holderJwk,
          statusListReference: statusListReferences[index],
          statusReference: captureSession.status_reference,
          digestAlgorithm: captureSession.digest_algorithm,
        };
        if (credential.vct === DEGREE_SD_JWT_VCT) {
          return degreeSdJwtCredentialSignOptions(signingOptions);
        }
        if (credential.vct === NUMERIC_SD_JWT_VCT) {
          return numericSdJwtCredentialSignOptions(signingOptions);
        }
        if (domesticPid) {
          return domesticPidSdJwtCredentialSignOptions({ ...signingOptions, subject });
        }
        return sdJwtCredentialSignOptions({ ...signingOptions, subject });
      }),
    };
  }

  private async linkCurrentRequest(captureSessionId: string): Promise<void> {
    const context = this.requestContext.getStore();
    if (!context?.capture) return;
    this.store.linkOid4vciRequestToSession(context.capture, captureSessionId);
    const captureSession = this.store.getSession(captureSessionId);
    if (!captureSession) return;
    captureAuthorizationEvidence(
      captureSession,
      this.store.sessionOid4vciRequest(context.capture, captureSession),
    );
    if (!context.dpop) return;
    const dpop = await decodeDpopHeader(context.dpop);
    if (!dpop.jwk) return;
    captureSession.observed.dpop_jwk = {
      observed: true,
      source: `${context.capture.path}.headers.dpop.jwk`,
      jwk: dpop.jwk,
      thumbprint: dpop.thumbprint,
    };
  }

  private issuerApi() {
    const issuer = this.agent.openid4vc?.issuer;
    if (!issuer) throw new Error("Credo OpenID4VC issuer API is unavailable");
    return issuer;
  }

  private requiredIssuer(issuerConfigurationId: string): ResolvedIssuerConfiguration {
    const issuer = resolvedIssuerConfigurationById(this.config, issuerConfigurationId);
    if (!issuer) throw new Error(`Unknown issuer configuration '${issuerConfigurationId}'`);
    return issuer;
  }
}

function statusAllocationId(session: SessionCapture, index: number): string {
  let allocationIds = session.status_list_allocation_ids;
  if (!allocationIds) {
    allocationIds = [];
    session.status_list_allocation_ids = allocationIds;
  }
  if (!allocationIds[index]) allocationIds[index] = `${session.session_id}:${index}`;
  const allocationId = allocationIds[index];
  if (!allocationId) throw new Error(`Missing status allocation id at index ${index}`);
  return allocationId;
}

function credentialOfferByValue(byReference: string, offer: JsonRecord): string {
  const deeplink = new URL(byReference);
  deeplink.searchParams.delete("credential_offer_uri");
  deeplink.searchParams.set("credential_offer", JSON.stringify(offer));
  return deeplink.toString();
}

function captureSessionIdFromCredo(issuanceSession: OpenId4VcIssuanceSessionRecord): string | null {
  const value = issuanceSession.issuanceMetadata?.captureSessionId;
  return typeof value === "string" ? value : null;
}

function issuanceSessionQuery(endpoint: string, req: Request): IssuanceSessionQuery | null {
  const body = isRecord(req.body) ? req.body : {};
  switch (endpoint) {
    case "par": {
      const issuerState = asStringOrNull(body.issuer_state);
      return issuerState ? { issuerState } : null;
    }
    case "authorize": {
      const requestUri = asStringOrNull(req.query.request_uri);
      return requestUri?.startsWith(PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX)
        ? {
            chainedIdentityRequestUriReferenceValue: requestUri.slice(
              PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX.length,
            ),
          }
        : null;
    }
    case "redirect": {
      const state = asStringOrNull(req.query.state);
      return state ? { chainedIdentityState: state } : null;
    }
    case "token": {
      const preAuthorizedCode = asStringOrNull(body["pre-authorized_code"]);
      if (preAuthorizedCode) return { preAuthorizedCode };
      const code = asStringOrNull(body.code);
      return code ? { authorizationCode: code } : null;
    }
    case "credential":
    case "deferred-credential":
    case "notification":
      return accessTokenSessionQuery(req.header("authorization"));
    default:
      return null;
  }
}

/** The grant an access token names, as Credo-TS's Credential endpoint reads it. */
function accessTokenSessionQuery(authorization: string | undefined): IssuanceSessionQuery | null {
  const accessToken = /^(?:DPoP|Bearer) (.+)$/i.exec(authorization ?? "")?.[1];
  if (!accessToken) return null;
  const { payload } = decodeJwtForEvidence(accessToken);
  const preAuthorizedCode = asStringOrNull(payload?.["pre-authorized_code"]);
  if (preAuthorizedCode) return { preAuthorizedCode };
  const issuerState = asStringOrNull(payload?.issuer_state);
  return issuerState ? { issuerState } : null;
}

/** The request headers as a Fetch `Headers`, the form Credo-TS's resource server reads. */
function requestHeaders(req: Request): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.append(name, value);
    else for (const item of value ?? []) headers.append(name, item);
  }
  return headers;
}

/**
 * The RFC 6750 Section 3 challenge of an access token or DPoP proof Credo-TS's resource server
 * refused, or null for any other error. The pinned `@openid4vc/oauth2` error class is not a
 * dependency of this package, so the error is recognized by the challenges it carries. They are
 * encoded here rather than with the error's own encoder, which keeps line breaks of Credo's error
 * descriptions that no HTTP header may contain: every value is limited to the characters RFC 6750
 * Section 3 allows in `error_description`.
 */
function wwwAuthenticateChallenge(error: unknown): string | null {
  if (!(error instanceof Error) || !("wwwAuthenticateHeaders" in error)) return null;
  const challenges = error.wwwAuthenticateHeaders;
  if (!Array.isArray(challenges)) return null;
  const encoded = challenges.flatMap((challenge: unknown) => {
    if (!isRecord(challenge) || typeof challenge.scheme !== "string") return [];
    const parameters = (["error", "error_description", "scope"] as const).flatMap((name) => {
      const value = challenge[name];
      if (typeof value !== "string") return [];
      return [`${name}="${value.replace(/[^\x20\x21\x23-\x5B\x5D-\x7E]/g, " ")}"`];
    });
    return [
      parameters.length > 0 ? `${challenge.scheme} ${parameters.join(", ")}` : challenge.scheme,
    ];
  });
  return encoded.length > 0 ? encoded.join(", ") : null;
}

/**
 * Whether a verified access token belongs to the issuance session that received a Credential
 * Response. Credo-TS binds the session to the `sub` of the access token used at its Credential
 * endpoint, and the token's grant, when it names one, must be this session's grant too.
 */
function issuanceSessionAuthorizes(
  issuanceSession: OpenId4VcIssuanceSessionRecord,
  tokenPayload: { sub?: string; [claim: string]: unknown },
): boolean {
  if (!tokenPayload.sub || issuanceSession.authorization?.subject !== tokenPayload.sub) {
    return false;
  }
  const preAuthorizedCode = asStringOrNull(tokenPayload["pre-authorized_code"]);
  if (preAuthorizedCode !== null && preAuthorizedCode !== issuanceSession.preAuthorizedCode) {
    return false;
  }
  const issuerState = asStringOrNull(tokenPayload.issuer_state);
  return issuerState === null || issuerState === issuanceSession.authorization?.issuerState;
}

function captureStatus(state: OpenId4VcIssuanceSessionState): string {
  switch (state) {
    case OpenId4VcIssuanceSessionState.OfferCreated:
      return "created";
    case OpenId4VcIssuanceSessionState.OfferUriRetrieved:
      return "offer_retrieved";
    case OpenId4VcIssuanceSessionState.AuthorizationInitiated:
      return "authorization_requested";
    case OpenId4VcIssuanceSessionState.AuthorizationGranted:
      return "authorization_granted";
    case OpenId4VcIssuanceSessionState.AccessTokenRequested:
      return "token_requested";
    case OpenId4VcIssuanceSessionState.AccessTokenCreated:
      return "token_issued";
    case OpenId4VcIssuanceSessionState.CredentialRequestReceived:
      return "credential_requested";
    case OpenId4VcIssuanceSessionState.CredentialsPartiallyIssued:
      return "credentials_partially_issued";
    case OpenId4VcIssuanceSessionState.Completed:
      return "credential_issued";
    case OpenId4VcIssuanceSessionState.Error:
      return "error";
    default:
      return state;
  }
}

function captureAuthorizationEvidence(
  session: SessionCapture,
  capture: Oid4vciHttpRequestCapture,
): void {
  const body = isRecord(capture.body) ? capture.body : {};
  session.raw ??= {};
  if (capture.path.endsWith("/par")) {
    session.raw.par_request = body;
    setObservedString(session.observed.client_id, body.client_id, `${capture.path}.body.client_id`);
    setObservedString(
      session.observed.redirect_uri,
      body.redirect_uri,
      `${capture.path}.body.redirect_uri`,
    );
    session.checks.pkce_present =
      typeof body.code_challenge === "string" && body.code_challenge_method === "S256";
    session.checks.state_present = typeof body.state === "string";
    session.checks.issuer_state_present = typeof body.issuer_state === "string";
  }
  if (capture.path.endsWith("/token")) {
    session.raw.token_request = body;
  }
}

function setObservedString(
  observed: SessionCapture["observed"]["client_id"],
  value: unknown,
  source: string,
): void {
  if (typeof value !== "string" || value.length === 0) return;
  if (observed.value && observed.value !== value) {
    observed.also_seen_in ??= [];
    observed.also_seen_in.push(source);
    return;
  }
  observed.value = value;
  observed.source ??= source;
}

function redactCredentialRequest(request: JsonRecord): JsonRecord {
  const redacted = structuredClone(request);
  const proofs = redacted.proofs as JsonRecord | undefined;
  if (proofs) {
    for (const proofType of Object.keys(proofs)) {
      proofs[proofType] = { redacted: true, present: true };
    }
  }
  if (redacted.proof !== undefined) {
    redacted.proof = { redacted: true, present: true };
  }
  return redacted;
}
