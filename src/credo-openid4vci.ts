import { AsyncLocalStorage } from "node:async_hooks";
import { readFile } from "node:fs/promises";
import { Agent, ClaimFormat, ConsoleLogger, Kms, LogLevel, X509Module } from "@credo-ts/core";
import {
  type OpenId4VcIssuanceSessionRecord,
  OpenId4VcIssuanceSessionState,
  type OpenId4VcIssuanceSessionStateChangedEvent,
  OpenId4VcIssuerEvents,
  OpenId4VcModule,
  type OpenId4VciCredentialRequestToCredentialMapperOptions,
  type OpenId4VciSignCredentials,
} from "@credo-ts/openid4vc";
import express, { type NextFunction, type Request, type Response } from "express";
import { accessTokenPrivateJwkPath, privateJwkPath, validateIssuerMaterial } from "./config.js";
import {
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "./configurations/registry.js";
import { issuerAppConfig } from "./configurations/resolve-urls.js";
import type { ResolvedIssuerConfiguration } from "./configurations/types.js";
import { mdocCredentialSignOptions, sdJwtCredentialSignOptions } from "./credential.js";
import { InMemoryStorageModule, NodeKmsBackend, nodeAgentDependencies } from "./credo-openid4vp.js";
import { fakeOAuthServer } from "./fake-oauth-server.js";
import {
  credentialIssuerMetadata,
  supportedCredentialById,
  supportedCredentialsForIssuer,
} from "./metadata.js";
import { captureProofHeaders, decodeDpopHeader } from "./proofs.js";
import type { CaptureStore } from "./state.js";
import type {
  AppConfig,
  CredentialOfferMode,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  SessionCapture,
} from "./types.js";

const issuers = new WeakMap<CaptureStore, Promise<CredoOpenId4VciIssuer>>();

type RequestContext = {
  capture: Oid4vciHttpRequestCapture | null;
  dpop: string | undefined;
  credentialRequestEvidence?: {
    body: JsonRecord;
    raw?: unknown;
  };
};

export interface CredoCredentialOffer {
  credentialOffer: string;
  credentialOfferObject: JsonRecord;
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
    runtimeRef.current = runtime;
    await agent.initialize();
    for (const issuer of issuerConfigurations) {
      await runtime.importIssuerKeys(issuer);
      await runtime.createIssuerRecord(issuer);
    }
    runtime.listenForIssuanceEvents();
    return runtime;
  }

  async createCredentialOffer(options: {
    issuerConfigurationId: string;
    captureSessionId: string;
    credentialConfigurationId: string;
    flow: SessionCapture["flow"];
    credentialOfferMode: CredentialOfferMode;
  }): Promise<CredoCredentialOffer> {
    const issuer = this.requiredIssuer(options.issuerConfigurationId);
    const credential = supportedCredentialById(
      this.config,
      options.credentialConfigurationId,
      issuer,
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
      version: "v1",
    });
    this.store.linkCredoIssuanceSession(
      options.captureSessionId,
      created.issuanceSession.id,
      created.issuanceSession.credentialOfferId,
    );
    return {
      credentialOffer:
        options.credentialOfferMode === "credential_offer"
          ? credentialOfferByValue(
              created.credentialOffer,
              created.issuanceSession.credentialOfferPayload as JsonRecord,
            )
          : created.credentialOffer,
      credentialOfferObject: created.issuanceSession.credentialOfferPayload as JsonRecord,
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
      response_types_supported: ["code"],
      scopes_supported: supportedCredentialsForIssuer(this.config, issuer).map(
        (credential) => credential.scope,
      ),
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
    if (req.path.endsWith("/par")) normalizeParResponseStatus(res);
    this.requestContext.run({ capture, dpop: req.header("DPoP"), credentialRequestEvidence }, () =>
      this.app(req, res, next),
    );
  }

  private async createIssuerRecord(issuer: ResolvedIssuerConfiguration): Promise<void> {
    const issuerConfig = issuerAppConfig(this.config, issuer);
    const metadata = credentialIssuerMetadata(issuerConfig, issuer);
    const fakeOAuth = fakeOAuthServer(this.config, this.store, issuer);
    const createdIssuer = await this.issuerApi().createIssuer({
      issuerId: issuer.id,
      accessTokenSignerKeyType: { kty: "EC", crv: "P-256" },
      display: metadata.display as never,
      dpopSigningAlgValuesSupported: ["ES256"],
      credentialConfigurationsSupported: metadata.credential_configurations_supported as never,
      authorizationServerConfigs: [
        {
          type: "chained",
          issuer: fakeOAuth.issuer,
          clientAuthentication: fakeOAuth.clientAuthentication,
          scopesMapping: Object.fromEntries(
            supportedCredentialsForIssuer(this.config, issuer).map((credential) => [
              credential.scope,
              [fakeOAuth.externalScope],
            ]),
          ),
        },
      ],
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

  private async mapCredentialRequest(
    options: OpenId4VciCredentialRequestToCredentialMapperOptions,
  ): Promise<OpenId4VciSignCredentials> {
    const captureSessionId = captureSessionIdFromCredo(options.issuanceSession);
    if (!captureSessionId) throw new Error("Capture session is missing from issuance metadata");
    await this.linkCurrentRequest(captureSessionId);
    const captureSession = this.store.getSession(captureSessionId);
    if (!captureSession) throw new Error("Capture session not found");
    const issuer = this.requiredIssuer(options.issuanceSession.issuerId);
    const credential = supportedCredentialById(
      this.config,
      options.credentialConfigurationId,
      issuer,
    );
    if (!credential) throw new Error("Credential configuration is not supported");
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

    const signingConfig = issuerAppConfig(this.config, issuer);
    if (credential.format === "mso_mdoc") {
      return {
        type: "credentials" as const,
        format: ClaimFormat.MsoMdoc,
        credentials: holderJwks.map((holderJwk) =>
          mdocCredentialSignOptions({
            config: signingConfig,
            holderJwk,
          }),
        ),
      };
    }
    return {
      type: "credentials" as const,
      format: ClaimFormat.SdJwtDc,
      credentials: holderJwks.map((holderJwk) =>
        sdJwtCredentialSignOptions({
          config: signingConfig,
          holderJwk,
        }),
      ),
    };
  }

  private async linkCurrentRequest(captureSessionId: string): Promise<void> {
    const context = this.requestContext.getStore();
    if (!context?.capture) return;
    this.store.linkOid4vciRequestToSession(context.capture, captureSessionId);
    const captureSession = this.store.getSession(captureSessionId);
    if (!captureSession) return;
    captureAuthorizationEvidence(captureSession, context.capture);
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

function credentialOfferByValue(byReference: string, offer: JsonRecord): string {
  const deeplink = new URL(byReference);
  deeplink.searchParams.delete("credential_offer_uri");
  deeplink.searchParams.set("credential_offer", JSON.stringify(offer));
  return deeplink.toString();
}

function normalizeParResponseStatus(res: Response): void {
  const send = res.send.bind(res);
  res.send = ((body: unknown) => {
    if (res.statusCode === 200) res.status(201);
    return send(body);
  }) as typeof res.send;
}

function captureSessionIdFromCredo(issuanceSession: OpenId4VcIssuanceSessionRecord): string | null {
  const value = issuanceSession.issuanceMetadata?.captureSessionId;
  return typeof value === "string" ? value : null;
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

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
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
