import { randomUUID } from "node:crypto";
import { recordClientAuthentication } from "./client-attestation.js";
import {
  DEFAULT_ISSUER_CONFIGURATION_ID,
  resolvedIssuerConfigurationById,
} from "./configurations/registry.js";
import type { ResolvedIssuerConfiguration } from "./configurations/types.js";
import { DEFAULT_SD_JWT_DIGEST_ALGORITHM } from "./digest-algorithm.js";
import { supportedCredentialConfigurationIdsForIssuer } from "./metadata.js";
import type { VpDeliveredRequestRecipe } from "./openid4vp.js";
import type {
  AppConfig,
  CaptureEvent,
  CredentialOfferMode,
  CredoIssuanceOffer,
  EvidenceMode,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  OpenId4VpResponseMode,
  RequestSigningMaterial,
  SdJwtDigestAlgorithm,
  SessionCapture,
  StatusReferenceFixture,
  VpDcApiCapture,
  VpRequestDelivery,
  VpSessionCapture,
} from "./types.js";

export class CaptureStore {
  readonly oid4vciRequests: Oid4vciHttpRequestCapture[] = [];
  readonly sessions = new Map<string, SessionCapture>();
  readonly vpSessions = new Map<string, VpSessionCapture>();
  readonly vpSessionIdsByRedirectResponseCode = new Map<string, string>();
  readonly vpCredoVerificationSessionIds = new Map<string, string>();
  readonly vpCredoAuthorizationRequestJwts = new Map<string, string>();
  /**
   * Fixture signing keys, held only in memory and deliberately never part of a session capture:
   * a capture is evidence that gets exported, and a private key must not travel with it.
   */
  readonly vpRequestSigningMaterial = new Map<string, RequestSigningMaterial>();
  readonly vpDeliveredRequestRecipes = new Map<string, VpDeliveredRequestRecipe>();
  readonly credoIssuanceSessionIds = new Map<string, string>();
  readonly captureSessionIdsByCredoSession = new Map<string, string>();
  readonly captureSessionIdsByCredentialOffer = new Map<string, string>();
  readonly credoIssuanceOffers = new Map<string, CredoIssuanceOffer>();
  /**
   * The `full` form of each ledger capture. It is kept apart from the ledger, which only ever
   * holds the redacted form, and is exposed only through a session created with
   * `evidence_mode: "full"`. Weakly held, so it is released with its ledger capture.
   */
  readonly fullOid4vciRequests = new WeakMap<
    Oid4vciHttpRequestCapture,
    Oid4vciHttpRequestCapture
  >();

  constructor(private readonly config: AppConfig) {}

  createSession(
    issuer: ResolvedIssuerConfiguration = defaultIssuerConfiguration(this.config),
    credentialConfigurationId = defaultCredentialConfigurationId(this.config, issuer),
    flow: SessionCapture["flow"] = "authorization_code",
    credentialOfferMode: CredentialOfferMode = "credential_offer",
    statusListEnabled = false,
    fixtureId?: string,
    statusReference?: StatusReferenceFixture,
    digestAlgorithm?: SdJwtDigestAlgorithm,
    evidenceMode: EvidenceMode = "redacted",
  ): SessionCapture {
    const sessionId = randomUUID();
    const session: SessionCapture = {
      session_id: sessionId,
      issuer_configuration_id: issuer.id,
      issuer_identifier: issuer.issuerIdentifier,
      authorization_server_identifier: issuer.issuerIdentifier,
      status: "created",
      credential_configuration_id: credentialConfigurationId,
      flow,
      credential_offer_mode: credentialOfferMode,
      status_list_enabled: statusListEnabled,
      ...(fixtureId ? { fixture_id: fixtureId } : {}),
      ...(statusReference && statusReference !== "valid"
        ? { status_reference: statusReference }
        : {}),
      ...(digestAlgorithm && digestAlgorithm !== DEFAULT_SD_JWT_DIGEST_ALGORITHM
        ? { digest_algorithm: digestAlgorithm }
        : {}),
      ...(evidenceMode === "full" ? { evidence_mode: evidenceMode } : {}),

      observed: {
        client_id: { value: null, source: null, also_seen_in: [] },
        redirect_uri: { value: null, source: null, also_seen_in: [] },
        wallet_jwks: {
          observed: false,
          source: null,
          jwks: null,
          observed_proof_header_fields: [],
        },
        dpop_jwk: { observed: false, source: null, jwk: null, thumbprint: null },
        client_authentication: emptyClientAuthenticationCapture(),
      },
      checks: {
        pkce_present: false,
        pkce_valid: false,
        state_present: false,
        issuer_state_present: false,
        proof_jwt_present: false,
        proof_attestation_present: false,
        proof_jwt_header_jwk_present: false,
        key_attestation_verified: false,
        nonce_verified: false,
        private_key_jwt_present: false,
        private_key_jwt_client_id_matches: null,
        wallet_attestation_present: false,
        wallet_attestation_pop_present: false,
        wallet_attestation_client_id_matches: null,
        wallet_attestation_pop_audience_matches: null,
      },
      events: [],
      raw: {},
    };
    this.sessions.set(sessionId, session);
    this.addEvent(session, "session_created", {
      issuer_configuration_id: issuer.id,
      issuer_identifier: issuer.issuerIdentifier,
      authorization_server_identifier: issuer.issuerIdentifier,
      credential_configuration_id: credentialConfigurationId,
      flow,
      credential_offer_mode: credentialOfferMode,
      status_list_enabled: statusListEnabled,
      ...(evidenceMode === "full" ? { evidence_mode: evidenceMode } : {}),
    });
    return session;
  }

  getSession(sessionId: string): SessionCapture | undefined {
    return this.sessions.get(sessionId);
  }

  recordOid4vciRequest(
    capture: Oid4vciHttpRequestCapture,
    fullCapture: Oid4vciHttpRequestCapture,
    sessionId: string | null = null,
  ): void {
    this.oid4vciRequests.push(capture);
    if (this.oid4vciRequests.length > 1_000) this.oid4vciRequests.shift();
    this.fullOid4vciRequests.set(capture, fullCapture);
    if (sessionId) this.linkOid4vciRequestToSession(capture, sessionId);
  }

  /**
   * Attributes a ledger capture to a session. The session receives the form its evidence mode
   * selects, and its client authentication evidence is taken from the first request carrying it.
   */
  linkOid4vciRequestToSession(capture: Oid4vciHttpRequestCapture, sessionId: string): void {
    if (capture.session_id === sessionId) return;
    const fullCapture = this.fullOid4vciRequests.get(capture);
    capture.session_id = sessionId;
    if (fullCapture) fullCapture.session_id = sessionId;
    const session = this.sessions.get(sessionId);
    if (!session) return;
    const sessionCapture = this.sessionOid4vciRequest(capture, session);
    session.raw ??= {};
    session.raw.oid4vci_requests ??= [];
    if (!session.raw.oid4vci_requests.includes(sessionCapture)) {
      session.raw.oid4vci_requests.push(sessionCapture);
    }
    if (fullCapture) recordClientAuthentication(session, fullCapture);
  }

  /** The form of a ledger capture that a session's evidence mode exposes. */
  sessionOid4vciRequest(
    capture: Oid4vciHttpRequestCapture,
    session: SessionCapture,
  ): Oid4vciHttpRequestCapture {
    if (session.evidence_mode !== "full") return capture;
    return this.fullOid4vciRequests.get(capture) ?? capture;
  }

  /**
   * Attributes unattributed Nonce Endpoint responses to the session whose Credential Request
   * carried their `c_nonce` as a proof `nonce`. The Nonce Endpoint takes no session context, so
   * the nonce value is the only link.
   */
  linkNonceResponses(sessionId: string, issuerConfigurationId: string, nonces: string[]): void {
    if (nonces.length === 0) return;
    for (const capture of this.oid4vciRequests) {
      if (capture.session_id !== null || capture.issuer_configuration_id !== issuerConfigurationId)
        continue;
      if (!capture.path.endsWith("/nonce")) continue;
      const body = capture.response.body;
      const cNonce = body && typeof body === "object" && "c_nonce" in body ? body.c_nonce : null;
      if (typeof cNonce === "string" && nonces.includes(cNonce)) {
        this.linkOid4vciRequestToSession(capture, sessionId);
      }
    }
  }

  linkCredoIssuanceSession(
    captureSessionId: string,
    credoSessionId: string,
    credentialOfferId?: string,
  ): void {
    this.credoIssuanceSessionIds.set(captureSessionId, credoSessionId);
    this.captureSessionIdsByCredoSession.set(credoSessionId, captureSessionId);
    if (credentialOfferId) {
      this.captureSessionIdsByCredentialOffer.set(credentialOfferId, captureSessionId);
    }
  }

  createVpSession(
    sessionId: string,
    authorizationRequest: JsonRecord,
    requestDelivery: VpRequestDelivery,
    requestUriMethod: string,
    responseMode: OpenId4VpResponseMode,
    deeplinkScheme: string,
    redirectUri?: string,
    urls?: {
      requestUri?: string;
      responseUri?: string;
    },
    dcApi?: VpDcApiCapture,
  ): VpSessionCapture {
    const requestUri = dcApi
      ? undefined
      : (urls?.requestUri ??
        `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`);
    const responseUri = dcApi
      ? undefined
      : (urls?.responseUri ??
        `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/response`);
    const session: VpSessionCapture = {
      session_id: sessionId,
      status: "created",
      request_delivery: requestDelivery,
      response_mode: responseMode,
      authorization_request: authorizationRequest,
      ...(dcApi
        ? { dc_api: dcApi }
        : {
            request_uri_method: requestUriMethod,
            request_uri: requestUri,
            deeplink_scheme: deeplinkScheme,
            response_uri: responseUri,
          }),
      ...(redirectUri ? { redirect_uri: redirectUri } : {}),
      deeplink: "",
      observed: {
        request_uri_payload: { value: null, source: null, also_seen_in: [] },
        wallet_response: { value: null, source: null, also_seen_in: [] },
      },
      checks: {
        presentation_valid: null,
        vp_token_format_valid: false,
        nonce_verified: false,
        holder_binding_verified: false,
        dcql_query_matched: false,
        transaction_data_verified: null,
        errors: [],
      },
      events: [],
      raw: {
        authorization_request: authorizationRequest,
      },
    };
    this.vpSessions.set(sessionId, session);
    this.addEvent(session, "vp_session_created", {});
    return session;
  }

  getVpSession(sessionId: string): VpSessionCapture | undefined {
    return this.vpSessions.get(sessionId);
  }

  linkVpRedirectResponseCode(sessionId: string, responseCode: string): void {
    this.vpSessionIdsByRedirectResponseCode.set(responseCode, sessionId);
  }

  addEvent(
    session: SessionCapture | VpSessionCapture,
    type: string,
    detail: JsonRecord,
  ): CaptureEvent {
    const event = { at: new Date().toISOString(), type, detail };
    session.events.push(event);
    return event;
  }
}

export function asStringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function defaultIssuerConfiguration(config: AppConfig): ResolvedIssuerConfiguration {
  const issuer = resolvedIssuerConfigurationById(config, DEFAULT_ISSUER_CONFIGURATION_ID);
  if (!issuer) throw new Error("Default issuer configuration is unavailable");
  return issuer;
}

function defaultCredentialConfigurationId(
  config: AppConfig,
  issuer: ResolvedIssuerConfiguration,
): string {
  const credentialConfigurationId = supportedCredentialConfigurationIdsForIssuer(config, issuer)[0];
  if (!credentialConfigurationId) {
    throw new Error(`Issuer '${issuer.id}' has no credential configurations`);
  }
  return credentialConfigurationId;
}

function emptyClientAuthenticationCapture(): SessionCapture["observed"]["client_authentication"] {
  const emptyJwt = { present: false, source: null, header: null, claims: null, error: null };
  return {
    method: "none",
    private_key_jwt: {
      ...emptyJwt,
      assertion_type: null,
      assertion_type_valid: false,
      client_id_matches: null,
      audience_matches: null,
    },
    wallet_attestation: {
      ...emptyJwt,
      cnf_jwk: null,
      client_id_matches: null,
    },
    wallet_attestation_pop: {
      ...emptyJwt,
      audience_matches: null,
      challenge: null,
    },
  };
}
