import { randomUUID } from "node:crypto";
import { supportedCredentialConfigurationIds } from "./metadata.js";
import type {
  AppConfig,
  CaptureEvent,
  CredoIssuanceOffer,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  SessionCapture,
  VpSessionCapture,
} from "./types.js";

export class CaptureStore {
  readonly oid4vciRequests: Oid4vciHttpRequestCapture[] = [];
  readonly sessions = new Map<string, SessionCapture>();
  readonly vpSessions = new Map<string, VpSessionCapture>();
  readonly vpCredoVerificationSessionIds = new Map<string, string>();
  readonly vpCredoAuthorizationRequestJwts = new Map<string, string>();
  readonly credoIssuanceSessionIds = new Map<string, string>();
  readonly captureSessionIdsByCredoSession = new Map<string, string>();
  readonly captureSessionIdsByCredentialOffer = new Map<string, string>();
  readonly credoIssuanceOffers = new Map<string, CredoIssuanceOffer>();

  constructor(private readonly config: AppConfig) {}

  createSession(
    credentialConfigurationId = defaultCredentialConfigurationId(this.config),
    broken = false,
    flow: SessionCapture["flow"] = "pre_authorized_code",
  ): SessionCapture {
    const sessionId = randomUUID();
    const session: SessionCapture = {
      session_id: sessionId,
      status: "created",
      credential_configuration_id: credentialConfigurationId,
      flow,
      broken,
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
      credential_configuration_id: credentialConfigurationId,
      flow,
      broken,
    });
    return session;
  }

  getSession(sessionId: string): SessionCapture | undefined {
    return this.sessions.get(sessionId);
  }

  recordOid4vciRequest(capture: Oid4vciHttpRequestCapture): void {
    this.oid4vciRequests.push(capture);
    if (this.oid4vciRequests.length > 1_000) this.oid4vciRequests.shift();
    if (!capture.session_id) return;
    const session = this.sessions.get(capture.session_id);
    if (!session) return;
    session.raw ??= {};
    session.raw.oid4vci_requests ??= [];
    session.raw.oid4vci_requests.push(capture);
  }

  linkOid4vciRequestToSession(capture: Oid4vciHttpRequestCapture, sessionId: string): void {
    if (capture.session_id === sessionId) return;
    capture.session_id = sessionId;
    const session = this.sessions.get(sessionId);
    if (!session) return;
    session.raw ??= {};
    session.raw.oid4vci_requests ??= [];
    if (!session.raw.oid4vci_requests.includes(capture)) {
      session.raw.oid4vci_requests.push(capture);
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
    requestDelivery: "by_reference" | "by_value",
    requestUriMethod: "get" | "post",
    responseMode: "direct_post" | "direct_post.jwt",
    deeplinkScheme: string,
    urls?: {
      requestUri?: string;
      responseUri?: string;
    },
  ): VpSessionCapture {
    const requestUri =
      urls?.requestUri ?? `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
    const responseUri =
      urls?.responseUri ??
      `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/response`;
    const session: VpSessionCapture = {
      session_id: sessionId,
      status: "created",
      request_delivery: requestDelivery,
      request_uri_method: requestUriMethod,
      response_mode: responseMode,
      authorization_request: authorizationRequest,
      request_uri: requestUri,
      deeplink_scheme: deeplinkScheme,
      response_uri: responseUri,
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

function defaultCredentialConfigurationId(config: AppConfig): string {
  return supportedCredentialConfigurationIds(config)[0];
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
