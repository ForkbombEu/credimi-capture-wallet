import { randomUUID } from "node:crypto";
import { supportedCredentialConfigurationIds } from "./metadata.js";
import type {
  AccessToken,
  AppConfig,
  AuthorizationCode,
  CaptureEvent,
  JsonRecord,
  ParRecord,
  SessionCapture,
  VpSessionCapture,
} from "./types.js";

export class CaptureStore {
  readonly sessions = new Map<string, SessionCapture>();
  readonly parRequests = new Map<string, ParRecord>();
  readonly authorizationCodes = new Map<string, AuthorizationCode>();
  readonly accessTokens = new Map<string, AccessToken>();
  readonly credentialNonces = new Map<string, number>();
  readonly vpSessions = new Map<string, VpSessionCapture>();
  readonly dpopJtis = new Set<string>();

  constructor(private readonly config: AppConfig) {}

  createSession(
    credentialConfigurationId = defaultCredentialConfigurationId(this.config),
  ): SessionCapture {
    const sessionId = randomUUID();
    const session: SessionCapture = {
      session_id: sessionId,
      status: "created",
      credential_configuration_id: credentialConfigurationId,
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
        proof_jwt_header_jwk_present: false,
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
    });
    return session;
  }

  getSession(sessionId: string): SessionCapture | undefined {
    return this.sessions.get(sessionId);
  }

  createVpSession(
    sessionId: string,
    authorizationRequest: JsonRecord,
    requestUriMethod: "get" | "post",
  ): VpSessionCapture {
    const requestUri = `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
    const responseUri = `${this.config.issuer_base_url}/openid4vp/sessions/${sessionId}/response`;
    const session: VpSessionCapture = {
      session_id: sessionId,
      status: "created",
      request_uri_method: requestUriMethod,
      authorization_request: authorizationRequest,
      request_uri: requestUri,
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

  ensureSession(sessionId?: string | null): SessionCapture {
    if (sessionId) {
      const existing = this.sessions.get(sessionId);
      if (existing) return existing;
    }
    const orphan = this.createSession();
    orphan.status = "orphaned";
    this.addEvent(orphan, "orphan_session_created", { requested_session_id: sessionId ?? null });
    return orphan;
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

  storePar(params: JsonRecord): ParRecord {
    const requestUri = `urn:credimi:fake-vci-issuer:par:${randomUUID()}`;
    const record = {
      request_uri: requestUri,
      expires_at: nowSeconds() + this.config.par_request_uri_ttl_seconds,
      params,
    };
    this.parRequests.set(requestUri, record);
    return record;
  }

  resolvePar(requestUri: string | undefined): ParRecord | null {
    if (!requestUri) return null;
    const record = this.parRequests.get(requestUri);
    if (!record || record.expires_at < nowSeconds()) return null;
    return record;
  }

  issueAuthorizationCode(session: SessionCapture, params: JsonRecord): AuthorizationCode {
    const code = randomUUID();
    const record: AuthorizationCode = {
      code,
      session_id: session.session_id,
      client_id: asStringOrNull(params.client_id),
      redirect_uri: asStringOrNull(params.redirect_uri),
      code_challenge: asStringOrNull(params.code_challenge),
      code_challenge_method: asStringOrNull(params.code_challenge_method),
      state: asStringOrNull(params.state),
      expires_at: nowSeconds() + this.config.authorization_code_ttl_seconds,
      used: false,
    };
    this.authorizationCodes.set(code, record);
    return record;
  }

  consumeAuthorizationCode(code: string | undefined): AuthorizationCode | null {
    if (!code) return null;
    const record = this.authorizationCodes.get(code);
    if (!record || record.used || record.expires_at < nowSeconds()) return null;
    record.used = true;
    return record;
  }

  issueAccessToken(sessionId: string, dpopJkt: string): AccessToken {
    const token = randomUUID();
    const record = {
      token,
      session_id: sessionId,
      dpop_jkt: dpopJkt,
      expires_at: nowSeconds() + this.config.access_token_ttl_seconds,
    };
    this.accessTokens.set(token, record);
    return record;
  }

  issueCredentialNonce(): string {
    const nonce = randomUUID();
    this.credentialNonces.set(nonce, nowSeconds() + this.config.nonce_ttl_seconds);
    return nonce;
  }

  consumeCredentialNonce(nonce: string): boolean {
    const expiresAt = this.credentialNonces.get(nonce);
    this.credentialNonces.delete(nonce);
    return expiresAt !== undefined && expiresAt >= nowSeconds();
  }

  resolveAccessToken(header: string | undefined): AccessToken | null {
    const token = header?.replace(/^Bearer\s+/i, "").replace(/^DPoP\s+/i, "");
    if (!token) return null;
    const record = this.accessTokens.get(token);
    if (!record || record.expires_at < nowSeconds()) return null;
    return record;
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function updateObservedValue(
  session: SessionCapture,
  key: "client_id" | "redirect_uri",
  value: unknown,
  source: string,
): void {
  if (typeof value !== "string" || value.length === 0) return;
  const observed = session.observed[key];
  if (!observed.value) {
    observed.value = value;
    observed.source = source;
    return;
  }
  if (observed.value === value && observed.source !== source) {
    observed.also_seen_in ??= [];
    if (!observed.also_seen_in.includes(source)) observed.also_seen_in.push(source);
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
