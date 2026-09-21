export type JsonRecord = Record<string, unknown>;
export type CredentialOfferMode = "credential_offer" | "credential_offer_uri";

export interface StatusListReference {
  uri: string;
  idx: number;
}

export interface AppConfig {
  issuer_base_url: string;
  /**
   * Public origin the operator UI is served from. The DC API presentation page URL and the
   * `expected_origins` of a signed DC API request are derived from it, never from a request Host
   * header. Defaults to `issuer_base_url`.
   */
  public_base_url: string;
  /**
   * Enables the FCAF scenario inputs that deliberately produce malformed protocol material, such
   * as `request_mutation`. Off by default: an ordinary deployment refuses them.
   */
  fcaf_scenarios_enabled: boolean;
  listen_addr: string;
  data_dir: string;
  credential_configuration_id: string;
  credential_format: string;
  credential_scope: string;
  authorization_code_ttl_seconds: number;
  par_request_uri_ttl_seconds: number;
  access_token_ttl_seconds: number;
  nonce_ttl_seconds: number;
  permissive_capture: boolean;
  gui_enabled: boolean;
  status_list_base_url: string;
  status_list_api_key: string;
  status_list_timeout_ms: number;
  status_list_trusted_certificates: string[];
}

export interface ObservedValue<T> {
  value: T | null;
  source: string | null;
  also_seen_in?: string[];
}

export interface CaptureEvent {
  at: string;
  type: string;
  detail: JsonRecord;
}

export interface Oid4vciHttpRequestCapture {
  id: string;
  at: string;
  method: string;
  path: string;
  session_id: string | null;
  issuer_configuration_id: string | null;
  headers: JsonRecord;
  query: unknown;
  body: unknown;
  response: {
    status: number | null;
    content_type: string | null;
  };
}

export interface PresentationResponseHttpCapture {
  method: string;
  headers: JsonRecord;
  body: string;
}

export interface RequestUriHttpCapture {
  method: string;
  headers: JsonRecord;
  body?: string;
}

export interface VerifierResponseHttpCapture {
  status: number;
  headers: JsonRecord;
  body: string;
}

export interface RedirectUriVisitHttpCapture {
  method: string;
  headers: JsonRecord;
}

export interface ProofHeaderCapture {
  proof_type?: "jwt" | "attestation";
  typ?: string;
  alg?: string;
  kid?: string;
  jwk?: JsonRecord;
  x5c?: string[];
  key_attestation_present?: boolean;
  source: string;
}

export interface JwtCapture {
  present: boolean;
  source: string | null;
  header: JsonRecord | null;
  claims: JsonRecord | null;
  error: string | null;
}

export interface ClientAuthenticationCapture {
  method: "none" | "private_key_jwt" | "wallet_attestation" | "multiple";
  private_key_jwt: JwtCapture & {
    assertion_type: string | null;
    assertion_type_valid: boolean;
    client_id_matches: boolean | null;
    audience_matches: boolean | null;
  };
  wallet_attestation: JwtCapture & {
    cnf_jwk: JsonRecord | null;
    client_id_matches: boolean | null;
  };
  wallet_attestation_pop: JwtCapture & {
    audience_matches: boolean | null;
    challenge: string | null;
  };
}

export interface SessionCapture {
  session_id: string;
  issuer_configuration_id: string;
  issuer_identifier: string;
  authorization_server_identifier: string;
  status: string;
  flow: "pre_authorized_code" | "authorization_code";
  credential_offer_mode: CredentialOfferMode;
  credential_configuration_id: string;
  status_list_enabled: boolean;
  status_list_allocation_ids?: string[];
  observed: {
    client_id: ObservedValue<string>;
    redirect_uri: ObservedValue<string>;
    wallet_jwks: {
      observed: boolean;
      source: string | null;
      jwks: { keys: JsonRecord[] } | null;
      observed_proof_header_fields: string[];
    };
    dpop_jwk: {
      observed: boolean;
      source: string | null;
      jwk: JsonRecord | null;
      thumbprint: string | null;
    };
    client_authentication: ClientAuthenticationCapture;
  };
  checks: {
    pkce_present: boolean;
    pkce_valid: boolean;
    state_present: boolean;
    issuer_state_present: boolean;
    proof_jwt_present: boolean;
    proof_attestation_present: boolean;
    proof_jwt_header_jwk_present: boolean;
    key_attestation_verified: boolean;
    nonce_verified: boolean;
    private_key_jwt_present: boolean;
    private_key_jwt_client_id_matches: boolean | null;
    wallet_attestation_present: boolean;
    wallet_attestation_pop_present: boolean;
    wallet_attestation_client_id_matches: boolean | null;
    wallet_attestation_pop_audience_matches: boolean | null;
  };
  events: CaptureEvent[];
  raw?: {
    par_request?: JsonRecord;
    authorization_request?: JsonRecord;
    token_request?: JsonRecord;
    credential_request?: JsonRecord;
    credential_request_raw?: unknown;
    proof_headers?: ProofHeaderCapture[];
    oid4vci_requests?: Oid4vciHttpRequestCapture[];
  };
}

export type OpenId4VpResponseMode = "direct_post" | "direct_post.jwt" | "dc_api" | "dc_api.jwt";

/** JSON Pointer edits applied to one generated message. Writes first, then removals. */
export interface VpRequestMutationEdits {
  /** JSON Pointer to the value written there, including `null` and wrong-typed values. */
  set?: JsonRecord;
  /** JSON Pointers whose member is removed entirely, which `set` with `null` does not do. */
  unset?: string[];
}

/**
 * Deliberate, test-only edits to the wallet-facing Authorization Request. The targets are kept
 * apart because a test may require the same parameter to differ between the outer request and the
 * signed Request Object.
 */
export interface VpRequestMutation {
  /** Deeplink query parameters, or the DC API `data` member. */
  outer_request?: VpRequestMutationEdits;
  /** Signed Request Object payload. */
  request_object?: VpRequestMutationEdits;
  /** Signed Request Object JOSE header. */
  request_object_header?: VpRequestMutationEdits;
  /**
   * Whether the caller still expects normal presentation verification to succeed. Recorded as
   * evidence, never enforced: the verifier keeps verifying against the message it generated.
   */
  verification_applies?: boolean;
}

/** A deliberately wrong HTTP response from the Request URI endpoint. */
export interface VpRequestUriResponseBehavior {
  status?: number;
  content_type?: string;
  body?: string;
}

/**
 * Test-only request-delivery behaviours that are not payload values, so a JSON Pointer edit
 * cannot express them.
 */
export interface VpRequestBehavior {
  /** Deliver a Request Object whose signature does not verify. */
  signature?: "corrupt";
  /**
   * How the POST Request URI flow answers the `wallet_nonce` the Wallet supplied. `echo` is the
   * normal behaviour and the default when the member is absent.
   */
  wallet_nonce?: "echo" | "mismatch" | "omit";
  /** Serve the Request URI with a specific status, media type, or body. */
  request_uri_response?: VpRequestUriResponseBehavior;
}

/**
 * Test-only control over the HTTP response the verifier returns after receiving an Authorization
 * Response. It changes only what the Wallet is told; the recorded verification outcome is
 * unaffected.
 */
export interface VpResponseScenario {
  status?: number;
  content_type?: string;
  /** Exact response body, replacing the normal JSON body. */
  body?: string;
  /** Members merged into the normal JSON body, for an unrecognised response parameter. */
  extra_parameters?: JsonRecord;
}

export type VpDcApiProtocol = "openid4vp-v1-signed" | "openid4vp-v1-unsigned";

/** Browser invocation request handed to `navigator.credentials.get({ digital: { requests } })`. */
export interface VpDcApiRequest {
  protocol: VpDcApiProtocol;
  data: JsonRecord;
}

/**
 * Why a DC API presentation produced no Authorization Response. A wallet refusal and an End-User
 * cancellation both surface as a `DOMException` with deliberately sparse detail, so `rejected`
 * records what the browser reported without claiming which of the two occurred.
 */
export type VpDcApiInvocationOutcome = "api_unavailable" | "rejected" | "no_vp_token" | "failed";

export interface VpDcApiInvocationCapture {
  at: string;
  outcome: VpDcApiInvocationOutcome;
  error_name?: string;
  error_message?: string;
  response_returned: boolean;
  vp_token_present: boolean;
  reported_origin?: string;
}

export interface VpDcApiCapture {
  request: VpDcApiRequest;
  /** Origin the presentation page is served from; the wallet binds its response to it. */
  expected_origin: string;
  expires_at: string;
  invocation?: VpDcApiInvocationCapture;
}

export interface VpSessionCapture {
  session_id: string;
  status: string;
  request_delivery: "by_reference" | "by_value" | "plain";
  response_mode: OpenId4VpResponseMode;
  /**
   * The verifier's own view of the request. When a `request_mutation` is applied this stays the
   * generated message, and the mutated copy delivered to the wallet is in
   * `raw.authorization_request_delivered`.
   */
  authorization_request: JsonRecord;
  decoded_presentations?: JsonRecord;
  deeplink: string;
  /** Redirect-only members. A DC API session has no request_uri, response_uri, or wallet scheme. */
  request_uri_method?: string;
  request_uri?: string;
  deeplink_scheme?: string;
  response_uri?: string;
  redirect_uri?: string;
  redirect_uri_visited_at?: string;
  redirect_uri_visit_count?: number;
  /** Present only for the `dc_api` and `dc_api.jwt` response modes. */
  dc_api?: VpDcApiCapture;
  /** Present when the wallet-facing request was deliberately mutated for an FCAF scenario. */
  request_mutation?: VpRequestMutation;
  /** Present when a test-only request-delivery behaviour was selected. */
  request_behavior?: VpRequestBehavior;
  /** Present when the HTTP response returned to the wallet is deliberately test-controlled. */
  response_scenario?: VpResponseScenario;
  observed: {
    request_uri_payload: ObservedValue<JsonRecord>;
    wallet_response: ObservedValue<JsonRecord>;
  };
  checks: {
    presentation_valid: boolean | null;
    vp_token_format_valid: boolean;
    nonce_verified: boolean;
    holder_binding_verified: boolean;
    dcql_query_matched: boolean;
    errors: string[];
  };
  events: CaptureEvent[];
  raw?: {
    authorization_request?: JsonRecord;
    authorization_request_jwt?: string;
    /** The mutated Request Object payload actually signed and delivered, when it differs. */
    authorization_request_delivered?: JsonRecord;
    /** Deeplink query parameters, or DC API `data`, as delivered to the wallet. */
    outer_request_delivered?: JsonRecord;
    request_uri_http?: RequestUriHttpCapture;
    /** The HTTP response the Request URI endpoint actually served to the wallet. */
    request_uri_response_http?: VerifierResponseHttpCapture;
    presentation_response?: JsonRecord;
    presentation_response_http?: PresentationResponseHttpCapture;
    presentation_response_verifier_http?: VerifierResponseHttpCapture;
    redirect_uri_visits?: RedirectUriVisitHttpCapture[];
    presentation_response_decrypted?: JsonRecord;
    decoded_presentations?: JsonRecord;
    presentation_response_raw?: string;
    /** The browser's report that the DC API invocation yielded no Authorization Response. */
    dc_api_invocation_http?: PresentationResponseHttpCapture;
  };
}

export interface CredoIssuanceOffer {
  credential_offer: string;
  credential_offer_object: JsonRecord;
  credential_offer_uri: string;
  credo_issuance_session_id: string;
}
