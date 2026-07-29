export type JsonRecord = Record<string, unknown>;
export type CredentialOfferMode = "credential_offer" | "credential_offer_uri";

export interface AppConfig {
  issuer_base_url: string;
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
  headers: JsonRecord;
  query: unknown;
  body: unknown;
  response: {
    status: number | null;
    content_type: string | null;
  };
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
  status: string;
  flow: "pre_authorized_code" | "authorization_code";
  credential_offer_mode: CredentialOfferMode;
  credential_configuration_id: string;
  broken: boolean;
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

export interface VpSessionCapture {
  session_id: string;
  status: string;
  request_delivery: "by_reference" | "by_value";
  request_uri_method: "get" | "post";
  response_mode: "direct_post" | "direct_post.jwt";
  authorization_request: JsonRecord;
  decoded_presentations?: JsonRecord;
  request_uri: string;
  deeplink_scheme: string;
  deeplink: string;
  response_uri: string;
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
    presentation_response?: JsonRecord;
    presentation_response_decrypted?: JsonRecord;
    decoded_presentations?: JsonRecord;
    presentation_response_raw?: string;
  };
}

export interface CredoIssuanceOffer {
  credential_offer: string;
  credential_offer_object: JsonRecord;
  credential_offer_uri: string;
  credo_issuance_session_id: string;
}
