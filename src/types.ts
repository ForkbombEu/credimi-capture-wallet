export type JsonRecord = Record<string, unknown>;

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

export interface ProofHeaderCapture {
  typ?: string;
  alg?: string;
  kid?: string;
  jwk?: JsonRecord;
  x5c?: string[];
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
  credential_configuration_id: string;
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
    proof_jwt_header_jwk_present: boolean;
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
    credential_request_raw?: string;
    proof_headers?: ProofHeaderCapture[];
  };
}

export interface ParRecord {
  request_uri: string;
  expires_at: number;
  params: JsonRecord;
}

export interface AuthorizationCode {
  code: string;
  session_id: string;
  client_id: string | null;
  redirect_uri: string | null;
  code_challenge: string | null;
  code_challenge_method: string | null;
  state: string | null;
  expires_at: number;
  used: boolean;
}

export interface AccessToken {
  token: string;
  session_id: string;
  expires_at: number;
}
