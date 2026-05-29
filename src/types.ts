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

export interface SessionCapture {
  session_id: string;
  status: string;
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
  };
  checks: {
    pkce_present: boolean;
    pkce_valid: boolean;
    state_present: boolean;
    issuer_state_present: boolean;
    proof_jwt_present: boolean;
    proof_jwt_header_jwk_present: boolean;
    nonce_verified: boolean;
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
