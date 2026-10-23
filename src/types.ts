export type JsonRecord = Record<string, unknown>;
export type CredentialOfferMode = "credential_offer" | "credential_offer_uri";

/** URL scheme of the Credential Offer deeplink. `openid-credential-offer://` is the default. */
export type CredentialOfferScheme =
  | "openid-credential-offer://"
  | "eu-eaa-offer://"
  | "haip-vci://";

/**
 * How much of the Wallet's OpenID4VCI traffic an issuance session keeps. `redacted` is the default
 * and the only form the global request ledger ever holds. `full` keeps the protocol material FCAF
 * evaluation needs in clear in that session's own capture, still redacting the bearer secrets
 * that would let a reader act as the Wallet: tokens, codes, `tx_code`, `code_verifier`, and the
 * `Authorization`, `DPoP`, and cookie headers.
 */
export type EvidenceMode = "redacted" | "full";

export interface StatusListReference {
  uri: string;
  idx: number;
}

/** A reference the Status List service allocated for one issued credential. */
export interface StatusListAllocation extends StatusListReference {
  /** The idempotency key sent to `/token_status_list/take`, `<session_id>:<credential index>`. */
  allocation_id: string;
}

/** Outcome of one `/token_status_list/set` call. `http_status` is null when no response came. */
export interface StatusListUpdateResult extends StatusListReference {
  /** Token Status List value requested: `1`, revoked. */
  status: number;
  ok: boolean;
  http_status: number | null;
  /** The Status List service's response body, as received. */
  response_body?: string;
  /** Transport failure, such as a timeout or refused connection. */
  error?: string;
}

/** One `POST /sessions/{sessionId}/status` request and the per-reference results. */
export interface StatusListUpdateCapture {
  at: string;
  requested_status: "revoked";
  results: StatusListUpdateResult[];
}

/**
 * Shape of the `status` claim in an issued credential. `valid` is the normal Token Status List
 * reference; the others are the deliberately malformed structures the revocation-metadata tests
 * require, and are refused unless the deployment enables FCAF scenarios. The `uri_*` shapes keep
 * `idx` and derive `uri` from the allocated one, breaking a single RFC 3986 rule each.
 */
export type StatusReferenceFixture =
  | "valid"
  | "status_without_status_list"
  | "negative_index"
  | "missing_index"
  | "malformed_uri"
  | "missing_uri"
  | "uri_missing_scheme"
  | "uri_space_in_host"
  | "uri_invalid_percent_encoding"
  | "uri_illegal_characters"
  | "uri_empty";

/**
 * Hash function an issued SD-JWT VC digests its disclosures with, placed in the `_sd_alg` claim.
 * SD-JWT VC Section 4.1.1 defaults an absent `_sd_alg` to `sha-256`; the other values produce a
 * credential a Wallet can only present if it supports that hash function, which is what the
 * cryptographic-hash tests check. `sha-1` is excluded: SD-JWT requires a hash function that is
 * secure at the time of issuance.
 */
export type SdJwtDigestAlgorithm = "sha-256" | "sha-384" | "sha-512";

/**
 * X.509 chain presented in the `x5c` header of a signed Request Object for a test scenario.
 * `with_trust_anchor` keeps the deployed leaf and appends the operator-configured CA certificate;
 * the others replace the chain with generated certificates.
 */
export type RequestCertificateFixture =
  | "unrelated_self_signed"
  | "untrusted_root"
  | "incomplete_chain"
  | "with_trust_anchor";

/** Key, and optional certificate chain, a Request Object is signed with. */
export interface RequestSigningMaterial {
  privateJwk: JsonRecord;
  x5c?: string[];
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

/** One request header field exactly as received, before Node merges repeated fields. */
export interface RawHttpHeader {
  name: string;
  /** The received value, or presence and length metadata when the header is a bearer secret. */
  value: string | JsonRecord;
}

export interface RawHttpBody {
  /** The declared `Content-Type` header, as sent. */
  content_type: string | null;
  /** The exact body bytes, base64-encoded; empty when the request had no body. */
  base64?: string;
  /** The text of an `application/jwt` body. */
  text?: string;
  /**
   * Set for a token request, whose body is described rather than kept: it carries the codes and
   * PKCE verifier that `full` evidence still redacts. `length` is its size in bytes.
   */
  redacted?: true;
  length?: number;
}

export interface Oid4vciHttpRequestCapture {
  id: string;
  at: string;
  method: string;
  path: string;
  session_id: string | null;
  issuer_configuration_id: string | null;
  /** Present when no configured issuer resource or other route matched, and the response was 404. */
  unmatched?: true;
  headers: JsonRecord;
  /**
   * Occurrences of each header field, keyed by lower-case name and counted from the raw header
   * list. Node joins repeated fields into one value, so `headers` cannot show that a field was
   * sent more than once.
   */
  header_counts: Record<string, number>;
  /** `full` evidence only: every header field in received order, with its original name casing. */
  raw_headers?: RawHttpHeader[];
  /** `full` evidence only: the body of a PAR, token, or Credential Request as received. */
  raw_body?: RawHttpBody;
  query: unknown;
  body: unknown;
  response: {
    status: number | null;
    content_type: string | null;
    /**
     * The delivered body: JSON redacted by the capture's rules, anything else reduced to presence
     * and length. Absent when the response had no body.
     */
    body?: unknown;
  };
}

export interface PresentationResponseHttpCapture {
  method: string;
  headers: JsonRecord;
  body: string;
}

export interface RequestUriHttpCapture {
  method: string;
  /**
   * Request target (path and query) as received by this service, which is after any reverse
   * proxy: a proxy that rewrites the path or query changes what is recorded here.
   */
  target: string;
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

/** A compact JWT exactly as received, with its header and payload decoded but never verified. */
export interface JwtEvidence {
  compact: string;
  header: JsonRecord | null;
  payload: JsonRecord | null;
  error: string | null;
}

export interface ProofJwtEvidence extends JwtEvidence {
  /** Where the JWT sits in the Credential Request, such as `proofs.jwt[0]`. */
  source: string;
  /** The Key Attestation in a `jwt` proof's `key_attestation` JOSE header, when it is a string. */
  key_attestation?: JwtEvidence;
}

/** The proofs of one Credential Request, as received and before Credo-TS verifies them. */
export interface CredentialRequestProofsCapture {
  /** `id` of the request's `raw.oid4vci_requests` entry. */
  request_id: string;
  at: string;
  /** The `proofs` member exactly as received, with its JSON types; absent when there was none. */
  proofs?: unknown;
  /** Each string in `proofs.jwt`, or `proofs.jwt` itself when it is a string. */
  jwt: ProofJwtEvidence[];
  /** Each Key Attestation string in `proofs.attestation`, or the member itself when a string. */
  attestation: ProofJwtEvidence[];
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
  /**
   * Predefined claim set the issued credential carries. Absent means the baseline identity, which
   * is what every session issued before this field existed used.
   */
  fixture_id?: string;
  /**
   * Shape of the `status` claim in the issued credential. Absent means the normal reference, so
   * a session that does not ask for a malformed structure cannot receive one.
   */
  status_reference?: StatusReferenceFixture;
  /**
   * Hash function the issued SD-JWT VC digests its disclosures with. Absent means `sha-256`, the
   * Section 4.1.1 default, which is what every session issued before this field existed used.
   */
  digest_algorithm?: SdJwtDigestAlgorithm;
  /**
   * Present, as `full`, only when the session keeps unredacted evidence. Absent means `redacted`,
   * which is what every session created before this field existed kept.
   */
  evidence_mode?: "full";
  /**
   * Present when the HTTP responses of this session's PAR or Credential endpoint are deliberately
   * test-controlled. Credo-TS still handles the request; only what the Wallet receives changes.
   */
  issuance_response_scenario?: IssuanceResponseScenario;
  /** Scheme of the delivered offer deeplink. Absent means `openid-credential-offer://`. */
  offer_scheme?: CredentialOfferScheme;
  /**
   * Present when the by-value Credential Offer delivered in the deeplink was deliberately edited
   * for an FCAF scenario. `raw.credential_offer` keeps the generated offer and
   * `raw.credential_offer_delivered` the edited one.
   */
  offer_mutation?: VpRequestMutationEdits;
  status_list_allocation_ids?: string[];
  /**
   * The reference allocated for each issued credential, at the credential's index. This is the
   * real allocation even when `status_reference` reshaped what the credential carries.
   */
  status_list_references?: StatusListAllocation[];
  /** Every `POST /sessions/{sessionId}/status` call, in order. */
  status_list_updates?: StatusListUpdateCapture[];
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
    /**
     * `full` evidence only: the latest Credential Request's proofs, recorded when the request
     * arrives, so a proof Credo-TS rejects is kept too.
     */
    credential_request_proofs?: CredentialRequestProofsCapture;
    oid4vci_requests?: Oid4vciHttpRequestCapture[];
    /** With `offer_mutation` only: the Credential Offer Credo-TS generated. */
    credential_offer?: JsonRecord;
    /** With `offer_mutation` only: the edited Credential Offer delivered in the deeplink. */
    credential_offer_delivered?: JsonRecord;
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
/**
 * Content of the Verifier Attestation JWT delivered in the Request Object's `jwt` JOSE header.
 * Each member breaks one of the bindings a wallet checks, so a test can present an attestation
 * whose only defect is the one it is about.
 */
export interface VpVerifierAttestation {
  /** Attestation `sub`. Differs from the Client Identifier only to test that binding. */
  subject?: string;
  /** Attestation `iss`, for an issuer outside the wallet's trusted list. */
  issuer?: string;
  /**
   * `redirect_uris` claim. Omitted entirely when absent, which a wallet must not enforce. An
   * entry equal to `{{response_uri}}` is replaced by the session's own `response_uri`.
   */
  redirect_uris?: string[];
  /** Additional attestation claims, merged last. */
  claims?: JsonRecord;
  /** Breaks the attestation signature while leaving its content intact. */
  signature?: "corrupt";
}

export interface VpRequestBehavior {
  /** Deliver a Request Object whose signature does not verify. */
  signature?: "corrupt";
  /**
   * Sign the Request Object with a key that is not the one bound to the advertised client
   * identifier, leaving the certificate or DID document itself untouched.
   */
  signing_key?: "unrelated";
  /**
   * Present a different X.509 chain in `x5c`. The request stays validly signed by that chain's
   * leaf key, so the chain is the only defect. For `with_trust_anchor` the defect is the trust
   * anchor itself: the deployed leaf, followed by the configured CA certificate that issued it,
   * which a Wallet must not accept inside `x5c`.
   */
  certificate_chain?: RequestCertificateFixture;
  /**
   * How the POST Request URI flow answers the `wallet_nonce` the Wallet supplied. `echo` is the
   * normal behaviour and the default when the member is absent.
   */
  wallet_nonce?: "echo" | "mismatch" | "omit";
  /** Serve the Request URI with a specific status, media type, or body. */
  request_uri_response?: VpRequestUriResponseBehavior;
  /**
   * Serve the signed Request Object unencrypted even when the Wallet's POST Request URI
   * `wallet_metadata` supplied encryption keys, so a Wallet that requires encryption receives a
   * plain JWS.
   */
  request_object_encryption?: "none";
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

/**
 * Test-only control over one issuer endpoint's HTTP response, applied at the HTTP boundary after
 * Credo-TS has produced the real response.
 */
export interface IssuanceEndpointResponseScenario extends VpResponseScenario {
  /** JSON Pointers removed from the normal JSON body, after `extra_parameters` are merged. */
  omit_parameters?: string[];
}

export interface IssuanceResponseScenario {
  par?: IssuanceEndpointResponseScenario;
  credential?: IssuanceEndpointResponseScenario;
}

export type VpDcApiProtocol =
  | "openid4vp-v1-signed"
  | "openid4vp-v1-multisigned"
  | "openid4vp-v1-unsigned";

/**
 * How the request reaches the Wallet. `multisigned` is a DC API JWS JSON Serialization request
 * signed under more than one Client Identifier (OpenID4VP Appendix A.3.2.2).
 */
export type VpRequestDelivery = "by_reference" | "by_value" | "plain" | "multisigned";

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

/**
 * Which `wallet_metadata` list a Request Object encryption algorithm was taken from: the
 * `request_object_encryption_*` member, the `authorization_encryption_*` fallback, or neither, in
 * which case the default (`ECDH-ES` with `A128GCM`) applies.
 */
export type RequestObjectEncryptionSource =
  | "request_object"
  | "authorization_encryption"
  | "default";

/** How the Request Object served from a POST Request URI was encrypted, and why. */
export interface VpRequestObjectEncryptionCapture {
  alg: "ECDH-ES";
  enc: string;
  /** `kid` of the Wallet key the Request Object was encrypted to, when it had one. */
  kid: string | null;
  alg_source: RequestObjectEncryptionSource;
  enc_source: RequestObjectEncryptionSource;
}

export interface VpSessionCapture {
  session_id: string;
  status: string;
  request_delivery: VpRequestDelivery;
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
  /**
   * Present when `verifier_attestation` content was supplied: the content actually signed into the
   * attestation, with `{{response_uri}}` already replaced by the session's `response_uri`.
   */
  verifier_attestation?: VpVerifierAttestation;
  /** Present once a Request Object was served encrypted; the latest POST Request URI wins. */
  request_object_encryption?: VpRequestObjectEncryptionCapture;
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
    /**
     * Section 8.4 transaction data binding. Null when the request sent no transaction data, or
     * when the presentation format's binding is not checked by this verifier.
     */
    transaction_data_verified: boolean | null;
    errors: string[];
  };
  events: CaptureEvent[];
  raw?: {
    authorization_request?: JsonRecord;
    authorization_request_jwt?: string;
    /**
     * The encrypted Request Object served to the Wallet when its POST Request URI
     * `wallet_metadata` supplied an encryption key. `authorization_request_jwt` is the signed JWT
     * it encloses.
     */
    authorization_request_jwe?: string;
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
