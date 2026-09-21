# Capture Wallet API reference

The Capture Wallet service is a stateful [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) credential issuer and [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) verifier. It issues deterministic PID and degree test credentials and captures wallet protocol evidence per session.

This is a companion to the machine-readable [OpenAPI document](/openapi.json). The OpenAPI document and the applicable OpenID specifications are authoritative for wire-level details. Use the issuer metadata rather than hard-coding credential configuration IDs, endpoints, or keys.

## Base URL and conventions

The base URL is configured by `--issuer-base-url`; production uses `https://capture-wallet.credimi.io`. Paths below are relative to that URL.

- Issuer configuration IDs are `eu-pid-device-bound` and `eu-pid-jwt-proof-only`.
- `sessionId` is a UUID returned by a session-creation response.
- JSON is the default representation unless a route states another media type.
- Unknown session IDs return `404` with an error object. Invalid protocol input normally returns `400`.
- Session and event responses are evidence records: their `observed`, `checks`, `raw`, and event `detail` members can grow as the service captures more protocol information. Do not rely on undocumented members.
- Never store access tokens, DPoP proofs, credential offers containing pre-authorized codes, or raw presentation payloads in logs or fixtures.

## Service and discovery

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Readiness response: `{ "status": "ok" }`. |
| `GET` | `/openapi.json` | OpenAPI 3.1 contract for the public REST and protocol surface. |
| `GET` | `/docs` | Interactive API documentation. |
| `GET` | `/issuers` | Lists the always-on issuer configurations, metadata URLs, warnings, and credential configuration IDs. |
| `GET` | `/oid4vci/requests` | Bounded chronological OpenID4VCI request ledger. Sensitive fields are redacted to presence/length metadata. |

For each `{issuerConfigurationId}`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/.well-known/openid-credential-issuer/issuers/{issuerConfigurationId}` | OpenID4VCI credential issuer metadata. Send `Accept: application/jwt` for signed metadata; JSON is the default. |
| `GET` | `/.well-known/oauth-authorization-server/issuers/{issuerConfigurationId}` | OAuth authorization-server metadata for the issuer. |
| `GET` | `/.well-known/jwt-vc-issuer/issuers/{issuerConfigurationId}` | JWT VC issuer metadata. |
| `GET` | `/issuers/{issuerConfigurationId}/jwks.json` | Authorization-server signing JWKS. |
| `GET` | `/issuers/{issuerConfigurationId}/credential-jwks.json` | Credential-signing JWKS. |

## OpenID4VCI issuance capture

### Create and inspect a session

`POST /sessions` creates an issuance session. Its optional JSON body is:

| Field | Values | Default |
| --- | --- | --- |
| `issuer_configuration_id` | `eu-pid-device-bound`, `eu-pid-jwt-proof-only` | `eu-pid-device-bound` |
| `flow` | `pre_authorized_code`, `authorization_code` | `authorization_code` |
| `credential_offer_mode` | `credential_offer`, `credential_offer_uri` | `credential_offer` |
| `credential_configuration_id` | A configuration advertised by the selected issuer metadata | First configuration for the issuer |
| `status_list_enabled` | Boolean; allocate and embed a Token Status List reference in each issued credential | `false` |

It returns `201` with `session_id`, issuer and authorization-server identifiers, the selected flow and configuration, `offer_url`, `deeplink`, and `status: "created"`. A configuration belonging to another issuer is rejected.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/sessions/{sessionId}` | Full current issuance capture, including status, observed information, checks, and events. |
| `GET` | `/sessions/{sessionId}/offer` | Credential Offer object. Returns `409` while no offer is available. |
| `GET` | `/sessions/{sessionId}/deeplink` | `{ deeplink, credential_offer }`; records a deeplink-generation event. |
| `GET` | `/sessions/{sessionId}/jwks` | Verified wallet holder-binding JWKS. Returns `409` until a holder key has been observed. |
| `GET` | `/sessions/{sessionId}/events` | Chronological issuance events (`at`, `type`, `detail`). |

### Issuer protocol endpoints

| Method | Path | Required input | Result |
| --- | --- | --- | --- |
| `GET` | `/issuers/{issuerConfigurationId}/offers/{credentialOfferId}` | Credential-offer ID from an offer-by-reference deeplink | Credential Offer object. |
| `POST` | `/issuers/{issuerConfigurationId}/par` | DPoP header; form `response_type=code`, `client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method=S256`; optional `issuer_state`, `state` | `201` with `request_uri` and `expires_in`. |
| `GET` | `/issuers/{issuerConfigurationId}/authorize` | Query `client_id` and `request_uri` | Starts the auto-approved authorization-code flow with redirects. |
| `GET` | `/issuers/{issuerConfigurationId}/redirect` | Chained OAuth callback parameters | Redirects back to the wallet with the issuer authorization code. |
| `POST` | `/issuers/{issuerConfigurationId}/token` | DPoP header plus either pre-authorized-code or authorization-code form grant | DPoP-bound access token, expiry, credential nonce, and nonce expiry. |
| `POST` | `/issuers/{issuerConfigurationId}/nonce` | No body | Fresh `c_nonce`. |
| `POST` | `/issuers/{issuerConfigurationId}/credential` | `Authorization: DPoP …`, DPoP header, and a Credential Request | Credential response containing `credentials[].credential`. |

The token endpoint accepts either:

- `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` and `pre-authorized_code`, with optional `tx_code`; or
- `grant_type=authorization_code`, `code`, `code_verifier`, and `redirect_uri`, with optional `client_id`.

The credential request normally uses `application/json` with `credential_configuration_id` and one `proofs.jwt` or `proofs.attestation` entry. For encrypted credential requests, send an `application/jwt` compact JWE; the encrypted response is also a compact JWE. The selected issuer's metadata determines supported proof and encryption capabilities.

## OpenID4VP presentation capture

### Create and inspect a session

`POST /openid4vp/sessions` creates a verifier session. Its optional JSON body accepts:

| Field | Values / shape | Default |
| --- | --- | --- |
| `scheme` | URL-scheme prefix, such as `openid4vp://` | `openid4vp://` |
| `request_uri_method` | Any string; OpenID4VP defines case-sensitive `get`, `post` | `get` |
| `client_id_scheme` | `x509_hash`, `x509_san_dns`, `decentralized_identifier`, `redirect_uri` | `x509_hash` |
| `request_delivery` | `by_reference`, `by_value`, `plain` | `by_reference` |
| `response_type` | `vp_token`, `vp_token id_token`, `code` | `vp_token` |
| `response_mode` | `direct_post`, `direct_post.jwt`, `dc_api`, `dc_api.jwt` | `direct_post.jwt` |
| `presentation_request` | Request-object claim overrides | — |
| `dcql_query` | DCQL query object, or `null` to omit the parameter | Default query |
| `scopes` | A string or string array | — |
| `transaction_data` | JSON value | — |
| `verifier_info` | JSON value | — |
| `client_metadata` | Object whose members override generated verifier metadata, or `null` to omit the parameter; top-level only | Generated verifier metadata |
| `redirect_uri` | Absolute URI for the Wallet to open after a successful presentation; use `{{base_url}}/openid4vp/redirect` for a capture redirect page | — |
| `allow_undecryptable_response` | `true` to publish a `client_metadata` object that omits the verifier encryption key | `false` |

`request_uri_method` is valid only with `request_delivery: "by_reference"`. The service preserves any supplied string in the deeplink, including values other than the OpenID4VP-defined, case-sensitive `get` and `post`, exclusively to create malformed requests for wallet negative tests. `by_value` supplies a signed Request Object in `request`; `plain` supplies the Authorization Request's URL-encoded parameters directly in the deeplink and omits `request`, `request_uri`, and `request_uri_method`. `response_type`, top-level DCQL, scopes, transaction data, and verifier information are used to construct the wallet-facing request. Inspect the returned `authorization_request` to confirm the exact claims.

`scheme`, `request_uri_method`, `client_id_scheme`, `request_delivery`, `response_mode`, `client_metadata`, and `redirect_uri` are top-level fields only. They select how the service builds, signs, and delivers the request instead of being request-object claims, so nesting any of them inside `presentation_request` has no effect and is not reported as an error. In particular, a `client_metadata` value inside `presentation_request` is discarded and the generated verifier metadata is used. Only `response_type`, `dcql_query`, `nonce`, `scopes`, `transaction_data`, and `verifier_info` are honoured in both positions, and a top-level `response_type` wins over a nested one.

`client_id_scheme: "x509_san_dns"` signs the request with the existing verifier certificate and uses its DNS Subject Alternative Name as the Client Identifier value. `client_id_scheme: "decentralized_identifier"` signs with a separate `did:web` key and publishes its DID Document at `/openid4vp/did.json`. `client_id_scheme: "redirect_uri"` creates an unsigned request and therefore requires `request_delivery: "plain"`; signed and by-reference delivery are rejected. The default remains the certificate hash prefix, `x509_hash`.

When `dcql_query` is `null`, the service omits it from the wallet-facing request. Credo retains the normal default query only as internal verification-session state; a wallet response to this deliberately incomplete request may not validate.

If `client_metadata` is absent, the service uses its generated metadata. `null` omits the parameter entirely, which is intentionally limited to `direct_post`.

An object overrides individual members of the generated metadata rather than replacing the whole object. A member you supply wins, a member you omit keeps its generated value, and a member set to `null` is dropped from the wallet-facing request. The merge is one level deep, so supplying `jwks` replaces the entire key set instead of editing individual JWK members. This is how the advertised response encryption is narrowed for wallet tests that require a specific JWE `enc`:

```json
{ "response_mode": "direct_post.jwt",
  "client_metadata": { "encrypted_response_enc_values_supported": ["A128GCM"] } }
```

The generated `jwks` and `vp_formats_supported` survive that request untouched, so the Wallet has exactly one content-encryption choice and the service still decrypts the response.

For `direct_post.jwt`, the merged metadata must still publish the session's generated verifier encryption public key. Keys are compared by RFC 7638 thumbprint, which covers the public key material only, so optional JOSE members such as `alg`, `use`, and `kid` may be altered or omitted. Because that key is minted inside the same `POST /openid4vp/sessions` call that returns it, a caller cannot reproduce it: omit `jwks` to keep it, and expect `invalid_client_metadata` when `jwks` is replaced or set to `null` without the flag below.

`allow_undecryptable_response: true` waives that check and publishes the supplied `jwks` verbatim, including a foreign or static key. It exists only to build requests that no wallet should answer, such as advertising a key the Verifier does not hold, omitting the key entirely, or reusing one key across sessions. The service can then no longer decrypt a `direct_post.jwt` response, and a wallet that answers anyway is captured as a decryption failure. It requires a `client_metadata` object and is otherwise rejected with `allow_undecryptable_response_requires_client_metadata`. Whenever a `direct_post.jwt` request goes out without the verifier encryption key, the session records a `vp_undecryptable_response_allowed` event.

The `201` response includes `session_id`, delivery and response settings, `deeplink`, `authorization_request`, and `status: "created"`. A redirect session also includes `request_uri`, `request_uri_method`, `response_uri`, and `scheme`; a DC API session omits those and includes `dc_api_request` instead.

When `redirect_uri` is supplied, the service appends a fresh 128-bit `response_code` query parameter and returns the resulting URI in the session-creation response. After a successful wallet submission, the response endpoint returns `200`, `Cache-Control: no-store`, and `{ "redirect_uri": "..." }`; the Wallet must redirect the user agent to it. Invalid presentations retain the normal `400` error response. The exact template `{{base_url}}/openid4vp/redirect`, or the equivalent concrete service URI, creates a service-hosted capture page. It displays the received `response_code` for both valid and invalid visits. A valid visit must include the generated `response_code`; it returns a `200` confirmation page and records `redirect_uri_visited_at`, `redirect_uri_visit_count`, a `vp_redirect_uri_visited` event, and redacted request headers in `raw.redirect_uri_visits`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/openid4vp/did.json` | Verifier `did:web` Document used by `client_id_scheme: "decentralized_identifier"`. |
| `GET` | `/openid4vp/sessions/{sessionId}` | Full current presentation capture. |
| `GET` | `/openid4vp/sessions/{sessionId}/deeplink` | `{ deeplink, authorization_request }`; records a deeplink event. |
| `GET` | `/openid4vp/sessions/{sessionId}/events` | Chronological presentation events. |
| `GET` | `/openid4vp/redirect?response_code=...` | Service-hosted capture redirect page created from the `redirect_uri` template. |

### Digital Credentials API presentation

`response_mode: "dc_api"` or `"dc_api.jwt"` presents over the W3C Digital Credentials API, as
defined in OpenID4VP 1.0 Appendix A. The response mode alone selects the flow; there is no
separate transport field.

`request_delivery` decides how the request reaches the browser rather than how it reaches a
wallet: `by_value` — the default for DC API — produces a signed Request Object carrying `client_id`
and `expected_origins`, `plain` produces unsigned request parameters with neither, and
`by_reference` is rejected with `request_delivery_unsupported_for_dc_api`.
`client_id_scheme: "redirect_uri"` is rejected with `client_id_scheme_unsupported_for_dc_api`
because a signed DC API request requires a `client_id`, and `request_uri_method` is rejected with
`request_uri_method_unsupported_for_dc_api`. A DC API request carries no `request_uri`,
`request_uri_method`, `response_uri`, `redirect_uri`, `state`, or `aud`.

`dc_api_request` in the `201` response is the browser invocation payload:

```json
{
  "deeplink": "https://capture-wallet.credimi.io/ui/openid4vp/sessions/sess_123/dc_api_presentation",
  "dc_api_request": {
    "protocol": "openid4vp-v1-signed",
    "data": { "request": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLC..." }
  }
}
```

Pass it as one entry of `navigator.credentials.get({ digital: { requests: [ ... ] } })`. For
`plain` delivery the protocol is `openid4vp-v1-unsigned` and `data` holds the Authorization
Request parameters themselves.

`deeplink` keeps its field name and string type, but for DC API it is the HTTPS URL of this
service's presentation page rather than a wallet invocation URL. It is built from the configured
public base URL (`PUBLIC_BASE_URL`, defaulting to `issuer_base_url`) and never from a request
`Host` header. The operator UI renders the usual QR code for it; scanning that code opens a
webpage, and the wallet is invoked only from the button press on that page.

| Method | Path | Input | Result |
| --- | --- | --- | --- |
| `GET` | `/ui/openid4vp/sessions/{sessionId}/dc_api_presentation` | — | Unauthenticated presentation page carrying only this session's `dc_api_request`. Requires `GUI_ENABLED`. |
| `POST` | `/openid4vp/sessions/{sessionId}/response` | The wallet's Authorization Response as JSON or form | Same endpoint as the redirect flows, with no `state` required. |
| `POST` | `/openid4vp/sessions/{sessionId}/dc_api_invocation` | `outcome` plus optional `error_name`, `error_message`, `response_returned`, `vp_token_present` | `202` and `{ "status": "dc_api_invocation_reported" }`; records why the invocation produced no Authorization Response. |

`outcome` is one of `api_unavailable`, `rejected`, `no_vp_token`, or `failed`, and is captured
under `dc_api.invocation` together with the reported `DOMException` name and message, whether a
response object came back, whether it contained a `vp_token`, and the browser `Origin`. This is
the evidence a HAIP wallet leaves when it refuses the unencrypted `dc_api` response mode, and it
is deliberately distinct from a verification failure over a real response: `checks` stays
untouched and the session status becomes `dc_api_invocation_reported`. A wallet refusal and an
End-User cancellation are indistinguishable through the browser API, so `rejected` records what
the browser reported without asserting which occurred.

DC API verification is origin-bound: the expected SD-JWT VC Key Binding JWT audience is
`origin:<origin>` and the mdoc session transcript uses the `OpenID4VPDCAPIHandover` over the bare
origin, the request nonce, and — only for `dc_api.jwt` — the thumbprint of the verifier's
response-encryption key. The origin is the session's configured one; a submission whose `Origin`
header disagrees is refused with `403 unexpected_dc_api_origin`.

A DC API presentation window lasts 10 minutes. A submission after the first captured presentation
is refused with `409 vp_session_already_completed`, and one after the window closes with
`400 vp_session_expired`. `GET` and `POST /openid4vp/sessions/{sessionId}/request` return
`404 vp_request_uri_not_available_for_dc_api`, so a DC API session never records a request_uri
retrieval. Redirect sessions keep their existing behaviour, including recording repeated wallet
submissions.

### Wallet-facing request and response endpoints

| Method | Path | Input | Result |
| --- | --- | --- | --- |
| `GET` | `/openid4vp/sessions/{sessionId}/request` | — | Signed request object with media type `application/oauth-authz-req+jwt`; marks the request as retrieved. |
| `POST` | `/openid4vp/sessions/{sessionId}/request` | Form payload; `wallet_nonce` is recognized and other fields are captured | Signed request object. Use only for a session with `request_uri_method: post`. |
| `POST` | `/openid4vp/sessions/{sessionId}/response` | Form-encoded wallet response | Captures and verifies the response for that session. `200` means valid; `400` returns `invalid_presentation` and verification errors. |
| `POST` | `/openid4vp/response` | Form-encoded wallet response with required `state` | Alternative direct-post endpoint; `state` selects the session. |

Raw form payloads are preserved in the presentation capture for fidelity. Treat them as sensitive evidence.

The session record additionally exposes `raw.authorization_request_jwt`, the exact signed Request Object returned to the Wallet, and `raw.request_uri_http`, the Wallet's Request URI retrieval method, headers with sensitive values redacted, and exact POST body when received. `raw.presentation_response_http` contains the received presentation response HTTP `method`, headers with sensitive values redacted, and exact body. `raw.presentation_response_verifier_http` captures the verifier reply's status, redacted headers, and exact body. The HTTP envelopes are retained for valid and invalid responses and are intentionally not shown as dedicated fields in the operator UI.

## Test-only chained OAuth server

The authorization-code issuance flow uses an internal, auto-approving OAuth server between Credo and the issuer. These are test-service endpoints, not a general-purpose identity provider.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/.well-known/oauth-authorization-server/authorization-servers/{issuerConfigurationId}` | Metadata for the fake OAuth server. |
| `GET` | `/authorization-servers/{issuerConfigurationId}/authorize` | Validates Credo's authorization request and immediately redirects with a code. |
| `POST` | `/authorization-servers/{issuerConfigurationId}/token` | Exchanges the chained code. Requires the configured client credentials, PKCE verifier, redirect URI, and client ID. |

## Browser-only routes

These routes support the server-rendered operator UI. They are not a stable programmatic contract; use the API routes above for integrations.

| Method | Path |
| --- | --- |
| `GET` | `/` |
| `GET` | `/ui/help` |
| `POST` | `/ui/sessions` |
| `GET` | `/ui/sessions/{sessionId}` |
| `POST` | `/ui/openid4vp/sessions` |
| `GET` | `/ui/openid4vp/sessions/{sessionId}` |
| `GET` | `/ui/openid4vp/sessions/{sessionId}/dc_api_presentation` |
| `GET` | `/favicon.svg` |
| `GET` | `/assets/style.css` |
| `GET` | `/assets/credimi_logo.svg` |
| `GET` | `/assets/credimi_logo_negative.svg` |
| `GET` | `/assets/credimi_logo-transp.svg` |
| `GET` | `/assets/credimi_logo-transp_white.svg` |

GUI routes can be disabled with the service configuration; disabling them does not disable API or protocol routes.

## Keeping this reference current

When the public contract changes, update this file and `src/openapi.ts` in the same change. Add or update route-level tests for every changed protocol, metadata, or security boundary. For exact schemas, error objects, and media types, consult `/openapi.json` and the relevant OpenID specification.
