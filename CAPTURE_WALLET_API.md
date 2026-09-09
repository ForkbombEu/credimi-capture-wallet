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
| `request_uri_method` | `get`, `post` | `get` |
| `client_id_scheme` | `x509_hash`, `x509_san_dns`, `decentralized_identifier`, `redirect_uri` | `x509_hash` |
| `request_delivery` | `by_reference`, `by_value`, `plain` | `by_reference` |
| `response_type` | `vp_token`, `vp_token id_token`, `code` | `vp_token` |
| `response_mode` | `direct_post`, `direct_post.jwt` | `direct_post.jwt` |
| `presentation_request` | Request-object claim overrides | — |
| `dcql_query` | DCQL query object, or `null` to omit the parameter | Default query |
| `scopes` | A string or string array | — |
| `transaction_data` | JSON value | — |
| `verifier_info` | JSON value | — |
| `client_metadata` | Object to replace verifier metadata, or `null` to omit it | Generated verifier metadata |
| `redirect_uri` | Absolute URI for the Wallet to open after a successful presentation | — |

`request_uri_method` is valid only with `request_delivery: "by_reference"`. `by_value` supplies a signed Request Object in `request`; `plain` supplies the Authorization Request's URL-encoded parameters directly in the deeplink and omits `request`, `request_uri`, and `request_uri_method`. `response_type`, top-level DCQL, scopes, transaction data, and verifier information are used to construct the wallet-facing request. Inspect the returned `authorization_request` to confirm the exact claims.

`client_id_scheme: "x509_san_dns"` signs the request with the existing verifier certificate and uses its DNS Subject Alternative Name as the Client Identifier value. `client_id_scheme: "decentralized_identifier"` signs with a separate `did:web` key and publishes its DID Document at `/openid4vp/did.json`. `client_id_scheme: "redirect_uri"` creates an unsigned request and therefore requires `request_delivery: "plain"`; signed and by-reference delivery are rejected. The default remains the certificate hash prefix, `x509_hash`.

When `dcql_query` is `null`, the service omits it from the wallet-facing request. Credo retains the normal default query only as internal verification-session state; a wallet response to this deliberately incomplete request may not validate.

If `client_metadata` is absent, the service uses its generated metadata. An object replaces it; `null` omits the parameter entirely. Omission is intentionally limited to `direct_post`. For `direct_post.jwt`, a replacement must retain the generated verifier encryption JWK so the service can decrypt the response; a replacement without that key is rejected rather than weakening response encryption.

The `201` response includes `session_id`, delivery and response settings, `request_uri`, `response_uri`, `deeplink`, `authorization_request`, and `status: "created"`.

When `redirect_uri` is supplied, the service appends a fresh 128-bit `response_code` query parameter and returns the resulting URI in the session-creation response. After a successful wallet submission, the response endpoint returns `200`, `Cache-Control: no-store`, and `{ "redirect_uri": "..." }`; the Wallet must redirect the user agent to it. Invalid presentations retain the normal `400` error response.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/openid4vp/did.json` | Verifier `did:web` Document used by `client_id_scheme: "decentralized_identifier"`. |
| `GET` | `/openid4vp/sessions/{sessionId}` | Full current presentation capture. |
| `GET` | `/openid4vp/sessions/{sessionId}/deeplink` | `{ deeplink, authorization_request }`; records a deeplink event. |
| `GET` | `/openid4vp/sessions/{sessionId}/events` | Chronological presentation events. |

### Wallet-facing request and response endpoints

| Method | Path | Input | Result |
| --- | --- | --- | --- |
| `GET` | `/openid4vp/sessions/{sessionId}/request` | — | Signed request object with media type `application/oauth-authz-req+jwt`; marks the request as retrieved. |
| `POST` | `/openid4vp/sessions/{sessionId}/request` | Form payload; `wallet_nonce` is recognized and other fields are captured | Signed request object. Use only for a session with `request_uri_method: post`. |
| `POST` | `/openid4vp/sessions/{sessionId}/response` | Form-encoded wallet response | Captures and verifies the response for that session. `200` means valid; `400` returns `invalid_presentation` and verification errors. |
| `POST` | `/openid4vp/response` | Form-encoded wallet response with required `state` | Alternative direct-post endpoint; `state` selects the session. |

Raw form payloads are preserved in the presentation capture for fidelity. Treat them as sensitive evidence.

The session record additionally exposes `raw.presentation_response_http` for machine processing. It contains the received HTTP `method`, the headers with sensitive values redacted, and the exact received body. `raw.presentation_response_verifier_http` captures the verifier reply's status, redacted headers, and exact body. Both are retained for valid and invalid responses and are intentionally not shown as dedicated fields in the operator UI.

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
| `GET` | `/favicon.svg` |
| `GET` | `/assets/style.css` |
| `GET` | `/assets/credimi_logo.svg` |
| `GET` | `/assets/credimi_logo_negative.svg` |
| `GET` | `/assets/credimi_logo-transp.svg` |
| `GET` | `/assets/credimi_logo-transp_white.svg` |

GUI routes can be disabled with the service configuration; disabling them does not disable API or protocol routes.

## Keeping this reference current

When the public contract changes, update this file and `src/openapi.ts` in the same change. Add or update route-level tests for every changed protocol, metadata, or security boundary. For exact schemas, error objects, and media types, consult `/openapi.json` and the relevant OpenID specification.
