<div align="center">

<img
    src="https://raw.githubusercontent.com/ForkbombEu/credimi-capture-wallet/refs/heads/master/src/design/logo/credimi_logo.svg"
    alt="credimi logo"
    height="48"/>

# Credimi Capture Wallet Metadata <!-- omit in toc -->

### Use credimi test issuer and verifier to get a PID and verify it capturing metadata and calls during the process. <!-- omit in toc -->

</div>

<br>


During the credential issue the service captures:
- Holder-binding public key from proof headers: `wallet_jwks`
- DPoP public key when present: `dpop_jwk`
- Redacted request headers and bodies for every OpenID4VCI endpoint call

During the credential verification the service captures:
- Verifier request object sent to the wallet: `authorization_request`
- Wallet payload when request_uri_method is post: `request_uri_payload`
- Wallet presentation response: `wallet_response`
- Raw wallet presentation HTTP envelope: `raw.presentation_response_http` (method, headers with sensitive values redacted, and exact received body)
- Raw signed presentation request object: `raw.authorization_request_jwt`
- Raw wallet `request_uri` retrieval envelope: `raw.request_uri_http` (method, headers with sensitive values redacted, and exact received POST body when present)
- Raw verifier HTTP response: `raw.presentation_response_verifier_http` (status, headers with sensitive values redacted, and exact response body)
- Decrypted wallet presentation response: `presentation_response_decrypted` (useful when response_mode is set to `direct_post.jwt`)
- Decoded claims from verified presentations: `decoded_presentations`
- Verifier checks for nonce, holder binding, transaction data binding, and DCQL matching: `presentation_validation`

<br>

---

<div id="toc">

### 🚩 Table of contents <!-- omit in toc -->

- [🚀 Quick Start](#-quick-start)
- [🏗️ Run your services](#️-run-your-services)
- [📡 Hosted REST API](#-hosted-rest-api)
  - [📖 API documentation](#-api-documentation)
  - [🪪 OpenID4VCI Issuance Flow](#-openid4vci-issuance-flow)
  - [🛂 OpenID4VP Presentation Flow](#-openid4vp-presentation-flow)
- [⚙️ Configuration](#️-configuration)
- [🚧 Known limitations](#-known-limitations)
- [💼 License](#-license)

</div>

---

## 🚀 Quick Start

Visit https://capture-wallet.credimi.io/ and start issuing and verifying PID in dc+sd-jwt and mdoc format.

Once you have chosen an issuer and credential format:
* Click on `New fake-issuance session` to open an OpenID4VCI QR session. Scan the QR with an EUDI Wallet. The session page updates as Wallet metadata, proof keys, DPoP keys, checks, and flow events are observed.
* Click on `New presentation session` to open an OpenID4VP QR session. The QR contains a presentation request for the credentials supported by this issuer. The page updates when the Wallet retrieves the request and posts the presentation response.


**[🔝 back to top](#toc)**

---

## 🏗️ Run your services

To run your own issuer and verifier:

```sh
pnpm install
cp env.example .env

# create services keys and metadata
pnpm capture-services init \
  --services-base-url https://issuer.example.test \
  --data-dir ./data \
  --credential-configuration-id urn:eu.europa.ec.eudi:pid:1

# start the services
pnpm dev
```

The default local service URL is `http://localhost:8080`. Both issuers are always
started below its `/issuers/` prefix. You can select your port using

```sh
PORT=22000 pnpm dev
```

**[🔝 back to top](#toc)**

---

## 📡 Hosted REST API

### 📖 API documentation

The interactive API reference is available at `$BASE_URL/docs`. It uses Stoplight Elements and loads the live OpenAPI 3.1 document from `$BASE_URL/openapi.json`. The reference covers every public REST and OpenID4VCI/OpenID4VP protocol endpoint; the browser-only operator form routes under `/ui` are intentionally excluded.

Common REST API endpoints are:
* Health: `/healthz`
* Issuer catalogue: `/issuers`
* Credential Issuer well-known:
  `/.well-known/openid-credential-issuer/issuers/{issuerConfigurationId}`
* Authorization server well-known:
  `/.well-known/oauth-authorization-server/issuers/{issuerConfigurationId}`
* Auto-approving chained OAuth server well-known:
  `/.well-known/oauth-authorization-server/authorization-servers/{issuerConfigurationId}`
* Authorization Server JWKS: `/issuers/{issuerConfigurationId}/jwks.json`
* Credential-signing JWKS: `/issuers/{issuerConfigurationId}/credential-jwks.json`

The Credential Issuer well-known endpoint returns unsigned JSON by default. Request
the OpenID4VCI 1.0 signed form with:
```sh
curl "$BASE_URL/.well-known/openid-credential-issuer/issuers/eu-pid-device-bound" \
  -H 'Accept: application/jwt'
```
The response is a compact JWS with media type `application/jwt`, protected type
`openidvci-issuer-metadata+jwt`, and the issuer certificate chain in `x5c`.
Because the Credential Issuer also provides the Authorization Server, its metadata
omits `authorization_servers` and uses the Credential Issuer identifier for discovery.
The Authorization Server metadata advertises public-client and optional Wallet
Attestation client authentication with
`token_endpoint_auth_methods_supported: ["none", "attest_jwt_client_auth"]`.
Both the Wallet Attestation and its proof of possession advertise `ES256` as their
supported signing algorithm.
Credo-TS verifies the `OAuth-Client-Attestation` and
`OAuth-Client-Attestation-PoP` headers when supplied; anonymous pre-authorized Token
Requests remain supported.
When a request supplies both a Client Attestation PoP and DPoP, Credo validates the
proofs independently and permits their keys to differ, as required by
[OAuth 2.0 Attestation-Based Client Authentication draft 10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-10#section-7).
The DPoP combined client-authentication method is not advertised.
The pinned Credo-TS/OpenID4VC stack accepts the OpenID4VCI 1.0 Wallet Attestation PoP
claim set, where `exp` is optional. Signature, audience, time, client,
proof-of-possession key, and certificate checks remain handled by Credo-TS.
When initialized with issuer encryption material, the metadata also advertises optional
Credential Request and Credential Response encryption using `ECDH-ES` and `A256GCM`.
The service runs two Credo-TS issuer records at all times. Each has its own identifier,
authorization server, chained auto-approving OAuth server, signing and encryption
keys, access-token key, and certificate:

| Issuer configuration ID | Credential issuer | Advertised proof policy |
| --- | --- | --- |
| `eu-pid-device-bound` | `/issuers/eu-pid-device-bound` | `jwt` and `attestation`, both with `key_attestations_required: {}` |
| `eu-pid-jwt-proof-only` | `/issuers/eu-pid-jwt-proof-only` | `jwt` without a key-attestation requirement |

The device-bound issuer is the default. The JWT-proof-only issuer is deliberately
non-conforming for a device-bound EUDI PID and exists for interoperability testing.
The legacy root issuer no longer exists.

### 🪪 OpenID4VCI Issuance Flow

> [!IMPORTANT]
> BASE_URL must be the `--services-base-url` you set during the setup, to use our hosted services use `https://capture-wallet.credimi.io`


The configured `--credential-configuration-id` is the base for four PID Credential
Configuration Identifiers. Each issuer additionally offers a fixed degree test
credential configuration for DCQL textual-encoding conformance cases:

| Issuer | Format | Configuration ID and scope suffix | Credential type |
| --- | --- | --- | --- |
| `eu-pid-device-bound` | SD-JWT VC | `.sd-jwt.key-attestation-required` | `vct: urn:eudi:pid:1` |
| `eu-pid-device-bound` | mdoc | `.mdoc.key-attestation-required` | `doctype: eu.europa.ec.eudi.pid.1` |
| `eu-pid-jwt-proof-only` | SD-JWT VC | `.sd-jwt.jwt-proof` | `vct: urn:eudi:pid:1` |
| `eu-pid-jwt-proof-only` | mdoc | `.mdoc.jwt-proof` | `doctype: eu.europa.ec.eudi.pid.1` |
| `eu-pid-device-bound` | SD-JWT VC | `urn:credimi:degree:1.sd-jwt.key-attestation-required` | `vct: urn:credimi:degree:1` |
| `eu-pid-jwt-proof-only` | SD-JWT VC | `urn:credimi:degree:1.sd-jwt.jwt-proof` | `vct: urn:credimi:degree:1` |

Each PID configuration has a unique scope formed by appending the same suffix to the
configured credential scope. The degree configurations use the fixed scopes shown in
the table. The duplicated configurations issue the same credential type and claims and
retain the same `vct` or `doctype`; only the issuer and proof policy differ. The
device-bound issuer and its key-attestation-required SD-JWT PID configuration are
selected when their request fields are omitted.

Start by creating a capture session for a credential configuration:

```sh
curl -X POST "$BASE_URL/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "issuer_configuration_id":"eu-pid-device-bound",
    "credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.key-attestation-required"
  }'
```

Status List references are opt-in per issuance session. The default keeps issued
credentials free of a `status` claim; request allocation and embedding explicitly:

```sh
curl -X POST "$BASE_URL/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.key-attestation-required",
    "status_list_enabled":true
  }'
```

When enabled, the issuer allocates one `(uri, idx)` reference per output
credential from the configured debug Status List service. Allocation failure stops
issuance rather than silently issuing an untracked credential. Configure the
Status List endpoint in the generated service config with
`status_list_base_url`, `status_list_api_key`, and `status_list_timeout_ms`.
`STATUS_LIST_BASE_URL` and `STATUS_LIST_API_KEY` environment variables override the
configured endpoint and management key at runtime.
The management API key is server-side only and is never included in a credential,
offer, browser response, or capture log.
`status_reference` is optional and shapes the `status` claim of an issued SD-JWT VC. `valid`, the
default, embeds the allocated Token Status List reference. The other values produce the
deliberately malformed structures the FCAF revocation-metadata tests require — `status` without a
`status_list` member, a negative or missing `idx`, and a malformed or missing `uri` — and are
refused unless the deployment sets `FCAF_SCENARIOS_ENABLED=true`. They also require
`status_list_enabled: true`, because the reference is always allocated normally first and the
fixture only reshapes that real allocation. A credential with no `status` claim at all is simply
`status_list_enabled: false`.

The malformed structures are not available for mdoc configurations, and the request is refused
rather than silently ignored: an mdoc `status` claim is built by `@owf/token-status-list` through
Credo, whose schema requires a non-negative integer `idx` and a string `uri`, so the COSE variants
of those tests cannot be produced without a non-Credo COSE implementation. See
[Known limitations](#known-limitations).

`issuer_configuration_id` is optional and accepts `eu-pid-device-bound` or
`eu-pid-jwt-proof-only`. A credential configuration must belong to the selected
issuer; the service rejects cross-issuer combinations.

`flow` is optional and defaults to `authorization_code`, whose authorization is
handled by Credo-TS through the service's auto-approving chained OAuth server. Set it
to `pre_authorized_code` to issue a pre-authorized offer instead.

`credential_offer_mode` is optional and defaults to `credential_offer`, which embeds
the Credential Offer JSON directly in the `deeplink`. Set it to
`credential_offer_uri` to make the `deeplink` refer to the hosted `offer_url` instead;
this can keep a QR code smaller when the offer is large.

`fixture_id` is optional and selects which predefined PID claim set the issued credential
carries; it defaults to `pid_default`. Every fixture is a fully valid, normally signed PID, and
no caller-supplied claim override exists, so an issued credential always corresponds to a named
fixture a test can reference. The fixtures differ from the baseline along one value axis each,
which is what the FCAF DCQL value-matching cases need: a query constraining that axis matches the
baseline and withholds the fixture.

| `fixture_id` | Differs from the baseline by |
| --- | --- |
| `pid_default` | — the baseline Mario Rossi identity, `age_over_18: true` |
| `pid_person_b` | A second complete identity: Giulia Bianchi, Milano, other document number |
| `pid_under_18` | `age_over_18: false` and a 2012 `birthdate` |
| `pid_family_name_uppercase` | `family_name` `"ROSSI"` — letter case |
| `pid_family_name_trailing_space` | `family_name` `"Rossi "` — trailing whitespace |
| `pid_locality_diacritics` | Locality `"München"` |
| `pid_locality_no_diacritics` | Locality `"Munchen"` — the same value without its umlaut |
| `pid_multiple_nationalities` | `nationalities` `["FR", "DE"]` — array cardinality |
| `pid_expiry_2032` | `date_of_expiry` `"2032-01-01"` — an upper-bound boundary |

Each fixture also carries a distinct `document_number`, so two credentials issued from different
fixtures are never byte-identical. Issue one session per fixture to give a Wallet several
credentials of the same type. [FCAF_FIXTURES.md](FCAF_FIXTURES.md) catalogues every fixture with
the conformance tests it serves and the ones that remain unavailable, and
[REMAINING_WORK.md](REMAINING_WORK.md) tracks the conformance capabilities this service still owes.
The PID attribute `age_over_18` exists in both the SD-JWT VC and the
mdoc encoding so that a DCQL query can constrain it.

Both issuers issue the same deterministic PID claims for the PID
configurations. The degree test credential is an SD-JWT VC for Arthur Dent with
`degrees` (including an entry without `type`) and `academic_programmes`, a nested
array of awarded programme titles. The interiors of `address` and of both arrays are
individually disclosable: each `address` member is its own disclosure, each `degrees`
entry is its own disclosure with `type` and `university` separate inside it, and each
`academic_programmes` inner array and each string inside
it is disclosable by index. A Wallet can therefore reveal `address.locality` alone, or
`degrees[0..1].type` while
withholding `degrees[2].university`, which is what the FCAF textual-encoding cases
assert. It supports DCQL paths such as
`["degrees", null, "type"]` and `["academic_programmes", null, 1]`. The removed legacy root issuer and its `broken`
credential fixture are no longer available.

To request an encrypted Credential Response, include `credential_response_encryption`
with a public JWK whose `alg` is `ECDH-ES` and set `enc` to `A256GCM`. OpenID4VCI 1.0
requires the containing Credential Request to also be encrypted: send it as an
`application/jwt` compact JWE using the public key from
`credential_request_encryption.jwks` in the issuer metadata. The response is an
`application/jwt` compact JWE. Plain JSON requests and responses remain supported when
response encryption is not requested.

A successful response returns HTTP 201 and includes:
```json
{
  "session_id": "...",
  "issuer_configuration_id": "eu-pid-device-bound",
  "issuer_identifier": "https://capture-wallet.credimi.io/issuers/eu-pid-device-bound",
  "authorization_server_identifier": "https://capture-wallet.credimi.io/issuers/eu-pid-device-bound",
  "flow": "authorization_code",
  "credential_offer_mode": "credential_offer",
  "credential_configuration_id": "urn:eu.europa.ec.eudi:pid:1.mdoc.key-attestation-required",
  "offer_url": "https://capture-wallet.credimi.io/issuers/eu-pid-device-bound/offers/...",
  "deeplink": "openid-credential-offer://...",
  "status": "created"
}
```

Open or transmit the returned `deeplink` to the Wallet under test. With the default
`credential_offer` mode, the Wallet reads the offer directly from the deeplink. With
`credential_offer_uri`, it first retrieves the hosted offer. The `offer_url` remains
available in both modes for capture diagnostics and manual inspection.

By default, the offer contains the `authorization_code` grant. The Wallet uses the
scope advertised for the offered Credential Configuration and returns the offer's
`issuer_state` in its Authorization Request. Credo requires PAR, S256 PKCE, and DPoP
for this flow. Opening Credo's `/authorize` endpoint redirects to
`/authorization-servers/{issuerConfigurationId}/authorize`; that issuer-specific test
server immediately approves every valid request and redirects to the matching
`/issuers/{issuerConfigurationId}/redirect` callback. Credo exchanges the external
one-time code, then immediately redirects to the Wallet's registered `redirect_uri`
with a separate Credo authorization code. The Wallet exchanges that code at the
matching issuer's `/token` endpoint and continues with the nonce and credential
requests.

The fake OAuth server is deliberately not an authentication or consent system. It has
one issuer-specific internal client, accepts only that issuer's exact callback URI,
requires S256 PKCE, and issues short-lived single-use codes. Authorization codes,
clients, and scopes are isolated between issuers. Its access token is consumed only
by Credo and is never accepted at the Credential Endpoint. Do not use this
auto-approval mechanism as a production authorization policy.

For a Pre-Authorized Code offer:

```sh
curl -X POST "$BASE_URL/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "issuer_configuration_id":"eu-pid-device-bound",
    "flow":"pre_authorized_code",
    "credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.key-attestation-required"
  }'
```

This offer contains the
`urn:ietf:params:oauth:grant-type:pre-authorized_code` grant. The Wallet exchanges the
pre-authorized code directly at the token endpoint, then calls the nonce and
credential endpoints.

Each issuer's `/credential` endpoint accepts exactly one proof type per request:

* A `.jwt-proof` configuration accepts `proofs.jwt`, containing one
  `openid4vci-proof+jwt` value signed by its public `header.jwk`. It does not
  require `header.key_attestation` and does not support the `attestation` proof type.
* A `.key-attestation-required` configuration accepts `proofs.jwt[0]` only when its
  `header.key_attestation` is a valid `key-attestation+jwt` that attests the
  proof-signing key. It also accepts `proofs.attestation[0]` containing one
  `key-attestation+jwt`; the issued credential is bound to the public keys in
  `attested_keys`.

Both forms require the current issuer nonce and `ES256`. Key-attestation signatures
and X.509 chains are verified through Credo-TS. This capture service accepts the last
certificate supplied in the attestation `x5c` chain as that chain's trust anchor; it
does not implement a production Wallet Provider trust list or the `kid` and
`trust_chain` attestation trust mechanisms, and does not resolve optional attestation
status information.

The wallet-facing pre-authorized and Authorization Code OpenID4VCI protocol paths are
owned by the Credo-TS issuer agent: credential offers, PAR, PKCE, authorization-code
and token issuance, DPoP, nonce and proof validation, holder binding, and SD-JWT VC or
MDOC signing. The narrowly scoped fake OAuth server only provides the chained,
auto-approved external authorization step. Express middleware records redacted
evidence.
The credential request/response encryption adapter remains narrowly scoped around
Credo's `/credential` handler because the installed Credo-TS router does not expose
that encryption extension.

For each session you can get different information:
* deeplink:
  ```sh
  curl "$BASE_URL/sessions/{sessionId}/deeplink"
  ```
* Normalized capture object:
  ```sh
  curl "$BASE_URL/sessions/{sessionId}"
  ```
* Event evidence for debugging or conformance records:
  ```sh
  curl "$BASE_URL/sessions/{sessionId}/events"
  ```
* Redacted HTTP evidence for every OpenID4VCI protocol request:
  ```sh
  curl "$BASE_URL/oid4vci/requests"
  ```
  Correlatable requests are also included under `raw.oid4vci_requests` in the
  normalized session capture. DPoP, pre-authorized-code, access-token, JWT proof,
  client-attestation, and other secret values are replaced with presence and length
  metadata. The service-wide ledger retains the latest 1,000 requests.
* Captured Wallet holder-binding JWKS after the Wallet has called `/credential` with a
  proof JWT `header.jwk` or a direct attestation `attested_keys` entry:
  ```sh
  curl "$BASE_URL/sessions/{sessionId}/jwks"
  ```
  If the JWKS is not ready, the service returns HTTP 409 with
  `wallet_jwks_not_observed`. Inspect the session object and event evidence for the
  rejected proof details.

### 🛂 OpenID4VP Presentation Flow

> [!IMPORTANT]
> BASE_URL is the `--services-base-url` you set during the setup, to use our hosted services use `https://capture-wallet.credimi.io`

Create a presentation session:
```sh
curl -X POST "$BASE_URL/openid4vp/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "request_uri_method":"post",
    "request_delivery":"by_reference",
    "response_type":"vp_token",
    "response_mode":"direct_post.jwt",
    "presentation_request": {
      "nonce": "external-nonce",
      "dcql_query": {
        "credentials": [
          {
            "id": "credential",
            "format": "mso_mdoc",
            "meta": {
              "doctype_value": [
                "eu.europa.ec.eudi.pid.1"
              ]
            },
            "claims": [
              {
                "path": [
                  "eu.europa.ec.eudi.pid.1",
                  "family_name"
                ]
              }
            ]
          }
        ]
      }
    }
  }'
```
Where:
* `request_uri_method` defaults to `get`. OpenID4VP defines case-sensitive `get` and `post`; any supplied string is preserved in a by-reference deeplink only for wallet negative tests, allowing deliberately malformed requests.
* `client_id_scheme` can be `x509_hash` (default), `x509_san_dns`, `decentralized_identifier`, `verifier_attestation`, or `redirect_uri`. `x509_san_dns` uses the verifier certificate and its DNS SAN. `decentralized_identifier` uses the verifier's `did:web` document at `/openid4vp/did.json`. `verifier_attestation` signs with the same request key but publishes no certificate, carrying instead a Verifier Attestation JWT in the request object's `jwt` JOSE header. `redirect_uri` creates an unsigned request and therefore requires `request_delivery: "plain"`.

#### Verifier attestations

With `client_id_scheme: "verifier_attestation"`, the Client Identifier is `verifier_attestation:<subject>` and the attestation JWT in the `jwt` header binds three things a Wallet checks separately: its `sub` equals the Client Identifier after the prefix, its `cnf.jwk` is the key that signed the request object, and its `iss` names the attestation issuer. The issuer is a fixture key generated beside the other verifier material, and its public key is served at `/openid4vp/verifier-attestation-issuer/jwks.json` so an operator can configure a Wallet to trust it. By default the attestation carries no `redirect_uris` claim, which is the case where a Wallet must not enforce a redirect URI match.

The optional `verifier_attestation` object changes the attestation content, one binding at a time:

| Member | Effect |
| --- | --- |
| `subject` | Attestation `sub`. The Client Identifier keeps the real subject, so the two disagree. |
| `issuer` | Attestation `iss`, for an issuer outside the Wallet's trusted list. |
| `redirect_uris` | Adds the `redirect_uris` claim, matching or not matching the request's redirect URI. |
| `claims` | Additional attestation claims, merged last. |
| `signature: "corrupt"` | Breaks the attestation signature, leaving the request object validly signed. Requires `FCAF_SCENARIOS_ENABLED`. |

#### Verifier info attestations

`verifier_info` is delivered exactly as supplied. OpenID4VP Section 5.11 leaves the format and semantics of these attestations to ecosystems and profiles — in the EUDI ecosystem the concrete type is the Relying Party Registration Certificate — so this service signs none of its own and delivers what the caller provides.

A key-bound attestation has to bind its proof of possession to the request's `nonce` and `client_id`, both of which a caller can fix in advance:

1. `GET /openid4vp/client-identifiers` returns the Client Identifier this verifier presents under each prefix.
2. Choose the `nonce` and sign the attestation and its proof of possession over that `nonce` and the Client Identifier, in the structure the profile under test defines.
3. Create the session with the same `nonce` and the whole `verifier_info` array:

```json
{"presentation_request": {"nonce": "<chosen nonce>", "verifier_info": [{"format": "jwt", "data": "<attestation>", "proof_of_possession": "<proof over nonce and client_id>"}]}}
```

Omitting the `nonce` or the `client_id` from the proof, breaking either signature, or declaring a format no profile defines are all differences in what the caller signs, so each is a change to that payload rather than a control on this service.

Two related cases need nothing new: a request object signed with a key that does not match `cnf` is `request_behavior: {"signing_key": "unrelated"}`, and a missing attestation is `request_mutation` unsetting `/jwt` in the request object header.
* `request_delivery` can be `by_reference`, `by_value`, or `plain`, default is `by_reference`. `plain` puts URL-encoded Authorization Request parameters directly in the deeplink, without `request` or `request_uri`; it cannot be combined with `request_uri_method`.
* `response_type` can be `vp_token` or `vp_token id_token` or `code`, but during presentation verification only `vp_token` is supported, default is `vp_token`
* `response_mode` selects the presentation flow. `direct_post` and `direct_post.jwt` are the redirect-based flows, default is `direct_post.jwt`. `dc_api` and `dc_api.jwt` present over the W3C Digital Credentials API instead; see [Digital Credentials API presentation](#digital-credentials-api-presentation).
* `dcql_query` may be `null` to omit the parameter entirely from the wallet-facing Authorization Request. The default query remains only in Credo's internal verifier session.
* `client_metadata` may be an object whose members override the generated verifier metadata, or `null` to omit the parameter. Omission is supported only with `direct_post`. A supplied member wins, an omitted member keeps its generated value, and a member set to `null` is dropped. The merge is one level deep, so supplying `jwks` replaces the whole key set. Narrow the advertised response encryption with `"client_metadata": {"encrypted_response_enc_values_supported": ["A128GCM"]}` to give the Wallet a single JWE `enc` choice; the generated `jwks` and `vp_formats_supported` are preserved, so the service still decrypts. For `direct_post.jwt` the merged metadata must keep the session's generated encryption public key, compared by RFC 7638 thumbprint so `alg`, `use`, and `kid` may be altered or omitted. That key is minted inside the same call that returns it, so omit `jwks` to keep it.
* `allow_undecryptable_response` is a test-only flag. With `true` the service publishes a `jwks` that is not the verifier's encryption key, which is what wallet response-encryption negative tests need: a JWK without `alg`, with an `alg` other than `ECDH-ES`, `"jwks": null` to advertise no key at all, or a static key reused across sessions. The service can then no longer decrypt a response, and a wallet that answers anyway is captured as a decryption failure. It requires a `client_metadata` object. Any `direct_post.jwt` request sent without the verifier encryption key records a `vp_undecryptable_response_allowed` event.
* `request_mutation` is a test-only object that deliberately edits the wallet-facing Authorization Request. It is refused unless the deployment sets `FCAF_SCENARIOS_ENABLED=true`. See [Deliberate request mutations](#deliberate-request-mutations).
* `request_behavior` is a test-only object selecting a request-delivery behaviour that is not a payload value, currently `{"signature":"corrupt"}`. It is refused unless the deployment sets `FCAF_SCENARIOS_ENABLED=true`.
* `redirect_uri` is an optional absolute URI returned to the Wallet after a successful presentation. The service appends a fresh 128-bit `response_code` parameter to it. Use `{{base_url}}/openid4vp/redirect`, or its equivalent concrete service URI, to create a service-hosted confirmation page; it displays the received `response_code` for both valid and invalid visits, and a valid visit is recorded in the VP session capture.
* `scheme` is the complete custom URL-scheme prefix for the deeplink (for example, `eudi-wallet://`); it defaults to `openid4vp://`

Optional `scopes`, `transaction_data`, and `verifier_info` values can be supplied at the top level or within `presentation_request`. `scopes` accepts a string or an array of strings and is emitted as the standard space-delimited `scope` authorization-request parameter.

OpenID4VP Section 5.1 lets a request carry a `scope` value representing a DCQL Query instead of the query itself. Combine `scopes` with `dcql_query: null` to send one:

```json
{"scopes": "eu.europa.ec.eudi.pid.1", "presentation_request": {"dcql_query": null}}
```

The scope value is the caller's to choose, because it is resolved by the Wallet's profile rather than by anything the Verifier sends; this service does not define scope values of its own, since an invented one would be recognised by no Wallet. The query is omitted from the wallet-facing request only: the Verifier keeps its query and matches the Authorization Response against it, so a presentation returned for a scope-only request is still verified. `session.authorization_request` shows the query the Verifier kept and `raw.authorization_request_delivered` shows the request the Wallet received without it. Sending `scopes` together with a `dcql_query` delivers both, which is the conflicting-parameter case a Wallet is expected to reject. `verifier_info` is included unchanged in the signed request object.

`transaction_data` is an array whose entries OpenID4VP Section 5.1 carries as base64url-encoded JSON strings. An entry supplied as an object is encoded, so a caller writes the entry it wants a Wallet to read:

```json
{"transaction_data": [{"type": "qes_authorization", "credential_ids": ["query_0"], "transaction_data_hashes_alg": ["sha-256"]}]}
```

Each decoded SD-JWT VC presentation records `digest_algorithm`, the credential's `_sd_alg` defaulted to `sha-256` when the issuer omitted it. That is the digest algorithm a Wallet had to support to present the credential at all, and it does not appear among the disclosed claims. A Verifier that wants to use a hash function other than SHA-256 without advertising it declares one in a transaction data entry's `transaction_data_hashes_alg`.

When a Wallet presents, `checks.transaction_data_verified` records the Section 8.4 binding: `true` when the presentation was accepted, `false` when it was rejected with `invalid_transaction_data`, and `null` when the request sent no transaction data or the presentation failed for an unrelated reason. Credo-TS performs the check against the request object this service signed, so a Wallet must return a hash of each base64url-encoded entry that applies to the Credential it presents, computed with an algorithm that entry offered.

Any other entry, a string included, is delivered exactly as supplied, so an entry that is deliberately not decodable stays expressible. The array itself is never rewritten: a `transaction_data` value that is not an array is passed through untouched, and a [request mutation](#deliberate-request-mutations) on `/transaction_data` replaces the whole parameter after encoding. This matters for the conformance tests that expect `invalid_transaction_data`: each of those defects — an unknown field, a field of the wrong type, an invalid value, a missing required field, mismatched `credential_ids` — lives inside an entry the Wallet must still be able to decode.

`scheme`, `request_uri_method`, `client_id_scheme`, `request_delivery`, `response_mode`, `client_metadata`, `allow_undecryptable_response`, and `redirect_uri` are top-level parameters only. They configure how the service builds, signs, and delivers the request rather than being request-object claims, so they are ignored when nested inside `presentation_request`. Supplying `client_metadata` inside `presentation_request` leaves the generated verifier metadata in place; the service does not report an error. `response_type` is the one exception, and a top-level value overrides a nested one.

A successful response returns HTTP 201 and includes:

```json
{
  "session_id": "...",
  "request_delivery": "by_reference",
  "request_uri": "$BASE_URL/openid4vp/sessions/.../request",
  "request_uri_method": "post",
  "response_mode": "direct_post.jwt",
  "scheme": "openid4vp://",
  "response_uri": "$BASE_URL/openid4vp/sessions/.../response",
  "deeplink": "openid4vp://...",
  "authorization_request": {
    "client_id": "x509_hash:...",
    "aud": "https://self-issued.me/v2",
    "response_type": "vp_token",
    "response_mode": "direct_post.jwt",
    "state": "..."
  },
  "status": "created"
}
```

The QR deeplink contains `client_id=x509_hash:...` and `request_uri=...`. The request URI returns a signed `application/oauth-authz-req+jwt` request object with `aud=https://self-issued.me/v2` and the verifier certificate in the JWS `x5c` header. By default the verifier uses `direct_post.jwt`, advertises an ephemeral JARM encryption key in `client_metadata.jwks`, captures the posted encrypted response, and stores the decrypted response in the session raw data after validation. Pass `"response_mode":"direct_post"` when creating a session if you need plaintext capture.

In this case for each session you can get:
* deeplink:
  ```sh
  curl "$BASE_URL/openid4vp/sessions/{sessionId}/deeplink"
  ```
* Normalized capture object:
  ```sh
  curl "$BASE_URL/openid4vp/sessions/{sessionId}"
  ```
* Event evidence for debugging or conformance records:
  ```sh
  curl "$BASE_URL/openid4vp/sessions/{sessionId}/events"
  ```

#### Deliberate request mutations

FCAF negative tests need Authorization Requests that are missing a parameter, carry a wrong value,
or contradict themselves. `request_mutation` expresses those variations as data, so a new test
needs no change to this service. It is refused with `request_mutation_not_enabled` unless the
deployment sets `FCAF_SCENARIOS_ENABLED=true`.

```sh
curl -X POST "$BASE_URL/openid4vp/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "request_mutation": {
      "request_object": { "unset": ["/response_uri"], "set": { "/state": null } },
      "request_object_header": { "set": { "/typ": "jwt" } },
      "outer_request": { "set": { "/client_id": "x509_hash:other" } }
    }
  }'
```

Three targets are addressed separately, so a test can make the outer Authorization Request
disagree with the signed Request Object:

| Target | What it edits |
| --- | --- |
| `request_object` | The signed Request Object payload. |
| `request_object_header` | The Request Object JOSE header, for example a missing or wrong `typ`. |
| `outer_request` | The deeplink query parameters, or the DC API `data` member. |

Members are addressed by [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON Pointer, not by a
dotted path, because protocol object keys contain dots and plus signs — the mdoc namespace
`eu.europa.ec.eudi.pid.1` and the credential format `dc+sd-jwt` are both keys. `set` writes a value
of any JSON type, including `null` and a deliberately wrong type; `unset` removes the member
entirely, which is a different wire outcome from `null`. Writes are applied before removals.

A mutation never moves the verifier's own expectations. The request the service generated stays in
`authorization_request` and is what presentation verification uses; the mutated copy is recorded in
`raw.authorization_request_delivered`, the delivered outer parameters in
`raw.outer_request_delivered`, and the applied pointers in a `vp_request_mutation_applied` event.
So a Wallet that answers with the original nonce still verifies even when the Request Object it
received advertised a different one. Set `verification_applies` to record whether the caller
expected verification to succeed; it is captured as evidence and never enforced.

Some variations are not payload values and therefore cannot be a pointer edit. Those are selected
by name through `request_behavior`, which is gated by the same flag and recorded in the capture
alongside a `vp_request_behavior_applied` event:

```sh
curl -X POST "$BASE_URL/openid4vp/sessions" \
  -H 'Content-Type: application/json' \
  -d '{"request_behavior":{"signature":"corrupt"}}'
```

`{"signature":"corrupt"}` delivers a Request Object whose signature does not verify. The request is
signed by the normal Credo path first and the signature value is then invalidated, so the JWS stays
well formed and a Wallet rejects it on the signature rather than on the encoding. The invalid
signature is what the Wallet receives from both `request_uri` retrieval and a `by_value` deeplink,
including after a `wallet_nonce` re-sign, while the verifier keeps the valid request it generated.
It requires a signed request, so it is refused with the `redirect_uri` client identifier prefix.

`{"signing_key":"unrelated"}` signs the Request Object with a key that is not the one bound to the
advertised client identifier, leaving the certificate in `x5c` and the DID document untouched, so
the key-to-identifier mismatch is the only defect.

`{"certificate_chain":"…"}` presents a different X.509 chain in `x5c`. The certificates are
generated through the same Credo X.509 path the service uses for its own material, the request is
signed by that chain's leaf key, and the `x509_hash` Client Identifier is recomputed from the new
leaf — so the chain is the only defect rather than also disagreeing with the identifier. It
requires the `x509_hash` prefix.

| `certificate_chain` | `x5c` |
| --- | --- |
| `unrelated_self_signed` | One self-signed leaf for `unrelated-verifier.invalid` |
| `untrusted_root` | `[leaf, root]` where the root is a generated CA no wallet trusts |
| `incomplete_chain` | `[leaf]` only, whose issuing CA is absent from the chain |

Because the delivered Client Identifier changes, a wallet that answers anyway produces a
presentation bound to it, which then fails audience verification. That is expected: these are
negative scenarios in which no presentation should arrive.

`{"wallet_nonce":"mismatch"}` and `{"wallet_nonce":"omit"}` change how the POST Request URI flow
answers the `wallet_nonce` the Wallet supplied: `mismatch` returns a fresh unrelated value and
`omit` leaves the parameter out. `echo` is the normal behaviour and the default. The received and
returned values are both recorded in the `vp_request_retrieved` event, so an assertion can show
which one the Wallet acted on.

`{"request_uri_response":{"status":404,"content_type":"text/plain","body":"..."}}` serves the
Request URI with a deliberately wrong retrieval response. Every member is optional and defaults to
the normal one. The signed Request Object is still generated and kept in
`raw.authorization_request_jwt`; what the endpoint actually returned is recorded in
`raw.request_uri_response_http`.

#### Verifier response scenarios

Some tests turn on what the verifier answers after the Wallet submits its Authorization Response.
`response_scenario` controls that response and is gated by the same `FCAF_SCENARIOS_ENABLED` flag:

```sh
curl -X POST "$BASE_URL/openid4vp/sessions" \
  -H 'Content-Type: application/json' \
  -d '{"response_scenario":{"status":400,"extra_parameters":{"error":"invalid_request"}}}'
```

`status`, `content_type`, and `body` replace the delivered status, media type, and body;
`extra_parameters` are merged into the normal JSON body, which is how an unrecognised response
parameter or an error member is added. Every member is optional.

The scenario applies at the HTTP boundary only. The recorded verification result, the session
status, and `checks` are unaffected, so a test-selected `400` never marks a valid presentation
invalid and a test-selected `200` never marks an invalid one verified. The response actually
delivered is recorded in `raw.presentation_response_verifier_http`, and the selection in
`response_scenario` with a `vp_response_scenario_selected` event.

#### Digital Credentials API presentation

`"response_mode": "dc_api.jwt"` (encrypted response) or `"dc_api"` (unencrypted) present over the
W3C Digital Credentials API, as defined in OpenID4VP 1.0 Appendix A. No new transport parameter
exists: the response mode alone selects the flow.

A DC API session carries no `request_uri`, `response_uri`, `request_uri_method`, `scheme`, or
`state`, so those members are absent from the 201 response. `request_delivery` keeps its meaning
but now decides how the request reaches the browser: `by_value` (the default for DC API) produces a
signed Request Object, `plain` produces unsigned request parameters, and `by_reference` is
rejected. The `redirect_uri` client identifier prefix is also rejected, because a signed DC API
request requires a `client_id`.

```sh
curl -X POST "$BASE_URL/openid4vp/sessions" \
  -H 'Content-Type: application/json' \
  -d '{"response_mode":"dc_api.jwt"}'
```

```json
{
  "session_id": "sess_123",
  "request_delivery": "by_value",
  "response_mode": "dc_api.jwt",
  "deeplink": "https://capture-wallet.credimi.io/ui/openid4vp/sessions/sess_123/dc_api_presentation",
  "dc_api_request": {
    "protocol": "openid4vp-v1-signed",
    "data": { "request": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLC..." }
  },
  "authorization_request": {
    "client_id": "x509_hash:...",
    "response_type": "vp_token",
    "response_mode": "dc_api.jwt",
    "expected_origins": ["https://capture-wallet.credimi.io"]
  },
  "status": "created"
}
```

For `plain` request delivery the protocol is `openid4vp-v1-unsigned` and `data` holds the
Authorization Request parameters themselves, without `client_id` or `expected_origins`.

`deeplink` keeps its name and type for compatibility, but for DC API it is **not** a wallet
deeplink: it is the HTTPS URL of this service's presentation page,
`/ui/openid4vp/sessions/{sessionId}/dc_api_presentation`, built from the configured public base
URL. The operator UI renders the same QR code for it. Scanning that code with the phone's camera
opens the page in a browser; the wallet is invoked only when the End-User presses **Present
credential** there, because the browser API requires user activation. The page then forwards the
wallet's Authorization Response to `POST /openid4vp/sessions/{sessionId}/response`, which needs no
`state` for DC API.

An invocation that returns no Authorization Response is reported to
`POST /openid4vp/sessions/{sessionId}/dc_api_invocation` and captured under `dc_api.invocation`
with the outcome, the `DOMException` name and message, whether a response object came back at all,
and whether it contained a `vp_token`. This is the evidence a HAIP wallet leaves when it refuses
the unencrypted `dc_api` response mode, and it is kept distinct from a verification failure over a
real response. A wallet refusal and an End-User cancellation are not distinguishable through the
browser API, so the `rejected` outcome records what the browser reported without asserting which
of the two happened; deciding that remains an operator judgement.

DC API verification is origin-bound rather than `client_id`-bound: the expected SD-JWT VC Key
Binding JWT audience is `origin:<origin>` and the mdoc session transcript uses the
`OpenID4VPDCAPIHandover` over the bare origin, the request nonce, and — for `dc_api.jwt` only —
the thumbprint of the verifier's response-encryption key. The origin comes from trusted
configuration, never from a request header or a JSON body member; a submission whose browser
`Origin` header disagrees with it is refused with HTTP 403.

A DC API presentation window lasts 10 minutes. Once a session holds a presentation, a further
submission is refused with HTTP 409 and the original capture is kept; after the window closes the
page stops offering the button and a submission is refused with HTTP 400. Redirect sessions are
unaffected and still record repeated wallet submissions as evidence.

Two deployment constraints bound this flow: the Digital Credentials API is only available in a
secure context, so `public_base_url` must be HTTPS for anything but local testing, and in-app
browsers, webviews, and iOS Safari do not expose `navigator.credentials.get({ digital: ... })`.
The presentation page is served by the operator UI, so it requires `GUI_ENABLED` to be true.

**[🔝 back to top](#toc)**

---

## ⚙️ Configuration

Runtime configuration comes from generated services config and environment variables.

`pnpm capture-services init` is the only way to initialize service material; the running HTTP service has no initialization endpoint. The command is idempotent and writes generated issuer, verifier, and config files below `./data`, which is ignored by Git. Use `--force` to replace existing generated state.

After upgrading an existing installation, rerun the command without `--force` to
provision the two issuer-specific material directories without rotating material that
already exists there. Legacy root issuer files are ignored; they are not served and
are not deleted automatically.

Startup validates that both issuer directories are complete, that certificates match
their signing keys and exact issuer URI SANs, and that signing, encryption, and
access-token public keys are not reused between issuer roles. A deployment-hostname
`dNSName` SAN is optional and is not checked, allowing externally issued certificates
that bind the path-based issuer through the URI SAN only.

For issuer signing material, `issuer-private-jwk.json` is the source of truth for the
key ID. Initialization rebuilds the derived `jwks.json` without rotating an existing
private key and copies its exact `kid`; Credo imports the signing key under that same
ID. An externally supplied private JWK must therefore contain a non-empty `kid`.

Issuer material is stored independently for each issuer:

```text
data/issuers/eu-pid-device-bound/
├── access-token-private-jwk.json
├── issuer-certificate.pem
├── issuer-encryption-private-jwk.json
├── issuer-private-jwk.json
└── jwks.json

data/issuers/eu-pid-jwt-proof-only/
├── access-token-private-jwk.json
├── issuer-certificate.pem
├── issuer-encryption-private-jwk.json
├── issuer-private-jwk.json
└── jwks.json
```

OpenID4VP verifier material:

```text
data/verifier/verifier-private-jwk.json
data/verifier/verifier-certificate.pem
data/verifier/verifier-jwks.json
```

To use a specific verifier key, replace `data/verifier/verifier-private-jwk.json`
with an ES256 private JWK and replace
`data/verifier/verifier-certificate.pem` with a certificate for the matching public
key. Do not use `init --force` after replacing verifier or issuer material unless you
want all generated material regenerated. The verifier `x509_hash` client identifier
is derived from its certificate, and signed request objects are signed with its
private JWK.

From env file `.env`, that is loaded automatically when present, you can set:
- `GUI_ENABLED`: enables or disables browser GUI routes. Defaults to `true`.
- `PORT`: overrides the configured listen port.
- `PUBLIC_BASE_URL`: public base URL the operator UI is served from. It defaults to the configured
  `issuer_base_url`, and can also be set as `public_base_url` in `config.yaml`. The DC API
  presentation page URL and the `expected_origins` of a signed DC API request are derived from it,
  never from a request `Host` header, so a cross-device DC API deployment behind a proxy must set
  it to the HTTPS URL the End-User's browser actually reaches.
- `FCAF_SCENARIOS_ENABLED`: enables the FCAF scenario inputs that deliberately produce malformed
  protocol material: `request_mutation`, `request_behavior`, and `response_scenario`. Defaults to
  `false`, so an ordinary deployment refuses them with `request_mutation_not_enabled`,
  `request_behavior_not_enabled`, or `response_scenario_not_enabled`.
- `STATUS_LIST_BASE_URL`: overrides the configured Status List endpoint.
- `STATUS_LIST_API_KEY`: overrides the configured Status List management API key.

To trust a Status List service that signs with a certificate separate from the credential
issuer, configure its trust anchor in `config.yaml` as a base64-DER or PEM certificate:

```yaml
status_list_trusted_certificates: ["MIIB..."]
```

When configured, the verifier validates a presented Status List JWT `x5c` chain against
this value. Without it, the verifier requires the Status List signer chain to match the
credential issuer chain.

**[🔝 back to top](#toc)**

---

## 🚧 Known limitations

These are deliberate gaps, not bugs. Each names what is missing and what would close it.

**COSE status-list structures.** The malformed `status_reference` fixtures apply to SD-JWT VC
only. An mdoc `status` claim is produced by `@owf/token-status-list` through Credo's
`MdocSignOptions.statusInfo`, whose schema requires a non-negative integer `idx` and a string
`uri`, so a negative or missing index, a missing or malformed URI, an empty status map, a map
without a `status_list` entry, and a missing status claim at CBOR label 65535 cannot be produced
through the library. Emitting them would mean assembling the Mobile Security Object outside
Credo, which `AGENTS.md` puts behind explicit approval; the service refuses the request instead of
issuing a silently valid credential. Valid COSE status references work today through
`status_list_enabled`.

**Credentials without cryptographic holder binding.** Not implemented, pending
[credo-ts#2936](https://github.com/openwallet-foundation/credo-ts/pull/2936). Every credential
this service issues is device-bound to the holder key from the wallet's proof.

**Credentials digested with an algorithm other than SHA-256.** Not issuable. Credo's
`SdJwtVcService.sign` accepts a `hashingAlgorithm` option but rejects every value other than
`sha-256`, so an SD-JWT VC carrying `_sd_alg: "sha-512"` would need a non-Credo signing path.

**The `x509_san_dns` happy path.** Not exercised. A wallet trusts a verifier certificate through
the [EUDI service-provider registry](https://registry.serviceproviders.eudiw.dev/guide), which
does not issue a certificate carrying a `dNSName` SAN, so a registry-trusted request cannot use
the `x509_san_dns` Client Identifier Prefix. The prefix itself is implemented and a request can be
created with it, but a wallet-accepted `x509_san_dns` request cannot be produced. The negative
`x509_san_dns` cases do not need it: a mismatching DNS name is a `request_mutation` on `client_id`.

**SD-JWT VC JSON serialization.** The service issues and verifies the compact serialization only.
A test requiring a presentation in JSON serialization needs both wallet support and a verifier
that accepts it; neither is in place.

**Digital Credentials API on iOS and in webviews.** `navigator.credentials.get({ digital: … })`
is not exposed there, so the DC API presentation page cannot drive those wallets. It also requires
a secure context, so `PUBLIC_BASE_URL` must be HTTPS outside local testing.

**Wallet refusal versus End-User cancellation.** The browser reports both as a `DOMException`
with deliberately sparse detail, so the `rejected` invocation outcome records what the browser
said without asserting which occurred. Deciding between them is an operator judgement.

---

## 💼 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
