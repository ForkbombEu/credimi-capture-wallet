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
- Decrypted wallet presentation response: `presentation_response_decrypted` (useful when response_mode is set to `direct_post.jwt`)
- Decoded claims from verified presentations: `decoded_presentations`
- Verifier checks for nonce, holder binding, and DCQL matching: `presentation_validation`

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


The configured `--credential-configuration-id` is the base for four Credential
Configuration Identifiers split across the two issuers:

| Issuer | Format | Configuration ID and scope suffix | Credential type |
| --- | --- | --- | --- |
| `eu-pid-device-bound` | SD-JWT VC | `.sd-jwt.key-attestation-required` | `vct: urn:eudi:pid:1` |
| `eu-pid-device-bound` | mdoc | `.mdoc.key-attestation-required` | `doctype: eu.europa.ec.eudi.pid.1` |
| `eu-pid-jwt-proof-only` | SD-JWT VC | `.sd-jwt.jwt-proof` | `vct: urn:eudi:pid:1` |
| `eu-pid-jwt-proof-only` | mdoc | `.mdoc.jwt-proof` | `doctype: eu.europa.ec.eudi.pid.1` |

Each configuration has a unique scope formed by appending the same suffix to the
configured credential scope. The duplicated configurations issue the same credential
type and claims and retain the same `vct` or `doctype`; only the issuer and proof policy
differ. The device-bound issuer and its key-attestation-required SD-JWT configuration
are selected when their request fields are omitted.

Start by creating a capture session for a credential configuration:

```sh
curl -X POST "$BASE_URL/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "issuer_configuration_id":"eu-pid-device-bound",
    "credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.key-attestation-required"
  }'
```
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

Both issuers issue the same deterministic Mario Rossi PID claims. The removed legacy
root issuer and its `broken` credential fixture are no longer available.

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
* `request_uri_method` can be `get` or `post`, default is `get`
* `request_delivery` can be `by_reference` or `by_value`, default is `by_reference`
* `response_type` can be `vp_token` or `vp_token id_token` or `code`, but during presentation verification only `vp_token` is supported, default is `vp_token`
* `response_mode` can be `direct_post` or `direct_post.jwt`, default is `direct_post.jwt`
* `scheme` is the complete custom URL-scheme prefix for the deeplink (for example, `eudi-wallet://`); it defaults to `openid4vp://`

Optional `scopes`, `transaction_data`, and `verifier_info` values can be supplied at the top level or within `presentation_request`. `scopes` accepts a string or an array of strings and is emitted as the standard space-delimited `scope` authorization-request parameter. The other two values are included unchanged in the signed request object.

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

**[🔝 back to top](#toc)**

---

## 💼 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
