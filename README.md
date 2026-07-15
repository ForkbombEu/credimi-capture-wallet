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
- Wallet OAuth client identifier: `client_id`
- Wallet authorization callback: `redirect_uri`
- Holder-binding public key from proof headers: `wallet_jwks`
- DPoP public key when present: `dpop_jwk`

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
  - [🪪 OpenID4VCI Issuance Flow](#-openid4vci-issuance-flow)
  - [🛂 OpenID4VP Presentation Flow](#-openid4vp-presentation-flow)
- [⚙️ Configuration](#️-configuration)
- [💼 License](#-license)

</div>

---

## 🚀 Quick Start

Visit https://capture-wallet.credimi.io/ and start issuing and verifying PID in dc+sd-jwt and mdoc format.

Once you have chosen what type of credential:
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

Default local issuer URL is `http://localhost:8080`. You can select your port using

```sh
PORT=22000 pnpm dev
```

**[🔝 back to top](#toc)**

---

## 📡 Hosted REST API

Common REST API endpoints are:
* Health: `/healthz`
* Credential Issuer well-known: `/.well-known/openid-credential-issuer`
* Authorization server well-known: `/.well-known/oauth-authorization-server`
* Credential Issuer jwks: `/jwks.json`

### 🪪 OpenID4VCI Issuance Flow

> [!IMPORTANT]
> BASE_URL must be the `--services-base-url` you set during the setup, to use our hosted services use `https://capture-wallet.credimi.io`


Start by creating a capture session for a credential configuration (that is the `--credential-configuration-id` used during the setup + `.jwt` for dc+sd-jwt or + `.mdoc.jwt` for mdoc):
```sh
curl -X POST "$BASE_URL/sessions" \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.jwt"}'
```
A successful response returns HTTP 201 and includes:
```json
{
  "session_id": "...",
  "credential_configuration_id": "urn:eu.europa.ec.eudi:pid:1.mdoc.jwt",
  "offer_url": "https://capture-wallet.credimi.io/sessions/.../offer",
  "deeplink": "openid-credential-offer://...",
  "status": "created"
}
```

Open or transmit the returned `deeplink` to the Wallet under test. The Wallet will call the issuer metadata, PAR, authorization, token, nonce, and credential endpoints directly during the OpenID4VCI flow.

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
* Captured Wallet holder-binding JWKS after the Wallet has called `/credential` with a proof JWT containing `header.jwk`:
  ```sh
  curl "$BASE_URL/sessions/{sessionId}/jwks"
  ```
  If the JWKS is not ready, the service returns HTTP 409 with `wallet_jwks_not_observed`. In that case, inspect the session object and event evidence to confirm whether the Wallet sent only `kid`, `x5c`, or no proof JWT header key material.

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

Optional `scopes`, `transaction_data`, and `verifier_info` values can be supplied at the top level or within `presentation_request`. `scopes` accepts a string or an array of strings and is emitted as the standard space-delimited `scope` authorization-request parameter. The other two values are included unchanged in the signed request object.

A successful response returns HTTP 201 and includes:

```json
{
  "session_id": "...",
  "request_delivery": "by_reference",
  "request_uri": "$BASE_URL/openid4vp/sessions/.../request",
  "request_uri_method": "post",
  "response_mode": "direct_post.jwt",
  "response_uri": "$BASE_URL/openid4vp/sessions/.../response",
  "deeplink": "openid4vp://...",
  "authorization_request": {
    "client_id": "x509_hash:...",
    "response_type": "vp_token",
    "response_mode": "direct_post.jwt",
    "state": "..."
  },
  "status": "created"
}
```

The QR deeplink contains `client_id=x509_hash:...` and `request_uri=...`. The request URI returns a signed `application/oauth-authz-req+jwt` request object with the verifier certificate in the JWS `x5c` header. By default the verifier uses `direct_post.jwt`, advertises an ephemeral JARM encryption key in `client_metadata.jwks`, captures the posted encrypted response, and stores the decrypted response in the session raw data after validation. Pass `"response_mode":"direct_post"` when creating a session if you need plaintext capture.

In this case for each session you can get:
* deeplink:
  ```sh
  curl "$BASE_URL/sessions/{sessionId}/deeplink"
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

`pnpm capture-services init` is idempotent and writes generated issuer, verifier, and config files below `./data`, which is ignored by Git. Use `--force` to replace existing generated state.

Issuer material:

```text
data/issuer-private-jwk.json
data/issuer-certificate.pem
data/jwks.json
```

OpenID4VP verifier material:

```text
data/verifier-private-jwk.json
data/verifier-certificate.pem
data/verifier-jwks.json
```

To use a specific verifier key, replace `verifier-private-jwk.json` with an ES256 private JWK and replace `verifier-certificate.pem` with a certificate for the matching public key. Do not use `init --force` after replacing verifier material unless you want it regenerated. The verifier `x509_hash` client identifier is derived from `verifier-certificate.pem`, and signed request objects are signed with `verifier-private-jwk.json`.

From env file `.env`, that is loaded automatically when present, you can set:
- `GUI_ENABLED`: enables or disables browser GUI routes. Defaults to `true`.
- `PORT`: overrides the configured listen port.

**[🔝 back to top](#toc)**

---

## 💼 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
