# Credimi Fake VCI Capture Issuer

Credimi Fake VCI Capture Issuer is a local fake OpenID4VCI issuer for Credimi conformance work. It is not a production issuer.

Its purpose is to drive an external Wallet through an authorization-code issuance flow and capture the Wallet protocol values needed by OpenID Foundation VCI Wallet tests.

## What It Captures

- Wallet OAuth `client_id`
- Wallet `redirect_uri`
- Wallet holder-binding public key as JWKS from credential proof JWT headers
- DPoP public JWK when present
- structured flow events for debugging and evidence

The implementation exposes compatibility endpoints directly and keeps the credential response minimal so the Wallet reaches `/credential`. At the end of the flow it uses Credo-TS to issue a holder-bound EEA SD-JWT VC with demo PID claims and Credimi branding.

## Quick Start

Install dependencies:

```sh
pnpm install
```

Create local environment settings:

```sh
cp env.example .env
```

Initialize issuer state:

```sh
pnpm fake-issuer init \
  --issuer-base-url https://issuer.example.test \
  --data-dir ./data \
  --credential-configuration-id urn:eu.europa.ec.eudi:pid:1
```

Start the issuer:

```sh
pnpm dev
```

Default local issuer URL is `http://localhost:8080`.

## GUI

The browser GUI is enabled by default.

Open:

```text
http://localhost:8080/
```

From the launcher, click `New fake-issuance session` to open a QR session in a new tab. Scan the QR with an EUDI Wallet. The session page updates as Wallet metadata, proof keys, DPoP keys, checks, and flow events are observed.

Click `New presentation session` to open an OpenID4VP QR session. The QR contains a presentation request for the credentials supported by this issuer. The page updates when the Wallet retrieves the request and posts the presentation response.

The GUI includes a `Help` button that opens the project README on GitHub in a new tab:

```text
https://github.com/ForkbombEu/fake-issuer/blob/master/README.md
```

Disable the GUI by setting `GUI_ENABLED=false` in `.env`:

```sh
GUI_ENABLED=false
```

When disabled, `/`, `/ui/help`, and `/ui/sessions/*` are unavailable. API endpoints remain available.

## Hosted REST API

The deployed capture issuer is available at:

```text
https://capture-wallet.credimi.io
```

Use the REST API to create a wallet capture session, hand the returned deeplink to a Wallet, and retrieve the values observed during the OpenID4VCI issuance flow. The service is intended for test and conformance workflows, not production credential issuance.

Set the base URL once for shell examples:

```sh
BASE_URL=https://capture-wallet.credimi.io
```

Check service health:

```sh
curl "$BASE_URL/healthz"
```

Fetch issuer metadata:

```sh
curl "$BASE_URL/.well-known/openid-credential-issuer"
curl "$BASE_URL/.well-known/oauth-authorization-server"
curl "$BASE_URL/.well-known/jwt-vc-issuer"
curl "$BASE_URL/jwks.json"
```

Create a capture session with the default credential configuration:

```sh
curl -X POST "$BASE_URL/sessions"
```

Create a capture session for a specific credential configuration:

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

Retrieve the deeplink again when needed:

```sh
curl "$BASE_URL/sessions/{sessionId}/deeplink"
```

Retrieve the normalized capture object:

```sh
curl "$BASE_URL/sessions/{sessionId}"
```

Retrieve event evidence for debugging or conformance records:

```sh
curl "$BASE_URL/sessions/{sessionId}/events"
```

Retrieve the captured Wallet holder-binding JWKS after the Wallet has called `/credential` with a proof JWT containing `header.jwk`:

```sh
curl "$BASE_URL/sessions/{sessionId}/jwks"
```

If the JWKS is not ready, the service returns HTTP 409 with `wallet_jwks_not_observed`. In that case, inspect the session object and event evidence to confirm whether the Wallet sent only `kid`, `x5c`, or no proof JWT header key material.

For OIDF VCI Wallet conformance tests, use these captured values:

- JWKS: response from `GET /sessions/{sessionId}/jwks`
- `client_id`: `observed.client_id.value` from `GET /sessions/{sessionId}`
- `redirect_uri`: `observed.redirect_uri.value` from `GET /sessions/{sessionId}`

## API Capture Flow

Create a session:

```sh
curl -X POST http://localhost:8080/sessions
```

Choose a specific credential configuration for the offer:

```sh
curl -X POST http://localhost:8080/sessions \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.jwt"}'
```

The issuer metadata exposes matching proof-specific scopes:

- `urn:eu.europa.ec.eudi:pid:1.jwt`
- `urn:eu.europa.ec.eudi:pid:1.mdoc.jwt`

Get a Wallet deeplink:

```sh
curl http://localhost:8080/sessions/{sessionId}/deeplink
```

Retrieve the captured Wallet JWKS:

```sh
curl http://localhost:8080/sessions/{sessionId}/jwks
```

Retrieve the full normalized capture object:

```sh
curl http://localhost:8080/sessions/{sessionId}
```

Retrieve event evidence:

```sh
curl http://localhost:8080/sessions/{sessionId}/events
```

## OpenID4VP Presentation Flow

Create a presentation session with the default request for this issuer's supported credentials:

```sh
curl -X POST http://localhost:8080/openid4vp/sessions
```

A successful response returns HTTP 201 and includes:

```json
{
  "session_id": "...",
  "request_uri": "http://localhost:8080/openid4vp/sessions/.../request",
  "request_uri_method": "get",
  "response_mode": "direct_post.jwt",
  "response_uri": "http://localhost:8080/openid4vp/sessions/.../response",
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

Set the request URI method explicitly when creating the session:

```sh
curl -X POST http://localhost:8080/openid4vp/sessions \
  -H 'Content-Type: application/json' \
  -d '{"request_uri_method":"post"}'
```

When `request_uri_method` is `post`, the QR deeplink also includes `request_uri_method=post`. The default is `get`.

Create a presentation session with an API-supplied request override:

```sh
curl -X POST http://localhost:8080/openid4vp/sessions \
  -H 'Content-Type: application/json' \
  -d '{
    "presentation_request": {
      "nonce": "external-nonce",
      "dcql_query": {
        "credentials": [
          {
            "id": "email_credential",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://example.test/email"] },
            "claims": [{ "path": ["email"] }]
          }
        ]
      }
    }
  }'
```

Optional `scopes`, `transaction_data`, and `verifier_info` values can be supplied at the top level or within `presentation_request`. `scopes` accepts a string or an array of strings and is emitted as the standard space-delimited `scope` authorization-request parameter. The other two values are included unchanged in the signed request object.

Retrieve the request object referenced by the QR:

```sh
curl -H 'Accept: application/oauth-authz-req+jwt' \
  http://localhost:8080/openid4vp/sessions/{sessionId}/request
```

Wallets that use request URI method `post` can provide `wallet_nonce`:

```sh
curl -X POST http://localhost:8080/openid4vp/sessions/{sessionId}/request \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'wallet_nonce=wallet-generated-nonce'
```

Retrieve the capture object:

```sh
curl http://localhost:8080/openid4vp/sessions/{sessionId}
```

Retrieve event evidence:

```sh
curl http://localhost:8080/openid4vp/sessions/{sessionId}/events
```

## Conformance Values

Pass these captured values into the OIDF VCI Wallet conformance test:

- JWKS: `GET /sessions/{sessionId}/jwks`
- `client_id`: `observed.client_id.value` from `GET /sessions/{sessionId}`
- `redirect_uri`: `observed.redirect_uri.value` from `GET /sessions/{sessionId}`

## Configuration

Runtime configuration comes from generated issuer config and environment variables.

### Issuer Config

`pnpm fake-issuer init` is idempotent and writes generated issuer, verifier, and config files below `./data`, which is ignored by Git. Use `--force` to replace existing generated state.

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

### Environment

`.env` is loaded automatically when present and is ignored by Git. Use `env.example` as the template.

Supported environment variables:

- `GUI_ENABLED`: enables or disables browser GUI routes. Defaults to `true`.
- `PORT`: overrides the configured listen port.

Example:

```sh
PORT=3000 pnpm dev
```

## Troubleshooting

If `/sessions/{sessionId}/jwks` returns `wallet_jwks_not_observed`, the Wallet did not send a credential proof JWT with `header.jwk`.

Inspect `/sessions/{sessionId}/events` and the session `raw.proof_headers` field to see whether only `kid` or `x5c` was present.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Validation

```sh
task format
task lint
task test
task build
```
