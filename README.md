# Credimi Fake VCI Capture Issuer

This project is a fake OpenID4VCI issuer for Credimi conformance work. It is not a
production issuer. Its purpose is to drive an external Wallet through an
authorization-code issuance flow and capture the Wallet protocol values needed by
OpenID Foundation VCI Wallet tests.

It captures:

- Wallet OAuth `client_id`
- Wallet `redirect_uri`
- Wallet holder-binding public key as JWKS from credential proof JWT headers
- DPoP public JWK when present
- structured flow events for debugging and evidence

The implementation exposes compatibility endpoints directly and keeps the
credential response minimal so the Wallet reaches `/credential`. `@credo-ts/openid4vc`
is declared as a project dependency for Credo-TS alignment, but capture mode uses
thin HTTP route wrappers because the raw Wallet request values are the primary
artifact.

## Install

```sh
pnpm install
```

## Initialize

```sh
pnpm fake-issuer init \
  --issuer-base-url https://issuer.example.test \
  --data-dir ./data \
  --credential-configuration-id urn:eu.europa.ec.eudi:pid:1
```

Init is idempotent and writes generated issuer keys/config below `./data`, which is
ignored by git. Use `--force` to replace existing generated state.

## Run

```sh
pnpm dev
```

Default local issuer URL is `http://localhost:8080`.
Set `PORT` to override the configured listen port:

```sh
PORT=3000 pnpm dev
```

## Capture Flow

Create a session:

```sh
curl -X POST http://localhost:8080/sessions
```

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

## Conformance Values

Pass these captured values into the OIDF VCI Wallet conformance test:

- JWKS: `GET /sessions/{sessionId}/jwks`
- `client_id`: `observed.client_id.value` from `GET /sessions/{sessionId}`
- `redirect_uri`: `observed.redirect_uri.value` from `GET /sessions/{sessionId}`

## Troubleshooting

If `/sessions/{sessionId}/jwks` returns `wallet_jwks_not_observed`, the Wallet did
not send a credential proof JWT with `header.jwk`. Inspect
`/sessions/{sessionId}/events` and the session `raw.proof_headers` field to see
whether only `kid` or `x5c` was present.

## Validation

```sh
task format
task test
task lint
task build
```
