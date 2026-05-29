# Codex prompt — Credimi fake OpenID4VCI capture issuer in TypeScript using Credo-TS

You are working in a repository that includes the following governance/context files:

- `AGENTS.md`
- `PURIA.md`
- `DESIGN.md`
- `HITL.md`
- `README.md`

Before making any change, read those files and obey them. `PURIA.md` is the canonical source of truth for agent behavior, engineering workflow, validation, commits, tooling, and project requirements. `AGENTS.md` explicitly says to read `PURIA.md` before any action. `DESIGN.md` is only relevant if you create any design-bearing artifact or UI/TUI. `HITL.md` is a write-only buffer for observations that require human validation. Do not infer repository conventions not documented in `PURIA.md`.

## Goal

Build a small **fake OpenID4VCI capture issuer** for Credimi.

This is not a production issuer. It is an instrumented test harness used to make an external Wallet under test perform an authorization-code OpenID4VCI issuance flow, so that Credimi can capture the Wallet protocol values required by the OpenID Foundation VCI Wallet conformance tests.

The service must capture and expose:

- the Wallet OAuth `client_id`
- the Wallet `redirect_uri`
- the Wallet holder-binding public key as JWKS, extracted from the credential request proof JWT JOSE header
- optionally the DPoP public JWK, if present
- a structured event log for debugging and conformance evidence

## Hard requirements

- Language: TypeScript.
- Runtime: Node.js.
- Use Credo-TS, especially `@credo-ts/openid4vc`, wherever practical.
- Prefer Credo-TS issuer primitives over hand-rolling OpenID4VCI where the framework supports the feature.
- Where Credo-TS does not expose the needed capture hooks directly, add a thin Express/Fastify middleware or route wrapper to capture raw requests before delegating to Credo-TS.
- Implement **Mode A: permissive capture mode**.
- Do **not** implement this as pre-authorized-code-only.
- Authorization-code flow is required.
- PAR support is required.
- Accept arbitrary Wallet `client_id`.
- Accept arbitrary Wallet `redirect_uri`.
- Do not require dynamic client registration or pre-registration of the Wallet client.
- Record what the Wallet sends; do not assume fixed values.
- The main output is captured protocol data, not the issued credential.
- Keep the credential issuance minimally functional only so the Wallet reaches `/credential`.

## Why Credo-TS

Use Credo-TS because it already exposes OpenID4VC modules for issuer, holder, and verifier roles. The issuer/verifier modules are intended to run in Node/server environments with public endpoints. Credo’s OpenID4VC issuer tutorial describes creating an issuer, creating credential offers, and using `credentialRequestToCredentialMapper` to dynamically generate the credential response when the holder requests the credential.

Also inspect the Credo `demo-openid` directory and reuse/adapt its issuer patterns when appropriate.

## Important implementation note

The OpenID4VCI spec allows the Credential Request to carry holder-binding material in proof(s). For this capture issuer, the critical place is the credential request body, especially these shapes:

Single proof:

```json
{
  "proof": {
    "proof_type": "jwt",
    "jwt": "..."
  }
}
```

Multiple proofs:

```json
{
  "proofs": {
    "jwt": ["..."]
  }
}
```

For each proof JWT:

1. Decode the JOSE header without trusting it blindly.
2. Capture `typ`, `alg`, `kid`, `jwk`, and `x5c` if present.
3. If `jwk` is present, convert it into a JWKS object:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "alg": "ES256",
      "use": "sig"
    }
  ]
}
```

4. If only `kid` is present, record that the wallet key is not directly observable.
5. If `x5c` is present, record it and, if practical, extract the leaf public key into JWK/JWKS.
6. Validate the proof signature if practical. If validation is blocked by missing key material, record a clear reason.

The OpenID Foundation VCI Wallet conformance test needs the Wallet public JWKS. The primary desired capture source is:

```text
credential_request.proofs.jwt[0].header.jwk
```

## Required captured object

Expose a normalized session capture object like:

```json
{
  "session_id": "uuid",
  "status": "credential_requested",
  "observed": {
    "client_id": {
      "value": "wallet-client-id",
      "source": "par_request.client_id",
      "also_seen_in": [
        "authorization_request.client_id",
        "token_request.client_id"
      ]
    },
    "redirect_uri": {
      "value": "eudi-wallet://callback",
      "source": "par_request.redirect_uri"
    },
    "wallet_jwks": {
      "observed": true,
      "source": "credential_request.proofs.jwt[0].header.jwk",
      "jwks": {
        "keys": []
      }
    },
    "dpop_jwk": {
      "observed": false,
      "source": null,
      "jwk": null
    }
  },
  "checks": {
    "pkce_present": true,
    "pkce_valid": true,
    "state_present": true,
    "issuer_state_present": true,
    "proof_jwt_present": true,
    "proof_jwt_header_jwk_present": true,
    "nonce_verified": true
  },
  "events": []
}
```

## Required endpoints

Expose these endpoints, even if some are wrappers around Credo-TS module handlers:

- `GET /healthz`
- `GET /.well-known/openid-credential-issuer`
- `GET /.well-known/oauth-authorization-server`
- `GET /jwks.json`
- `POST /init` optional but useful
- `POST /sessions`
- `GET /sessions/:sessionId`
- `GET /sessions/:sessionId/offer`
- `GET /sessions/:sessionId/deeplink`
- `GET /sessions/:sessionId/jwks`
- `GET /sessions/:sessionId/events`
- `POST /par`
- `GET /authorize`
- `POST /token`
- `POST /nonce`
- `POST /credential`

If Credo-TS exposes different internal routes, still provide these external routes or compatibility aliases.

## Init requirements

The issuer needs stable initialization.

Provide a CLI command:

```sh
pnpm fake-issuer init \
  --issuer-base-url https://example.com \
  --data-dir ./data \
  --credential-configuration-id urn:eu.europa.ec.eudi:pid:1
```

The init command must:

- generate issuer signing keys
- generate issuer JWKS
- generate/persist service config
- prepare Credo wallet/storage configuration as needed
- write all persistent state under `--data-dir`
- be idempotent: do not overwrite existing keys/config unless `--force` is provided
- print:
  - issuer base URL
  - credential issuer metadata URL
  - authorization server metadata URL
  - JWKS URL
  - health URL

Also implement optional API init:

```http
POST /init
Content-Type: application/json
```

Example:

```json
{
  "issuer_base_url": "https://example.com",
  "credential_configuration_id": "urn:eu.europa.ec.eudi:pid:1",
  "force": false
}
```

The CLI init path is canonical. The API init path is only for dev/container convenience.

## Configuration

Support at least:

```yaml
issuer_base_url: "https://example.com"
listen_addr: ":8080"
data_dir: "./data"
credential_configuration_id: "urn:eu.europa.ec.eudi:pid:1"
credential_format: "dc+sd-jwt"
credential_scope: "urn:eu.europa.ec.eudi:pid:1"
authorization_code_ttl_seconds: 300
par_request_uri_ttl_seconds: 90
access_token_ttl_seconds: 600
nonce_ttl_seconds: 300
permissive_capture: true
```

## Metadata behavior

Credential issuer metadata must advertise an authorization-code-capable issuer with `dc+sd-jwt`, holder binding via `jwk`, and proof type `jwt`.

The metadata should include the effective equivalent of:

```json
{
  "credential_issuer": "{issuer_base_url}",
  "authorization_servers": ["{issuer_base_url}"],
  "credential_endpoint": "{issuer_base_url}/credential",
  "nonce_endpoint": "{issuer_base_url}/nonce",
  "credential_configurations_supported": {
    "urn:eu.europa.ec.eudi:pid:1": {
      "format": "dc+sd-jwt",
      "scope": "urn:eu.europa.ec.eudi:pid:1",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      }
    }
  }
}
```

Authorization server metadata should include:

```json
{
  "issuer": "{issuer_base_url}",
  "authorization_endpoint": "{issuer_base_url}/authorize",
  "token_endpoint": "{issuer_base_url}/token",
  "pushed_authorization_request_endpoint": "{issuer_base_url}/par",
  "jwks_uri": "{issuer_base_url}/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "dpop_signing_alg_values_supported": ["ES256"]
}
```

## Session flow

### `POST /sessions`

Create a capture session and return:

```json
{
  "session_id": "uuid",
  "credential_configuration_id": "urn:eu.europa.ec.eudi:pid:1",
  "offer_url": "{issuer_base_url}/sessions/{sessionId}/offer",
  "deeplink": "openid-credential-offer://?credential_offer=...",
  "status": "created"
}
```

### `GET /sessions/:sessionId/offer`

Return a credential offer using authorization-code grant:

```json
{
  "credential_issuer": "{issuer_base_url}",
  "credential_configuration_ids": ["urn:eu.europa.ec.eudi:pid:1"],
  "grants": {
    "authorization_code": {
      "issuer_state": "{sessionId}",
      "scope": "urn:eu.europa.ec.eudi:pid:1"
    }
  }
}
```

### `GET /sessions/:sessionId/deeplink`

Return:

```json
{
  "deeplink": "openid-credential-offer://?credential_offer=...",
  "credential_offer": {}
}
```

Support inline `credential_offer` first. Add `credential_offer_uri` support if straightforward.

## PAR behavior

`POST /par`

Accept `application/x-www-form-urlencoded` and JSON. Be permissive.

Capture at least:

- `client_id`
- `redirect_uri`
- `response_type`
- `scope`
- `state`
- `code_challenge`
- `code_challenge_method`
- `issuer_state`
- `authorization_details`
- any unknown parameters

Return:

```json
{
  "request_uri": "urn:credimi:fake-vci-issuer:par:{random}",
  "expires_in": 90
}
```

Store PAR data by `request_uri`.

## Authorization behavior

`GET /authorize`

Support:

1. direct authorization requests
2. PAR-based requests via `request_uri`

Resolve session using:

1. direct query `issuer_state`
2. PAR payload `issuer_state`
3. fallback orphan session, clearly marked

Record the final merged authorization request.

Generate an authorization code bound to:

- session ID
- client_id
- redirect_uri
- code_challenge
- code_challenge_method
- state

Redirect back to the captured `redirect_uri`:

```http
302 Location: {redirect_uri}?code={code}&state={state}
```

If `redirect_uri` is missing, return a clear JSON error and record the event.

## Token behavior

`POST /token`

Accept form-urlencoded and support:

- `grant_type=authorization_code`
- `code`
- `redirect_uri`
- `client_id`
- `code_verifier`

In permissive mode:

- validate authorization code exists and is unexpired
- validate PKCE if possible
- record missing or invalid PKCE clearly
- issue an access token if the flow is good enough to let the Wallet continue to `/credential`

If DPoP header is present:

- decode DPoP JWT header/payload
- extract JOSE header `jwk` if present
- store as `dpop_jwk`
- compute JWK thumbprint if practical

Return:

```json
{
  "access_token": "{token}",
  "token_type": "DPoP",
  "expires_in": 600,
  "c_nonce": "{nonce}",
  "c_nonce_expires_in": 300
}
```

If DPoP is absent, return `Bearer` or be permissive, but record what happened.

## Nonce behavior

`POST /nonce`

Return:

```json
{
  "c_nonce": "{nonce}",
  "c_nonce_expires_in": 300
}
```

## Credential behavior

`POST /credential`

This is the critical endpoint.

Capture:

- raw request body
- normalized request body
- Authorization header
- DPoP header if present
- proof/proofs fields
- credential configuration or identifier
- proof JWT headers
- extracted holder-binding JWK/JWKS

If using Credo-TS `credentialRequestToCredentialMapper`, instrument it so the raw/normalized `credentialRequest` is captured before returning a dummy credential.

Return a minimal successful credential response. It can be a dummy SD-JWT VC if Credo-TS can produce one easily, or a minimal placeholder accepted by the Wallet for the flow. The priority is reaching the credential request and capturing the proof JWK.

Do not log private keys or secrets.

## Capture output endpoints

### `GET /sessions/:sessionId/jwks`

Return only the wallet holder-binding JWKS, suitable for feeding into the OpenID Foundation VCI Wallet test:

```json
{
  "keys": []
}
```

If not observed, return HTTP 404 or 409 with:

```json
{
  "error": "wallet_jwks_not_observed",
  "reason": "Credential proof JWT did not contain header.jwk",
  "observed_proof_header_fields": ["kid"]
}
```

### `GET /sessions/:sessionId/events`

Return structured events in chronological order.

Events should include:

- session created
- credential offer generated
- PAR request received
- authorize request received
- redirect sent
- token request received
- DPoP observed/not observed
- nonce issued
- credential request received
- proof JWT observed
- wallet JWK observed/not observed
- wallet JWKS exported

## Tests

Add tests for:

- decoding proof JWT header
- extracting `jwk` from proof JWT header
- converting JWK to JWKS
- detecting `kid`-only proof headers
- detecting `x5c` proof headers
- parsing single `proof.jwt`
- parsing multi `proofs.jwt[]`
- PAR storage and request_uri resolution
- authorization request merging from PAR + `/authorize`
- PKCE verification
- session capture object normalization
- `/sessions/:sessionId/jwks` success and failure cases

## Tooling

Follow repository rules from `PURIA.md`.

For TypeScript, create or update tooling consistently with the repo. If `PURIA.md` only defines Go-specific skeletons, do not invent conflicting doctrine. Add factual observations to `HITL.md` only when required by `PURIA.md`.

Use a modern TypeScript stack:

- `pnpm`
- `tsx` for dev execution if suitable
- `vitest` for tests
- `biome` or the repo’s existing formatter/linter, if present
- `mise.toml` must declare all tools used by tasks
- `Taskfile.yml` must expose common tasks:
  - `task install`
  - `task dev`
  - `task build`
  - `task test`
  - `task lint`
  - `task run`
  - `task init`

Do not commit generated secrets, issuer private keys, local databases, logs, caches, build outputs, or `.env` files.

## README

Write a minimal README explaining:

- what this fake issuer is
- that it is not a production issuer
- how to initialize it
- how to run it
- how to create a session
- how to get a deeplink
- how to retrieve the captured Wallet JWKS
- how Credimi should pass the JWKS, `client_id`, and `redirect_uri` into the OIDF VCI Wallet test
- troubleshooting when no JWKS is observed

Include example:

```sh
pnpm install
pnpm fake-issuer init --issuer-base-url https://issuer.example.test --data-dir ./data
pnpm dev
curl -X POST http://localhost:8080/sessions
curl http://localhost:8080/sessions/{sessionId}/jwks
```

## Acceptance criteria

The task is complete only if:

- the service starts
- init is idempotent
- metadata endpoints return valid JSON
- a session can be created
- a credential offer/deeplink is generated
- `/par` captures `client_id` and `redirect_uri`
- `/authorize` redirects back to the observed `redirect_uri`
- `/token` returns a token/nonce response
- `/credential` captures proof JWT data
- `/sessions/:sessionId/jwks` returns the extracted Wallet JWKS when `header.jwk` is present
- tests cover the key extraction and session-capture logic
- no secrets or generated private keys are committed
- repo validation passes according to `PURIA.md`
