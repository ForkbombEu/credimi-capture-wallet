# Credimi Capture Wallet

## Intro

Credimi Capture Wallet is a local OpenID4VCI issuer and OpenID4VP verifier for observing wallet metadata and protocol evidence during PID issuance and presentation flows. It creates disposable sessions, presents QR/deeplink entry points, and preserves the observed client, proof, DPoP, request, response, and validation data.

## Technical specs

TypeScript on Node.js. [Credo.TS](https://credo.js.org/) provides credential, key, and EUDI protocol primitives; the service also emits OpenID4VCI/OpenID4VP metadata and an OpenAPI 3.1 description.

## HOW to run

```sh
pnpm install
cp env.example .env
pnpm capture-services init \
  --services-base-url http://127.0.0.1:8080 \
  --data-dir ./data \
  --credential-configuration-id urn:eu.europa.ec.eudi:pid:1
pnpm capture-services serve --data-dir ./data
```

Open `http://127.0.0.1:8080`. The public base URL used during `init` must match the address exposed to the wallet. For another local port, initialize with that port and start with `PORT=<port>`.

Validate with `pnpm lint`, `pnpm test`, and `pnpm build`.

## Quick GUI guide

### Home

The home page starts issuance or presentation sessions and shows the categories of evidence each session captures.

### Issuance

Choose a credential configuration, select **New fake-issuance session**, scan the QR/deeplink with a wallet, then inspect captured client identifiers, proof keys, DPoP keys, and events.

### Presentation

Select **New presentation session**, scan the request with a wallet, and inspect the authorization request, submitted presentation, decoded claims, and validation result.

## CLI Examples

| Function | Example |
| --- | --- |
| Initialize local material | `pnpm capture-services init --services-base-url http://127.0.0.1:8080 --data-dir ./data --credential-configuration-id urn:eu.europa.ec.eudi:pid:1` |
| Start the service | `pnpm capture-services serve --data-dir ./data` |

## API Examples

| Function | Example |
| --- | --- |
| Health | `curl http://127.0.0.1:8080/healthz` |
| Issuer metadata | `curl http://127.0.0.1:8080/.well-known/openid-credential-issuer` |
| Create an issuance session | `curl -X POST http://127.0.0.1:8080/sessions -H 'content-type: application/json' -d '{"credential_configuration_id":"urn:eu.europa.ec.eudi:pid:1.mdoc.jwt"}'` |
| Create a presentation session | `curl -X POST http://127.0.0.1:8080/openid4vp/sessions -H 'content-type: application/json' -d '{}'` |

Interactive API documentation is at `/docs`; the OpenAPI 3.1 document is at `/openapi.json`.
