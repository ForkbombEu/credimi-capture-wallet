# Findings outside the approved scope

Discoveries made during the refactoring that are **not** fixed by it. Each entry: id, category,
evidence, impact, recommendation, status.

| ID | Category | Finding | Evidence | Recommendation | Status |
|---|---|---|---|---|---|
| F-01 | Docs | `src/design/style.css` `@font-face` rules reference `../fonts/*.ttf`; no `src/fonts/` directory and no `/fonts` route exist. | `src/design/style.css:6-21` | Repair or remove font declarations (X-3). | Deferred |
| F-02 | Docs / OpenAPI | `/openapi.json` omits `GET /openid4vp/client-identifiers`, `GET /openid4vp/verifier-attestation-issuer/jwks.json`, `GET /openid4vp/redirect`, Credo-forwarded `GET /issuers/{id}/challenge` and `/deferred-credential`. | `src/server.ts:604,610,1312`; `src/credo-openid4vci.ts:207,210` | Document them (X-2). | Deferred |
| F-03 | Type safety | `loadConfig` spreads YAML values over `AppConfig` without per-field validation (e.g. a non-numeric TTL becomes a string at runtime). | `src/config.ts:262-287, 406-407` | Validate file values (behaviour change; needs approval). C-18 only makes the type honest. | Deferred |
| F-04 | Security (by design) | The legacy validator disabled certificate-chain validation; it has no production caller and is removed by D-05. | `src/openid4vp-validation.ts:346-347, 633` | None after D-05. | Resolved by D-05 |
| F-05 | Type safety | `dcql: { query: dcqlQuery as never }` hides malformed caller DCQL until Credo rejects it and the fallback query is used. | `src/credo-openid4vp.ts:266-274` | X-4. | Deferred |
