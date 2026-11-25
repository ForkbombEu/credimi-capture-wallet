# Refactoring final report

Branch `refactor/codebase-health` (worktree `/home/matteo/src/ccw-refactor/integration`), from
baseline `ae9e74c`. Not merged, not pushed. Task-level detail (bases, task commits, review rounds,
measurements, risks) is in `PROGRESS.md`; decisions in `DECISIONS.md`; out-of-scope discoveries in
`FINDINGS.md`; reproducible metrics and gates in `BASELINES.md`.

## 1. Implementation summary

**Completed** (each: Luna implementation in an isolated worktree → independent Opus review →
corrections amended into one task commit → cherry-picked → integration validation):

| Phase | Tasks | Integration commits |
|---|---|---|
| 0 Tooling/navigation | R-01, R-02, R-03 | 1787e51, b69173d, f6d6220 |
| 1 Test support | S-01a | 6e715cd |
| 2 Characterisation tests | T-01 … T-09 | 08a97c4, 8de40a8, 07f3dd7, ea76c05, 5d9d4d3, 99e3f0c, 77c9d77, f2211eb, 001853b |
| 3 Dead code | D-01 … D-06 | e5c3cd8, e554463, 7630b46, 8ca8351, dae9d82, cdbaa61 |
| 4 Boundaries | B-10, B-01 … B-09 | 5a14aef, fcf97d8, 2c3a254, 47729f9, 980d432, e221d77, 0fd94f0, b2dde4f, 0a53661, 223fe2d |
| — Stability | S-00 | 4728ea4 |
| 5 Simplification | C-01 … C-18 | 4c9cf37, 3334f8a, f4847eb, d56fd72, 466644c, 5294d7d, 2cfa76d (C-07), e9d12d8 (C-08), 5ef10de, 4734ad7, ec4cb46, 58c17fc, bc6e1e4, f013bb0, 09d32bb, b545534, 21433ab (C-17), 8a2e780 |
| 6 Test simplification | S-01b, S-02, S-03 | b61d6b9, 810efb1, 75e9b36 |
| 7 Docs and gates | Q-01, N-01, X-5 decision | 145a1e2, 64a79bf, ADR-06 |
| 8 Validation | V-01, FR-01, FR-01a | see §4; 8bd12a2 (FR-01a documentation paths) |

**Deferred (not implemented, per PLAN §7):** X-2 (missing OpenAPI paths), X-3 (CSS/font repair),
X-4 (`DcqlQuery.parse`), X-5 (types split — re-evaluated and kept deferred, ADR-06), X-6 (Credo
startup ordering), X-7 (asRecord/asString variants).

**Blocked:** none.

**Adjusted from the audit / plan:**
- S-00 added: two timing-sensitive tests made deterministic (F-09) — tests only.
- S-01b, S-02, S-03, Q-01, C-08 ∥ C-17 were run in parallel with the tail of Phase 5 (disjoint
  files) instead of strictly sequentially; dependencies on file ownership were respected.
- C-05 and C-07 deviated from the plan's suggested shape after review: C-05 keeps the route as the
  orchestrator in `app.ts`/route module (no handler factory); C-07 registers routes directly on the
  app (`register*Routes(app, ctx)`) instead of mounting `express.Router()`s, because sub-routers
  answer `OPTIONS` themselves and changed captured evidence for CORS preflights.
- Q-01 test-only exports are tagged `@internal` (production knip scan) instead of file-level ignores.
- R-02 corrected the AGENTS.md design-source path (`atlas-style.css` did not exist →
  `src/design/style.css`).

## 2. Architecture summary

Final layout (`src/`): `cli/`, `config/` (defaults, environment, load, key-material, paths,
verifier-identity), `configurations/`, `credentials/` (catalogue, registry, signing), `credo/`
(agent runtime), `openid4vci/` (Credo issuer, attribution, evidence, credential mapping, proofs,
encryption, HTTP capture), `openid4vp/` (Credo verifier, request construction, presentation
decoding, request-object encryption), `server/` (`app.ts` composition root, `context.ts`, `routes/`,
session intake/creation, credential endpoint, request URI, VP submission), `ui/`, `openapi/`,
`attestbook/`, `status-list/`, `fcaf/`, `federation/`, `shared/` (errors, JSON guards), `state.ts`,
`types.ts`.

Major improvements:
- 2 590-line `server.ts` → `server/app.ts` composition root (~140 lines) + `ServerContext` (the only
  shared per-request capture state) + 11 route modules + focused request-intake/endpoint modules.
- 2 257-line `openapi.ts` and 1 866-line `ui.ts` split by concern / page family (byte-identical output).
- The four largest handlers (cx 91, 65, 50, 22×3) replaced by orchestrators with named, ordered steps.
- Positional parameter lists replaced by named options (`createVpSession`, `CaptureStore.createSession`).
- Legacy OpenID4VP validator and request builders removed (Credo-TS path only); `dcql` dependency removed.
- Import cycles 2 → 0, enforced by `task analyze:check`.

Shared responsibilities introduced: `src/shared/errors.ts`, `src/shared/json.ts` (ADR-05),
`src/server/context.ts`, `tests/support/*`.

Remaining limitations: `types.ts` remains one module (ADR-06); `openapi/components.ts` is a single
1 120-line schema literal; `createIssuanceSession` (15) and `CredoOpenId4VpVerifier.createSession`
(13) keep positional signatures (F-16); directory-level dependency cycles between attestbook,
config, credentials and status-list predate the branch and are not gated (F-17); some Attestbook
and FCAF parsers remain at cx 15–22 (their check order selects the error code).

## 3. Before-and-after measurements

Baseline `ae9e74c` vs final tip. Function metrics: the audit's AST counter (`fnstats`), confirmed by
the FR-01 reviewer's independent counter.

| Measure | Baseline | Final |
|---|---|---|
| Production TypeScript (`src`) | 62 files, 20 659 lines | 110 files, 21 222 lines |
| Test TypeScript (`tests`) | 21 files, 13 288 lines | 68 files, 21 042 lines |
| Largest production modules | `server.ts` 2 590, `openapi.ts` 2 257, `ui.ts` 1 866, `credo-openid4vp.ts` 1 473 | `openapi/components.ts` 1 120 (schema literal), `attestbook/integration.ts` 817, `openid4vci/credo-issuer.ts` 793, `types.ts` 792 |
| Largest test file | `server.test.ts` 7 922 | `server-vp-requests.test.ts` 1 040 |
| Highest function complexity | 91 (`POST /openid4vp/sessions`) | 22 (`requestBehaviorOrNull`) |
| Functions cx ≥ 20 / ≥ 15 | 11 / 26 | 2 / 17 |
| Busiest route handler cx | 91 | 13 |
| Total decision points (src) | 2 314 | 2 201 (−92 from the deleted legacy validator) |
| Duplication `src` (jscpd) | 10 clones, 134 lines (0.65 %) | 6 clones, 50 lines (0.24 %) |
| Duplication `tests` (jscpd) | 79 clones, 894 lines (6.73 %) | 115 clones, 1 388 lines (6.60 %) |
| Unused exports / types (knip, full) | 14 export groups, 8 type groups | 0 / 0 (31 test-only seams tagged `@internal`) |
| Unused dependencies (knip, production) | 1 (`dcql`) | 0 |
| File-level import cycles (madge) | 2 | 0 (gated) |
| Tests | 471 in 19 files | 793 in 58 files (all baseline names kept; 2 renamed in D-06) |
| Coverage statements / branches / functions | 87.05 % / 81.78 % / — | 95.00 % / 87.2 % / 97.8 % |
| Static-analysis health (audit score) | 61 C | gated by `task analyze:check` (see `BASELINES.md`) |

Limitations of these numbers: production lines grew slightly (module headers, named step
functions, comments kept verbatim); total decision points barely moved — server-layer logic was
split into named, ordered steps rather than reduced, which is the intended outcome of a
behaviour-preserving refactor. Test duplication rose in absolute terms because 322 new
characterisation tests were added and the test suite was split into 15 files (repeated import
blocks); the percentage fell slightly. Coverage rose mainly from new characterisation tests, not
from refactoring. None of these numbers alone shows the refactoring is correct; the evidence for that
is the differential checks below.

## 4. Validation results

- **Full test suite (final tip):** 793 tests / 58 files pass. The first run skipped the 3
  degree-credential tests because `initIssuer` hit the known F-06 flake in `beforeAll`; the rerun
  passed 793/793.
- **Build:** `pnpm build` pass. **Strict tsc** (`--noUnusedLocals --noUnusedParameters`): 0 diagnostics.
- **Lint:** `task lint` (Biome + design lint) pass.
- **Static analysis:** `task analyze:check` pass (madge 0 cycles; knip full and production clean;
  jscpd 3.5 % ≤ 4.0, src 0.2 % ≤ 0.5, tests 6.6 % ≤ 7.0).
- **Coverage:** 95.00 % statements, 87.2 % branches, 97.8 % functions (reported, not gated).
- **Per-task behaviour equivalence:** every Phase 5 task was checked by an independent reviewer
  with a differential harness against its base (e.g. C-03 8 125 requests, C-06 701, C-07 853 + 14,
  C-13 36 954 sessions, C-17 50 641 renders + 820 requests, C-08 byte-identical OpenAPI documents);
  see `PROGRESS.md`.
- **Protocol regression (V-01):** external scripted wallet against the real CLI (`init`, `serve`)
  of the baseline and final trees, 5 configuration profiles, 30–63 protocol requests each (issuance
  pre-authorized / by reference / authorization code with PAR + PKCE + DPoP / wallet-initiated / mdoc
  / encrypted; notifications; status-list revocation; OpenID4VP direct_post.jwt by reference, by
  value, request_uri POST with wallet_nonce, DC API, wallet error; FCAF mutation and response
  scenario; error paths). Baseline-vs-final differences are a subset of a baseline-vs-baseline
  control run's noise in every profile. Not executed: mdoc presentation (DeviceResponse
  construction), chained federation authority, Token Status List GET.
- **Final independent review (FR-01, Opus):** APPROVE, no Blocking or Major findings. Its own
  differential run over 9 322 HTTP cases (4 configurations, pairwise input matrices for session
  creation, request retrieval, VP submission, webhook) found no behaviour change (7 differences, all
  explained: control-run noise and the edited README shown by `/ui/help`). Minor findings: stale
  documentation paths (fixed, 8bd12a2); positional signatures and one type re-export (F-16);
  C-18 "as built" note (PLAN); directory-level cycles (F-17).
- **Real-wallet interoperability:** **not executed** (scripted HTTP client only).

## 5. Remaining risks

- **F-06 (pre-existing bug, needs approval to fix):** ≈ 0.8 % of `initIssuer` runs generate an
  issuer certificate with a non-minimal DER serial that OpenSSL rejects. Production impact: `init`
  can fail until re-run with `--force`; ≈ 0.2 % of verifier certificates are malformed. Test impact
  grew with the suite (58 files, many `initIssuer` calls): roughly every second full run hits it.
- **F-15 (pre-existing protocol deviation):** invalid DPoP, wrong proof `nonce`/`aud` and replayed
  proofs at the Credential Endpoint return `500 server_error` instead of OpenID4VCI errors.
- **F-07:** `POST /openid4vp/response` state lookup and missing DC API guards (pre-existing).
- **F-13:** some `/ui/openid4vp/sessions/:id` pages return 500 (suspected QR capacity).
- Deferred items X-2 … X-7; F-03 (unvalidated config file values); F-12 (config parser quirks).
- Flows needing manual validation: a real wallet against issuance (SD-JWT and mdoc) and
  presentation (SD-JWT, mdoc, DC API in a browser); federation trust chain with a real authority.
- Recommended next steps: fix F-06 (it now dominates test noise), F-15, F-16 options objects, decide
  the layering for F-17 and gate it.
