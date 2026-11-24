# Refactoring progress

Owner: main agent. Implementation subagents never edit this file.

- Integration branch: `refactor/codebase-health` in `/home/matteo/src/ccw-refactor/integration`
- Base revision: `ae9e74c` (master, "chore: add code-refactoring skills")
- User checkout `/home/matteo/src/credimi-capture-wallet` at start: modified
  `.claude/helpers/graft-hooks.cjs`, `.claude/helpers/graft-statusline.cjs`; untracked
  `docs/refactoring/` (copied into the branch). Never modified by the refactoring.
- Implementation model: `openai-codex/gpt-5.6-luna` (`task`); reviewer model:
  `anthropic/claude-opus-5-5` (`reviewer`). Session setting to re-apply on resume:
  `task.agentModelOverrides = {"task": "openai-codex/gpt-5.6-luna:high", "reviewer": "anthropic/claude-opus-5-5:high"}`.
- Resume procedure: read PLAN.md, this file, DECISIONS.md, FINDINGS.md; `git -C integration log
  --oneline`; `git worktree list`; continue from the first task that is not Completed.

Statuses: Pending · Ready · In progress · Under review · Changes requested · Completed · Blocked · Deferred.

## Current batch

Batch 10 (B-02). Batches 0–9 completed.

## Tasks

| Task | Status | Depends on | Impl | Reviewer | Base | Commit | Review | Validation | Remaining risks |
|---|---|---|---|---|---|---|---|---|---|
| R-01 | Completed | — | Luna | Opus | de5eddf | 1787e51 (task 683e207) | APPROVE (no findings; optional: `./graft` pattern) | lint/task lint pass; 471 tests; build; Biome 89→88 files (only graft wiring.json dropped) | none |
| R-02 | Completed | — | Luna | Opus | de5eddf | b69173d (task 90d1287) | APPROVE after amendment (two optional findings adopted: 7 missing modules, server.ts description) | all 37 documented paths exist | map rewritten again in N-01 |
| R-03 | Completed | — | Luna | Opus | de5eddf | f6d6220 (task e4826a4) | APPROVE after amendment (analyze sequential; madge rc=1 for cycles and config errors, so `ignore_error` kept) | task analyze: 471 tests, 87.05 % stmts / 81.84 % branches, jscpd 61 C, madge 2 cycles, knip prod = openid4vp-validation.ts + dcql | madge failures indistinguishable from cycles until Q-01 |
| S-01a | Completed | R-01, R-02, R-03 | Luna | Opus | f6d6220 | 6e715cd (task a5f1771) | APPROVE after amendment (temp-dir cleanup on init failure, `data_dir` override blocked, exact VP assertions, nits); helper names kept (`postToken`, `preAuthorizedToken`) | 473/473 (+2 support tests), lint, build, strict tsc 8 pre-existing | callers must pass `issuerAppConfig(...)` to `credentialProofJwt` |
| T-01 | Completed | S-01a | Luna | Opus | 80e8b48 | 8de40a8 (task ce88b70) | APPROVE after 2 rounds (lint; DC API test asserted a false claim → real asymmetry pinned incl. evidence overwrite; state mismatch, wallet error branch, headers) | +14 tests; alternative response/events routes 8.7 % → 95.7 %; 487 full | FINDINGS F-07 (alternative endpoint state lookup, DC API guards skipped); success tests rely on Credo accepting an unrequested `state` |
| T-02 | Completed | S-01a | Luna | Opus | 8de40a8 | 99e3f0c (task 70c75a5) | APPROVE after 3 rounds (409 supersession reached deterministically via registry queue; pinned stale definition 400; full-body `toEqual` matrices; re-sign with header mutation; missing codes; order pairs; forward no-response 500 via spy; spies restored; CA test cleanup) | +73 tests | `ResponseModeError` mapping unreachable over HTTP (createVpSession overwrites `response_mode`) |
| T-03 | Completed | S-01a | Luna | Opus | 80e8b48 | 07f3dd7 (task 562c81e) | APPROVE after 3 rounds (real inputs instead of mocked Credo results; no-op `vi.doUnmock` removed; real wrapping case; deterministic tag tamper) | +22 tests; credential-encryption.ts 100 % stmts / 91.6 % branches (file alone) | invalid-JWK case pins Credo/zod message text |
| T-04 | Completed | S-01a | Luna | Opus | 80e8b48 | 08a97c4 (task c6bb4b4) | APPROVE after amendment (lint; id-conflict isolation; rollback restore order; concurrency test); 8/8 source mutations caught | +12 tests; credential-registry.ts 93.96 % / 92.1 % | static-conflict branches unreachable with real configs (F-08); D-04 must keep `CatalogueConflictError` export |
| T-05 | Completed | S-01a | Luna | Opus | 8de40a8 | ea76c05 (task ccffa76) | APPROVE after amendment (DCQL `multiple` case failed for an unrelated Credo rule → real cardinality case + positive case; DC API origin handover; exact JSON-pointer message; shared `keyAttestationJwt`) | +18 tests; mdoc branch of `decodedPresentationFromCredo` covered | Credo error strings copied verbatim |
| T-06 | Completed | S-01a | Luna | Opus | 8de40a8 | 77c9d77 (task 9905057) | APPROVE after 3 rounds (commit format; declared vs streamed size, body-read errors, deadline, URL rules; exact sync JSON, real rollback, real EISDIR, retry schedule; webhook order/logs; json-schema order); 16/18 then 18/18 source mutants caught | +72 tests; settings 100 %, http 100 % stmts | reconcile tests share fixture state in file order |
| T-07 | Completed | S-01a | Luna | Opus | ea76c05 | 5d9d4d3 (task 47ee0bb) | APPROVE after amendment (experimental exemption pinned); 15/18 mutants killed, survivors = check reordering (acceptable, no refactor follows) | +11 tests; validate.ts 100 % | F-11 (rule 2 reachable only with invalid compliance) |
| T-08 | Completed | S-01a | Luna | Opus | ea76c05 | 001853b (task bfad60d) | APPROVE after amendment (stdout compared as text incl. banner; full summary literals; token-present case; key stability across rerun; init stderr surfaced; real symlink invocation); 9/10 mutants caught (M13 `force` always false is indistinguishable by design) | +12 subprocess tests (~22 s); also verified on integration tip after D-03 | pnpm bin shell shim itself not exercised |
| T-09 | Completed | S-01a | Luna | Opus | 5d9d4d3 | f2211eb (task 2b9ed97) | APPROVE after amendment (full path sets per flag case; every issuer enum; distinct public URL) | +8 tests; openapi.ts 100 % | operation/component content guarded only by C-08's byte-equality script |
| D-01 | Completed | Phase 2 | Luna | Opus | 77c9d77 | 7630b46 (task e2cb02c) | APPROVE | strict tsc 0 diagnostics after D-05; inventory unchanged | only error-ordering edge case when both issuer key files are broken |
| D-02 | Completed | D-01 | Luna | Opus | 7630b46 | 8ca8351 (task 4578198) | APPROVE; reviewer proved byte-identical `x509_hash` and request URIs over 8 generated verifier materials | openid4vp.ts 100 % stmts; inventory unchanged | none |
| D-03 | Completed | D-01 | Luna | Opus | 7630b46 | dae9d82 (task d3f8460) | APPROVE; federation CLI output byte-identical base vs impl; `PID_MDOC_DOCTYPE` now imported from credential-definitions (same constant) | inventory unchanged | ESM import order in state.ts changed (no top-level side effects) |
| D-04 | Completed | T-04, D-02, D-03 | Luna | Opus | bfb538a | cdbaa61 (task c6b8e53) | APPROVE; deleted `CREDIMI_WEBSITE`, `supportedCredentialConfigurationIdsForIssuer` (no references); 62 symbols unexported | knip default 40+26 → 3+1 (tests/support exceptions for S-01b); knip production 71+28 → 35+3; 707/707 | `CredentialFormat` export handled in B-03 |
| D-05 | Completed | T-05 | Luna | Opus | 99e3f0c | e554463 (task 2413a62, message blank line fixed at integration) | APPROVE (only commit-message format) | 615/615; inventory: 7 tests relocated to `tests/mdoc-session-transcript.test.ts`, names unchanged; direct `dcql` removed (still transitive via Credo 3.0.1); knip prod no longer reports the file/dependency | none |
| D-06 | Completed | Phase 2 | Luna | Opus | 99e3f0c | e5c3cd8 (task 80eb750) | APPROVE | removed `jwkToJwks`, `firstWalletJwks` (no src consumers); no tests removed; renamed "extracts jwk from proof JWT header and converts it to JWKS" → "captures jwk from proof JWT header" and "detects kid-only proof headers without treating a key as observable" → "captures kid-only proof headers"; dead-helper assertions replaced by direct `captureProofHeaders` assertions (`source`, `jwk`); 615/615 | observed-field list in `mapCredentialRequest` still not unit-tested (pre-existing) |
| B-10 | Completed | Phase 3 | Luna | Opus | 65010ca | 5a14aef (task ce71c32) | APPROVE; reviewer script proved only specifiers changed in all 61 files; vi.mock path verified behaviourally (negative control) | 27 renames (91–100 %); inventory identical (707); same 2 type-only cycles | none |
| B-01 | Completed | B-10 | Luna | Opus | 5a14aef | fcf97d8 (task 3455d70) | APPROVE | 4 identical copies → `src/shared/errors.ts`; inline variants left (not helpers) | none |
| B-04 | Completed | B-10 | Luna | Opus | 5a14aef | 2c3a254 (task 71172bd) | APPROVE; verbatim move verified; `defaultBackend: kms.backend` (same value) | openid4vci no longer imports openid4vp | none |
| B-09 | Completed | B-10, T-08 | Luna | Opus | 5a14aef | 47729f9 (task 7e3c7ab) | APPROVE after amendment (AGENTS map, exact regex, two parseArgs quirks pinned) | +3 in-process tests; T-08 subprocess suite unchanged; 710/710 | in-process coverage excludes init/serve/attestbook (subprocess only) |
| B-02 | In progress | B-01 | Luna | Opus | 47729f9 | | | | |
| B-03 | Pending | B-02 | Luna | Opus | | | | | |
| B-05 | Pending | B-02, B-04, T-05 | Luna | Opus | | | | | |
| B-06 | Pending | B-03, B-09 | Luna | Opus | | | | | |
| B-07 | Pending | B-06, T-06, T-08 | Luna | Opus | | | | | |
| B-08 | Pending | B-07 | Luna | Opus | | | | | |
| C-01 | Pending | B-08, T-01 | Luna | Opus | | | | | |
| C-02 | Pending | C-01, T-02 | Luna | Opus | | | | | |
| C-03 | Pending | C-02 | Luna | Opus | | | | | |
| C-04 | Pending | C-03 | Luna | Opus | | | | | |
| C-05 | Pending | C-04, T-03 | Luna | Opus | | | | | |
| C-06 | Pending | C-05 | Luna | Opus | | | | | |
| C-13 | Pending | C-06, C-11, D-03 | Luna | Opus | | | | | |
| C-17 | Pending | C-13, B-03 | Luna | Opus | | | | | |
| C-08 | Pending | C-17, T-09 | Luna | Opus | | | | | |
| C-07 | Pending | C-08 | Luna | Opus | | | | | |
| C-09 | Pending | B-08, T-05, B-04 | Luna | Opus | | | | | |
| C-10 | Pending | B-08 | Luna | Opus | | | | | |
| C-11 | Pending | C-10, T-04 | Luna | Opus | | | | | |
| C-12 | Pending | B-08 | Luna | Opus | | | | | |
| C-14 | Pending | B-08, T-06 | Luna | Opus | | | | | |
| C-15 | Pending | C-14 | Luna | Opus | | | | | |
| C-16 | Pending | B-08, T-06 | Luna | Opus | | | | | |
| C-18 | Pending | C-15, B-07 | Luna | Opus | | | | | |
| S-01b | Pending | Phase 5 | Luna | Opus | | | | | |
| S-02 | Pending | S-01b | Luna | Opus | | | | | |
| S-03 | Pending | S-01b | Luna | Opus | | | | | |
| N-01 | Pending | S-02, S-03 | Luna | Opus | | | | | |
| Q-01 | Pending | N-01 | Luna | Opus | | | | | |
| X-5 | Deferred | Phase 5 (re-evaluate) | — | — | | | | | |
| V-01 | Pending | Q-01 | main + Luna | Opus | | | | | |
| FR-01 | Pending | V-01 | — | Opus | | | | | |

## Batch log

### Batch -1 — planning (main agent)

- Baseline captured in `/home/matteo/src/ccw-refactor/baseline/` (PLAN.md §2).
- Models verified by probe subagents (ADR-01).
- Plan, decisions, findings and this tracker committed as documentation.

### Batch 0 — R-01 ‖ R-02 ‖ R-03 (completed)

- Integrated as 1787e51, b69173d, f6d6220. Integration validation: lint pass (90 files), build pass,
  471/471 tests.
- Duplication baseline corrected to the TypeScript-only figure tracked by `.jscpd.json`: 3.03 %,
  89 clone pairs (the audit's 3.2 % / 97 also counted CSS and markup).
- Reviewer found a pre-existing intermittent failure (`asn1 … illegal padding` in
  `validateIssuerMaterial`); recorded as FINDINGS F-06, root cause under investigation.

### Batches 2–7 — Phase 2 (T-01…T-09) and Phase 3 (D-01…D-06) (completed)

- Integration tip after Phase 3: `cdbaa61`. Validation: build, `task lint`, strict tsc 0 diagnostics,
  707/707 tests in 35 files (inventory `reports/inventory-after-phase3.txt`).
- Test inventory grew 471 → 707: +236 characterisation tests; D-06 renamed 2 tests; D-05 relocated 7
  tests to `tests/mdoc-session-transcript.test.ts` (names unchanged). No test removed.
- Inventory names include temp paths in some `it.each` titles; `scripts/test-inventory.sh` now
  normalises `/tmp/<prefix>-XXXXXX` to `/tmp/<tmp>`.
- Reviews were substantive: several suites initially asserted too little; reviewers mutation-tested
  production code in throwaway copies and every Major finding was fixed before integration.
- New findings: F-07 (alternative `/openid4vp/response` route), F-08, F-09 (ledger millisecond race,
  flaky), F-10 (possible Credo state flake), F-11 (dead conformance rule).
- Subagent tooling incident: one implementer tried the eval `commit` namespace (which targets the
  user's checkout); it did not commit there. Briefs now forbid it; user checkout verified unchanged.
