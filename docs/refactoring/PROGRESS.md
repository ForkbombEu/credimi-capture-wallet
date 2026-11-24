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

Batch 2 (T-01 ‖ T-03 ‖ T-04). Batches 0–1 completed.

## Tasks

| Task | Status | Depends on | Impl | Reviewer | Base | Commit | Review | Validation | Remaining risks |
|---|---|---|---|---|---|---|---|---|---|
| R-01 | Completed | — | Luna | Opus | de5eddf | 1787e51 (task 683e207) | APPROVE (no findings; optional: `./graft` pattern) | lint/task lint pass; 471 tests; build; Biome 89→88 files (only graft wiring.json dropped) | none |
| R-02 | Completed | — | Luna | Opus | de5eddf | b69173d (task 90d1287) | APPROVE after amendment (two optional findings adopted: 7 missing modules, server.ts description) | all 37 documented paths exist | map rewritten again in N-01 |
| R-03 | Completed | — | Luna | Opus | de5eddf | f6d6220 (task e4826a4) | APPROVE after amendment (analyze sequential; madge rc=1 for cycles and config errors, so `ignore_error` kept) | task analyze: 471 tests, 87.05 % stmts / 81.84 % branches, jscpd 61 C, madge 2 cycles, knip prod = openid4vp-validation.ts + dcql | madge failures indistinguishable from cycles until Q-01 |
| S-01a | Completed | R-01, R-02, R-03 | Luna | Opus | f6d6220 | 6e715cd (task a5f1771) | APPROVE after amendment (temp-dir cleanup on init failure, `data_dir` override blocked, exact VP assertions, nits); helper names kept (`postToken`, `preAuthorizedToken`) | 473/473 (+2 support tests), lint, build, strict tsc 8 pre-existing | callers must pass `issuerAppConfig(...)` to `credentialProofJwt` |
| T-01 | Pending | S-01a | Luna | Opus | | | | | |
| T-02 | Pending | S-01a | Luna | Opus | | | | | |
| T-03 | Pending | S-01a | Luna | Opus | | | | | |
| T-04 | Pending | S-01a | Luna | Opus | | | | | |
| T-05 | Pending | S-01a | Luna | Opus | | | | | |
| T-06 | Pending | S-01a | Luna | Opus | | | | | |
| T-07 | Pending | S-01a | Luna | Opus | | | | | |
| T-08 | Pending | S-01a | Luna | Opus | | | | | |
| T-09 | Pending | S-01a | Luna | Opus | | | | | |
| D-01 | Pending | Phase 2 | Luna | Opus | | | | | |
| D-02 | Pending | D-01 | Luna | Opus | | | | | |
| D-03 | Pending | D-01 | Luna | Opus | | | | | |
| D-04 | Pending | T-04, D-02, D-03 | Luna | Opus | | | | | |
| D-05 | Pending | T-05 | Luna | Opus | | | | | |
| D-06 | Pending | Phase 2 | Luna | Opus | | | | | |
| B-10 | Pending | Phase 3 | Luna | Opus | | | | | |
| B-01 | Pending | B-10 | Luna | Opus | | | | | |
| B-04 | Pending | B-10 | Luna | Opus | | | | | |
| B-09 | Pending | B-10, T-08 | Luna | Opus | | | | | |
| B-02 | Pending | B-01 | Luna | Opus | | | | | |
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
