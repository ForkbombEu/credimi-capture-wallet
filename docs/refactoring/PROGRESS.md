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

Batch 0 (R-01 ‖ R-02 ‖ R-03).

## Tasks

| Task | Status | Depends on | Impl | Reviewer | Base | Commit | Review | Validation | Remaining risks |
|---|---|---|---|---|---|---|---|---|---|
| R-01 | Ready | — | Luna | Opus | | | | | |
| R-02 | Ready | — | Luna | Opus | | | | | |
| R-03 | Ready | — | Luna | Opus | | | | | |
| S-01a | Pending | R-01, R-02, R-03 | Luna | Opus | | | | | |
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
