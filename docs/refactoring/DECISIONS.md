# Architecture decisions — refactoring

Each entry: decision, context, alternatives, reason, consequences, tasks.

## ADR-01 · Model assignment and subagent configuration

- **Decision:** implementation/test subagents use the `task` agent type pinned to
  `openai-codex/gpt-5.6-luna:high`; reviewers use the `reviewer` agent type pinned to
  `anthropic/claude-opus-5-5:high`, via the session setting `task.agentModelOverrides`. The main
  agent runs on `anthropic/claude-opus-5-5:high`.
- **Context:** INSTRUCTIONS.md §4 requires "Codex Luna" for implementation and "Claude Opus 5.5" for
  review, resolved from local configuration. The local `modelRoles` already use
  `openai-codex/gpt-5.6-luna` (roles `tiny`, `commit`) and `anthropic/claude-opus-5-5` (`default`). The
  provider catalogue also lists `openai-codex/gpt-6-luna`.
- **Alternatives:** `gpt-6-luna` (not the identifier in local configuration); per-call model selection
  (`task.perCallModel`, disabled locally).
- **Reason:** follow the identifiers present in local configuration; overrides apply to every spawn of
  the agent type without per-call configuration.
- **Consequences:** both overrides verified by probe subagents reporting `openai-codex/gpt-5.6-luna`
  and `anthropic/claude-opus-5-5`. The setting is session-only; re-apply on resume.
- **Tasks:** all.

## ADR-02 · Target directory structure

- **Decision:** domain directories `shared/`, `config/`, `credentials/`, `status-list/`, `credo/`,
  `openid4vci/`, `openid4vp/`, `fcaf/`, `server/` (+ `routes/`), `openapi/`, `ui/`, `cli/`, keeping
  `attestbook/`, `configurations/`, `federation/`, `design/`. `cli.ts`, `state.ts`, `types.ts` stay at
  `src/` root. See PLAN.md §3.1 for the file mapping.
- **Context:** 36 top-level `src/*.ts` files; issuer and verifier modules interleaved; FCAF scenario
  machinery spread across `request-*`, `response-scenario`, `json-pointer`.
- **Alternatives:** (a) keep a flat `src/` and only split oversized files — rejected: navigation stays
  poor and new split files would add 20+ more top-level files; (b) a `capture/` directory for
  `state.ts` + `types.ts` — rejected for now: both are cross-domain hubs (40 importers of `types.ts`),
  a move adds churn without boundary gain; (c) `src/cli/main.ts` as entry — rejected: `package.json`
  `bin` and scripts name `src/cli.ts` (CLI contract and pnpm bin symlink behaviour).
- **Reason:** protocol roles (issuer vs verifier) and conformance-testing machinery are the real
  seams; credentials and status lists are shared by both protocols.
- **Consequences:** a dedicated relocation task (B-10) performs pure moves after dead-code removal and
  before boundary work, so later tasks create modules in their final location. `config.ts`, `ui.ts`,
  `openapi.ts` move when they are split (B-06/B-07, C-17, C-08) to avoid temporary names.
- **Tasks:** B-10, B-01…B-09, C-*.

## ADR-03 · Static-analysis tooling distribution

- **Decision:** Knip 6.48.0, JSCPD 5.4.3 and Madge 8.0.0 are declared as pinned `npm:` tools in
  `mise.toml`; `@vitest/coverage-v8@2.1.9` is an exact-pinned devDependency. Taskfile exposes
  `analyze:dead-code`, `analyze:duplication`, `analyze:cycles`, `test:coverage`, `analyze`.
- **Context:** INSTRUCTIONS.md Decision 2 and AGENTS.md "Required Developer Tools" require tools used
  by validation to be declared in `mise.toml`. The coverage provider must be resolvable by Vitest from
  the project and must match Vitest 2.1.9.
- **Alternatives:** all four as devDependencies (rejected: double declaration with mise, and the
  instructions ask for mise declaration); `npx` at run time (rejected: unpinned, network-dependent).
- **Reason:** one declaration per tool; versions pinned; no runtime dependencies.
- **Consequences:** contributors run `mise install` once. Initial use is measurement only; Q-01 sets
  regression baselines.
- **Tasks:** R-03, Q-01.

## ADR-04 · Integration workflow

- **Decision:** dedicated integration worktree on branch `refactor/codebase-health` outside the user's
  checkout; one worktree and branch `rf/<TASK>` per implementation task; reviewed commits are
  cherry-picked (linear history, one commit per task); planning docs get their own commits.
- **Context:** the user's checkout on `master` has uncommitted changes that must not be touched.
- **Alternatives:** switching the user checkout to a refactoring branch (rejected: shares the working
  tree with the user); merge commits per task (rejected: unnecessary merge commits).
- **Consequences:** the branch is never merged into `master` automatically.
- **Tasks:** all.

## ADR-05 · Shared helper modules

- **Decision:** `src/shared/errors.ts` (`errorMessage`) and `src/shared/json.ts` (JSON guards) are the
  only cross-domain helper modules.
- **Context:** audit B-01/B-02 found 4 identical `errorMessage` copies and 9 equivalent record guards.
- **Alternatives:** a generic `utils.ts` (rejected: generic utility collection); leaving copies
  (rejected: 13 copies of two predicates).
- **Consequences:** undefined-returning `asRecord`/`asString` variants stay local (X-7).
- **Tasks:** B-01, B-02.
