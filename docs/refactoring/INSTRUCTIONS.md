# Comprehensive Codebase Refactoring — credimi-capture-wallet

## 1. Objective

The previously completed codebase audit and proposed refactoring plan are approved in principle.

Revise the existing plan according to the requirements below, persist the revised plan in the repository, and proceed with its implementation.

The objective is to substantially improve the entire codebase in terms of:

- Readability.
- Maintainability.
- Architectural consistency.
- Separation of responsibilities.
- Code duplication.
- Dead and unused code.
- Cognitive and cyclomatic complexity.
- Type safety.
- Test quality and organisation.
- Developer experience.
- Codebase navigation for both humans and coding agents.

Use the existing `improve-codebase-architecture` and `codebase-refactoring` skills throughout the process, together with Graft and the static analysis tools identified during the audit.

This is a comprehensive refactoring, not a rewrite.

The final codebase must be easier to understand, navigate, maintain, extend and test, without changing its externally observable behaviour.

## 2. Mandatory repository instructions

Read and strictly follow `AGENTS.md`.

Use Graft according to the instructions provided in `AGENTS.md`:

- Use `graft map` to understand the architecture.
- Use `graft ask` to retrieve relevant context.
- Use `graft callers` to establish dependencies and blast radius.
- Use `graft skeleton` to inspect module interfaces.
- Use `graft grep` for exhaustive symbol searches.
- Refresh the graph after significant architectural changes.

Every subagent must independently read and comply with `AGENTS.md`.

Preserve existing unrelated working-tree changes, untracked files, secrets, certificates, configuration files and captured evidence.

Do not discard, overwrite, stash or commit unrelated user changes.

Do not push, deploy, publish or create releases.

## 3. Approved decisions from the audit

### Decision 1 — Remove the legacy OpenID4VP validator

Approve D-05.

Remove `src/openid4vp-validation.ts` after:

- Completing the required mdoc regression tests.
- Confirming that it has no production consumers, dynamic imports or known external consumers.
- Confirming that its production responsibilities are already handled by Credo-TS.
- Moving necessary test-only helpers into appropriate test-support modules.
- Preserving meaningful coverage of the retained helpers.

Remove the direct `dcql` dependency if it becomes unused.

Update `package.json`, the lockfile, documentation and affected imports accordingly.

The dependency removal is explicitly approved and does not require further confirmation.

### Decision 2 — Permanent static analysis tooling

Approve permanent integration of:

- Knip.
- JSCPD.
- Madge.
- Vitest coverage.

Pin compatible versions and declare required tools in `mise.toml`, following `AGENTS.md`.

Use a coverage provider compatible with the currently installed Vitest version. Do not upgrade Vitest or unrelated dependencies merely to introduce coverage.

Provide consistent Taskfile commands for:

- Dead code analysis.
- Duplication analysis.
- Circular dependency analysis.
- Test coverage.
- Combined codebase analysis.

Initially, use these tools to collect measurements and identify refactoring candidates rather than enforcing arbitrary blocking thresholds.

Once the refactoring is complete, establish sustainable regression-prevention baselines.

Do not introduce new runtime dependencies.

### Decision 3 — Remove tests covering confirmed dead code

Approve D-06.

Remove tests that exclusively exercise confirmed dead or obsolete code.

Document:

- Removed functions.
- Removed tests.
- Reasons for removal.
- Evidence that production behaviour is unaffected.

Preserve all meaningful regression coverage.

A reduction in test count resulting from removing obsolete implementations is acceptable.

## 4. Agent configuration and delegation

### Mandatory model assignments

Use the current coding agent's native subagent system.

The model assignments are:

| Role | Model |
|---|---|
| Main agent | Claude Opus 5.5 |
| Architect and orchestrator | Claude Opus 5.5 |
| Implementation subagents | Codex Luna |
| Test implementation subagents | Codex Luna |
| Independent reviewer subagents | Claude Opus 5.5 |
| Final architecture reviewer | Claude Opus 5.5 |

Use high reasoning effort where supported, particularly for protocol-sensitive implementation and review.

Resolve the exact model identifiers from the local agent configuration.

Verify model availability before starting.

Do not silently substitute another model or fall back to a weaker model. If a required model is unavailable, report the configuration problem.

Do not use:

- Superagent.
- GitHub issues as implementation tasks.
- External coding automation.
- External orchestration services.

All orchestration, implementation, review and integration must happen through the current agent and its native subagents.

### Main agent responsibilities — Claude Opus 5.5

The main agent is the architect, orchestrator and integration owner.

It must:

- Own the complete refactoring plan.
- Maintain the overall architectural vision.
- Define module boundaries and architectural conventions.
- Establish the final target directory structure.
- Identify task dependencies and conflicts.
- Determine which tasks can execute concurrently.
- Prepare focused implementation assignments.
- Delegate implementation to Codex Luna subagents.
- Delegate independent review to Claude Opus 5.5 reviewer subagents.
- Evaluate reviewer findings.
- Resolve architectural ambiguity.
- Integrate completed work.
- Maintain consistency across modules.
- Run integration-level validation.
- Maintain persistent progress documentation.
- Reassess the plan when actual implementation findings justify changes.

The main agent should primarily coordinate, design, review and integrate rather than implement every task itself.

Complex architectural and protocol decisions must remain the responsibility of the main agent.

Codex Luna subagents must not independently establish new architectural conventions.

### Implementation subagent responsibilities — Codex Luna

Each implementation subagent must receive a focused, self-contained assignment containing:

- Task identifier.
- Task objective.
- Relevant architectural decisions.
- Affected files and symbols.
- Relevant Graft context.
- Explicit scope boundaries.
- Dependencies.
- Protocol-specific constraints.
- Behaviour that must be preserved.
- Required tests.
- Validation commands.
- Acceptance criteria.
- Expected deliverables.

Each subagent must read `AGENTS.md` before making changes.

Implementation subagents must:

- Implement only their assigned task.
- Preserve existing behaviour.
- Follow the established architecture.
- Avoid speculative abstractions.
- Avoid unrelated cleanup.
- Avoid expanding the assigned scope.
- Run the required validation.
- Inspect their diff before committing.
- Produce one focused implementation commit using the required commit format.

Each subagent must report:

- Changes implemented.
- Files modified.
- Tests added or removed.
- Validation commands and results.
- Unexpected findings.
- Remaining risks.
- Commit identifier.

If an assignment requires a meaningful architectural, protocol or security decision not covered by the plan, the subagent must escalate it to the main agent rather than guessing.

### Independent reviewer responsibilities — Claude Opus 5.5

Every completed implementation task must be independently reviewed by a Claude Opus 5.5 subagent.

The reviewer must be separate from the implementation subagent and should receive:

- Original task definition.
- Relevant architectural decisions.
- Base commit.
- Implementation commit and diff.
- Validation results.
- Relevant source and protocol context.

The reviewer must independently inspect the actual changes rather than trusting the implementation report.

Reviewers must evaluate:

- Behaviour preservation.
- Protocol correctness.
- Security implications.
- Readability.
- Maintainability.
- Architectural consistency.
- Module cohesion.
- Unnecessary abstractions.
- Type safety.
- Error handling.
- Evidence capture.
- Regression test adequacy.
- Compliance with `AGENTS.md`.

Reviewers should initially operate in read-only mode.

Classify findings as:

- Blocking.
- Major.
- Minor.
- Optional improvement.

Blocking and major findings must be resolved before integration.

Return required corrections to a Codex Luna implementation subagent and repeat review and validation.

Corrections should be incorporated into the task's focused implementation commit before integration, where safe and consistent with the repository's commit requirements.

A passing test suite is not sufficient evidence of a successful refactoring.

### Parallel execution

Execute independent tasks in parallel where practical.

Initially limit concurrency to three implementation subagents.

Use isolated Git worktrees or equivalent isolation for concurrent writing subagents.

Requirements:

- Never allow concurrent writing subagents to modify the same working tree.
- Avoid assigning overlapping files to concurrent tasks.
- Account for semantic dependencies, not only file overlap.
- Respect the task dependency graph.
- Start dependent tasks from the latest integrated revision.
- Keep architectural changes affecting shared interfaces sequential.
- Keep middleware-order changes sequential.
- Keep foundational module changes sequential when downstream tasks depend on them.
- Review and validate each task before integration.
- Run integration validation after combining parallel tasks.

If an unexpected conflict occurs, the main agent must resolve it or schedule a dedicated correction task.

Read-only exploration and review can execute concurrently with implementation when the reviewed revision is explicitly identified.

Increase or decrease concurrency according to task complexity, resource availability and integration risk.

## 5. Architectural principles

### Domain-oriented organisation

Define a cohesive target directory structure before beginning major structural changes.

Prefer domain-oriented directories over introducing numerous additional top-level files in `src/`.

Consider a structure similar to:

```
src/
├── attestbook/
├── cli/
├── config/
├── configurations/
├── credo/
├── federation/
├── openapi/
├── openid4vci/
├── openid4vp/
├── server/
│   └── routes/
├── shared/
└── ui/

tests/
├── support/
└── domain-specific test suites
```

This is an illustrative structure, not a mandatory final layout.

The main agent must evaluate the actual codebase and select the most cohesive structure.

Preserve existing domain directories where appropriate.

Avoid creating directories containing only one trivial module without a clear architectural reason.

Evaluate whether the large `types.ts` file should be reorganised by domain, but do not introduce a large import migration unless it produces a meaningful maintainability benefit.

### Deep modules and simple interfaces

Apply the principles from the `improve-codebase-architecture` skill.

Prefer:

- Deep modules with small, clear interfaces.
- High cohesion within modules.
- Low coupling between modules.
- Explicit dependencies.
- Domain-specific terminology.
- Predictable file organisation.
- Straightforward control flow.
- Testable boundaries.
- Clear ownership of state and side effects.

Avoid:

- Shallow modules.
- Excessive indirection.
- Unnecessary wrappers.
- Generic service layers.
- Speculative abstractions.
- Generic utility collections.
- Excessive numbers of small files.
- Artificial architectural patterns.
- Compatibility re-export layers without a genuine external compatibility requirement.
- Extracting functions merely to reduce the size of another function.

An abstraction must justify its existence through improved readability, cohesion, reuse or testability.

Do not replace a large cohesive module with numerous tiny modules that are collectively harder to understand.

### Complexity and readability

Do not optimise blindly for:

- Lines of code.
- File size.
- Number of functions.
- Cyclomatic complexity.
- Duplication percentages.
- Static analysis health scores.

Treat these measurements as indicators rather than absolute acceptance criteria.

Extract functions only when they represent cohesive responsibilities or meaningfully improve readability.

Do not simply relocate complexity into additional helpers.

Prefer explicit code over clever, compact or overly generic implementations.

Remove comments that merely restate the code, but preserve comments explaining:

- Protocol requirements.
- Security decisions.
- Interoperability constraints.
- Intentional malformed behaviour.
- Non-obvious ordering requirements.
- Historical compatibility decisions.

Use clear and consistent domain terminology.

Where practical, prefer options objects over long positional parameter lists, especially when adjacent parameters share the same type.

### Deduplication

Consolidate implementations only when they are semantically equivalent.

Do not merge code merely because it looks similar.

Before deduplicating, compare:

- Accepted inputs.
- Return values.
- Error handling.
- Side effects.
- Ordering.
- Default values.
- Security checks.
- Protocol requirements.
- Evidence capture.
- Null and undefined semantics.

Preserve intentionally different implementations.

Do not introduce a generic abstraction when two straightforward domain-specific implementations are easier to understand.

### Dead code

Use Knip, TypeScript diagnostics, Graft and direct source inspection to identify unused code.

Static analysis results are candidates, not proof.

Before removing code, verify relevant:

- Static imports.
- Dynamic imports.
- CLI entry points.
- Runtime configuration.
- Test fixtures.
- Public exports.
- Scripts.
- External consumers.
- Documentation references.

Remove confirmed dead code and unnecessary exports.

Do not delete code solely because it has low coverage.

## 6. Behaviour preservation

The refactoring must preserve externally observable behaviour.

Preserve all existing:

- Public HTTP endpoints.
- Request and response schemas.
- HTTP status codes.
- Error codes and descriptions.
- Content types.
- Response headers.
- Redirect behaviour.
- Configuration formats.
- Environment variable semantics.
- CLI interfaces.
- Persistence formats.
- Session lifecycle.
- Event ordering.
- Evidence capture.
- Redaction.
- OpenAPI documentation output.
- UI behaviour and appearance.

Preserve distinctions between:

- `null`.
- `undefined`.
- Omitted fields.
- Empty strings.
- Empty arrays.
- Missing configuration.
- Explicit default values.

Preserve the order of validation when it affects which error is returned.

Preserve the order of side effects when it affects protocol behaviour, session state or captured evidence.

Use byte-identical output comparisons only for deterministic outputs.

For nondeterministic outputs involving timestamps, UUIDs, nonces, JWT signatures, certificates or cryptographic material:

- Control the nondeterministic inputs where practical.
- Compare decoded structures semantically.
- Independently validate signatures and cryptographic properties.
- Preserve relevant claim values, headers and encoding requirements.

Do not weaken existing tests or alter expected behaviour merely to accommodate a refactoring.

If characterization tests reveal existing bugs, vulnerabilities or protocol nonconformities, document them separately.

Do not silently fix them during this refactoring.

## 7. Protocol and security constraints

This repository implements protocol-sensitive OpenID4VCI and OpenID4VP services.

Preserve all relevant behaviour concerning:

- OpenID4VCI 1.0.
- OpenID4VP 1.0.
- OpenID Federation.
- SD-JWT VC.
- mdoc.
- DCQL.
- DC API.
- DPoP.
- PKCE.
- Client attestation.
- Wallet attestation.
- Credential encryption.
- Presentation response encryption.
- Request object signing.
- Credential signing.
- Holder binding.
- Nonce validation.
- Audience validation.
- Certificate validation.
- Status lists.
- Trust mechanisms.
- Attestbook integration.
- FCAF conformance-testing scenarios.

Credo-TS remains the mandatory primary library according to `AGENTS.md`.

Do not replace Credo-TS functionality with custom implementations.

Do not introduce new cryptographic or protocol libraries.

Do not change the pinned Credo-TS version.

Do not modify signature verification, trust validation or security requirements to simplify the implementation.

Preserve intentionally malformed, permissive and negative-testing behaviours.

This application is a capture and conformance-testing tool. Behaviour that would be inappropriate in a conventional production issuer or verifier may be intentionally supported here.

Do not remove such behaviour without explicit approval.

Preserve the fidelity of captured wallet input and protocol evidence, including differences between raw, normalized, decoded and redacted representations.

When refactoring protocol-sensitive logic, consult the applicable authoritative specifications and the existing Credo-TS integration.

## 8. Persistent planning and progress tracking

Create and maintain the following files:

```
docs/refactoring/
├── PLAN.md
├── PROGRESS.md
├── DECISIONS.md
└── FINDINGS.md
```

### PLAN.md

Maintain:

- Original audit findings.
- Revised complete task list.
- Target directory structure.
- Architectural principles.
- Task dependencies.
- Execution batches.
- Scope boundaries.
- Assigned agent roles and models.
- Acceptance criteria.
- Validation strategy.
- Interoperability validation strategy.

Retain the existing task identifiers where possible, including R-, T-, D-, B-, C-, S- and N-series tasks.

Do not replace the detailed original audit with a generic refactoring checklist.

Preserve its concrete findings, affected files, symbols and protocol-specific constraints.

### PROGRESS.md

For every task, record:

- Task identifier.
- Status.
- Dependencies.
- Assigned implementation model.
- Assigned reviewer model.
- Base revision.
- Implementation commit.
- Review outcome.
- Validation results.
- Remaining risks.

Use consistent statuses:

- Pending.
- Ready.
- In progress.
- Under review.
- Changes requested.
- Completed.
- Blocked.
- Deferred.

Keep this file updated between execution batches.

The main agent owns the progress tracker. Implementation subagents must not concurrently edit it.

### DECISIONS.md

Record significant architectural decisions and their rationale.

Include:

- Decision.
- Context.
- Alternatives considered.
- Reason for the selected approach.
- Consequences.
- Relevant task identifiers.

Avoid documenting trivial implementation decisions.

### FINDINGS.md

Record discoveries that are outside the approved refactoring scope, including:

- Existing bugs.
- Security concerns.
- Protocol nonconformities.
- Potential future improvements.
- Deferred behavioural changes.
- Unresolved interoperability problems.

Document these findings without silently expanding the current implementation scope.

### Session resumption

The persistent documentation must allow the refactoring to resume after:

- Context compaction.
- Agent restart.
- Model session expiration.
- Interrupted execution.
- Subagent failure.

When resuming, read the persistent documentation, inspect Git state, verify completed commits and continue from the next ready task.

Do not repeat previously completed work unnecessarily.

## 9. Revised execution phases

Use the original audit's detailed task definitions as the basis for implementation, with the following revised ordering.

### Phase 0 — Tooling, planning and baseline

Complete:

- R-01: Fix the lint gate.
- R-02: Correct stale references in `AGENTS.md`.
- Integrate the approved static analysis tools.
- Establish the persistent refactoring documentation.
- Define the target directory structure.
- Correct the dependency graph.
- Establish isolated execution and integration conventions.

Capture the initial baseline:

- Current Git revision.
- Existing working-tree changes.
- Test inventory.
- Test results.
- Build results.
- Lint results.
- Statement coverage.
- Branch coverage.
- Duplication measurements.
- Dead code findings.
- Circular dependencies.
- Major complexity hotspots.

The audit previously reported:

- 471 passing tests across 19 files.
- 87.1% statement coverage.
- 81.8% branch coverage.
- 3.2% duplicated lines.
- 97 duplicated blocks.
- Two type-only import cycles.
- Overall health score of 61.
- Complexity score of 38.

Revalidate these measurements against the actual starting revision.

Do not assume that the repository remains identical to the audited revision.

Fix the existing Biome issue involving Graft-generated files without reducing meaningful lint coverage.

Establish a clean validation baseline before proceeding.

### Phase 1 — Minimal shared test infrastructure

Implement the foundational part of S-01 before introducing additional safety-net tests.

Create minimal reusable test-support infrastructure for:

- Isolated temporary directories.
- Issuer and verifier initialization.
- Server lifecycle.
- HTTP request helpers.
- Deterministic fixtures.
- Shared configuration.

Add characterization tests where needed to protect the behaviour of the extracted infrastructure.

Keep this phase focused.

Do not restructure the entire existing test suite yet.

Do not introduce a complex testing framework or overly generic fixture abstraction.

Use this infrastructure for the new safety-net tests.

### Phase 2 — Regression protection

Complete T-01 through T-09 from the original audit:

- T-01: VP response endpoints.
- T-02: Session creation and credential endpoint error matrices.
- T-03: Credential encryption security checks.
- T-04: Credential registry conflicts and rollback.
- T-05: mdoc presentation end-to-end coverage.
- T-06: Attestbook security checks.
- T-07: Issuer configuration validation.
- T-08: CLI behaviour.
- T-09: Conditional OpenAPI paths.

Preserve the concrete test cases and uncovered branches identified in the original audit.

Add missing characterization coverage before modifying corresponding production code.

Where appropriate, use table-driven tests.

Assert meaningful behaviour, including:

- Exact protocol error codes.
- HTTP status codes.
- Response structures.
- Evidence fields.
- Security rejection behaviour.
- State transitions.
- Ordering of validation and side effects.

Prefer tests of public or meaningful module interfaces over tests coupled to private implementation details.

Make tests deterministic, isolated and independently executable.

Do not modify production behaviour during this phase.

If existing behaviour prevents an intended regression test from passing, investigate and document the discrepancy. Do not silently fix production code.

### Phase 3 — Dead code removal

Complete D-01 through D-06:

- D-01: Remove unused imports, locals and parameters.
- D-02: Remove the legacy pre-Credo request builder.
- D-03: Remove dead wrappers, re-exports and unreachable defaults.
- D-04: Stop exporting internal-only symbols.
- D-05: Remove the unused legacy OpenID4VP validator.
- D-06: Remove obsolete test-only helpers.

Apply the approved dependency cleanup.

Preserve the distinctions and exceptions identified in the original audit.

Do not remove meaningful tests merely to satisfy static analysis.

Ensure CLI and runtime entry points remain functional.

### Phase 4 — Architecture and module boundaries

Complete B-01 through B-09, adapted to the approved domain-oriented directory structure:

- B-01: Consolidate equivalent error-message helpers.
- B-02: Consolidate equivalent JSON guards.
- B-03: Resolve import cycles and inappropriate dependency directions.
- B-04: Extract the shared Credo agent runtime.
- B-05: Extract presentation decoding.
- B-06: Separate cohesive configuration responsibilities, phase A.
- B-07: Separate cohesive configuration responsibilities, phase B.
- B-08: Separate credential catalogue responsibilities from metadata generation.
- B-09: Improve CLI testability.

Retain the original audit's concrete constraints.

Do not create unnecessary micro-modules.

Keep configuration parsing and serialization compatible with existing files.

Preserve key material handling and filesystem permissions.

Preserve CLI behaviour under package-manager binary symlinks.

Do not introduce generic wrappers or compatibility re-export layers without an actual compatibility requirement.

Resolve the existing type-only cycles where this improves architectural dependency direction, but do not introduce excessive indirection merely to satisfy Madge.

### Phase 5 — Production code simplification

Complete C-01 through C-18 in the corrected dependency order.

#### Server and route responsibilities

- C-01: Deduplicate equivalent VP submission and session lookup logic.
- C-02: Simplify issuance session creation.
- C-03: Simplify presentation session creation.
- C-04: Simplify presentation request retrieval.
- C-05: Simplify credential endpoint handling.
- C-06: Replace excessive positional parameters and improve session state responsibilities.
- C-07: Make `createApp` a composition root with cohesive route modules.

Preserve:

- Middleware ordering.
- Request path semantics.
- Capture attribution.
- Raw body handling.
- Body parser ordering.
- Error handling.
- Route registration ordering where meaningful.
- Routes that intentionally fall through.
- Session-specific submission restrictions.
- HTML versus JSON response distinctions.

When comparing route inventories, account for nested Express routers and middleware ordering. A flat inspection of `app._router.stack` is insufficient after router extraction.

Add HTTP-level regression tests for routing, fallthrough and middleware-sensitive behaviour.

#### OpenAPI

- C-08: Split OpenAPI generation into cohesive sections.

Preserve conditional paths, schemas, tags, ordering and deterministic output.

Do not fix missing documented endpoints during this refactoring unless separately approved.

#### OpenID4VP and OpenID4VCI

- C-09: Simplify `CredoOpenId4VpVerifier.createSession`.
- C-10: Extract issuance attribution and evidence responsibilities.
- C-11: Simplify credential request mapping.
- C-12: Consolidate equivalent SD-JWT signing-envelope construction.
- C-13: Replace the excessive `CaptureStore.createSession` positional parameters.

Preserve:

- Signing order.
- Mutation order.
- Intentional request corruption.
- Request delivery modes.
- Session transcript generation.
- Credential binding.
- Status-list allocation.
- Evidence recording order.
- Error semantics.
- Redaction.
- Differences between credential formats.

Use controlled or semantic comparisons for cryptographic output.

#### Attestbook

- C-14: Simplify webhook handling.
- C-15: Simplify catalogue reconciliation.
- C-16: Simplify JSON Schema processing and bounded HTTP fetching.

Preserve:

- Webhook signature verification.
- Origin validation.
- Bounded response handling.
- Rejection codes.
- Diagnostic ordering.
- Retry behaviour.
- Rollback.
- Queue behaviour.
- Persistence.
- No-leak guarantees.

#### UI and type safety

- C-17: Organise UI rendering into cohesive page families.
- C-18: Improve type safety at boundaries without runtime changes.

Preserve existing rendered HTML, CSS, JavaScript and user-visible behaviour.

Do not introduce a frontend framework.

Do not redesign the UI.

Do not replace TypeScript casts at Credo-TS boundaries unless the replacement is compatible with the pinned library version and preserves behaviour.

Evaluate complexity improvements holistically rather than accepting changes solely because a particular function becomes shorter.

### Phase 6 — Test code simplification

Complete the remaining S-01 work, followed by S-02 and S-03.

- Finish the shared test harness.
- Consolidate genuinely equivalent DPoP and protocol test helpers.
- Split the oversized `server.test.ts` suite by domain or concern.
- Consolidate equivalent issuer fixtures.
- Remove unnecessary test duplication.

The original `server.test.ts` was approximately 7,922 lines.

The objective is to produce cohesive, understandable test suites rather than simply satisfy a maximum line count.

Preserve meaningful test identities wherever practical.

Keep tests isolated with independent temporary directories and cleanup.

Preserve mock scope.

Check that tests pass:

- Individually.
- As part of their domain suite.
- As part of the complete test suite.
- Under supported parallel execution.

Do not merge fixtures that differ in security requirements, nonce behaviour, attestation requirements, credential metadata or expected return contracts.

Do not allow shared test helpers to hide important protocol-specific assertions.

### Phase 7 — Documentation, navigation and quality gates

Complete N-01 and the additional documentation tasks.

- Update the `AGENTS.md` repository map.
- Update references to moved or removed files.
- Document the final architectural boundaries.
- Document the static analysis commands.
- Update developer workflows where necessary.
- Refresh Graft.
- Verify that all documented paths exist.
- Verify that the project remains straightforward to navigate.

Establish final static analysis baselines for:

- Unused code.
- Unused dependencies.
- Duplication.
- Circular dependencies.
- Statement coverage.
- Branch coverage.

Configure regression-prevention checks where appropriate.

Do not introduce excessively strict or arbitrary thresholds.

Prefer preventing new technical debt over enforcing cosmetic targets.

The original audit's health-score targets may be used as directional indicators, but must not become a reason to introduce unnecessary abstractions or remove meaningful tests.

### Phase 8 — Final interoperability validation

Perform final protocol and interoperability validation beyond ordinary unit tests.

Cover the applicable supported flows:

| Domain | Required validation |
|---|---|
| OpenID4VCI | Authorization code issuance |
| OpenID4VCI | Pre-authorized code issuance |
| OpenID4VCI | Wallet-initiated issuance |
| OpenID4VCI | DPoP and client attestation |
| OpenID4VCI | Credential request and response encryption |
| OpenID4VCI | Notification handling |
| OpenID4VP | SD-JWT presentations |
| OpenID4VP | mdoc presentations |
| OpenID4VP | DC API presentations |
| OpenID4VP | Request by reference and by value |
| OpenID4VP | Signed and intentionally malformed requests |
| Federation | Entity configuration and trust-chain behaviour |
| Attestbook | Synchronization, import and credential issuance |
| Status lists | Valid and revoked credentials |
| FCAF | Intentional negative and malformed scenarios |

Use existing integration tests and available real-wallet testing infrastructure where possible.

Use isolated test environments and generated test credentials.

Do not deploy changes or modify shared remote services without explicit approval.

Where real-wallet testing is unavailable, clearly distinguish:

- Successfully validated automated flows.
- Flows validated using simulated clients.
- Flows requiring real-wallet verification.
- Flows that could not be validated.
- Remaining interoperability risks.

Never claim that a real-wallet flow passed unless it was actually executed successfully.

Compare final protocol behaviour against the initial baseline.

## 10. Validation strategy

### Per-task validation

Run focused validation during implementation.

Before completing each source-code or test task, run the standard repository validation required by `AGENTS.md`:

```
pnpm test
pnpm build
pnpm lint
```

Also run the repository formatter and `task lint` as required.

Run additional relevant checks depending on the task:

- TypeScript unused-local and unused-parameter diagnostics.
- Knip.
- JSCPD.
- Madge.
- Coverage.
- Focused protocol regression tests.
- Output comparisons.
- HTTP contract tests.

Use the correct pinned toolchain and package-manager versions.

Do not bypass failing tests or lint checks.

Do not weaken repository validation to make a task pass.

If a validation failure predates the task, establish evidence that it is pre-existing and report it to the main agent.

### Test inventory validation

Compare test identities against the immediate pre-task baseline.

Do not use the original fixed count of 471 tests as an acceptance criterion for later phases.

For each refactoring task:

- Capture the pre-task test inventory.
- Capture the post-task test inventory.
- Identify added tests.
- Identify removed tests.
- Identify renamed or relocated tests.
- Verify that every intentional difference is justified.

Account for repeated test names and file relocation when comparing inventories.

Use test inventories as a safeguard against accidental test removal, not as proof that coverage or assertions remain equivalent.

### Integration validation

After every execution batch:

- Integrate reviewed implementation commits.
- Inspect the combined diff.
- Run relevant integration tests.
- Run full tests, build and lint.
- Check for unexpected architectural inconsistencies.
- Check for regressions introduced by interactions between parallel tasks.
- Update the progress tracker.
- Refresh Graft when necessary.
- Reassess the next execution batch.

If combined validation fails, identify and resolve the responsible change before continuing with dependent tasks.

### Coverage validation

Use statement and branch coverage to identify regression risks.

Do not optimise coverage by adding meaningless assertions or excluding difficult code.

Compare coverage against equivalent production code where possible.

Removing dead code may change overall coverage percentages; interpret these changes in context.

Prioritise coverage of:

- Public endpoints.
- Protocol branches.
- Security rejection paths.
- State transitions.
- Persistence and rollback.
- Cryptographic integration boundaries.

## 11. Git and integration strategy

Use a dedicated local refactoring integration branch based on the appropriate current revision.

Preserve all existing user changes on their original working tree.

Use isolated worktrees for concurrent implementation tasks.

Requirements:

- One focused implementation commit per task.
- Commit messages must follow `AGENTS.md`.
- Include only task-related changes.
- Inspect staged changes for secrets.
- Keep unrelated changes untouched.
- Avoid unnecessary merge commits.
- Maintain a clear and reversible history.
- Do not rewrite existing user history.
- Do not force-push.
- Do not push or deploy.

The main agent is responsible for integrating reviewed commits into the local refactoring branch.

Use a consistent integration strategy that preserves individual task boundaries.

If a task needs corrections before integration, consolidate them into the focused task commit when safe.

Planning, progress and architecture documentation may have dedicated documentation commits.

Do not automatically merge the final refactoring branch into the production branch.

## 12. Deferred changes

Keep the original audit's deferred behavioural changes separate.

The removal of the unused direct `dcql` dependency is explicitly approved.

Unless separately authorised, do not implement:

- X-2: Add missing OpenAPI paths.
- X-3: Redesign or merge UI CSS and repair font assets.
- X-4: Change DCQL parsing and rejection behaviour.
- X-6: Change Credo issuer startup and restoration ordering.
- X-7: Merge null-returning and undefined-returning helpers.

X-5, reorganising `types.ts`, may be reconsidered as a purely structural refactoring if the main agent determines that it provides a meaningful architectural benefit without changing public contracts.

Document additional discoveries in `FINDINGS.md`.

Do not allow deferred improvements to expand the approved scope.

## 13. Escalation and failure handling

Subagents must escalate to the main agent when:

- A task requires an undocumented architectural decision.
- Existing behaviour differs from the audit.
- Two implementations are not semantically equivalent.
- A protocol requirement is ambiguous.
- A security boundary may be affected.
- A public API change appears necessary.
- A required test cannot be implemented without changing production behaviour.
- An unexpected dependency is discovered.
- A task exceeds its intended scope.
- A static analysis finding appears to be a false positive.

The main agent should resolve ordinary implementation and architectural ambiguity using:

- Existing code.
- `AGENTS.md`.
- Recorded architectural decisions.
- Relevant authoritative specifications.
- Graft.
- Existing tests.
- Independent reviewer findings.

Only request user input when a genuine decision requires approval, particularly when mandated by `AGENTS.md`.

Do not request confirmation for routine approved refactoring tasks.

If one task becomes blocked, continue with independent ready tasks where safe.

Do not repeatedly retry a failing task without investigating the underlying cause.

Do not sacrifice correctness to maintain execution speed.

## 14. Final independent architecture review

After all implementation phases, spawn a dedicated Claude Opus 5.5 reviewer subagent.

The final reviewer must assess the entire refactoring relative to the initial baseline.

Evaluate:

- Overall architectural improvement.
- Module cohesion.
- Dependency direction.
- Readability.
- Maintainability.
- Test architecture.
- Unnecessary abstractions.
- Remaining duplication.
- Remaining dead code.
- Remaining complexity hotspots.
- Security boundaries.
- Protocol behaviour preservation.
- Documentation consistency.
- Compliance with the approved plan.

The reviewer must specifically identify cases where complexity was merely relocated rather than reduced.

The reviewer must also identify cases where excessive fragmentation has made navigation or comprehension worse.

Resolve blocking and major findings using Codex Luna implementation subagents, followed by independent review.

## 15. Final deliverables

At completion, provide a comprehensive final report containing:

### Implementation summary

- Completed tasks.
- Deferred tasks.
- Blocked tasks.
- Tasks adjusted from the original audit.
- Reasons for significant deviations.
- Final refactoring branch.
- Relevant commit identifiers.

### Architecture summary

- Final directory structure.
- Major architectural improvements.
- Shared responsibilities introduced.
- Removed legacy implementations.
- Simplified interfaces.
- Remaining architectural limitations.

### Before-and-after measurements

Compare:

- Total production lines of code.
- Total test lines of code.
- Largest modules.
- Major complexity hotspots.
- Duplicated lines.
- Duplicated blocks.
- Unused exports.
- Unused dependencies.
- Circular dependencies.
- Test inventory.
- Statement coverage.
- Branch coverage.
- Static analysis health measurements.

Explain the limitations of these metrics.

Do not treat numerical improvement alone as proof of successful refactoring.

### Validation results

Report:

- Full test results.
- Build results.
- Lint results.
- Static analysis results.
- Coverage results.
- Protocol regression results.
- Real-wallet interoperability results, where actually available.
- Final independent review results.

### Remaining risks

Document:

- Unresolved risks.
- Deferred behavioural improvements.
- Existing bugs or security concerns discovered during the process.
- Flows requiring additional manual validation.
- Recommended future improvements.

Ensure the persistent documentation accurately reflects the final state.

## 16. Definition of done

The refactoring is complete only when:

- All approved tasks are completed or explicitly documented as blocked or deferred.
- Every implementation task has undergone independent Claude Opus 5.5 review.
- All blocking and major review findings are resolved.
- The repository builds successfully.
- The full test suite passes.
- Lint and required validation commands pass.
- Public behaviour is preserved.
- Protocol and security requirements remain intact.
- Intentional conformance-testing behaviour remains intact.
- Meaningful regression coverage is preserved or improved.
- Confirmed dead code is removed.
- Unnecessary duplication is reduced.
- Major complexity hotspots are meaningfully simplified.
- Module boundaries are cohesive.
- The codebase is easier to navigate.
- Graft is refreshed.
- Documentation is accurate.
- Static analysis tooling is available and reproducible.
- The final independent architecture review is completed.
- Interoperability validation is completed to the extent supported by the available infrastructure.
- Remaining validation limitations are explicitly reported.
- All work is committed locally using the required commit conventions.
- No unrelated user changes have been modified.
- No changes have been pushed or deployed.

## 17. Start execution

Proceed now.

First:

1. Read `AGENTS.md` and the existing audit.
2. Load the relevant architecture and refactoring skills.
3. Inspect Git status and establish a safe integration branch.
4. Verify the configured Claude Opus 5.5 and Codex Luna model identifiers.
5. Revise the detailed original plan according to these instructions.
6. Define the target architecture.
7. Correct the dependency graph and execution batches.
8. Persist the revised plan and progress documentation.
9. Begin Phase 0.
10. Continue executing the remaining phases through native subagent delegation.

Use Claude Opus 5.5 as the main architect, orchestrator and independent reviewer model.

Use Codex Luna for implementation and test-writing subagents.

Maintain a maximum of three concurrent implementation subagents initially.

Do not stop after producing another plan. The approved plan is intended to be implemented.

Continue through the execution batches without requesting routine approval between tasks or phases.

Only stop or request user input when a genuine blocker, unavailable required model, protocol ambiguity, security concern or unapproved behavioural change requires it.

If execution is interrupted by session limits, persist the current state so the next session can resume immediately.

Prioritise correctness, readability, architectural cohesion and behaviour preservation over speed, token consumption and cosmetic metric improvements.
