# AGENTS.md

This file is the source of truth for agents working in the `credimi-capture-wallet` repository.

## Purpose and protocol boundary

This repository implements two interoperable, stateful test services:

- an **OpenID for Verifiable Credential Issuance (OpenID4VCI) 1.0 credential issuer**;
- an **OpenID for Verifiable Presentations (OpenID4VP) 1.0 verifier**.

It captures wallet behaviour and protocol evidence while issuing and verifying PID credentials. It is not a generic Express application: protocol correctness, interoperability, reproducibility, and faithful evidence capture are the primary requirements.

The protocol specifications are authoritative:

- OpenID4VCI 1.0: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
- OpenID4VP 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>

When changing an OpenID4VCI or OpenID4VP flow, read the applicable section of the relevant specification and preserve its wire-level requirements. Do not silently substitute an older draft, a vendor convention, or a similarly named OAuth/OpenID feature.

If this file conflicts with a user instruction, existing protocol behaviour, or a specification requirement:

1. Stop.
2. Explain the conflict and its impact.
3. Ask the user how to proceed.

Do not invent protocol conventions or silently resolve meaningful ambiguity.

## Credo-TS is mandatory

**Credo-TS is the primary and preferred library for all OpenID4VCI, OpenID4VP, verifiable-credential, DID, key-management, cryptographic, credential-format, and presentation-validation functionality.** Use the repository's existing `@credo-ts/core` and `@credo-ts/openid4vc` integration first.

Before writing custom protocol or cryptographic logic, first determine whether Credo-TS already provides the required feature and use it when it does. Do not bypass Credo-TS merely because a direct implementation or another package appears shorter.

An agent may use another library only when the needed capability is genuinely unavailable in Credo-TS or cannot be used for a documented technical reason. Before adding or using that alternative, the agent MUST:

1. State precisely what Credo-TS capability was checked and why it is insufficient.
2. Identify the proposed alternative and its limited responsibility.
3. Explain the interoperability, security, maintenance, and dependency impact.
4. Ask the user for permission to continue.

Do not add the alternative library, implement the fallback, or change protocol behaviour until the user approves. Keep any approved non-Credo dependency narrowly scoped; do not let it become the default protocol implementation.

Existing non-Credo dependencies are not permission to introduce more or replace Credo-TS. Preserve the current dependency lockfile and do not remove or upgrade dependencies unless the task requires it.

## Engineering doctrine

All rules in this file are mandatory unless the user explicitly overrides them.

- Do not behave like a generic coding agent.
- Prefer protocol correctness and explicitness over convenience.
- Make the smallest safe change that satisfies the request.
- Preserve unrelated user changes and existing captured evidence.
- Prefer deterministic, reproducible behaviour and tests over assumptions.
- Do not redesign a protocol flow, public API, data model, or captured response shape without explicit user approval.
- At the end of every task, create a commit containing only that task's files. Do not push, publish, deploy, or create releases unless explicitly asked.
- Do not modify generated state under `data/`, secrets, certificates, or local environment files unless the task explicitly requires it.

A task is incomplete until the agent has inspected the relevant code path, made the smallest safe change, run proportionate validation (or explained why it could not), created the required commit, and reported remaining risk.

## Boot sequence

Before editing:

1. Read this file and inspect the relevant source and tests.
2. Run `git status --short`; preserve all unrelated changes.
3. Identify whether the change touches OpenID4VCI, OpenID4VP, credentials, cryptography, metadata, or stateful capture.
4. For protocol work, consult the applicable authoritative specification and the existing Credo-TS usage before designing a change.
5. Choose the narrowest implementation and matching tests.

If a required design decision, convention, or security policy is not evident from this file, the specification, and existing code, stop and ask the user. Do not establish a new precedent by guessing.

## Repository map

- `src/server/app.ts`: Express composition root: parser/capture middleware, fake OAuth server, ordered route registrations, unmatched 404 and error handling.
- `src/server/context.ts`: per-request OpenID4VCI capture context and issuance response-scenario seam shared by route groups.
- `src/server/issuance-session.ts`: issuance-session creation and credential supersession guard used by issuance/UI routes.
- `src/server/presentation-session.ts`: OpenID4VP session creation, request signing material, and redirect helpers.
- `src/server/routes/`: cohesive direct app registrations for public/UI, discovery and issuer metadata, issuance, OpenID4VP sessions/requests/responses, credential/notification and protocol forwarding.
- `src/openid4vp/authorization-request.ts`: OpenID4VP session creation and request construction.
- `src/openid4vp/credo-verifier.ts`: Credo-TS-backed OpenID4VP verification integration.
- `src/openid4vci/credo-issuer.ts`: Credo-TS-backed OpenID4VCI issuer integration and credential-request mapping.
- `src/fcaf/request-behavior.ts`: verifier Request Object integrity and delivery fault-behaviour validation.
- `src/openid4vp/request-certificates.ts`: verifier Request Object signing keys and X.509 certificate-chain fixtures.
- `src/fcaf/request-mutation.ts`: JSON Pointer mutations for delivered verifier requests and credential offers.
- `src/openid4vp/request-object-encryption.ts`: wallet-metadata negotiation for encrypted verifier Request Objects.
- `src/openid4vp/verifier-attestation.ts`: signed verifier-attestation creation and Client Identifier handling.
- `src/fcaf/response-scenario.ts`: validation for issuance and presentation response fault scenarios.
- `src/fcaf/json-pointer.ts`: RFC 6901 JSON Pointer parsing and document member operations.
- `src/credentials/signing.ts`, `src/credentials/definitions.ts`, `src/openid4vci/proofs.ts`: credential generation, supported credential definitions, and holder proof handling.
- `src/credentials/catalogue.ts`: static supported-credential catalogue, configuration ids, and claim-path helpers.
- `src/openid4vci/http-capture.ts`: OpenID4VCI HTTP request and response evidence capture and redaction.
- `src/openid4vci/notification.ts`: OpenID4VCI notification parsing and Credo-TS `notification_id` injection.
- `src/openid4vci/credential-encryption.ts`: OpenID4VCI Credential Request/Response JWE validation and encryption.
- `src/credentials/registry.ts`: active static and Attestbook credential catalogues synchronized with Credo-TS.
- `src/credo/kms-encryption.ts`: Credo KMS-compatible ECDH-ES content-encryption primitives.
- `src/openid4vci/key-attestation.ts`: Credo-TS issuer support for EUDI key-attested proof verification.
- `src/credentials/digest-algorithm.ts`: supported and default SD-JWT digest-algorithm validation.
- `src/openid4vci/metadata.ts`: issuer and authorization-server metadata output.
- `src/state.ts`: in-memory issuance and presentation session state plus captured evidence.
- `src/config/defaults.ts`: default service configuration and URL normalization.
- `src/config/paths.ts`: configuration, issuer, and verifier material paths.
- `src/config/verifier-identity.ts`: verifier key ids, DID, and attestation identity.
- `src/config/environment.ts`: environment and listen-address parsing.
- `src/config/load.ts`: config.yaml loading and hand-written format helpers.
- `src/config/key-material.ts`: issuer/verifier key and certificate generation, loading, validation, and signing contexts.
- `src/openid4vci/fake-oauth-server.ts`: test OAuth authorization server used by Credo-TS, including PKCE.
- `src/openid4vci/client-attestation.ts`: OAuth client-attestation evidence capture for issuer requests.
- `src/attestbook/`: Attestbook rulebook integration, credential imports, persistence, and webhooks.
- `src/configurations/`: issuer configuration catalogue, URL resolution, registry, and validation.
- `src/federation/`: OpenID Federation entity-configuration signing and registration data.
- `src/status-list/allocation.ts`: Token Status List reference allocation and revocation.
- `src/status-list/reference-fixtures.ts`: valid and malformed Token Status List reference fixtures.
- `src/status-list/malformed-mdoc-status.ts`: malformed mdoc Token Status List fixture generation.
- `src/openapi/`: OpenAPI document assembly (`document.ts`), shared helpers (`common.ts`), component schemas (`components.ts`), concern-based `paths-*.ts`, and the interactive docs page (`docs-page.ts`).
- `src/cli.ts`: package.json `"bin"` entry point.
- `src/cli/commands.ts`: command-line argument parsing and command handling for service operation, federation exports and Attestbook commands.
- `src/ui/`: server-rendered operator UI page families (`html`, `launcher`, `issuer`, `verifier`, `session`, `markdown`, `styles`, `scripts`).
- `tests/`: Vitest coverage for protocol routes, Credo-TS integration, metadata, proofs, configuration, and validation.
- `README.md`: public API and runtime documentation; update it when a public contract changes.

## Protocol and security rules

- Treat issuer metadata, authorization-server metadata, JWKS, credential offers, PAR, authorization, token, nonce, credential, verifier request objects, and presentation responses as public protocol contracts.
- Preserve protocol parameter names, response modes, media types, status codes, and error shapes unless the user explicitly requests a compatible change.
- Keep issuance and verification key material separate. Never log private keys, access tokens, authorization codes, DPoP proofs, decrypted presentation payloads containing sensitive data, or raw secrets.
- Do not weaken signature verification, nonce checks, audience checks, holder binding, PKCE, encryption, or DCQL matching to make a test pass. Any intentional malformed or permissive test mode must be explicit, isolated, and documented.
- Preserve raw captured wallet input alongside normalized or decoded results where the existing state model does so. Capture fidelity matters for conformance diagnosis.
- Ensure session state remains isolated by session identifier; do not introduce cross-session state leakage.
- When handling mdoc, SD-JWT VC, JWT, JWK, X.509, JOSE, DCQL, or cryptographic operations, use Credo-TS first. The exception approval process above still applies to every missing capability.

## TypeScript and API conventions

- Use TypeScript in strict mode. Avoid `any`, unchecked casts, and broad `unknown` conversions; validate untrusted HTTP input before use.
- Keep route handlers thin and place protocol-specific logic in focused modules.
- Prefer the existing domain types in `src/types.ts` and make public input/output changes explicit in types and tests.
- Preserve ESM import conventions and the repository's Biome formatting configuration.
- Do not use a dependency upgrade, framework rewrite, or broad refactor as an incidental part of a focused fix.

## Design Source

Use `./src/design/style.css` as the main source for UI work.

Use similar principles, colors, fonts, and branding.

## Required Developer Tools

If a repository requires a command to operate, that command MUST be declared in `mise.toml`.

A tool is required if it is used by:

- `Taskfile.yml`
- tests
- build commands
- lint commands
- release commands
- validation instructions

Missing required tools in `mise.toml` is a failure.

## Validation

Use `pnpm`; the package manager version is pinned in `package.json`.

Run the narrowest meaningful validation first. For source or test changes, normally run:

```sh
pnpm test
pnpm build
pnpm lint
```

For a focused change, run the affected Vitest file while iterating, then run the full relevant suite before finishing. For changes to a public endpoint, protocol flow, metadata, or a security boundary, add or update tests that exercise the actual HTTP contract as well as lower-level logic where appropriate.

If validation cannot run, report the exact command, reason, and remaining confidence gap. Never claim a change is validated when it is not.

## Commit Style

### Format

```text
<type>(<scope>): <subject>

reason:
<why>

prompt:
<short intent>
```

### Rules

- Subject MUST be imperative, concise, and lowercase.
- MUST include `reason` and `prompt`.
- MUST NOT describe the diff.
- MUST explain intent.

### Constraints

- `reason`: maximum three lines.
- `prompt`: maximum two lines.

### Failure Conditions

A commit is invalid if it:

- is missing `reason` or `prompt`;
- describes only changes; or
- lacks intent.

Before committing, run the repository formatter and `task lint`. If either fails, fix the issue and rerun it before committing. Inspect the staged files for secrets and include only files belonging to the task; preserve unrelated user changes.

## Documentation and handoff

- Update `README.md` when a public endpoint, configuration option, supported credential format, OpenID4VCI/OpenID4VP behaviour, or operational workflow changes.
- Update `CAPTURE_WALLET_API.md` when a public API endpoint, request parameter, response shape, or API behaviour changes.
- Keep docs accurate about deliberate limitations and test-only behaviour.
- In the final handoff, state what changed, which validation ran, and any remaining protocol or interoperability risk.

<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->
