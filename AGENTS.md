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

- `src/server.ts`: Express routes and the OpenID4VCI issuer endpoints.
- `src/openid4vp.ts`: OpenID4VP session creation and request construction.
- `src/credo-openid4vp.ts`: Credo-TS-backed OpenID4VP verification integration.
- `src/openid4vp-validation.ts`: validation helpers for OpenID4VP presentations.
- `src/credential.ts`, `src/credential-definitions.ts`, `src/proofs.ts`: credential generation, supported credential definitions, and holder proof handling.
- `src/metadata.ts`: issuer and authorization-server metadata.
- `src/state.ts`: in-memory issuance and presentation session state plus captured evidence.
- `src/config.ts`: service configuration and issuer/verifier key material.
- `src/client-auth.ts`, `src/pkce.ts`: OAuth client authentication and PKCE support.
- `src/ui.ts`: server-rendered operator UI.
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

Use `./src/design/atlas-style.css` as the main source for UI work.

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
- Keep docs accurate about deliberate limitations and test-only behaviour.
- In the final handoff, state what changed, which validation ran, and any remaining protocol or interoperability risk.
