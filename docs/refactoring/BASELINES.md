# Refactoring quality baselines

These measurements were taken on the Q-01 base (`40ce531cb50ded1ee0abe0b1e133a47f5fd1d0d9`) before the parallel C-07 composition-root change. The main integration branch must refresh the numbers after C-07 lands.

## Reproduction

The tools are pinned in `mise.toml`. The gate definition is in `Taskfile.yml` and can be run with:

```sh
task analyze:check
```

Individual measurements:

```sh
mise exec -- knip --no-config-hints
mise exec -- knip --production --no-config-hints
mise exec -- jscpd --summary
mise exec -- jscpd src --format typescript --summary
mise exec -- jscpd tests --format typescript --summary
mise exec -- madge --circular --extensions ts --ts-config tsconfig.json src
task test:coverage
pnpm test
```

Coverage is reported, not gated: the known F-06 certificate-serial flake makes a coverage threshold noisy. Coverage output is written to `coverage/coverage-summary.json`.

## Gate definition

`task analyze:check` runs these commands in order:

```yaml
analyze:check:
  cmds:
    - mise exec -- madge --circular --extensions ts --ts-config tsconfig.json src
    - mise exec -- knip --no-config-hints
    - mise exec -- knip --production --no-config-hints
    - mise exec -- jscpd --threshold 4.0
    - mise exec -- jscpd src --format typescript --threshold 0.5
    - mise exec -- jscpd tests --format typescript --threshold 7.0
```

Madge has no `ignore_error` on this task, so any cycle fails the task. Knip exits non-zero for unused files, dependencies, exports, or types. The full scan checks every export/type; the production-only test seams are tagged `@internal`, which Knip skips only in `--production`. JSCPD's 3.56% combined duplicated-line baseline is rounded up to the next 0.5 percentage point, giving a 4.0% threshold. The source and test baselines are independently rounded to 0.5% and 7.0%, respectively. The task is intentionally not wired into `pnpm test`.

## Measurements

| Check | Baseline |
| --- | ---: |
| Knip unused files (full project) | 0 |
| Knip unused dependencies (full project) | 0 |
| Knip unused exports/types (full project) | 0 |
| Knip production-only `@internal` test seams | 31 exports, 1 type |
| JSCPD, all paths | 124 clones; 1,481 duplicated lines (3.56%) |
| JSCPD, `src` | 6 clones; 51 duplicated lines (0.25%) |
| JSCPD, `tests` | 115 clones; 1,388 duplicated lines (6.65%) |
| Madge modules | 97 |
| Madge cycles | 0 |
| Coverage statements | 94.94% (14,899 / 15,693) |
| Coverage branches | 87.01% (3,577 / 4,111) |
| Coverage functions | 97.78% (705 / 721) |
| Coverage lines | 94.94% (14,899 / 15,693) |
| Tests | 787 tests in 57 files |

### Knip `@internal` test seams

The production scan excludes `tests/`, while the full scan confirms these symbols are imported by tests. They are intentionally exported as direct unit-test seams for production helpers; `@internal` documents that boundary and suppresses only the production-only report. The full scan still fails for an untagged unused export or type. The table has 31 exported-symbol entries:

| Symbol | Source | Test |
| --- | --- | --- |
| `vctForAttestationName` | `src/attestbook/compiler.ts` | `tests/attestbook.test.ts` |
| `ClaimGenerationError` | `src/attestbook/generator.ts` | `tests/attestbook.test.ts` |
| `allowedUrl` | `src/attestbook/http.ts` | `tests/attestbook.test.ts` |
| `ATTESTBOOK_ENABLED_ENV_VAR` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `ATTESTBOOK_BASE_URL_ENV_VAR` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `ATTESTBOOK_RULEBOOK_ID_ENV_VAR` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `ATTESTBOOK_WEBHOOK_SECRET_ENV_VAR` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `ATTESTBOOK_ADMIN_TOKEN_ENV_VAR` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `trustedOrigin` | `src/attestbook/settings.ts` | `tests/attestbook-settings.test.ts` |
| `webhookSignature` | `src/attestbook/webhook.ts` | `tests/attestbook.test.ts` |
| `parseArgs` | `src/cli/commands.ts` | `tests/cli-commands.test.ts` |
| `parseEnvText` | `src/config/environment.ts` | `tests/config.test.ts` |
| `validateIssuerCertificateSubjectAlternativeName` | `src/config/key-material.ts` | `tests/config.test.ts` |
| `parseYamlConfig` | `src/config/load.ts` | `tests/config-file.test.ts` |
| `issuerConfigurations` | `src/configurations/registry.ts` | `tests/configurations-validation.test.ts`, `tests/configurations.test.ts` |
| `sdJwtCredentialConfigurationId` | `src/credentials/catalogue.ts` | `tests/credential-mapping.test.ts`, `tests/metadata.test.ts` |
| `mdocCredentialConfigurationId` | `src/credentials/catalogue.ts` | `tests/credential-mapping.test.ts`, `tests/metadata.test.ts` |
| `degreeSdJwtCredentialConfigurationId` | `src/credentials/catalogue.ts` | `tests/degree-credential.test.ts`, `tests/metadata.test.ts` |
| `numericSdJwtCredentialConfigurationId` | `src/credentials/catalogue.ts` | `tests/credential-mapping.test.ts`, `tests/metadata.test.ts` |
| `domesticPidCredentialConfigurationId` | `src/credentials/catalogue.ts` | `tests/credential-mapping.test.ts`, `tests/metadata.test.ts` |
| `CatalogueConflictError` | `src/credentials/registry.ts` | `tests/credential-registry.test.ts` |
| `CREDIMI_LOGO_URL` | `src/credentials/signing.ts` | `tests/metadata.test.ts` |
| `issueSdJwtCredential` | `src/credentials/signing.ts` | `tests/federation.test.ts`, `tests/support/presentation.ts` |
| `readJsonPointer` | `src/fcaf/json-pointer.ts` | `tests/json-pointer.test.ts` |
| `accessTokenSessionQuery` | `src/openid4vci/attribution.ts` | `tests/oid4vci-attribution.test.ts` |
| `setObservedString` | `src/openid4vci/evidence.ts` | `tests/oid4vci-attribution.test.ts` |
| `decodeJwtHeader` | `src/openid4vci/proofs.ts` | `tests/proofs.test.ts` |
| `extractProofJwts` | `src/openid4vci/proofs.ts` | `tests/proofs.test.ts` |
| `trustedIssuerForX509Credential` | `src/openid4vp/credo-verifier.ts` | `tests/credo-openid4vp.test.ts` |
| `toJsonSafe` | `src/openid4vp/presentation-decoding.ts` | `tests/credo-openid4vp.test.ts` |
The additional type-only seam, `SessionCredentialDefinition` in `src/types.ts`, is tagged `@internal` and used by `tests/credential-endpoint.test.ts`.

The two initial full-project findings, `DecodedPresentation` in `src/openid4vp/presentation-decoding.ts` and `IssuanceSessionInput` in `src/server/issuance-session-input.ts`, were module-local types and therefore are no longer exported.

### Duplication detection limits

At the measured line counts, the rounded thresholds tolerate approximately 180 additional duplicated lines globally, 52 additional duplicated lines in `src`, and 72 additional duplicated lines in `tests` before crossing their thresholds. These are approximate limits: adding source also increases the denominator, and JSCPD clone boundaries can make the reported duplicated-line count differ from the literal lines added.

## Throwaway gate proofs

Each proof was run with a local violation and reverted immediately; no violation remains in the worktree.

- **Madge:** temporary side-effect imports made `src/shared/json.ts` and `src/shared/errors.ts` import one another. Madge reported `Found 1 circular dependency` and exited 1.
- **Knip export:** a temporary untagged `q01UnusedExport` in `src/credentials/catalogue.ts` produced `Unused exports (1)` and exited 1.
- **Knip type:** a temporary untagged `q01UnusedType` in `src/types.ts` produced `Unused exported types (1)` and exited 1.
- **JSCPD:** temporary duplicate blocks in `src/shared/errors.ts` were run through the actual `task analyze:check` commands. The source command reported `7 clones`, `0.5%` duplication and `ERROR: jscpd found too many duplicates (0.5%) over threshold (0.5%)`; the task exited 1.

After reverting all throwaway edits, both Knip runs exited 0 and the final `task analyze:check` passed. C-07 will land after this base; the main agent must refresh these measurements and rerun the gate after integration.
