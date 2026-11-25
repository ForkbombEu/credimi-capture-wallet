 I've finished the audit and the prioritised plan is below. Nothing in the repo was changed: git status shows only the files that were already modified or untracked when I started, so there was nothing to commit. Coverage was measured in a
 throwaway copy under /tmp/audit/repo, because @vitest/coverage-v8 is not a repo dependency. Two caveats:

 - No glossary or ADRs: the improve-codebase-architecture skill expects GLOSSARY.md and ADRs in docs/adr/. The repo has neither, so I used the protocol specs' terms.
 - HTML report: the skill's report is at /tmp/architecture-review-20261124-101247.html, with seven candidates. It only presents the candidates; I haven't started the skill's follow-up step of discussing one in depth.

 Baseline

 ┌──────────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ Check                                        │ Result                                                                                                                          │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ pnpm test                                    │ 19 files, 471 passed                                                                                                            │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ pnpm build (tsc)                             │ pass                                                                                                                            │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ pnpm lint                                    │ fails locally because Biome scans the gitignored graft/.graph/wiring.json, which is over 1 MiB. biome check src tests is clean. │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ jscpd health score (0–100, higher is better) │ 61 C: duplication 78, dead code 74, complexity 38                                                                               │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Duplicated lines                             │ 3.2%, 97 copied blocks, about 70 of them in tests                                                                               │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Statement / branch coverage                  │ 87.1% / 81.8%                                                                                                                   │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Import cycles (madge)                        │ 2, both through type imports only, both via metadata.ts                                                                         │
 ├──────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Source file used only by tests (knip)        │ src/openid4vp-validation.ts (668 lines)                                                                                         │
 └──────────────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 Largest modules and functions (cx is cyclomatic complexity):

 ┌──────────────────────────────────────────────────────────────┬───────┬────┐
 │ Where                                                        │ Lines │ cx │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ createApp, src/server.ts:141 (about 65 routes inline)        │ 1652  │ –  │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ openApiDocument, src/openapi.ts:49                           │ 2192  │ –  │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ POST /openid4vp/sessions, server.ts:1095                     │ 210   │ 91 │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ POST /sessions, server.ts:768                                │ 209   │ 65 │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ CredoOpenId4VpVerifier.createSession, credo-openid4vp.ts:239 │ 231   │ 50 │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ mapCredentialRequest, credo-openid4vci.ts:722                │ 150   │ 18 │
 ├──────────────────────────────────────────────────────────────┼───────┼────┤
 │ tests/server.test.ts (one top-level describe is 5001 lines)  │ 7922  │ –  │
 └──────────────────────────────────────────────────────────────┴───────┴────┘





















 Gaps that must be protected before refactoring:
 - POST /openid4vp/response has no test at all (server.ts:1582-1622). It is a documented public endpoint (CAPTURE_WALLET_API.md:685).
 - The mdoc presentation path has no end-to-end test.
 - The security checks that reject bad credential-request encryption are untested (credential-encryption.ts: 55% branch coverage).
 - The conflict and rollback paths in credential-registry.ts are untested.
 - Several Attestbook security checks are untested: environment settings, bounded HTTP fetch, webhook rejection branches.
 - cli.ts has 0% coverage.

 Stale references in AGENTS.md: src/client-auth.ts, src/pkce.ts and src/design/atlas-style.css don't exist.

 Decisions I need from you

 1. Delete src/openid4vp-validation.ts (D-05)? It is an older hand-written verifier with certificate-chain validation turned off, and nothing in production calls it. Deleting it leaves the direct dcql dependency unused. AGENTS.md says not
    to remove dependencies unless the task requires it, so removing dcql needs your approval.
 2. Analysis tools as validation gates? knip, jscpd and madge were run through npx. If they become required validation steps, AGENTS.md requires declaring them in mise.toml (e.g. npm:knip). Otherwise they stay optional measurements.
    Coverage would also need the @vitest/coverage-v8 dev dependency.
 3. Deleting tests that only cover dead functions (D-06): removing jwkToJwks/firstWalletJwks from src/proofs.ts means removing the tests/proofs.test.ts cases that only exercise those two functions, so the test count drops by a known
    amount. Is that acceptable?

 Conventions used in every task

 - Standard validation: pnpm test && pnpm build && pnpm lint, plus npx tsc --noEmit --noUnusedLocals --noUnusedParameters must report nothing new.
 - Test-identity check: run pnpm vitest run --reporter=json before and after, then compare the sorted list of full test names with diff. The counts must match and the diff must be empty, unless the task explicitly lists added or removed
   tests.
 - Output-equality script: a throwaway script, never committed, that captures output before the change and asserts it is byte-identical afterwards.
 - Commits: one commit per task in the AGENTS.md style (type(scope): subject, with reason: and prompt: sections).
 - Shared module names, chosen once: src/errors.ts and src/json-guards.ts.
 - No re-export layers: callers are updated directly, with no compatibility re-exports left behind.

 Task order

                                                      ┌───────────────────────┐     ┌─────────────────────────┐
                                                      │                       │     │                         │
                                                      │                       │     │                         │
                                    ┌────────────────►│   C-01..C-06 server   ├────►│  C-07 createApp routers │
                                    │                 │        handlers       │     │                         │
                                    │                 │                       │     │                         │
                                    │                 └───────────────────────┘     └────────────┬────────────┘
                                    │                                                            │
                                    │                                                            │
                                    │                                                            └───────────────────────────────────────────┐
                                    │                                                                                                        │
                                    │                                                                                                        │
                                    │                 ┌───────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────┐  │
                                    │                 │                       │     │                         │     │                     │  │
                                    ├────────────────►│   C-08 openapi split  │  ┌─►│  S-02 split server.test ├────►│    S-03 fixtures    │  │
                                    │                 │                       │  │  │                         │     │                     │  │
                                    │                 └───────────────────────┘  │  └────────────┬────────────┘     └─────────────────────┘  │
                                    │                                            │               │                                           │
                                    │                                            │               │                                           │
                                    │                             ┌──────────────┘               └───────────────────────────────────────────┤
                                    │                             │                                                                          │
                                    │                             │                                                                          │
                                    │                 ┌───────────┴───────────┐     ┌─────────────────────────┐     ┌─────────────────────┐  │  ┌──────────────────────┐
                                    │                 │                       │     │                         │     │                     │  │  │                      │
                                    │                 │                       │     │                         │     │                     │  │  │                      │
                                    ├────────────────►│   S-01 test harness   │  ┌─►│           C-11          │     │ B-07 config split B ├──┴─►│ N-01 navigation docs │
                                    │                 │                       │  │  │   mapCredentialRequest  │     │                     │     │                      │
                                    │                 │                       │  │  │                         │     │                     │     │                      │
                                    │                 └───────────────────────┘  │  └─────────────────────────┘     └─────────────────────┘     └──────────────────────┘
                                    │                                            │                                             ▲
                                    │                                            │                                             │
                                    │                             ┌──────────────┘                                             │
                                    │                             │                                                            │
                                    │                             │                                                            │
                        ┌───────────┴───────────┐     ┌───────────┴───────────┐     ┌─────────────────────────┐                │
                        │                       │     │                       │     │                         │                │
                        │                       │     │                       │     │                         │                │
          ┌────────────►│ T-01..T-09 safety-net ├──┬─►│    C-10 attribution   │  ┌─►│   B-06 config split A   ├────────────────┘
          │             │         tests         │  │  │                       │  │  │                         │
          │             │                       │  │  │                       │  │  │                         │
          │             └───────────┬───────────┘  │  └───────────────────────┘  │  └─────────────────────────┘
          │                         │              │                             │
          │                         │              │                             │
          │                         │              └─────────────────────────────┼───────────────┐
          │                         │                                            │               │
          │                         │                                            │               │
 ┌────────┴───────┐                 │                 ┌───────────────────────┐  │               │
 │                │                 │                 │                       │  │               │
 │ R-01 lint gate ├─────────────────┼────────────────►│ C-14..C-16 attestbook │  │               │
 │                │                 │                 │                       │  │               │
 └────────────────┘                 │                 └───────────────────────┘  │               │
                                    │                                            │               │
                                    │                                            │               │
                                    │                             ┌──────────────┘               │
                                    │                             │                              │
                                    │                             │                              ▼
 ┌────────────────┐                 │                 ┌───────────┴───────────┐     ┌─────────────────────────┐
 │                │                 │                 │                       │     │                         │
 │ B-09 CLI core  │                 ├────────────────►│    B-03 type cycles   │  ┌─►│  C-09 VP createSession  │
 │                │                 │                 │                       │  │  │                         │
 └────────────────┘                 │                 └───────────┬───────────┘  │  └─────────────────────────┘
                                    │                             │              │
                                    │                             │              │
                                    │                             └──────────────┤
                                    │                                            │
                                    │                                            │
                                    │                 ┌───────────────────────┐  │  ┌─────────────────────────┐
                                    │                 │                       │  │  │                         │
                                    ├────────────────►│     B-01 errors.ts    │  ├─►│   B-08 catalogue split  │
                                    │                 │                       │  │  │                         │
                                    │                 └───────────────────────┘  │  └─────────────────────────┘
                                    │                                            │
                                    │                                            │
                                    │                             ┌──────────────┘
                                    │                             │
                                    ▼                             │
                        ┌───────────┴───────────┐     ┌───────────┴───────────┐
                        │                       │     │                       │
                        │  D-01..D-06 dead code ├────►│    B-04 credo-agent   ├──────────────────┐
                        │                       │     │                       │                  │
                        └───────────┬───────────┘     └───────────────────────┘                  │
                                    │                                                            │
                                    │                                                            │
                                    │                                                            │
                                    │                                                            │
                                    │                                                            ▼
                                    │                 ┌───────────────────────┐     ┌─────────────────────────┐
                                    │                 │                       │     │                         │
                                    └────────────────►│  B-02 json-guards.ts  │     │ B-05 credo-presentation │
                                                      │                       │     │                         │
                                                      └───────────────────────┘     └─────────────────────────┘

 server.ts is touched by D-01, B-01, B-02 and C-01 to C-07, so those must run one after another. Everything inside the T-, D- and C-14 to C-16 groups can run in parallel.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 0: Tooling

 ### R-01 · Make the lint gate green

 Severity High · Risk Low · Benefit High · Depends on none
 - Files: biome.json (files.ignore).
 - Problem: pnpm lint fails on graft's local graph cache. AGENTS.md requires task lint to pass before every commit, so no refactoring task can currently satisfy that rule.
 - Refactoring: replace the graft/.cache ignore entry with graft. The whole directory is already gitignored.
 - Benefit: a usable validation gate for every later task.
 - Risks: none; it only stops Biome scanning a generated directory.
 - Validation: pnpm lint, task lint.
 - Acceptance: both exit 0, and Biome still checks the same 84 source and test files.

 ### R-02 · Correct stale facts in AGENTS.md

 Severity Low · Risk Low · Benefit Med · Depends on none
 - Files: AGENTS.md (repo map; "Design Source" section, around line 108).
 - Problem:
   - It lists src/client-auth.ts and src/pkce.ts, which don't exist. PKCE lives in fake-oauth-server.ts and Credo-TS; client-authentication evidence is in client-attestation.ts.
   - It names atlas-style.css, but the file is src/design/style.css.
   - It omits credo-openid4vci.ts, attestbook/, configurations/, federation/ and the request-*.ts modules.
 - Refactoring: fix those facts only.
 - Benefit: agents stop following paths that don't exist.
 - Validation: every path the doc mentions resolves (checked with fd).
 - Acceptance: no dangling path references remain.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 1: Safety-net tests (test files only, no changes to src/)

 New tests go in new files, so they don't collide with the later split of server.test.ts (S-02). Each one asserts exact status codes, error bodies and evidence fields as the code produces them today.

 ### T-01 · VP response endpoints

 Severity High · Risk Low · Depends on R-01 · Needed before C-01, C-07
 - Targets:
   - POST /openid4vp/response (server.ts:1582-1622): selects the session by state; cover success, missing or unknown state, invalid presentation, and the FCAF gating described in CAPTURE_WALLET_API.md:587.
   - GET /openid4vp/sessions/:id/events (1625).
   - /openid4vp/redirect with an unknown code (1316).
 - Problem: a public endpoint is completely uncovered, and C-01 will move its body.
 - Acceptance: those line ranges are covered; the assertions include the evidence recorded in session.raw.

 ### T-02 · Error matrices for session creation and the credential endpoint

 Severity High · Risk Low · Needed before C-02 to C-05
 - Targets:
   - POST /sessions: every 400 code, the 409 CredentialSupersededError (server.ts:968-975), and the order in which checks run (for example, status_reference is checked before fixture).
   - POST /openid4vp/sessions: uncovered branches 1100-1101, 1108-1109, 1123-1128, 1149-1150, 1175-1176, 1187-1188 and 1232-1233; how ClientMetadataError/ResponseModeError become responses (1299-1303); the duplicated
     request_behavior_not_enabled check (1143).
   - POST /openid4vp/sessions/:id/request: wallet_metadata with an unsupported encryption algorithm (1480-1491), and the re-sign path.
   - POST /issuers/:id/credential: plain JSON body, encrypted (JWE) body, response encryption requested without JWE (400), and a superseded definition (400).
 - Approach: table-driven, one row per input, asserting (status, body).
 - Acceptance: every uncovered branch listed above is covered.

 ### T-03 · Credential-encryption security checks

 Severity High · Risk Low · Needed before B-01, B-02
 - Target: new tests/credential-encryption.test.ts, calling the exported functions directly.
 - Cases (uncovered lines, credential-encryption.ts):
   - missing issuer key (33-34)
   - payload that can't be decrypted (46-47)
   - alg/enc mismatch (49-53)
   - kid mismatch (55-58)
   - errors wrapped rather than leaked (61-63)
   - missing jwk, private key material present, bad jwk.alg/enc, zip set (74-93)
   - invalid public JWK and unsupported key type or curve (99-112)
   - unexpected JWE serialisation (227-228)
   - invalid JSON payload (304-305)
 - Acceptance: every rejection asserts CredentialEncryptionError and its exact message; branch coverage of the file is at least 90%.

 ### T-04 · Credential-registry conflicts and rollback

 Severity High · Risk Low · Needed before B-01, D-04
 - Target: new tests/credential-registry.test.ts, using new CredentialRegistry(config) with a stub synchroniser.
 - Cases:
   - conflict on configuration id, on a static credential's id, on scope, and on vct
   - an issuer that doesn't import Attestbook credentials
   - synchroniser failure with a previous catalogue: the previous one is restored and the original error is rethrown
   - synchroniser failure with no previous catalogue
   - both the sync and the restore fail: the combined message contains both
   - a failed operation doesn't break the next queued one
 - Acceptance: uncovered lines 99-144 are covered.

 ### T-05 · mdoc presentation end to end

 Severity High · Risk Med · Needed before C-09, B-05, D-05
 - Target: build an mdoc DeviceResponse and post it to the verifier.
   - Accepted case: status: "presentation_validated", all checks true, and decoded_presentations.query_0[0] contains format, document_types, issuer_claims and device_claims.
   - Rejected cases: wrong nonce or origin, and a second document when multiple is not true.
   - Also: setJsonPointer overwriting an array index, and "/keys/x" throwing "not an index" (json-pointer.ts:109-114).
 - Note: the session-transcript helper in openid4vp-validation.ts:428-460 already implements the spec algorithm. Use it to build the response (D-05 later moves it into a test helper).
 - Acceptance: the mdoc branch at credo-openid4vp.ts:1006-1014 is covered.

 ### T-06 · Attestbook security checks

 Severity Med · Risk Low · Needed before C-14 to C-16, B-07
 - Targets:
   - resolveAttestbookSettings, trustedOrigin and isLoopbackHost (settings.ts:28-86, 54% covered).
   - boundedGet: every AttestbookFetchErrorCode (url_not_allowed, redirect_not_followed, not_found, unexpected_status, response_too_large, timeout, network_failure). Use the existing injectable fetch with stubbed Response objects, no
     network.
   - Webhook rejection branches (integration.ts:252-350): non-JSON body, wrong event type, secret not configured, missing headers, event-id mismatch, persistence failure (503).
   - Sync failure stages: activation_rolled_back, persist_failed, skipping an already-rejected digest, retry cap of 8.
   - Unsupported-keyword diagnostics in json-schema.ts.
 - Acceptance: exact codes, statuses and messages, and the order of diagnostics, are asserted.

 ### T-07 · Issuer-configuration validation errors

 Severity Med · Risk Low
 - Target: table-driven tests for every throw in configurations/validate.ts (uncovered 22-55): empty list, duplicate slug, duplicate upstream scope, JWT-only conformance rule, experimental issuer without the feature flag, Attestbook
   imports outside the feature.
 - Acceptance: exact error strings are asserted. No refactor follows; the validator is already flat and explicit.

 ### T-08 · CLI behaviour

 Severity Med · Risk Low · Needed before B-09
 - Target: run tsx src/cli.ts as a subprocess (tsx is already a dev dependency) against a temp directory.
   - init summary keys.
   - federation-jwks and federation-registration output shapes, --issuer-configuration-id filtering, the "Unknown or disabled" error, and refusal when federation is disabled.
   - An unknown command sets exit code 1.
   - Attestbook command argument validation.
 - Acceptance: stdout JSON and exit codes are pinned.

 ### T-09 · Conditional OpenAPI paths

 Severity Med · Risk Low · Needed before C-08
 - Target: assert that the federation, Attestbook and notification paths and tags appear only when their flags are on (openapi.ts 76-91, 144-170, 283-347, 1048-1108).
 - Acceptance: all four flag combinations are asserted.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 2: Confirmed dead code

 ### D-01 · Unused imports, locals and parameters

 Severity Low · Risk Low · Depends on R-01
 - Symbols:
   - server.ts:53 supportedCredentials and :114 VerifierResponseHttpCapture
   - credential.ts:1 MdocSignOptions, plus the certificate loaded but never read at credential.ts:69-70
   - the attestation parameter of verifierAttestationClientId (verifier-attestation.ts:81) and its single caller (credo-openid4vp.ts:342)
   - in tests/server.test.ts: the PID_SD_JWT_CLAIMS (64) and CREDIMI_LOGO_URL (67) imports, and the never-called postForm (7504)
 - Problem: dead identifiers add noise for readers and agents.
 - Validation: standard validation; the strict tsc flags report zero.
 - Acceptance: tsc --noUnusedLocals --noUnusedParameters is clean, apart from openid4vp-validation.ts, which D-05 handles.

 ### D-02 · Legacy pre-Credo request builder in openid4vp.ts

 Severity High · Risk Low · Depends on D-01
 - Symbols: delete REQUEST_OBJECT_AUDIENCE (30), createJarmEncryptionJwk (138-152), buildPresentationAuthorizationRequest (154-170), presentationRequestByReferenceDeeplink (223-235), vpResponseUri (274-276) and verifierClientMetadata
   (308-324), plus the generateKeyPair/exportJWK imports they used.
 - Also:
   - Compute x509_hash with x509HashClientId from request-certificates.ts:97-103, then delete verifierClientId and verifierCertificateSha256 (two implementations of the same hash).
   - Replace the inline request URI at credo-openid4vp.ts:323-325 with vpRequestUri.
 - Problem: a second, divergent request-building path sits beside the live Credo-backed one. Its line ranges are exactly the uncovered ranges in this file.
 - Risks: client identifiers must not change. x509_hash: is asserted at server.test.ts:968-994, x509_san_dns at 1159 and DID at 1189.
 - Acceptance: openid4vp.ts has no uncovered code; the test-identity check passes.

 ### D-03 · Dead wrappers, re-exports and unreachable defaults

 Severity Med · Risk Low · Depends on D-01
 - Symbols:
   - metadata.ts: signedCredentialIssuerMetadata (110-121, no callers) and the PID_MDOC_NAMESPACE/PID_SD_JWT_VCT re-exports (56).
   - credential.ts: the CREDIMI_WEBSITE re-export (33).
   - state.ts: defaultIssuerConfiguration/defaultCredentialConfigurationId (395-410), which can't be reached because both call sites pass the arguments. Make those parameters required.
   - federation/registration.ts: the issuerFederationJwks alias (callers switch to loadIssuerFederationJwks) and the never-passed enabled parameter. The returned object keeps enabled: true.
 - Keep: issueSdJwtCredential and CREDIMI_LOGO_URL, which tests use as fixtures.
 - Acceptance: the test-identity check passes; the CLI federation-* output (T-08) is unchanged.

 ### D-04 · Stop exporting internal-only symbols

 Severity Low · Risk Low · Depends on T-04
 - Symbols (knip results checked by hand; every one is used inside its own module):
   - config.ts *_ENV_VAR/*_FILE constants and helpers; attestbook/settings.ts, webhook.ts, json-schema.ts
   - configurations/registry.ts:27, pid-fixtures.ts:12
   - credential-encryption.ts:17-18, credential-registry.ts:24-29,150-163
   - metadata.ts:176-182,227-233, json-pointer.ts:12 (parseJsonPointer)
   - openid4vp.ts DC_API_PRESENTATION_TTL_SECONDS, VpRequestSigner
   - ui.ts PresentationParameterValues, VerifierCredentialGroup
   - tests/attestbook-fixture.ts sri
   - the knip-listed unexported types in configurations/types.ts, attestbook/types.ts, pid-data.ts and integration.ts
 - Refactoring: remove the export keyword only; delete nothing.
 - Keep exported: everything tests import (DEFAULT_CONFIG, path helpers, IssuanceParameterValues, …).
 - Acceptance: knip's "unused exports" list contains only test-consumed symbols; the build passes.

 ### D-05 · Remove openid4vp-validation.ts (needs decision 1)

 Severity High · Risk Med · Depends on T-05
 - Problem: this 668-line validator has no production caller, 15.7% coverage, and certificate-chain validation disabled (lines 346-347, 633). Credo-TS already does this verification (credo-openid4vp.ts:498-596).
 - Refactoring:
   - Move mdocSessionTranscript, oid4vpJwkThumbprint and a digest-only mdoc context into tests/support/mdoc-session-transcript.ts.
   - Rename tests/openid4vp-validation.test.ts to tests/mdoc-session-transcript.test.ts.
   - Delete the source file and update the AGENTS.md map.
   - Remove dcql from package.json only if you approve.
 - Risks: none at runtime, since nothing imports it.
 - Acceptance: the test-identity check passes (identical tests, renamed file); grep openid4vp-validation finds no references.

 ### D-06 · Test-only helpers in proofs.ts (needs decision 3)

 Severity Low · Risk Low
 - Refactoring: delete jwkToJwks and firstWalletJwks (proofs.ts:135-157) and the assertions that only cover them.
 - Do not merge them with the similar inline logic in mapCredentialRequest. They differ: one tests in header, the other !== undefined, so merging would change captured evidence.
 - Acceptance: the list of removed tests is stated in the commit; everything else passes the test-identity check.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 3: Shared helpers and module boundaries

 ### B-01 · One errorMessage in src/errors.ts

 Severity Low · Risk Low · Depends on D-05, T-03, T-04
 - Sites: server.ts:1951, credential-encryption.ts:315, credential-registry.ts:165, attestbook/integration.ts:762. All four are identical.
 - Keep separate: credoErrorMessage in credo-openid4vp.ts:983, which also takes a fallback.
 - Acceptance: one definition; the error_description of invalid_encryption_parameters is unchanged.

 ### B-02 · Leaf src/json-guards.ts

 Severity Med · Risk Med · Depends on B-01
 - Move here:
   - isRecord, replacing the export from attestbook/snapshot.ts:362 (seven importers) and the copies in credo-openid4vci.ts:1100, fake-oauth-server.ts:315 and oid4vci-capture.ts:289. All are equivalent.
   - The asRecord variants that return null: credential-encryption.ts:311, credo-openid4vp.ts:1421 and server.ts:2461 (objectOrNull).
   - isStringArray (metadata.ts:165, plus the same check in proofs.ts:216).
   - asStringOrNull, moved from state.ts:391. It requires a non-empty string, so it keeps its name.
 - Do not merge: the undefined-returning asRecord in proofs.ts:206 and client-attestation.ts:84, or the asString variants. Swapping null for undefined changes captured evidence (a null member versus an absent one).
 - Problem: nine copies of the same check, and an integrity-verifier module doubling as the shared utility.
 - Acceptance: one definition of each; the test-identity check passes.

 ### B-03 · Break both import cycles

 Severity Med · Risk Low · Depends on D-03
 - Refactoring:
   - Move CredentialFormat and CredentialProofPolicy from metadata.ts:29-33 into the leaf src/types.ts. The two cycles exist because of CredentialProofPolicy.
   - Move AttestbookIssuerSummary (ui.ts:19-24) into attestbook/types.ts, so domain code no longer imports from the UI module.
   - Update all importers directly.
 - Validation: npx madge --circular --extensions ts src (optional tool).
 - Acceptance: zero cycles; attestbook/integration.ts no longer imports ui.ts.

 ### B-04 · Extract the Credo agent runtime (src/credo-agent.ts)

 Severity Med · Risk Low · Depends on D-05
 - Move unchanged: InMemoryStorageModule/InMemoryStorage, NodeKmsBackend and nodeAgentDependencies from credo-openid4vp.ts:1120-1473, with their private helpers.
 - Update: credo-openid4vci.ts:47 and tests/credo-issuer-hot-update.test.ts:9-12.
 - Problem: the issuer imports the 1473-line verifier module only to build a Credo agent.
 - Do not merge: with CredentialEncryptionKms, or the two publicJwk helpers. They behave differently (one adds a random kid).
 - Acceptance: credo-openid4vci.ts doesn't import credo-openid4vp.ts; credo-issuer-hot-update.test.ts passes.

 ### B-05 · Extract presentation decoding (src/credo-presentation.ts)

 Severity Low · Risk Low · Depends on B-04, T-05
 - Move: the DecodedPresentation(s) types, decodedPresentationsFromDcql, decodedPresentationFromCredo, toJsonSafe/toJsonSafeValue and trustedIssuerForX509Credential (credo-openid4vp.ts:146-164, 988-1118).
 - Update: tests/credo-openid4vp.test.ts.
 - Acceptance: the decoded-presentation evidence is byte-identical (the T-05 mdoc test plus the SD-JWT tests).

 ### B-06 · Split config.ts, phase A: pure modules

 Severity Med · Risk Med · Depends on B-03
 - New modules:
   - src/config-paths.ts: all *Path helpers and *_FILE constants (config.ts:25-27, 289-348, 395-397).
   - src/config-verifier.ts: VERIFIER_*_KEY_ID, the verifier-attestation issuer helpers, and the verifierDid/verifierDidDocument helpers (22-24, 350-393).
 - Update: roughly 12 source and 5 test importers, directly.
 - Benefit: modules that only need a path string stop pulling in Credo, jose and the filesystem code.
 - Acceptance: config.ts shrinks by about 150 lines; the test-identity check passes.

 ### B-07 · Split config.ts, phase B: environment, YAML, key material, loading

 Severity Med · Risk Med · Depends on B-06, T-06, T-08
 - Step 1, tests first: round-trip tests for the hand-written parseYamlConfig/stringifyYaml. Cover:
   - every key that init writes
   - "", quoted strings, "true" vs true (matching is case-sensitive), negative and decimal numbers, a JSON array
   - an inline #, CRLF line endings, a duplicate key (the last one wins)
 - Step 2, split:
   - config-env.ts (114-254), config-yaml.ts (256-287), config-material.ts (456-1003), config-load.ts (399-454).
   - config.ts keeps the constants, DEFAULT_CONFIG and normalizeBaseUrl.
   - attestbook/settings.ts:28-34 reuses the boolean environment parser from config-env.ts (same accepted values, same error text).
 - Constraints: no YAML library (that would change the config format and add a dependency); the config.yaml file mode stays 0o600.
 - Acceptance: init writes identical files and contents, checked by the output-equality script over a temp directory.

 ### B-08 · Separate the credential catalogue from metadata output

 Severity Med · Risk Low · Depends on B-03
 - New src/credential-catalogue.ts: SupportedCredential, StaticCatalogueIssuer, the configuration-id helpers, supportedCredentials* and the claim-path helpers (metadata.ts:29-56, 176-393).
 - metadata.ts keeps: issuer metadata, jwtVcIssuerMetadata, proof types and signing.
 - Rules: update importers directly; keep supportedCredentials as a literal. Turning it into a table would hide the scopes that tests assert.
 - Acceptance: tests/metadata.test.ts passes unchanged; the metadata JSON for every issuer is byte-identical (output-equality script).

 ### B-09 · Make the CLI testable

 Severity Med · Risk Med · Depends on T-08
 - Refactoring:
   - Create src/cli/commands.ts with runCommand(command, args, io) and initSummary, both without side effects.
   - Move parseArgs there from config.ts:70-85.
   - src/cli.ts stays the entry point and keeps calling main().
 - Do not add an import.meta.url === argv[1] guard: with the pnpm bin symlink the two paths can differ and the CLI would silently do nothing.
 - Acceptance: T-08 passes unchanged; new direct runCommand tests replace nothing.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 4: Reducing complexity

 ### C-01 · Deduplicate VP submission and session lookups

 Severity Med · Risk Med · Depends on T-01, B-02
 - Problem: server.ts:1502-1546 and 1586-1624 are byte-identical submission bodies. There are also identical preambles at 1346 and 1366, 984 and 992, 492 and 512, and 619 and 684.
 - Refactoring:
   - submitPresentation(ctx, req, res, session, body). Each route keeps its own preamble: only the session-scoped route checks dcApiSubmissionRejectionOrNull, and that asymmetry stays.
   - loadVpSession and loadIssuanceSessionAndOffer. The UI (HTML) and API (JSON) versions stay separate.
 - Keep separate: the federation metadata lookup (651-679) differs and stays as it is.
 - Acceptance: jscpd reports none of those copies; T-01 passes.

 ### C-02 · Pull POST /sessions input handling out of the handler

 Severity High · Risk Med · Depends on T-02, C-01
 - New src/server/issuance-session-input.ts:
   - parseIssuanceSessionInput returns {ok, value} | {ok: false, status, body}.
   - resolveIssuanceTarget, parsePidOptions and serializeIssuanceSession cover the remaining steps.
 - Must preserve: the order of checks, every error body (supported_*, unsupported_parameters), and the 409 response.
 - Acceptance: handler complexity (cx) at or below 15; T-02 passes unchanged.

 ### C-03 · Pull POST /openid4vp/sessions input handling out of the handler

 Severity High · Risk Med · Depends on T-02, C-01
 - New src/server/presentation-session-input.ts:
   - parseVpSessionInput (1097-1145) and deriveVpSessionOptions (1146-1150).
   - validateVpSessionCombination (1151-1243). The existsSync and trust-anchor checks keep their current order.
   - parseVpRequestOverride and serializeVpSession.
 - Acceptance: handler cx at or below 15 (from 91); T-02 passes unchanged.

 ### C-04 · Decompose POST /openid4vp/sessions/:id/request

 Severity Med · Risk Med · Depends on C-01
 - New src/server/vp-request-uri.ts: recordWalletNonceRequest, resignDeliveredRequest and sendNegotiatedRequestObject.
 - Must preserve: the deliberate sendRequestUriResponse(…400…) at 1465-1471, and the vp_request_retrieved event payload.
 - Acceptance: T-02 and the wallet_nonce tests (server.test.ts:1212-1226, 2256-2319) pass.

 ### C-05 · Decompose POST /issuers/:id/credential

 Severity Med · Risk Med · Depends on T-02, T-03
 - New src/server/credential-endpoint.ts: readCredentialRequestBody, recordCredentialRequestEvidence, pinnedDefinitionMismatch and forwardCredentialRequest.
 - Must preserve: the encryption interceptor runs before the scenario interceptor (see the comment at 1714-1716); the Cache-Control: no-store header; how redaction works.
 - Acceptance: T-02 and T-03 pass.

 ### C-06 · createVpSession options object, and verifierAttestationOrNull

 Severity Med · Risk Low · Depends on C-03
 - Refactoring:
   - Replace createVpSession's 16 positional parameters (server.ts:2116) with a CreateVpSessionOptions object, keeping the same defaults.
   - Split out recordVpSessionState.
   - In verifierAttestationOrNull (2544, cx 20), extract redirectUrisOrStringOrNull. Add a test for the uncovered 2556-2557 first.
 - Acceptance: both call sites (API and UI) updated; the test-identity check passes.

 ### C-07 · createApp as composition root with route modules

 Severity High · Risk High · Depends on C-01 to C-06
 - New src/server/context.ts: ServerContext owns the per-request capture WeakMap and the three functions that use it (148-212). Those closures are the only real coupling between route groups.
 - Router factories, all mounted at the root (never app.use("/prefix", …), because req.path drives capture attribution):
   - public, ui, discovery, issuer-metadata
   - issuance-session, presentation-session, presentation-request, presentation-response
   - credential, protocol-forwarding
 - Must preserve:
   - the order: webhook raw parser, then body parsers, then parse-error handling, then capture, then the fake OAuth server, then routes
   - routes that fall through with next()
   - the unmatched 404 before the 500 handler
 - Validation: a throwaway route-inventory diff that lists app._router.stack as (method, path) under four configurations, before and after; must be identical. Not committed.
 - Acceptance: server.ts under 300 lines; the inventory diff is empty; the test-identity check passes.

 ### C-08 · Split openApiDocument

 Severity Med · Risk Low · Depends on T-09
 - New src/openapi/: common.ts, paths-service.ts, paths-issuance.ts, paths-presentation.ts, paths-openid4vci.ts, paths-federation.ts, components.ts and document.ts.
 - Must preserve: the current key order, by spreading the sections in the same sequence (JSON.stringify follows insertion order).
 - Validation: output-equality script on JSON.stringify(openApiDocument(cfg)) for four configurations.
 - Acceptance: byte-identical output.

 ### C-09 · Decompose CredoOpenId4VpVerifier.createSession

 Severity High · Risk Med · Depends on T-05, B-04
 - Step 1, tests first: snapshot tests of the resulting session for each delivery mode (by_reference, by_value, plain, multisigned, dc_api) and for a request_mutation case. They assert the delivered request differs from the verifier's own
   copy.
 - Step 2, new src/credo-openid4vp-request.ts: authorizationRequestForVerifier (282-305), applyClientMetadata (301-319), signedDeliveryPlan (330-414) and requestEnvelope (417-439).
 - Keep: the 13-parameter signature (changing it is a separate task).
 - Risks: the order of mutation, signing and deliberate corruption is part of the protocol behaviour and must stay the same.
 - Acceptance: cx at or below 15; snapshots unchanged.

 ### C-10 · Extract issuance attribution and evidence helpers

 Severity Med · Risk Low · Depends on B-02
 - Move verbatim from credo-openid4vci.ts:907-1116:
   - into src/oid4vci-attribution.ts: issuanceSessionQuery, accessTokenSessionQuery, issuanceSessionAuthorizes, captureStatus, requestHeaders
   - into src/oid4vci-evidence.ts: captureAuthorizationEvidence, setObservedString, redactCredentialRequest
   - wwwAuthenticateChallenge into oid4vci-notification.ts
 - Then add table tests: each endpoint type, duplicated headers, a pre-authorized code mismatch, an unknown Credo state.
 - Acceptance: uncovered lines 963, 983, 1028-1029, 1057 and 1092-1095 are covered.

 ### C-11 · Decompose mapCredentialRequest

 Severity High · Risk Med · Depends on C-10, T-04
 - New src/oid4vci-credential-mapping.ts: recordCredentialRequestEvidence, allocateStatusListReferences (keeping index-based replacement) and signingOptionsForCredential.
 - Must preserve: evidence is recorded before signing; the exact error strings ("superseded credential definition", …).
 - Acceptance: about 35 lines left in the mapper; the revocation, wallet-initiated and Attestbook issuance tests pass.

 ### C-12 · One SD-JWT signing envelope

 Severity Med · Risk Low · Depends on D-01
 - Problem: five builders (credential.ts:85-97, 153-165, 178-195, 226-238) repeat the same issuer, holder, header-type and hashing-algorithm block.
 - Refactoring: sdJwtSigningEnvelope(config, holderJwk, digestAlgorithm) and expiresAt(now). In the imported-credential builder, claim validation stays ahead of the envelope.
 - Test first: with a fixed now, a table test across all five builders asserting issuer, holder, headerType, whether hashingAlgorithm is present, and exp.
 - Acceptance: jscpd reports none of the credential.ts copies.

 ### C-13 · CaptureStore.createSession options object

 Severity Med · Risk Med · Depends on D-03
 - Problem: 10 positional parameters (state.ts:65), two of them adjacent strings that are easy to swap (fixtureId, documentNumber).
 - Refactoring: createSession(issuer, options).
 - Test first: a new tests/state.test.ts pinning the SessionCapture keys and the session_created details.
 - Acceptance: both call sites updated; the snapshots are identical.

 ### C-14 · Attestbook handleWebhook

 Severity Med · Risk Med · Depends on T-06
 - Refactoring (integration.ts:244-365): private verifyDelivery, returning one of challenge / reject / publication, and recordNotification.
 - Must preserve: every status and body, and logging before each return.
 - Acceptance: the T-06 webhook rows pass.

 ### C-15 · Attestbook reconcile

 Severity Low · Risk Med · Depends on T-06
 - Refactoring: evaluateIssuability(definitions) (560-600) and publishCatalogue(catalogue).
 - Must preserve: the status().sync failure and diagnostics JSON, and the no-leak checks (attestbook-integration.test.ts:765-766).

 ### C-16 · Attestbook json-schema.ts and boundedGet

 Severity Low · Risk Low · Depends on T-06
 - Refactoring:
   - In json-schema.ts: validateObjectShape, compileProperties, checkScalarKeywords.
   - In http.ts: assertResponseAcceptable and readBoundedBody, keeping the same checks in the same order.
 - Must preserve: diagnostics stay in the order asserted at attestbook.test.ts:400-470.

 ### C-17 · Split ui.ts by page family

 Severity Med · Risk Low · Depends on B-03
 - New src/ui/:
   - html.ts (escapeHtml, htmlPage)
   - launcher.ts, issuer.ts, verifier.ts, session.ts, markdown.ts
   - styles.ts (APP_CSS, unchanged) and scripts.ts (four script constants, unchanged)
 - Rules: update server.ts and tests/ui.test.ts directly. Keep CSS and JS as TypeScript strings: tsc doesn't copy assets, and tests assert inline fragments.
 - Test first: errorPage (1062-1076) and the Attestbook summary branches.
 - Validation: output-equality script rendering every page function with fixed inputs.
 - Acceptance: byte-identical HTML.

 ### C-18 · Type safety at boundaries, with no runtime change

 Severity Low · Risk Low · Depends on B-02, B-07, C-14
 - Changes:
   - Add an AttestbookSyncStatus type so status() needs no casts (integration.ts:410-447).
   - parseYamlConfig returns Record<string, unknown> and fields are mapped explicitly. Values that pass through today still pass through.
   - Replace casts made after an inline shape check with isRecord guards (request-object-encryption.ts:136,143, response-scenario.ts:63, request-behavior.ts:87-89).
 - Leave as is: the as never casts at Credo-TS call sites; they are a convention for the pinned alpha API.
 - Acceptance: fewer as casts; the test-identity check passes.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 5: Test structure

 ### S-01 · Shared test harness

 Severity High · Risk Med · Depends on T-01 to T-09
 - Problem: about 70 copied blocks in tests. server.test.ts helpers (7504-7833, 5851-5875, 118-144) close over module-level config and dataDir, so other files can't use them.
 - New modules:
   - tests/support/server-context.ts: temp directory, initIssuer hooks, conforming-issuer constants, postJson, getJson.
   - dpop.ts: one dpopProof(key, {method, url, accessToken, overrides?}), replacing three variants. Notification callers pass POST; the resulting claims are identical.
   - issuance.ts, vp.ts, mdoc.ts.
 - Keep file-local: the two requestCredential helpers (different nonce, attestation and return contracts) and the JWT-only default used by the notification tests.
 - Acceptance: server.test.ts still a single file; the test-identity check passes; the jscpd count of copied test blocks is down by at least 60%.

 ### S-02 · Split server.test.ts by concern

 Severity High · Risk Med · Depends on S-01
 - Split: about 10–15 files following the existing describe blocks. Line-range mapping is in the UI and tests scout's report (agent://UiAndTestsSlice, finding T1).
 - Rules:
   - Each file keeps the outer describe("capture issuer server") name, so full test names don't change.
   - Each file gets its own temp directory and afterAll cleanup.
   - vi.mock("../src/credential-encryption.js") goes only into the file containing the delayed-response test (around 4505).
 - Acceptance: the test-identity check passes with an empty diff of 471 names; no file over 1500 lines.

 ### S-03 · Shared issuer fixture for the small suites

 Severity Low · Risk Low · Depends on S-01
 - Refactoring: tests/support/issuer-fixture.ts providing holderJwk and fixtureIssuerContext. Use it in degree-credential (three inline copies), pid-fixtures, status-reference-fixtures and config.test.ts:116-205.
 - Do not merge: the Attestbook membership fixtures; they differ (required, additionalProperties, metadata).
 - Acceptance: the test-identity check passes.

 ────────────────────────────────────────────────────────────────────────────────

 Phase 6: Navigation

 ### N-01 · Refresh repo docs and the graph

 Severity Med · Risk Low · Depends on C-07, B-07, S-02
 - Refactoring: rewrite the AGENTS.md repo map for the new src/server/, src/ui/, src/openapi/, config, credo and test-support modules, then run graft build.
 - Acceptance: every module named exists. Re-run jscpd health: target complexity above 60, duplication above 85.

 ────────────────────────────────────────────────────────────────────────────────

 Deferred: these change behaviour or a public surface, so each needs your approval

 ┌─────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────────────────┐
 │ ID  │ Item                                                                                                                               │ Why deferred                                                               │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-1 │ Remove dcql from package.json                                                                                                      │ AGENTS.md dependency rule (decision 1)                                     │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-2 │ Add missing /openapi.json paths (client-identifiers, attestation-issuer JWKS, /openid4vp/redirect, challenge, deferred-credential) │ Changes a public document                                                  │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-3 │ Merge the inline appCss with style.css; fix the @font-face rules that point at font files which don't exist                        │ Changes served HTML and CSS                                                │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-4 │ Parse DCQL with DcqlQuery.parse instead of as never (credo-openid4vp.ts:266)                                                       │ Changes when invalid DCQL is rejected and when the fallback query kicks in │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-5 │ Split types.ts (787 lines) by domain                                                                                               │ Rewrites 40 imports for little gain                                        │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-6 │ Move restore/start/pinSession out of the Credo issuer's create                                                                     │ Startup order is protocol-relevant                                         │
 ├─────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┤
 │ X-7 │ Merge the undefined- and null-returning asRecord/asString                                                                          │ null versus an absent member changes captured evidence                     │
 └─────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────────────────────────┘

 Checked and not recommended

 - One generic JSON-error helper: every error body differs, so it would add nothing.
 - Merging GET and POST request-URI handlers, clientScript with vpClientScript, the two requestCredential test helpers, or the URL validators in config, settings, http and federation: verified to behave differently.
 - Splitting CaptureStore: the instance is the lookup key for three WeakMap registries.
 - Turning supportedCredentials into a table, or merging the per-issuer configuration modules: both are declarative contracts that tests pin.
 - Splitting notification.test.ts or attestbook-integration.test.ts: both are cohesive single-concern files.

 Remaining risks

 - Highest-risk tasks: C-07 (middleware order), C-09 (signing and mutation order) and S-02 (tests interfering with each other once split across files). Each has its own validation step above.
 - One correction to the scouts: a scout described POST /openid4vp/response as the default response_uri. It isn't; that builder is dead code. It is a documented alternative endpoint that picks the session by state, so T-01 still has to
   cover it.
