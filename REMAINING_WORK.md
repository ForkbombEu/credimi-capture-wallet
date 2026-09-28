# Remaining work

This register intentionally lists only unfinished work from `whole_plan.md`: missing prerequisites,
blocked capabilities, and decisions. Completed capabilities and their evidence remain documented in
the source, tests, `FCAF_FIXTURES.md`, `README.md`, and `CAPTURE_WALLET_API.md`.

## Phase 0 — capability matrix

The plan's machine-diffable capability matrix has not yet been produced. It must use the harness
repository's `ASSERTION_REVIEW_BACKLOG.md` as read-only input and contain one row for every upstream
test: its category, repository-owned capability, evidence fields, phase owner, and external
blocker/owner.
### Execution sequence

1. Produce and commit the Phase 0 capability matrix from every upstream
   relying-party test, the harness backlog, and the current Capture Wallet
   contract.
2. Confirm category-A scenarios by recording the actual delivered request,
   response, credential, and evidence fields; do not add duplicate service
   controls.
3. Group the remaining service-owned request variations behind the isolated,
   FCAF-gated Request Object and Request URI mechanism, then implement and
   verify it.
4. Add the per-session verifier-response mechanism and preserve independent
   HTTP and cryptographic-verification evidence.
5. Add only the issuer and credential fixtures that Credo can generate and the
   reference Wallet can consume.
6. Investigate signing, discovery, encryption, and trust work through
   Credo-TS first; record external Wallet or infrastructure dependencies
   instead of substituting a custom implementation.
7. Reassess scope, transaction-data, device-binding, and external blockers
   after their shared prerequisites have been proven.

Each service-owned slice is a separate commit with HTTP-level evidence, normal
session regression coverage, documentation, formatter, lint, and the relevant
test/build validation.

## Phase 4 — credential fixtures

| Item | Blocker |
| --- | --- |
| 4.2 credentials without holder binding: `WS_RP_IA_MainInteraction__006`, `__008`, `__010`, `WS_RP_MS_CredentialFormats__046` | [credo-ts#2936](https://github.com/openwallet-foundation/credo-ts/pull/2936): Credo currently refuses `require_cryptographic_holder_binding: false` during issuance. |
| 4.4 SD-JWT VC JSON serialization: `WS_RP_MS_CredentialFormats__048` | The issuer and verifier currently support compact serialization only. |


## Phase 5 — trust, identity, and cryptography

| Item | Status / next prerequisite |
| --- | --- |
| 5.1 `x509_san_dns` happy path: `WS_RP_MS_Metadata__125`, `__127`, `__128` | Blocked: the EUDI service-provider registry issues no certificate with a `dNSName` SAN, so a registry-trusted request cannot use that prefix. |
| 5.1 wallet trust anchor inside `x5c`: `WS_RP_SM_RpIntegrity__025` | Needs the certificate the configured wallet trusts. |
| 5.3 RS384 or PS384 signed requests: `WS_RP_SM_RpIntegrity__032`, `WS_RP_SM_RpIntegrity_CryptographicSignature_002` | Resolve whether the upstream text intends PS384 or RS384; Credo's current KMS fixture creates EC keys only, and an RSA certificate would require an approved non-Credo path. |
| 5.3 COSE algorithm identifiers −7 versus −9: `WS_RP_SM_RpIntegrity__033`, `__034`, `WS_RP_SM_RpIntegrity_CryptographicSignature_003`, `_004` | Likely upstream reclassification: both identifiers describe ECDSA P-256 with SHA-256, while a JOSE Request Object has only `ES256`; the verifier cannot select a COSE identifier. |
| 5.3 unacceptable and multi-signed Request Objects: `WS_RP_SM_RpIntegrity__013c_UF`, `__030` | Determine Credo support for the source-required unacceptable algorithm and multi-signature construction. An unsupported signing format needs the AGENTS.md non-Credo approval path; do not emulate it with a different request shape. |
| 5.9 discovery, client identifier, and metadata resolution: `WS_RP_IA_Metadata__011`–`__013`, `WS_RP_MS_Metadata__110`, `__133`, `WS_RP_MS_ProtocolMessages__143`–`__146` | Credo-TS `0.7.2-alpha-20260924150946` supports DID, X.509 (`x509_hash`/`x509_san_dns`), and unsigned `redirect_uri` request signers only; the API exposes the same schemes. Dynamic/static discovery cannot currently produce the required signed Request Object. Find a Credo capability first; otherwise an AGENTS.md-approved JOSE alternative is required. |

| 5.4 encrypted Request Object: `WS_RP_IA_MainInteraction__024` | Next repository capability investigation: determine whether the installed Credo version can encrypt a JAR to the wallet's `wallet_metadata` JWKS. |
| 5.5 verifier attestation trust case: `WS_RP_SM_RpIntegrity__010` | Operator must configure the fixture issuer key published at `/openid4vp/verifier-attestation-issuer/jwks.json` as trusted in the wallet. |
| 5.6 WRPAC: `WS_RP_SM_TrustMechanisms__101`, `__101b_UF`, `__101c_UF` | Needs WRPAC certificate fixtures and confirmation that the wallet under test processes the mechanism. |
| 5.7 OpenID Federation: `WS_RP_IA_Metadata__014`, `WS_RP_MS_Metadata__112`–`__115` | Needs entity statements, a resolvable trust chain, and a federation authority. |
| 5.8 ETSI trusted lists and certificate matching: `WS_RP_MS_ProtocolMessages__095`, `WS_RP_SM_TrustMechanisms__002`–`__013`, `__015`, `__021`, `WS_RP_IA_MainInteraction__065` | Needs credential and issuer chains with controlled Authority Key Identifiers plus trusted-list fixtures. `WS_RP_SM_TrustMechanisms__014` does not exist upstream. |

Phases 5.6–5.8 depend on external trust infrastructure that this repository does not stand up. Their
scope remains an explicit decision.

## Phase 7 — blocked-test register

The plan still needs a per-test register with the missing precondition, owner, whether this
repository can implement it, whether another profile/environment is required, and the unblocking
condition. The unaddressed entries are:

| Test | Missing precondition |
| --- | --- |
| `WS_RP_IA_Engagement__001b` | An `eu-eaap://` scheme invocation. |
| `WS_RP_IA_Supportive__006` | Device resource exhaustion on the wallet device. |
| `WS_RP_MS_ProtocolMessages__151` | An unsupported mdoc format variant. |
| `WS_RP_SM_IssuerIntegrity__012` | An mdoc revocation fixture. |
| `WS_RP_IA_MainInteraction__046` | A credential large enough to exceed URL or transport limits. |
| `WS_RP_IA_MainInteraction__060` | Applicability reassessment by the wallet. |
| `WS_RP_SM_RpIntegrity__024` | Wallet profile rejecting every non-`x509_hash` client identifier. |
| `WS_RP_UC_Presentation__004` | Independently controllable second-device invocation path. |


## Cross-cutting external prerequisites

- **Digital Credentials API execution:** the transport and its corresponding FCAF tests are
  implemented and working. No DC API implementation or FCAF test work remains in this repository.
- **Developer tools:** no additional tool is currently required; `mise.toml` declares `node`,
  `pnpm`, and `task`.

## Open decisions

- Whether `WS_RP_SM_RpIntegrity__032` and `CryptographicSignature_002` mean PS384 or RS384.
- Whether phases 5.6–5.8 are in scope given their external trust infrastructure.
