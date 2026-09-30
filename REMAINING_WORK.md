# Remaining work

This register intentionally lists only unfinished work from `whole_plan.md`: missing prerequisites,
blocked capabilities, and decisions. Completed capabilities and their evidence remain documented in
the source, tests, `FCAF_FIXTURES.md`, `README.md`, and `CAPTURE_WALLET_API.md`.

## Phase 0 — capability matrix

`FCAF_CAPABILITY_MATRIX.csv` is the committed, machine-diffable inventory of all 621 upstream
relying-party tests. It records the source requirement, category, Capture Wallet capability,
evidence fields, owning phase, and external blocker or owner. `FCAF_CAPABILITY_MATRIX.md` defines
its stable columns and inputs.

### Execution sequence

1. Confirm category-A scenarios by recording the actual delivered request,
   response, credential, and evidence fields; do not add duplicate service
   controls.
2. Add only the issuer and credential fixtures that Credo can generate and the
   reference Wallet can consume.
3. Investigate signing, discovery, encryption, and trust work through
   Credo-TS first; record external Wallet or infrastructure dependencies
   instead of substituting a custom implementation.
4. Reassess scope, transaction-data, device-binding, and external blockers
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
| 5.3 PS384 signed requests: `WS_RP_SM_RpIntegrity__032`, `WS_RP_SM_RpIntegrity_CryptographicSignature_002` | Source says RSA-PSS with SHA-384 but labels it `RS384`; JWA names that operation `PS384`. Do not choose either until upstream resolves the identifier. Credo core supports both; the repository's `NodeKmsBackend` and verifier fixtures currently support only ES256. |
| 5.3 unacceptable-algorithm Request Object: `WS_RP_SM_RpIntegrity__013c_UF` | Needs a Wallet-trusted verifier certificate for a key of the unacceptable algorithm (source example: EdDSA). Credo core signs EdDSA, but a request signed by an untrusted certificate would be rejected on trust rather than on the algorithm the test is about. |
| 5.4 Request Object encryption parameter names: `WS_RP_MS_Metadata__134` | Implemented. The verifier negotiates `request_object_encryption_*` (OpenID4VP Section 10, RFC 8414 registry); the source text names `authorization_encryption_*`, which OpenID4VP Section 5.10 assigns to the Authorization Response. A Wallet advertising only the latter receives `400 invalid_request`. Open decision: whether to accept the source's names as a fallback. |
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
