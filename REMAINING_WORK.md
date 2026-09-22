# Remaining work

Status of the FCAF coverage plan for this repository. One section per plan phase, listing what is
still missing, what each missing item needs, and what blocks it externally.

Status markers: **done**, **partial**, **not started**, **blocked** (needs something outside this
repository).

Test identifiers are the upstream file names verbatim, from the `submitted` branch of
[`eudi-doc-functional-conformance-assessment`](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment),
under `docs/fcaf/suts/wallet_solution/relying_party/`. Identifiers keep their double underscores
and their `_UF` suffixes; the rendered site normalises them and reports false negatives.

## Phase 0 — capability inventory — not started

| Missing | Needs |
| --- | --- |
| The capability matrix: one row per upstream test with category, capability owed, owning phase, whether the capability and its evidence already exist, and the blocker | `ASSERTION_REVIEW_BACKLOG.md` from the harness repository, which is not available locally |
| Mechanical identifier validation of the backlog against the upstream branch | The same file. The method is settled: 621 `WS_RP_*` files exist, and each file name is the identifier verbatim |
| Resolving the cross-phase ownership overlaps recorded in Phase 7 | The matrix's owner column |

Every capability below was implemented by reading the upstream test files directly, so Phase 0 does
not block the code. It does block the coverage count and the harness-side worklist.

## Phase 1 — close gaps needing no new capability — partial

Covered while implementing later phases: request delivery (1.1), presentation-response capture
(1.2), issuer and credential capabilities (1.4).

Still missing:

- **1.3, systematic confirmation of optional Authorization Request parameters.** `scope`,
  `transaction_data` and `verifier_info` are confirmed to reach the signed Request Object.
  `client_metadata`, `response_uri`, `redirect_uri` and `require_cryptographic_holder_binding` have
  not been checked end to end, and one defect in this area is already known (see 6.2).

## Phases 2 and 3 — done

Request Object and Request URI scenarios (`request_mutation`, `signature`, `request_uri_response`,
`wallet_nonce`) and configurable verifier HTTP response scenarios (`response_scenario`) are
implemented, documented and tested.

## Phase 4 — issuer and credential fixtures — partial

| Item | Status | Detail |
| --- | --- | --- |
| 4.1 multiple credentials of one type, 4.5 additional claim values | done | Nine `fixture_id` claim sets, plus the `age_over_18` attribute in both encodings |
| 4.2 credentials without holder binding: `WS_RP_IA_MainInteraction__006`, `__008`, `__010`, `WS_RP_MS_CredentialFormats__046` | blocked | Awaiting [credo-ts#2936](https://github.com/openwallet-foundation/credo-ts/pull/2936); Credo currently refuses `require_cryptographic_holder_binding: false` |
| 4.3 JOSE status structures | done | Six `status_reference` fixtures, SD-JWT VC only |
| 4.3 COSE status structures: `WS_RP_MS_Metadata__092`, `__094`, `__096`, `__097`, `__099`, `__100`, `__102` | blocked | `@owf/token-status-list` enforces a non-negative integer `idx` and a string `uri`, so malformed COSE structures need a non-Credo COSE path. Requires explicit approval under AGENTS.md |
| 4.4 SD-JWT VC JSON serialization: `WS_RP_MS_CredentialFormats__048` | blocked | Compact serialization only, on both the issuing and the verifying side |
| The numeric axis of `WS_RP_IA_MainInteraction__033` | not started | No issued credential carries a numeric claim; the test's `kg` axis needs a new credential type |

## Phase 5 — trust, identity and cryptography — partial

| Item | Status | Detail |
| --- | --- | --- |
| 5.1 negative X.509 scenarios | done | Wrong signing key, self-signed leaf, untrusted root, incomplete chain, missing `x5c`, mismatching hash or DNS name |
| 5.1 `x509_san_dns` happy path: `WS_RP_MS_Metadata__125`, `__127`, `__128` | blocked | The EUDI service-provider registry issues no certificate with a `dNSName` SAN, so a registry-trusted request cannot use that prefix |
| 5.1 wallet trust anchor inside `x5c`: `WS_RP_SM_RpIntegrity__025` | not started | Needs the certificate the wallet is configured to trust, which this service does not hold |
| 5.2 DID signing-key mismatch: `WS_RP_SM_RpIntegrity__007` | done | `request_behavior.signing_key: "unrelated"` with the `decentralized_identifier` prefix |
| 5.3 RS384 or PS384 signed requests: `WS_RP_SM_RpIntegrity__032`, `WS_RP_SM_RpIntegrity_CryptographicSignature_002` | not started | The KMS backend generates EC keys only, so an RSA certificate needs a non-Credo path. The upstream text says "RSASSA-PSS … (RS384)", which is self-contradictory: PS384 is RSASSA-PSS, RS384 is PKCS#1 v1.5. Resolve which is intended before building it |
| 5.3 COSE algorithm identifiers −7 versus −9: `WS_RP_SM_RpIntegrity__033`, `__034`, `WS_RP_SM_RpIntegrity_CryptographicSignature_003`, `_004` | not started | Both identifiers describe ECDSA P-256 with SHA-256, which a JOSE `alg` header expresses only as `ES256`. Not verifier-controllable in a JAR request; likely needs reclassification upstream rather than code here |
| 5.4 encrypted Request Object: `WS_RP_IA_MainInteraction__024` | not started | Request Object encryption is not implemented. First check whether Credo can encrypt a JAR request to the wallet's `wallet_metadata` JWKS |
| 5.4 remaining cases: `WS_RP_MS_Metadata__134`, `__135`, `__136`, `__137` | done | `__134`, `__136` and `__137` need only the captured `wallet_metadata`; `__135` is the service's current unencrypted behaviour |
| 5.5 verifier attestation: `WS_RP_SM_RpIntegrity__001`, `__008`–`__012`, `WS_RP_MS_Metadata__116`–`__124` | not started | Needs a fixture attestation issuer producing a valid attestation plus variants with an untrusted issuer, a broken signature, a wrong subject, a wrong confirmation key and wrong redirect-URI claims |
| 5.6 WRPAC: `WS_RP_SM_TrustMechanisms__101`, `__101b_UF`, `__101c_UF` | not started | Needs WRPAC certificate fixtures and confirmation that the wallet under test processes that mechanism |
| 5.7 OpenID Federation: `WS_RP_IA_Metadata__014`, `WS_RP_MS_Metadata__112`–`__115` | not started | Needs entity statements, a resolvable trust chain and a federation authority |
| 5.8 ETSI trusted lists and certificate matching: `WS_RP_MS_ProtocolMessages__095`, `WS_RP_SM_TrustMechanisms__002`–`__013`, `__015`, `__021` | not started | Needs credential and issuer chains with controlled Authority Key Identifiers plus trusted-list fixtures. `WS_RP_SM_TrustMechanisms__014` does not exist upstream |

Phases 5.6 to 5.8 depend on external trust infrastructure that this repository does not stand up.
Whether they are in scope at all is an open decision.

## Phase 6 — scope mapping, transaction data, remaining capabilities — partial

| Item | Status | Detail |
| --- | --- | --- |
| 6.1 scope-based requests: `WS_RP_UC_Presentation__003`, `WS_RP_MS_ProtocolMessages__020`, `__030`, `__141` | done | `dcql_query: null` now omits the query from the delivered request only, so a scope-only request is verifiable: the Verifier keeps its query and matches the Authorization Response against the request object it signs. Previously the query was dropped from both, and any presentation returned for a scope-only request failed with "the authorization request is missing a 'dcql_query'". Scope values stay caller-supplied, because a Wallet resolves them through its own profile and a value invented here would be recognised by none |
| 6.2 `transaction_data` wire form: `WS_RP_MS_ProtocolMessages__017`, `__018`, `__154`–`__159` | done | Array entries supplied as JSON objects are base64url-encoded as Section 5.1 requires, so a caller writes the entry a Wallet has to decode and reject; entries of any other type are delivered exactly as supplied, a value that is not an array is untouched, and a `request_mutation` on `/transaction_data` bypasses encoding for a container-level defect |
| 6.2 transaction data binding: `WS_RP_MS_ProtocolMessages__135` | done | Credo-TS verifies the Section 8.4 binding itself, because this service hands it the request object it signed and that object carries the transaction data. The outcome is now recorded as `checks.transaction_data_verified`: true when the presentation was accepted, false when Credo rejected it with `invalid_transaction_data`, null when no transaction data was sent or the failure was unrelated. Credo enforces more than the hash set: every entry must be covered by some presentation, and the hash algorithm must be one the entry offered |
| 6.3 `WS_RP_SM_DeviceBinding__002`–`__006` | not started | Misnamed in the plan: all five concern key-bound **Verifier Info attestations**, namely `nonce` and `client_id` in the signature object, a valid proof, a failing proof and an unrecognised attestation type. This is the same workstream as 5.5, not credential device binding. `verifier_info` is forwarded raw, so a pre-made attestation can be injected once the 5.5 fixture issuer exists |
| 6.4 `WS_RP_SH_Cryptography_Encryption_002` | done | Expressible today with `client_metadata`, for example `{"encrypted_response_enc_values_supported": ["A128GCM"]}` |
| 6.4 `WS_RP_SH_Cryptography_CryptographicHash_006` | done | Capture-only: the wallet metadata recorded by the POST `request_uri` flow |
| 6.4 `WS_RP_SH_Cryptography_CryptographicHash_007`, `_008` | not started | Needs the verifier to advertise, or use, a hash algorithm other than SHA-256. Determine which client-metadata member expresses this before implementing |
| 6.4 `WS_RP_SH_Cryptography_CryptographicHash_010` | not started | Needs an issuer fixture whose credential uses a digest hash algorithm other than SHA-256 (`_sd_alg`). Check whether Credo's SD-JWT VC signing options expose the digest algorithm |

## Phase 7 — blocked-test register — partial

Blockers are recorded in `FCAF_FIXTURES.md` and in the README's "Known limitations" section, but not
yet as the register the plan asks for: per test, the missing precondition, the owner, whether it is
implementable here, whether another profile or environment is required, and what would unblock it.

Not yet addressed at all:

| Test | Precondition |
| --- | --- |
| `WS_RP_IA_Engagement__001b` | An `eu-eaap://` scheme invocation |
| `WS_RP_IA_Supportive__006` | Device resource exhaustion on the wallet device |
| `WS_RP_MS_ProtocolMessages__151` | An unsupported mdoc format variant |
| `WS_RP_SM_IssuerIntegrity__012` | An mdoc revocation fixture |
| `WS_RP_IA_MainInteraction__046` | A credential large enough to exceed URL or transport limits |
| `WS_RP_IA_MainInteraction__060` | Applicability reassessment by the wallet |

## Cross-cutting

- **Digital Credentials API execution.** The transport is implemented, but nothing in this
  repository can drive a wallet through it. `WS_RP_IA_Engagement__002`,
  `WS_RP_IA_ProtocolFlow__003a` and `__003b_UF` additionally need a DC-API-provider wallet, an HTTPS
  browser context and harness automation. That work is harness-side, but it is the precondition for
  those three tests. If a browser driver is introduced for it, declare it in `mise.toml`.
- **Required developer tools.** No new tool is needed so far; `mise.toml` still declares only
  `node`, `pnpm` and `task`.

## Suggested order

1. **5.5 with 6.3, verifier attestation fixtures.** One workstream covering eleven tests, and
   self-contained if the attestation issuer is a local fixture.
2. **6.4 credential digest algorithm**, if Credo exposes it.

Open decisions needed before the remaining items can proceed:

- Whether `WS_RP_SM_RpIntegrity__032` and `CryptographicSignature_002` mean PS384 or RS384.
- Whether a non-Credo COSE path is approved for the malformed COSE status structures in 4.3.
- Whether phases 5.6 to 5.8 are in scope, given that they need external trust infrastructure.
