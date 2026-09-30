# FCAF capability matrix

`FCAF_CAPABILITY_MATRIX.csv` is the Phase 0 inventory from `whole_plan.md`.
It contains one stable, identifier-sorted row for every 621 upstream relying-party
Markdown test in the local `submitted`-branch mirror.

## Sources

- Upstream source mirror: `credimi/config_templates/fcaf_sources/wallet_solution/relying_party/`, cross-checked by the harness against upstream `submitted` commit `2b223b56be0d0a073ee0cdc9db1d7fd31d9529a1`.
- Harness work register: `credimi/config_templates/fcaf/wallet_solution/relying_party/ASSERTION_REVIEW_BACKLOG.md`.
- Capture Wallet contract: this repository's current API and capture model.

The harness sources are read-only inputs. This repository owns the matrix, not
FCAF test definitions, assertions, or Wallet runs.

## Columns

| Column | Meaning |
| --- | --- |
| `test_id` | Upstream filename, verbatim. |
| `source_path`, `source_sha256`, `objective`, `expected_results` | Stable source-test identity and the reviewed requirement. |
| `category` | `A` already supported; `B` missing verifier scenario control; `C` missing issuer or credential fixture; `D` missing reference-Wallet capability; `E` missing external trust or infrastructure; `F` unsupported or inapplicable. |
| `capability_owed`, `owner_phase` | Observable behaviour still owed and the sole workstream responsible for it. `none` means Capture Wallet owes no new capability. |
| `capability_present`, `evidence_present` | Independent current-state assessments. `partial` means the available fixture or capture covers only part of the source requirement. |
| `evidence_fields` | Capture or credential artefacts the harness can bind its assertions to. |
| `blocker`, `blocker_owner` | Dependency outside this repository when no local implementation can close the gap. |
| `classification_basis` | Exact inventory inputs used for the row. |

A category-A row says only that Capture Wallet already exposes the required
capability and evidence. It does not claim that an FCAF scenario has passed: the
harness and a real Wallet determine that outcome.
