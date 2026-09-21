# FCAF credential fixture catalogue

Every credential this service issues is reproducible: the claim values come from a named fixture,
there is no caller-supplied claim override, and the signing path is always the normal Credo one.
This file records what can be issued, how it is selected, and which FCAF relying-party tests it is
there to serve. Test identifiers are the file names on the `submitted` branch of
[eudi-doc-functional-conformance-assessment](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/tree/submitted/docs/fcaf/suts/wallet_solution/relying_party).

## Credentials

| Credential configuration | Format | Type | Holder binding | Signing |
| --- | --- | --- | --- | --- |
| `urn:eu.europa.ec.eudi:pid:1.sd-jwt.key-attestation-required` | `dc+sd-jwt` | `vct` `urn:eudi:pid:1` | Device-bound to the wallet's proof key; key attestation required | ES256, issuer certificate in `x5c` |
| `urn:eu.europa.ec.eudi:pid:1.mdoc.key-attestation-required` | `mso_mdoc` | doctype `eu.europa.ec.eudi.pid.1` | Device-bound; key attestation required | ES256, issuer certificate in the MSO |
| `urn:credimi:degree:1.sd-jwt.key-attestation-required` | `dc+sd-jwt` | `vct` `urn:credimi:degree:1` | Device-bound; key attestation required | ES256, issuer certificate in `x5c` |
| `urn:eu.europa.ec.eudi:pid:1.sd-jwt.jwt-proof` | `dc+sd-jwt` | `vct` `urn:eudi:pid:1` | Device-bound; plain JWT proof accepted | ES256, issuer certificate in `x5c` |
| `urn:eu.europa.ec.eudi:pid:1.mdoc.jwt-proof` | `mso_mdoc` | doctype `eu.europa.ec.eudi.pid.1` | Device-bound; plain JWT proof accepted | ES256, issuer certificate in the MSO |
| `urn:credimi:degree:1.sd-jwt.jwt-proof` | `dc+sd-jwt` | `vct` `urn:credimi:degree:1` | Device-bound; plain JWT proof accepted | ES256, issuer certificate in `x5c` |

The `key-attestation-required` configurations belong to issuer `eu-pid-device-bound`, the
`jwt-proof` ones to `eu-pid-jwt-proof-only`. No configuration issues a credential without
cryptographic holder binding; see the limitation at the end.

## PID claim-set fixtures

Selected with `fixture_id` on `POST /sessions`. Each is a fully valid PID that differs from the
baseline along exactly one value axis, so a DCQL query constraining that axis matches the baseline
and withholds the fixture. Each carries a distinct `document_number`, so two credentials are never
byte-identical. Applies to both the SD-JWT VC and mdoc PID configurations.

| `fixture_id` | Axis | Claim values | Serves |
| --- | --- | --- | --- |
| `pid_default` | — | Mario Rossi, Roma, `age_over_18: true`, `nationalities: ["IT"]`, `date_of_expiry: 2031-01-01` | Baseline for every value-matching test |
| `pid_person_b` | Distinct identity | Giulia Bianchi, Milano, `1985-07-14` | `WS_RP_IA_MainInteraction__040`, `__041`, `WS_RP_MS_ProtocolMessages__013`, `WS_RP_MS_CredentialFormats__041` |
| `pid_under_18` | Boolean constraint | `age_over_18: false`, `birthdate: 2012-03-04` | `WS_RP_IA_MainInteraction__032`, age axis of `__033` |
| `pid_family_name_uppercase` | Letter case | `family_name: "ROSSI"` | Case axis of `WS_RP_IA_MainInteraction__033` |
| `pid_family_name_trailing_space` | Whitespace | `family_name: "Rossi "` | Whitespace axis of `WS_RP_IA_MainInteraction__033` |
| `pid_locality_diacritics` | Diacritics, present | Locality `"München"` | Encoding axis of `WS_RP_IA_MainInteraction__033` |
| `pid_locality_no_diacritics` | Diacritics, absent | Locality `"Munchen"` | Encoding axis of `WS_RP_IA_MainInteraction__033` |
| `pid_multiple_nationalities` | Array cardinality | `nationalities: ["FR", "DE"]` | Array axis of `WS_RP_IA_MainInteraction__033` |
| `pid_expiry_2032` | Upper bound | `date_of_expiry: "2032-01-01"` | Expiry-boundary axis of `WS_RP_IA_MainInteraction__033` |

The PID attribute `age_over_18` exists in both encodings so a DCQL query can constrain it.

`WS_RP_IA_MainInteraction__033` also has a numeric data-type axis, a float where an integer is
expected. Neither the PID nor the degree credential carries a numeric claim, so no fixture covers
it; a credential type with a numeric attribute would have to be added first.

To give a wallet several credentials of the same type, issue one session per fixture.

## Status-list fixtures

`status_list_enabled` allocates a real reference from the configured Status List service.
`status_reference` then shapes the `status` claim of an SD-JWT VC; anything other than `valid`
requires `FCAF_SCENARIOS_ENABLED` and `status_list_enabled: true`.

| Configuration | Issued `status` | Serves |
| --- | --- | --- |
| `status_list_enabled: false` | claim absent | `WS_RP_MS_Metadata__082` |
| `status_reference: "valid"` | `{"status_list":{"uri","idx"}}` | `WS_RP_MS_CredentialFormats__029`, `__030`, `__031`, `__044`, `WS_RP_MS_Metadata__081`, `__083`, `__085`, `__088` |
| `status_without_status_list` | `{}` | `WS_RP_MS_Metadata__084` |
| `negative_index` | `idx: -1` | `WS_RP_MS_Metadata__086` |
| `missing_index` | only `uri` | `WS_RP_MS_Metadata__087` |
| `malformed_uri` | unparseable `uri` | `WS_RP_MS_Metadata__089` |
| `missing_uri` | only `idx` | `WS_RP_MS_Metadata__090` |
| mdoc configuration with `status_list_enabled: true` | valid COSE status at CBOR label 65535 | `WS_RP_MS_CredentialFormats__032`, `__033`, `WS_RP_MS_Metadata__091`, `__093`, `__095`, `__098`, `__101`, `__103` |

## Degree credential structure

The degree SD-JWT VC carries the exact claim structure the textual-encoding cases describe:
`name`, an `address` object, a `degrees` array of objects including one without `type`, a nested
`academic_programmes` array, and a `nationalities` array. Object and array interiors are
individually disclosable, so a wallet can reveal `address.locality` alone, or `degrees[0..1].type`
while withholding `degrees[2].university`. It supports DCQL claim paths such as
`["degrees", null, "type"]` and `["academic_programmes", null, 1]`.

Serves `WS_RP_SH_Encoding_TextualEncoding002` and `WS_RP_SH_Encoding_TextualEncoding003`. No
issuer change was needed for these; the structure is asserted in `tests/degree-credential.test.ts`.

## Request-signing and certificate fixtures

Selected with `request_behavior` on `POST /openid4vp/sessions`, gated by `FCAF_SCENARIOS_ENABLED`.
These are verifier-side request fixtures rather than credential fixtures, and are listed here so
the whole set is in one place.

| Control | Effect | Serves |
| --- | --- | --- |
| `signature: "corrupt"` | Signature does not verify | `WS_RP_SM_RpIntegrity__027` |
| `signing_key: "unrelated"` | Signed by a key that is not the certificate's or the DID's | `WS_RP_MS_Metadata__132`, `WS_RP_SM_RpIntegrity__015`, `WS_RP_SM_RpIntegrity__007` (with `client_id_scheme: "decentralized_identifier"`) |
| `certificate_chain: "unrelated_self_signed"` | Self-signed leaf for `unrelated-verifier.invalid` | `WS_RP_SM_RpIntegrity__026` |
| `certificate_chain: "untrusted_root"` | `[leaf, generated root]` | `WS_RP_SM_RpIntegrity__017`, `__019` |
| `certificate_chain: "incomplete_chain"` | `[leaf]` with its issuer absent | `WS_RP_SM_RpIntegrity__017`, `__019` |

Three more cases need no new control, because the mechanisms from Phase 2 already express them:

| Case | How |
| --- | --- |
| `x5c` header missing — `WS_RP_SM_RpIntegrity__014` | `request_mutation.request_object_header.unset: ["/x5c"]` |
| Client Identifier does not match the leaf hash — `WS_RP_MS_Metadata__130` | `request_mutation.request_object.set: {"/client_id": "x509_hash:…"}` |
| DNS name does not match the certificate SAN — `WS_RP_MS_Metadata__126` | `request_mutation.request_object.set` on `/client_id` |

The happy paths `WS_RP_MS_Metadata__129` and `__131` are the service's default behaviour with the
`x509_hash` prefix and need no fixture.

## Reference-wallet compatibility

Not established here. Every fixture above is verified against the credential this service actually
issues, in `tests/pid-fixtures.test.ts`, `tests/status-reference-fixtures.test.ts`, and
`tests/degree-credential.test.ts`. Whether a given reference wallet stores, selects, or rejects
one is a wallet-profile question that the FCAF harness answers by running the test.

## Fixtures that are not available

| Requirement | Blocked by |
| --- | --- |
| A credential without cryptographic holder binding — `WS_RP_IA_MainInteraction__006`, `__008`, `__010`, `WS_RP_MS_CredentialFormats__046` | [credo-ts#2936](https://github.com/openwallet-foundation/credo-ts/pull/2936) |
| Malformed COSE status structures — `WS_RP_MS_Metadata__092`, `__094`, `__096`, `__097`, `__099`, `__100`, `__102` | `@owf/token-status-list` requires a non-negative integer `idx` and a string `uri`; producing these needs a non-Credo COSE path, which `AGENTS.md` puts behind explicit approval |
| A presentation in SD-JWT VC JSON serialization — `WS_RP_MS_CredentialFormats__048` | Compact serialization only, on both the issuing and the verifying side |
| A numeric data-type mismatch — the `kg` axis of `WS_RP_IA_MainInteraction__033` | No issued credential carries a numeric claim |
| A wallet-accepted `x509_san_dns` request — `WS_RP_MS_Metadata__125`, `__127`, `__128` | The EUDI service-provider registry does not issue a certificate with a `dNSName` SAN, so a registry-trusted request cannot use that prefix |
| The wallet's configured trust anchor inside `x5c` — `WS_RP_SM_RpIntegrity__025` | `untrusted_root` includes the generated chain's own root, not the anchor the wallet trusts, which this service does not hold |
| RS384 or PS384 signed requests — `WS_RP_SM_RpIntegrity__032`, `WS_RP_SM_RpIntegrity_CryptographicSignature_002` | The KMS backend generates EC keys only, and an RSA certificate would need a non-Credo path; signing with an RSA key under the existing certificate would add a second defect |
| COSE algorithm identifiers −7 versus −9 — `WS_RP_SM_RpIntegrity__033`, `__034`, `CryptographicSignature_003`, `_004` | Both describe ECDSA P-256 with SHA-256, which a JOSE `alg` header expresses only as `ES256`; the COSE identifier distinction is not expressible in a JAR request object |
| An encrypted Request Object — `WS_RP_IA_MainInteraction__024` | Request Object encryption is not implemented; the wallet-metadata cases `WS_RP_MS_Metadata__134`, `__136`, `__137` need only the captured `wallet_metadata`, and `__135` is the service's current unencrypted behaviour |
