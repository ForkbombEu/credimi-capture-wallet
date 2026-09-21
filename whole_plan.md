# FCAF Coverage Improvement — Complete Implementation Plan

## 1. Objective

Improve the FCAF (Functional Conformance Assessment Framework) test coverage of our OpenID4VP implementation.

This plan covers one repository:
https://github.com/ForkbombEu/credimi-capture-wallet

It owns the verifier and the issuer: session creation, Authorization Request construction and signing, Request URI delivery, response verification, evidence capture, credential issuance, and credential fixtures.

The FCAF harness in https://github.com/ForkbombEu/credimi owns the test definitions, scenario generation, assertions, evidence processing, and `ASSERTION_REVIEW_BACKLOG.md`. That work is **out of scope here**. This plan reads the backlog to learn which verifier and issuer capabilities are missing, and delivers those capabilities plus the evidence the assertions need. It does not write test definitions or assertions, and it does not commit to that repository.

`pkg/fcaf/CAPTURE_WALLET_API.md` in the harness repository mirrors the contract owned here by `CAPTURE_WALLET_API.md`. When the contract changes here, flag the mirror for update; do not edit it from this repository.

### FCAF source of truth

Use the `submitted` branch of the upstream repository, never the rendered documentation site:

https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/tree/submitted/docs/fcaf/suts/wallet_solution/relying_party

Each test case is one Markdown file whose name is the test identifier, for example `Interaction/ProtocolFlow/WS_RP_IA_ProtocolFlow__003b_UF.md`. That branch currently holds **621** relying-party test files, which matches the backlog's recorded baseline of 621 upstream source tests.

The rendered site at `conformance.eudi.dev` is a lossy view of the same content: it exposes roughly 532 distinct test anchors and normalises identifiers, collapsing `WS_RP_IA_ProtocolFlow__003b_UF` to a single-underscore form and dropping others. Resolving an identifier against the site produces false "does not exist" results. Do not use it to decide whether a test exists.

Read the relevant test files and inspect the current implementation before making changes.

The objective is not simply to increase the number of test definitions. The goal is to make additional FCAF scenarios executable and provide sufficient evidence to evaluate their assertions.

Distinguish carefully between:

1. Missing verifier functionality.
2. Missing issuer or credential-fixture functionality.
3. Missing FCAF test definitions.
4. Incomplete or incorrect FCAF assertions.
5. Missing reference-Wallet capabilities.
6. Missing infrastructure or external trust configuration.

Do not implement verifier functionality when the test is already executable using the existing API.

Do not implement functionality that belongs to the issuer, reference Wallet, or FCAF harness inside the verifier.

### 1.1 Test identifier convention

A test identifier is the file name on the `submitted` branch, verbatim, including its double underscore before the number and any `_UF` suffix: `WS_RP_IA_MainInteraction__006`, `WS_RP_IA_ProtocolFlow__003b_UF`, `WS_RP_SM_TrustMechanisms__101b_UF`. The `WS_RP_SH_*` and `WS_RP_SM_RpIntegrity_CryptographicSignature_*` families use a single underscore before the number; that is also what their file names say.

Every identifier referenced in this document has been checked against the `submitted` branch and exists there verbatim, with one exception: section 5.8 writes `WS_RP_SM_TrustMechanisms__002` through `__015`, and `__014` does not exist. Ranges are unsafe in general — enumerate identifiers instead of writing spans, and validate any list mechanically against the branch's file names rather than by eye.


---

## 2. Out of scope

**DC API transport.** `response_mode=dc_api` and `response_mode=dc_api.jwt` are already implemented, documented, and covered by HTTP-level tests in this repository, together with the presentation page at `/ui/openid4vp/sessions/{sessionId}/dc_api_presentation`, origin-bound verification, and invocation-outcome capture. No DC API implementation work remains, so this plan contains none. Leave that flow alone: do not reimplement the transport, add a `transport` parameter, rename or duplicate the `deeplink` field, redesign the presentation page, or add a second DC API session-creation endpoint. Section 3.2 still applies to it — any new scenario mechanism must not weaken it.

**FCAF definitions, assertions, and execution.** Writing test definitions, generating scenarios, evaluating assertions, driving a browser and a reference Wallet, and updating `ASSERTION_REVIEW_BACKLOG.md` all belong to the harness repository. This plan stops at the capability and the evidence: for each missing capability it delivers the verifier or issuer behaviour plus a capture field the harness can assert on.

**Reference-Wallet and external trust infrastructure.** Wallet profiles, wallet capabilities, trusted lists, federation authorities, and attestation issuers are external dependencies. This plan prepares the fixtures the verifier must present and records what remains blocked; it does not stand up that infrastructure.

---

## 3. Repository requirements and implementation principles

Read the current `AGENTS.md` before starting.

Follow its requirements throughout the implementation.

In particular:

### 3.1 Use Credo-TS

Prefer the existing Credo-TS integration for OpenID4VP, OpenID4VCI, credential generation, request signing, response verification, and related cryptographic functionality.

Before implementing any feature, inspect the installed Credo-TS version and determine whether it already supports the required behavior.

Do not implement an independent protocol or cryptographic engine when Credo provides the necessary functionality.

If a required feature is unsupported by Credo, document the exact limitation and follow the approval requirements in `AGENTS.md` before introducing an alternative.

### 3.2 Preserve production behavior

FCAF testing requires intentionally malformed requests, invalid certificates, conflicting parameters, incorrect signatures, and unexpected HTTP responses.

These must not weaken normal verifier behavior.

Introduce isolated, explicitly enabled FCAF scenarios where necessary.

Normal sessions must continue enforcing the existing protocol, cryptographic, and session-validation requirements.

Do not introduce global options that disable signature verification, nonce validation, audience validation, holder binding, or certificate verification.

### 3.3 Preserve evidence

Existing session capture functionality must remain available.

When implementing a negative scenario, preserve the actual request and response exchanged with the Wallet.

Never replace captured evidence with the expected value of the test.

Keep raw transport evidence separate from decoded or normalized representations.

If a verifier response is intentionally modified for an FCAF scenario, preserve both the actual verification outcome and the HTTP response delivered to the Wallet.

### 3.4 Avoid unnecessary API changes

Before introducing a new public API parameter, determine whether the required scenario can be generated using the existing API.

If a new parameter is required, make it narrowly scoped, typed, documented, and backward compatible.

Malformed protocol material must never travel through the ordinary session-creation path unnoticed. Put it behind one explicitly enabled input, typed and documented, and record in the capture that it was used — see 2.1 for the shape and its invariants.

### 3.5 Development workflow

Use Graft as required by `AGENTS.md` to identify the relevant implementation paths before editing.

Use strict TypeScript and follow the existing repository architecture.

Keep each implementation task focused.

Add unit tests and HTTP-level integration tests where appropriate. For a change to a public endpoint, protocol flow, metadata, or security boundary, `AGENTS.md` requires a test that exercises the actual HTTP contract, not only the lower-level logic.

In `credimi-capture-wallet` the required commands are `pnpm test`, `pnpm build`, and `pnpm lint`. `pnpm lint` currently reports pre-existing errors in `.claude/` and `graft/.cache/` files that are unrelated to source; scope the check to `src` and `tests` when validating a change, and do not reformat those files as a side effect — `pnpm format` will otherwise touch them.

Any command a task depends on must be declared in `mise.toml`, which `AGENTS.md` treats as a hard requirement. It currently declares only `node`, `pnpm`, and `task`. Add anything a new fixture, scenario, or validation step needs in the same change.

Update the API documentation whenever the public contract changes: `src/openapi.ts`, `README.md`, and `CAPTURE_WALLET_API.md`. Flag the harness's `pkg/fcaf` mirror for update instead of editing it from here.

Commit each independently completed task, following the repository's instructions.

Do not push or deploy unless explicitly requested.

---

# PHASE 0 — Inventory the capabilities the backlog actually needs

## Goal

Establish the actual remaining work in this repository before implementing new features.

The backlog records a baseline of 621 upstream source tests and 584 matching Credimi definitions. The upstream count matches the `submitted` branch exactly; the definition count belongs to the harness repository and is not verified here.

The backlog was prepared against an earlier version of this repository and still lists DC API as unavailable. The current repository is the implementation baseline.

This phase produces no verifier code. Its output is the list of capabilities the later phases implement.

## Tasks

### 0.1 Inspect the repository

Read, in this repository:

* `AGENTS.md`
* `CAPTURE_WALLET_API.md` and `src/openapi.ts` for the current public contract.
* `src/server.ts` for the OpenID4VP and OpenID4VCI routes and their input validation.
* `src/credo-openid4vp.ts`, `src/openid4vp.ts` for request construction, signing, and delivery.
* `src/openid4vp-validation.ts` for the repository's own presentation validation.
* `src/state.ts` and `src/types.ts` for the capture model.
* `src/configurations/` for issuer configurations and credential fixtures.
* `tests/` for the existing HTTP-level coverage and the conventions to follow.

Read, in the harness repository, as input only: `ASSERTION_REVIEW_BACKLOG.md` and `pkg/fcaf/CAPTURE_WALLET_API.md`.

Inspect this repository's test commands and validation requirements.

### 0.2 Resolve each backlog entry against the upstream source

Use the `submitted` branch named in section 1. For each backlog entry, identify:

* The test identifier, verbatim as the upstream file name.
* The objective and expected results, read from the test file rather than from the backlog summary.
* The request, response, signing, metadata, and credential material the verifier or issuer must produce.
* The evidence each assertion needs, expressed as fields of the session capture or the issued credential.
* Which of those the current implementation already produces.
* The actual missing capability in this repository, or the external dependency that blocks it.

Validate identifiers mechanically, not by eye: list the `.md` file names under the branch's `relying_party` tree and assert that every backlog entry matches one verbatim. Report entries that match none.

An identifier that no longer exists is a finding, not a typo to fix silently: upstream may have renamed, split, or withdrawn the test. Do not silently merge different test cases or drop tests because their identifiers differ.

### 0.3 Classify each entry by what this repository owes it

Use these categories:

**A — Already supported**

The required request, response, or credential can already be produced with the current API, and the capture already holds the evidence the assertions need. Nothing is owed here.

**B — Missing verifier scenario control**

The test requires a specific request, response, signing, delivery, or metadata variation that cannot currently be generated.

**C — Missing credential or issuer fixture**

The test requires credentials or issuer behavior that the current issuer cannot produce.

**D — Missing reference-Wallet capability**

The verifier can generate the scenario, but the selected reference Wallet cannot execute its required behavior or does not have the necessary configuration.

**E — Missing external infrastructure or trust configuration**

The test requires certificate chains, trusted lists, federation infrastructure, verifier attestations, WRPAC, or other external fixtures.

**F — Unsupported or inapplicable scenario**

The source test's applicability requirements cannot be satisfied by the selected test profile.

Document the exact reason and do not count it as completed coverage.

A test may have multiple dependencies. Record all of them.

### 0.4 Separate what this repository can close

Categories B and C are this plan's work. Categories A, D, E, and F are not: record them, name the owner, and stop.

For every entry, state the capability in terms of observable behaviour — "the signed Request Object must omit `response_uri`", "the issued credential must carry a status list with a negative index" — not in terms of a test name. Capabilities, not tests, are what the later phases implement, and several tests usually share one.

## Deliverable

A capability matrix committed in this repository, in a machine-diffable form — one row per upstream test, fixed columns, stable ordering — so later phases can be measured by diffing it rather than by re-reading prose. Columns:

* Upstream test identifier, verbatim.
* Category from 0.3, with every applicable dependency recorded.
* The capability this repository owes, stated as observable behaviour, or none.
* The single phase that owns that capability. A test may be referenced by several phases, but exactly one owns it; later references are cross-references. Without this rule two workstreams both claim the same work.
* Whether the capability exists, and whether the evidence the assertions need is present — two separate columns, never collapsed into one status.
* The blocking dependency and its owner, for anything outside this repository.

Updating `ASSERTION_REVIEW_BACKLOG.md` from this matrix happens in the harness repository and is out of scope, but the matrix must carry everything that update needs.

---

# PHASE 1 — Close the gaps that need no new verifier capability

## Goal

Establish which category-A entries are genuinely already supported, and fix the ones that only look supported.

This phase writes little or no verifier code. Its value is evidence: for each entry it either confirms that the current API and capture already satisfy the source test — which the harness can then assert against — or it demotes the entry to category B with a concrete, named gap.

DC API scenarios are out of scope; see section 2.

## 1.1 Request URI and request-delivery scenarios

Review the current support for:

* `request_delivery=by_reference`
* `request_delivery=by_value`
* `request_delivery=plain`
* GET Request URI retrieval.
* POST Request URI retrieval.

Review relevant tests including:

* `WS_RP_IA_Supportive__002`
* `WS_RP_MS_ProtocolMessages__011`
* `WS_RP_IA_ProtocolFlow__002d`

For each test, distinguish missing verifier behavior from missing Wallet-profile support.

If the current API already generates the required request, record it as supported with the evidence fields rather than introducing another delivery mechanism.

## 1.2 Presentation-response capture

Review:

* `WS_RP_MS_ProtocolMessages__132`
* Applicable direct-post response-handling tests.
* Existing `direct_post.jwt` decryption and response capture.

Determine whether the current session capture preserves:

* The raw HTTP request from the Wallet.
* The encrypted Authorization Response.
* The decrypted Authorization Response.
* The decoded presentation.
* The actual verifier HTTP response.
* The final verification outcome.

For `WS_RP_MS_ProtocolMessages__132`, inspect the decrypted response and verify the required JSON serialization and parameter structure.

If the existing capture is sufficient, record it as supported and name the fields; the assertion itself is harness work.

If required information is lost during normalization, extend the capture model without removing existing fields.

## 1.3 Optional Authorization Request parameters

Review the current handling of:

* `scope`
* `transaction_data`
* `verifier_info`
* `client_metadata`
* `response_uri`
* `redirect_uri`
* `require_cryptographic_holder_binding`

Determine which backlog scenarios are already constructible.

Relevant tests include:

* `WS_RP_IA_MainInteraction__055`
* `WS_RP_IA_Metadata__010`
* `WS_RP_MS_ProtocolMessages__017`
* `WS_RP_MS_ProtocolMessages__018`
* `WS_RP_MS_ProtocolMessages__020`
* `WS_RP_MS_ProtocolMessages__034`
* `WS_RP_MS_ProtocolMessages__135`

Do not assume that accepting a parameter in the HTTP API guarantees its presence in the final signed Request Object.

Inspect the actual generated request and its captured evidence.

If an input is accepted but not propagated to the generated request, classify the problem as a concrete implementation gap.

## 1.4 Issuer and credential capabilities

Review current support for:

* SD-JWT VC issuance.
* mdoc issuance.
* Status-list allocation.
* Credential status references.
* Existing credential claim fixtures.
* Existing nested-array and textual-encoding fixtures.

Relevant tests include:

* `WS_RP_MS_CredentialFormats__031`
* `WS_RP_MS_CredentialFormats__044`
* `WS_RP_SH_Encoding_TextualEncoding_002`
* `WS_RP_SH_Encoding_TextualEncoding_003`

Verify the actual generated credential structure before deciding that issuer changes are needed.

## Deliverable

For every entry reviewed in this phase, one of two recorded outcomes:

* Confirmed supported — with the concrete request, response, or credential the current implementation produced, and the capture fields that hold the evidence the assertions need. State them by name, so the harness can be written against them without rediscovery.
* Demoted to category B or C — with the exact missing behaviour, which then belongs to a later phase.

A capability being present is not a passed test. This plan does not mark FCAF tests as passed; it reports capabilities and evidence.

---

# PHASE 2 — Controlled Request Object and Request URI scenarios

## Goal

Support tests requiring deliberately modified, malformed, or conflicting Authorization Requests.

The normal verifier must remain unchanged.

## 2.1 Introduce an isolated request-mutation mechanism

First inspect the existing session-creation and Request Object signing pipeline. In `credimi-capture-wallet` the relevant path is `POST /openid4vp/sessions` in `src/server.ts`, which validates the inputs and calls `createVpSession`, which calls `CredoOpenId4VpVerifier.createSession` in `src/credo-openid4vp.ts`. That method obtains Credo's request payload, applies the caller's overrides, and then re-signs it with `signPresentationAuthorizationRequest` from `src/openid4vp.ts`. The gap between Credo's payload and that re-signing is the narrowest extension point for a controlled modification, because Credo's own verification-session state stays intact while the material delivered to the Wallet changes.

The repository already has two precedents for an isolated, explicitly enabled test mode: the `permissive_capture` configuration flag and the `allow_undecryptable_response` request field, which publishes metadata the verifier cannot decrypt with and records a `vp_undecryptable_response_allowed` event. Follow that shape — a typed field plus a recorded capture event — rather than inventing a third convention.

Identify the smallest extension point that allows controlled modifications to the generated request, and record it explicitly so every mutation is applied at the same stage.

Do not use a registry of named scenario identifiers as the primary mechanism. A name like `missing_response_uri` puts per-test knowledge in this repository, so every upstream test that is added, renamed, or retuned becomes a code change and a release here — and this repository owns capabilities, not tests. Express the variation as data instead, and let the harness own which variation each test needs.

The repository already does exactly this, one level deep, for `client_metadata`: a supplied member wins, an omitted member keeps its generated value, and a member set to `null` is dropped from the wallet-facing request. Generalise that idea rather than inventing a parallel convention.

### Shape

A mutation is a set of targeted edits, not a flat key space. The target matters because several tests require the same parameter name to differ between the outer Authorization Request and the signed Request Object, so the two cannot share a namespace:

```json
{
  "response_mode": "direct_post.jwt",
  "request_delivery": "by_reference",
  "request_mutation": {
    "request_object": {
      "unset": ["/response_uri"],
      "set": { "/state": null }
    },
    "request_object_header": { "set": { "/typ": "jwt" } },
    "outer_request": { "set": { "/client_id": "x509_hash:other" } }
  }
}
```

Rules the shape must follow:

* **Use JSON Pointer (RFC 6901), not dotted paths.** Keys in this domain contain dots and plus signs: the mdoc namespace `eu.europa.ec.eudi.pid.1` and the credential format `dc+sd-jwt` are both object keys. A dotted path cannot address them unambiguously.
* **Keep `unset` and `set` separate.** Removing a parameter and sending it as an explicit `null` are different wire outcomes, and FCAF tests ask for both. The `client_metadata` merge conflates them; the mutation input must not.
* **Name the target explicitly** — outer request, Request Object payload, Request Object JOSE header — so a conflict between outer and signed values is expressible, and so the applicable construction stage follows from the target rather than from a convention.
* **Set arbitrary values, including wrong types and empty strings.** That is the point of expressing the variation as data: a new malformed-value test needs no code here.

### What data cannot express

A patch over the request payload covers 2.2 and 2.5 completely, and the claim part of 2.3. It cannot express the rest, so keep a small typed vocabulary for behaviours that are not payload values:

* An invalid signature — corrupting bytes after signing is not a payload edit.
* A Request URI response with a specific status, `Content-Type`, or body (2.6).
* A mismatched or omitted `wallet_nonce` (2.7), which is a decision taken at request time against an input the Wallet supplies, not a static value.
* A verifier HTTP response variation (Phase 3).
* Key and certificate material selection (5.1 to 5.3).

Those are a handful of named behaviours, and naming them is correct. They do not grow with the test catalogue; parameter variations do.

### Invariants

* **Apply mutations after all internal validation, at the last stage before signing and serialisation.** A mutated request must reach the Wallet; if the verifier rejects it first, the scenario is not executable. The endpoint must not re-validate the mutated payload.
* **Never let a mutation move the verifier's own session state.** Internal correlation — nonce, session identifier, expected origin, decryption key — must be derived from the pre-mutation payload. Mutating `nonce` or `client_id` only in the delivered request is a legitimate test; mutating what the verifier expects turns every later verification failure into noise.
* **State per mutation whether normal verification still applies**, and record that in the capture. This is the one thing the named-registry shape gave for free, and the mutation shape has to carry it deliberately.
* **Gate it explicitly.** An unrestricted mutation input on the public session endpoint is arbitrary malformed protocol material through the normal API, which `AGENTS.md` requires to be isolated and documented. Follow the `allow_undecryptable_response` precedent: an explicit opt-in, refused unless a configuration flag enables FCAF scenarios, and a recorded capture event naming what was mutated.
* **Capture the mutation and both payloads** — the request as generated and the request as delivered — so an assertion can prove the malformed material actually went out rather than assuming it.

## 2.2 Missing and invalid request parameters

Implement the required variations for:

* `WS_RP_IA_MainInteraction__053`
* `WS_RP_IA_MainInteraction__056`
* `WS_RP_MS_ProtocolMessages__033`
* `WS_RP_MS_ProtocolMessages__034`
* `WS_RP_MS_ProtocolMessages__039`
* `WS_RP_MS_ProtocolMessages__040`
* `WS_RP_MS_ProtocolMessages__041`

Required controls may include:

* Missing `response_uri`.
* Incorrect `response_uri`.
* Missing `redirect_uri`.
* Invalid or missing `state`.
* Invalid `redirect_uri:` client identifier.
* Controlled holder-binding parameters.

Generate the exact wire-level request required by each source test.

Keep the verifier's internal session-correlation state separate from the intentionally malformed parameter delivered to the Wallet.

## 2.3 JOSE header and Request Object claim variations

Review:

* `WS_RP_MS_ProtocolMessages__003_UF`
* `WS_RP_MS_ProtocolMessages__006`
* `WS_RP_MS_ProtocolMessages__007`
* `WS_RP_MS_ProtocolMessages__009`
* `WS_RP_MS_ProtocolMessages__010`
* `WS_RP_SM_RpIntegrity__013b_UF`
* `WS_RP_SM_RpIntegrity__027`

Required controls include:

* Missing JOSE `typ`.
* Invalid JOSE `typ`.
* Conflicting `client_id` and `iss`.
* Missing required `client_id`.
* Invalid Request Object signature.

Prefer the existing Credo signing path for normal signed requests.

For an intentionally invalid signature, corrupt the encoded signature after normal signing rather than signing differently. Two delivery paths carry the signed request and both must receive the corrupted value: `store.vpCredoAuthorizationRequestJwts`, which `GET` and `POST /openid4vp/sessions/{sessionId}/request` serve, and `dc_api_request.data.request` for DC API sessions. Note that `createSession` also assigns the re-signed JWT to Credo's `verificationSession.authorizationRequestJwt`; decide deliberately whether the corrupted value belongs there too, because that field feeds Credo's own session state.

Do not introduce another signing implementation merely to corrupt an otherwise valid signature.

Ensure the modified request can still be delivered to the Wallet.

If the verifier rejects the malformed material before the Wallet receives it, the test scenario is not yet executable.

## 2.4 Conflicting outer and signed parameters

Review:

* `WS_RP_MS_ProtocolMessages__049`
* `WS_RP_MS_ProtocolMessages__051`

These tests require independent control of parameters in the outer Authorization Request and the signed Request Object.

Introduce the smallest isolated mechanism allowing the test to create the required conflict.

Do not change normal request construction to generate conflicting parameters.

Capture both the outer request and the signed Request Object.

Assert their actual values before evaluating the Wallet's behavior.

## 2.5 Unknown Authorization Request parameters

Review:

* `WS_RP_MS_ProtocolMessages__016`
* `WS_RP_MS_ProtocolMessages__124`
* `WS_RP_MS_ProtocolMessages__128`

Determine whether the existing request-generation pipeline preserves unrecognized parameters.

If not, implement a controlled mechanism for adding an unrecognized parameter to the generated Authorization Request.

Ensure the parameter appears at the exact location required by the FCAF test.

Do not assume that a value supplied in `presentation_request` automatically appears in the final request.

## 2.6 Controlled Request URI responses

Review:

* `WS_RP_IA_Supportive__002`
* `WS_RP_MS_ProtocolMessages__043`
* `WS_RP_MS_ProtocolMessages__048`

Implement only the missing Request URI variations.

Potential scenarios include:

* Invalid Request URI.
* A Request URI endpoint returning the wrong Content-Type.
* A controlled HTTP Request URI endpoint, where the source test requires it.
* Other specifically defined negative retrieval behavior.

Use per-session behavior where possible.

Avoid global changes to the Request URI handlers.

Capture the actual HTTP response delivered to the Wallet.

## 2.7 Wallet nonce controls

Review:

* `WS_RP_MS_ProtocolMessages__046`
* `WS_RP_MS_Metadata__139`
* `WS_RP_MS_Metadata__140`

The normal case already works: `POST /openid4vp/sessions/{sessionId}/request` in `src/server.ts` reads `wallet_nonce`, merges it into the stored authorization request, re-signs, and serves the result. Only the two negative variants need the scenario mechanism.

The POST Request URI flow must support the required controlled nonce scenarios:

**Normal nonce**

Return the received `wallet_nonce` in the signed Request Object.

**Mismatched nonce**

Return a deliberately different nonce.

**Missing nonce**

Omit the nonce despite receiving it from the Wallet.

Preserve the normal nonce behavior for all ordinary sessions.

Capture:

* The original Wallet POST request.
* The received `wallet_nonce`.
* The returned signed Request Object.
* The actual nonce in the returned object.
* The subsequent Wallet outcome.

## Deliverable

An isolated Request Object and Request URI scenario mechanism that supports the missing test variations without modifying normal production behavior.

Add tests demonstrating that ordinary sessions are unaffected.

---

# PHASE 3 — Configurable verifier HTTP response scenarios

## Goal

Support FCAF tests requiring the verifier to return specific HTTP statuses, response bodies, or Content-Types after receiving an Authorization Response.

## 3.1 Inspect current response handling

Find the existing response-submission endpoints and HTTP response helper. In `credimi-capture-wallet` these are `POST /openid4vp/sessions/{sessionId}/response` and `POST /openid4vp/response` in `src/server.ts`, and the single HTTP boundary is `sendVpSubmissionResponse`, which already records the delivered status, redacted headers, and exact body in `raw.presentation_response_verifier_http`. Verification and evidence are written separately by `captureVpResponse`, so the invariant required in 3.3 is already structural: a test-selected status cannot alter `checks` unless the scenario mechanism is wired into the wrong function. Add the scenario hook inside `sendVpSubmissionResponse` and leave `captureVpResponse` alone.

Determine where the verifier:

1. Receives the Wallet response.
2. Performs response verification.
3. Stores presentation evidence.
4. Constructs the HTTP response returned to the Wallet.

Introduce a test-only response scenario mechanism at the HTTP response boundary.

Do not alter normal presentation verification merely to produce a test-specific HTTP response.

## 3.2 Required response scenarios

Review:

* `WS_RP_MS_ProtocolMessages__125`
* `WS_RP_MS_ProtocolMessages__126`
* `WS_RP_MS_ProtocolMessages__127`
* `WS_RP_MS_ProtocolMessages__128`
* `WS_RP_IA_MainInteraction__064`

Implement the exact response variations required by the source tests.

These include:

**HTTP 200 with plain-text body**

Return the required plain-text response instead of the normal JSON response.

**HTTP 400 with JSON body**

Return the required JSON error response.

**HTTP response with unknown parameter**

Add an unrecognized parameter to the verifier response.

**Unknown parameters in both request and response**

Combine the Request Object scenario mechanism from Phase 2 with the response scenario mechanism.

**Error response containing a redirect URI**

Generate the exact error response required by the corresponding FCAF source test.

Do not assume all error responses use the same schema. Follow each source test's requirements.

## 3.3 Evidence requirements

Capture:

* The Wallet's submitted Authorization Response.
* The actual verification outcome.
* The actual HTTP status returned.
* The actual Content-Type returned.
* The exact response body delivered to the Wallet.
* The subsequent Wallet behavior, where observable.

A test-selected HTTP 400 response must not automatically change the recorded cryptographic verification result.

Similarly, an HTTP 200 response must not cause a failed presentation to be recorded as successfully verified.

## Deliverable

Per-session configurable verifier HTTP response scenarios.

Preserve backward compatibility and the existing normal HTTP response contract.

---

# PHASE 4 — Additional issuer and credential fixtures

## Goal

Make the credential-dependent FCAF tests executable.

Keep issuer-specific functionality outside the verifier.

Use the existing OpenID4VCI issuer and credential-generation infrastructure wherever possible.

## 4.1 Multiple credentials of the same type

Review:

* `WS_RP_IA_MainInteraction__033`
* `WS_RP_IA_MainInteraction__040`
* `WS_RP_IA_MainInteraction__041`
* `WS_RP_MS_ProtocolMessages__013`
* `WS_RP_MS_CredentialFormats__041`

These tests require multiple credentials with the same type but distinct values.

Inspect the existing issuer configuration and credential fixture system. In `credimi-capture-wallet` each issuer is a directory under `src/configurations` — currently `eu-pid-device-bound` and `eu-pid-jwt-proof-only` — with shared claim data and encoders under `src/configurations/shared`, resolved through `src/configurations/registry.ts`. A `fixture_id` should resolve within that structure to a predefined claim set for an existing issuer configuration, rather than becoming a parallel fixture system beside it.

If necessary, introduce predefined test identities or fixture identifiers.

An illustrative issuer input is:

```json
{
  "fixture_id": "pid_person_b"
}
```

The issuer should resolve this identifier to a predefined claim set and issue the credential using its normal signing mechanism.

Avoid adding unrestricted claim overrides if predefined fixtures are sufficient.

The harness then needs to, outside this repository:

1. Issue the first credential.
2. Issue a second credential of the same required type with different claim values.
3. Ensure that the reference Wallet stores both.
4. Verify that both credentials remain available.
5. Execute the required presentation scenario.
6. Evaluate the Wallet's credential-selection behavior.

Do not mark the fixture ready merely because the issuer successfully returns two credentials.

## 4.2 Credentials without holder binding

Review:

* `WS_RP_IA_MainInteraction__006`
* `WS_RP_IA_MainInteraction__008`
* `WS_RP_IA_MainInteraction__010`
* `WS_RP_MS_CredentialFormats__046`

Determine the exact credential structure required by each source test.

Do not confuse:

* A credential without cryptographic holder binding.
* A device-bound credential presented without its binding proof.
* A presentation containing an invalid binding proof.

Investigate the installed Credo version and the reference Wallet's support for the required credential structure.

Implement issuer fixtures only for the missing supported variations.

## 4.3 Token Status List credential fixtures

Review:

* `WS_RP_MS_CredentialFormats__029` through `__033`
* `WS_RP_MS_CredentialFormats__044`
* `WS_RP_MS_Metadata__081` through `__103`

The current status-list allocation mechanism must be reused wherever it satisfies the source tests.

Determine which tests require:

* A valid status-list reference.
* A missing status claim.
* A missing `status_list` member.
* A controlled index.
* A negative or invalid index.
* A missing index.
* A controlled URI.
* An invalid URI.
* A missing URI.
* JOSE status-token encoding.
* COSE/CBOR status-token encoding.
* Specific CBOR labels or map structures.

Implement only the missing fixture controls.

Separate normal valid issuance from deliberately malformed credential issuance.

Do not introduce arbitrary malformed status-list data into normal production issuance.

For every fixture, ensure that the actual issued credential contains the intended structure.

A test requiring a CWT or mdoc credential must receive the appropriate format; do not substitute an SD-JWT VC simply because it supports status lists.

Verify the reference Wallet's support for each format.

## 4.4 Additional credential encodings

Review:

* `WS_RP_MS_CredentialFormats__048`
* `WS_RP_SH_Encoding_TextualEncoding_002`
* `WS_RP_SH_Encoding_TextualEncoding_003`

Inspect the current issuer implementation before creating new fixtures.

Determine whether the required JSON serialization or nested-array structures are already supported.

Add only the missing credential variations.

For tests requiring unsupported or intentionally unusual credential encodings, document the exact issuer and Wallet capabilities needed.

## 4.5 Additional claim-value fixtures

Review:

* `WS_RP_IA_MainInteraction__032`

This test requires a credential containing the specific over-18 claim value described by the source scenario.

Implement a predefined PID fixture with the required claim value if the existing issuer does not already support it.

Verify the actual issued credential before executing the Wallet interaction.

## Deliverable

A documented collection of reproducible credential fixtures, each identifying:

* Credential format.
* Credential type.
* Required claims.
* Holder-binding configuration.
* Status-list configuration.
* Signing configuration.
* Reference-Wallet compatibility.
* FCAF test IDs using the fixture.

Do not implement credential variations unrelated to the active backlog.

---

# PHASE 5 — Trust, identity, and cryptographic test fixtures

## Goal

Implement the missing trust and cryptographic scenarios that can be supported by the existing verifier architecture and available reference-Wallet profiles.

Treat these as separate workstreams.

Do not implement all trust mechanisms as one large change.

## 5.1 X.509 request and certificate scenarios

Review:

* `WS_RP_MS_Metadata__125` through `__132`, where applicable.
* `WS_RP_SM_RpIntegrity__014`
* `WS_RP_SM_RpIntegrity__015`
* `WS_RP_SM_RpIntegrity__017`
* `WS_RP_SM_RpIntegrity__019`
* `WS_RP_SM_RpIntegrity__025`
* `WS_RP_SM_RpIntegrity__026`

Inspect the existing `x509_san_dns` and `x509_hash` implementations.

Determine which scenarios can use the existing certificate configuration and which require new controlled fixtures.

Prepare only the certificate variations required by the source tests.

Potential fixtures include:

* A valid certificate with a matching DNS SAN.
* A certificate with a mismatching DNS SAN.
* A request signed by a key different from the certificate's public key.
* A missing or incomplete `x5c` chain.
* A certificate chain containing an inappropriate trust anchor.
* A self-signed certificate.
* An incorrect certificate hash.

Keep ordinary verifier certificates and production signing keys unchanged.

Ensure that intentionally invalid requests can reach the Wallet.

If a test is blocked because the current verifier certificate does not have the required DNS SAN, provide the appropriate test certificate before classifying the test as executable.

## 5.2 DID-based request scenarios

Review:

* `WS_RP_SM_RpIntegrity__007`

Determine whether the current DID configuration can produce the required mismatch between the Request Object signing key and the DID document's authorized verification methods.

Use an isolated DID document and test key configuration.

Do not modify the verifier's normal DID identity.

Preserve the actual DID document, Request Object, and Wallet outcome as test evidence.

## 5.3 Additional signing algorithms

Review:

* `WS_RP_SM_RpIntegrity_CryptographicSignature_002`
* `WS_RP_SM_RpIntegrity_CryptographicSignature_003`
* `WS_RP_SM_RpIntegrity_CryptographicSignature_004`
* `WS_RP_SM_RpIntegrity__032`
* `WS_RP_SM_RpIntegrity__033`
* `WS_RP_SM_RpIntegrity__034`

These tests require specific signature algorithms or signing formats, including RS384 and COSE variants.

First inspect the installed Credo-TS version.

Determine:

1. Whether the required format is supported.
2. Whether the required algorithm is supported.
3. Whether compatible signing keys can be configured.
4. Whether the selected reference Wallet supports the required request format.

Where Credo supports the functionality, add the necessary test-specific signing configuration.

Do not treat JOSE and COSE signatures as interchangeable.

If the required functionality is not supported by Credo, document the limitation and follow the repository's approval requirements before introducing an alternative implementation.

## 5.4 Encrypted Request Objects

Review:

* `WS_RP_IA_MainInteraction__024`
* `WS_RP_MS_Metadata__134`
* `WS_RP_MS_Metadata__135`
* `WS_RP_MS_Metadata__136`
* `WS_RP_MS_Metadata__137`

These tests concern Request Object encryption and encryption-related Wallet metadata.

This is separate from the already implemented `dc_api.jwt` encrypted Authorization Response.

Do not reimplement DC API or response encryption as part of this workstream.

Inspect the existing POST Request URI implementation.

Determine whether the reference Wallet provides encryption metadata and keys through the required mechanism.

Where supported, implement the missing Request Object encryption functionality using Credo.

Preserve the received Wallet metadata, selected encryption algorithm, returned Request Object, and actual Wallet outcome.

For negative scenarios, provide the exact encryption-related variation required by the source test.

## 5.5 Verifier attestation

Review:

* `WS_RP_SM_RpIntegrity__001`
* `WS_RP_SM_RpIntegrity__008` through `__012`
* `WS_RP_MS_Metadata__116` through `__124`

These tests require verifier-attestation functionality and controlled attestation fixtures.

Determine whether the selected Wallet profile supports verifier attestation and how its trust configuration is established.

Required fixtures may include:

* A valid verifier attestation.
* A trusted attestation issuer.
* An untrusted attestation issuer.
* An invalid attestation signature.
* A mismatching attestation subject.
* A mismatching confirmation key.
* Missing or mismatching redirect URI claims.
* Missing or incorrectly placed attestation metadata.

Reuse the existing request-generation and signing mechanisms where possible.

Do not implement a general attestation issuance service unless it is actually needed to produce the required fixtures.

## 5.6 WRPAC

Review:

* `WS_RP_SM_TrustMechanisms__101`
* `WS_RP_SM_TrustMechanisms__101b_UF`
* `WS_RP_SM_TrustMechanisms__101c_UF`

These tests require Wallet Relying Party Registration Certificate fixtures.

Do not treat an ordinary verifier X.509 certificate as automatically equivalent to WRPAC.

Determine the exact certificate structure and trust configuration required by the source tests.

Prepare:

* A valid WRPAC fixture.
* An invalid-signature WRPAC fixture.
* WRPAC fixtures with the required controlled organization mismatch.

Implement the necessary verifier integration only after confirming the reference Wallet can process this trust mechanism.

## 5.7 OpenID Federation

Review:

* `WS_RP_IA_Metadata__014`
* `WS_RP_MS_Metadata__112`
* `WS_RP_MS_Metadata__113`
* `WS_RP_MS_Metadata__114`
* `WS_RP_MS_Metadata__115`

Determine the exact OpenID Federation requirements of each source test.

Do not assume that supporting the `openid_federation:` client identifier prefix alone is sufficient.

The relevant tests may require:

* Valid federation entity statements.
* A resolvable trust chain.
* Trusted federation authorities.
* Invalid or untrusted trust chains.
* Metadata resolution.
* Conflicting metadata sources.

Check the selected Wallet profile before implementing the required federation infrastructure.

Where the test requires external infrastructure, prepare a minimal reproducible fixture rather than embedding federation behavior directly into the verifier.

## 5.8 ETSI trusted lists and certificate matching

Review:

* `WS_RP_MS_ProtocolMessages__095`
* `WS_RP_SM_TrustMechanisms__002` through `__015` — upstream has no `__014`, so enumerate the existing identifiers instead of relying on the range.
* `WS_RP_SM_TrustMechanisms__021`

These tests require certificate-chain, issuer-identification, or trusted-list fixtures.

Distinguish the following requirements:

**AKI certificate matching**

Provide credential and issuer certificate chains with the exact matching or mismatching Authority Key Identifier properties required by each test.

**Trusted-list matching**

Provide an ETSI trusted-list fixture containing the relevant trusted entity or issuer.

**Trusted-list non-matching**

Provide a credential or trusted-list configuration where the expected issuer is absent.

**Invalid trusted list**

Provide the specifically invalid structure or trust property required by the source test.

**List of Trusted Lists navigation**

Provide the necessary list references, trust infrastructure, and resolvable certificates.

Use the current verifier's existing DCQL support where possible.

Do not implement Wallet-side trusted-list resolution inside the verifier.

Verify that the reference Wallet supports the required trust mechanism and has been configured with the appropriate trust anchors or list references.

## Deliverable

A set of independent, reproducible trust and cryptographic fixture implementations.

For each workstream, document:

* Implemented capabilities.
* Required external infrastructure.
* Applicable reference-Wallet profile.
* Test cases unlocked.
* Tests that remain blocked.
* Evidence available for the assertions.

---

# PHASE 6 — Scope mapping, transaction data, and remaining protocol capabilities

## Goal

Address the remaining protocol and Wallet-profile-dependent tests not covered by the previous phases.

## 6.1 Scope-to-DCQL mapping

Review:

* `WS_RP_UC_Presentation__003`
* `WS_RP_MS_ProtocolMessages__020`
* `WS_RP_MS_ProtocolMessages__030`
* `WS_RP_MS_ProtocolMessages__141`

Determine whether the verifier currently supports the required scope values and their corresponding DCQL mappings.

Do not introduce an arbitrary scope value without defining its expected credential query.

Check whether the reference Wallet supports the same scope mapping.

If the required behavior is Wallet-side scope resolution rather than verifier-side request generation, classify it accordingly.

Implement verifier functionality only where the source test requires the verifier to produce a specific request.

## 6.2 Transaction data

Review:

* `WS_RP_MS_ProtocolMessages__017`
* `WS_RP_MS_ProtocolMessages__018`
* `WS_RP_MS_ProtocolMessages__135`
* `WS_RP_MS_ProtocolMessages__154` through `__159`

Inspect the current `transaction_data` implementation and generated Authorization Request.

Determine:

* Which transaction-data types are supported.
* Whether transaction data reaches the final Request Object.
* Which transaction-data hashes or presentation information can be captured.
* Which types are supported by the reference Wallet.

Do not implement an arbitrary transaction-data type merely to populate the request.

Where the source test requires Wallet support for a transaction-data type, classify the test as blocked until that capability is available.

Where the verifier can already generate the required request, the remaining work is the evidence capture, if anything; the assertion is harness work.

## 6.3 Device binding

Review:

* `WS_RP_SM_DeviceBinding__002` through `__006`

Inspect the source-test objectives individually.

Determine whether each test requires:

* A particular credential binding configuration.
* A specific presentation proof.
* A controlled invalid binding proof.
* A particular verifier request.
* A reference-Wallet capability.

Reuse the existing presentation-verification functionality.

Add issuer or credential fixtures where necessary.

Do not weaken holder-binding verification to make negative tests executable.

## 6.4 Cryptographic capability and hash-selection tests

Review:

* `WS_RP_SH_Cryptography_Encryption_002`
* `WS_RP_SH_Cryptography_CryptographicHash_006`
* `WS_RP_SH_Cryptography_CryptographicHash_007`
* `WS_RP_SH_Cryptography_CryptographicHash_008`
* `WS_RP_SH_Cryptography_CryptographicHash_010`

Determine the exact algorithm advertisement, negotiation, selection, or credential-fixture requirements.

Check whether the selected Wallet profile supports the alternative algorithms required by the source tests.

Do not implement new algorithms merely because they appear in the FCAF catalogue.

Only introduce additional verifier capability when the test is applicable and all other required preconditions can be established.

---

# PHASE 7 — Tests that remain blocked by external requirements

## Goal

Avoid introducing unnecessary verifier changes for scenarios that depend on unsupported Wallet behavior, external infrastructure, or unavailable fixtures.

Review these tests individually:

| Test                             | External dependency or investigation                                           |
| -------------------------------- | ------------------------------------------------------------------------------ |
| `WS_RP_IA_Engagement__001b`      | Wallet support for the required `eu-eaap://` invocation scheme                 |
| `WS_RP_IA_ProtocolFlow__002d`    | Reference-Wallet profile without POST Request URI support                      |
| `WS_RP_IA_Supportive__006`       | Controlled Wallet-device resource-exhaustion scenario                          |
| `WS_RP_MS_ProtocolMessages__151` | Required unsupported mdoc format and Wallet profile                            |
| `WS_RP_SM_IssuerIntegrity__012`  | Appropriate mdoc revocation fixture                                            |
| `WS_RP_IA_MainInteraction__046`  | Large credential/presentation fixture and URL-limit conditions                 |
| `WS_RP_IA_MainInteraction__060`  | Reassessment of exact source-test applicability and response-mode requirements |

Also review any tests from the previous phases that remain blocked by missing reference-Wallet capabilities.

Several tests appear in more than one phase of this plan, and those overlaps must be resolved by the owner column of the Phase 0 matrix before implementation starts, not during it. The known ones:

* `WS_RP_IA_ProtocolFlow__002d` — listed both in 1.1, as possibly already constructible, and in the table above as blocked by a Wallet profile without POST Request URI support. These cannot both be true. Resolve it first: verifier-side POST Request URI delivery already exists, so if this test is blocked it is blocked on the Wallet profile, and it belongs here rather than in Phase 1.
* `WS_RP_MS_ProtocolMessages__034` — listed in 1.3 as possibly constructible and in 2.2 as needing a new control. Determine which parameter variation the source test requires before assigning it.
* `WS_RP_MS_ProtocolMessages__020` — listed in 1.3 and 6.1.
* `WS_RP_MS_ProtocolMessages__017`, `__018`, `__135` — listed in 1.3 and 6.2.
* `WS_RP_MS_ProtocolMessages__128` — listed in 2.5 and 3.2. This one is genuinely both: it needs the request and response scenario mechanisms together, as 3.2 already states. Record one owner and the dependency.
* `WS_RP_IA_Supportive__002` — listed in 1.1 and 2.6.
* `WS_RP_SH_Encoding_TextualEncoding_002` and `_003` — listed in 1.4 and 4.4.

For each blocked test, document:

1. The exact missing precondition.
2. Whether it belongs to the verifier, issuer, Wallet, test harness, or infrastructure.
3. Whether the missing capability can be implemented within this repository.
4. Whether another reference-Wallet profile or test fixture is required.
5. What would make the test executable.

Do not mark a test as completed because the current Wallet does not implement the behavior being tested.

For negative tests, ensure that the Wallet actually receives the intended malformed request before interpreting its behavior.

Distinguish a protocol-level rejection from browser invocation failure, unsupported Wallet functionality, network failure, or a test-harness timeout.

---

# 8. Execution order and implementation strategy

Implement the phases in the following order:

1. Inventory the capabilities the backlog needs and classify every entry.
2. Confirm or demote the entries that need no new capability.
3. Implement controlled Request Object and Request URI scenarios.
4. Implement configurable verifier HTTP response scenarios.
5. Extend issuer and credential fixtures.
6. Implement independent trust and cryptographic fixtures.
7. Complete scope, transaction-data, device-binding, and other applicable protocol scenarios.
8. Reassess externally blocked tests.

Do not treat these as one large coding task.

After Phase 0, group test cases by shared missing capability.

For example, implement one controlled Request Object mechanism that supports the necessary variants rather than creating a different API or handler for every individual FCAF test.

Similarly, use a shared response-scenario mechanism for the HTTP response tests.

Do not overgeneralize the scenario system. Its scope must remain limited to actual FCAF requirements.

Where one workstream depends on another, implement and validate the dependency first.

For example, a test requiring an unknown request parameter and a modified verifier response needs both the Request Object scenario and HTTP response scenario mechanisms.

Where an entry depends only on harness-side definitions or assertions, it is out of scope here: record it as category A with its evidence fields and move on.

---

# 9. Requirements for every implementation task

Before implementing a capability:

1. Read the relevant upstream FCAF source tests from the `submitted` branch.
2. Read the backlog entry and the harness's existing definition, as input, to learn which evidence the assertions need.
3. Inspect the actual verifier and issuer implementation in this repository.
4. Use Graft to identify the relevant code paths and dependencies.
5. Verify the installed Credo-TS capabilities.
6. Identify the smallest change that satisfies the source-test requirements.

For each implementation task, produce:

## A. Capability and coverage

Name the capability the change adds, as observable behaviour, and list the test identifiers that depend on it.

Distinguish tests the capability unblocks in this repository from tests that still need fixtures, Wallet capabilities, or harness work.

## B. Current limitation

Describe the current code path and explain precisely why the existing implementation cannot generate or evaluate the required scenario.

Do not rely exclusively on the backlog's original classification.

## C. Implementation

Identify the files and modules to modify.

Explain any public API changes, internal scenario configuration, fixture additions, or evidence-capture changes.

Reuse existing functionality whenever possible.

## D. Tests

Add the necessary unit and integration tests.

Verify both the intended FCAF scenario and normal production behavior.

For negative scenarios, verify that the intentionally malformed material is actually delivered to the Wallet.

## E. Evidence

Name the capture fields, credential members, or HTTP artefacts that carry the evidence for each upstream assertion, and show their actual values from a run.

Preserve the observed value: never write a scenario's expected value into the capture in place of what was actually exchanged.

Implementing the assertions themselves is harness work and out of scope.

## F. Documentation

Update `src/openapi.ts`, `README.md`, and `CAPTURE_WALLET_API.md` whenever the public contract changes, and flag the harness's mirror for update.

Document any remaining unsupported capability, and record the new capability in the Phase 0 matrix.

## G. Validation

Run the applicable repository validation commands.

Report the results and any failures.

Do not claim that an FCAF test passes. This repository delivers capabilities and evidence; whether a test passes is decided by the harness after a real Wallet interaction.

Commit each completed implementation task according to `AGENTS.md`.

---

# 10. Definition of done for this repository

A capability is complete only when all the following hold:

* It was derived from the upstream source test on the `submitted` branch, not from the backlog summary alone.
* The verifier produces the exact required Authorization Request, Request URI response, or HTTP response, verified at the HTTP level.
* The required credential fixture is issued with the intended structure, verified on the actual issued credential.
* The evidence every upstream assertion needs is present in the capture and named in the handoff.
* Existing protocol validation and normal service behaviour remain intact, with tests proving ordinary sessions are unaffected.
* A verifier or harness failure cannot be mistaken for a Wallet result in the recorded evidence.

Track capability presence and evidence presence separately, and keep both separate from any FCAF test outcome.

Do not equate an implemented verifier feature with a passed FCAF test.

---

# 11. Expected final deliverables

The overall implementation should produce, in this repository:

1. A capability matrix covering every backlog entry, with its category, the capability owed, the owning phase, and the blocking dependency where the work lies elsewhere.

2. A narrowly scoped Request Object and Request URI scenario mechanism for the required negative and boundary tests.

3. A configurable verifier HTTP response mechanism for the required response-handling tests.

4. Additional credential and issuer fixtures for tests requiring specific credential values, formats, status references, or binding properties.

5. Additional trust and cryptographic fixtures for applicable tests, without replacing the existing Credo-TS architecture.

6. For each of the above, the capture fields or credential members that carry the evidence, named so the harness can be written against them.

7. A documented list of entries that remain blocked by reference-Wallet capabilities, external infrastructure, or harness work, with the owner of each.

8. Validation results demonstrating that new functionality does not break existing behaviour, including the DC API flow.

---

# 12. Start implementation

Begin with Phase 0.

Inspect this repository, `AGENTS.md`, the backlog, and the actual FCAF source tests on the `submitted` branch.

Produce the capability matrix showing what this repository already satisfies and what it owes.

Then proceed to Phase 1 and settle the entries that need no new capability, recording their evidence fields.

Continue through the remaining phases in dependency order, implementing the smallest independent workstreams first.

Do not stop after producing another high-level plan. The purpose of this instruction is to carry out the implementation work.

Do not ask for confirmation between ordinary implementation tasks. Follow the repository's existing requirements for cases where explicit approval is necessary, particularly when a non-Credo cryptographic implementation would otherwise be introduced.

Preserve existing functionality, especially the newly implemented `dc_api` and `dc_api.jwt` flows.

Do not push or deploy unless explicitly requested.
