# Issuer Catalogue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show every configured issuer below the launcher controls with its conformance explanation and three public links.

**Architecture:** Keep the change inside the server-rendered launcher. `indexPage` will pass its existing resolved issuer groups to focused HTML helpers, so names, descriptions, warnings, issuer identifiers, and discovery URLs continue to come from the issuer registry rather than duplicated UI constants.

**Tech Stack:** TypeScript, Express-rendered HTML, inline CSS using the existing Credimi/Atlas design tokens, Vitest, and Supertest.

## Global Constraints

- Preserve all OpenID4VCI behavior, endpoint paths, metadata, and response shapes.
- Use the existing resolved issuer configuration; do not duplicate protocol URLs or conformance descriptions.
- Show only “Issuer,” “Credential issuer well-known,” and “Authorization server well-known.”
- Do not show the chained auto-approving authorization server.
- Escape every rendered value and use `target="_blank" rel="noreferrer"` on issuer links.
- Preserve unrelated files and changes, including untracked repository-root documents.
- Do not change dependencies or generated state under `data/`.

---

### Task 1: Render and verify the launcher issuer catalogue

**Files:**

- Modify: `src/ui.ts:13-96`
- Modify: `src/ui.ts:177-205`
- Modify: `src/ui.ts:385-493`
- Modify: `tests/server.test.ts:502-558`
- Create: `tests/ui.test.ts`
- Include in final task commit: `docs/superpowers/plans/2026-07-30-issuer-catalogue.md`

**Interfaces:**

- Consumes: `indexPage(groups: readonly IssuerCredentialGroup[]): string`
- Consumes: `ResolvedIssuerConfiguration.display`, `.compliance`, `.issuerIdentifier`, `.issuerMetadataUrl`, and `.authorizationServerMetadataUrl`
- Produces: `issuerCatalogueHtml(groups: readonly IssuerCredentialGroup[]): string`
- Produces: `issuerCardHtml(group: IssuerCredentialGroup): string`
- Produces: `issuerLinkHtml(label: string, href: string): string`

- [ ] **Step 1: Write the failing homepage and empty-state tests**

Extend the existing launcher test in `tests/server.test.ts` after the credential
`optgroup` assertions:

```ts
expect(response.text).toContain(
  '<section class="issuer-catalogue" aria-labelledby="issuer-catalogue-title">',
);
expect(response.text).toContain('<h2 id="issuer-catalogue-title">Available issuers</h2>');
expect(response.text.match(/<article class="issuer-card">/g)).toHaveLength(2);
expect(response.text).toContain("EUDI PID — device-bound conforming");
expect(response.text).toContain("Conforming");
expect(response.text).toContain(
  "PID issuer advertising JWT and attestation proofs with key attestation required.",
);
expect(response.text).toContain("EUDI PID — JWT proof only");
expect(response.text).toContain("Deliberately non-conforming");
expect(response.text).toContain(
  "PID interoperability test issuer advertising JWT proof without key attestation.",
);
expect(response.text).toContain(
  "Deliberately non-conforming for a device-bound EUDI PID; a conforming wallet may reject issuance.",
);

for (const issuerId of [conformingIssuerId, jwtOnlyIssuerId]) {
  expect(response.text).toContain(
    `href="${config.issuer_base_url}/issuers/${issuerId}" target="_blank" rel="noreferrer">Issuer</a>`,
  );
  expect(response.text).toContain(
    `href="${config.issuer_base_url}/.well-known/openid-credential-issuer/issuers/${issuerId}" target="_blank" rel="noreferrer">Credential issuer well-known</a>`,
  );
  expect(response.text).toContain(
    `href="${config.issuer_base_url}/.well-known/oauth-authorization-server/issuers/${issuerId}" target="_blank" rel="noreferrer">Authorization server well-known</a>`,
  );
}

expect(response.text).not.toContain(
  "/.well-known/oauth-authorization-server/authorization-servers/",
);
```

Create `tests/ui.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { indexPage } from "../src/ui.js";

describe("launcher issuer catalogue", () => {
  it("renders an explicit empty state when no issuers are available", () => {
    const page = indexPage([]);

    expect(page).toContain('<h2 id="issuer-catalogue-title">Available issuers</h2>');
    expect(page).toContain('<p class="issuer-empty">No issuers available</p>');
    expect(page).not.toContain('<article class="issuer-card">');
  });
});
```

- [ ] **Step 2: Run the focused tests and verify the new assertions fail**

Run:

```sh
pnpm exec vitest run tests/server.test.ts tests/ui.test.ts
```

Expected: FAIL because `issuer-catalogue`, issuer cards, links, and the empty-state
message are not rendered yet. Confirm the failure comes from the new assertions rather
than server initialization or unrelated tests.

- [ ] **Step 3: Implement the minimal server-rendered catalogue**

In `indexPage`, render the catalogue after the form’s synchronization script:

```ts
'<script>const credentialPicker=document.querySelector(\'select[name="credential_configuration_id"]\');const issuerInput=document.getElementById("issuer-configuration-id");function syncIssuer(){const selected=credentialPicker?.selectedOptions[0];if(selected&&issuerInput)issuerInput.value=selected.dataset.issuerConfigurationId||"";}credentialPicker?.addEventListener("change",syncIssuer);syncIssuer();</script>',
issuerCatalogueHtml(groups),
```

Add focused helpers beside `issuerCredentialGroupHtml`:

```ts
function issuerCatalogueHtml(groups: readonly IssuerCredentialGroup[]): string {
  return [
    '<section class="issuer-catalogue" aria-labelledby="issuer-catalogue-title">',
    '<h2 id="issuer-catalogue-title">Available issuers</h2>',
    groups.length > 0
      ? `<div class="issuer-cards">${groups.map(issuerCardHtml).join("")}</div>`
      : '<p class="issuer-empty">No issuers available</p>',
    "</section>",
  ].join("");
}

function issuerCardHtml(group: IssuerCredentialGroup): string {
  const { issuer } = group;
  const conforming = issuer.compliance === "eudi-pid-device-bound";
  const status = conforming ? "Conforming" : "Deliberately non-conforming";
  const statusClass = conforming
    ? "issuer-compliance-conforming"
    : "issuer-compliance-nonconforming";

  return [
    '<article class="issuer-card">',
    '<div class="issuer-card-header">',
    "<h3>",
    escapeHtml(issuer.display.name),
    "</h3>",
    '<span class="issuer-compliance ',
    statusClass,
    '">',
    status,
    "</span>",
    "</div>",
    '<p class="issuer-description">',
    escapeHtml(issuer.display.description),
    "</p>",
    issuer.display.warning
      ? `<p class="issuer-warning">${escapeHtml(issuer.display.warning)}</p>`
      : "",
    '<nav class="issuer-links" aria-label="',
    escapeHtml(`${issuer.display.name} endpoints`),
    '">',
    issuerLinkHtml("Issuer", issuer.issuerIdentifier),
    issuerLinkHtml("Credential issuer well-known", issuer.issuerMetadataUrl),
    issuerLinkHtml("Authorization server well-known", issuer.authorizationServerMetadataUrl),
    "</nav>",
    "</article>",
  ].join("");
}

function issuerLinkHtml(label: string, href: string): string {
  return [
    '<a class="issuer-link" href="',
    escapeHtml(href),
    '" target="_blank" rel="noreferrer">',
    escapeHtml(label),
    "</a>",
  ].join("");
}
```

Add styles to `appCss()` near the existing credential-picker and session-action rules:

```ts
".issuer-catalogue { display: grid; gap: 12px; width: 100%; margin-top: 8px; }",
".issuer-catalogue h2 { font-size: 20px; }",
".issuer-cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }",
".issuer-card { min-width: 0; display: grid; align-content: start; gap: 12px; padding: 18px; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--bg); box-shadow: var(--shadow-sm); }",
".issuer-card-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }",
".issuer-card h3 { min-width: 0; font-size: 16px; line-height: 1.4; }",
".issuer-compliance { display: inline-flex; align-items: center; min-height: 24px; padding: 0 9px; border-radius: var(--radius-pill); font-size: 10px; font-weight: 800; line-height: 1.2; text-transform: uppercase; }",
".issuer-compliance-conforming { background: var(--success-bg); color: var(--success); }",
".issuer-compliance-nonconforming { background: var(--warning-bg); color: var(--warning); }",
".issuer-description, .issuer-warning, .issuer-empty { color: var(--fg-muted); font-size: 13px; line-height: 1.5; }",
".issuer-warning { padding: 10px; border-left: 3px solid var(--warning); background: var(--warning-bg); color: var(--fg); }",
".issuer-links { display: grid; gap: 6px; margin-top: auto; }",
".issuer-link { overflow-wrap: anywhere; font-size: 12px; font-weight: 700; }",
```

Extend the existing `@media (max-width: 860px)` rule with:

```css
.issuer-cards { grid-template-columns: 1fr; }
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```sh
pnpm exec vitest run tests/server.test.ts tests/ui.test.ts
```

Expected: PASS for both files with no warnings or unrelated failures.

- [ ] **Step 5: Format and run the complete required validation**

Run:

```sh
task format
pnpm test
pnpm build
task lint
```

Expected: every command exits with status 0. Inspect `git diff --stat` after formatting
and ensure only `src/ui.ts`, `tests/server.test.ts`, `tests/ui.test.ts`, and this plan
belong to the implementation commit.

- [ ] **Step 6: Inspect and commit only this task**

Stage the task files:

```sh
git add src/ui.ts tests/server.test.ts tests/ui.test.ts \
  docs/superpowers/plans/2026-07-30-issuer-catalogue.md
```

Inspect:

```sh
git diff --cached --check
git diff --cached
rg -n -i "private[_ -]?key|access[_ -]?token|secret|password" \
  src/ui.ts tests/server.test.ts tests/ui.test.ts \
  docs/superpowers/plans/2026-07-30-issuer-catalogue.md
```

Commit:

```text
feat(ui): expose issuer choices

reason:
Operators need to understand issuer conformance before starting wallet flows.

prompt:
List every issuer with its description and public discovery links.
```
