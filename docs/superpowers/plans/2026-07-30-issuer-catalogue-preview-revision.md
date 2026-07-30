# Issuer Catalogue Preview Revision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simplify the previewed issuer cards by removing status and warning treatments and replacing the conforming issuer’s UI description with a linked TR_KA-4 explanation.

**Architecture:** Keep the revision inside `src/ui.ts`, selecting a static conforming explanation from the existing typed compliance value while retaining the configured description for the JWT-only issuer. The shared issuer configuration and public `/issuers` response remain unchanged.

**Tech Stack:** TypeScript, Express-rendered HTML, inline CSS using the existing Credimi/Atlas design tokens, Vitest, and Supertest.

## Global Constraints

- Preserve all OpenID4VCI behavior, endpoint paths, metadata, and response shapes.
- Preserve the public `/issuers` catalogue content.
- Remove conformance status tags and the configured warning block from issuer cards.
- Preserve the previewed colors.
- Link “Commission Implementing Regulation (EU) 2026/1731” to `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731`.
- State that TR_KA-4 has both `jwt` and `attestation` proof types present and both include `key_attestations_required`.
- Continue to show only the three endpoint links “Issuer,” “Credential issuer well-known,” and “Authorization server well-known.”
- Do not show the chained auto-approving authorization server.
- Escape every configured value and use `target="_blank" rel="noreferrer"` on every card link.
- Preserve unrelated files and changes; do not change dependencies or generated state under `data/`.
- Existing Node `punycode` deprecation output is accepted baseline noise; introduce no new warnings.

---

### Task 1: Apply and verify the preview revision

**Files:**

- Modify: `src/ui.ts:193-247`
- Modify: `src/ui.ts:467-484`
- Modify: `tests/server.test.ts:535-575`
- Modify: `tests/ui.test.ts`

**Interfaces:**

- Consumes: `IssuerCredentialGroup.issuer.compliance`
- Consumes: `IssuerCredentialGroup.issuer.display.description`
- Produces: `issuerDescriptionHtml(group: IssuerCredentialGroup): string`
- Preserves: `issuerLinkHtml(label: string, href: string): string`

- [ ] **Step 1: Write failing HTTP assertions for the revised card content**

Replace the status, warning, and conforming-description assertions in the existing
launcher HTTP test with:

```ts
expect(response.text).not.toContain('class="issuer-compliance');
expect(response.text).not.toContain('class="issuer-warning"');
expect(response.text).not.toContain(
  "Deliberately non-conforming for a device-bound EUDI PID; a conforming wallet may reject issuance.",
);
expect(response.text).not.toContain(
  "PID issuer advertising JWT and attestation proofs with key attestation required.",
);
expect(response.text).toContain(
  '<a href="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731" target="_blank" rel="noreferrer">Commission Implementing Regulation (EU) 2026/1731</a>',
);
expect(response.text).toContain(
  "in particular <code>TR_KA-4</code>: both <code>jwt</code> and <code>attestation</code> proof types are present and both include <code>key_attestations_required</code>.",
);
expect(response.text).toContain(
  "PID interoperability test issuer advertising JWT proof without key attestation.",
);
expect(response.text.match(/class="issuer-link"/g)).toHaveLength(6);
```

Keep the existing assertions for both issuer names, all six endpoint URLs, and absence
of the chained authorization-server metadata URL.

- [ ] **Step 2: Run the focused HTTP test and verify RED**

Run:

```sh
pnpm exec vitest run tests/server.test.ts
```

Expected: FAIL because the current cards still render status tags, the warning block,
and the configured conforming description instead of the linked TR_KA-4 explanation.
The accepted baseline `punycode` warning may remain.

- [ ] **Step 3: Implement the minimal card revision**

Add the regulation URL beside the existing UI constants:

```ts
const REGULATION_2026_1731_URL =
  "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731";
```

Replace `issuerCardHtml` with:

```ts
function issuerCardHtml(group: IssuerCredentialGroup): string {
  const { issuer } = group;

  return [
    '<article class="issuer-card">',
    "<h3>",
    escapeHtml(issuer.display.name),
    "</h3>",
    '<p class="issuer-description">',
    issuerDescriptionHtml(group),
    "</p>",
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
```

Add:

```ts
function issuerDescriptionHtml(group: IssuerCredentialGroup): string {
  if (group.issuer.compliance !== "eudi-pid-device-bound") {
    return escapeHtml(group.issuer.display.description);
  }

  return [
    "Conformant to ",
    '<a href="',
    REGULATION_2026_1731_URL,
    '" target="_blank" rel="noreferrer">',
    "Commission Implementing Regulation (EU) 2026/1731",
    "</a>",
    ", in particular <code>TR_KA-4</code>: both <code>jwt</code> and ",
    "<code>attestation</code> proof types are present and both include ",
    "<code>key_attestations_required</code>.",
  ].join("");
}
```

Remove the unused `.issuer-card-header`, `.issuer-compliance`,
`.issuer-compliance-conforming`, `.issuer-compliance-nonconforming`, and
`.issuer-warning` CSS rules. Keep the existing `.issuer-description` color and sizing,
changing the combined selector to:

```ts
".issuer-description, .issuer-empty { color: var(--fg-muted); font-size: 13px; line-height: 1.5; }",
```

- [ ] **Step 4: Run the focused HTTP test and verify GREEN**

Run:

```sh
pnpm exec vitest run tests/server.test.ts
```

Expected: PASS. The only warning may be the accepted baseline `punycode` deprecation.

- [ ] **Step 5: Add an adversarial escaping regression fixture**

Extend `tests/ui.test.ts` using a real resolved JWT-only issuer:

```ts
import { DEFAULT_CONFIG } from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";

const jwtOnlyIssuer = resolvedIssuerConfigurationById(
  DEFAULT_CONFIG,
  "eu-pid-jwt-proof-only",
);
if (!jwtOnlyIssuer) throw new Error("JWT-only issuer configuration unavailable");

it("escapes configured issuer text and endpoint URLs", () => {
  const page = indexPage([
    {
      issuer: {
        ...jwtOnlyIssuer,
        display: {
          name: 'Issuer <script>alert("name")</script> &',
          description: 'Description <img src=x onerror="description"> &',
        },
        issuerIdentifier:
          "https://issuer.example.test/?next=\"><script>alert('url')</script>&mode=test",
      },
      credentials: [],
    },
  ]);

  expect(page).toContain(
    "Issuer &lt;script&gt;alert(&quot;name&quot;)&lt;/script&gt; &amp;",
  );
  expect(page).toContain(
    "Description &lt;img src=x onerror=&quot;description&quot;&gt; &amp;",
  );
  expect(page).toContain(
    "https://issuer.example.test/?next=&quot;&gt;&lt;script&gt;alert(&#39;url&#39;)&lt;/script&gt;&amp;mode=test",
  );
  expect(page).not.toContain("<script>alert");
  expect(page).not.toContain("<img src=x");
});
```

Run:

```sh
pnpm exec vitest run tests/ui.test.ts
```

Expected: PASS because the shared `escapeHtml` boundary already protects configured
values.

Perform a mutation check: temporarily return the raw value from `escapeHtml`, rerun
`tests/ui.test.ts`, confirm the new escaping test fails on raw injected markup, restore
`escapeHtml`, and rerun the test to PASS. Do not commit the temporary mutation.

- [ ] **Step 6: Format and run complete validation**

Run:

```sh
task format
pnpm test
pnpm build
task lint
```

Expected: every command exits with status 0. The accepted baseline `punycode` warning
may remain; no new warning may appear.

- [ ] **Step 7: Refresh the preview and inspect the final layout**

Capture the launcher at a desktop viewport and verify:

- issuer cards contain no status tags;
- the JWT-only card contains no warning block;
- the conforming explanation contains the regulation link and TR_KA-4 terms;
- the current colors and responsive card layout remain unchanged.

- [ ] **Step 8: Inspect and commit only the revision**

Stage:

```sh
git add src/ui.ts tests/server.test.ts tests/ui.test.ts
```

Inspect:

```sh
git diff --cached --check
git diff --cached
rg -n -i "private[_ -]?key|access[_ -]?token|secret|password" \
  src/ui.ts tests/server.test.ts tests/ui.test.ts
```

Commit:

```text
fix(ui): clarify issuer conformance

reason:
Operators need the applicable TR_KA-4 basis without redundant status treatments.

prompt:
Remove issuer tags and warnings while preserving the previewed colors.
```
