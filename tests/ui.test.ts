import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { indexPage } from "../src/ui.js";

const jwtOnlyIssuer = resolvedIssuerConfigurationById(DEFAULT_CONFIG, "eu-pid-jwt-proof-only");
if (!jwtOnlyIssuer) throw new Error("JWT-only issuer configuration unavailable");

describe("launcher issuer catalogue", () => {
  it("renders an explicit empty state when no issuers are available", () => {
    const page = indexPage([]);

    expect(page).toContain('<h2 id="issuer-catalogue-title">Available issuers</h2>');
    expect(page).toContain('<p class="issuer-empty">No issuers available</p>');
    expect(page).not.toContain('<article class="issuer-card">');
  });

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

    expect(page).toContain("Issuer &lt;script&gt;alert(&quot;name&quot;)&lt;/script&gt; &amp;");
    expect(page).toContain("Description &lt;img src=x onerror=&quot;description&quot;&gt; &amp;");
    expect(page).toContain(
      "https://issuer.example.test/?next=&quot;&gt;&lt;script&gt;alert(&#39;url&#39;)&lt;/script&gt;&amp;mode=test",
    );
    expect(page).not.toContain("<script>alert");
    expect(page).not.toContain("<img src=x");
  });

  it("renders unsafe issuer endpoint schemes as non-interactive text", () => {
    const page = indexPage([
      {
        issuer: {
          ...jwtOnlyIssuer,
          issuerIdentifier: 'javascript:alert("issuer")',
          issuerMetadataUrl: 'data:text/html,<script>alert("metadata")</script>',
        },
        credentials: [],
      },
    ]);

    expect(page).not.toContain('href="javascript:');
    expect(page).not.toContain('href="data:');
    expect(page).toContain(
      '<span class="issuer-link">Issuer: javascript:alert(&quot;issuer&quot;)</span>',
    );
    expect(page).toContain(
      '<span class="issuer-link">Credential issuer well-known: data:text/html,&lt;script&gt;alert(&quot;metadata&quot;)&lt;/script&gt;</span>',
    );
    expect(page).not.toContain("<script>alert");
  });

  it("keeps HTTP and HTTPS issuer endpoints interactive", () => {
    const page = indexPage([
      {
        issuer: {
          ...jwtOnlyIssuer,
          issuerIdentifier: "http://issuer.example.test/issuer",
          issuerMetadataUrl: "https://issuer.example.test/metadata",
        },
        credentials: [],
      },
    ]);

    expect(page).toContain(
      '<a class="issuer-link" href="http://issuer.example.test/issuer" target="_blank" rel="noreferrer">Issuer</a>',
    );
    expect(page).toContain(
      '<a class="issuer-link" href="https://issuer.example.test/metadata" target="_blank" rel="noreferrer">Credential issuer well-known</a>',
    );
  });
});
