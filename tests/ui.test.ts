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
});
