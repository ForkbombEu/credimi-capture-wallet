import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import type { SupportedCredential } from "../src/openid4vci/metadata.js";
import { defaultDcqlQuery } from "../src/openid4vp/authorization-request.js";
import {
  type IssuanceParameterValues,
  type IssuerPageOptions,
  indexPage,
  issuerPage,
  verifierPage,
} from "../src/ui.js";

const jwtOnlyIssuerOrNull = resolvedIssuerConfigurationById(
  DEFAULT_CONFIG,
  "eu-pid-jwt-proof-only",
);
if (!jwtOnlyIssuerOrNull) throw new Error("JWT-only issuer configuration unavailable");
const jwtOnlyIssuer = jwtOnlyIssuerOrNull;

const issuanceParameters: IssuanceParameterValues = {
  flows: ["authorization_code"],
  credentialOfferModes: ["credential_offer"],
  offerSchemes: ["openid-credential-offer://"],
  fixtureIds: ["pid_default"],
  digestAlgorithms: ["sha-256"],
  evidenceModes: ["redacted", "full"],
  statusReferences: ["valid"],
};

function issuerPageOptions(overrides: Partial<IssuerPageOptions> = {}): IssuerPageOptions {
  return {
    group: { issuer: jwtOnlyIssuer, credentials: [] },
    fcafScenariosEnabled: false,
    parameters: issuanceParameters,
    ...overrides,
  };
}

describe("launcher", () => {
  it("renders an explicit empty state when no issuers are available, and still offers the verifier", () => {
    const page = indexPage([]);

    expect(page).toContain('<h2 id="issuer-catalogue-title">Issuers</h2>');
    expect(page).toContain('<p class="issuer-empty">No issuers available</p>');
    expect(page).not.toContain('<article class="issuer-card">');
    expect(page).toContain('<a class="btn btn-primary btn-md" href="/openid4vp">Open verifier</a>');
  });

  it("escapes configured issuer text and the issuer page URL", () => {
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

  it("renders an unsafe issuer page URL as non-interactive text", () => {
    const page = indexPage([
      {
        issuer: { ...jwtOnlyIssuer, issuerIdentifier: 'javascript:alert("issuer")' },
        credentials: [],
      },
    ]);

    expect(page).not.toContain('href="javascript:');
    expect(page).toContain(
      '<span class="btn btn-primary btn-md">Open issuer: javascript:alert(&quot;issuer&quot;)</span>',
    );
  });
});

describe("issuer page", () => {
  it("links the authorization server, credential issuer, and federation metadata", () => {
    const page = issuerPage(
      issuerPageOptions({
        federationEntityConfigurationUrl:
          "https://issuer.example.test/issuers/x/.well-known/openid-federation",
      }),
    );

    expect(page).toContain(
      `<a class="issuer-link" href="${jwtOnlyIssuer.authorizationServerMetadataUrl}" target="_blank" rel="noreferrer">Authorization server metadata</a>`,
    );
    expect(page).toContain(
      `<a class="issuer-link" href="${jwtOnlyIssuer.issuerMetadataUrl}" target="_blank" rel="noreferrer">OpenID4VCI credential issuer metadata</a>`,
    );
    expect(page).toContain(
      '<a class="issuer-link" href="https://issuer.example.test/issuers/x/.well-known/openid-federation" target="_blank" rel="noreferrer">OpenID Federation entity configuration</a>',
    );
  });

  it("omits the federation link when federation is disabled", () => {
    expect(issuerPage(issuerPageOptions())).not.toContain("OpenID Federation entity configuration");
  });

  it("renders unsafe metadata URL schemes as non-interactive text", () => {
    const page = issuerPage(
      issuerPageOptions({
        group: {
          issuer: {
            ...jwtOnlyIssuer,
            issuerMetadataUrl: 'data:text/html,<script>alert("metadata")</script>',
          },
          credentials: [],
        },
      }),
    );

    expect(page).not.toContain('href="data:');
    expect(page).toContain(
      '<span class="issuer-link">OpenID4VCI credential issuer metadata: data:text/html,&lt;script&gt;alert(&quot;metadata&quot;)&lt;/script&gt;</span>',
    );
  });

  it("offers the test-only parameters only when FCAF scenarios are enabled", () => {
    const testOnly = [
      'data-param="evidence_mode"',
      'data-param="status_reference"',
      'data-param="issuance_response_scenario"',
      'data-param="offer_mutation"',
    ];
    const disabled = issuerPage(issuerPageOptions());
    const enabled = issuerPage(issuerPageOptions({ fcafScenariosEnabled: true }));

    for (const parameter of testOnly) {
      expect(disabled).not.toContain(parameter);
      expect(enabled).toContain(parameter);
    }
    expect(disabled).toContain('data-param="flow"');
  });
});

describe("verifier page", () => {
  it("carries each credential's DCQL query, escaped, under its issuer", () => {
    const credential: SupportedCredential = {
      id: "urn:attestbook:membership-card",
      scope: "urn:attestbook:membership-card",
      format: "dc+sd-jwt",
      proofPolicy: "jwt-proof",
      displayName: 'Membership "card" <b>',
      vct: "urn:attestbook:membership-card",
      claimPaths: [["club"]],
    };
    const dcqlQuery = defaultDcqlQuery([credential]);
    const page = verifierPage({
      groups: [{ issuer: jwtOnlyIssuer, credentials: [{ credential, dcqlQuery }] }],
      fcafScenariosEnabled: false,
      parameters: { responseModes: [], requestDeliveries: [], clientIdSchemes: [] },
    });

    expect(page).toContain(
      `<optgroup label="${jwtOnlyIssuer.display.name} — deliberately non-conforming">`,
    );
    expect(page).toContain(
      `data-dcql="${JSON.stringify(dcqlQuery).replaceAll('"', "&quot;")}">Membership &quot;card&quot; &lt;b&gt;</option>`,
    );
    expect(page).not.toContain('data-param="request_mutation"');
  });
});
