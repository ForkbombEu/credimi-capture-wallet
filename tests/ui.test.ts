import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import type { SupportedCredential } from "../src/credentials/catalogue.js";
import { defaultDcqlQuery } from "../src/openid4vp/authorization-request.js";
import { issuerPage } from "../src/ui/issuer.js";
import type { IssuerPageOptions } from "../src/ui/issuer.js";
import { credentialPreselectionFragment, indexPage } from "../src/ui/launcher.js";
import type { IssuanceParameterValues } from "../src/ui/launcher.js";
import { errorPage } from "../src/ui/session.js";
import { verifierPage } from "../src/ui/verifier.js";

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

function attributeJson(page: string, pattern: RegExp): unknown {
  const value = pattern.exec(page)?.[1];
  if (value === undefined) throw new Error(`no match for ${pattern}`);
  return JSON.parse(value.replaceAll("&quot;", '"'));
}

describe("launcher", () => {
  it("renders an explicit empty state when no issuers are available, and still offers the verifier", () => {
    const page = indexPage([]);

    expect(page).toContain('<h2 id="credential-catalogue-title">Credentials</h2>');
    expect(page).toContain('<p class="issuer-empty">No issuers available</p>');
    expect(page).not.toContain('<article class="issuer-group">');
    expect(page).toContain('<a class="btn btn-outline btn-md" href="/openid4vp">Verifier page</a>');
  });

  it("issues and verifies each credential in one click, and links its customization", () => {
    const credential: SupportedCredential = {
      id: "urn:eudi:pid:1.sd-jwt",
      scope: "pid",
      format: "dc+sd-jwt",
      proofPolicy: "jwt-proof",
      displayName: "PID",
      vct: "urn:eudi:pid:1",
      claimPaths: [["given_name"]],
    };
    const dcqlQuery = defaultDcqlQuery([credential]);
    const page = indexPage([{ issuer: jwtOnlyIssuer, credentials: [{ credential, dcqlQuery }] }]);

    expect(
      attributeJson(
        page,
        /data-launch="\/sessions" data-session-page="\/ui\/sessions\/" data-body="([^"]+)" data-status-list="true">Issue</,
      ),
    ).toEqual({
      issuer_configuration_id: jwtOnlyIssuer.id,
      credential_configuration_id: credential.id,
    });
    expect(
      attributeJson(
        page,
        /data-launch="\/openid4vp\/sessions" data-session-page="\/ui\/openid4vp\/sessions\/" data-body="([^"]+)">Verify</,
      ),
    ).toEqual({ dcql_query: dcqlQuery });

    const fragment = credentialPreselectionFragment(credential.id);
    expect(fragment).toBe("#credential_configuration_id=urn%3Aeudi%3Apid%3A1.sd-jwt");
    expect(page).toContain(
      `<a class="issuer-link" href="${jwtOnlyIssuer.issuerIdentifier}${fragment}">Customize issuance</a>`,
    );
    expect(page).toContain(
      `<a class="issuer-link" href="/openid4vp${fragment}">Customize presentation</a>`,
    );
    expect(page).toContain(
      `<a class="btn btn-outline btn-md" href="${jwtOnlyIssuer.issuerIdentifier}">Issuer page</a>`,
    );
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
      '<span class="btn btn-outline btn-md">Issuer page: javascript:alert(&quot;issuer&quot;)</span>',
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

describe("shared UI pages", () => {
  it("escapes error-page messages", () => {
    const page = errorPage(`wallet <script>alert("x")</script> & '`);
    expect(page).toContain("wallet &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;");
    expect(page).not.toContain("<script>alert");
  });

  it("renders both Attestbook summary states", () => {
    const active = issuerPage(
      issuerPageOptions({
        group: {
          issuer: jwtOnlyIssuer,
          credentials: [],
          attestbook: {
            syncState: "idle",
            activeVersion: "2026.1",
            activeContentDigest: "abcdef1234567890",
            failureStage: null,
          },
        },
      }),
    );
    expect(active).toContain(
      "Attestbook rulebook version 2026.1 (sha-256 abcdef123456…) is active",
    );
    expect(active).toContain("synchronization idle.");

    const failed = issuerPage(
      issuerPageOptions({
        group: {
          issuer: jwtOnlyIssuer,
          credentials: [],
          attestbook: {
            syncState: "failed",
            activeVersion: null,
            activeContentDigest: null,
            failureStage: "verify",
          },
        },
      }),
    );
    expect(failed).toContain(
      "No Attestbook rulebook version is active; last synchronization failed at the verify stage.",
    );
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
