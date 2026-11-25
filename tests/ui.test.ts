import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import type { SupportedCredential } from "../src/credentials/catalogue.js";
import { defaultDcqlQuery } from "../src/openid4vp/authorization-request.js";
import { issuerPage } from "../src/ui/issuer.js";
import type { IssuerPageOptions } from "../src/ui/issuer.js";
import { indexPage } from "../src/ui/launcher.js";
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

  it("disables both session buttons when no credential exists, and still offers the verifier", () => {
    const page = indexPage([]);

    expect(page).toContain('<option value="">No credentials available</option>');
    expect(page).toContain("data-issue disabled>New issuance session</button>");
    expect(page).toContain("data-verify disabled>New presentation session</button>");
    expect(page).toContain('<p class="issuer-empty">No issuers available</p>');
    expect(page).toContain('<a class="issuer-card" href="/openid4vp"><h3>OpenID4VP verifier</h3>');
  });

  it("preselects the first credential and makes each card a link with no link inside", () => {
    const page = indexPage([{ issuer: jwtOnlyIssuer, credentials: [{ credential, dcqlQuery }] }]);

    // No placeholder: the first option is the selection.
    expect(page).toContain(
      `<select data-credential-choice autocomplete="off"><optgroup label="${jwtOnlyIssuer.display.name} — deliberately non-conforming"><option value="${credential.id}" data-issuer="${jwtOnlyIssuer.id}" data-dcql="`,
    );
    expect(attributeJson(page, /data-dcql="([^"]+)"/)).toEqual(dcqlQuery);
    expect(page).not.toContain("data-imported");
    expect(page).toContain("data-issue>New issuance session</button>");
    expect(page).toContain(
      `<a class="issuer-card" href="${jwtOnlyIssuer.issuerIdentifier}"><h3>${jwtOnlyIssuer.display.name} — deliberately non-conforming</h3>`,
    );
    expect(page).not.toContain("Customize");
    expect(page).not.toContain('class="issuer-link"');
  });

  it("keeps the device-bound regulation reference as text inside its card", () => {
    const deviceBound = resolvedIssuerConfigurationById(DEFAULT_CONFIG, "eu-pid-device-bound");
    if (!deviceBound) throw new Error("device-bound issuer configuration unavailable");
    const page = indexPage([{ issuer: deviceBound, credentials: [] }]);
    const card = /<a class="issuer-card"[^>]*>(.*?)<\/a>/.exec(page)?.[1] ?? "";

    expect(card).toContain("Commission Implementing Regulation (EU) 2026/1731");
    expect(card).not.toContain("<a ");
  });

  it("escapes configured issuer text and the issuer page URL", () => {
    const page = indexPage([
      {
        issuer: {
          ...jwtOnlyIssuer,
          display: { name: 'Issuer <script>alert("name")</script> &', description: "" },
          issuerIdentifier:
            "https://issuer.example.test/?next=\"><script>alert('url')</script>&mode=test",
        },
        credentials: [{ credential, dcqlQuery }],
      },
    ]);

    expect(page).toContain("Issuer &lt;script&gt;alert(&quot;name&quot;)&lt;/script&gt; &amp;");
    expect(page).toContain(
      "https://issuer.example.test/?next=&quot;&gt;&lt;script&gt;alert(&#39;url&#39;)&lt;/script&gt;&amp;mode=test",
    );
    expect(page).not.toContain("<script>alert");
  });

  it("renders a card with an unsafe issuer page URL as inert, never as a link target", () => {
    const page = indexPage([
      {
        issuer: { ...jwtOnlyIssuer, issuerIdentifier: 'javascript:alert("issuer")' },
        credentials: [{ credential, dcqlQuery }],
      },
    ]);

    expect(page).not.toContain('href="javascript:');
    expect(page).toContain(
      `<article class="issuer-card"><h3>${jwtOnlyIssuer.display.name} — deliberately non-conforming</h3>`,
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
