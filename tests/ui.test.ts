import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import type { SupportedCredential } from "../src/credentials/catalogue.js";
import { defaultDcqlQuery } from "../src/openid4vp/authorization-request.js";
import { issuerPage } from "../src/ui/issuer.js";
import type { IssuerPageOptions } from "../src/ui/issuer.js";
import { indexPage } from "../src/ui/launcher.js";
import type { IndexPageOptions, IssuerCredentialChoices } from "../src/ui/launcher.js";
import type { IssuanceParameterValues } from "../src/ui/session-parameters.js";
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

function launcherPage(
  groups: readonly IssuerCredentialChoices[],
  overrides: Partial<IndexPageOptions> = {},
): string {
  return indexPage({
    groups,
    fcafScenariosEnabled: false,
    issuanceParameters,
    presentationParameters: { responseModes: [], requestDeliveries: [], clientIdSchemes: [] },
    ...overrides,
  });
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

  it("disables Start when no credential exists", () => {
    const page = launcherPage([]);

    expect(page).toContain('<option value="">No credentials available</option>');
    expect(page).toContain('type="submit" autocomplete="off" disabled>Start</button>');
  });

  it("preselects the first credential and carries what each flow sends in its option", () => {
    const page = launcherPage([
      { issuer: jwtOnlyIssuer, credentials: [{ credential, dcqlQuery }] },
    ]);

    // No placeholder: the first option is the selection.
    expect(page).toContain(
      `<select data-credential-picker autocomplete="off"><optgroup label="${jwtOnlyIssuer.display.name} — deliberately non-conforming"><option value="${credential.id}" data-issuer="${jwtOnlyIssuer.id}" data-dcql="`,
    );
    expect(attributeJson(page, /data-dcql="([^"]+)"/)).toEqual(dcqlQuery);
    expect(page).toContain(' data-format="dc+sd-jwt">PID</option>');
    expect(page).not.toContain("data-imported");
    expect(page).toContain('type="submit" autocomplete="off">Start</button>');
  });

  it("starts on issuance and keeps the presentation settings out of the request", () => {
    const page = launcherPage([
      { issuer: jwtOnlyIssuer, credentials: [{ credential, dcqlQuery }] },
    ]);

    expect(page).toContain(
      '<input type="radio" name="session-flow" value="issuance" data-flow-choice data-endpoint="/sessions" data-session-page="/ui/sessions/" autocomplete="off" checked>',
    );
    expect(page).toContain(
      '<input type="radio" name="session-flow" value="presentation" data-flow-choice data-endpoint="/openid4vp/sessions" data-session-page="/ui/openid4vp/sessions/" autocomplete="off">',
    );
    // A disabled fieldset's fields are skipped when the request body is built.
    expect(page).toContain(
      '<fieldset class="flow-settings" data-flow="presentation" hidden disabled>',
    );
    const issuance = /<fieldset class="flow-settings" data-flow="issuance">(.*?)<\/fieldset>/.exec(
      page,
    )?.[1];
    expect(issuance).toContain(
      'data-param="issuer_configuration_id" data-type="string" data-option="issuer"',
    );
    expect(issuance).toContain(
      'data-param="credential_configuration_id" data-type="string" data-option="credential"',
    );
    // The Token Status List reference is on unless the operator turns it off.
    expect(issuance).toContain(
      '<input type="checkbox" role="switch" value="true" data-param="status_list_enabled" data-type="flag" data-requires="static-credential" checked>',
    );
    expect(issuance).toContain(
      '<a href="https://tsl.credimi.io/" target="_blank" rel="noreferrer">Token Status List service ↗</a>',
    );
  });

  it("links each issuer's page and metadata, and its federation configuration when enabled", () => {
    const groups = [{ issuer: jwtOnlyIssuer, credentials: [{ credential, dcqlQuery }] }];
    const page = launcherPage(groups, {
      federationEntityConfigurationUrl: (issuer) => `${issuer.issuerIdentifier}/federation`,
    });

    // The links belong to the issuance settings, so the Present flow hides them.
    const [, issuance = "", presentation = ""] =
      /data-flow="issuance">(.*)data-flow="presentation"(.*)<\/details>/.exec(page) ?? [];
    expect(issuance).toContain(
      `<p class="parameter-group-title">Issuer information</p><nav class="metadata-cards" data-issuer-links="${jwtOnlyIssuer.id}" aria-label="${jwtOnlyIssuer.display.name} — deliberately non-conforming links">`,
    );
    expect(presentation).not.toContain("data-issuer-links");
    for (const [label, href] of [
      ["Issuer page", jwtOnlyIssuer.issuerIdentifier],
      ["Authorization server metadata", jwtOnlyIssuer.authorizationServerMetadataUrl],
      ["OpenID4VCI credential issuer metadata", jwtOnlyIssuer.issuerMetadataUrl],
      ["OpenID Federation entity configuration", `${jwtOnlyIssuer.issuerIdentifier}/federation`],
    ]) {
      expect(page).toContain(
        `<a class="issuer-card metadata-card" href="${href}" target="_blank" rel="noreferrer"><h3>${label}</h3>`,
      );
    }
    expect(launcherPage(groups)).not.toContain("OpenID Federation entity configuration");
  });

  it("escapes configured issuer text", () => {
    const page = launcherPage([
      {
        issuer: {
          ...jwtOnlyIssuer,
          display: { name: 'Issuer <script>alert("name")</script> &', description: "" },
        },
        credentials: [{ credential, dcqlQuery }],
      },
    ]);

    expect(page).toContain("Issuer &lt;script&gt;alert(&quot;name&quot;)&lt;/script&gt; &amp;");
    expect(page).not.toContain("<script>alert");
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
      `<a class="issuer-card metadata-card" href="${jwtOnlyIssuer.authorizationServerMetadataUrl}" target="_blank" rel="noreferrer"><h3>Authorization server metadata</h3>`,
    );
    expect(page).toContain(
      `<a class="issuer-card metadata-card" href="${jwtOnlyIssuer.issuerMetadataUrl}" target="_blank" rel="noreferrer"><h3>OpenID4VCI credential issuer metadata</h3>`,
    );
    expect(page).toContain(
      '<a class="issuer-card metadata-card" href="https://issuer.example.test/issuers/x/.well-known/openid-federation" target="_blank" rel="noreferrer"><h3>OpenID Federation entity configuration</h3>',
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
      '<article class="issuer-card metadata-card"><h3>OpenID4VCI credential issuer metadata</h3><p class="metadata-card-url">data:text/html,&lt;script&gt;alert(&quot;metadata&quot;)&lt;/script&gt;</p></article>',
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
