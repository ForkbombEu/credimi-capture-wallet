import type { SupportedCredential } from "../credentials/catalogue.js";
import { escapeHtml, htmlPage } from "./html.js";
import type { IssuanceParameterValues, IssuerCredentialGroup } from "./launcher.js";
import {
  additionalParametersField,
  advancedSettingsHtml,
  attestbookSummaryHtml,
  credentialLabel,
  issuerDescriptionHtml,
  issuerLabel,
  launcherActionsHtml,
  launcherTopbarHtml,
  safeLinkHtml,
} from "./launcher.js";
import type { ParameterGroup } from "./launcher.js";
import { sessionLauncherScript } from "./scripts.js";

export interface IssuerPageOptions {
  readonly group: IssuerCredentialGroup;
  /** Absent when OpenID Federation is disabled. */
  readonly federationEntityConfigurationUrl?: string;
  readonly fcafScenariosEnabled: boolean;
  readonly parameters: IssuanceParameterValues;
}
/**
 * The operator page served at an issuer's Credential Issuer Identifier. Sessions are created
 * through the public `POST /sessions` API, so the page offers exactly what the API accepts.
 */
export function issuerPage(options: IssuerPageOptions): string {
  const { group } = options;
  const { issuer } = group;
  return htmlPage({
    title: `${issuer.display.name} — OpenID4VCI issuer`,
    body: [
      launcherTopbarHtml(),
      '<main class="page-content session-page">',
      '<section class="session-header launcher-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VCI credential issuer</p>',
      "<h1>",
      escapeHtml(issuerLabel(issuer)),
      "</h1>",
      '<p class="session-intro">',
      issuerDescriptionHtml(group),
      "</p>",
      group.attestbook ? attestbookSummaryHtml(group.attestbook) : "",
      "</div>",
      "</section>",
      '<section class="launcher-layout container">',
      issuanceFormHtml(options),
      issuerMetadataHtml(options),
      "</section>",
      "</main>",
      "<script>",
      sessionLauncherScript(),
      "</script>",
    ].join(""),
  });
}
function issuerCredentialOptionHtml(credential: SupportedCredential): string {
  return [
    '<option value="',
    escapeHtml(credential.id),
    '" data-format="',
    escapeHtml(credential.format),
    '"',
    credential.attestbook ? ' data-imported="true"' : "",
    ">",
    escapeHtml(credentialLabel(credential)),
    "</option>",
  ].join("");
}
function issuanceFormHtml({ group, fcafScenariosEnabled, parameters }: IssuerPageOptions): string {
  const { issuer, credentials } = group;
  const groups: ParameterGroup[] = [
    {
      legend: "Credential offer",
      fields: [
        { name: "flow", label: "Grant", kind: "select", values: parameters.flows },
        {
          name: "credential_offer_mode",
          label: "Offer delivery",
          kind: "select",
          values: parameters.credentialOfferModes,
          hint: "credential_offer embeds the offer in the deeplink; credential_offer_uri passes it by reference.",
        },
        {
          name: "offer_scheme",
          label: "Offer deeplink scheme",
          kind: "select",
          values: parameters.offerSchemes,
        },
      ],
    },
    {
      legend: "Credential content",
      fields: [
        {
          name: "fixture_id",
          label: "PID fixture",
          kind: "select",
          values: parameters.fixtureIds,
          requires: "static-credential",
        },
        {
          name: "document_number",
          label: "Document number",
          kind: "text",
          hint: "Overrides the fixture's document number only.",
          requires: "static-credential",
        },
        {
          name: "digest_algorithm",
          label: "SD-JWT disclosure digest",
          kind: "select",
          values: parameters.digestAlgorithms,
          requires: "sd-jwt",
        },
      ],
    },
    ...(fcafScenariosEnabled
      ? [
          {
            legend: "Test scenarios (FCAF)",
            fields: [
              {
                name: "evidence_mode",
                label: "Evidence mode",
                kind: "select",
                values: parameters.evidenceModes,
              },
              {
                name: "status_reference",
                label: "Status reference",
                kind: "select",
                values: parameters.statusReferences,
                hint: "Anything but valid needs the Token Status List switch.",
                requires: "static-credential",
              },
              {
                name: "issuance_response_scenario",
                label: "Issuance response scenario",
                kind: "json",
                placeholder: '{"par": {"omit_parameters": ["/request_uri"]}}',
              },
              {
                name: "offer_mutation",
                label: "Offer mutation",
                kind: "json",
                placeholder: '{"unset": ["/credential_issuer"]}',
                hint: "Applies to a by-value offer only.",
              },
            ],
          } satisfies ParameterGroup,
        ]
      : []),
    {
      legend: "Raw request",
      fields: [additionalParametersField('{"fixture_id": "pid_default"}')],
    },
  ];

  return [
    '<form class="card launcher-card session-launcher" data-endpoint="/sessions" data-session-page="/ui/sessions/" novalidate>',
    '<div class="section-head">',
    "<h2>Issue a credential</h2>",
    "</div>",
    '<input type="hidden" data-param="issuer_configuration_id" data-type="string" value="',
    escapeHtml(issuer.id),
    '">',
    '<div class="credential-row">',
    '<label class="credential-picker">',
    "<span>Credential</span>",
    '<select data-param="credential_configuration_id" data-type="string" data-credential-picker>',
    credentials.map(issuerCredentialOptionHtml).join(""),
    "</select>",
    "</label>",
    '<label class="status-list-toggle">',
    '<input type="checkbox" role="switch" data-param="status_list_enabled" data-type="flag" value="true" data-requires="static-credential">',
    '<span class="toggle-track" aria-hidden="true"></span>',
    "<span>Include a Token Status List reference</span>",
    "</label>",
    "</div>",
    advancedSettingsHtml(groups),
    launcherActionsHtml("Create issuance session", credentials.length === 0),
    credentials.length === 0
      ? '<p class="issuer-empty">This issuer serves no credential configuration.</p>'
      : "",
    "</form>",
  ].join("");
}
function issuerMetadataHtml({
  group,
  federationEntityConfigurationUrl,
}: IssuerPageOptions): string {
  const { issuer } = group;
  return [
    '<aside class="card launcher-card" aria-labelledby="issuer-metadata-title">',
    '<div class="section-head">',
    '<h2 id="issuer-metadata-title">Metadata</h2>',
    "</div>",
    '<dl class="entity-facts">',
    "<div><dt>Credential Issuer Identifier</dt><dd><code>",
    escapeHtml(issuer.issuerIdentifier),
    "</code></dd></div>",
    "</dl>",
    '<nav class="issuer-links" aria-label="',
    escapeHtml(`${issuer.display.name} metadata`),
    '">',
    metadataLinkHtml("Authorization server metadata", issuer.authorizationServerMetadataUrl),
    metadataLinkHtml("OpenID4VCI credential issuer metadata", issuer.issuerMetadataUrl),
    federationEntityConfigurationUrl
      ? metadataLinkHtml("OpenID Federation entity configuration", federationEntityConfigurationUrl)
      : "",
    group.attestbook
      ? metadataLinkHtml("Attestbook status", "/integrations/attestbook/status")
      : "",
    "</nav>",
    "</aside>",
  ].join("");
}

function metadataLinkHtml(label: string, href: string): string {
  return safeLinkHtml(label, href, "issuer-link", true);
}
