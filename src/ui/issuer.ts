import type { SupportedCredential } from "../credentials/catalogue.js";
import { escapeHtml, htmlPage } from "./html.js";
import type { IssuanceParameterValues, IssuerCredentialGroup } from "./launcher.js";
import {
  additionalParametersField,
  advancedSettingsHtml,
  attestbookSummaryText,
  credentialLabel,
  entityCardHtml,
  heroSectionHtml,
  issuerDescriptionHtml,
  issuerLabel,
  launcherActionsHtml,
  launcherTopbarHtml,
  sectionIntroHtml,
} from "./launcher.js";
import type { ParameterGroup } from "./launcher.js";
import { launcherScript } from "./scripts.js";

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
      "<main>",
      heroSectionHtml({
        id: "issuer-title",
        title: issuerLabel(issuer),
        paragraphsHtml: [
          issuerDescriptionHtml(issuer),
          ...(group.attestbook ? [escapeHtml(attestbookSummaryText(group.attestbook))] : []),
        ],
      }),
      '<section class="page-section" aria-labelledby="issue-title">',
      '<div class="container">',
      sectionIntroHtml({
        tag: "h2",
        id: "issue-title",
        title: "Issue a credential",
        paragraphsHtml: [
          "Choose one of this issuer’s credentials and create a session. Advanced settings expose every parameter of <code>POST /sessions</code>; a field left empty keeps the API default.",
        ],
      }),
      issuanceFormHtml(options),
      "</div>",
      "</section>",
      issuerMetadataHtml(options),
      "</main>",
      "<script>",
      launcherScript(),
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
    '<form class="launcher-form session-launcher" data-endpoint="/sessions" data-session-page="/ui/sessions/" novalidate>',
    '<input type="hidden" data-param="issuer_configuration_id" data-type="string" value="',
    escapeHtml(issuer.id),
    '">',
    '<div class="credential-row">',
    '<label class="credential-picker">',
    '<span class="subsection-heading">Credential</span>',
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
    '<section class="page-section page-section-white" aria-labelledby="issuer-metadata-title">',
    '<div class="container">',
    sectionIntroHtml({
      tag: "h2",
      id: "issuer-metadata-title",
      title: "Metadata",
      paragraphsHtml: [
        "The metadata this issuer publishes. Each card opens the document in a new tab.",
      ],
    }),
    '<nav class="metadata-cards" aria-label="',
    escapeHtml(`${issuer.display.name} metadata`),
    '">',
    metadataCardHtml("Authorization server metadata", issuer.authorizationServerMetadataUrl),
    metadataCardHtml("OpenID4VCI credential issuer metadata", issuer.issuerMetadataUrl),
    federationEntityConfigurationUrl
      ? metadataCardHtml("OpenID Federation entity configuration", federationEntityConfigurationUrl)
      : "",
    group.attestbook
      ? metadataCardHtml("Attestbook status", "/integrations/attestbook/status")
      : "",
    "</nav>",
    "</div>",
    "</section>",
  ].join("");
}

function metadataCardHtml(label: string, href: string): string {
  return entityCardHtml(
    href,
    [`<h3>${escapeHtml(label)}</h3>`, `<p class="metadata-card-url">${escapeHtml(href)}</p>`],
    { className: "metadata-card", newTab: true },
  );
}
