import type { SupportedCredential } from "../credentials/catalogue.js";
import { escapeHtml, htmlPage } from "./html.js";
import type { IssuerCredentialGroup } from "./launcher.js";
import {
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
import { launcherScript } from "./scripts.js";
import {
  type IssuanceParameterValues,
  advancedSettingsHtml,
  issuanceParameterGroups,
  parameterGroupsHtml,
} from "./session-parameters.js";

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
    "</div>",
    advancedSettingsHtml(
      parameterGroupsHtml(issuanceParameterGroups(parameters, fcafScenariosEnabled)),
    ),
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
