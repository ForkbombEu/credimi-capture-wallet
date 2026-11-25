import { escapeHtml, htmlPage } from "./html.js";
import {
  credentialLabel,
  heroSectionHtml,
  issuerLabel,
  launcherActionsHtml,
  launcherTopbarHtml,
  sectionIntroHtml,
} from "./launcher.js";
import type { IssuerCredentialChoices } from "./launcher.js";
import { launcherScript } from "./scripts.js";
import {
  type PresentationParameterValues,
  advancedSettingsHtml,
  parameterGroupsHtml,
  presentationParameterGroups,
} from "./session-parameters.js";

export interface VerifierPageOptions {
  readonly groups: readonly IssuerCredentialChoices[];
  readonly fcafScenariosEnabled: boolean;
  readonly parameters: PresentationParameterValues;
}
/**
 * The operator page of the OpenID4VP verifier. Each credential choice carries the DCQL query the
 * session is created with, so a credential any issuer serves can be requested through the public
 * `POST /openid4vp/sessions` API without a verifier-side catalogue lookup.
 */
export function verifierPage(options: VerifierPageOptions): string {
  return htmlPage({
    title: "OpenID4VP verifier",
    body: [
      launcherTopbarHtml(),
      "<main>",
      heroSectionHtml({
        id: "verifier-title",
        title: "OpenID4VP verifier",
        paragraphsHtml: [
          "Choose the credential to request, scan the presentation request with the wallet, and inspect the response, its decoded claims, and the verifier checks.",
        ],
      }),
      '<section class="page-section" aria-labelledby="request-title">',
      '<div class="container">',
      sectionIntroHtml({
        tag: "h2",
        id: "request-title",
        title: "Request a presentation",
        paragraphsHtml: [
          "Choose a credential and create a session. Advanced exposes every parameter of <code>POST /openid4vp/sessions</code>; the DCQL query follows the chosen credential until you edit it.",
        ],
      }),
      presentationFormHtml(options),
      "</div>",
      "</section>",
      "</main>",
      "<script>",
      launcherScript(),
      "</script>",
    ].join(""),
  });
}
function verifierCredentialGroupHtml(group: IssuerCredentialChoices): string {
  return [
    '<optgroup label="',
    escapeHtml(issuerLabel(group.issuer)),
    '">',
    group.credentials
      .map(({ credential, dcqlQuery }) =>
        [
          '<option value="',
          escapeHtml(credential.id),
          '" data-dcql="',
          escapeHtml(JSON.stringify(dcqlQuery)),
          '">',
          escapeHtml(credentialLabel(credential)),
          "</option>",
        ].join(""),
      )
      .join(""),
    "</optgroup>",
  ].join("");
}
function presentationFormHtml({
  groups,
  fcafScenariosEnabled,
  parameters,
}: VerifierPageOptions): string {
  const empty = groups.every((group) => group.credentials.length === 0);

  return [
    '<form class="launcher-form session-launcher" data-endpoint="/openid4vp/sessions" data-session-page="/ui/openid4vp/sessions/" novalidate>',
    '<div class="credential-row">',
    '<label class="credential-picker">',
    '<span class="subsection-heading">Credential</span>',
    "<select data-credential-picker>",
    groups.map(verifierCredentialGroupHtml).join(""),
    "</select>",
    "</label>",
    "</div>",
    advancedSettingsHtml(
      parameterGroupsHtml(presentationParameterGroups(parameters, fcafScenariosEnabled)),
    ),
    launcherActionsHtml("Create presentation session", empty),
    "</form>",
  ].join("");
}
