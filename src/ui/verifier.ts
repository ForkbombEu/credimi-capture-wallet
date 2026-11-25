import { escapeHtml, htmlPage } from "./html.js";
import {
  additionalParametersField,
  advancedSettingsHtml,
  credentialLabel,
  heroSectionHtml,
  issuerLabel,
  launcherActionsHtml,
  launcherTopbarHtml,
  sectionIntroHtml,
} from "./launcher.js";
import type { IssuerCredentialChoices, ParameterGroup } from "./launcher.js";
import { launcherScript } from "./scripts.js";
/** Allowed values of the `POST /openid4vp/sessions` parameters the verifier page offers. */
interface PresentationParameterValues {
  readonly responseModes: readonly string[];
  readonly requestDeliveries: readonly string[];
  readonly clientIdSchemes: readonly string[];
}

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
          "Choose a credential and create a session. Advanced settings expose every parameter of <code>POST /openid4vp/sessions</code>; the DCQL query follows the chosen credential until you edit it.",
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
  const parameterGroups: ParameterGroup[] = [
    {
      legend: "Query",
      fields: [
        {
          name: "dcql_query",
          label: "DCQL query",
          kind: "json",
          hint: "Filled from the selected credential until edited. Empty sends the API default query; null omits the parameter from the wallet-facing request.",
        },
        {
          name: "transaction_data",
          label: "Transaction data",
          kind: "json",
          placeholder: '["…"]',
        },
        { name: "verifier_info", label: "Verifier info", kind: "json" },
        { name: "scopes", label: "Scopes", kind: "text" },
        {
          name: "state",
          label: "Omit state from the request",
          kind: "flag",
          flagValue: "null",
        },
      ],
    },
    {
      legend: "Request delivery",
      fields: [
        {
          name: "response_mode",
          label: "Response mode",
          kind: "select",
          values: parameters.responseModes,
        },
        {
          name: "response_type",
          label: "Response type",
          kind: "select",
          values: ["vp_token", "vp_token id_token", "code"],
        },
        {
          name: "request_delivery",
          label: "Request delivery",
          kind: "select",
          values: parameters.requestDeliveries,
          hint: "multisigned needs a DC API response mode.",
        },
        {
          name: "request_uri_method",
          label: "request_uri_method",
          kind: "select",
          values: ["get", "post"],
          hint: "by_reference delivery only.",
        },
        {
          name: "client_id_scheme",
          label: "Client Identifier prefix",
          kind: "select",
          values: parameters.clientIdSchemes,
        },
        {
          name: "scheme",
          label: "Deeplink scheme",
          kind: "text",
          placeholder: "openid4vp://",
        },
      ],
    },
    {
      legend: "Verifier metadata and redirect",
      fields: [
        {
          name: "client_metadata",
          label: "Client metadata",
          kind: "json",
          hint: "Members override the generated verifier metadata; null omits it.",
        },
        {
          name: "allow_undecryptable_response",
          label: "Publish client metadata without the verifier encryption key",
          kind: "flag",
          flagValue: "true",
        },
        {
          name: "verifier_attestation",
          label: "Verifier attestation",
          kind: "json",
          placeholder: '{"redirect_uris": ["https://wallet.example/callback"]}',
          hint: "Needs the verifier_attestation prefix.",
        },
        {
          name: "redirect_uri",
          label: "Redirect URI",
          kind: "text",
          placeholder: "{{base_url}}/openid4vp/redirect",
          hint: "Not available with a DC API response mode.",
        },
      ],
    },
    ...(fcafScenariosEnabled
      ? [
          {
            legend: "Test scenarios (FCAF)",
            fields: [
              {
                name: "request_mutation",
                label: "Request mutation",
                kind: "json",
                placeholder: '{"request_object": {"unset": ["/response_uri"]}}',
              },
              {
                name: "request_behavior",
                label: "Request behaviour",
                kind: "json",
                placeholder: '{"signature": "corrupt"}',
              },
              {
                name: "response_scenario",
                label: "Response scenario",
                kind: "json",
                placeholder: '{"status": 400}',
              },
            ],
          } satisfies ParameterGroup,
        ]
      : []),
    {
      legend: "Raw request",
      fields: [
        {
          name: "presentation_request",
          label: "Presentation request",
          kind: "json",
          hint: "Replaces every request parameter of the Query group.",
        },
        additionalParametersField('{"nonce": "…"}'),
      ],
    },
  ];
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
    advancedSettingsHtml(parameterGroups),
    launcherActionsHtml("Create presentation session", empty),
    "</form>",
  ].join("");
}
