import { TOKEN_STATUS_LIST_URL, escapeHtml } from "./html.js";

/** Allowed values of the `POST /sessions` parameters the operator UI offers as choices. */
export interface IssuanceParameterValues {
  readonly flows: readonly string[];
  readonly credentialOfferModes: readonly string[];
  readonly offerSchemes: readonly string[];
  readonly fixtureIds: readonly string[];
  readonly digestAlgorithms: readonly string[];
  readonly evidenceModes: readonly string[];
  readonly statusReferences: readonly string[];
}

/** Allowed values of the `POST /openid4vp/sessions` parameters the operator UI offers. */
export interface PresentationParameterValues {
  readonly responseModes: readonly string[];
  readonly requestDeliveries: readonly string[];
  readonly clientIdSchemes: readonly string[];
}

/**
 * When a parameter applies: `static-credential` fields are refused by the API for an imported
 * Attestbook credential, and `sd-jwt` fields for an mdoc.
 */
type ParameterRequirement = "static-credential" | "sd-jwt";

interface ParameterField {
  /** The API body member; `merge` fields are an object merged into the body instead. */
  readonly name: string;
  readonly label: string;
  readonly kind: "select" | "text" | "json" | "flag" | "merge";
  readonly values?: readonly string[];
  readonly hint?: string;
  readonly placeholder?: string;
  /** The value a `flag` sends when checked, as JSON. */
  readonly flagValue?: "true" | "null";
  readonly requires?: ParameterRequirement;
}

export interface ParameterGroup {
  readonly legend: string;
  readonly fields: readonly ParameterField[];
}

/** Every `POST /sessions` parameter the operator can set, the test-only ones with FCAF scenarios. */
export function issuanceParameterGroups(
  parameters: IssuanceParameterValues,
  fcafScenariosEnabled: boolean,
): ParameterGroup[] {
  return [
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
                hint: "Anything but valid needs a Token Status List reference.",
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
}

/**
 * Every `POST /openid4vp/sessions` parameter the operator can set, the test-only ones with FCAF
 * scenarios. The DCQL query is filled from the selected credential.
 */
export function presentationParameterGroups(
  parameters: PresentationParameterValues,
  fcafScenariosEnabled: boolean,
): ParameterGroup[] {
  return [
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
}

function additionalParametersField(placeholder: string): ParameterField {
  return {
    name: "additional_parameters",
    label: "Additional body members",
    kind: "merge",
    placeholder,
    hint: "A JSON object merged into the request body last, overriding the fields above.",
  };
}

/** The collapsed panel holding the settings, such as the parameter groups. */
export function advancedSettingsHtml(contentHtml: string): string {
  return [
    '<details class="advanced-settings">',
    "<summary>Advanced</summary>",
    '<p class="field-hint">Every field left empty takes the API default.</p>',
    contentHtml,
    "</details>",
  ].join("");
}

/**
 * The Token Status List option, on by default and set apart above the issuance parameter groups.
 * The API refuses it for an imported Attestbook credential, so it is disabled for one.
 */
export function statusListOptionHtml(): string {
  return [
    '<div class="featured-option">',
    '<label class="featured-option-toggle">',
    '<input type="checkbox" role="switch" value="true" data-param="status_list_enabled" data-type="flag" data-requires="static-credential" checked>',
    '<span class="toggle-track" aria-hidden="true"></span>',
    '<span class="featured-option-label">Include a Token Status List reference <code>status_list_enabled</code></span>',
    "</label>",
    '<p class="field-hint">Each issued credential gets an entry in a Token Status List, so its status can be checked. Imported Attestbook credentials do not support one. ',
    `<a href="${escapeHtml(TOKEN_STATUS_LIST_URL)}" target="_blank" rel="noreferrer">Token Status List service ↗</a>`,
    "</p>",
    "</div>",
  ].join("");
}

export function parameterGroupsHtml(groups: readonly ParameterGroup[]): string {
  return groups.map(parameterGroupHtml).join("");
}

function parameterGroupHtml(group: ParameterGroup): string {
  return [
    '<fieldset class="parameter-group">',
    "<legend>",
    escapeHtml(group.legend),
    "</legend>",
    '<div class="parameter-fields">',
    group.fields.map(parameterFieldHtml).join(""),
    "</div>",
    "</fieldset>",
  ].join("");
}

function parameterFieldHtml(field: ParameterField): string {
  const type = field.kind === "select" || field.kind === "text" ? "string" : field.kind;
  const attributes = [
    ` data-param="${escapeHtml(field.name)}"`,
    ` data-type="${type}"`,
    field.requires ? ` data-requires="${field.requires}"` : "",
    field.placeholder ? ` placeholder="${escapeHtml(field.placeholder)}"` : "",
  ].join("");
  const hint = field.hint ? `<span class="field-hint">${escapeHtml(field.hint)}</span>` : "";
  const label = [
    '<span class="field-label">',
    escapeHtml(field.label),
    field.kind === "merge" ? "" : ` <code>${escapeHtml(field.name)}</code>`,
    "</span>",
  ].join("");

  if (field.kind === "flag") {
    return [
      '<label class="field field-flag">',
      `<input type="checkbox" value="${field.flagValue ?? "true"}"${attributes}>`,
      label,
      hint,
      "</label>",
    ].join("");
  }

  const control =
    field.kind === "select"
      ? [
          `<select${attributes}>`,
          '<option value="">API default</option>',
          (field.values ?? [])
            .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)
            .join(""),
          "</select>",
        ].join("")
      : field.kind === "text"
        ? `<input type="text" autocomplete="off" spellcheck="false"${attributes}>`
        : `<textarea rows="4" spellcheck="false"${attributes}></textarea>`;
  const className = field.kind === "json" || field.kind === "merge" ? "field field-wide" : "field";
  return [`<label class="${className}">`, label, control, hint, "</label>"].join("");
}
