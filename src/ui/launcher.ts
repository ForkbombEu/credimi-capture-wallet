import type { AttestbookIssuerSummary } from "../attestbook/types.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { SupportedCredential } from "../credentials/catalogue.js";
import type { JsonRecord } from "../types.js";
import { API_DOCS_URL, OPENAPI_URL, REPOSITORY_URL, escapeHtml, htmlPage } from "./html.js";
import { launcherScript } from "./scripts.js";

const REGULATION_2026_1731_URL =
  "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731";
export const VERIFIER_PAGE_PATH = "/openid4vp";

export interface IssuerCredentialGroup {
  issuer: ResolvedIssuerConfiguration;
  credentials: readonly SupportedCredential[];
  /** Present for an issuer that imports Attestbook credentials. */
  attestbook?: AttestbookIssuerSummary;
}

/** A credential an issuer serves, with the DCQL query the verifier requests it with. */
export interface CredentialChoice {
  readonly credential: SupportedCredential;
  readonly dcqlQuery: JsonRecord;
}

export interface IssuerCredentialChoices {
  readonly issuer: ResolvedIssuerConfiguration;
  readonly credentials: readonly CredentialChoice[];
}

/**
 * The fragment the issuer and verifier pages read to preselect a credential and open their
 * advanced settings, so the launcher can hand a choice over without a server-side parameter.
 */
export function credentialPreselectionFragment(credentialConfigurationId: string): string {
  return `#credential_configuration_id=${encodeURIComponent(credentialConfigurationId)}`;
}

/** Allowed values of the `POST /sessions` parameters the issuer page offers as choices. */
export interface IssuanceParameterValues {
  readonly flows: readonly string[];
  readonly credentialOfferModes: readonly string[];
  readonly offerSchemes: readonly string[];
  readonly fixtureIds: readonly string[];
  readonly digestAlgorithms: readonly string[];
  readonly evidenceModes: readonly string[];
  readonly statusReferences: readonly string[];
}
/**
 * One credential picker over every issuer: Issue and Verify create a session with the API
 * defaults, and the Customize links open the issuer or verifier page, which carry every other
 * parameter, with the chosen credential preselected.
 */
export function indexPage(groups: readonly IssuerCredentialChoices[]): string {
  const empty = groups.every((group) => group.credentials.length === 0);
  return htmlPage({
    title: "Wallet Metadata Capture",
    body: [
      launcherTopbarHtml(),
      '<main class="page-content session-page">',
      '<section class="session-header launcher-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VCI issuers and OpenID4VP verifier</p>',
      "<h1>Wallet metadata capture</h1>",
      '<p class="session-intro">Choose a credential, then issue it to a wallet or request its presentation. Every session captures the protocol evidence the wallet leaves behind.</p>',
      "</div>",
      "</section>",
      '<section class="launcher-layout container">',
      '<div class="card launcher-card" data-launcher>',
      '<div class="section-head">',
      "<h2>Issue or verify a credential</h2>",
      "</div>",
      '<div class="credential-row">',
      '<label class="credential-picker">',
      "<span>Credential</span>",
      '<select data-credential-choice autocomplete="off">',
      '<option value="" selected>',
      empty ? "No credentials available" : "Choose a credential…",
      "</option>",
      groups.map(credentialGroupHtml).join(""),
      "</select>",
      "</label>",
      '<label class="status-list-toggle">',
      '<input type="checkbox" role="switch" data-status-list-toggle>',
      '<span class="toggle-track" aria-hidden="true"></span>',
      "<span>Include a Token Status List reference</span>",
      "</label>",
      "</div>",
      '<div class="session-actions">',
      '<button class="btn btn-primary btn-lg" type="button" autocomplete="off" data-issue disabled>Issue</button>',
      '<button class="btn btn-outline btn-lg" type="button" autocomplete="off" data-verify disabled>Verify</button>',
      "</div>",
      '<nav class="launcher-links" aria-label="Customize">',
      '<a class="issuer-link" href="#issuer-chooser" data-customize-issuance>Customize issuance</a>',
      `<a class="issuer-link" href="${VERIFIER_PAGE_PATH}" data-customize-presentation>Customize presentation</a>`,
      "</nav>",
      issuerChooserHtml(groups),
      '<pre class="launcher-error" role="alert" data-launcher-error hidden></pre>',
      "</div>",
      "</section>",
      "</main>",
      "<script>",
      launcherScript(),
      "</script>",
    ].join(""),
  });
}
export function launcherTopbarHtml(): string {
  return [
    '<header class="topbar">',
    '<div class="topbar-inner">',
    '<a class="brand-lockup" href="/">',
    '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="Credimi">',
    "<span>Wallet metadata capture</span>",
    "</a>",
    '<div class="topbar-actions">',
    '<span class="status-chip status-issuer">ISSUER READY</span>',
    '<span class="status-chip status-wallet">VERIFIER READY</span>',
    '<a class="btn btn-outline btn-md" href="',
    API_DOCS_URL,
    '">API docs</a>',
    '<a class="btn btn-outline btn-md" href="',
    OPENAPI_URL,
    '" download="openapi.json">OpenAPI</a>',
    '<a class="btn btn-outline btn-md" href="',
    REPOSITORY_URL,
    '" target="_blank" rel="noreferrer">Repository</a>',
    "</div>",
    "</div>",
    "</header>",
  ].join("");
}
export function issuerLabel(issuer: ResolvedIssuerConfiguration): string {
  return issuer.compliance === "deliberately-nonconforming"
    ? `${issuer.display.name} — deliberately non-conforming`
    : issuer.compliance === "experimental"
      ? `${issuer.display.name} — experimental`
      : issuer.display.name;
}

function credentialGroupHtml({ issuer, credentials }: IssuerCredentialChoices): string {
  return [
    '<optgroup label="',
    escapeHtml(issuerLabel(issuer)),
    '">',
    credentials.map((choice) => credentialOptionHtml(issuer, choice)).join(""),
    "</optgroup>",
  ].join("");
}

/** Everything Issue, Verify, and the Customize links need, carried by the option itself. */
function credentialOptionHtml(
  issuer: ResolvedIssuerConfiguration,
  { credential, dcqlQuery }: CredentialChoice,
): string {
  const fragment = credentialPreselectionFragment(credential.id);
  return [
    '<option value="',
    escapeHtml(credential.id),
    '" data-issuer="',
    escapeHtml(issuer.id),
    '" data-dcql="',
    escapeHtml(JSON.stringify(dcqlQuery)),
    '"',
    // The API refuses a Token Status List for an imported Attestbook credential.
    credential.attestbook ? ' data-imported="true"' : "",
    isHttpUrl(issuer.issuerIdentifier)
      ? ` data-issuance-href="${escapeHtml(`${issuer.issuerIdentifier}${fragment}`)}"`
      : "",
    ` data-presentation-href="${escapeHtml(`${VERIFIER_PAGE_PATH}${fragment}`)}"`,
    ">",
    escapeHtml(credentialLabel(credential)),
    "</option>",
  ].join("");
}

/** Shown by Customize issuance while no credential is chosen; also the way to every issuer page. */
function issuerChooserHtml(groups: readonly IssuerCredentialChoices[]): string {
  return [
    '<div class="issuer-chooser" id="issuer-chooser" data-issuer-chooser hidden>',
    "<p>Choose the issuer to customize:</p>",
    groups.length > 0
      ? `<ul>${groups
          .map(
            ({ issuer }) =>
              `<li>${safeLinkHtml(issuerLabel(issuer), issuer.issuerIdentifier, "issuer-link")}</li>`,
          )
          .join("")}</ul>`
      : '<p class="issuer-empty">No issuers available</p>',
    "</div>",
  ].join("");
}

export function attestbookSummaryHtml(summary: AttestbookIssuerSummary): string {
  const active =
    summary.activeVersion && summary.activeContentDigest
      ? `Attestbook rulebook version ${summary.activeVersion} (sha-256 ${summary.activeContentDigest.slice(0, 12)}…) is active`
      : "No Attestbook rulebook version is active";
  const sync = summary.failureStage
    ? `last synchronization failed at the ${summary.failureStage} stage`
    : `synchronization ${summary.syncState}`;
  return `<p class="issuer-description">${escapeHtml(`${active}; ${sync}.`)}</p>`;
}

export function issuerDescriptionHtml(issuer: ResolvedIssuerConfiguration): string {
  if (issuer.compliance !== "eudi-pid-device-bound") {
    return escapeHtml(issuer.display.description);
  }

  return [
    "Conformant to ",
    '<a href="',
    REGULATION_2026_1731_URL,
    '" target="_blank" rel="noreferrer">',
    "Commission Implementing Regulation (EU) 2026/1731",
    "</a>",
    ", in particular <code>TR_KA-4</code>: both <code>jwt</code> and ",
    "<code>attestation</code> proof types are present and both include ",
    "<code>key_attestations_required</code>.",
  ].join("");
}

/** Renders a link, or plain text when the target is not an HTTP(S) URL or a same-origin path. */
export function safeLinkHtml(
  label: string,
  href: string,
  className: string,
  newTab = false,
): string {
  if (!isHttpUrl(href) && !href.startsWith("/")) {
    return `<span class="${className}">${escapeHtml(label)}: ${escapeHtml(href)}</span>`;
  }

  return [
    `<a class="${className}" href="`,
    escapeHtml(href),
    newTab ? '" target="_blank" rel="noreferrer">' : '">',
    escapeHtml(label),
    "</a>",
  ].join("");
}

function isHttpUrl(value: string): boolean {
  try {
    const protocol = new URL(value).protocol;
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * When a parameter applies: `static-credential` fields are refused by the API for an imported
 * Attestbook credential, and `sd-jwt` fields for an mdoc.
 */
type ParameterRequirement = "static-credential" | "sd-jwt";

export interface ParameterField {
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

export function additionalParametersField(placeholder: string): ParameterField {
  return {
    name: "additional_parameters",
    label: "Additional body members",
    kind: "merge",
    placeholder,
    hint: "A JSON object merged into the request body last, overriding the fields above.",
  };
}

export function launcherActionsHtml(label: string, disabled: boolean): string {
  return [
    '<div class="session-actions">',
    '<button class="btn btn-primary btn-lg" type="submit" autocomplete="off"',
    disabled ? " disabled" : "",
    ">",
    escapeHtml(label),
    "</button>",
    "</div>",
    '<pre class="launcher-error" role="alert" data-launcher-error hidden></pre>',
  ].join("");
}

export function advancedSettingsHtml(groups: readonly ParameterGroup[]): string {
  return [
    '<details class="advanced-settings">',
    "<summary>Advanced settings</summary>",
    '<p class="field-hint">Every field left empty takes the API default.</p>',
    groups.map(parameterGroupHtml).join(""),
    "</details>",
  ].join("");
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

export function credentialLabel(credential: SupportedCredential): string {
  return credential.attestbook
    ? `${credential.displayName} (Attestbook ${credential.attestbook.version})`
    : credential.displayName;
}
