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
  /** Present for an issuer that imports Attestbook credentials. */
  readonly attestbook?: AttestbookIssuerSummary;
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
 * One credential picker over every issuer: the session buttons create a session with the API
 * defaults, and each card opens the issuer or verifier page, which carries every other parameter.
 */
export function indexPage(groups: readonly IssuerCredentialChoices[]): string {
  const empty = groups.every((group) => group.credentials.length === 0);
  return htmlPage({
    title: "Wallet Metadata Capture",
    body: [
      launcherTopbarHtml(),
      "<main>",
      '<section class="hero-band">',
      '<div class="hero-inner">',
      '<div class="hero-copy">',
      "<h1>Wallet metadata capture</h1>",
      "<p>Step 1) Start a one-time issuance flow, scan the offer, and inspect the wallet identifiers, callbacks, and proof keys observed by the issuer.</p>",
      "<p>Step 2) After receiving the credential, start a Presentation session, and inspect the Wallet response as well as the DCQL</p>",
      '<div class="launcher-panel" data-launcher>',
      '<div class="credential-row">',
      '<label class="credential-picker">',
      "<span>Credential</span>",
      // The first credential is preselected, so every action always has a target.
      '<select data-credential-choice autocomplete="off">',
      empty
        ? '<option value="">No credentials available</option>'
        : groups.map(credentialGroupHtml).join(""),
      "</select>",
      "</label>",
      '<label class="status-list-toggle">',
      '<input type="checkbox" role="switch" data-status-list-toggle>',
      '<span class="toggle-track" aria-hidden="true"></span>',
      "<span>Include a Token Status List reference</span>",
      "</label>",
      "</div>",
      '<div class="session-actions">',
      `<button class="btn btn-primary btn-lg" type="button" autocomplete="off" data-issue${empty ? " disabled" : ""}>New issuance session</button>`,
      `<button class="btn btn-outline btn-lg" type="button" autocomplete="off" data-verify${empty ? " disabled" : ""}>New presentation session</button>`,
      "</div>",
      '<pre class="launcher-error" role="alert" data-launcher-error hidden></pre>',
      "</div>",
      entityCatalogueHtml(groups),
      "</div>",
      capturedValuesHtml(),
      "</div>",
      "</section>",
      "</main>",
      "<script>",
      launcherScript(),
      "</script>",
    ].join(""),
  });
}

/**
 * The issuer cards and the verifier card share one grid, so every card is the same size. Card rows
 * are `1fr`, which in a grid of unconstrained height makes each as tall as the tallest card, while
 * the heading rows keep their own height; the row counts for the two-column and the one-column
 * layout are passed to the stylesheet.
 */
function entityCatalogueHtml(groups: readonly IssuerCredentialChoices[]): string {
  // An empty catalogue still holds one row: its "No issuers available" notice.
  const issuerRows = Math.max(groups.length, 1);
  return [
    `<section class="entity-catalogue" aria-label="Issuers and verifier" style="--issuer-rows-wide: ${Math.ceil(issuerRows / 2)}; --issuer-rows-narrow: ${issuerRows}">`,
    '<h2 id="issuer-catalogue-title">Issuers</h2>',
    groups.length > 0
      ? groups.map(issuerCardHtml).join("")
      : '<p class="issuer-empty">No issuers available</p>',
    '<h2 id="verifier-catalogue-title">Verifier</h2>',
    entityCardHtml(VERIFIER_PAGE_PATH, [
      "<h3>OpenID4VP verifier</h3>",
      '<p class="issuer-description">Requests a presentation of any credential the issuers above serve, and verifies it.</p>',
    ]),
    "</section>",
  ].join("");
}

function issuerCardHtml(group: IssuerCredentialChoices): string {
  const { issuer } = group;
  return entityCardHtml(issuer.issuerIdentifier, [
    "<h3>",
    escapeHtml(issuerLabel(issuer)),
    "</h3>",
    '<p class="issuer-description">',
    // The whole card is a link, which cannot contain another one.
    issuerDescriptionHtml(issuer, false),
    "</p>",
    group.attestbook ? attestbookSummaryHtml(group.attestbook) : "",
  ]);
}

/** A card that opens `href` when clicked; a target that is not a safe URL leaves it inert. */
function entityCardHtml(href: string, content: readonly string[]): string {
  const body = content.join("");
  return isSafeHref(href)
    ? `<a class="issuer-card" href="${escapeHtml(href)}">${body}</a>`
    : `<article class="issuer-card">${body}</article>`;
}

/** What a session records about the Wallet, named as on the session pages. */
function capturedValuesHtml(): string {
  return [
    '<aside class="card launcher-card" aria-labelledby="captured-values-title">',
    '<div class="section-head">',
    '<h2 id="captured-values-title">Captured values</h2>',
    '<span class="count-chip">10</span>',
    "</div>",
    '<div class="capture-groups">',
    '<section class="capture-group" aria-label="OpenID4VCI captured values">',
    "<h3>OpenID4VCI</h3>",
    '<dl class="capture-list">',
    "<div><dt>client_id</dt><dd>Wallet OAuth client identifier</dd></div>",
    "<div><dt>redirect_uri</dt><dd>Wallet authorization callback</dd></div>",
    "<div><dt>wallet_jwks</dt><dd>Holder-binding public key from proof headers</dd></div>",
    "<div><dt>dpop_jwk</dt><dd>DPoP public key when present</dd></div>",
    "</dl>",
    "</section>",
    '<section class="capture-group" aria-label="OpenID4VP captured values">',
    "<h3>OpenID4VP</h3>",
    '<dl class="capture-list">',
    "<div><dt>authorization_request</dt><dd>Verifier request object sent to the wallet</dd></div>",
    "<div><dt>request_uri_payload</dt><dd>Wallet payload when request_uri_method is post</dd></div>",
    "<div><dt>wallet_response</dt><dd>Wallet presentation response including vp_token</dd></div>",
    "<div><dt>presentation_response_decrypted</dt><dd>Decrypted wallet presentation response</dd></div>",
    "<div><dt>decoded_presentations</dt><dd>Credo-decoded claims from verified presentations</dd></div>",
    "<div><dt>presentation_validation</dt><dd>Verifier checks for nonce, holder binding, and DCQL matching</dd></div>",
    "</dl>",
    "</section>",
    "</div>",
    "</aside>",
  ].join("");
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

/** Everything the session buttons need, carried by the option itself. */
function credentialOptionHtml(
  issuer: ResolvedIssuerConfiguration,
  { credential, dcqlQuery }: CredentialChoice,
): string {
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
    ">",
    escapeHtml(credentialLabel(credential)),
    "</option>",
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

export function issuerDescriptionHtml(
  issuer: ResolvedIssuerConfiguration,
  linkRegulation = true,
): string {
  if (issuer.compliance !== "eudi-pid-device-bound") {
    return escapeHtml(issuer.display.description);
  }

  const regulation = "Commission Implementing Regulation (EU) 2026/1731";
  return [
    "Conformant to ",
    linkRegulation
      ? `<a href="${REGULATION_2026_1731_URL}" target="_blank" rel="noreferrer">${regulation}</a>`
      : regulation,
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
  if (!isSafeHref(href)) {
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

/** Only HTTP(S) URLs and same-origin paths become link targets; `javascript:` and the like never. */
function isSafeHref(value: string): boolean {
  if (value.startsWith("/")) return true;
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
