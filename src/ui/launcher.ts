import type { AttestbookIssuerSummary } from "../attestbook/types.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { SupportedCredential } from "../credentials/catalogue.js";
import type { JsonRecord } from "../types.js";
import { API_DOCS_URL, OPENAPI_URL, REPOSITORY_URL, escapeHtml, htmlPage } from "./html.js";
import { launcherScript } from "./scripts.js";
import {
  type IssuanceParameterValues,
  type PresentationParameterValues,
  advancedSettingsHtml,
  issuanceParameterGroups,
  parameterGroupsHtml,
  presentationParameterGroups,
  statusListOptionHtml,
} from "./session-parameters.js";

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
interface CredentialChoice {
  readonly credential: SupportedCredential;
  readonly dcqlQuery: JsonRecord;
}

export interface IssuerCredentialChoices {
  readonly issuer: ResolvedIssuerConfiguration;
  readonly credentials: readonly CredentialChoice[];
  /** Present for an issuer that imports Attestbook credentials. */
  readonly attestbook?: AttestbookIssuerSummary;
}

export interface IndexPageOptions {
  readonly groups: readonly IssuerCredentialChoices[];
  readonly fcafScenariosEnabled: boolean;
  readonly issuanceParameters: IssuanceParameterValues;
  readonly presentationParameters: PresentationParameterValues;
  /** Absent when OpenID Federation is disabled. */
  readonly federationEntityConfigurationUrl?: (issuer: ResolvedIssuerConfiguration) => string;
}

export function indexPage(options: IndexPageOptions): string {
  return htmlPage({
    title: "Wallet Metadata Capture",
    body: [
      launcherTopbarHtml(),
      "<main>",
      heroSectionHtml({
        id: "hero-title",
        title: "Wallet metadata capture",
        paragraphsHtml: [
          "Step 1) Start a one-time issuance flow, scan the offer, and inspect the wallet identifiers, callbacks, and proof keys observed by the issuer.",
          "Step 2) After receiving the credential, start a Presentation session, and inspect the Wallet response as well as the DCQL",
        ],
      }),
      '<section class="page-section" aria-labelledby="launcher-title">',
      '<div class="container">',
      sectionIntroHtml({
        tag: "h2",
        id: "launcher-title",
        title: "Issue and verify",
        paragraphsHtml: [
          "Choose a flow and a credential, then start a session. Advanced follows the flow and the credential you choose.",
        ],
      }),
      sessionLauncherHtml(options),
      "</div>",
      "</section>",
      capturedValuesHtml(),
      "</main>",
      "<script>",
      launcherScript(),
      "</script>",
    ].join(""),
  });
}

/**
 * One form for both flows. The flow switch picks the endpoint and which settings apply: the other
 * flow's settings are hidden, disabled fieldsets, so they are never sent. An issuance takes its
 * issuer and credential configuration from the selected option, whose issuer's links are shown.
 */
function sessionLauncherHtml(options: IndexPageOptions): string {
  const { groups, fcafScenariosEnabled, issuanceParameters, presentationParameters } = options;
  const empty = groups.every((group) => group.credentials.length === 0);
  return [
    '<form class="launcher-form session-launcher" novalidate>',
    launcherRowHtml(
      [
        '<div class="flow-switch">',
        '<span class="subsection-heading" id="flow-label">Flow</span>',
        '<div class="segmented" role="radiogroup" aria-labelledby="flow-label">',
        flowChoiceHtml("issuance", "Issue", "/sessions", "/ui/sessions/", true),
        flowChoiceHtml("presentation", "Present", "/openid4vp/sessions", "/ui/openid4vp/sessions/"),
        "</div>",
        "</div>",
        '<label class="credential-picker">',
        '<span class="subsection-heading">Credential</span>',
        // The first credential is preselected, so Start always has a target.
        '<select data-credential-picker autocomplete="off">',
        empty
          ? '<option value="">No credentials available</option>'
          : groups.map(credentialGroupHtml).join(""),
        "</select>",
        "</label>",
      ].join(""),
      "Start",
      empty,
    ),
    advancedSettingsHtml(
      [
        '<fieldset class="flow-settings" data-flow="issuance">',
        '<input type="hidden" data-param="issuer_configuration_id" data-type="string" data-option="issuer">',
        '<input type="hidden" data-param="credential_configuration_id" data-type="string" data-option="credential">',
        statusListOptionHtml(),
        parameterGroupsHtml(issuanceParameterGroups(issuanceParameters, fcafScenariosEnabled)),
        issuerLinksGroupHtml(options),
        "</fieldset>",
        '<fieldset class="flow-settings" data-flow="presentation" hidden disabled>',
        parameterGroupsHtml(
          presentationParameterGroups(presentationParameters, fcafScenariosEnabled),
        ),
        '<div class="parameter-group">',
        '<p class="parameter-group-title">Verifier information</p>',
        `<nav class="metadata-cards" aria-label="Verifier links">${metadataCardHtml("Verifier page", VERIFIER_PAGE_PATH)}</nav>`,
        "</div>",
        "</fieldset>",
      ].join(""),
    ),
    "</form>",
  ].join("");
}

/**
 * The selected credential's issuer, last in the issuance settings: its page and the documents it
 * publishes. Each issuer has its own set of cards, and only the selected credential's issuer's is
 * shown.
 */
function issuerLinksGroupHtml({
  groups,
  federationEntityConfigurationUrl,
}: IndexPageOptions): string {
  if (groups.length === 0) return "";
  return [
    '<div class="parameter-group">',
    '<p class="parameter-group-title">Issuer information</p>',
    groups
      .map(({ issuer, attestbook }, index) =>
        [
          `<nav class="metadata-cards" data-issuer-links="${escapeHtml(issuer.id)}" aria-label="`,
          escapeHtml(`${issuerLabel(issuer)} links`),
          index === 0 ? '">' : '" hidden>',
          issuerMetadataCardsHtml(issuer, {
            issuerPage: true,
            federationEntityConfigurationUrl: federationEntityConfigurationUrl?.(issuer),
            attestbook: attestbook !== undefined,
          }),
          "</nav>",
        ].join(""),
      )
      .join(""),
    "</div>",
  ].join("");
}

function flowChoiceHtml(
  flow: "issuance" | "presentation",
  label: string,
  endpoint: string,
  sessionPage: string,
  checked = false,
): string {
  return [
    `<label><input type="radio" name="session-flow" value="${flow}" data-flow-choice`,
    ` data-endpoint="${endpoint}" data-session-page="${sessionPage}" autocomplete="off"`,
    checked ? " checked" : "",
    `><span>${label}</span></label>`,
  ].join("");
}

/** The page's opening section: the brand-blue band with its title and description. */
export function heroSectionHtml(options: {
  id: string;
  title: string;
  paragraphsHtml: readonly string[];
}): string {
  return [
    `<section class="page-section hero-band" aria-labelledby="${options.id}">`,
    '<div class="hero-inner">',
    sectionIntroHtml({ tag: "h1", ...options }),
    "</div>",
    "</section>",
  ].join("");
}

/** Every page section opens the same way: its title over a rule, then its description. */
export function sectionIntroHtml(options: {
  tag: "h1" | "h2";
  id: string;
  title: string;
  /** Shown at the end of the title row, such as a count. */
  aside?: string;
  /** Each paragraph's content as HTML, so it may carry links and code; escape any dynamic text. */
  paragraphsHtml: readonly string[];
}): string {
  const { tag, id, title, aside, paragraphsHtml } = options;
  return [
    '<header class="section-intro">',
    '<div class="section-intro-heading">',
    `<${tag} class="section-intro-title" id="${id}">${escapeHtml(title)}</${tag}>`,
    aside ?? "",
    "</div>",
    '<div class="section-intro-description">',
    paragraphsHtml.map((paragraph) => `<p>${paragraph}</p>`).join(""),
    "</div>",
    "</header>",
  ].join("");
}

/** The documents an issuer publishes as cards; with `issuerPage`, its operator page comes first. */
export function issuerMetadataCardsHtml(
  issuer: ResolvedIssuerConfiguration,
  options: {
    issuerPage?: boolean;
    federationEntityConfigurationUrl?: string | undefined;
    attestbook: boolean;
  },
): string {
  return [
    options.issuerPage ? metadataCardHtml("Issuer page", issuer.issuerIdentifier) : "",
    metadataCardHtml("Authorization server metadata", issuer.authorizationServerMetadataUrl),
    metadataCardHtml("OpenID4VCI credential issuer metadata", issuer.issuerMetadataUrl),
    options.federationEntityConfigurationUrl
      ? metadataCardHtml(
          "OpenID Federation entity configuration",
          options.federationEntityConfigurationUrl,
        )
      : "",
    options.attestbook
      ? metadataCardHtml("Attestbook status", "/integrations/attestbook/status")
      : "",
  ].join("");
}

/** A card that opens `href` in a new tab; a target that is not a safe URL leaves it inert. */
function metadataCardHtml(label: string, href: string): string {
  const body = `<h3>${escapeHtml(label)}</h3><p class="metadata-card-url">${escapeHtml(href)}</p>`;
  return isSafeHref(href)
    ? `<a class="issuer-card metadata-card" href="${escapeHtml(href)}" target="_blank" rel="noreferrer">${body}</a>`
    : `<article class="issuer-card metadata-card">${body}</article>`;
}

/**
 * The values each session page shows beside its QR code, then what a session records beyond them;
 * the last section. The fields named here are the session pages' and the session records'.
 */
function capturedValuesHtml(): string {
  return [
    '<section class="page-section page-section-white" aria-labelledby="captured-values-title">',
    '<div class="container">',
    sectionIntroHtml({
      tag: "h2",
      id: "captured-values-title",
      title: "Captured values",
      aside: '<span class="count-chip">11</span>',
      paragraphsHtml: [
        "The values each session page shows live beside its QR code, as the wallet sends them. They are a summary: every session records the whole flow, listed below.",
      ],
    }),
    '<div class="capture-groups">',
    '<section class="capture-group" aria-label="OpenID4VCI captured values">',
    '<h3 class="subsection-heading">OpenID4VCI</h3>',
    '<dl class="capture-list">',
    "<div><dt>client_id</dt><dd>Wallet OAuth client identifier</dd></div>",
    "<div><dt>redirect_uri</dt><dd>Wallet authorization callback</dd></div>",
    "<div><dt>wallet_jwks</dt><dd>Holder-binding public key from proof headers</dd></div>",
    "<div><dt>dpop_jwk</dt><dd>DPoP public key when present</dd></div>",
    "<div><dt>wallet_notification</dt><dd>Issuance outcome the wallet reports, when it sends one</dd></div>",
    "</dl>",
    "</section>",
    '<section class="capture-group" aria-label="OpenID4VP captured values">',
    '<h3 class="subsection-heading">OpenID4VP</h3>',
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
    '<section class="capture-more" aria-labelledby="capture-more-title">',
    '<h3 class="subsection-heading" id="capture-more-title">Also recorded</h3>',
    '<p class="capture-more-intro">Read a session’s full record from <code>GET /sessions/{sessionId}</code> or <code>GET /openid4vp/sessions/{sessionId}</code>, and every request an issuer received from <code>GET /sessions/{sessionId}/requests</code>. Secrets such as tokens and codes stay redacted.</p>',
    '<div class="capture-more-groups">',
    '<section class="capture-group" aria-label="Also recorded for OpenID4VCI">',
    '<h3 class="subsection-heading">OpenID4VCI</h3>',
    '<ul class="capture-more-list">',
    "<li>Every HTTP request the wallet sends to the issuer: PAR, authorization, token, nonce, credential, and notification, with headers and body</li>",
    "<li>Client authentication: the Wallet Attestation and its proof of possession, or <code>private_key_jwt</code></li>",
    "<li>Credential Request proofs and key attestations, with checks for PKCE, state, nonce, and key attestation</li>",
    "<li>The Token Status List reference of each issued credential, and every later status change</li>",
    "<li>A timeline of the session’s events</li>",
    "</ul>",
    "</section>",
    '<section class="capture-group" aria-label="Also recorded for OpenID4VP">',
    '<h3 class="subsection-heading">OpenID4VP</h3>',
    '<ul class="capture-more-list">',
    "<li>The request object as signed, and encrypted when asked, and the deeplink parameters delivered</li>",
    "<li>Request URI retrieval, including the <code>wallet_metadata</code> and <code>wallet_nonce</code> of a POST</li>",
    "<li>The raw and decrypted Authorization Response, and the HTTP reply the wallet received</li>",
    "<li>Verification checks: nonce, holder binding, DCQL match, and transaction data</li>",
    "<li>Redirect URI visits, Digital Credentials API invocations, and a timeline of the session’s events</li>",
    "</ul>",
    "</section>",
    "</div>",
    "</section>",
    "</div>",
    "</section>",
  ].join("");
}
export function launcherTopbarHtml(): string {
  return [
    '<header class="topbar">',
    '<div class="topbar-inner">',
    '<a class="brand-lockup" href="/">',
    '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="Credimi">',
    '<span class="brand-name">Wallet metadata capture</span>',
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

/** Everything the form needs from the selected credential, carried by the option itself. */
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
    // An mdoc has no SD-JWT disclosure digest.
    ' data-format="',
    escapeHtml(credential.format),
    '">',
    escapeHtml(credentialLabel(credential)),
    "</option>",
  ].join("");
}

/** The active rulebook version and the last synchronization's outcome, as one sentence. */
export function attestbookSummaryText(summary: AttestbookIssuerSummary): string {
  const active =
    summary.activeVersion && summary.activeContentDigest
      ? `Attestbook rulebook version ${summary.activeVersion} (sha-256 ${summary.activeContentDigest.slice(0, 12)}…) is active`
      : "No Attestbook rulebook version is active";
  const sync = summary.failureStage
    ? `last synchronization failed at the ${summary.failureStage} stage`
    : `synchronization ${summary.syncState}`;
  return `${active}; ${sync}.`;
}

export function issuerDescriptionHtml(issuer: ResolvedIssuerConfiguration): string {
  if (issuer.compliance !== "eudi-pid-device-bound") {
    return escapeHtml(issuer.display.description);
  }

  return [
    "Conformant to ",
    `<a href="${REGULATION_2026_1731_URL}" target="_blank" rel="noreferrer">Commission Implementing Regulation (EU) 2026/1731</a>`,
    ", in particular <code>TR_KA-4</code>: both <code>jwt</code> and ",
    "<code>attestation</code> proof types are present and both include ",
    "<code>key_attestations_required</code>.",
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
 * A form's first row: its pickers, then the submit button on the right, then the box the API's
 * refusal is shown in.
 */
export function launcherRowHtml(pickersHtml: string, label: string, disabled: boolean): string {
  return [
    '<div class="launcher-row">',
    pickersHtml,
    `<button class="btn btn-primary btn-lg" type="submit" autocomplete="off"${disabled ? " disabled" : ""}>`,
    escapeHtml(label),
    "</button>",
    "</div>",
    '<pre class="launcher-error" role="alert" data-launcher-error hidden></pre>',
  ].join("");
}

export function credentialLabel(credential: SupportedCredential): string {
  return credential.attestbook
    ? `${credential.displayName} (Attestbook ${credential.attestbook.version})`
    : credential.displayName;
}
