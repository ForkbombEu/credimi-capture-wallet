import type { ResolvedIssuerConfiguration } from "./configurations/types.js";
import type { SupportedCredential } from "./metadata.js";
import type { JsonRecord, VpDcApiRequest } from "./types.js";

const REPOSITORY_URL = "https://github.com/ForkbombEu/credimi-capture-wallet";
const OPENAPI_URL = "/openapi.json";
const API_DOCS_URL = "/docs";
const REGULATION_2026_1731_URL =
  "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731";
export const VERIFIER_PAGE_PATH = "/openid4vp";

export interface IssuerCredentialGroup {
  issuer: ResolvedIssuerConfiguration;
  credentials: readonly SupportedCredential[];
  /** Present for an issuer that imports Attestbook credentials. */
  attestbook?: AttestbookIssuerSummary;
}

export interface AttestbookIssuerSummary {
  readonly syncState: string;
  readonly activeVersion: string | null;
  readonly activeContentDigest: string | null;
  readonly failureStage: string | null;
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

export interface IssuerPageOptions {
  readonly group: IssuerCredentialGroup;
  /** Absent when OpenID Federation is disabled. */
  readonly federationEntityConfigurationUrl?: string;
  readonly fcafScenariosEnabled: boolean;
  readonly parameters: IssuanceParameterValues;
}

/** Allowed values of the `POST /openid4vp/sessions` parameters the verifier page offers. */
export interface PresentationParameterValues {
  readonly responseModes: readonly string[];
  readonly requestDeliveries: readonly string[];
  readonly clientIdSchemes: readonly string[];
}

export interface VerifierCredentialGroup {
  readonly issuer: ResolvedIssuerConfiguration;
  readonly credentials: readonly {
    readonly credential: SupportedCredential;
    /** The query the verifier sends when the operator does not edit it. */
    readonly dcqlQuery: JsonRecord;
  }[];
}

export interface VerifierPageOptions {
  readonly groups: readonly VerifierCredentialGroup[];
  readonly fcafScenariosEnabled: boolean;
  readonly parameters: PresentationParameterValues;
}

export function indexPage(groups: readonly IssuerCredentialGroup[]): string {
  return htmlPage({
    title: "Wallet Metadata Capture",
    body: [
      launcherTopbarHtml(),
      "<main>",
      '<section class="hero-band">',
      '<div class="hero-inner">',
      '<div class="hero-copy">',
      "<h1>Wallet metadata capture</h1>",
      "<p>Open an issuer to issue one of its credentials to a wallet, or open the verifier to request a presentation. Every session captures the protocol evidence the wallet leaves behind.</p>",
      "</div>",
      issuerCatalogueHtml(groups),
      verifierCatalogueHtml(),
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
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
      '<main class="page-content session-page">',
      '<section class="session-header launcher-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VP verifier</p>',
      "<h1>Request a presentation</h1>",
      '<p class="session-intro">Choose the credential to request, scan the presentation request with the wallet, and inspect the response, its decoded claims, and the verifier checks.</p>',
      "</div>",
      "</section>",
      '<section class="launcher-layout launcher-layout-single container">',
      presentationFormHtml(options),
      "</section>",
      "</main>",
      "<script>",
      sessionLauncherScript(),
      "</script>",
    ].join(""),
  });
}

function launcherTopbarHtml(): string {
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

export function vpSessionPage(
  sessionId: string,
  deeplink: string,
  qrSvg: string,
  dcApi = false,
): string {
  const escapedDeeplink = escapeHtml(deeplink);
  return htmlPage({
    title: "OpenID4VP Session",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="brand-lockup" href="/">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</a>",
      '<div class="topbar-actions">',
      '<span class="status-chip status-wallet" id="status-label">waiting</span>',
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
      '<main class="page-content session-page">',
      '<section class="session-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VP session</p>',
      dcApi ? "<h1>Open the presentation page</h1>" : "<h1>Scan the presentation request</h1>",
      dcApi
        ? '<p class="session-intro">Scan the code with the device that holds the wallet. It opens this verifier\'s presentation page in the browser, where the presentation is started through the Digital Credentials API.</p>'
        : '<p class="session-intro">Scan the request, select a matching credential in the wallet, and inspect the submitted presentation response.</p>',
      "</div>",
      "</section>",
      '<section class="session-layout container">',
      '<div class="card qr-panel">',
      '<div class="qr-box" id="qr-box" aria-live="polite">',
      '<div class="qr-code" id="qr-code">',
      qrSvg,
      "</div>",
      '<div class="qr-empty" id="qr-empty" hidden></div>',
      "</div>",
      dcApi
        ? '<p class="scan-text" id="scan-text">Scan the code to open the presentation page</p>'
        : '<p class="scan-text" id="scan-text">Scan the presentation request with the wallet</p>',
      dcApi
        ? '<p class="qr-guidance" id="qr-guidance">The code is an HTTPS page URL, not a wallet deeplink. Scanning it opens the page in a browser; the wallet is invoked only when the End-User presses "Present credential" there.</p>'
        : '<p class="qr-guidance" id="qr-guidance">The QR points to a request_uri hosted by this service. The wallet response is captured when it posts the presentation.</p>',
      dcApi
        ? '<div class="deeplink-panel" aria-label="DC API presentation page URL">'
        : '<div class="deeplink-panel" aria-label="Presentation request deeplink">',
      '<p class="deeplink-label">Same content as the QR code</p>',
      '<a class="deeplink" href="',
      escapedDeeplink,
      '">',
      escapedDeeplink,
      "</a>",
      "</div>",
      "</div>",
      '<div class="card metadata-panel metadata-pending" id="metadata-panel">',
      '<div class="section-head">',
      "<h2>Presentation response</h2>",
      '<span class="status-chip metadata-state metadata-state-waiting" id="metadata-state-label">waiting</span>',
      "</div>",
      '<div class="metadata-grid" id="metadata-grid">',
      '<details class="metadata-row"><summary>authorization_request</summary><code>pending</code></details>',
      dcApi
        ? '<details class="metadata-row"><summary>dc_api</summary><code>pending</code></details>'
        : '<details class="metadata-row"><summary>request_uri_payload</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>wallet_response</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>presentation_response_decrypted</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>decoded_presentations</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>presentation_validation</summary><code>pending</code></details>',
      "</div>",
      '<pre class="metadata-json" id="metadata-json">{}</pre>',
      "</div>",
      "</section>",
      "</main>",
      "<script>window.__FAKE_ISSUER_VP_SESSION_ID__ = ",
      JSON.stringify(sessionId),
      ";</script>",
      "<script>",
      vpClientScript(),
      "</script>",
    ].join(""),
  });
}

export interface DcApiPresentationPageOptions {
  sessionId: string;
  request: VpDcApiRequest;
  expectedOrigin: string;
  expiresAt: string;
  state: "ready" | "expired" | "completed";
}

/**
 * The page a DC API session's QR code opens on the End-User's device. It carries the session's
 * browser invocation request and nothing else from the capture record, and it invokes the wallet
 * only from the button press: the Digital Credentials API requires user activation, and navigating
 * to the page is deliberately not enough.
 */
export function dcApiPresentationPage(options: DcApiPresentationPageOptions): string {
  const blocked = options.state !== "ready";
  const notice =
    options.state === "completed"
      ? "This session already holds a presentation. Create a new session to present again."
      : "This presentation session has expired. Create a new session to present again.";
  return htmlPage({
    title: "Present a credential",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="brand-lockup" href="/">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</a>",
      '<div class="topbar-actions">',
      '<span class="status-chip status-wallet">',
      escapeHtml(options.request.protocol),
      "</span>",
      "</div>",
      "</div>",
      "</header>",
      '<main class="page-content session-page">',
      '<section class="session-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VP over the Digital Credentials API</p>',
      "<h1>Present a credential</h1>",
      '<p class="session-intro">This page asks your wallet for a presentation through the browser\'s Digital Credentials API. The request is bound to ',
      escapeHtml(options.expectedOrigin),
      " and expires at ",
      escapeHtml(options.expiresAt),
      ".</p>",
      "</div>",
      "</section>",
      '<section class="session-layout container">',
      '<div class="card">',
      blocked
        ? `<p class="qr-guidance" id="dc-api-status">${escapeHtml(notice)}</p>`
        : [
            '<button class="btn btn-primary btn-lg" id="dc-api-present" type="button">Present credential</button>',
            '<p class="qr-guidance" id="dc-api-status">Press the button to let your wallet answer the request.</p>',
            '<pre class="metadata-json" id="dc-api-detail"></pre>',
          ].join(""),
      "</div>",
      "</section>",
      "</main>",
      ...(blocked
        ? []
        : [
            "<script>window.__CREDIMI_DC_API__ = ",
            // `<` is escaped so a value can never terminate the script element early.
            JSON.stringify({
              session_id: options.sessionId,
              request: options.request,
            }).replaceAll("<", "\\u003c"),
            ";</script>",
            "<script>",
            dcApiPresentationScript(),
            "</script>",
          ]),
    ].join(""),
  });
}

function issuerLabel(issuer: ResolvedIssuerConfiguration): string {
  return issuer.compliance === "deliberately-nonconforming"
    ? `${issuer.display.name} — deliberately non-conforming`
    : issuer.compliance === "experimental"
      ? `${issuer.display.name} — experimental`
      : issuer.display.name;
}

function issuerCatalogueHtml(groups: readonly IssuerCredentialGroup[]): string {
  return [
    '<section class="issuer-catalogue" aria-labelledby="issuer-catalogue-title">',
    '<h2 id="issuer-catalogue-title">Issuers</h2>',
    groups.length > 0
      ? `<div class="issuer-cards">${groups.map(issuerCardHtml).join("")}</div>`
      : '<p class="issuer-empty">No issuers available</p>',
    "</section>",
  ].join("");
}

function issuerCardHtml(group: IssuerCredentialGroup): string {
  const { issuer } = group;
  const count = group.credentials.length;

  return [
    '<article class="issuer-card">',
    "<h3>",
    escapeHtml(issuerLabel(issuer)),
    "</h3>",
    '<p class="issuer-description">',
    issuerDescriptionHtml(group),
    "</p>",
    group.attestbook ? attestbookSummaryHtml(group.attestbook) : "",
    '<p class="issuer-credential-count">',
    `${count} credential configuration${count === 1 ? "" : "s"}`,
    "</p>",
    '<nav class="issuer-links" aria-label="',
    escapeHtml(issuer.display.name),
    '">',
    safeLinkHtml("Open issuer", issuer.issuerIdentifier, "btn btn-primary btn-md"),
    "</nav>",
    "</article>",
  ].join("");
}

function verifierCatalogueHtml(): string {
  return [
    '<section class="issuer-catalogue" aria-labelledby="verifier-catalogue-title">',
    '<h2 id="verifier-catalogue-title">Verifier</h2>',
    '<div class="issuer-cards">',
    '<article class="issuer-card verifier-card">',
    "<h3>OpenID4VP verifier</h3>",
    '<p class="issuer-description">Request a presentation of any credential the issuers above serve, then inspect the wallet response, its decoded claims, and the verifier checks.</p>',
    '<nav class="issuer-links" aria-label="Verifier">',
    safeLinkHtml("Open verifier", VERIFIER_PAGE_PATH, "btn btn-primary btn-md"),
    "</nav>",
    "</article>",
    "</div>",
    "</section>",
  ].join("");
}

function attestbookSummaryHtml(summary: AttestbookIssuerSummary): string {
  const active =
    summary.activeVersion && summary.activeContentDigest
      ? `Attestbook rulebook version ${summary.activeVersion} (sha-256 ${summary.activeContentDigest.slice(0, 12)}…) is active`
      : "No Attestbook rulebook version is active";
  const sync = summary.failureStage
    ? `last synchronization failed at the ${summary.failureStage} stage`
    : `synchronization ${summary.syncState}`;
  return `<p class="issuer-description">${escapeHtml(`${active}; ${sync}.`)}</p>`;
}

function issuerDescriptionHtml(group: IssuerCredentialGroup): string {
  if (group.issuer.compliance !== "eudi-pid-device-bound") {
    return escapeHtml(group.issuer.display.description);
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

/** Renders a link, or plain text when the target is not an HTTP(S) URL or a same-origin path. */
function safeLinkHtml(label: string, href: string, className: string, newTab = false): string {
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

interface ParameterGroup {
  readonly legend: string;
  readonly fields: readonly ParameterField[];
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
    '<form class="card launcher-card session-launcher" data-endpoint="/openid4vp/sessions" data-session-page="/ui/openid4vp/sessions/" novalidate>',
    '<div class="section-head">',
    "<h2>Request a credential</h2>",
    "</div>",
    '<div class="credential-row">',
    '<label class="credential-picker">',
    "<span>Credential</span>",
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

function additionalParametersField(placeholder: string): ParameterField {
  return {
    name: "additional_parameters",
    label: "Additional body members",
    kind: "merge",
    placeholder,
    hint: "A JSON object merged into the request body last, overriding the fields above.",
  };
}

function launcherActionsHtml(label: string, disabled: boolean): string {
  return [
    '<div class="session-actions">',
    '<button class="btn btn-primary btn-lg" type="submit"',
    disabled ? " disabled" : "",
    ">",
    escapeHtml(label),
    "</button>",
    "</div>",
    '<pre class="launcher-error" role="alert" data-launcher-error hidden></pre>',
  ].join("");
}

function advancedSettingsHtml(groups: readonly ParameterGroup[]): string {
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

function verifierCredentialGroupHtml(group: VerifierCredentialGroup): string {
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

function credentialLabel(credential: SupportedCredential): string {
  return credential.attestbook
    ? `${credential.displayName} (Attestbook ${credential.attestbook.version})`
    : credential.displayName;
}

export function sessionPage(sessionId: string, deeplink: string, qrSvg: string): string {
  const escapedDeeplink = escapeHtml(deeplink);
  return htmlPage({
    title: "OpenID4VCI Session",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="brand-lockup" href="/">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</a>",
      '<div class="topbar-actions">',
      '<span class="status-chip status-issuer" id="status-label">waiting</span>',
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
      '<main class="page-content session-page">',
      '<section class="session-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VCI session</p>',
      "<h1>Scan the credential offer</h1>",
      '<p class="session-intro">Scan the offer, accept the issuance in the wallet, then complete the final wallet interaction.</p>',
      "</div>",
      "</section>",
      '<section class="session-layout container">',
      '<div class="card qr-panel">',
      '<div class="qr-box" id="qr-box" aria-live="polite">',
      '<div class="qr-code" id="qr-code">',
      qrSvg,
      "</div>",
      '<div class="qr-empty" id="qr-empty" hidden></div>',
      "</div>",
      '<p class="scan-text" id="scan-text">Scan the offer and accept it in the wallet</p>',
      '<p class="qr-guidance" id="qr-guidance">After scanning, keep going in the wallet issuance flow. Most wallets ask you to accept the issuance before metadata appears here.</p>',
      '<div class="deeplink-panel" aria-label="Credential offer deeplink">',
      '<p class="deeplink-label">Same content as the QR code</p>',
      '<a class="deeplink" href="',
      escapedDeeplink,
      '">',
      escapedDeeplink,
      "</a>",
      "</div>",
      "</div>",
      '<div class="card metadata-panel metadata-pending" id="metadata-panel">',
      '<div class="section-head">',
      "<h2>Wallet metadata</h2>",
      '<span class="status-chip metadata-state metadata-state-waiting" id="metadata-state-label">waiting</span>',
      "</div>",
      '<div class="metadata-grid" id="metadata-grid">',
      '<details class="metadata-row"><summary>client_id</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>redirect_uri</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>wallet_jwks</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>dpop_jwk</summary><code>pending</code></details>',
      '<details class="metadata-row"><summary>wallet_notification</summary><code>pending</code></details>',
      "</div>",
      '<pre class="metadata-json" id="metadata-json">{}</pre>',
      "</div>",
      "</section>",
      "</main>",
      "<script>window.__FAKE_ISSUER_SESSION_ID__ = ",
      JSON.stringify(sessionId),
      ";</script>",
      "<script>",
      clientScript(),
      "</script>",
    ].join(""),
  });
}

/**
 * The page an End-User engages a Wallet from: the session's delivered offer deeplink, as a button
 * and a QR code, and nothing else from the capture. Served from this service's own origin, so a
 * Wallet that derives metadata from the engaging page's origin or referrer asks this service, which
 * records the request.
 */
export function credentialOfferEngagementPage(deeplink: string, qrSvg: string): string {
  const escapedDeeplink = escapeHtml(deeplink);
  return htmlPage({
    title: "Add a credential",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="brand-lockup" href="/">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</a>",
      "</div>",
      "</header>",
      '<main class="page-content session-page">',
      '<section class="session-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VCI credential offer</p>',
      "<h1>Add a credential</h1>",
      '<p class="session-intro">Open the offer in your wallet on this device, or scan it with your wallet.</p>',
      "</div>",
      "</section>",
      '<section class="session-layout container">',
      '<div class="card qr-panel">',
      '<a class="btn btn-primary btn-lg" id="engage-offer" href="',
      escapedDeeplink,
      '">Open in wallet</a>',
      '<div class="qr-box"><div class="qr-code">',
      qrSvg,
      "</div></div>",
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
}

export function errorPage(message: string): string {
  return htmlPage({
    title: "Wallet Metadata Capture Error",
    body: [
      '<main class="page-content">',
      '<section class="card danger-panel container">',
      '<p class="eyebrow">Error</p>',
      "<h1>",
      escapeHtml(message),
      "</h1>",
      '<a class="btn btn-primary btn-md" href="/">Back to launcher</a>',
      "</section>",
      "</main>",
    ].join(""),
  });
}

export function vpRedirectPage(responseCode: string, found: boolean): string {
  const title = found ? "Presentation complete" : "Redirect page not found";
  const eyebrow = found ? "Presentation complete" : "Redirect error";
  const description = found
    ? "You can return to the application."
    : "The response code could not be matched to a presentation session.";

  return htmlPage({
    title,
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="brand-lockup" href="/">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</a>",
      "</div>",
      "</header>",
      '<main class="page-content">',
      '<section class="card redirect-result-panel container',
      found ? "" : " danger-panel",
      '">',
      '<p class="eyebrow">',
      eyebrow,
      "</p>",
      "<h1>",
      title,
      "</h1>",
      "<p>",
      description,
      "</p>",
      '<dl class="redirect-response-code">',
      "<dt>response_code</dt>",
      "<dd><code>",
      escapeHtml(responseCode),
      "</code></dd>",
      "</dl>",
      '<a class="btn btn-primary btn-md" href="/">Back to launcher</a>',
      "</section>",
      "</main>",
    ].join(""),
  });
}

export function helpPage(readmeMarkdown: string): string {
  return htmlPage({
    title: "Wallet Metadata Capture Help",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="brand-lockup" href="/">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</a>",
      '<span class="status-chip status-wallet">help</span>',
      "</div>",
      "</header>",
      '<main class="page-content">',
      '<article class="card readme-card container">',
      renderMarkdown(readmeMarkdown),
      "</article>",
      "</main>",
    ].join(""),
  });
}

function htmlPage({ title, body }: { title: string; body: string }): string {
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<link rel="icon" type="image/svg+xml" href="/favicon.svg">',
    '<link rel="stylesheet" href="/assets/style.css">',
    "<title>",
    escapeHtml(title),
    "</title>",
    "<style>",
    appCss(),
    "</style>",
    "</head>",
    "<body>",
    credimiExtrasBarTopHtml(),
    body,
    footerHtml(),
    '<script>console.log("%cWallet metadata capture%c Credimi capture UI", "background:#312060;color:#fff;padding:5px 9px;font-weight:800;border-radius:6px 0 0 6px;", "background:#f1e9f7;color:#22172f;padding:5px 9px;font-weight:700;border-radius:0 6px 6px 0;");</script>',
    "</body>",
    "</html>",
  ].join("");
}

function footerHtml(): string {
  return [
    '<footer class="footer">',
    '<div class="footer-inner">',
    '<div class="footer-content">',
    '<div class="footer-brand">',
    '<img class="footer-logo" src="/assets/credimi_logo_negative.svg" alt="" aria-hidden="true">',
    "<p>Issuer and verifier for EUDI wallet metadata capture and conformance testing.</p>",
    "</div>",
    '<nav class="footer-links" aria-label="Project links">',
    '<a class="footer-link fork-link" href="',
    REPOSITORY_URL,
    '" target="_blank" rel="noreferrer">Repository</a>',
    "</nav>",
    "</div>",
    "</div>",
    credimiExtrasBarBottomHtml(),
    "</footer>",
  ].join("");
}

/**
 * The Credimi Extras cross-promotional strips. The top one is emitted by
 * htmlPage() rather than beside each `<header class="topbar">`: the four
 * topbars differ in their status chips and labels, and folding them into one
 * helper would change markup unrelated to this banner. Emitting it at the
 * single point where `<body>` opens keeps one copy and also covers errorPage(),
 * which has no topbar of its own but does carry the footer.
 */
function credimiExtrasBarTopHtml(): string {
  return [
    '<div class="credimi-extras-bar">',
    '<div class="credimi-extras-bar-inner">',
    '<img class="credimi-extras-mark" src="/assets/credimi_logo.svg" alt="" aria-hidden="true" width="16" height="16">',
    " This app is part of <strong>Credimi Extras</strong>. Automate all your EUDI testing with ",
    '<a href="https://credimi.io" target="_blank" rel="noopener">Credimi</a>',
    "</div>",
    "</div>",
  ].join("");
}

function credimiExtrasBarBottomHtml(): string {
  return [
    '<div class="credimi-extras-bar-footer">',
    '<div class="credimi-extras-bar-inner">',
    "This app is part of <strong>Credimi Extras</strong>. Automate all your EUDI testing with ",
    '<a class="credimi-extras-wordmark-link" href="https://credimi.io" target="_blank" rel="noopener">',
    '<img class="credimi-extras-wordmark" src="/assets/credimi_logo-transp_white.svg" alt="Credimi">',
    "</a>",
    "</div>",
    "</div>",
  ].join("");
}

function appCss(): string {
  return [
    ":root { --brand-primary: oklch(0.2955 0.1659 277.31); --brand-primary-700: oklch(0.36 0.18 277.31); --brand-secondary: oklch(0.9464 0.0284 294.59); --brand-secondary-strong: oklch(0.8794 0.0567 294.59); --bg: oklch(1 0 0); --bg-muted: oklch(0.9811 0.0064 308.39); --fg: oklch(0.129 0.042 264.695); --fg-muted: oklch(0.7248 0.0094 286.16); --border: oklch(0.929 0.013 255.508); --border-strong: oklch(0.82 0.015 255.508); --warning: oklch(0.65 0.18 85); --warning-bg: oklch(0.96 0.06 85); --success: oklch(0.55 0.18 150); --success-bg: oklch(0.95 0.04 150); --info: oklch(0.4 0.15 260); --info-bg: oklch(0.94 0.04 260); --destructive: oklch(0.50 0.22 25); --wallet: oklch(0.45 0.18 300); --wallet-bg: oklch(0.95 0.04 300); --radius-md: 6px; --radius-lg: 10px; --radius-pill: 999px; --shadow-sm: 0 1px 2px rgba(0,0,0,.04); --max-width: 1280px; --topbar-height: 56px; }",
    "*, *::before, *::after { box-sizing: border-box; }",
    "html { background: var(--brand-primary); }",
    "body { margin: 0; min-height: 100vh; display: flex; flex-direction: column; background: var(--brand-secondary); color: var(--fg); font-family: Manrope, system-ui, -apple-system, Segoe UI, sans-serif; font-size: 14px; line-height: 1.571; -webkit-font-smoothing: antialiased; }",
    "main { flex: 1; }",
    "h1, h2, h3, p { margin: 0; }",
    "h1 { max-width: 820px; font-size: clamp(38px, 6vw, 64px); line-height: 1.05; font-weight: 800; letter-spacing: -0.035em; }",
    "h2 { font-size: 26px; line-height: 1.2; font-weight: 800; letter-spacing: -0.015em; }",
    "h3 { font-size: 22px; line-height: 1.25; }",
    "a { color: var(--brand-primary); }",
    "code, pre, .brand-mark { font-family: JetBrains Mono, Fira Code, Cascadia Code, ui-monospace, monospace; }",
    ".container { width: min(100% - 48px, var(--max-width)); margin-inline: auto; }",
    ".topbar { position: sticky; top: 0; z-index: 100; height: 58px; background: var(--bg); border-bottom: 1px solid var(--border); }",
    ".topbar-inner { width: min(100% - 48px, var(--max-width)); height: 100%; margin-inline: auto; display: flex; align-items: center; justify-content: space-between; gap: 24px; }",
    ".topbar-actions { display: inline-flex; align-items: center; gap: 10px; flex-shrink: 0; }",
    ".brand-lockup { display: inline-flex; align-items: center; gap: 10px; color: var(--fg); font-weight: 800; text-decoration: none; }",
    ".brand-logo { box-sizing: border-box; width: 42px; height: 42px; padding: 4px; object-fit: contain; flex: 0 0 auto; }",
    ".brand-mark { display: inline-grid; place-items: center; width: 30px; height: 30px; border-radius: var(--radius-md); background: var(--brand-primary); color: white; font-size: 12px; font-weight: 800; }",
    ".brand-name { font-size: 14px; font-weight: 700; }",
    ".page-content { padding: 42px 0 72px; }",
    ".footer { background: var(--brand-primary); color: white; padding: 32px 0; }",
    ".footer-inner { width: min(100% - 48px, var(--max-width)); margin-inline: auto; }",
    ".footer-content { display: flex; align-items: center; justify-content: space-between; gap: 24px; }",
    ".footer-brand { display: inline-flex; align-items: center; gap: 14px; min-width: 0; }",
    ".footer-logo {  box-sizing: border-box; width: 56px; height: 56px; padding: 6px; object-fit: contain; flex: 0 0 auto; }",
    ".footer-brand p { max-width: 420px; color: rgba(255,255,255,.76); font-size: 13px; line-height: 1.5; }",
    ".footer-mark { background: white; color: var(--brand-primary); flex: 0 0 auto; }",
    ".footer-links { display: inline-flex; align-items: center; justify-content: flex-end; gap: 12px; flex-wrap: wrap; }",
    ".footer-link { display: inline-flex; align-items: center; min-height: 36px; padding: 0 14px; border-radius: var(--radius-md); color: white; font-size: 13px; font-weight: 700; text-decoration: none; white-space: nowrap; }",
    ".fork-link { background: white; color: var(--brand-primary); }",
    // Credimi Extras cross-promotional bars: one above the topbar, one closing
    // the footer. Both logos are inline images inside the sentence rather than
    // flex siblings of it, so at a phone width the line breaks between words
    // and the marks stay attached to the text they belong to.
    ".credimi-extras-bar { background: var(--brand-secondary); color: var(--brand-primary); padding: 7px 24px; font-size: 12.5px; line-height: 1.45; }",
    // Darkens the footer's own brand fill rather than introducing a new colour.
    ".credimi-extras-bar-footer { background: rgba(0,0,0,.35); color: rgba(255,255,255,.85); padding: 9px 24px; font-size: 12.5px; line-height: 1.45; }",
    // The bar has to reach the bottom edge of the page, so the footer's own
    // closing padding moves onto the bar's top margin: the space above the
    // strip is unchanged and nothing shows below it.
    ".footer { padding-bottom: 0; }",
    ".credimi-extras-bar-footer { margin-top: 32px; }",
    ".credimi-extras-bar-inner { max-width: var(--max-width); margin-inline: auto; text-align: center; text-wrap: balance; }",
    ".credimi-extras-mark { display: inline-block; width: 16px; height: 16px; margin-right: 2px; object-fit: contain; vertical-align: -3px; }",
    // Only the linked word is clickable — the bar itself is not a target.
    ".credimi-extras-bar a { color: inherit; text-decoration: underline; }",
    ".credimi-extras-wordmark-link { text-decoration: none; }",
    ".credimi-extras-wordmark { display: inline-block; height: 16px; width: auto; vertical-align: -4px; }",
    ".credimi-extras-bar a:focus-visible, .credimi-extras-wordmark-link:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; border-radius: 2px; }",
    ".hero-band { position: relative; overflow: hidden; padding: 76px 0 68px; }",
    ".hero-band::after { content: ''; position: absolute; inset: 0 0 auto auto; width: 360px; height: 360px; background: linear-gradient(135deg, transparent 49.5%, rgb(49 32 96 / 8%) 49.5%, rgb(49 32 96 / 8%) 50.5%, transparent 50.5%), linear-gradient(45deg, transparent 49.5%, rgb(49 32 96 / 8%) 49.5%, rgb(49 32 96 / 8%) 50.5%, transparent 50.5%); pointer-events: none; }",
    ".hero-inner { position: relative; z-index: 1; width: min(100% - 48px, var(--max-width)); margin-inline: auto; display: grid; gap: 32px; align-items: start; }",
    ".hero-copy { display: grid; gap: 20px; max-width: 740px; }",
    ".hero-copy p:not(.eyebrow) { max-width: 720px; color: var(--fg-muted); font-size: 17px; line-height: 1.571; }",
    ".session-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }",
    ".credential-picker { display: grid; gap: 8px; width: min(100%, 520px); color: var(--fg); font-size: 13px; font-weight: 700; }",
    ".credential-picker select { width: 100%; min-height: 44px; padding: 0 42px 0 14px; border: 1px solid var(--border-strong); border-radius: var(--radius-md); background: var(--bg); color: var(--fg); font: inherit; font-size: 14px; font-weight: 600; }",
    ".credential-picker select:focus { outline: 2px solid color-mix(in oklch, var(--brand-primary) 36%, transparent); outline-offset: 2px; }",
    // The credential select and the status-list switch share one row: the
    // switch is pushed to the trailing edge and baseline-matched to the select
    // (the picker carries its own label above, hence flex-end).
    ".credential-row { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; width: 100%; }",
    ".credential-row .credential-picker { flex: 1 1 320px; }",
    ".status-list-toggle { position: relative; display: inline-flex; align-items: center; gap: 10px; min-height: 44px; margin-left: auto; color: var(--fg); font-size: 13px; font-weight: 700; cursor: pointer; }",
    // The native checkbox stays in the layout for form submission and keyboard
    // focus; only the track is painted.
    ".status-list-toggle input { position: absolute; width: 1px; height: 1px; margin: 0; padding: 0; border: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }",
    ".toggle-track { position: relative; flex: 0 0 auto; width: 40px; height: 22px; border: 1px solid var(--border-strong); border-radius: var(--radius-pill); background: var(--bg-muted); transition: background 150ms ease-out, border-color 150ms ease-out; }",
    ".toggle-track::after { content: ''; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: var(--bg); box-shadow: var(--shadow-sm); transition: transform 150ms ease-out; }",
    ".status-list-toggle input:checked + .toggle-track { background: var(--brand-primary); border-color: var(--brand-primary); }",
    ".status-list-toggle input:checked + .toggle-track::after { transform: translateX(18px); }",
    ".status-list-toggle input:focus-visible + .toggle-track { outline: 2px solid color-mix(in oklch, var(--brand-primary) 36%, transparent); outline-offset: 2px; }",
    ".issuer-catalogue { display: grid; gap: 12px; width: 100%; margin-top: 8px; }",
    ".issuer-catalogue h2 { font-size: 20px; }",
    ".issuer-cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }",
    ".issuer-card { min-width: 0; display: grid; align-content: start; gap: 12px; padding: 18px; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--bg); box-shadow: var(--shadow-sm); }",
    ".issuer-card h3 { min-width: 0; font-size: 16px; line-height: 1.4; }",
    ".issuer-description, .issuer-empty { color: var(--fg-muted); font-size: 13px; line-height: 1.5; }",
    ".issuer-links { display: grid; gap: 6px; margin-top: auto; }",
    ".issuer-link { overflow-wrap: anywhere; font-size: 12px; font-weight: 700; }",
    ".eyebrow { margin-bottom: 10px; color: var(--brand-primary); font-size: 12px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; }",
    ".card { min-width: 0; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--shadow-sm); }",
    ".section-header, .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }",
    ".section-header.compact { margin-bottom: 0; }",
    ".section-header h2::after, .section-head h2::after { content: ':'; }",
    ".status-chip { display: inline-flex; align-items: center; gap: 6px; min-height: 24px; padding: 0 11px; border-radius: var(--radius-pill); font-size: 11px; font-weight: 700; text-transform: uppercase; white-space: nowrap; }",
    ".status-chip::before { content: ''; width: 8px; height: 8px; border-radius: 50%; }",
    ".status-issuer { background: var(--warning-bg); color: var(--warning); }",
    ".status-issuer::before { background: var(--warning); }",
    ".status-wallet { background: var(--wallet-bg); color: var(--wallet); }",
    ".status-wallet::before { background: var(--wallet); }",
    ".btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; width: fit-content; border: 0; border-radius: var(--radius-lg); font: inherit; font-size: 14px; font-weight: 700; text-decoration: none; cursor: pointer; transition: background 150ms ease-out, border-color 150ms ease-out; }",
    ".btn-lg { min-height: 44px; padding: 0 24px; font-size: 15px; }",
    ".btn-md { min-height: 36px; padding: 0 18px; }",
    ".btn-primary { background: var(--brand-primary); color: white; }",
    ".btn-primary:hover { background: var(--brand-primary-700); }",
    ".btn-outline { background: var(--bg); color: var(--fg); border: 1px solid var(--border); }",
    ".btn-outline:hover { border-color: var(--border-strong); background: var(--bg-muted); }",
    "dt { color: var(--fg); font-size: 13px; font-weight: 700; }",
    "dd { margin: 4px 0 0; color: var(--fg-muted); font-size: 13px; line-height: 1.5; }",
    ".issuer-credential-count { color: var(--fg); font-size: 12px; font-weight: 700; }",
    ".launcher-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 360px); gap: 24px; align-items: start; }",
    ".launcher-layout-single { grid-template-columns: minmax(0, 1fr); }",
    ".launcher-card { display: grid; gap: 18px; align-content: start; }",
    ".launcher-card .section-head { margin-bottom: 0; }",
    ".entity-facts { margin: 0; }",
    ".entity-facts dd code { overflow-wrap: anywhere; color: var(--fg); font-size: 12px; }",
    ".advanced-settings { border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".advanced-settings > summary { display: flex; align-items: center; min-height: 44px; padding: 10px 14px; color: var(--fg); font-size: 14px; font-weight: 700; cursor: pointer; }",
    ".advanced-settings[open] > summary { border-bottom: 1px solid var(--border); }",
    ".advanced-settings > .field-hint { padding: 12px 14px 0; }",
    ".parameter-group { min-width: 0; margin: 0; padding: 14px; border: 0; }",
    ".parameter-group + .parameter-group { border-top: 1px solid var(--border); }",
    // A floated legend is laid out inside the fieldset instead of on its border.
    ".parameter-group legend { float: left; width: 100%; margin-bottom: 12px; padding: 0; color: var(--brand-primary); font-size: 12px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }",
    ".parameter-fields { clear: both; display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 14px; }",
    ".field { display: grid; gap: 6px; align-content: start; min-width: 0; }",
    ".field-wide { grid-column: 1 / -1; }",
    ".field-label { color: var(--fg); font-size: 13px; font-weight: 700; }",
    ".field-label code { color: var(--fg-muted); font-size: 11px; font-weight: 500; }",
    ".field select, .field input[type=text], .field textarea { width: 100%; min-height: 38px; padding: 8px 10px; border: 1px solid var(--border-strong); border-radius: var(--radius-md); background: var(--bg); color: var(--fg); font: inherit; font-size: 13px; }",
    ".field textarea { min-height: 96px; resize: vertical; font-family: JetBrains Mono, Fira Code, Cascadia Code, ui-monospace, monospace; font-size: 12px; }",
    ".field textarea[data-param='dcql_query'] { min-height: 260px; }",
    ".launcher-header h1 { font-size: clamp(32px, 4.5vw, 48px); }",
    ".field select:focus, .field input:focus, .field textarea:focus { outline: 2px solid color-mix(in oklch, var(--brand-primary) 36%, transparent); outline-offset: 1px; }",
    ".field-flag { grid-template-columns: auto minmax(0, 1fr); align-items: center; column-gap: 8px; }",
    ".field-flag .field-hint { grid-column: 2; }",
    ".field-hint { color: var(--fg-muted); font-size: 12px; font-weight: 500; line-height: 1.45; }",
    ".field-disabled { opacity: .45; }",
    ".launcher-error { margin: 0; padding: 12px 14px; border: 1px solid var(--border); border-left: 3px solid var(--destructive); border-radius: var(--radius-md); background: var(--bg); color: var(--destructive); font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }",
    ".btn[disabled] { opacity: .55; cursor: not-allowed; }",
    ".session-page { background: var(--brand-secondary); }",
    ".session-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-bottom: 24px; }",
    ".session-header > div { display: grid; gap: 10px; max-width: 760px; }",
    ".session-intro { max-width: 680px; color: var(--fg-muted); font-size: 16px; line-height: 1.6; }",
    ".session-layout { display: grid; grid-template-columns: minmax(300px, 420px) minmax(0, 1fr); gap: 24px; }",
    ".qr-panel { display: grid; gap: 16px; align-content: start; }",
    ".qr-box { width: min(100%, 336px); aspect-ratio: 1; display: grid; place-items: center; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--bg-muted); padding: 20px; }",
    ".qr-code svg { display: block; width: 100%; height: auto; }",
    ".qr-empty { width: 100%; height: 100%; border: 1px dashed var(--border-strong); border-radius: var(--radius-md); background: var(--brand-secondary-strong); }",
    ".scan-text { color: var(--fg); font-size: 22px; font-weight: 700; line-height: 1.364; }",
    ".qr-guidance { color: var(--fg-muted); font-size: 14px; line-height: 1.6; }",
    ".deeplink-panel { display: grid; gap: 8px; padding: 14px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".deeplink-label { color: var(--fg-muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }",
    ".deeplink { overflow-wrap: anywhere; color: var(--brand-primary); font-family: JetBrains Mono, Fira Code, Cascadia Code, ui-monospace, monospace; font-size: 12px; line-height: 1.5; }",
    ".metadata-panel { transition: background 220ms ease-out, border-color 220ms ease-out, box-shadow 220ms ease-out; }",
    ".metadata-pending { background: color-mix(in oklch, var(--bg) 74%, var(--bg-muted)); }",
    ".metadata-pending .metadata-row, .metadata-pending .metadata-json { opacity: .56; filter: grayscale(1); }",
    ".metadata-ready { border-color: color-mix(in oklch, var(--success) 42%, var(--border)); background: var(--bg); }",
    ".metadata-flash { animation: metadata-flash 1400ms ease-out; }",
    ".metadata-state { min-width: 88px; justify-content: center; }",
    ".metadata-state-waiting { background: var(--warning-bg); color: var(--warning); }",
    ".metadata-state-waiting::before { border: 2px solid color-mix(in oklch, var(--warning) 28%, transparent); border-top-color: var(--warning); background: transparent; animation: metadata-spin 900ms linear infinite; }",
    ".metadata-state-receiving { background: var(--info-bg); color: var(--info); }",
    ".metadata-state-receiving::before { border: 2px solid color-mix(in oklch, var(--info) 28%, transparent); border-top-color: var(--info); background: transparent; animation: metadata-spin 900ms linear infinite; }",
    ".metadata-state-done { background: var(--success-bg); color: var(--success); }",
    ".metadata-state-done::before { background: var(--success); }",
    ".metadata-grid { display: grid; gap: 8px; margin-bottom: 16px; }",
    ".metadata-row { border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".metadata-row summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; min-height: 42px; padding: 10px 12px; color: var(--fg); font-size: 13px; font-weight: 700; cursor: pointer; list-style: none; }",
    ".metadata-row summary::-webkit-details-marker { display: none; }",
    ".metadata-row summary::after { content: '\\02C5'; display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; flex: 0 0 auto; box-sizing: border-box; padding-top: 8px; color: var(--brand-primary); font-family: JetBrains Mono, Fira Code, Cascadia Code, ui-monospace, monospace; font-size: 18px; font-weight: 500; line-height: 20px; }",
    ".metadata-row[open] summary { border-bottom: 1px solid var(--border); }",
    ".metadata-row[open] summary::after { content: '\\02C4'; }",
    ".metadata-row code { display: block; padding: 12px; overflow-wrap: anywhere; color: var(--fg); font-size: 12px; white-space: pre-wrap; }",
    ".metadata-json { min-height: 280px; max-height: 50vh; overflow: auto; margin: 0; padding: 16px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); color: var(--fg); white-space: pre-wrap; font-size: 13px; line-height: 1.5; }",
    ".danger-panel { display: grid; gap: 20px; border-left: 3px solid var(--destructive); }",
    ".danger-panel h1 { font-size: 28px; }",
    ".redirect-result-panel { display: grid; gap: 20px; max-width: 680px; }",
    ".redirect-result-panel h1 { font-size: 28px; }",
    ".redirect-result-panel > p:not(.eyebrow) { color: var(--fg-muted); font-size: 16px; }",
    ".redirect-response-code { margin: 0; padding: 14px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".redirect-response-code dd { margin-top: 8px; overflow-wrap: anywhere; }",
    ".redirect-response-code code { color: var(--fg); font-size: 13px; }",
    ".readme-card { max-width: 900px; }",
    ".readme-card h1 { margin-bottom: 20px; }",
    ".readme-card h2 { margin-top: 32px; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }",
    ".readme-card h3 { margin-top: 24px; margin-bottom: 8px; font-size: 22px; line-height: 1.364; }",
    ".readme-card p, .readme-card ul, .readme-card pre { margin-top: 12px; }",
    ".readme-card ul { padding-left: 22px; color: var(--fg-muted); }",
    ".readme-card li { margin-top: 6px; }",
    ".readme-card code { padding: 1px 4px; border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".readme-card pre code { padding: 0; background: transparent; }",
    "@keyframes metadata-spin { to { transform: rotate(360deg); } }",
    "@keyframes metadata-flash { 0% { background: var(--warning-bg); box-shadow: 0 0 0 0 color-mix(in oklch, var(--warning) 32%, transparent); } 30% { background: var(--success-bg); box-shadow: 0 0 0 6px color-mix(in oklch, var(--success) 20%, transparent); } 100% { background: var(--bg); box-shadow: var(--shadow-sm); } }",
    "@media (prefers-reduced-motion: reduce) { .metadata-state-waiting::before, .metadata-state-receiving::before, .metadata-flash { animation: none; } .toggle-track, .toggle-track::after { transition: none; } }",
    "@media (max-width: 860px) { h1 { font-size: 38px; } h2 { font-size: 22px; } .hero-band { padding: 52px 0; } .session-layout, .launcher-layout { grid-template-columns: 1fr; } .issuer-cards { grid-template-columns: 1fr; } .session-header, .section-head, .footer-content { flex-direction: column; align-items: stretch; } .session-actions { align-items: stretch; flex-direction: column; } .session-actions .btn { width: 100%; } .footer-links { justify-content: flex-start; } .qr-box { width: 100%; max-width: 336px; } }",
    "@media (max-width: 560px) { .container, .topbar-inner, .hero-inner, .footer-inner { width: min(100% - 28px, var(--max-width)); } .page-content { padding: 28px 0 52px; } .card { padding: 18px; } .brand-name { display: none; } .topbar-actions .btn { display: none; } .status-list-toggle { margin-left: 0; } }",
  ].join("\n");
}

function renderMarkdown(markdown: string): string {
  const html: string[] = [];
  let listOpen = false;
  let codeOpen = false;
  let paragraph: string[] = [];

  function flushParagraph(): void {
    if (paragraph.length === 0) return;
    html.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
    paragraph = [];
  }

  function closeList(): void {
    if (!listOpen) return;
    html.push("</ul>");
    listOpen = false;
  }

  for (const line of markdown.split(/\r?\n/)) {
    if (line.startsWith("```")) {
      flushParagraph();
      closeList();
      if (codeOpen) {
        html.push("</code></pre>");
        codeOpen = false;
      } else {
        html.push("<pre><code>");
        codeOpen = true;
      }
      continue;
    }

    if (codeOpen) {
      html.push(escapeHtml(line), "\n");
      continue;
    }

    const trimmed = line.trim();
    if (!trimmed) {
      flushParagraph();
      closeList();
      continue;
    }

    const heading = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushParagraph();
      closeList();
      const level = heading[1].length;
      html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }

    if (trimmed.startsWith("- ")) {
      flushParagraph();
      if (!listOpen) {
        html.push("<ul>");
        listOpen = true;
      }
      html.push(`<li>${inlineMarkdown(trimmed.slice(2))}</li>`);
      continue;
    }

    paragraph.push(trimmed);
  }

  flushParagraph();
  closeList();
  if (codeOpen) html.push("</code></pre>");
  return html.join("");
}

function inlineMarkdown(value: string): string {
  return escapeHtml(value).replace(/`([^`]+)`/g, "<code>$1</code>");
}

/**
 * Creates a session through the public JSON API from the issuer or verifier page. Only fields the
 * operator filled are sent, so every other parameter keeps the API default, and a refusal is shown
 * as the API's own error body.
 */
function sessionLauncherScript(): string {
  return `(function () {
  const form = document.querySelector("form.session-launcher");
  if (!form) return;
  const picker = form.querySelector("[data-credential-picker]");
  const dcql = form.querySelector('[data-param="dcql_query"]');
  const errorBox = form.querySelector("[data-launcher-error]");
  const submit = form.querySelector('button[type="submit"]');
  let generatedDcql = "";

  function applyCredential() {
    const option = picker ? picker.selectedOptions[0] : undefined;
    const imported = option?.dataset.imported === "true";
    const mdoc = option?.dataset.format === "mso_mdoc";
    for (const field of form.querySelectorAll("[data-requires]")) {
      const applies = field.dataset.requires === "static-credential" ? !imported : !mdoc;
      field.disabled = !applies;
      field.closest("label")?.classList.toggle("field-disabled", !applies);
    }
    // The query follows the selected credential until the operator edits it.
    if (dcql && option?.dataset.dcql && (dcql.value.trim() === "" || dcql.value === generatedDcql)) {
      generatedDcql = JSON.stringify(JSON.parse(option.dataset.dcql), null, 2);
      dcql.value = generatedDcql;
    }
  }

  function requestBody() {
    const body = {};
    let merged;
    for (const field of form.querySelectorAll("[data-param]")) {
      if (field.disabled) continue;
      const name = field.dataset.param;
      const type = field.dataset.type;
      if (type === "flag") {
        if (field.checked) body[name] = JSON.parse(field.value);
        continue;
      }
      const raw = field.value.trim();
      if (raw === "") continue;
      if (type === "string") {
        body[name] = raw;
        continue;
      }
      let value;
      try {
        value = JSON.parse(raw);
      } catch (error) {
        throw new Error(name + " is not valid JSON: " + error.message);
      }
      if (type !== "merge") {
        body[name] = value;
      } else if (value && typeof value === "object" && !Array.isArray(value)) {
        merged = value;
      } else {
        throw new Error(name + " must be a JSON object");
      }
    }
    return merged ? Object.assign(body, merged) : body;
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.hidden = true;
    let body;
    try {
      body = requestBody();
    } catch (error) {
      showError(error.message);
      return;
    }
    submit.disabled = true;
    try {
      const response = await fetch(form.dataset.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await response.json().catch(() => null);
      if (response.status === 201 && payload && typeof payload.session_id === "string") {
        window.location.assign(form.dataset.sessionPage + encodeURIComponent(payload.session_id));
        return;
      }
      showError("The API refused the session (HTTP " + response.status + ")\\n" + JSON.stringify(payload, null, 2));
    } catch (error) {
      showError("The session request failed: " + error.message);
    }
    submit.disabled = false;
  });

  picker?.addEventListener("change", applyCredential);
  applyCredential();
})();`;
}

function clientScript(): string {
  return '(function () {\n  const sessionId = window.__FAKE_ISSUER_SESSION_ID__;\n  const qrCode = document.getElementById("qr-code");\n  const qrEmpty = document.getElementById("qr-empty");\n  const scanText = document.getElementById("scan-text");\n  const qrGuidance = document.getElementById("qr-guidance");\n  const statusLabel = document.getElementById("status-label");\n  const metadataPanel = document.getElementById("metadata-panel");\n  const metadataStateLabel = document.getElementById("metadata-state-label");\n  const metadataGrid = document.getElementById("metadata-grid");\n  const metadataJson = document.getElementById("metadata-json");\n  // A Notification Request is optional for the wallet, so polling for one stops after this long.\n  const notificationWaitMs = 120000;\n  let lastMetadataState = "waiting";\n  let flashTimer = null;\n  let pollTimer = null;\n  let doneAt = null;\n\n  function setQrConsumed(consumed) {\n    qrCode.hidden = consumed;\n    qrEmpty.hidden = !consumed;\n    scanText.textContent = consumed ? "Offer retrieved by wallet" : "Scan the offer and accept it in the wallet";\n    qrGuidance.textContent = consumed\n      ? "The wallet has retrieved the offer. Accept the issuance, then complete the final wallet interaction."\n      : "After scanning, keep going in the wallet issuance flow. Most wallets ask you to accept the issuance before metadata appears here.";\n  }\n\n  function notificationReceipts(session) {\n    return (session.notifications || []).flatMap(function (notification) {\n      return notification.received;\n    });\n  }\n\n  function walletNotification(session) {\n    const receipts = notificationReceipts(session);\n    if (receipts.length > 0) {\n      return receipts\n        .map(function (receipt) {\n          return receipt.event_description ? receipt.event + ": " + receipt.event_description : receipt.event;\n        })\n        .join("; ");\n    }\n    return credentialRequestArrived(session) ? "not reported" : "pending";\n  }\n\n  function metadataRows(session) {\n    const walletJwks = session.observed.wallet_jwks.observed\n      ? JSON.stringify(session.observed.wallet_jwks.jwks)\n      : "pending";\n    const dpopJwk = session.observed.dpop_jwk.observed\n      ? JSON.stringify(session.observed.dpop_jwk.jwk)\n      : "pending";\n    return [\n      ["client_id", session.observed.client_id.value || "pending"],\n      ["redirect_uri", session.observed.redirect_uri.value || "pending"],\n      ["wallet_jwks", walletJwks],\n      ["dpop_jwk", dpopJwk],\n      ["wallet_notification", walletNotification(session)],\n    ];\n  }\n\n  function sessionHasMetadata(session) {\n    return Boolean(\n      session.observed.client_id.value ||\n        session.observed.redirect_uri.value ||\n        session.observed.wallet_jwks.observed ||\n        session.observed.dpop_jwk.observed,\n    );\n  }\n\n  function credentialRequestArrived(session) {\n    return Boolean(session.raw && session.raw.credential_request);\n  }\n\n  function metadataState(session) {\n    if (credentialRequestArrived(session)) return "done";\n    if (sessionHasMetadata(session)) return "receiving";\n    return "waiting";\n  }\n\n  function setMetadataState(state) {\n    const done = state === "done";\n    metadataPanel.classList.toggle("metadata-pending", state === "waiting");\n    metadataPanel.classList.toggle("metadata-ready", done);\n    metadataStateLabel.textContent = state;\n    metadataStateLabel.classList.toggle("metadata-state-waiting", state === "waiting");\n    metadataStateLabel.classList.toggle("metadata-state-receiving", state === "receiving");\n    metadataStateLabel.classList.toggle("metadata-state-done", done);\n  }\n\n  function flashMetadataPanel() {\n    metadataPanel.classList.remove("metadata-flash");\n    void metadataPanel.offsetWidth;\n    metadataPanel.classList.add("metadata-flash");\n    if (flashTimer) window.clearTimeout(flashTimer);\n    flashTimer = window.setTimeout(function () {\n      metadataPanel.classList.remove("metadata-flash");\n    }, 1400);\n  }\n\n  function render(session) {\n    setQrConsumed(session.status !== "created");\n    statusLabel.textContent = session.status.replaceAll("_", " ");\n    const state = metadataState(session);\n    setMetadataState(state);\n    if (state !== lastMetadataState) flashMetadataPanel();\n    lastMetadataState = state;\n    if (state === "done" && doneAt === null) doneAt = Date.now();\n    const notified = notificationReceipts(session).length > 0;\n    if (pollTimer && doneAt !== null && (notified || Date.now() - doneAt > notificationWaitMs)) {\n      window.clearInterval(pollTimer);\n      pollTimer = null;\n    }\n    const openFields = new Set(\n      Array.from(metadataGrid.querySelectorAll(".metadata-row[open]"), function (row) {\n        return row.dataset.field;\n      }),\n    );\n    metadataGrid.innerHTML = metadataRows(session)\n      .map(function (row) {\n        return \'<details class="metadata-row" data-field="\' + escapeHtml(row[0]) + \'"\' + (openFields.has(row[0]) ? " open" : "") + \'><summary>\' + escapeHtml(row[0]) + \'</summary><code>\' + escapeHtml(row[1]) + \'</code></details>\';\n      })\n      .join("");\n    metadataJson.textContent = JSON.stringify(\n      {\n        session_id: session.session_id,\n        status: session.status,\n        observed: session.observed,\n        checks: session.checks,\n        notifications: session.notifications,\n        events: session.events,\n      },\n      null,\n      2,\n    );\n  }\n\n  function escapeHtml(value) {\n    return String(value).replace(/[&<>"\']/g, function (char) {\n      return {\n        "&": "&amp;",\n        "<": "&lt;",\n        ">": "&gt;",\n        \'"\': "&quot;",\n        "\'": "&#39;",\n      }[char];\n    });\n  }\n\n  async function poll() {\n    const response = await fetch("/sessions/" + encodeURIComponent(sessionId), {\n      headers: { accept: "application/json" },\n    });\n    if (!response.ok) throw new Error("session fetch failed");\n    render(await response.json());\n  }\n\n  poll().catch(console.error);\n  pollTimer = setInterval(function () {\n    poll().catch(console.error);\n  }, 1500);\n})();';
}

function vpClientScript(): string {
  return `(function () {
  const sessionId = window.__FAKE_ISSUER_VP_SESSION_ID__;
  const qrCode = document.getElementById("qr-code");
  const qrEmpty = document.getElementById("qr-empty");
  const scanText = document.getElementById("scan-text");
  const qrGuidance = document.getElementById("qr-guidance");
  const statusLabel = document.getElementById("status-label");
  const metadataPanel = document.getElementById("metadata-panel");
  const metadataStateLabel = document.getElementById("metadata-state-label");
  const metadataGrid = document.getElementById("metadata-grid");
  const metadataJson = document.getElementById("metadata-json");
  let lastMetadataState = "waiting";
  let flashTimer = null;
  let pollTimer = null;

  function setQrConsumed(session) {
    const consumed = session.status !== "created";
    const dcApi = Boolean(session.dc_api);
    qrCode.hidden = consumed;
    qrEmpty.hidden = !consumed;
    scanText.textContent = consumed
      ? (dcApi ? "Answered from the browser" : "Request retrieved by wallet")
      : (dcApi ? "Scan the code to open the presentation page" : "Scan the presentation request with the wallet");
    qrGuidance.textContent = consumed
      ? (dcApi
        ? "The presentation page has reported the outcome of the Digital Credentials API invocation."
        : "The wallet has retrieved the request. Select a matching credential and submit the presentation.")
      : (dcApi
        ? "The code is an HTTPS page URL, not a wallet deeplink. Scanning it opens the page in a browser; the wallet is invoked only when the End-User presses the button there."
        : "The QR points to a request_uri hosted by this service. The wallet response is captured when it posts the presentation.");
  }

  function metadataRows(session) {
    return [
      ["authorization_request", session.authorization_request ? formatJsonValue(session.authorization_request) : "pending"],
      session.dc_api
        ? ["dc_api", formatJsonValue(session.dc_api)]
        : ["request_uri_payload", session.observed.request_uri_payload.value ? JSON.stringify(session.observed.request_uri_payload.value) : "pending"],
      ["wallet_response", session.observed.wallet_response.value ? JSON.stringify(session.observed.wallet_response.value) : "pending"],
      ["presentation_response_decrypted", session.raw && session.raw.presentation_response_decrypted ? formatJsonValue(session.raw.presentation_response_decrypted) : "pending"],
      ["decoded_presentations", session.raw && session.raw.decoded_presentations ? formatJsonValue(session.raw.decoded_presentations) : "pending"],
      ["presentation_validation", session.checks ? JSON.stringify(session.checks) : "pending"],
    ];
  }

  function formatJsonValue(value) {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    return JSON.stringify(parsed, null, 4);
  }

  function metadataState(session) {
    if (session.status === "presentation_validated" || session.status === "presentation_invalid") return "done";
    if (session.status === "dc_api_invocation_reported") return "done";
    if (session.status === "request_retrieved") return "receiving";
    return "waiting";
  }

  function setMetadataState(state) {
    const done = state === "done";
    metadataPanel.classList.toggle("metadata-pending", state === "waiting");
    metadataPanel.classList.toggle("metadata-ready", done);
    metadataStateLabel.textContent = state;
    metadataStateLabel.classList.toggle("metadata-state-waiting", state === "waiting");
    metadataStateLabel.classList.toggle("metadata-state-receiving", state === "receiving");
    metadataStateLabel.classList.toggle("metadata-state-done", done);
  }

  function flashMetadataPanel() {
    metadataPanel.classList.remove("metadata-flash");
    void metadataPanel.offsetWidth;
    metadataPanel.classList.add("metadata-flash");
    if (flashTimer) window.clearTimeout(flashTimer);
    flashTimer = window.setTimeout(function () {
      metadataPanel.classList.remove("metadata-flash");
    }, 1400);
  }

  function render(session) {
    setQrConsumed(session);
    statusLabel.textContent = session.status.replaceAll("_", " ");
    const state = metadataState(session);
    setMetadataState(state);
    if (state !== lastMetadataState) flashMetadataPanel();
    lastMetadataState = state;
    if (state === "done" && pollTimer) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
    const openFields = new Set(
      Array.from(metadataGrid.querySelectorAll(".metadata-row[open]"), function (row) {
        return row.dataset.field;
      }),
    );
    metadataGrid.innerHTML = metadataRows(session)
      .map(function (row) {
        return '<details class="metadata-row" data-field="' + escapeHtml(row[0]) + '"' + (openFields.has(row[0]) ? " open" : "") + '><summary>' + escapeHtml(row[0]) + "</summary><code>" + escapeHtml(row[1]) + "</code></details>";
      })
      .join("");
    metadataJson.textContent = JSON.stringify(
      {
        session_id: session.session_id,
        status: session.status,
        authorization_request: session.authorization_request,
        dc_api: session.dc_api,
        request_uri_payload: session.dc_api ? undefined : session.observed.request_uri_payload,
        wallet_response: session.observed.wallet_response,
        presentation_response_decrypted: session.raw ? session.raw.presentation_response_decrypted : undefined,
        decoded_presentations: session.raw ? session.raw.decoded_presentations : undefined,
        checks: session.checks,
        events: session.events,
      },
      null,
      2,
    );
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (char) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[char];
    });
  }

  async function poll() {
    const response = await fetch("/openid4vp/sessions/" + encodeURIComponent(sessionId), {
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error("vp session fetch failed");
    render(await response.json());
  }

  poll().catch(console.error);
  pollTimer = setInterval(function () {
    poll().catch(console.error);
  }, 1500);
})();`;
}

/**
 * Drives `navigator.credentials.get()` from the button press and forwards whatever comes back.
 * An invocation that yields no Authorization Response is reported separately, so a wallet that
 * refuses the request is captured as a refusal rather than as a verification failure.
 */
function dcApiPresentationScript(): string {
  return `(function () {
  const config = window.__CREDIMI_DC_API__;
  const button = document.getElementById("dc-api-present");
  const status = document.getElementById("dc-api-status");
  const detail = document.getElementById("dc-api-detail");
  if (!button || !config) return;

  function show(message, payload) {
    status.textContent = message;
    detail.textContent = payload ? JSON.stringify(payload, null, 2) : "";
  }

  function sessionPath(suffix) {
    return "/openid4vp/sessions/" + encodeURIComponent(config.session_id) + suffix;
  }

  async function report(outcome, extra) {
    try {
      await fetch(sessionPath("/dc_api_invocation"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(Object.assign({ outcome: outcome }, extra)),
      });
    } catch (error) {
      console.error(error);
    }
  }

  function authorizationResponse(credential) {
    const data = credential && credential.data !== undefined ? credential.data : credential;
    if (typeof data !== "string") return data;
    try {
      return JSON.parse(data);
    } catch (error) {
      return null;
    }
  }

  button.addEventListener("click", async function () {
    button.disabled = true;
    if (!navigator.credentials || typeof window.DigitalCredential === "undefined") {
      show("This browser does not expose the Digital Credentials API. Open this page in a browser that supports it.");
      await report("api_unavailable", { response_returned: false, vp_token_present: false });
      button.disabled = false;
      return;
    }

    show("Waiting for the wallet\\u2026");
    let credential;
    try {
      credential = await navigator.credentials.get({ digital: { requests: [config.request] } });
    } catch (error) {
      show("The wallet did not complete the presentation (" + (error && error.name ? error.name : "unknown error") + "). It may have refused the request, or the presentation may have been cancelled.");
      await report("rejected", {
        error_name: error && error.name ? String(error.name) : undefined,
        error_message: error && error.message ? String(error.message) : undefined,
        response_returned: false,
        vp_token_present: false,
      });
      button.disabled = false;
      return;
    }

    const response = authorizationResponse(credential);
    const presented = Boolean(response && (response.vp_token !== undefined || response.response !== undefined));
    if (!presented) {
      show("The wallet answered without a presentation.", response);
      await report("no_vp_token", { response_returned: true, vp_token_present: false });
      button.disabled = false;
      return;
    }

    show("Submitting the presentation to the verifier\\u2026");
    let submission;
    try {
      submission = await fetch(sessionPath("/response"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(response),
      });
    } catch (error) {
      show("The presentation could not be submitted to the verifier.");
      await report("failed", {
        error_message: error && error.message ? String(error.message) : undefined,
        response_returned: true,
        vp_token_present: true,
      });
      button.disabled = false;
      return;
    }

    const result = await submission.json().catch(function () {
      return null;
    });
    if (submission.ok) {
      show("Presentation accepted. You can close this page.", result);
      return;
    }
    show("The verifier rejected the presentation.", result);
    button.disabled = false;
  });
})();`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[char] ?? char;
  });
}
