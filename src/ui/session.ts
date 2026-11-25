import type { VpDcApiRequest } from "../types.js";
import { API_DOCS_URL, OPENAPI_URL, REPOSITORY_URL, escapeHtml, htmlPage } from "./html.js";
import { renderMarkdown } from "./markdown.js";
import { clientScript, dcApiPresentationScript, vpClientScript } from "./scripts.js";
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
