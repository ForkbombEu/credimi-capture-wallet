import type { VpDcApiRequest } from "../types.js";
import { API_DOCS_URL, OPENAPI_URL, REPOSITORY_URL, escapeHtml, htmlPage } from "./html.js";
import { heroSectionHtml, sectionIntroHtml } from "./launcher.js";
import { renderMarkdown } from "./markdown.js";
import {
  clientScript,
  copyButtonScript,
  dcApiPresentationScript,
  vpClientScript,
} from "./scripts.js";
export function vpSessionPage(
  sessionId: string,
  deeplink: string,
  qrSvg: string,
  dcApi = false,
): string {
  return htmlPage({
    title: "OpenID4VP Session",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="topbar-brand" href="/">',
      '<img class="topbar-logo" src="/assets/credimi_logo.svg" alt="Credimi">',
      '<span class="topbar-project-title">Wallet metadata capture</span>',
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
      "<main>",
      heroSectionHtml({
        id: "session-title",
        title: "OpenID4VP session",
        paragraphsHtml: [
          dcApi
            ? "Scan the code with the device that holds the wallet. It opens this verifier’s presentation page in the browser, where the presentation is started through the Digital Credentials API."
            : "Scan the request, select a matching credential in the wallet, and inspect the submitted presentation response.",
        ],
      }),
      '<section class="page-section" aria-labelledby="scan-text">',
      '<div class="container">',
      sectionIntroHtml({
        tag: "h2",
        id: "scan-text",
        title: dcApi
          ? "Scan the code to open the presentation page"
          : "Scan the presentation request with the wallet",
        paragraphsHtml: [
          dcApi
            ? '<span id="qr-guidance">The code is an HTTPS page URL, not a wallet deeplink. Scanning it opens the page in a browser; the wallet is invoked only when the End-User presses “Present credential” there.</span>'
            : '<span id="qr-guidance">The QR points to a request_uri hosted by this service. The wallet response is captured when it posts the presentation.</span>',
        ],
      }),
      '<div class="session-layout qr-layout">',
      '<div class="qr-panel">',
      '<div class="qr-box" id="qr-box" aria-live="polite">',
      '<div class="qr-code" id="qr-code">',
      qrSvg,
      "</div>",
      '<div class="qr-empty" id="qr-empty" hidden></div>',
      "</div>",
      deeplinkHtml(
        deeplink,
        dcApi ? "DC API presentation page URL" : "Presentation request deeplink",
      ),
      "</div>",
      '<div class="card metadata-panel metadata-pending" id="metadata-panel">',
      '<div class="panel-head">',
      '<h2 class="subsection-heading">Presentation response</h2>',
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
      "</div>",
      "</div>",
      "</section>",
      "</main>",
      "<script>window.__FAKE_ISSUER_VP_SESSION_ID__ = ",
      JSON.stringify(sessionId),
      ";</script>",
      "<script>",
      vpClientScript(),
      "</script>",
      "<script>",
      copyButtonScript(),
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
      '<a class="topbar-brand" href="/">',
      '<img class="topbar-logo" src="/assets/credimi_logo.svg" alt="Credimi">',
      '<span class="topbar-project-title">Wallet metadata capture</span>',
      "</a>",
      '<div class="topbar-actions">',
      '<span class="status-chip status-wallet">',
      escapeHtml(options.request.protocol),
      "</span>",
      "</div>",
      "</div>",
      "</header>",
      "<main>",
      heroSectionHtml({
        id: "session-title",
        title: "Present a credential",
        paragraphsHtml: [
          [
            "This page asks your wallet for a presentation through the browser’s Digital Credentials API. The request is bound to ",
            escapeHtml(options.expectedOrigin),
            " and expires at ",
            escapeHtml(options.expiresAt),
            ".",
          ].join(""),
        ],
      }),
      '<section class="page-section">',
      '<div class="container session-layout">',
      '<div class="card">',
      blocked
        ? `<p class="qr-guidance" id="dc-api-status">${escapeHtml(notice)}</p>`
        : [
            '<button class="btn btn-primary btn-lg" id="dc-api-present" type="button">Present credential</button>',
            '<p class="qr-guidance" id="dc-api-status">Press the button to let your wallet answer the request.</p>',
            '<pre class="metadata-json" id="dc-api-detail"></pre>',
          ].join(""),
      "</div>",
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
  return htmlPage({
    title: "OpenID4VCI Session",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<a class="topbar-brand" href="/">',
      '<img class="topbar-logo" src="/assets/credimi_logo.svg" alt="Credimi">',
      '<span class="topbar-project-title">Wallet metadata capture</span>',
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
      "<main>",
      heroSectionHtml({
        id: "session-title",
        title: "OpenID4VCI session",
        paragraphsHtml: [
          "Scan the offer, accept the issuance in the wallet, then complete the final wallet interaction.",
        ],
      }),
      '<section class="page-section" aria-labelledby="scan-text">',
      '<div class="container">',
      sectionIntroHtml({
        tag: "h2",
        id: "scan-text",
        title: "Scan the offer and accept it in the wallet",
        paragraphsHtml: [
          '<span id="qr-guidance">After scanning, keep going in the wallet issuance flow. Most wallets ask you to accept the issuance before metadata appears here.</span>',
        ],
      }),
      '<div class="session-layout qr-layout">',
      '<div class="qr-panel">',
      '<div class="qr-box" id="qr-box" aria-live="polite">',
      '<div class="qr-code" id="qr-code">',
      qrSvg,
      "</div>",
      '<div class="qr-empty" id="qr-empty" hidden></div>',
      "</div>",
      deeplinkHtml(deeplink, "Credential offer deeplink"),
      "</div>",
      '<div class="card metadata-panel metadata-pending" id="metadata-panel">',
      '<div class="panel-head">',
      '<h2 class="subsection-heading">Wallet metadata</h2>',
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
      "</div>",
      "</div>",
      "</section>",
      "</main>",
      "<script>window.__FAKE_ISSUER_SESSION_ID__ = ",
      JSON.stringify(sessionId),
      ";</script>",
      "<script>",
      clientScript(),
      "</script>",
      "<script>",
      copyButtonScript(),
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
      brandTopbarHtml(),
      "<main>",
      heroSectionHtml({
        id: "session-title",
        title: "Add a credential",
        paragraphsHtml: [
          "Open the offer in your wallet on this device, or scan it with your wallet.",
        ],
      }),
      '<section class="page-section">',
      '<div class="container session-layout">',
      '<div class="qr-panel">',
      '<a class="btn btn-primary btn-lg" id="engage-offer" href="',
      escapedDeeplink,
      '">Open in wallet</a>',
      '<div class="qr-box"><div class="qr-code">',
      qrSvg,
      "</div></div>",
      "</div>",
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
}

/** The deeplink the QR code carries, as wide as the code, with a button that copies it. */
function deeplinkHtml(deeplink: string, label: string): string {
  const escaped = escapeHtml(deeplink);
  return [
    `<div class="deeplink-panel" aria-label="${escapeHtml(label)}">`,
    `<a class="deeplink" id="deeplink" href="${escaped}">${escaped}</a>`,
    '<button class="btn btn-sm btn-copy" type="button" data-copy="deeplink">',
    '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    "<span>Copy</span>",
    "</button>",
    "</div>",
  ].join("");
}

/** The top bar of a page with no session controls: the brand, and optionally a status chip. */
function brandTopbarHtml(chipHtml = ""): string {
  return [
    '<header class="topbar">',
    '<div class="topbar-inner">',
    '<a class="topbar-brand" href="/">',
    '<img class="topbar-logo" src="/assets/credimi_logo.svg" alt="Credimi">',
    '<span class="topbar-project-title">Wallet metadata capture</span>',
    "</a>",
    chipHtml,
    "</div>",
    "</header>",
  ].join("");
}

export function errorPage(message: string): string {
  return htmlPage({
    title: "Wallet Metadata Capture Error",
    body: [
      brandTopbarHtml(),
      "<main>",
      heroSectionHtml({
        id: "error-title",
        title: "Something went wrong",
        paragraphsHtml: [escapeHtml(message)],
      }),
      '<section class="page-section">',
      '<div class="container">',
      '<a class="btn btn-primary btn-lg" href="/">Back to launcher</a>',
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
}

export function vpRedirectPage(responseCode: string, found: boolean): string {
  const title = found ? "Presentation complete" : "Redirect page not found";
  const description = found
    ? "You can return to the application."
    : "The response code could not be matched to a presentation session.";

  return htmlPage({
    title,
    body: [
      brandTopbarHtml(),
      "<main>",
      heroSectionHtml({ id: "redirect-title", title, paragraphsHtml: [description] }),
      '<section class="page-section">',
      '<div class="container redirect-result">',
      '<dl class="redirect-response-code">',
      "<dt>response_code</dt>",
      "<dd><code>",
      escapeHtml(responseCode),
      "</code></dd>",
      "</dl>",
      '<a class="btn btn-primary btn-lg" href="/">Back to launcher</a>',
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
}

export function helpPage(readmeMarkdown: string): string {
  return htmlPage({
    title: "Wallet Metadata Capture Help",
    body: [
      brandTopbarHtml('<span class="status-chip status-wallet">help</span>'),
      "<main>",
      heroSectionHtml({
        id: "help-title",
        title: "Help",
        paragraphsHtml: [
          "How to issue and verify credentials with this service, and every option it offers, from its README.",
        ],
      }),
      '<section class="page-section page-section-white">',
      '<div class="container">',
      '<article class="readme-card">',
      renderMarkdown(readmeMarkdown),
      "</article>",
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
}
