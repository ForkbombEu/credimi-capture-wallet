import { APP_CSS } from "./styles.js";

export const REPOSITORY_URL = "https://github.com/ForkbombEu/credimi-capture-wallet";
export const OPENAPI_URL = "/openapi.json";
export const API_DOCS_URL = "/docs";

export function htmlPage({ title, body }: { title: string; body: string }): string {
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
    APP_CSS,
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
export function escapeHtml(value: string): string {
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
