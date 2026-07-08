const HELP_README_URL = "https://github.com/ForkbombEu/fake-issuer/blob/master/README.md";

import type { SupportedCredential } from "./metadata.js";

export function indexPage(credentials: SupportedCredential[]): string {
  return htmlPage({
    title: "Fake Issuer",
    body: [
      '<header class="topbar">',
      '<div class="topbar-inner">',
      '<div class="brand-lockup">',
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true">',
      '<span class="brand-name">Wallet metadata capture</span>',
      "</div>",
      '<div class="topbar-actions">',
      '<span class="status-chip status-issuer">ISSUER READY</span>',
      '<a class="btn btn-outline btn-md" href="',
      HELP_README_URL,
      '" target="_blank" rel="noreferrer">Help</a>',
      "</div>",
      "</div>",
      "</header>",
      '<main class="page-shell">',
      '<section class="hero-band">',
      '<div class="hero-inner">',
      '<div class="hero-copy">',
      '<p class="eyebrow">EUDI wallet capture</p>',
      "<h1>Wallet metadata capture</h1>",
      "<p>Step 1) Start a one-time fake issuance flow, scan the offer, and inspect the wallet identifiers, callbacks, and proof keys observed by the issuer.</p>",
      "<p>Step 2) After receiving the credential, start a Presentation session, and inspect the Wallet response as well as the DCQL</p>",
      '<form action="/ui/sessions" method="post" target="_blank">',
      '<label class="credential-picker">',
      "<span>Credential</span>",
      '<select name="credential_configuration_id">',
      credentials.map(credentialOptionHtml).join(""),
      "</select>",
      "</label>",
      '<div class="session-actions">',
      '<button class="btn btn-primary btn-lg" type="submit">New fake-issuance session</button>',
      '<button class="btn btn-outline btn-lg" type="submit" formaction="/ui/openid4vp/sessions">New presentation session</button>',
      "</div>",
      "</form>",
      "</div>",
      '<aside class="summary-panel" aria-label="Captured values">',
      '<div class="section-header compact">',
      "<h2>Captured values</h2>",
      '<span class="count-chip">7</span>',
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
      "</dl>",
      "</section>",
      "</div>",
      "</aside>",
      "</div>",
      "</section>",
      "</main>",
    ].join(""),
  });
}

export function vpSessionPage(sessionId: string, deeplink: string, qrSvg: string): string {
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
      HELP_README_URL,
      '" target="_blank" rel="noreferrer">Help</a>',
      "</div>",
      "</div>",
      "</header>",
      '<main class="page-content session-page">',
      '<section class="session-header container">',
      "<div>",
      '<p class="eyebrow">OpenID4VP session</p>',
      "<h1>Scan the presentation request</h1>",
      '<p class="session-intro">Scan the request, select a matching credential in the wallet, and inspect the submitted presentation response.</p>',
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
      '<p class="scan-text" id="scan-text">Scan the presentation request with the wallet</p>',
      '<p class="qr-guidance" id="qr-guidance">The QR points to a request_uri hosted by this service. The wallet response is captured when it posts the presentation.</p>',
      '<div class="deeplink-panel" aria-label="Presentation request deeplink">',
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
      '<div class="metadata-row"><span>authorization_request</span><code>pending</code></div>',
      '<div class="metadata-row"><span>request_uri_payload</span><code>pending</code></div>',
      '<div class="metadata-row"><span>wallet_response</span><code>pending</code></div>',
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

function credentialOptionHtml(credential: SupportedCredential): string {
  return [
    '<option value="',
    escapeHtml(credential.id),
    '">',
    escapeHtml(credential.displayName),
    "</option>",
  ].join("");
}

export function sessionPage(sessionId: string, deeplink: string, qrSvg: string): string {
  const escapedDeeplink = escapeHtml(deeplink);
  return htmlPage({
    title: "Fake Issuance Session",
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
      HELP_README_URL,
      '" target="_blank" rel="noreferrer">Help</a>',
      "</div>",
      "</div>",
      "</header>",
      '<main class="page-content session-page">',
      '<section class="session-header container">',
      "<div>",
      '<p class="eyebrow">Fake issuance session</p>',
      "<h1>Scan with an EUDI Wallet</h1>",
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
      '<div class="metadata-row"><span>client_id</span><code>pending</code></div>',
      '<div class="metadata-row"><span>redirect_uri</span><code>pending</code></div>',
      '<div class="metadata-row"><span>wallet_jwks</span><code>pending</code></div>',
      '<div class="metadata-row"><span>dpop_jwk</span><code>pending</code></div>',
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

export function errorPage(message: string): string {
  return htmlPage({
    title: "Fake Issuer Error",
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

export function helpPage(readmeMarkdown: string): string {
  return htmlPage({
    title: "Fake Issuer Help",
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
    '<link rel="icon" type="image/svg+xml" href="https://credimi.io/logos/credimi_logo.svg">',
    "<title>",
    escapeHtml(title),
    "</title>",
    "<style>",
    appCss(),
    "</style>",
    "</head>",
    "<body>",
    body,
    footerHtml(),
    '<script>console.log("%cFake Issuer%c Credimi capture UI", "background:#312060;color:#fff;padding:5px 9px;font-weight:800;border-radius:6px 0 0 6px;", "background:#f1e9f7;color:#22172f;padding:5px 9px;font-weight:700;border-radius:0 6px 6px 0;");</script>',
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
    "<p>Fake issuer for EUDI wallet metadata capture and conformance testing.</p>",
    "</div>",
    '<nav class="footer-links" aria-label="Project links">',
    '<a class="footer-link" href="https://forkbomb.eu" target="_blank" rel="noreferrer">Developed by Forkbomb BV</a>',
    '<a class="footer-link fork-link" href="https://github.com/ForkbombEu/fake-issuer" target="_blank" rel="noreferrer">Fork me on GitHub</a>',
    "</nav>",
    "</div>",
    "</div>",
    "</footer>",
  ].join("");
}

function appCss(): string {
  return [
    ":root { --brand-primary: oklch(0.2955 0.1659 277.31); --brand-primary-700: oklch(0.36 0.18 277.31); --brand-secondary: oklch(0.9464 0.0284 294.59); --brand-secondary-strong: oklch(0.8794 0.0567 294.59); --bg: oklch(1 0 0); --bg-muted: oklch(0.9811 0.0064 308.39); --fg: oklch(0.129 0.042 264.695); --fg-muted: oklch(0.7248 0.0094 286.16); --border: oklch(0.929 0.013 255.508); --border-strong: oklch(0.82 0.015 255.508); --warning: oklch(0.65 0.18 85); --warning-bg: oklch(0.96 0.06 85); --success: oklch(0.55 0.18 150); --success-bg: oklch(0.95 0.04 150); --info: oklch(0.4 0.15 260); --info-bg: oklch(0.94 0.04 260); --destructive: oklch(0.50 0.22 25); --wallet: oklch(0.45 0.18 300); --wallet-bg: oklch(0.95 0.04 300); --radius-md: 6px; --radius-lg: 10px; --radius-pill: 999px; --shadow-sm: 0 1px 2px rgba(0,0,0,.04); --max-width: 1280px; --topbar-height: 56px; }",
    "*, *::before, *::after { box-sizing: border-box; }",
    "body { margin: 0; min-height: 100vh; background: var(--brand-secondary); color: var(--fg); font-family: Manrope, system-ui, -apple-system, Segoe UI, sans-serif; font-size: 14px; line-height: 1.571; -webkit-font-smoothing: antialiased; }",
    "h1, h2, p { margin: 0; }",
    "h1 { font-size: 48px; line-height: 1.104; font-weight: 800; letter-spacing: 0; }",
    "h2 { font-size: 28px; line-height: 1.25; font-weight: 700; letter-spacing: 0; }",
    "a { color: var(--brand-primary); }",
    "code, pre, .brand-mark { font-family: JetBrains Mono, Fira Code, Cascadia Code, ui-monospace, monospace; }",
    ".container { max-width: var(--max-width); margin: 0 auto; padding: 0 24px; }",
    ".topbar { position: sticky; top: 0; z-index: 100; height: var(--topbar-height); background: var(--bg); border-bottom: 1px solid var(--border); }",
    ".topbar-inner { max-width: var(--max-width); height: 100%; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }",
    ".topbar-actions { display: inline-flex; align-items: center; gap: 12px; }",
    ".brand-lockup { display: inline-flex; align-items: center; gap: 10px; color: var(--fg); text-decoration: none; }",
    ".brand-logo { display: block; width: 60px; height: 60px; object-fit: contain; flex: 0 0 auto; }",
    ".brand-mark { display: inline-grid; place-items: center; width: 30px; height: 30px; border-radius: var(--radius-md); background: var(--brand-primary); color: white; font-size: 12px; font-weight: 800; }",
    ".brand-name { font-size: 14px; font-weight: 700; }",
    ".page-shell { min-height: calc(100vh - var(--topbar-height)); }",
    ".page-content { padding: 32px 0 64px; }",
    ".footer { background: var(--brand-primary); color: white; padding: 32px 0; }",
    ".footer-inner { max-width: var(--max-width); margin: 0 auto; padding: 0 24px; }",
    ".footer-content { display: flex; align-items: center; justify-content: space-between; gap: 32px; }",
    ".footer-brand { display: inline-flex; align-items: center; gap: 14px; min-width: 0; }",
    ".footer-logo { display: block; width: 60px; height: 60px; object-fit: contain; flex: 0 0 auto; }",
    ".footer-brand p { max-width: 420px; color: rgba(255,255,255,.76); font-size: 13px; line-height: 1.5; }",
    ".footer-mark { background: white; color: var(--brand-primary); flex: 0 0 auto; }",
    ".footer-links { display: inline-flex; align-items: center; justify-content: flex-end; gap: 12px; flex-wrap: wrap; }",
    ".footer-link { display: inline-flex; align-items: center; min-height: 36px; padding: 0 14px; border: 1px solid rgba(255,255,255,.22); border-radius: var(--radius-md); color: white; font-size: 13px; font-weight: 700; text-decoration: none; white-space: nowrap; transition: background 150ms ease-out, border-color 150ms ease-out; }",
    ".footer-link:hover { background: rgba(255,255,255,.08); border-color: rgba(255,255,255,.44); }",
    ".fork-link { background: white; color: var(--brand-primary); border-color: white; }",
    ".fork-link:hover { background: var(--brand-secondary); border-color: var(--brand-secondary); }",
    ".hero-band { position: relative; overflow: hidden; padding: 64px 0; }",
    ".hero-band::after { content: ''; position: absolute; top: 0; right: 0; width: 300px; height: 300px; background: linear-gradient(135deg, transparent 49.5%, rgba(0,0,0,0.04) 49.5%, rgba(0,0,0,0.04) 50.5%, transparent 50.5%), linear-gradient(45deg, transparent 49.5%, rgba(0,0,0,0.04) 49.5%, rgba(0,0,0,0.04) 50.5%, transparent 50.5%); pointer-events: none; }",
    ".hero-inner { position: relative; z-index: 1; max-width: var(--max-width); margin: 0 auto; padding: 0 24px; display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 430px); gap: 32px; align-items: start; }",
    ".hero-copy { display: grid; gap: 20px; max-width: 740px; }",
    ".hero-copy form { display: grid; gap: 14px; justify-items: start; }",
    ".hero-copy p:not(.eyebrow) { max-width: 640px; color: var(--fg-muted); font-size: 16px; line-height: 1.6; }",
    ".session-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }",
    ".credential-picker { display: grid; gap: 8px; width: min(100%, 520px); color: var(--fg); font-size: 13px; font-weight: 700; }",
    ".credential-picker select { width: 100%; min-height: 44px; padding: 0 42px 0 14px; border: 1px solid var(--border-strong); border-radius: var(--radius-md); background: var(--bg); color: var(--fg); font: inherit; font-size: 14px; font-weight: 600; }",
    ".credential-picker select:focus { outline: 2px solid color-mix(in oklch, var(--brand-primary) 36%, transparent); outline-offset: 2px; }",
    ".eyebrow { margin-bottom: 8px; color: var(--brand-primary); font-size: 12px; font-weight: 500; letter-spacing: 0.14em; text-transform: uppercase; }",
    ".card, .summary-panel { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--shadow-sm); }",
    ".summary-panel { display: grid; gap: 18px; }",
    ".section-header, .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }",
    ".section-header.compact { margin-bottom: 0; }",
    ".section-header h2::after, .section-head h2::after { content: ':'; }",
    ".count-chip { display: inline-flex; align-items: center; justify-content: center; min-width: 24px; height: 24px; padding: 0 8px; border-radius: var(--radius-pill); background: var(--brand-secondary-strong); color: var(--fg-muted); font-size: 13px; font-weight: 600; }",
    ".status-chip { display: inline-flex; align-items: center; gap: 6px; min-height: 24px; padding: 0 12px; border-radius: var(--radius-pill); font-size: 11px; font-weight: 500; text-transform: uppercase; white-space: nowrap; }",
    ".status-chip::before { content: ''; width: 12px; height: 12px; border-radius: 50%; }",
    ".status-issuer { background: var(--warning-bg); color: var(--warning); }",
    ".status-issuer::before { background: var(--warning); }",
    ".status-wallet { background: var(--wallet-bg); color: var(--wallet); }",
    ".status-wallet::before { background: var(--wallet); }",
    ".btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; width: fit-content; border: 0; border-radius: var(--radius-lg); font: inherit; font-size: 13px; font-weight: 600; text-decoration: none; cursor: pointer; transition: background 150ms ease-out, border-color 150ms ease-out; }",
    ".btn-lg { min-height: 44px; padding: 0 24px; font-size: 16px; }",
    ".btn-md { min-height: 36px; padding: 0 20px; }",
    ".btn-primary { background: var(--brand-primary); color: white; }",
    ".btn-primary:hover { background: var(--brand-primary-700); }",
    ".btn-outline { background: var(--bg); color: var(--fg); border: 1px solid var(--border); }",
    ".btn-outline:hover { border-color: var(--border-strong); background: var(--bg-muted); }",
    ".capture-list { display: grid; gap: 12px; margin: 0; }",
    ".capture-list div { padding: 12px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".capture-groups { display: grid; gap: 18px; }",
    ".capture-group { display: grid; gap: 10px; }",
    ".capture-group h3 { margin: 0; color: var(--brand-primary); font-size: 13px; line-height: 1.4; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }",
    "dt { color: var(--fg); font-size: 13px; font-weight: 700; }",
    "dd { margin: 4px 0 0; color: var(--fg-muted); font-size: 13px; line-height: 1.5; }",
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
    ".metadata-row { display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 12px; padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); }",
    ".metadata-row span { color: var(--fg-muted); font-size: 13px; font-weight: 600; }",
    ".metadata-row code { overflow-wrap: anywhere; color: var(--fg); font-size: 12px; white-space: pre-wrap; }",
    ".metadata-json { min-height: 280px; max-height: 50vh; overflow: auto; margin: 0; padding: 16px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-muted); color: var(--fg); white-space: pre-wrap; font-size: 13px; line-height: 1.5; }",
    ".danger-panel { display: grid; gap: 20px; border-left: 3px solid var(--destructive); }",
    ".danger-panel h1 { font-size: 28px; }",
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
    "@media (prefers-reduced-motion: reduce) { .metadata-state-waiting::before, .metadata-state-receiving::before, .metadata-flash { animation: none; } }",
    "@media (max-width: 860px) { h1 { font-size: 32px; } h2 { font-size: 22px; } .container, .topbar-inner, .hero-inner, .footer-inner { padding-left: 16px; padding-right: 16px; } .hero-band { padding: 40px 0; } .hero-inner, .session-layout { grid-template-columns: 1fr; } .session-header, .section-head, .footer-content { flex-direction: column; align-items: stretch; } .session-actions { align-items: stretch; flex-direction: column; } .session-actions .btn { width: 100%; } .footer-links { justify-content: flex-start; } .metadata-row { grid-template-columns: 1fr; } .qr-box { width: 100%; max-width: 336px; } }",
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

function clientScript(): string {
  return '(function () {\n  const sessionId = window.__FAKE_ISSUER_SESSION_ID__;\n  const qrCode = document.getElementById("qr-code");\n  const qrEmpty = document.getElementById("qr-empty");\n  const scanText = document.getElementById("scan-text");\n  const qrGuidance = document.getElementById("qr-guidance");\n  const statusLabel = document.getElementById("status-label");\n  const metadataPanel = document.getElementById("metadata-panel");\n  const metadataStateLabel = document.getElementById("metadata-state-label");\n  const metadataGrid = document.getElementById("metadata-grid");\n  const metadataJson = document.getElementById("metadata-json");\n  let lastMetadataState = "waiting";\n  let flashTimer = null;\n  let pollTimer = null;\n\n  function setQrConsumed(consumed) {\n    qrCode.hidden = consumed;\n    qrEmpty.hidden = !consumed;\n    scanText.textContent = consumed ? "Offer retrieved by wallet" : "Scan the offer and accept it in the wallet";\n    qrGuidance.textContent = consumed\n      ? "The wallet has retrieved the offer. Accept the issuance, then complete the final wallet interaction."\n      : "After scanning, keep going in the wallet issuance flow. Most wallets ask you to accept the issuance before metadata appears here.";\n  }\n\n  function metadataRows(session) {\n    const walletJwks = session.observed.wallet_jwks.observed\n      ? JSON.stringify(session.observed.wallet_jwks.jwks)\n      : "pending";\n    const dpopJwk = session.observed.dpop_jwk.observed\n      ? JSON.stringify(session.observed.dpop_jwk.jwk)\n      : "pending";\n    return [\n      ["client_id", session.observed.client_id.value || "pending"],\n      ["redirect_uri", session.observed.redirect_uri.value || "pending"],\n      ["wallet_jwks", walletJwks],\n      ["dpop_jwk", dpopJwk],\n    ];\n  }\n\n  function sessionHasMetadata(session) {\n    return Boolean(\n      session.observed.client_id.value ||\n        session.observed.redirect_uri.value ||\n        session.observed.wallet_jwks.observed ||\n        session.observed.dpop_jwk.observed,\n    );\n  }\n\n  function credentialRequestArrived(session) {\n    return Boolean(session.raw && session.raw.credential_request);\n  }\n\n  function metadataState(session) {\n    if (credentialRequestArrived(session)) return "done";\n    if (sessionHasMetadata(session)) return "receiving";\n    return "waiting";\n  }\n\n  function setMetadataState(state) {\n    const done = state === "done";\n    metadataPanel.classList.toggle("metadata-pending", state === "waiting");\n    metadataPanel.classList.toggle("metadata-ready", done);\n    metadataStateLabel.textContent = state;\n    metadataStateLabel.classList.toggle("metadata-state-waiting", state === "waiting");\n    metadataStateLabel.classList.toggle("metadata-state-receiving", state === "receiving");\n    metadataStateLabel.classList.toggle("metadata-state-done", done);\n  }\n\n  function flashMetadataPanel() {\n    metadataPanel.classList.remove("metadata-flash");\n    void metadataPanel.offsetWidth;\n    metadataPanel.classList.add("metadata-flash");\n    if (flashTimer) window.clearTimeout(flashTimer);\n    flashTimer = window.setTimeout(function () {\n      metadataPanel.classList.remove("metadata-flash");\n    }, 1400);\n  }\n\n  function render(session) {\n    setQrConsumed(session.status !== "created");\n    statusLabel.textContent = session.status.replaceAll("_", " ");\n    const state = metadataState(session);\n    setMetadataState(state);\n    if (state !== lastMetadataState) flashMetadataPanel();\n    lastMetadataState = state;\n    if (state === "done" && pollTimer) {\n      window.clearInterval(pollTimer);\n      pollTimer = null;\n    }\n    metadataGrid.innerHTML = metadataRows(session)\n      .map(function (row) {\n        return \'<div class="metadata-row"><span>\' + escapeHtml(row[0]) + \'</span><code>\' + escapeHtml(row[1]) + \'</code></div>\';\n      })\n      .join("");\n    metadataJson.textContent = JSON.stringify(\n      {\n        session_id: session.session_id,\n        status: session.status,\n        observed: session.observed,\n        checks: session.checks,\n        events: session.events,\n      },\n      null,\n      2,\n    );\n  }\n\n  function escapeHtml(value) {\n    return String(value).replace(/[&<>"\']/g, function (char) {\n      return {\n        "&": "&amp;",\n        "<": "&lt;",\n        ">": "&gt;",\n        \'"\': "&quot;",\n        "\'": "&#39;",\n      }[char];\n    });\n  }\n\n  async function poll() {\n    const response = await fetch("/sessions/" + encodeURIComponent(sessionId), {\n      headers: { accept: "application/json" },\n    });\n    if (!response.ok) throw new Error("session fetch failed");\n    render(await response.json());\n  }\n\n  poll().catch(console.error);\n  pollTimer = setInterval(function () {\n    poll().catch(console.error);\n  }, 1500);\n})();';
}

function vpClientScript(): string {
  return '(function () {\n  const sessionId = window.__FAKE_ISSUER_VP_SESSION_ID__;\n  const qrCode = document.getElementById("qr-code");\n  const qrEmpty = document.getElementById("qr-empty");\n  const scanText = document.getElementById("scan-text");\n  const qrGuidance = document.getElementById("qr-guidance");\n  const statusLabel = document.getElementById("status-label");\n  const metadataPanel = document.getElementById("metadata-panel");\n  const metadataStateLabel = document.getElementById("metadata-state-label");\n  const metadataGrid = document.getElementById("metadata-grid");\n  const metadataJson = document.getElementById("metadata-json");\n  let lastMetadataState = "waiting";\n  let flashTimer = null;\n  let pollTimer = null;\n\n  function setQrConsumed(consumed) {\n    qrCode.hidden = consumed;\n    qrEmpty.hidden = !consumed;\n    scanText.textContent = consumed ? "Request retrieved by wallet" : "Scan the presentation request with the wallet";\n    qrGuidance.textContent = consumed\n      ? "The wallet has retrieved the request. Select a matching credential and submit the presentation."\n      : "The QR points to a request_uri hosted by this service. The wallet response is captured when it posts the presentation.";\n  }\n\n  function metadataRows(session) {\n    return [\n      ["authorization_request", session.authorization_request ? formatJsonValue(session.authorization_request) : "pending"],\n      ["request_uri_payload", session.observed.request_uri_payload.value ? JSON.stringify(session.observed.request_uri_payload.value) : "pending"],\n      ["wallet_response", session.observed.wallet_response.value ? JSON.stringify(session.observed.wallet_response.value) : "pending"],\n    ];\n  }\n\n  function formatJsonValue(value) {\n    const parsed = typeof value === "string" ? JSON.parse(value) : value;\n    return JSON.stringify(parsed, null, 4);\n  }\n\n  function metadataState(session) {\n    if (session.status === "presentation_received") return "done";\n    if (session.status === "request_retrieved") return "receiving";\n    return "waiting";\n  }\n\n  function setMetadataState(state) {\n    const done = state === "done";\n    metadataPanel.classList.toggle("metadata-pending", state === "waiting");\n    metadataPanel.classList.toggle("metadata-ready", done);\n    metadataStateLabel.textContent = state;\n    metadataStateLabel.classList.toggle("metadata-state-waiting", state === "waiting");\n    metadataStateLabel.classList.toggle("metadata-state-receiving", state === "receiving");\n    metadataStateLabel.classList.toggle("metadata-state-done", done);\n  }\n\n  function flashMetadataPanel() {\n    metadataPanel.classList.remove("metadata-flash");\n    void metadataPanel.offsetWidth;\n    metadataPanel.classList.add("metadata-flash");\n    if (flashTimer) window.clearTimeout(flashTimer);\n    flashTimer = window.setTimeout(function () {\n      metadataPanel.classList.remove("metadata-flash");\n    }, 1400);\n  }\n\n  function render(session) {\n    setQrConsumed(session.status !== "created");\n    statusLabel.textContent = session.status.replaceAll("_", " ");\n    const state = metadataState(session);\n    setMetadataState(state);\n    if (state !== lastMetadataState) flashMetadataPanel();\n    lastMetadataState = state;\n    if (state === "done" && pollTimer) {\n      window.clearInterval(pollTimer);\n      pollTimer = null;\n    }\n    metadataGrid.innerHTML = metadataRows(session)\n      .map(function (row) {\n        return \'<div class="metadata-row"><span>\' + escapeHtml(row[0]) + \'</span><code>\' + escapeHtml(row[1]) + \'</code></div>\';\n      })\n      .join("");\n    metadataJson.textContent = JSON.stringify(\n      {\n        session_id: session.session_id,\n        status: session.status,\n        authorization_request: session.authorization_request,\n        request_uri_payload: session.observed.request_uri_payload,\n        wallet_response: session.observed.wallet_response,\n        events: session.events,\n      },\n      null,\n      2,\n    );\n  }\n\n  function escapeHtml(value) {\n    return String(value).replace(/[&<>"\']/g, function (char) {\n      return {\n        "&": "&amp;",\n        "<": "&lt;",\n        ">": "&gt;",\n        \'"\': "&quot;",\n        "\'": "&#39;",\n      }[char];\n    });\n  }\n\n  async function poll() {\n    const response = await fetch("/openid4vp/sessions/" + encodeURIComponent(sessionId), {\n      headers: { accept: "application/json" },\n    });\n    if (!response.ok) throw new Error("vp session fetch failed");\n    render(await response.json());\n  }\n\n  poll().catch(console.error);\n  pollTimer = setInterval(function () {\n    poll().catch(console.error);\n  }, 1500);\n})();';
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
