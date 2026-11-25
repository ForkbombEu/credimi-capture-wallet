/**
 * Creates a session through the public JSON API, from the launcher's one-click buttons or from the
 * issuer or verifier page form. A form sends only the fields the operator filled, so every other
 * parameter keeps the API default, and a refusal is shown as the API's own error body.
 */
export function launcherScript(): string {
  return `(function () {
  async function launch(endpoint, sessionPage, body, errorBox, button) {
    errorBox.hidden = true;
    button.disabled = true;
    button.dataset.launching = "true";
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await response.json().catch(() => null);
      if (response.status === 201 && payload && typeof payload.session_id === "string") {
        window.location.assign(sessionPage + encodeURIComponent(payload.session_id));
        return;
      }
      showError(errorBox, "The API refused the session (HTTP " + response.status + ")\\n" + JSON.stringify(payload, null, 2));
    } catch (error) {
      showError(errorBox, "The session request failed: " + error.message);
    }
    button.disabled = false;
    delete button.dataset.launching;
  }

  // The disabled button navigates away; Back restores the page from the back/forward cache as it
  // was left, so the buttons a launch disabled are released when the page is shown again.
  window.addEventListener("pageshow", () => {
    for (const button of document.querySelectorAll("[data-launching]")) {
      button.disabled = false;
      delete button.dataset.launching;
    }
  });

  function showError(errorBox, message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  const statusListToggle = document.querySelector("[data-status-list-toggle]");
  for (const button of document.querySelectorAll("button[data-launch]")) {
    button.addEventListener("click", () => {
      const body = JSON.parse(button.dataset.body);
      if (statusListToggle?.checked && button.dataset.statusList === "true") {
        body.status_list_enabled = true;
      }
      const errorBox = button.closest("li").querySelector("[data-launcher-error]");
      launch(button.dataset.launch, button.dataset.sessionPage, body, errorBox, button);
    });
  }

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

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    let body;
    try {
      body = requestBody();
    } catch (error) {
      showError(errorBox, error.message);
      return;
    }
    launch(form.dataset.endpoint, form.dataset.sessionPage, body, errorBox, submit);
  });

  // A launcher "Customize" link names the credential in the fragment.
  const preselected = new URLSearchParams(window.location.hash.slice(1)).get("credential_configuration_id");
  if (picker && preselected && Array.from(picker.options).some((option) => option.value === preselected)) {
    picker.value = preselected;
    form.querySelector("details.advanced-settings")?.setAttribute("open", "");
  }
  picker?.addEventListener("change", applyCredential);
  applyCredential();
})();`;
}

export function clientScript(): string {
  return '(function () {\n  const sessionId = window.__FAKE_ISSUER_SESSION_ID__;\n  const qrCode = document.getElementById("qr-code");\n  const qrEmpty = document.getElementById("qr-empty");\n  const scanText = document.getElementById("scan-text");\n  const qrGuidance = document.getElementById("qr-guidance");\n  const statusLabel = document.getElementById("status-label");\n  const metadataPanel = document.getElementById("metadata-panel");\n  const metadataStateLabel = document.getElementById("metadata-state-label");\n  const metadataGrid = document.getElementById("metadata-grid");\n  const metadataJson = document.getElementById("metadata-json");\n  // A Notification Request is optional for the wallet, so polling for one stops after this long.\n  const notificationWaitMs = 120000;\n  let lastMetadataState = "waiting";\n  let flashTimer = null;\n  let pollTimer = null;\n  let doneAt = null;\n\n  function setQrConsumed(consumed) {\n    qrCode.hidden = consumed;\n    qrEmpty.hidden = !consumed;\n    scanText.textContent = consumed ? "Offer retrieved by wallet" : "Scan the offer and accept it in the wallet";\n    qrGuidance.textContent = consumed\n      ? "The wallet has retrieved the offer. Accept the issuance, then complete the final wallet interaction."\n      : "After scanning, keep going in the wallet issuance flow. Most wallets ask you to accept the issuance before metadata appears here.";\n  }\n\n  function notificationReceipts(session) {\n    return (session.notifications || []).flatMap(function (notification) {\n      return notification.received;\n    });\n  }\n\n  function walletNotification(session) {\n    const receipts = notificationReceipts(session);\n    if (receipts.length > 0) {\n      return receipts\n        .map(function (receipt) {\n          return receipt.event_description ? receipt.event + ": " + receipt.event_description : receipt.event;\n        })\n        .join("; ");\n    }\n    return credentialRequestArrived(session) ? "not reported" : "pending";\n  }\n\n  function metadataRows(session) {\n    const walletJwks = session.observed.wallet_jwks.observed\n      ? JSON.stringify(session.observed.wallet_jwks.jwks)\n      : "pending";\n    const dpopJwk = session.observed.dpop_jwk.observed\n      ? JSON.stringify(session.observed.dpop_jwk.jwk)\n      : "pending";\n    return [\n      ["client_id", session.observed.client_id.value || "pending"],\n      ["redirect_uri", session.observed.redirect_uri.value || "pending"],\n      ["wallet_jwks", walletJwks],\n      ["dpop_jwk", dpopJwk],\n      ["wallet_notification", walletNotification(session)],\n    ];\n  }\n\n  function sessionHasMetadata(session) {\n    return Boolean(\n      session.observed.client_id.value ||\n        session.observed.redirect_uri.value ||\n        session.observed.wallet_jwks.observed ||\n        session.observed.dpop_jwk.observed,\n    );\n  }\n\n  function credentialRequestArrived(session) {\n    return Boolean(session.raw && session.raw.credential_request);\n  }\n\n  function metadataState(session) {\n    if (credentialRequestArrived(session)) return "done";\n    if (sessionHasMetadata(session)) return "receiving";\n    return "waiting";\n  }\n\n  function setMetadataState(state) {\n    const done = state === "done";\n    metadataPanel.classList.toggle("metadata-pending", state === "waiting");\n    metadataPanel.classList.toggle("metadata-ready", done);\n    metadataStateLabel.textContent = state;\n    metadataStateLabel.classList.toggle("metadata-state-waiting", state === "waiting");\n    metadataStateLabel.classList.toggle("metadata-state-receiving", state === "receiving");\n    metadataStateLabel.classList.toggle("metadata-state-done", done);\n  }\n\n  function flashMetadataPanel() {\n    metadataPanel.classList.remove("metadata-flash");\n    void metadataPanel.offsetWidth;\n    metadataPanel.classList.add("metadata-flash");\n    if (flashTimer) window.clearTimeout(flashTimer);\n    flashTimer = window.setTimeout(function () {\n      metadataPanel.classList.remove("metadata-flash");\n    }, 1400);\n  }\n\n  function render(session) {\n    setQrConsumed(session.status !== "created");\n    statusLabel.textContent = session.status.replaceAll("_", " ");\n    const state = metadataState(session);\n    setMetadataState(state);\n    if (state !== lastMetadataState) flashMetadataPanel();\n    lastMetadataState = state;\n    if (state === "done" && doneAt === null) doneAt = Date.now();\n    const notified = notificationReceipts(session).length > 0;\n    if (pollTimer && doneAt !== null && (notified || Date.now() - doneAt > notificationWaitMs)) {\n      window.clearInterval(pollTimer);\n      pollTimer = null;\n    }\n    const openFields = new Set(\n      Array.from(metadataGrid.querySelectorAll(".metadata-row[open]"), function (row) {\n        return row.dataset.field;\n      }),\n    );\n    metadataGrid.innerHTML = metadataRows(session)\n      .map(function (row) {\n        return \'<details class="metadata-row" data-field="\' + escapeHtml(row[0]) + \'"\' + (openFields.has(row[0]) ? " open" : "") + \'><summary>\' + escapeHtml(row[0]) + \'</summary><code>\' + escapeHtml(row[1]) + \'</code></details>\';\n      })\n      .join("");\n    metadataJson.textContent = JSON.stringify(\n      {\n        session_id: session.session_id,\n        status: session.status,\n        observed: session.observed,\n        checks: session.checks,\n        notifications: session.notifications,\n        events: session.events,\n      },\n      null,\n      2,\n    );\n  }\n\n  function escapeHtml(value) {\n    return String(value).replace(/[&<>"\']/g, function (char) {\n      return {\n        "&": "&amp;",\n        "<": "&lt;",\n        ">": "&gt;",\n        \'"\': "&quot;",\n        "\'": "&#39;",\n      }[char];\n    });\n  }\n\n  async function poll() {\n    const response = await fetch("/sessions/" + encodeURIComponent(sessionId), {\n      headers: { accept: "application/json" },\n    });\n    if (!response.ok) throw new Error("session fetch failed");\n    render(await response.json());\n  }\n\n  poll().catch(console.error);\n  pollTimer = setInterval(function () {\n    poll().catch(console.error);\n  }, 1500);\n})();';
}

export function vpClientScript(): string {
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
export function dcApiPresentationScript(): string {
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
