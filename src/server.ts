import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import express, { type Request } from "express";
import QRCode from "qrcode";
import { captureClientAuthentication } from "./client-auth.js";
import { type InitOptions, initIssuer, loadIssuerJwks } from "./config.js";
import { issueMdocCredential, issueSdJwtCredential } from "./credential.js";
import {
  authorizationServerMetadata,
  credentialIssuerMetadata,
  credentialOffer,
  credentialOfferDeeplink,
  jwtVcIssuerMetadata,
  supportedCredentialById,
  supportedCredentialConfigurationIds,
  supportedCredentials,
} from "./metadata.js";
import {
  buildPresentationAuthorizationRequest,
  defaultPresentationRequest,
  presentationRequestByReferenceDeeplink,
} from "./openid4vp.js";
import { verifyPkce } from "./pkce.js";
import { captureProofHeaders, decodeDpopHeader, firstWalletJwks } from "./proofs.js";
import { CaptureStore, asStringOrNull, updateObservedValue } from "./state.js";
import type { AppConfig, JsonRecord, SessionCapture, VpSessionCapture } from "./types.js";
import { errorPage, helpPage, indexPage, sessionPage, vpSessionPage } from "./ui.js";

export function createApp(config: AppConfig, store = new CaptureStore(config)): express.Express {
  const app = express();

  app.use(
    express.json({
      type: ["application/json", "application/*+json"],
      verify: rawBodyCapture,
    }),
  );
  app.use(express.urlencoded({ extended: false, type: "application/x-www-form-urlencoded" }));

  if (config.gui_enabled) {
    app.get("/", (_req, res) => {
      res.type("html").send(indexPage(supportedCredentials(config)));
    });

    app.get("/ui/help", (_req, res) => {
      res.type("html").send(helpPage(readFileSync("README.md", "utf8")));
    });

    app.get("/assets/credimi_logo.svg", (_req, res) => {
      res.type("image/svg+xml").send(readFileSync("src/design/logo/credimi_logo.svg", "utf8"));
    });

    app.get("/assets/credimi_logo_negative.svg", (_req, res) => {
      res
        .type("image/svg+xml")
        .send(readFileSync("src/design/logo/credimi_logo_negative.svg", "utf8"));
    });

    app.post("/ui/sessions", (req, res) => {
      const body = requestParams(req);
      const credentialConfigurationId =
        asStringOrNull(body.credential_configuration_id) ??
        supportedCredentialConfigurationIds(config)[0];
      if (!supportedCredentialConfigurationIds(config).includes(credentialConfigurationId)) {
        return res.status(400).type("html").send(errorPage("Unsupported credential configuration"));
      }

      const session = store.createSession(credentialConfigurationId);
      store.addEvent(session, "credential_deeplink_generated", {});
      return res.redirect(303, `/ui/sessions/${encodeURIComponent(session.session_id)}`);
    });

    app.post("/ui/openid4vp/sessions", (req, res) => {
      const session = createVpSession(config, store, {});
      store.addEvent(session, "vp_deeplink_generated", {});
      return res.redirect(303, `/ui/openid4vp/sessions/${encodeURIComponent(session.session_id)}`);
    });

    app.get("/ui/sessions/:sessionId", async (req, res, next) => {
      try {
        const session = store.getSession(req.params.sessionId);
        if (!session) return res.status(404).type("html").send(errorPage("Session not found"));
        const offer = credentialOffer(
          config,
          session.session_id,
          session.credential_configuration_id,
        );
        const deeplink = credentialOfferDeeplink(offer);
        const qrSvg = await QRCode.toString(deeplink, {
          type: "svg",
          errorCorrectionLevel: "M",
          margin: 1,
          width: 288,
        });
        return res.type("html").send(sessionPage(session.session_id, deeplink, qrSvg));
      } catch (error) {
        return next(error);
      }
    });

    app.get("/ui/openid4vp/sessions/:sessionId", async (req, res, next) => {
      try {
        const session = store.getVpSession(req.params.sessionId);
        if (!session) return res.status(404).type("html").send(errorPage("VP session not found"));
        const qrSvg = await QRCode.toString(session.deeplink, {
          type: "svg",
          errorCorrectionLevel: "M",
          margin: 1,
          width: 288,
        });
        return res.type("html").send(vpSessionPage(session.session_id, session.deeplink, qrSvg));
      } catch (error) {
        return next(error);
      }
    });
  }
  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/.well-known/openid-credential-issuer", (_req, res) => {
    res.json(credentialIssuerMetadata(config));
  });

  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json(authorizationServerMetadata(config));
  });

  app.get("/.well-known/jwt-vc-issuer", (_req, res) => {
    res.json(jwtVcIssuerMetadata(config));
  });

  app.get("/jwks.json", (_req, res) => {
    res.json(loadIssuerJwks(config));
  });

  app.post("/init", async (req, res, next) => {
    try {
      const body = req.body as JsonRecord;
      const initialized = await initIssuer({
        issuer_base_url: asStringOrNull(body.issuer_base_url) ?? undefined,
        data_dir: asStringOrNull(body.data_dir) ?? config.data_dir,
        credential_configuration_id:
          asStringOrNull(body.credential_configuration_id) ?? config.credential_configuration_id,
        force: body.force === true,
      });
      res.json(initSummary(initialized));
    } catch (error) {
      next(error);
    }
  });

  app.post("/sessions", (req, res) => {
    const body = requestParams(req);
    const credentialConfigurationId =
      asStringOrNull(body.credential_configuration_id) ??
      supportedCredentialConfigurationIds(config)[0];
    if (!supportedCredentialConfigurationIds(config).includes(credentialConfigurationId)) {
      return res.status(400).json({
        error: "unsupported_credential_configuration",
        supported_credential_configuration_ids: supportedCredentialConfigurationIds(config),
      });
    }

    const session = store.createSession(credentialConfigurationId);
    const offer = credentialOffer(config, session.session_id, session.credential_configuration_id);
    store.addEvent(session, "credential_offer_generated", {});
    res.status(201).json({
      session_id: session.session_id,
      credential_configuration_id: session.credential_configuration_id,
      offer_url: `${config.issuer_base_url}/sessions/${session.session_id}/offer`,
      deeplink: credentialOfferDeeplink(offer),
      status: session.status,
    });
  });

  app.get("/sessions/:sessionId", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    return res.json(session);
  });

  app.get("/sessions/:sessionId/offer", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    session.status = "offer_retrieved";
    store.addEvent(session, "credential_offer_generated", {});
    return res.json(
      credentialOffer(config, session.session_id, session.credential_configuration_id),
    );
  });

  app.get("/sessions/:sessionId/deeplink", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    const offer = credentialOffer(config, session.session_id, session.credential_configuration_id);
    store.addEvent(session, "credential_deeplink_generated", {});
    return res.json({ deeplink: credentialOfferDeeplink(offer), credential_offer: offer });
  });

  app.get("/sessions/:sessionId/jwks", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    if (!session.observed.wallet_jwks.observed || !session.observed.wallet_jwks.jwks) {
      return res.status(409).json({
        error: "wallet_jwks_not_observed",
        reason: "Credential proof JWT did not contain header.jwk",
        observed_proof_header_fields: session.observed.wallet_jwks.observed_proof_header_fields,
      });
    }
    store.addEvent(session, "wallet_jwks_exported", {});
    return res.json(session.observed.wallet_jwks.jwks);
  });

  app.get("/sessions/:sessionId/events", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    return res.json(session.events);
  });

  app.post("/openid4vp/sessions", (req, res) => {
    const body = requestParams(req);
    const requestOverride = objectOrNull(body.presentation_request) ?? body;
    const session = createVpSession(config, store, requestOverride);
    store.addEvent(session, "vp_deeplink_generated", {});
    res.status(201).json({
      session_id: session.session_id,
      request_uri: session.request_uri,
      response_uri: session.response_uri,
      deeplink: session.deeplink,
      authorization_request: session.authorization_request,
      status: session.status,
    });
  });

  app.get("/openid4vp/sessions/:sessionId", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    return res.json(session);
  });

  app.get("/openid4vp/sessions/:sessionId/request", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    session.status = "request_retrieved";
    store.addEvent(session, "vp_request_retrieved", {});
    return res.json(session.authorization_request);
  });

  app.get("/openid4vp/sessions/:sessionId/deeplink", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    store.addEvent(session, "vp_deeplink_generated", {});
    return res.json({
      deeplink: session.deeplink,
      authorization_request: session.authorization_request,
    });
  });

  app.post("/openid4vp/sessions/:sessionId/response", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    const body = requestParams(req);
    captureVpResponse(store, session, body, (req as Request & { rawBody?: string }).rawBody);
    return res.json({ status: "ok" });
  });

  app.post("/openid4vp/response", (req, res) => {
    const body = requestParams(req);
    const session = store.getVpSession(asStringOrNull(body.state) ?? "");
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    captureVpResponse(store, session, body, (req as Request & { rawBody?: string }).rawBody);
    return res.json({ status: "ok" });
  });

  app.get("/openid4vp/sessions/:sessionId/events", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    return res.json(session.events);
  });

  app.post("/par", (req, res) => {
    const params = requestParams(req);
    const par = store.storePar(params);
    const session = store.ensureSession(asStringOrNull(params.issuer_state));
    session.status = "par_received";
    session.raw ??= {};
    session.raw.par_request = params;
    updateObservedValue(session, "client_id", params.client_id, "par_request.client_id");
    updateObservedValue(session, "redirect_uri", params.redirect_uri, "par_request.redirect_uri");
    session.checks.state_present = typeof params.state === "string";
    session.checks.issuer_state_present = typeof params.issuer_state === "string";
    session.checks.pkce_present =
      typeof params.code_challenge === "string" && typeof params.code_challenge_method === "string";
    store.addEvent(session, "par_request_received", { request_uri: par.request_uri, params });
    res
      .status(201)
      .json({ request_uri: par.request_uri, expires_in: config.par_request_uri_ttl_seconds });
  });

  app.get("/authorize", (req, res) => {
    const directParams = queryToRecord(req.query);
    const par = store.resolvePar(asStringOrNull(directParams.request_uri) ?? undefined);
    const merged = { ...(par?.params ?? {}), ...directParams };
    const session = store.ensureSession(
      asStringOrNull(merged.issuer_state) ?? asStringOrNull(par?.params.issuer_state),
    );
    session.status = "authorization_requested";
    session.raw ??= {};
    session.raw.authorization_request = merged;
    updateObservedValue(session, "client_id", merged.client_id, "authorization_request.client_id");
    updateObservedValue(
      session,
      "redirect_uri",
      merged.redirect_uri,
      "authorization_request.redirect_uri",
    );
    session.checks.state_present = typeof merged.state === "string";
    session.checks.issuer_state_present = typeof merged.issuer_state === "string";
    session.checks.pkce_present =
      typeof merged.code_challenge === "string" && typeof merged.code_challenge_method === "string";
    store.addEvent(session, "authorize_request_received", { params: merged });

    const redirectUri = asStringOrNull(merged.redirect_uri);
    if (!redirectUri) {
      store.addEvent(session, "authorize_redirect_missing", {});
      return res.status(400).json({ error: "redirect_uri_missing" });
    }

    const code = store.issueAuthorizationCode(session, merged);
    const location = new URL(redirectUri);
    location.searchParams.set("code", code.code);
    if (code.state) location.searchParams.set("state", code.state);
    session.status = "authorization_code_issued";
    store.addEvent(session, "redirect_sent", { redirect_uri: redirectUri });
    return res.redirect(302, location.toString());
  });

  app.post("/token", async (req, res, next) => {
    try {
      const params = requestParams(req);
      const code = store.consumeAuthorizationCode(asStringOrNull(params.code) ?? undefined);
      const session = code ? store.ensureSession(code.session_id) : store.ensureSession();
      session.status = "token_requested";
      session.raw ??= {};
      session.raw.token_request = params;
      updateObservedValue(session, "client_id", params.client_id, "token_request.client_id");
      updateObservedValue(
        session,
        "redirect_uri",
        params.redirect_uri,
        "token_request.redirect_uri",
      );
      session.checks.pkce_valid = code
        ? verifyPkce(
            asStringOrNull(params.code_verifier),
            code.code_challenge,
            code.code_challenge_method,
          )
        : false;
      store.addEvent(session, "token_request_received", { params, code_valid: Boolean(code) });

      const clientAuthentication = captureClientAuthentication({
        params,
        oauthClientAttestation: req.header("OAuth-Client-Attestation"),
        oauthClientAttestationPop: req.header("OAuth-Client-Attestation-PoP"),
        issuerBaseUrl: config.issuer_base_url,
      });
      session.observed.client_authentication = clientAuthentication;
      session.checks.private_key_jwt_present = clientAuthentication.private_key_jwt.present;
      session.checks.private_key_jwt_client_id_matches =
        clientAuthentication.private_key_jwt.client_id_matches;
      session.checks.wallet_attestation_present = clientAuthentication.wallet_attestation.present;
      session.checks.wallet_attestation_pop_present =
        clientAuthentication.wallet_attestation_pop.present;
      session.checks.wallet_attestation_client_id_matches =
        clientAuthentication.wallet_attestation.client_id_matches;
      session.checks.wallet_attestation_pop_audience_matches =
        clientAuthentication.wallet_attestation_pop.audience_matches;
      updateObservedValue(
        session,
        "client_id",
        clientAuthentication.private_key_jwt.claims?.sub,
        "token_request.client_assertion.claims.sub",
      );
      updateObservedValue(
        session,
        "client_id",
        clientAuthentication.wallet_attestation.claims?.sub,
        "token_request.headers.oauth_client_attestation.claims.sub",
      );
      store.addEvent(session, "client_authentication_observed", {
        method: clientAuthentication.method,
        private_key_jwt_present: clientAuthentication.private_key_jwt.present,
        wallet_attestation_present: clientAuthentication.wallet_attestation.present,
        wallet_attestation_pop_present: clientAuthentication.wallet_attestation_pop.present,
      });

      const dpop = req.header("DPoP");
      const dpopCapture = await decodeDpopHeader(dpop);
      if (dpopCapture.jwk) {
        session.observed.dpop_jwk = {
          observed: true,
          source: "token_request.dpop.header.jwk",
          jwk: dpopCapture.jwk,
          thumbprint: dpopCapture.thumbprint,
        };
        store.addEvent(session, "dpop_observed", { thumbprint: dpopCapture.thumbprint });
      } else {
        store.addEvent(session, "dpop_not_observed", {});
      }

      const token = store.issueAccessToken(session.session_id);
      const nonce = randomUUID();
      session.status = "token_issued";
      store.addEvent(session, "nonce_issued", { source: "token_response" });
      res.json({
        access_token: token.token,
        token_type: dpopCapture.jwk ? "DPoP" : "Bearer",
        expires_in: config.access_token_ttl_seconds,
        c_nonce: nonce,
        c_nonce_expires_in: config.nonce_ttl_seconds,
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/nonce", (_req, res) => {
    res.json({ c_nonce: randomUUID(), c_nonce_expires_in: config.nonce_ttl_seconds });
  });

  app.post("/credential", async (req, res, next) => {
    try {
      const body = requestParams(req);
      const accessToken = store.resolveAccessToken(req.header("Authorization"));
      const session = accessToken
        ? store.ensureSession(accessToken.session_id)
        : store.ensureSession();
      session.status = "credential_requested";
      session.raw ??= {};
      session.raw.credential_request = body;
      session.raw.credential_request_raw =
        (req as Request & { rawBody?: string }).rawBody ?? JSON.stringify(body);
      store.addEvent(session, "credential_request_received", {
        authorization_header_observed: Boolean(req.header("Authorization")),
        dpop_observed: Boolean(req.header("DPoP")),
      });

      const headers = captureProofHeaders(body);
      session.raw.proof_headers = headers;
      session.checks.proof_jwt_present = headers.length > 0;
      session.checks.proof_jwt_header_jwk_present = headers.some((header) => header.jwk);
      session.checks.nonce_verified =
        typeof body.proof === "object" || typeof body.proofs === "object";
      for (const header of headers) {
        store.addEvent(session, "proof_jwt_observed", { header });
      }
      const wallet = firstWalletJwks(headers);
      session.observed.wallet_jwks = {
        observed: Boolean(wallet.jwks),
        source: wallet.source,
        jwks: wallet.jwks,
        observed_proof_header_fields: wallet.observedFields,
      };
      store.addEvent(session, wallet.jwks ? "wallet_jwk_observed" : "wallet_jwk_not_observed", {
        observed_proof_header_fields: wallet.observedFields,
      });

      const dpopCapture = await decodeDpopHeader(req.header("DPoP"));
      if (dpopCapture.jwk) {
        session.observed.dpop_jwk = {
          observed: true,
          source: "credential_request.dpop.header.jwk",
          jwk: dpopCapture.jwk,
          thumbprint: dpopCapture.thumbprint,
        };
      }

      const holderJwk = wallet.jwks?.keys[0];
      if (!holderJwk) {
        return res.status(400).json({
          error: "invalid_proof",
          error_description: "Credential proof JWT must contain a public JWK",
        });
      }

      const selectedCredential = supportedCredentialById(
        config,
        session.credential_configuration_id,
      );
      if (!selectedCredential) {
        return res.status(400).json({
          error: "unsupported_credential_configuration",
          supported_credential_configuration_ids: supportedCredentialConfigurationIds(config),
        });
      }

      const credential =
        selectedCredential.format === "mso_mdoc"
          ? await issueMdocCredential({ config, holderJwk })
          : await issueSdJwtCredential({
              config,
              credentialConfigurationId: session.credential_configuration_id,
              holderJwk,
            });
      session.status = "credential_issued";
      store.addEvent(session, "credential_issued", {
        format: selectedCredential.format,
        credential_configuration_id: session.credential_configuration_id,
      });

      res.json({
        credentials: [
          {
            credential,
          },
        ],
      });
    } catch (error) {
      next(error);
    }
  });

  app.use(
    (error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: "internal_error", message: error.message });
    },
  );

  return app;
}

export function initSummary(config: AppConfig): JsonRecord {
  return {
    issuer_base_url: config.issuer_base_url,
    credential_issuer_metadata_url: `${config.issuer_base_url}/.well-known/openid-credential-issuer`,
    authorization_server_metadata_url: `${config.issuer_base_url}/.well-known/oauth-authorization-server`,
    jwt_vc_issuer_metadata_url: `${config.issuer_base_url}/.well-known/jwt-vc-issuer`,
    jwks_url: `${config.issuer_base_url}/jwks.json`,
    health_url: `${config.issuer_base_url}/healthz`,
  };
}

function requestParams(req: Request): JsonRecord {
  return { ...(req.body as JsonRecord) };
}

function queryToRecord(query: Request["query"]): JsonRecord {
  const output: JsonRecord = {};
  for (const [key, value] of Object.entries(query)) {
    if (typeof value === "string") output[key] = value;
  }
  return output;
}

function rawBodyCapture(req: Request, _res: express.Response, buffer: Buffer): void {
  (req as Request & { rawBody?: string }).rawBody = buffer.toString("utf8");
}

function createVpSession(
  config: AppConfig,
  store: CaptureStore,
  requestOverride: JsonRecord,
): VpSessionCapture {
  const sessionId = randomUUID();
  const request = {
    ...defaultPresentationRequest(config),
    ...requestOverride,
  };
  const authorizationRequest = buildPresentationAuthorizationRequest(config, sessionId, request);
  const session = store.createVpSession(sessionId, authorizationRequest);
  session.deeplink = presentationRequestByReferenceDeeplink(config, sessionId);
  return session;
}

function captureVpResponse(
  store: CaptureStore,
  session: VpSessionCapture,
  body: JsonRecord,
  rawBody: string | undefined,
): void {
  session.status = "presentation_received";
  session.raw ??= {};
  session.raw.presentation_response = body;
  session.raw.presentation_response_raw = rawBody ?? JSON.stringify(body);
  session.observed.wallet_response = {
    value: body,
    source: "presentation_response",
    also_seen_in: [],
  };
  session.observed.vp_token = {
    value: body.vp_token ?? null,
    source: body.vp_token === undefined ? null : "presentation_response.vp_token",
    also_seen_in: [],
  };
  session.observed.presentation_submission = {
    value: body.presentation_submission ?? null,
    source:
      body.presentation_submission === undefined
        ? null
        : "presentation_response.presentation_submission",
    also_seen_in: [],
  };
  store.addEvent(session, "vp_presentation_response_received", {
    vp_token_observed: body.vp_token !== undefined,
    presentation_submission_observed: body.presentation_submission !== undefined,
  });
}

function objectOrNull(value: unknown): JsonRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as JsonRecord;
}
