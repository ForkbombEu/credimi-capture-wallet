import type { Express, Request } from "express";
import { redactHttpHeaders } from "../../openid4vci/http-capture.js";
import { ClientMetadataError, ResponseModeError } from "../../openid4vp/request-construction.js";
import { asStringOrNull } from "../../shared/json.js";
import type { RedirectUriVisitHttpCapture } from "../../types.js";
import { vpRedirectPage } from "../../ui/session.js";
import { type ServerContext, requestParams } from "../context.js";
import {
  deriveVpSessionOptions,
  parseVpRequestOverride,
  parseVpSessionInput,
  serializeVpSession,
  validateVpSessionCombination,
} from "../presentation-session-input.js";
import { createVpSession, redirectResponseCodeMatches } from "../presentation-session.js";

export function registerVpSessionRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.post("/openid4vp/sessions", async (req, res, next) => {
    try {
      const input = parseVpSessionInput(config, requestParams(req));
      if (!input.ok) return res.status(input.status).json(input.body);
      const options = deriveVpSessionOptions(input.value);
      const combinationError = await validateVpSessionCombination(config, options);
      if (combinationError) {
        return res.status(combinationError.status).json(combinationError.body);
      }
      const requestOverride = parseVpRequestOverride(options);
      if (!requestOverride.ok) {
        return res.status(requestOverride.status).json(requestOverride.body);
      }
      const session = await createVpSession(config, store, {
        requestOverride: requestOverride.value,
        requestUriMethod: options.requestUriMethod ?? "get",
        responseMode: options.selectedResponseMode,
        requestDelivery: options.selectedRequestDelivery,
        deeplinkScheme: options.deeplinkScheme ?? "openid4vp://",
        redirectUri: options.redirectUri?.value,
        captureRedirect: options.redirectUri?.capture,
        clientMetadata: options.clientMetadata,
        clientIdScheme: options.selectedClientIdScheme,
        allowUndecryptableResponse: options.allowUndecryptableResponse,
        requestMutation: options.requestMutation,
        requestBehavior: options.requestBehavior,
        responseScenario: options.responseScenario,
        verifierAttestation: options.verifierAttestation,
      });
      store.addEvent(session, "vp_deeplink_generated", {});
      return res.status(201).json(serializeVpSession(session));
    } catch (error) {
      if (error instanceof ClientMetadataError) {
        return res.status(400).json({ error: "invalid_client_metadata" });
      }
      if (error instanceof ResponseModeError) {
        return res.status(400).json({ error: "unsupported_response_mode" });
      }
      return next(error);
    }
  });

  app.get("/openid4vp/sessions/:sessionId", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    return res.json(session);
  });

  app.get("/openid4vp/redirect", (req, res) => {
    const responseCode = asStringOrNull(req.query.response_code);
    const sessionId = responseCode
      ? store.vpSessionIdsByRedirectResponseCode.get(responseCode)
      : undefined;
    const session = sessionId ? store.getVpSession(sessionId) : undefined;
    if (
      !session ||
      !responseCode ||
      !redirectResponseCodeMatches(session.redirect_uri, responseCode)
    ) {
      return res
        .status(404)
        .type("html")
        .send(vpRedirectPage(responseCode ?? "No response code received", false));
    }

    const visitedAt = new Date().toISOString();
    session.redirect_uri_visited_at = visitedAt;
    session.redirect_uri_visit_count = (session.redirect_uri_visit_count ?? 0) + 1;
    session.raw ??= {};
    session.raw.redirect_uri_visits ??= [];
    session.raw.redirect_uri_visits.push(redirectUriVisitHttpCapture(req));
    store.addEvent(session, "vp_redirect_uri_visited", {
      visit_count: session.redirect_uri_visit_count,
    });
    return res
      .status(200)
      .set("Cache-Control", "no-store")
      .set("Referrer-Policy", "no-referrer")
      .type("html")
      .send(vpRedirectPage(responseCode, true));
  });
}

function redirectUriVisitHttpCapture(req: Request): RedirectUriVisitHttpCapture {
  return {
    method: req.method,
    headers: redactHttpHeaders(req.headers),
  };
}

export function registerVpSessionTailRoutes(app: Express, ctx: ServerContext): void {
  const { store } = ctx;
  app.get("/openid4vp/sessions/:sessionId/deeplink", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    store.addEvent(session, "vp_deeplink_generated", {});
    return res.json({
      deeplink: session.deeplink,
      authorization_request: session.authorization_request,
    });
  });
}
