import type { Express } from "express";
import { asStringOrNull } from "../../shared/json.js";
import type { VpDcApiInvocationCapture, VpDcApiInvocationOutcome } from "../../types.js";
import { type ServerContext, requestParams } from "../context.js";
import {
  dcApiSubmissionRejectionOrNull,
  presentationResponseHttpCapture,
  submitPresentation,
  vpPresentationCaptured,
} from "../vp-submission.js";

export function registerVpResponseRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.post("/openid4vp/sessions/:sessionId/response", async (req, res, next) => {
    try {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      const dcApiRejection = dcApiSubmissionRejectionOrNull(session, req);
      if (dcApiRejection) {
        return res.status(dcApiRejection.status).json({ error: dcApiRejection.error });
      }
      const body = requestParams(req);
      return await submitPresentation({ config, store, req, res, session, body });
    } catch (error) {
      return next(error);
    }
  });

  /**
   * The browser reports a DC API invocation that yielded no Authorization Response: the API is
   * unavailable, the wallet refused, the End-User cancelled, or the returned response carried no
   * `vp_token`. This is the evidence a HAIP wallet's refusal of the unencrypted `dc_api` flow
   * produces, and it is kept distinct from a verification failure over a real response.
   */
  app.post("/openid4vp/sessions/:sessionId/dc_api_invocation", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    const dcApi = session.dc_api;
    if (!dcApi) return res.status(400).json({ error: "vp_session_is_not_dc_api" });
    if (vpPresentationCaptured(session)) {
      return res.status(409).json({ error: "vp_session_already_completed" });
    }
    const body = requestParams(req);
    const outcome = dcApiInvocationOutcomeOrNull(body.outcome);
    if (!outcome) return res.status(400).json({ error: "unsupported_dc_api_invocation_outcome" });
    const errorName = asStringOrNull(body.error_name);
    const errorMessage = asStringOrNull(body.error_message);
    const reportedOrigin = asStringOrNull(req.headers.origin);
    const invocation: VpDcApiInvocationCapture = {
      at: new Date().toISOString(),
      outcome,
      ...(errorName ? { error_name: errorName } : {}),
      ...(errorMessage ? { error_message: errorMessage } : {}),
      response_returned: body.response_returned === true || body.response_returned === "true",
      vp_token_present: body.vp_token_present === true || body.vp_token_present === "true",
      ...(reportedOrigin ? { reported_origin: reportedOrigin } : {}),
    };
    dcApi.invocation = invocation;
    session.status = "dc_api_invocation_reported";
    session.raw ??= {};
    session.raw.dc_api_invocation_http = presentationResponseHttpCapture(req, body);
    store.addEvent(session, "vp_dc_api_invocation_reported", {
      outcome: invocation.outcome,
      response_returned: invocation.response_returned,
      vp_token_present: invocation.vp_token_present,
      ...(invocation.error_name ? { error_name: invocation.error_name } : {}),
    });
    return res.status(202).set("Cache-Control", "no-store").json({ status: session.status });
  });

  app.post("/openid4vp/response", async (req, res, next) => {
    try {
      const body = requestParams(req);
      const session = store.getVpSession(asStringOrNull(body.state) ?? "");
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      return await submitPresentation({ config, store, req, res, session, body });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/openid4vp/sessions/:sessionId/events", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    return res.json(session.events);
  });
}
function dcApiInvocationOutcomeOrNull(value: unknown): VpDcApiInvocationOutcome | null {
  return value === "api_unavailable" ||
    value === "rejected" ||
    value === "no_vp_token" ||
    value === "failed"
    ? value
    : null;
}
