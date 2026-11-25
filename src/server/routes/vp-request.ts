import type { Express } from "express";
import { isDcApiResponseMode } from "../../openid4vp/authorization-request.js";
import { asStringOrNull } from "../../shared/json.js";
import { type ServerContext, requestParams } from "../context.js";
import {
  recordWalletNonceRequest,
  requestUriHttpCapture,
  resignDeliveredRequest,
  sendNegotiatedRequestObject,
  sendRequestUriResponse,
} from "../vp-request-uri.js";

export function registerVpRequestRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.get("/openid4vp/sessions/:sessionId/request", async (req, res, next) => {
    try {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      if (isDcApiResponseMode(session.response_mode)) {
        return res.status(404).json({ error: "vp_request_uri_not_available_for_dc_api" });
      }
      session.status = "request_retrieved";
      session.raw ??= {};
      session.raw.request_uri_http = requestUriHttpCapture(req);
      store.addEvent(session, "vp_request_retrieved", {});
      const requestObject = store.vpCredoAuthorizationRequestJwts.get(session.session_id);
      if (!requestObject) return res.status(404).json({ error: "vp_request_not_found" });
      session.raw.authorization_request_jwt = requestObject;
      return sendRequestUriResponse(res, session, requestObject);
    } catch (error) {
      return next(error);
    }
  });

  app.post("/openid4vp/sessions/:sessionId/request", async (req, res, next) => {
    try {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      if (isDcApiResponseMode(session.response_mode)) {
        return res.status(404).json({ error: "vp_request_uri_not_available_for_dc_api" });
      }
      const body = requestParams(req);
      const walletNonce = asStringOrNull(body.wallet_nonce);
      session.raw ??= {};
      session.raw.request_uri_http = requestUriHttpCapture(req);
      const returnedWalletNonce = recordWalletNonceRequest(store, session, body, walletNonce);
      await resignDeliveredRequest({
        config,
        store,
        session,
        walletNonce,
        returnedWalletNonce,
      });
      const requestObject = store.vpCredoAuthorizationRequestJwts.get(session.session_id);
      if (!requestObject) return res.status(404).json({ error: "vp_request_not_found" });
      session.raw.authorization_request_jwt = requestObject;
      return await sendNegotiatedRequestObject({
        config,
        store,
        session,
        body,
        requestObject,
        res,
      });
    } catch (error) {
      return next(error);
    }
  });
}
