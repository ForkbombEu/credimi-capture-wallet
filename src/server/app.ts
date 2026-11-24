import express, { type NextFunction, type Request, type Response } from "express";
import { attestbookIntegration } from "../attestbook/integration.js";
import { WEBHOOK_MAX_BODY_BYTES, WEBHOOK_PATH } from "../attestbook/webhook.js";
import { validateIssuerMaterial } from "../config/key-material.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import { registerFakeOAuthServer } from "../openid4vci/fake-oauth-server.js";
import { isOid4vciProtocolPath, isRawBodyEvidencePath } from "../openid4vci/http-capture.js";
import { CaptureStore } from "../state.js";
import type { AppConfig } from "../types.js";
import { ServerContext } from "./context.js";
import { registerCredentialRoutes } from "./routes/credential.js";
import { registerDiscoveryRoutes } from "./routes/discovery.js";
import { registerForwardingRoutes } from "./routes/forwarding.js";
import { registerIssuanceRoutes } from "./routes/issuance.js";
import { registerIssuerMetadataRoutes } from "./routes/issuer-metadata.js";
import { registerPublicProtocolRoutes, registerPublicStaticRoutes } from "./routes/public.js";
import { registerUiRoutes } from "./routes/ui.js";
import { registerVpRequestRoutes } from "./routes/vp-request.js";
import { registerVpResponseRoutes } from "./routes/vp-response.js";
import { registerVpSessionRoutes, registerVpSessionTailRoutes } from "./routes/vp-sessions.js";

export function createApp(config: AppConfig, store = new CaptureStore(config)): express.Express {
  if (config.federation.enabled) validateIssuerMaterial(config);
  const app = express();
  const ctx = new ServerContext(config, store);

  // The Attestbook callback needs the exact body bytes its signature commits to, so it is routed
  // before the shared body parsers, with its own bounded raw parser.
  if (config.attestbook.enabled) {
    const webhookBodyParser = express.raw({ type: () => true, limit: WEBHOOK_MAX_BODY_BYTES });
    app.post(WEBHOOK_PATH, (req, res, next) => {
      webhookBodyParser(req, res, async (parseError?: unknown) => {
        if (parseError) {
          const tooLarge =
            typeof parseError === "object" &&
            parseError !== null &&
            "type" in parseError &&
            parseError.type === "entity.too.large";
          return res
            .status(tooLarge ? 413 : 400)
            .json({ error: tooLarge ? "payload_too_large" : "invalid_request" });
        }
        try {
          await credoOpenId4VciIssuer(config, store);
          const result = await attestbookIntegration(config, store).handleWebhook(
            Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0),
            (name) => req.header(name),
          );
          return res.set("Cache-Control", "no-store").status(result.status).json(result.body);
        } catch (error) {
          return next(error);
        }
      });
    });
  }

  app.use(
    express.json({
      type: ["application/json", "application/*+json"],
      verify: rawBodyCapture,
    }),
  );
  app.use(
    express.urlencoded({
      extended: false,
      type: "application/x-www-form-urlencoded",
      verify: rawBodyCapture,
    }),
  );
  app.use(express.text({ type: "application/jwt" }));
  // The exact bytes of a PAR, token, or Credential Request are evidence even when its media type
  // matches none of the parsers above. Such a body is read only to keep those bytes; handlers see
  // the same empty body as before.
  const evidenceBodyParser = express.raw({ type: () => true, verify: rawBodyCapture });
  app.use((req, res, next) => {
    if (!isRawBodyEvidencePath(req.path)) return next();
    return evidenceBodyParser(req, res, (error?: unknown) => {
      if (Buffer.isBuffer(req.body)) req.body = {};
      next(error);
    });
  });
  // A body a parser rejects skips the capture below, so it is recorded here, with no parsed body,
  // before the error continues to the error handler.
  app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
    if (!isOid4vciProtocolPath(req.path)) return next(error);
    req.body = undefined;
    // A Notification Request whose body is not JSON still reaches the Notification Endpoint, with
    // no body and captured below like any other request, so its access token is checked before it
    // is answered `invalid_notification_request` (OpenID4VCI 1.0 Section 11.3).
    if (config.oid4vci_notifications_enabled && /^\/issuers\/[^/]+\/notification$/.test(req.path)) {
      return next();
    }
    ctx.captureOid4vciRequest(req, res).then(() => next(error), next);
  });
  app.use(async (req, res, next) => {
    if (!isOid4vciProtocolPath(req.path)) return next();
    try {
      await ctx.captureOid4vciRequest(req, res);
    } catch (error) {
      return next(error);
    }
    return next();
  });

  registerFakeOAuthServer(app, config, store);
  registerPublicStaticRoutes(app, ctx);
  registerUiRoutes(app, ctx);
  registerPublicProtocolRoutes(app, ctx);
  registerIssuerMetadataRoutes(app, ctx);
  registerDiscoveryRoutes(app, ctx);
  registerIssuanceRoutes(app, ctx);
  registerVpSessionRoutes(app, ctx);
  registerVpRequestRoutes(app, ctx);
  registerVpSessionTailRoutes(app, ctx);
  registerVpResponseRoutes(app, ctx);
  registerCredentialRoutes(app, ctx);
  registerForwardingRoutes(app, ctx);

  // A request no route handles is recorded as `unmatched` before its 404, so a Wallet that fetches
  // metadata from a URL it derived itself, or anything else unexpected, leaves evidence.
  app.use((req, res, next) => {
    const capture = ctx.capture(req);
    if (!capture) return ctx.captureOid4vciRequest(req, res, true).then(() => next(), next);
    ctx.markOid4vciRequestUnmatched(req);
    return next();
  });

  app.use(
    (error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: "internal_error", message: error.message });
    },
  );

  return app;
}
function rawBodyCapture(req: Request, _res: Response, buffer: Buffer): void {
  const rawBodyRequest = req as Request & { rawBody?: string; rawBodyBytes?: Buffer };
  rawBodyRequest.rawBody = buffer.toString("utf8");
  rawBodyRequest.rawBodyBytes = buffer;
}
