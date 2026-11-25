import type { Express } from "express";
import { credoOpenId4VciIssuer } from "../../openid4vci/credo-issuer.js";
import type { ServerContext } from "../context.js";

export function registerForwardingRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.use(async (req, res, next) => {
    if (!isCredoIssuerEndpoint(req.path)) return next();
    if (req.path.endsWith("/par")) ctx.applyIssuanceResponseScenario(req, res, "par");
    try {
      return (await credoOpenId4VciIssuer(config, store)).forward(
        req,
        res,
        next,
        ctx.capture(req) ?? null,
      );
    } catch (error) {
      return next(error);
    }
  });
}

function isCredoIssuerEndpoint(path: string): boolean {
  return (
    /^\/issuers\/[^/]+\/(?:jwks\.json|par|authorize|challenge|redirect|nonce|token|deferred-credential)$/.test(
      path,
    ) || /^\/issuers\/[^/]+\/offers\/[^/]+$/.test(path)
  );
}
