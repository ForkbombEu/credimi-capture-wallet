import { timingSafeEqual } from "node:crypto";
import type { Express } from "express";
import { sha256Hex } from "../../attestbook/digest.js";
import { attestbookIntegration } from "../../attestbook/integration.js";
import { issuerCatalogue } from "../../configurations/registry.js";
import { credoOpenId4VciIssuer } from "../../openid4vci/credo-issuer.js";
import type { ServerContext } from "../context.js";
import { issuerCredentialRegistry } from "../issuance-session-input.js";

export function registerDiscoveryRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.get("/issuers", async (_req, res, next) => {
    try {
      const registry = await issuerCredentialRegistry(config, store);
      res.json(
        issuerCatalogue(config, (issuer) =>
          registry.credentialsForIssuer(issuer).map((credential) => credential.id),
        ),
      );
    } catch (error) {
      next(error);
    }
  });

  app.get("/integrations/attestbook/status", async (_req, res, next) => {
    try {
      if (!config.attestbook.enabled) return res.json({ enabled: false });
      await credoOpenId4VciIssuer(config, store);
      return res
        .set("Cache-Control", "no-store")
        .json(attestbookIntegration(config, store).status());
    } catch (error) {
      return next(error);
    }
  });

  // Controlled manual resynchronisation for recovery: it reconciles the configured rulebook only,
  // waits for the outcome, and is available only when an administrator token is configured.
  app.post("/integrations/attestbook/sync", async (req, res, next) => {
    try {
      const adminToken = config.attestbook.enabled ? config.attestbook.admin_token : null;
      if (!adminToken) return res.status(404).json({ error: "manual_sync_not_configured" });
      const presented = /^Bearer (\S+)$/.exec(req.header("authorization") ?? "")?.[1] ?? "";
      if (
        !timingSafeEqual(
          Buffer.from(sha256Hex(Buffer.from(presented, "utf8")), "hex"),
          Buffer.from(sha256Hex(Buffer.from(adminToken, "utf8")), "hex"),
        )
      ) {
        return res
          .status(401)
          .set("WWW-Authenticate", 'Bearer realm="attestbook-sync"')
          .json({ error: "unauthorized" });
      }
      await credoOpenId4VciIssuer(config, store);
      const integration = attestbookIntegration(config, store);
      await integration.reconcile("manual").catch(() => undefined);
      return res
        .set("Cache-Control", "no-store")
        .status(integration.syncState === "failed" ? 502 : 200)
        .json(integration.status());
    } catch (error) {
      return next(error);
    }
  });
}
