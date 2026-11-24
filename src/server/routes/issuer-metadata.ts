import type { Express } from "express";
import { loadIssuerJwks } from "../../config/key-material.js";
import { resolvedIssuerConfigurationById } from "../../configurations/registry.js";
import { issuerAppConfig } from "../../configurations/resolve-urls.js";
import {
  ENTITY_STATEMENT_MEDIA_TYPE,
  signIssuerEntityConfiguration,
} from "../../federation/entity-configuration.js";
import { credoOpenId4VciIssuer } from "../../openid4vci/credo-issuer.js";
import { jwtVcIssuerMetadata, signCredentialIssuerMetadata } from "../../openid4vci/metadata.js";
import type { ServerContext } from "../context.js";

export function registerIssuerMetadataRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.get(
    "/.well-known/openid-credential-issuer/issuers/:issuerConfigurationId",
    async (req, res, next) => {
      try {
        const issuer = ctx.matchedIssuerOrNull(req);
        if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
        const credoIssuer = await credoOpenId4VciIssuer(config, store);
        const metadata = await credoIssuer.credentialIssuerMetadata(issuer.id);
        res.vary("Accept");
        const responseType = req.accepts(["application/json", "application/jwt"]);
        if (responseType === "application/jwt") {
          return res
            .status(200)
            .type("application/jwt")
            .send(
              await signCredentialIssuerMetadata(
                issuerAppConfig(config, issuer),
                metadata,
                credoIssuer.context,
              ),
            );
        }
        return res.json(metadata);
      } catch (error) {
        return next(error);
      }
    },
  );

  app.get(
    "/issuers/:issuerConfigurationId/.well-known/openid-federation",
    async (req, res, next) => {
      try {
        if (!config.federation.enabled) {
          return res.status(404).json({ error: "issuer_not_found" });
        }
        const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
        if (!issuer) return res.status(404).json({ error: "issuer_not_found" });

        const credoIssuer = await credoOpenId4VciIssuer(config, store);
        const issuerMetadata = await credoIssuer.credentialIssuerMetadata(issuer.id);
        const authorizationServerMetadata = await credoIssuer.authorizationServerMetadata(
          issuer.id,
        );
        return res
          .status(200)
          .type(ENTITY_STATEMENT_MEDIA_TYPE)
          .send(
            await signIssuerEntityConfiguration({
              issuer,
              authorityHints: config.federation.authority_hints,
              issuerMetadata,
              issuerJwks: loadIssuerJwks(issuerAppConfig(config, issuer)),
              authorizationServerMetadata,
            }),
          );
      } catch (error) {
        return next(error);
      }
    },
  );

  app.get(
    "/.well-known/oauth-authorization-server/issuers/:issuerConfigurationId",
    async (req, res, next) => {
      try {
        const issuer = ctx.matchedIssuerOrNull(req);
        if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
        return res.json(
          await (await credoOpenId4VciIssuer(config, store)).authorizationServerMetadata(issuer.id),
        );
      } catch (error) {
        return next(error);
      }
    },
  );

  app.get("/.well-known/jwt-vc-issuer/issuers/:issuerConfigurationId", (req, res) => {
    const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
    if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
    res.json(jwtVcIssuerMetadata(issuerAppConfig(config, issuer)));
  });

  app.get("/issuers/:issuerConfigurationId/credential-jwks.json", (req, res) => {
    const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
    if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
    res.json(loadIssuerJwks(issuerAppConfig(config, issuer)));
  });
}
