import { readFileSync } from "node:fs";
import type { Express } from "express";
import {
  verifierAttestationIssuerPublicJwk,
  verifierDidDocument,
} from "../../config/verifier-identity.js";
import { apiDocsPage } from "../../openapi/docs-page.js";
import { openApiDocument } from "../../openapi/document.js";
import { verifierClientIdentifiers } from "../../openid4vp/authorization-request.js";
import type { ServerContext } from "../context.js";
export function registerPublicStaticRoutes(app: Express, ctx: ServerContext): void {
  const { config } = ctx;

  app.get("/openapi.json", (_req, res) => {
    res.json(openApiDocument(config));
  });

  app.get("/docs", (_req, res) => {
    res.type("html").send(apiDocsPage());
  });

  app.get("/favicon.svg", (_req, res) => {
    res.type("image/svg+xml").send(readFileSync("src/design/logo/credimi_logo.svg", "utf8"));
  });

  app.get("/assets/style.css", (_req, res) => {
    res.type("text/css").send(readFileSync("src/design/style.css", "utf8"));
  });
}

export function registerPublicProtocolRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/openid4vp/did.json", (_req, res) => {
    res.type("application/did+json").json(verifierDidDocument(config));
  });

  // A caller that signs its own verifier_info attestation binds it to the Client Identifier, so
  // the identifiers are published rather than learned from a throwaway session.
  app.get("/openid4vp/client-identifiers", (_req, res) => {
    res.json(verifierClientIdentifiers(config));
  });

  // The key of the fixture issuer of Verifier Attestation JWTs. A wallet resolves attestation
  // issuers out of band, so this is published for an operator to configure as a trusted issuer.
  app.get("/openid4vp/verifier-attestation-issuer/jwks.json", (_req, res) => {
    res.json({ keys: [verifierAttestationIssuerPublicJwk(config)] });
  });

  app.get("/oid4vci/requests", (_req, res) => {
    res.json(store.oid4vciRequests);
  });
}
