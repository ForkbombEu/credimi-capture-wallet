import type { AgentContext } from "@credo-ts/core";
import type { Express, NextFunction } from "express";
import { resolvedIssuerConfigurationById } from "../../configurations/registry.js";
import { issuerAppConfig } from "../../configurations/resolve-urls.js";
import { resolveCredentialIdentifier } from "../../openid4vci/authorization-details.js";
import { credoOpenId4VciIssuer } from "../../openid4vci/credo-issuer.js";
import { errorMessage } from "../../shared/errors.js";
import type { ServerContext } from "../context.js";
import type { CredentialRequestBody } from "../credential-endpoint.js";
import {
  forwardCredentialRequest,
  interceptCredentialResponse,
  pinnedDefinitionMismatch,
  readCredentialRequestBody,
  recordCredentialRequestEvidence,
} from "../credential-endpoint.js";

export function registerCredentialRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

  app.post("/issuers/:issuerConfigurationId/credential", async (req, res, next) => {
    const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
    if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
    const issuerConfig = issuerAppConfig(config, issuer);
    let agentContext: AgentContext;
    try {
      agentContext = (await credoOpenId4VciIssuer(config, store)).context;
    } catch (error) {
      return next(error);
    }
    let requestBody: CredentialRequestBody;
    try {
      requestBody = await readCredentialRequestBody(req, issuerConfig, agentContext);
    } catch (error) {
      return res.status(400).json({
        error: "invalid_encryption_parameters",
        error_description: errorMessage(error),
      });
    }

    const capture = ctx.capture(req) ?? null;
    const credentialRequestRaw = requestBody.encryptedRequest ? capture?.body : undefined;
    recordCredentialRequestEvidence(capture, store, issuer, requestBody.body);
    const attributed = capture?.session_id ? store.getSession(capture.session_id) : undefined;
    const pinnedVersion = pinnedDefinitionMismatch(config, store, issuer, attributed);
    if (pinnedVersion !== null) {
      return res
        .status(400)
        .set("Cache-Control", "no-store")
        .json({
          error: "invalid_credential_request",
          error_description: `the offer was made under rulebook version ${pinnedVersion}, which is no longer active; request a new offer`,
        });
    }
    const identifier = resolveCredentialIdentifier(
      attributed ? store.authorizationDetails.get(attributed.session_id) : undefined,
      requestBody.body,
    );
    if (!identifier.ok) {
      return res
        .status(400)
        .set("Cache-Control", "no-store")
        .json({ error: identifier.error, error_description: identifier.description });
    }
    const encryptedResponse = requestBody.responseEncryption
      ? interceptCredentialResponse(res, next, agentContext, requestBody.responseEncryption)
      : null;
    // Installed after the encryption interceptor so a scenario edits the plaintext response,
    // which is then encrypted only if it is still a success (OpenID4VCI 1.0 Section 8.3.1).
    ctx.applyIssuanceResponseScenario(req, res, "credential");
    const credentialEndpointNext: NextFunction = (error) => {
      if (encryptedResponse?.isPending()) return;
      if (error) return next(error);
      if (res.headersSent) return;
      return next(new Error("Credo Credential endpoint completed without sending a response"));
    };
    try {
      return await forwardCredentialRequest(
        config,
        store,
        req,
        res,
        credentialEndpointNext,
        capture,
        requestBody.body,
        credentialRequestRaw,
        identifier.credentialConfigurationId,
      );
    } catch (error) {
      return next(error);
    }
  });

  if (config.oid4vci_notifications_enabled) {
    app.post("/issuers/:issuerConfigurationId/notification", async (req, res, next) => {
      const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
      if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
      try {
        const outcome = await (await credoOpenId4VciIssuer(config, store)).receiveNotification(
          issuer,
          req,
          ctx.capture(req) ?? null,
        );
        res.set("Cache-Control", "no-store");
        if (outcome.status === 401) {
          return res.set("WWW-Authenticate", outcome.wwwAuthenticate).status(401).end();
        }
        if (outcome.status === 400) return res.status(400).json({ error: outcome.error });
        return res.status(204).end();
      } catch (error) {
        return next(error);
      }
    });
  }
}
