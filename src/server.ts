import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import express, { type NextFunction, type Request, type Response } from "express";
import QRCode from "qrcode";
import { loadIssuerJwks } from "./config.js";
import {
  DEFAULT_ISSUER_CONFIGURATION_ID,
  issuerCatalogue,
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "./configurations/registry.js";
import { issuerAppConfig } from "./configurations/resolve-urls.js";
import type { ResolvedIssuerConfiguration } from "./configurations/types.js";
import {
  CredentialEncryptionError,
  credentialResponseEncryption,
  decryptCredentialRequest,
  encryptCredentialResponse,
} from "./credential-encryption.js";
import { credoOpenId4VciIssuer } from "./credo-openid4vci.js";
import { credoOpenId4VpVerifier } from "./credo-openid4vp.js";
import { registerFakeOAuthServer } from "./fake-oauth-server.js";
import {
  jwtVcIssuerMetadata,
  signCredentialIssuerMetadata,
  supportedCredentialConfigurationIds,
  supportedCredentialConfigurationIdsForIssuer,
  supportedCredentials,
  supportedCredentialsForIssuer,
} from "./metadata.js";
import {
  completeOid4vciRequestCapture,
  createOid4vciRequestCapture,
  isOid4vciProtocolPath,
  redactOid4vciValue,
} from "./oid4vci-capture.js";
import { apiDocsPage, openApiDocument } from "./openapi.js";
import {
  type OpenId4VpResponseMode,
  defaultPresentationRequest,
  signPresentationAuthorizationRequest,
} from "./openid4vp.js";
import { CaptureStore, asStringOrNull } from "./state.js";
import type {
  AppConfig,
  CredentialOfferMode,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  SessionCapture,
  VpSessionCapture,
} from "./types.js";
import { errorPage, helpPage, indexPage, sessionPage, vpSessionPage } from "./ui.js";

export function createApp(config: AppConfig, store = new CaptureStore(config)): express.Express {
  const app = express();
  const oid4vciCaptures = new WeakMap<Request, Oid4vciHttpRequestCapture>();

  app.use(
    express.json({
      type: ["application/json", "application/*+json"],
      verify: rawBodyCapture,
    }),
  );
  app.use(express.urlencoded({ extended: false, type: "application/x-www-form-urlencoded" }));
  app.use(express.text({ type: "application/jwt" }));
  app.use((req, res, next) => {
    if (!isOid4vciProtocolPath(req.path)) return next();
    const capture = createOid4vciRequestCapture(
      req,
      oid4vciRequestSessionId(store, req),
      oid4vciRequestIssuerConfigurationId(store, req),
    );
    oid4vciCaptures.set(req, capture);
    store.recordOid4vciRequest(capture);
    res.once("finish", () => completeOid4vciRequestCapture(capture, res));
    return next();
  });
  registerFakeOAuthServer(app, config, store);

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

  if (config.gui_enabled) {
    app.get("/", (_req, res) => {
      res.type("html").send(
        indexPage(
          resolvedIssuerConfigurations(config).map((issuer) => ({
            issuer,
            credentials: supportedCredentialsForIssuer(config, issuer),
          })),
        ),
      );
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

    app.post("/ui/sessions", async (req, res, next) => {
      try {
        const body = requestParams(req);
        const issuer = issuerFromRequest(config, body.issuer_configuration_id);
        if (!issuer) {
          return res.status(400).type("html").send(errorPage("Unsupported issuer configuration"));
        }
        const supportedIds = supportedCredentialConfigurationIdsForIssuer(config, issuer);
        const credentialConfigurationId =
          asStringOrNull(body.credential_configuration_id) ?? supportedIds[0];
        if (!credentialConfigurationId || !supportedIds.includes(credentialConfigurationId)) {
          return res
            .status(400)
            .type("html")
            .send(errorPage("Unsupported credential configuration"));
        }

        const session = await createIssuanceSession(
          config,
          store,
          issuer,
          credentialConfigurationId,
        );
        store.addEvent(session, "credential_deeplink_generated", {});
        return res.redirect(303, `/ui/sessions/${encodeURIComponent(session.session_id)}`);
      } catch (error) {
        return next(error);
      }
    });

    app.post("/ui/openid4vp/sessions", async (req, res, next) => {
      try {
        const body = requestParams(req);
        const credentialConfigurationId =
          asStringOrNull(body.credential_configuration_id) ??
          supportedCredentialConfigurationIds(config)[0];
        if (!supportedCredentialConfigurationIds(config).includes(credentialConfigurationId)) {
          return res
            .status(400)
            .type("html")
            .send(errorPage("Unsupported credential configuration"));
        }

        const session = await createVpSession(config, store, {}, [credentialConfigurationId]);
        store.addEvent(session, "vp_deeplink_generated", {});
        return res.redirect(
          303,
          `/ui/openid4vp/sessions/${encodeURIComponent(session.session_id)}`,
        );
      } catch (error) {
        return next(error);
      }
    });

    app.get("/ui/sessions/:sessionId", async (req, res, next) => {
      try {
        const session = store.getSession(req.params.sessionId);
        if (!session) return res.status(404).type("html").send(errorPage("Session not found"));
        const offer = store.credoIssuanceOffers.get(session.session_id);
        if (!offer)
          return res.status(409).type("html").send(errorPage("Credential offer not ready"));
        const deeplink = offer.credential_offer;
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

  app.get("/oid4vci/requests", (_req, res) => {
    res.json(store.oid4vciRequests);
  });

  app.get(
    "/.well-known/openid-credential-issuer/issuers/:issuerConfigurationId",
    async (req, res, next) => {
      try {
        const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
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
    "/.well-known/oauth-authorization-server/issuers/:issuerConfigurationId",
    async (req, res, next) => {
      try {
        const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
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

  app.get("/issuers", (_req, res) => {
    res.json(
      issuerCatalogue(config, (issuer) =>
        supportedCredentialConfigurationIdsForIssuer(config, issuer),
      ),
    );
  });

  app.post("/sessions", async (req, res, next) => {
    try {
      const body = requestParams(req);
      if (body.broken !== undefined) {
        return res.status(400).json({
          error: "invalid_request",
          error_description:
            "'broken' is unavailable because the legacy root issuer has been removed",
        });
      }
      const flow = issuanceFlowOrNull(body.flow);
      if (body.flow !== undefined && !flow) {
        return res.status(400).json({
          error: "unsupported_issuance_flow",
          supported_flows: ["pre_authorized_code", "authorization_code"],
        });
      }
      const credentialOfferMode = credentialOfferModeOrNull(body.credential_offer_mode);
      if (body.credential_offer_mode !== undefined && !credentialOfferMode) {
        return res.status(400).json({
          error: "unsupported_credential_offer_mode",
          supported_credential_offer_modes: ["credential_offer", "credential_offer_uri"],
        });
      }
      const issuer = issuerFromRequest(config, body.issuer_configuration_id);
      if (!issuer) {
        return res.status(400).json({
          error: "unsupported_issuer_configuration",
          supported_issuer_configuration_ids: resolvedIssuerConfigurations(config).map(
            (candidate) => candidate.id,
          ),
        });
      }
      const supportedCredentialIds = supportedCredentialConfigurationIdsForIssuer(config, issuer);
      const credentialConfigurationId =
        asStringOrNull(body.credential_configuration_id) ?? supportedCredentialIds[0];
      if (
        !credentialConfigurationId ||
        !supportedCredentialIds.includes(credentialConfigurationId)
      ) {
        return res.status(400).json({
          error: "unsupported_credential_configuration",
          issuer_configuration_id: issuer.id,
          supported_credential_configuration_ids: supportedCredentialIds,
        });
      }

      const session = await createIssuanceSession(
        config,
        store,
        issuer,
        credentialConfigurationId,
        flow ?? "authorization_code",
        credentialOfferMode ?? "credential_offer",
      );
      const offer = store.credoIssuanceOffers.get(session.session_id);
      if (!offer) throw new Error("Credo credential offer was not stored");
      return res.status(201).json({
        session_id: session.session_id,
        issuer_configuration_id: session.issuer_configuration_id,
        issuer_identifier: session.issuer_identifier,
        authorization_server_identifier: session.authorization_server_identifier,
        flow: session.flow,
        credential_offer_mode: session.credential_offer_mode,
        credential_configuration_id: session.credential_configuration_id,
        offer_url: offer.credential_offer_uri,
        deeplink: offer.credential_offer,
        status: session.status,
      });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/sessions/:sessionId", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    return res.json(session);
  });

  app.get("/sessions/:sessionId/offer", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    const offer = store.credoIssuanceOffers.get(session.session_id);
    if (!offer) return res.status(409).json({ error: "credential_offer_not_ready" });
    return res.json(offer.credential_offer_object);
  });

  app.get("/sessions/:sessionId/deeplink", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    const offer = store.credoIssuanceOffers.get(session.session_id);
    if (!offer) return res.status(409).json({ error: "credential_offer_not_ready" });
    store.addEvent(session, "credential_deeplink_generated", {});
    return res.json({
      deeplink: offer.credential_offer,
      credential_offer: offer.credential_offer_object,
    });
  });

  app.get("/sessions/:sessionId/jwks", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    if (!session.observed.wallet_jwks.observed || !session.observed.wallet_jwks.jwks) {
      return res.status(409).json({
        error: "wallet_jwks_not_observed",
        reason: "No verified credential holder-binding key has been observed",
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

  app.post("/openid4vp/sessions", async (req, res, next) => {
    try {
      const body = requestParams(req);
      const requestUriMethod = requestUriMethodOrNull(body.request_uri_method);
      if (body.request_uri_method !== undefined && !requestUriMethod) {
        return res.status(400).json({ error: "unsupported_request_uri_method" });
      }
      const requestDelivery = requestDeliveryOrNull(body.request_delivery);
      if (body.request_delivery !== undefined && !requestDelivery) {
        return res.status(400).json({ error: "unsupported_request_delivery" });
      }
      if (requestDelivery === "by_value" && requestUriMethod) {
        return res.status(400).json({ error: "request_uri_method_requires_by_reference_delivery" });
      }
      const responseMode = responseModeOrNull(body.response_mode);
      if (body.response_mode !== undefined && !responseMode) {
        return res.status(400).json({ error: "unsupported_response_mode" });
      }
      const deeplinkScheme = deeplinkSchemeOrNull(body.scheme);
      if (body.scheme !== undefined && !deeplinkScheme) {
        return res.status(400).json({ error: "invalid_deeplink_scheme" });
      }
      const requestOverride = {
        ...(objectOrNull(body.presentation_request) ?? vpRequestBody(body)),
        ...(body.response_type !== undefined ? { response_type: body.response_type } : {}),
      };
      const session = await createVpSession(
        config,
        store,
        requestOverride,
        undefined,
        requestUriMethod ?? "get",
        responseMode ?? "direct_post.jwt",
        requestDelivery ?? "by_reference",
        deeplinkScheme ?? "openid4vp://",
      );
      store.addEvent(session, "vp_deeplink_generated", {});
      return res.status(201).json({
        session_id: session.session_id,
        request_delivery: session.request_delivery,
        request_uri: session.request_uri,
        request_uri_method: session.request_uri_method,
        response_mode: session.response_mode,
        scheme: session.deeplink_scheme,
        response_uri: session.response_uri,
        deeplink: session.deeplink,
        authorization_request: session.authorization_request,
        status: session.status,
      });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/openid4vp/sessions/:sessionId", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    return res.json(session);
  });

  app.get("/openid4vp/sessions/:sessionId/request", async (req, res, next) => {
    try {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      session.status = "request_retrieved";
      store.addEvent(session, "vp_request_retrieved", {});
      const requestObject = store.vpCredoAuthorizationRequestJwts.get(session.session_id);
      if (!requestObject) return res.status(404).json({ error: "vp_request_not_found" });
      return res.type("application/oauth-authz-req+jwt").send(requestObject);
    } catch (error) {
      return next(error);
    }
  });

  app.post("/openid4vp/sessions/:sessionId/request", async (req, res, next) => {
    try {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      const body = requestParams(req);
      const walletNonce = asStringOrNull(body.wallet_nonce);
      session.status = "request_retrieved";
      session.observed.request_uri_payload = {
        value: body,
        source: "request_uri.post",
        also_seen_in: [],
      };
      store.addEvent(session, "vp_request_retrieved", {
        request_uri_method: "post",
        wallet_nonce_present: Boolean(walletNonce),
        payload: body,
      });
      if (walletNonce) {
        session.authorization_request = {
          ...session.authorization_request,
          wallet_nonce: walletNonce,
        };
        session.raw ??= {};
        session.raw.authorization_request = session.authorization_request;
        store.vpCredoAuthorizationRequestJwts.set(
          session.session_id,
          await signPresentationAuthorizationRequest(config, session.authorization_request),
        );
      }
      const requestObject = store.vpCredoAuthorizationRequestJwts.get(session.session_id);
      if (!requestObject) return res.status(404).json({ error: "vp_request_not_found" });
      return res.type("application/oauth-authz-req+jwt").send(requestObject);
    } catch (error) {
      return next(error);
    }
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

  app.post("/openid4vp/sessions/:sessionId/response", async (req, res, next) => {
    try {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      const body = requestParams(req);
      const verificationSessionId = store.vpCredoVerificationSessionIds.get(session.session_id);
      if (!verificationSessionId) return res.status(404).json({ error: "vp_request_not_found" });
      const validation = await (await credoOpenId4VpVerifier(config)).verifyResponse(
        session,
        body,
        verificationSessionId,
      );
      captureVpResponse(
        store,
        session,
        body,
        (req as Request & { rawBody?: string }).rawBody,
        validation,
      );
      if (!validation.valid) {
        return res.status(400).json({ error: "invalid_presentation", errors: validation.errors });
      }
      return res.json({});
    } catch (error) {
      return next(error);
    }
  });

  app.post("/openid4vp/response", async (req, res, next) => {
    try {
      const body = requestParams(req);
      const session = store.getVpSession(asStringOrNull(body.state) ?? "");
      if (!session) return res.status(404).json({ error: "vp_session_not_found" });
      const verificationSessionId = store.vpCredoVerificationSessionIds.get(session.session_id);
      if (!verificationSessionId) return res.status(404).json({ error: "vp_request_not_found" });
      const validation = await (await credoOpenId4VpVerifier(config)).verifyResponse(
        session,
        body,
        verificationSessionId,
      );
      captureVpResponse(
        store,
        session,
        body,
        (req as Request & { rawBody?: string }).rawBody,
        validation,
      );
      if (!validation.valid) {
        return res.status(400).json({ error: "invalid_presentation", errors: validation.errors });
      }
      return res.json({});
    } catch (error) {
      return next(error);
    }
  });

  app.get("/openid4vp/sessions/:sessionId/events", (req, res) => {
    const session = store.getVpSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "vp_session_not_found" });
    return res.json(session.events);
  });

  app.post("/issuers/:issuerConfigurationId/credential", async (req, res, next) => {
    const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
    if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
    const issuerConfig = issuerAppConfig(config, issuer);
    const encryptedRequest = req.is("application/jwt") === "application/jwt";
    let body: JsonRecord;
    let responseEncryption: ReturnType<typeof credentialResponseEncryption>;
    try {
      if (encryptedRequest) {
        if (typeof req.body !== "string" || !req.body) {
          throw new CredentialEncryptionError(
            "Encrypted Credential Request body must be a compact JWE",
          );
        }
        body = await decryptCredentialRequest(issuerConfig, req.body);
      } else {
        body = requestParams(req);
      }
      responseEncryption = credentialResponseEncryption(body);
      if (responseEncryption && !encryptedRequest) {
        throw new CredentialEncryptionError(
          "credential_response_encryption requires an encrypted Credential Request",
        );
      }
    } catch (error) {
      return res.status(400).json({
        error: "invalid_encryption_parameters",
        error_description: errorMessage(error),
      });
    }

    const capture = oid4vciCaptures.get(req) ?? null;
    const credentialRequestRaw = encryptedRequest ? capture?.body : undefined;
    if (capture) capture.body = redactOid4vciValue(body);
    const { credential_response_encryption: _credentialResponseEncryption, ...credoBody } = body;
    req.body = credoBody;
    req.headers["content-type"] = "application/json";
    const encryptedResponse = responseEncryption
      ? interceptCredentialResponse(res, next, issuerConfig, responseEncryption)
      : null;
    const credentialEndpointNext: NextFunction = (error) => {
      if (encryptedResponse?.isPending()) return;
      if (error) return next(error);
      if (res.headersSent) return;
      return next(new Error("Credo Credential endpoint completed without sending a response"));
    };
    try {
      return (await credoOpenId4VciIssuer(config, store)).forward(
        req,
        res,
        credentialEndpointNext,
        capture,
        {
          body,
          raw: credentialRequestRaw,
        },
      );
    } catch (error) {
      return next(error);
    }
  });

  app.use(async (req, res, next) => {
    if (!isCredoIssuerEndpoint(req.path)) return next();
    try {
      return (await credoOpenId4VciIssuer(config, store)).forward(
        req,
        res,
        next,
        oid4vciCaptures.get(req) ?? null,
      );
    } catch (error) {
      return next(error);
    }
  });

  app.use(
    (error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: "internal_error", message: error.message });
    },
  );

  return app;
}

function oid4vciRequestSessionId(store: CaptureStore, req: Request): string | null {
  const sessionPath = /^\/sessions\/([^/]+)\/(?:offer|deeplink)$/.exec(req.path);
  if (sessionPath?.[1]) return decodeURIComponent(sessionPath[1]);
  const offerPath = /^\/issuers\/[^/]+\/offers\/([^/]+)$/.exec(req.path);
  if (offerPath?.[1]) {
    return store.captureSessionIdsByCredentialOffer.get(offerPath[1]) ?? null;
  }
  return null;
}

function oid4vciRequestIssuerConfigurationId(store: CaptureStore, req: Request): string | null {
  const issuerPath =
    /^\/issuers\/([^/]+)\//.exec(req.path) ??
    /^\/(?:authorization-servers)\/([^/]+)\//.exec(req.path) ??
    /^\/\.well-known\/(?:openid-credential-issuer|jwt-vc-issuer)\/issuers\/([^/]+)$/.exec(
      req.path,
    ) ??
    /^\/\.well-known\/oauth-authorization-server\/(?:issuers|authorization-servers)\/([^/]+)$/.exec(
      req.path,
    );
  if (issuerPath?.[1]) return decodeURIComponent(issuerPath[1]);
  const sessionId = oid4vciRequestSessionId(store, req);
  return sessionId ? (store.getSession(sessionId)?.issuer_configuration_id ?? null) : null;
}

function isCredoIssuerEndpoint(path: string): boolean {
  return (
    /^\/issuers\/[^/]+\/(?:jwks\.json|par|authorize|challenge|redirect|nonce|token|deferred-credential)$/.test(
      path,
    ) || /^\/issuers\/[^/]+\/offers\/[^/]+$/.test(path)
  );
}

function interceptCredentialResponse(
  res: Response,
  next: NextFunction,
  issuerConfig: AppConfig,
  responseEncryption: NonNullable<ReturnType<typeof credentialResponseEncryption>>,
): { isPending: () => boolean } {
  const send = res.send.bind(res);
  let pending = false;
  let settled = false;
  res.send = ((responseBody: unknown) => {
    if (pending || settled) return res;
    const serialized =
      typeof responseBody === "string"
        ? responseBody
        : Buffer.isBuffer(responseBody)
          ? responseBody.toString("utf8")
          : JSON.stringify(responseBody);
    let json: JsonRecord;
    try {
      json = JSON.parse(serialized) as JsonRecord;
    } catch {
      settled = true;
      res.send = send;
      return send(responseBody);
    }

    const statusCode = res.statusCode;
    pending = true;
    void encryptCredentialResponse(issuerConfig, responseEncryption, json)
      .then((jwe) => {
        pending = false;
        settled = true;
        res.send = send;
        res.status(statusCode);
        res.setHeader("Content-Type", "application/jwt");
        send(jwe);
      })
      .catch((error: unknown) => {
        pending = false;
        settled = true;
        res.send = send;
        next(error);
      });
    return res;
  }) as typeof res.send;
  return { isPending: () => pending };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function requestParams(req: Request): JsonRecord {
  return { ...(req.body as JsonRecord) };
}

function rawBodyCapture(req: Request, _res: express.Response, buffer: Buffer): void {
  (req as Request & { rawBody?: string }).rawBody = buffer.toString("utf8");
}

async function createIssuanceSession(
  config: AppConfig,
  store: CaptureStore,
  issuer: ResolvedIssuerConfiguration,
  credentialConfigurationId: string,
  flow: SessionCapture["flow"] = "authorization_code",
  credentialOfferMode: CredentialOfferMode = "credential_offer",
): Promise<SessionCapture> {
  const session = store.createSession(issuer, credentialConfigurationId, flow, credentialOfferMode);
  const offer = await (await credoOpenId4VciIssuer(config, store)).createCredentialOffer({
    issuerConfigurationId: issuer.id,
    captureSessionId: session.session_id,
    credentialConfigurationId: session.credential_configuration_id,
    flow: session.flow,
    credentialOfferMode: session.credential_offer_mode,
  });
  store.credoIssuanceOffers.set(session.session_id, {
    credential_offer: offer.credentialOffer,
    credential_offer_object: offer.credentialOfferObject,
    credential_offer_uri: offer.credentialOfferUri,
    credo_issuance_session_id: offer.issuanceSessionId,
  });
  store.addEvent(session, "credential_offer_generated", {
    flow: session.flow,
    credential_offer_mode: session.credential_offer_mode,
    implementation: "credo-ts",
  });
  return session;
}

function issuerFromRequest(config: AppConfig, value: unknown): ResolvedIssuerConfiguration | null {
  const id = asStringOrNull(value) ?? DEFAULT_ISSUER_CONFIGURATION_ID;
  return resolvedIssuerConfigurationById(config, id);
}

function issuanceFlowOrNull(value: unknown): SessionCapture["flow"] | null {
  return value === "pre_authorized_code" || value === "authorization_code" ? value : null;
}

function credentialOfferModeOrNull(value: unknown): CredentialOfferMode | null {
  return value === "credential_offer" || value === "credential_offer_uri" ? value : null;
}

async function createVpSession(
  config: AppConfig,
  store: CaptureStore,
  requestOverride: JsonRecord,
  credentialConfigurationIds?: string[],
  requestUriMethod: "get" | "post" = "get",
  responseMode: OpenId4VpResponseMode = "direct_post.jwt",
  requestDelivery: "by_reference" | "by_value" = "by_reference",
  deeplinkScheme = "openid4vp://",
): Promise<VpSessionCapture> {
  const sessionId = randomUUID();
  const defaultRequest = defaultPresentationRequest(
    config,
    credentialConfigurationIds,
    responseMode,
  );
  const request = {
    ...defaultRequest,
    ...requestOverride,
    response_mode: responseMode,
  };
  const credoVerifier = await credoOpenId4VpVerifier(config);
  const credoSession = await credoVerifier.createSession(
    sessionId,
    request,
    defaultRequest.dcql_query as JsonRecord,
    requestUriMethod,
    requestDelivery,
    deeplinkScheme,
  );
  const session = store.createVpSession(
    sessionId,
    credoSession.authorizationRequest,
    requestDelivery,
    requestUriMethod,
    responseMode,
    deeplinkScheme,
    {
      requestUri: credoSession.requestUri,
      responseUri: credoSession.responseUri,
    },
  );
  store.vpCredoVerificationSessionIds.set(sessionId, credoSession.verificationSessionId);
  store.vpCredoAuthorizationRequestJwts.set(sessionId, credoSession.authorizationRequestJwt);
  session.deeplink = credoSession.deeplink;
  return session;
}

function captureVpResponse(
  store: CaptureStore,
  session: VpSessionCapture,
  body: JsonRecord,
  rawBody: string | undefined,
  validation: {
    valid: boolean;
    vp_token_format_valid: boolean;
    nonce_verified: boolean;
    holder_binding_verified: boolean;
    dcql_query_matched: boolean;
    authorization_response?: JsonRecord;
    decoded_presentations?: JsonRecord;
    errors: string[];
  },
): void {
  session.status = validation.valid ? "presentation_validated" : "presentation_invalid";
  session.checks = {
    presentation_valid: validation.valid,
    vp_token_format_valid: validation.vp_token_format_valid,
    nonce_verified: validation.nonce_verified,
    holder_binding_verified: validation.holder_binding_verified,
    dcql_query_matched: validation.dcql_query_matched,
    errors: validation.errors,
  };
  session.raw ??= {};
  session.raw.presentation_response = body;
  if (validation.authorization_response) {
    session.raw.presentation_response_decrypted = validation.authorization_response;
  }
  if (validation.decoded_presentations) {
    session.decoded_presentations = validation.decoded_presentations;
    session.raw.decoded_presentations = validation.decoded_presentations;
  }
  session.raw.presentation_response_raw = rawBody ?? JSON.stringify(body);
  session.observed.wallet_response = {
    value: body,
    source: "presentation_response",
    also_seen_in: [],
  };
  store.addEvent(session, "vp_presentation_response_received", {
    vp_token_observed: body.vp_token !== undefined,
    presentation_valid: validation.valid,
    errors: validation.errors,
  });
}

function objectOrNull(value: unknown): JsonRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as JsonRecord;
}

function requestUriMethodOrNull(value: unknown): "get" | "post" | null {
  if (typeof value !== "string") return null;
  const normalized = value.toLowerCase();
  return normalized === "get" || normalized === "post" ? normalized : null;
}

function responseModeOrNull(value: unknown): OpenId4VpResponseMode | null {
  if (typeof value !== "string") return null;
  const normalized = value.toLowerCase();
  return normalized === "direct_post" || normalized === "direct_post.jwt" ? normalized : null;
}

function requestDeliveryOrNull(value: unknown): "by_reference" | "by_value" | null {
  if (typeof value !== "string") return null;
  const normalized = value.toLowerCase();
  return normalized === "by_reference" || normalized === "by_value" ? normalized : null;
}

function deeplinkSchemeOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return /^[a-z][a-z0-9+.-]*:\/\/$/i.test(value) ? value : null;
}

function vpRequestBody(body: JsonRecord): JsonRecord {
  const {
    request_delivery: _requestDelivery,
    request_uri_method: _requestUriMethod,
    response_mode: _responseMode,
    scheme: _scheme,
    ...request
  } = body;
  return request;
}
