import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import express, { type NextFunction, type Request, type Response } from "express";
import QRCode from "qrcode";
import { sha256Hex } from "../attestbook/digest.js";
import { attestbookIntegration } from "../attestbook/integration.js";
import type { AttestbookCredentialDefinition } from "../attestbook/types.js";
import { WEBHOOK_MAX_BODY_BYTES, WEBHOOK_PATH } from "../attestbook/webhook.js";
import { loadIssuerJwks, validateIssuerMaterial } from "../config/key-material.js";
import {
  verifierAttestationIssuerPublicJwk,
  verifierDidDocument,
} from "../config/verifier-identity.js";
import {
  issuerCatalogue,
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../configurations/registry.js";
import { issuerAppConfig } from "../configurations/resolve-urls.js";
import { PID_FIXTURE_IDS } from "../configurations/shared/pid-fixtures.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import { supportedCredentialConfigurationIds } from "../credentials/catalogue.js";
import { SD_JWT_DIGEST_ALGORITHMS } from "../credentials/digest-algorithm.js";
import { credentialRegistry } from "../credentials/registry.js";
import { unsetJsonPointer } from "../fcaf/json-pointer.js";
import { requestMutationPointers } from "../fcaf/request-mutation.js";
import {
  ENTITY_STATEMENT_MEDIA_TYPE,
  signIssuerEntityConfiguration,
} from "../federation/entity-configuration.js";
import { apiDocsPage } from "../openapi/docs-page.js";
import { openApiDocument } from "../openapi/document.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import { registerFakeOAuthServer } from "../openid4vci/fake-oauth-server.js";
import {
  completeOid4vciRequestCapture,
  createOid4vciRequestCaptures,
  isOid4vciProtocolPath,
  isRawBodyEvidencePath,
  recordResponseBody,
  redactHttpHeaders,
  responseBodyEvidence,
} from "../openid4vci/http-capture.js";
import { jwtVcIssuerMetadata, signCredentialIssuerMetadata } from "../openid4vci/metadata.js";
import {
  OPENID4VP_RESPONSE_MODE_VALUES,
  type OpenId4VpClientIdScheme,
  type OpenId4VpResponseMode,
  dcApiPresentationExpiresAt,
  defaultDcqlQuery,
  defaultPresentationRequest,
  isDcApiResponseMode,
  isEncryptedResponseMode,
  verifierClientIdentifiers,
} from "../openid4vp/authorization-request.js";
import { type CredoVpSession, credoOpenId4VpVerifier } from "../openid4vp/credo-verifier.js";
import {
  generateRequestCertificateMaterial,
  generateUnrelatedSigningKey,
  verifierChainWithTrustAnchor,
} from "../openid4vp/request-certificates.js";
import { ClientMetadataError, ResponseModeError } from "../openid4vp/request-construction.js";
import { errorMessage } from "../shared/errors.js";
import { asStringOrNull, booleanOrNull } from "../shared/json.js";
import { CaptureStore } from "../state.js";
import { revokeStatusListReference } from "../status-list/allocation.js";
import { STATUS_REFERENCE_FIXTURES } from "../status-list/reference-fixtures.js";
import type {
  AppConfig,
  CredentialOfferMode,
  CredentialOfferScheme,
  EvidenceMode,
  IssuanceEndpointResponseScenario,
  IssuanceResponseScenario,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  RedirectUriVisitHttpCapture,
  RequestSigningMaterial,
  SdJwtDigestAlgorithm,
  SessionCapture,
  StatusListUpdateCapture,
  StatusReferenceFixture,
  VpDcApiInvocationCapture,
  VpDcApiInvocationOutcome,
  VpRequestBehavior,
  VpRequestDelivery,
  VpRequestMutation,
  VpRequestMutationEdits,
  VpResponseScenario,
  VpSessionCapture,
  VpVerifierAttestation,
} from "../types.js";
import {
  type IssuerCredentialGroup,
  VERIFIER_PAGE_PATH,
  credentialOfferEngagementPage,
  dcApiPresentationPage,
  errorPage,
  helpPage,
  indexPage,
  issuerPage,
  sessionPage,
  verifierPage,
  vpRedirectPage,
  vpSessionPage,
} from "../ui.js";
import {
  type CredentialRequestBody,
  forwardCredentialRequest,
  interceptCredentialResponse,
  pinnedDefinitionMismatch,
  readCredentialRequestBody,
  recordCredentialRequestEvidence,
} from "./credential-endpoint.js";
import {
  CREDENTIAL_OFFER_MODES,
  DEFAULT_OFFER_SCHEME,
  EVIDENCE_MODES,
  ISSUANCE_FLOWS,
  OFFER_SCHEMES,
  issuerCredentialRegistry,
  issuerFromRequest,
  parseIssuanceSessionInput,
} from "./issuance-session-input.js";
import {
  VP_CLIENT_ID_SCHEMES,
  VP_REQUEST_DELIVERIES,
  deriveVpSessionOptions,
  parseVpRequestOverride,
  parseVpSessionInput,
  serializeVpSession,
  validateVpSessionCombination,
} from "./presentation-session-input.js";
import {
  recordWalletNonceRequest,
  requestUriHttpCapture,
  resignDeliveredRequest,
  sendNegotiatedRequestObject,
  sendRequestUriResponse,
} from "./vp-request-uri.js";
import {
  dcApiSubmissionRejectionOrNull,
  presentationResponseHttpCapture,
  submitPresentation,
  vpPresentationCaptured,
} from "./vp-submission.js";

export function createApp(config: AppConfig, store = new CaptureStore(config)): express.Express {
  if (config.federation.enabled) validateIssuerMaterial(config);
  const app = express();
  const oid4vciCaptures = new WeakMap<Request, Oid4vciHttpRequestCapture>();
  // Every OpenID4VCI request is recorded before any handler runs, and attributed to its capture
  // session there too, so a request Credo-TS rejects still leaves session evidence. A request with
  // no matching route or configured issuer resource is recorded as `unmatched`.
  const captureOid4vciRequest = async (
    req: Request,
    res: Response,
    unmatched = false,
  ): Promise<void> => {
    const captures = createOid4vciRequestCaptures(
      req,
      oid4vciRequestIssuerConfigurationId(store, req),
    );
    if (unmatched) {
      captures.redacted.unmatched = true;
      captures.full.unmatched = true;
    }
    oid4vciCaptures.set(req, captures.redacted);
    store.recordOid4vciRequest(captures.redacted, captures.full);
    const responseBody = recordResponseBody(res);
    res.once("finish", () => {
      completeOid4vciRequestCapture(captures.redacted, res, responseBody(), "redacted");
      completeOid4vciRequestCapture(captures.full, res, responseBody(), "full");
    });
    const sessionId = unmatched
      ? unmatchedRequestSessionId(store, req)
      : (oid4vciRequestSessionId(store, req) ??
        (isCredoSessionEndpoint(req.path)
          ? await (await credoOpenId4VciIssuer(config, store)).captureSessionIdForRequest(req)
          : null));
    if (sessionId) store.linkOid4vciRequestToSession(captures.redacted, sessionId);
  };

  const markOid4vciRequestUnmatched = (req: Request): void => {
    const capture = oid4vciCaptures.get(req);
    if (!capture) return;
    capture.unmatched = true;
    const fullCapture = store.fullOid4vciRequests.get(capture);
    if (fullCapture) fullCapture.unmatched = true;
  };
  const matchedIssuerOrNull = (req: Request): ResolvedIssuerConfiguration | null => {
    const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
    if (!issuer) markOid4vciRequestUnmatched(req);
    return issuer;
  };

  // A session's issuance_response_scenario replaces what the Wallet receives from its PAR or
  // Credential endpoint. Credo-TS has already produced the real response, which is recorded next to
  // the delivered one, redacted for the session's evidence mode.
  const applyIssuanceResponseScenario = (
    req: Request,
    res: Response,
    endpoint: keyof IssuanceResponseScenario,
  ): void => {
    const capture = oid4vciCaptures.get(req);
    const session = capture?.session_id ? store.getSession(capture.session_id) : undefined;
    const scenario = session?.issuance_response_scenario?.[endpoint];
    if (!capture || !session || !scenario) return;
    const mode = session.evidence_mode ?? "redacted";
    const evidence = (response: ScenarioHttpResponse): JsonRecord => ({
      status: response.status,
      content_type: response.content_type,
      body: responseBodyEvidence(Buffer.from(response.body), response.content_type, mode),
    });
    interceptIssuanceResponse(res, scenario, (original, delivered) => {
      store.addEvent(session, "issuance_response_scenario_applied", {
        endpoint,
        request_id: capture.id,
        scenario: { ...scenario },
        original: evidence(original),
        delivered: evidence(delivered),
      });
    });
  };

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
    captureOid4vciRequest(req, res).then(() => next(error), next);
  });
  app.use(async (req, res, next) => {
    if (!isOid4vciProtocolPath(req.path)) return next();
    try {
      await captureOid4vciRequest(req, res);
    } catch (error) {
      return next(error);
    }
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
    app.get("/", async (_req, res, next) => {
      try {
        res.type("html").send(indexPage(await issuerCredentialGroups(config, store)));
      } catch (error) {
        next(error);
      }
    });

    // The Credential Issuer Identifier doubles as the issuer's operator page for a browser. Any
    // other client, a Wallet probing the identifier included, still falls through to the 404 and
    // its `unmatched` capture.
    app.get("/issuers/:issuerConfigurationId", async (req, res, next) => {
      try {
        res.vary("Accept");
        if (req.accepts(["application/json", "text/html"]) !== "text/html") return next();
        const issuerId = req.params.issuerConfigurationId;
        const group = (await issuerCredentialGroups(config, store)).find(
          (candidate) => candidate.issuer.id === issuerId,
        );
        if (!group) return next();
        return res.type("html").send(
          issuerPage({
            group,
            ...(config.federation.enabled
              ? {
                  federationEntityConfigurationUrl: `${group.issuer.issuerIdentifier}/.well-known/openid-federation`,
                }
              : {}),
            fcafScenariosEnabled: config.fcaf_scenarios_enabled,
            parameters: {
              flows: ISSUANCE_FLOWS,
              credentialOfferModes: CREDENTIAL_OFFER_MODES,
              offerSchemes: OFFER_SCHEMES,
              fixtureIds: PID_FIXTURE_IDS,
              digestAlgorithms: SD_JWT_DIGEST_ALGORITHMS,
              evidenceModes: EVIDENCE_MODES,
              statusReferences: STATUS_REFERENCE_FIXTURES,
            },
          }),
        );
      } catch (error) {
        return next(error);
      }
    });

    app.get(VERIFIER_PAGE_PATH, async (_req, res, next) => {
      try {
        const groups = (await issuerCredentialGroups(config, store)).map(
          ({ issuer, credentials }) => ({
            issuer,
            credentials: credentials.map((credential) => ({
              credential,
              dcqlQuery: defaultDcqlQuery([credential]),
            })),
          }),
        );
        res.type("html").send(
          verifierPage({
            groups,
            fcafScenariosEnabled: config.fcaf_scenarios_enabled,
            parameters: {
              responseModes: OPENID4VP_RESPONSE_MODE_VALUES,
              requestDeliveries: VP_REQUEST_DELIVERIES,
              clientIdSchemes: VP_CLIENT_ID_SCHEMES,
            },
          }),
        );
      } catch (error) {
        next(error);
      }
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

    app.get("/assets/credimi_logo-transp.svg", (_req, res) => {
      res
        .type("image/svg+xml")
        .send(readFileSync("src/design/logo/credimi_logo-transp.svg", "utf8"));
    });

    app.get("/assets/credimi_logo-transp_white.svg", (_req, res) => {
      res
        .type("image/svg+xml")
        .send(readFileSync("src/design/logo/credimi_logo-transp_white.svg", "utf8"));
    });

    app.post("/ui/sessions", async (req, res, next) => {
      try {
        const body = requestParams(req);
        const issuer = issuerFromRequest(config, body.issuer_configuration_id);
        if (!issuer) {
          return res.status(400).type("html").send(errorPage("Unsupported issuer configuration"));
        }
        const registry = await issuerCredentialRegistry(config, store);
        const supportedIds = registry
          .credentialsForIssuer(issuer)
          .map((credential) => credential.id);
        const credentialConfigurationId =
          asStringOrNull(body.credential_configuration_id) ?? supportedIds[0];
        const credential = credentialConfigurationId
          ? registry.credentialById(issuer, credentialConfigurationId)
          : null;
        if (!credentialConfigurationId || !credential) {
          return res
            .status(400)
            .type("html")
            .send(errorPage("Unsupported credential configuration"));
        }
        const statusListEnabled = booleanOrNull(body.status_list_enabled);
        if (body.status_list_enabled !== undefined && statusListEnabled === null) {
          return res
            .status(400)
            .type("html")
            .send(errorPage("status_list_enabled must be true or false"));
        }
        const imported = credential.attestbook;
        if (imported && statusListEnabled) {
          return res
            .status(400)
            .type("html")
            .send(errorPage("Imported Attestbook credentials do not support a Token Status List"));
        }
        const session = await createIssuanceSession(
          config,
          store,
          issuer,
          credentialConfigurationId,
          "authorization_code",
          "credential_offer",
          statusListEnabled ?? false,
          undefined,
          undefined,
          undefined,
          undefined,
          "redacted",
          DEFAULT_OFFER_SCHEME,
          undefined,
          imported,
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

        const session = await createVpSession(config, store, {
          requestOverride: {},
          credentialConfigurationIds: [credentialConfigurationId],
        });
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

    app.get("/ui/sessions/:sessionId/engage", async (req, res, next) => {
      try {
        const session = store.getSession(req.params.sessionId);
        if (!session) return res.status(404).type("html").send(errorPage("Session not found"));
        const offer = store.credoIssuanceOffers.get(session.session_id);
        if (!offer)
          return res.status(409).type("html").send(errorPage("Credential offer not ready"));
        const qrSvg = await QRCode.toString(offer.credential_offer, {
          type: "svg",
          errorCorrectionLevel: "M",
          margin: 1,
          width: 288,
        });
        store.addEvent(session, "credential_offer_engagement_page_served", {});
        return res.type("html").send(credentialOfferEngagementPage(offer.credential_offer, qrSvg));
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
        return res
          .type("html")
          .send(
            vpSessionPage(
              session.session_id,
              session.deeplink,
              qrSvg,
              isDcApiResponseMode(session.response_mode),
            ),
          );
      } catch (error) {
        return next(error);
      }
    });

    /**
     * The page the DC API QR code opens on the End-User's device. It is unauthenticated by
     * design — the phone has no operator session — so it receives only the browser invocation
     * request for the addressed session and nothing else from the capture record.
     */
    app.get("/ui/openid4vp/sessions/:sessionId/dc_api_presentation", (req, res) => {
      const session = store.getVpSession(req.params.sessionId);
      if (!session) return res.status(404).type("html").send(errorPage("VP session not found"));
      const dcApi = session.dc_api;
      if (!dcApi) {
        return res
          .status(400)
          .type("html")
          .send(errorPage("This session does not use the Digital Credentials API"));
      }
      const state = vpPresentationCaptured(session)
        ? "completed"
        : Date.parse(dcApi.expires_at) <= Date.now()
          ? "expired"
          : "ready";
      store.addEvent(session, "vp_dc_api_presentation_page_opened", { state });
      return res
        .status(200)
        .set("Cache-Control", "no-store")
        .set("Referrer-Policy", "no-referrer")
        .type("html")
        .send(
          dcApiPresentationPage({
            sessionId: session.session_id,
            request: dcApi.request,
            expectedOrigin: dcApi.expected_origin,
            expiresAt: dcApi.expires_at,
            state,
          }),
        );
    });
  }
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

  app.get(
    "/.well-known/openid-credential-issuer/issuers/:issuerConfigurationId",
    async (req, res, next) => {
      try {
        const issuer = matchedIssuerOrNull(req);
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
        const issuer = matchedIssuerOrNull(req);
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

  app.post("/sessions", async (req, res, next) => {
    try {
      const parsed = await parseIssuanceSessionInput(config, store, requestParams(req));
      if (!parsed.ok) return res.status(parsed.status).json(parsed.body);
      const {
        issuer,
        credentialConfigurationId,
        flow,
        credentialOfferMode,
        statusListEnabled,
        fixtureId,
        documentNumber,
        statusReference,
        digestAlgorithm,
        evidenceMode,
        issuanceResponseScenario,
        offerScheme,
        offerMutation,
        importedDefinition,
      } = parsed.value;
      const session = await createIssuanceSession(
        config,
        store,
        issuer,
        credentialConfigurationId,
        flow,
        credentialOfferMode,
        statusListEnabled,
        fixtureId,
        documentNumber,
        statusReference,
        digestAlgorithm,
        evidenceMode,
        offerScheme,
        offerMutation,
        importedDefinition,
      );
      if (issuanceResponseScenario) session.issuance_response_scenario = issuanceResponseScenario;
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
        status_list_enabled: session.status_list_enabled,
        fixture_id: session.fixture_id,
        ...(session.credential_definition
          ? { credential_definition: session.credential_definition }
          : {}),
        ...(session.generated_claims ? { generated_claims: session.generated_claims } : {}),
        ...(session.document_number ? { document_number: session.document_number } : {}),
        ...(session.status_reference ? { status_reference: session.status_reference } : {}),
        ...(session.digest_algorithm ? { digest_algorithm: session.digest_algorithm } : {}),
        ...(session.evidence_mode ? { evidence_mode: session.evidence_mode } : {}),
        ...(session.offer_scheme ? { offer_scheme: session.offer_scheme } : {}),
        offer_url: offer.credential_offer_uri,
        deeplink: offer.credential_offer,
        status: session.status,
      });
    } catch (error) {
      if (error instanceof CredentialSupersededError) {
        return res.status(409).json({
          error: "credential_configuration_superseded",
          error_description: error.message,
        });
      }
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

  // A session's attributed requests, plus every unattributed one recorded since it was created, so
  // a consumer can establish that a Wallet made no request it should not have, such as a metadata
  // request derived from the engagement page's origin, which carries no session context.
  app.get("/sessions/:sessionId/requests", (req, res) => {
    const session = store.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "session_not_found" });
    const from = session.events.find((event) => event.type === "session_created")?.at ?? "";
    const to = new Date().toISOString();
    return res.json({
      session_id: session.session_id,
      window: { from, to },
      requests: [...(session.raw?.oid4vci_requests ?? [])].sort((a, b) => a.at.localeCompare(b.at)),
      unattributed_requests: store.oid4vciRequests.filter(
        (entry) => entry.session_id === null && entry.at >= from && entry.at <= to,
      ),
    });
  });

  // Test-only revocation of every reference allocated for the session's credentials, through the
  // Status List service. It is separate from issuance so that a test can revoke after the Wallet
  // has stored the credential.
  app.post("/sessions/:sessionId/status", async (req, res, next) => {
    try {
      if (!config.fcaf_scenarios_enabled) {
        return res.status(400).json({ error: "status_update_not_enabled" });
      }
      const session = store.getSession(req.params.sessionId);
      if (!session) return res.status(404).json({ error: "session_not_found" });
      const body = requestParams(req);
      if (body.status !== "revoked") {
        return res
          .status(400)
          .json({ error: "unsupported_status", supported_statuses: ["revoked"] });
      }
      if (!session.status_list_enabled) {
        return res.status(400).json({ error: "status_list_not_enabled" });
      }
      const references = (session.status_list_references ?? []).filter(Boolean);
      if (references.length === 0) {
        return res.status(409).json({ error: "status_list_references_not_allocated" });
      }
      const update: StatusListUpdateCapture = {
        at: new Date().toISOString(),
        requested_status: "revoked",
        results: await Promise.all(
          references.map(({ uri, idx }) => revokeStatusListReference(config, { uri, idx })),
        ),
      };
      session.status_list_updates ??= [];
      session.status_list_updates.push(update);
      store.addEvent(session, "status_list_status_updated", {
        requested_status: update.requested_status,
        results: update.results.map(({ uri, idx, ok, http_status, error }) => ({
          uri,
          idx,
          ok,
          http_status,
          ...(error === undefined ? {} : { error }),
        })),
      });
      const failed = update.results.some((result) => !result.ok);
      return res.status(failed ? 502 : 200).json({
        ...(failed ? { error: "status_list_update_failed" } : {}),
        session_id: session.session_id,
        ...update,
      });
    } catch (error) {
      return next(error);
    }
  });

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

  app.post("/issuers/:issuerConfigurationId/credential", async (req, res, next) => {
    const issuer = resolvedIssuerConfigurationById(config, req.params.issuerConfigurationId);
    if (!issuer) return res.status(404).json({ error: "issuer_not_found" });
    const issuerConfig = issuerAppConfig(config, issuer);
    let requestBody: CredentialRequestBody;
    try {
      requestBody = await readCredentialRequestBody(req, issuerConfig);
    } catch (error) {
      return res.status(400).json({
        error: "invalid_encryption_parameters",
        error_description: errorMessage(error),
      });
    }

    const capture = oid4vciCaptures.get(req) ?? null;
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
    const encryptedResponse = requestBody.responseEncryption
      ? interceptCredentialResponse(res, next, issuerConfig, requestBody.responseEncryption)
      : null;
    // Installed after the encryption interceptor so a scenario edits the plaintext response,
    // which is then encrypted only if it is still a success (OpenID4VCI 1.0 Section 8.3.1).
    applyIssuanceResponseScenario(req, res, "credential");
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
          oid4vciCaptures.get(req) ?? null,
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

  app.use(async (req, res, next) => {
    if (!isCredoIssuerEndpoint(req.path)) return next();
    if (req.path.endsWith("/par")) applyIssuanceResponseScenario(req, res, "par");
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

  // A request no route handles is recorded as `unmatched` before its 404, so a Wallet that fetches
  // metadata from a URL it derived itself, or anything else unexpected, leaves evidence.
  app.use((req, res, next) => {
    const capture = oid4vciCaptures.get(req);
    if (!capture) return captureOid4vciRequest(req, res, true).then(() => next(), next);
    markOid4vciRequestUnmatched(req);
    return next();
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

/** The existing session an unrouted request names in its path, such as a mistyped session route. */
function unmatchedRequestSessionId(store: CaptureStore, req: Request): string | null {
  const sessionId = /^\/(?:ui\/)?sessions\/([^/]+)/.exec(req.path)?.[1];
  return sessionId && store.getSession(sessionId) ? sessionId : null;
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

/** Issuer endpoints whose requests carry something Credo-TS can map back to an issuance session. */
function isCredoSessionEndpoint(path: string): boolean {
  return /^\/issuers\/[^/]+\/(?:par|authorize|redirect|token|credential|deferred-credential|notification)$/.test(
    path,
  );
}

interface ScenarioHttpResponse {
  status: number;
  content_type: string | null;
  body: string;
}

/**
 * The single HTTP boundary for an `issuance_response_scenario`. The response Credo-TS produced is
 * replaced once, as it is sent, so Credo's own state and the session's checks keep the real
 * outcome. `body` replaces the body exactly; otherwise `extra_parameters` are merged into the JSON
 * body and `omit_parameters` then removed from it.
 */
function interceptIssuanceResponse(
  res: Response,
  scenario: IssuanceEndpointResponseScenario,
  onApplied: (original: ScenarioHttpResponse, delivered: ScenarioHttpResponse) => void,
): void {
  const send = res.send;
  res.send = function (this: Response, responseBody?: unknown) {
    res.send = send;
    const original = {
      status: res.statusCode,
      content_type: res.get("Content-Type") ?? null,
      body:
        typeof responseBody === "string"
          ? responseBody
          : Buffer.isBuffer(responseBody)
            ? responseBody.toString("utf8")
            : (JSON.stringify(responseBody) ?? ""),
    };
    const body = scenario.body ?? scenarioJsonBody(original.body, scenario);
    if (scenario.status !== undefined) res.status(scenario.status);
    if (scenario.content_type !== undefined) res.type(scenario.content_type);
    onApplied(original, {
      status: res.statusCode,
      content_type: res.get("Content-Type") ?? null,
      body,
    });
    return send.call(this, body);
  } as Response["send"];
}

function scenarioJsonBody(text: string, scenario: IssuanceEndpointResponseScenario): string {
  if (!scenario.extra_parameters && !scenario.omit_parameters) return text;
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return text;
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) return text;
  const edited: JsonRecord = { ...json, ...(scenario.extra_parameters ?? {}) };
  for (const pointer of scenario.omit_parameters ?? []) unsetJsonPointer(edited, pointer);
  return JSON.stringify(edited);
}

function requestParams(req: Request): JsonRecord {
  return { ...(req.body as JsonRecord) };
}

function rawBodyCapture(req: Request, _res: express.Response, buffer: Buffer): void {
  const rawBodyRequest = req as Request & { rawBody?: string; rawBodyBytes?: Buffer };
  rawBodyRequest.rawBody = buffer.toString("utf8");
  rawBodyRequest.rawBodyBytes = buffer;
}

async function createIssuanceSession(
  config: AppConfig,
  store: CaptureStore,
  issuer: ResolvedIssuerConfiguration,
  credentialConfigurationId: string,
  flow: SessionCapture["flow"] = "authorization_code",
  credentialOfferMode: CredentialOfferMode = "credential_offer",
  statusListEnabled = false,
  fixtureId?: string,
  documentNumber?: string,
  statusReference?: StatusReferenceFixture,
  digestAlgorithm?: SdJwtDigestAlgorithm,
  evidenceMode: EvidenceMode = "redacted",
  offerScheme: CredentialOfferScheme = DEFAULT_OFFER_SCHEME,
  offerMutation?: VpRequestMutationEdits,
  importedDefinition?: AttestbookCredentialDefinition,
): Promise<SessionCapture> {
  const create = async (): Promise<SessionCapture> => {
    const session = store.createSession(issuer, {
      credentialConfigurationId,
      flow,
      credentialOfferMode,
      statusListEnabled,
      fixtureId,
      documentNumber,
      statusReference,
      digestAlgorithm,
      evidenceMode,
    });
    if (offerScheme !== DEFAULT_OFFER_SCHEME) session.offer_scheme = offerScheme;
    if (importedDefinition) {
      attestbookIntegration(config, store).pinSession(session, importedDefinition);
    }

    const offer = await (await credoOpenId4VciIssuer(config, store)).createCredentialOffer({
      issuerConfigurationId: issuer.id,
      captureSessionId: session.session_id,
      credentialConfigurationId: session.credential_configuration_id,
      flow: session.flow,
      credentialOfferMode: session.credential_offer_mode,
      offerScheme,
      offerMutation,
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
      ...(session.offer_scheme ? { offer_scheme: session.offer_scheme } : {}),
      implementation: "credo-ts",
    });
    if (offerMutation && offer.deliveredCredentialOfferObject) {
      session.offer_mutation = offerMutation;
      session.raw ??= {};
      session.raw.credential_offer = offer.credentialOfferObject;
      session.raw.credential_offer_delivered = offer.deliveredCredentialOfferObject;
      store.addEvent(session, "credential_offer_mutation_applied", {
        pointers: [...Object.keys(offerMutation.set ?? {}), ...(offerMutation.unset ?? [])],
      });
    }
    return session;
  };
  if (!importedDefinition) return create();
  // An imported session is created while no activation runs, and only if its definition is still
  // the active one, so the session is always pinned to a definition the issuer record carries.
  const registry = credentialRegistry(config, store);
  return registry.serialize(async () => {
    const active = registry.credentialById(issuer, credentialConfigurationId)?.attestbook;
    if (active?.contentDigest !== importedDefinition.contentDigest) {
      throw new CredentialSupersededError(
        `credential configuration '${credentialConfigurationId}' was replaced by a newer rulebook version`,
      );
    }
    return create();
  });
}

class CredentialSupersededError extends Error {}

/** Every served issuer with the credentials it currently serves, static and imported. */
async function issuerCredentialGroups(
  config: AppConfig,
  store: CaptureStore,
): Promise<IssuerCredentialGroup[]> {
  const registry = await issuerCredentialRegistry(config, store);
  return resolvedIssuerConfigurations(config).map((issuer) => ({
    issuer,
    credentials: registry.credentialsForIssuer(issuer),
    ...(issuer.importsAttestbookCredentials
      ? { attestbook: attestbookIntegration(config, store).summary() }
      : {}),
  }));
}

type CreateVpSessionOptions = {
  requestOverride: JsonRecord;
  credentialConfigurationIds?: string[];
  requestUriMethod?: string;
  responseMode?: OpenId4VpResponseMode;
  requestDelivery?: VpRequestDelivery;
  deeplinkScheme?: string;
  redirectUri?: string;
  captureRedirect?: boolean;
  clientMetadata?: JsonRecord | null;
  clientIdScheme?: OpenId4VpClientIdScheme;
  allowUndecryptableResponse?: boolean;
  requestMutation?: VpRequestMutation;
  requestBehavior?: VpRequestBehavior;
  responseScenario?: VpResponseScenario;
  verifierAttestation?: VpVerifierAttestation;
};

type RecordVpSessionStateOptions = {
  store: CaptureStore;
  session: VpSessionCapture;
  credoSession: CredoVpSession;
  captureRedirect: boolean;
  sessionRedirectUri?: string;
  requestBehavior?: VpRequestBehavior;
  requestSigningMaterial?: RequestSigningMaterial;
  responseScenario?: VpResponseScenario;
  requestMutation?: VpRequestMutation;
};

async function createVpSession(
  config: AppConfig,
  store: CaptureStore,
  {
    requestOverride,
    credentialConfigurationIds,
    requestUriMethod = "get",
    responseMode = "direct_post.jwt",
    requestDelivery = "by_reference",
    deeplinkScheme = "openid4vp://",
    redirectUri,
    captureRedirect = false,
    clientMetadata,
    clientIdScheme = "x509_hash",
    allowUndecryptableResponse = false,
    requestMutation,
    requestBehavior,
    responseScenario,
    verifierAttestation,
  }: CreateVpSessionOptions,
): Promise<VpSessionCapture> {
  const sessionId = randomUUID();
  const defaultRequest = defaultPresentationRequest(
    config,
    credentialConfigurationIds,
    responseMode,
  );
  const sessionRedirectUri = redirectUri ? redirectUriWithResponseCode(redirectUri) : undefined;
  const request = {
    ...defaultRequest,
    ...requestOverride,
    response_mode: responseMode,
  };
  const requestSigningMaterial = await requestSigningMaterialOrUndefined(config, requestBehavior);
  const credoVerifier = await credoOpenId4VpVerifier(config);
  const credoSession = await credoVerifier.createSession(
    sessionId,
    request,
    defaultRequest.dcql_query as JsonRecord,
    requestUriMethod,
    requestDelivery,
    deeplinkScheme,
    clientMetadata,
    clientIdScheme,
    allowUndecryptableResponse,
    requestMutation,
    requestBehavior,
    requestSigningMaterial,
    verifierAttestation,
  );
  const dcApi =
    credoSession.dcApiRequest && credoSession.expectedOrigin
      ? {
          request: credoSession.dcApiRequest,
          expected_origin: credoSession.expectedOrigin,
          expires_at: dcApiPresentationExpiresAt(),
        }
      : undefined;
  const session = store.createVpSession(
    sessionId,
    credoSession.authorizationRequest,
    requestDelivery,
    requestUriMethod,
    responseMode,
    deeplinkScheme,
    sessionRedirectUri,
    {
      requestUri: credoSession.requestUri,
      responseUri: credoSession.responseUri,
    },
    dcApi,
  );
  recordVpSessionState({
    store,
    session,
    credoSession,
    captureRedirect,
    sessionRedirectUri,
    requestBehavior,
    requestSigningMaterial,
    responseScenario,
    requestMutation,
  });
  session.deeplink = credoSession.deeplink;
  return session;
}

function recordVpSessionState({
  store,
  session,
  credoSession,
  captureRedirect,
  sessionRedirectUri,
  requestBehavior,
  requestSigningMaterial,
  responseScenario,
  requestMutation,
}: RecordVpSessionStateOptions): void {
  const responseCode = sessionRedirectUri ? responseCodeFromRedirectUri(sessionRedirectUri) : null;
  if (captureRedirect && responseCode) {
    store.linkVpRedirectResponseCode(session.session_id, responseCode);
  }
  store.vpCredoVerificationSessionIds.set(session.session_id, credoSession.verificationSessionId);
  if (credoSession.deliveredAuthorizationRequestJwt) {
    store.vpCredoAuthorizationRequestJwts.set(
      session.session_id,
      credoSession.deliveredAuthorizationRequestJwt,
    );
  }
  if (
    isEncryptedResponseMode(session.response_mode) &&
    !credoSession.verifierEncryptionKeyPublished
  ) {
    store.addEvent(session, "vp_undecryptable_response_allowed", {
      verifier_encryption_key_published: false,
    });
  }
  if (requestBehavior) {
    session.request_behavior = requestBehavior;
    store.addEvent(session, "vp_request_behavior_applied", { ...requestBehavior });
  }
  if (requestSigningMaterial) {
    store.vpRequestSigningMaterial.set(session.session_id, requestSigningMaterial);
  }
  store.vpDeliveredRequestRecipes.set(session.session_id, credoSession.deliveredRequestRecipe);
  if (responseScenario) {
    session.response_scenario = responseScenario;
    store.addEvent(session, "vp_response_scenario_selected", { ...responseScenario });
  }
  if (credoSession.verifierAttestation) {
    session.verifier_attestation = credoSession.verifierAttestation;
  }
  session.raw ??= {};
  session.raw.outer_request_delivered = credoSession.outerRequest;
  if (requestMutation) {
    session.request_mutation = requestMutation;
    session.raw.authorization_request_delivered = credoSession.deliveredAuthorizationRequest;
    store.addEvent(session, "vp_request_mutation_applied", {
      pointers: requestMutationPointers(requestMutation),
      verification_applies: requestMutation.verification_applies ?? null,
    });
  }
}

/**
 * Resolves the key, and chain, a session's Request Object is signed with. `signing_key` keeps the
 * real certificate and changes only the key, so the mismatch between them is the single defect;
 * `certificate_chain` generates a chain and signs with its leaf key, so the chain is. Its
 * `with_trust_anchor` value keeps the real key and leaf and appends the configured CA certificate,
 * so the trust anchor's presence in `x5c` is.
 */
async function requestSigningMaterialOrUndefined(
  config: AppConfig,
  behavior: VpRequestBehavior | undefined,
): Promise<RequestSigningMaterial | undefined> {
  if (behavior?.certificate_chain === "with_trust_anchor") {
    return verifierChainWithTrustAnchor(config);
  }
  if (behavior?.certificate_chain) {
    return generateRequestCertificateMaterial(behavior.certificate_chain);
  }
  if (behavior?.signing_key === "unrelated") return generateUnrelatedSigningKey();
  return undefined;
}

function redirectUriWithResponseCode(redirectUri: string): string {
  const url = new URL(redirectUri);
  url.searchParams.append("response_code", randomBytes(16).toString("base64url"));
  return url.toString();
}

function redirectResponseCodeMatches(
  redirectUri: string | undefined,
  responseCode: string,
): boolean {
  if (!redirectUri) return false;
  const expectedResponseCode = responseCodeFromRedirectUri(redirectUri);
  if (!expectedResponseCode || expectedResponseCode.length !== responseCode.length) return false;
  return timingSafeEqual(Buffer.from(expectedResponseCode), Buffer.from(responseCode));
}

function responseCodeFromRedirectUri(redirectUri: string): string | null {
  return new URL(redirectUri).searchParams.get("response_code");
}

function redirectUriVisitHttpCapture(req: Request): RedirectUriVisitHttpCapture {
  return {
    method: req.method,
    headers: redactHttpHeaders(req.headers),
  };
}

function dcApiInvocationOutcomeOrNull(value: unknown): VpDcApiInvocationOutcome | null {
  return value === "api_unavailable" ||
    value === "rejected" ||
    value === "no_vp_token" ||
    value === "failed"
    ? value
    : null;
}
