import { readFileSync } from "node:fs";
import type { Express } from "express";
import QRCode from "qrcode";
import { attestbookIntegration } from "../../attestbook/integration.js";
import { resolvedIssuerConfigurations } from "../../configurations/registry.js";
import { PID_FIXTURE_IDS } from "../../configurations/shared/pid-fixtures.js";
import { supportedCredentialConfigurationIds } from "../../credentials/catalogue.js";
import { SD_JWT_DIGEST_ALGORITHMS } from "../../credentials/digest-algorithm.js";
import {
  OPENID4VP_RESPONSE_MODE_VALUES,
  defaultDcqlQuery,
  isDcApiResponseMode,
} from "../../openid4vp/authorization-request.js";
import { asStringOrNull, booleanOrNull } from "../../shared/json.js";
import type { CaptureStore } from "../../state.js";
import { STATUS_REFERENCE_FIXTURES } from "../../status-list/reference-fixtures.js";
import type { AppConfig } from "../../types.js";
import { issuerPage } from "../../ui/issuer.js";
import {
  type IssuerCredentialChoices,
  type IssuerCredentialGroup,
  VERIFIER_PAGE_PATH,
  indexPage,
} from "../../ui/launcher.js";
import {
  credentialOfferEngagementPage,
  dcApiPresentationPage,
  errorPage,
  helpPage,
  sessionPage,
  vpSessionPage,
} from "../../ui/session.js";
import { verifierPage } from "../../ui/verifier.js";
import { type ServerContext, requestParams } from "../context.js";
import {
  CREDENTIAL_OFFER_MODES,
  DEFAULT_OFFER_SCHEME,
  EVIDENCE_MODES,
  ISSUANCE_FLOWS,
  OFFER_SCHEMES,
  issuerCredentialRegistry,
  issuerFromRequest,
} from "../issuance-session-input.js";
import { createIssuanceSession } from "../issuance-session.js";
import { VP_CLIENT_ID_SCHEMES, VP_REQUEST_DELIVERIES } from "../presentation-session-input.js";
import { createVpSession } from "../presentation-session.js";
import { vpPresentationCaptured } from "../vp-submission.js";

export function registerUiRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;
  if (!config.gui_enabled) return;

  app.get("/", async (_req, res, next) => {
    try {
      res.type("html").send(indexPage(await issuerCredentialChoices(config, store)));
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
      res.type("html").send(
        verifierPage({
          groups: await issuerCredentialChoices(config, store),
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
    res.type("image/svg+xml").send(readFileSync("src/design/logo/credimi_logo-transp.svg", "utf8"));
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
      const supportedIds = registry.credentialsForIssuer(issuer).map((credential) => credential.id);
      const credentialConfigurationId =
        asStringOrNull(body.credential_configuration_id) ?? supportedIds[0];
      const credential = credentialConfigurationId
        ? registry.credentialById(issuer, credentialConfigurationId)
        : null;
      if (!credentialConfigurationId || !credential) {
        return res.status(400).type("html").send(errorPage("Unsupported credential configuration"));
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
        return res.status(400).type("html").send(errorPage("Unsupported credential configuration"));
      }

      const session = await createVpSession(config, store, {
        requestOverride: {},
        credentialConfigurationIds: [credentialConfigurationId],
      });
      store.addEvent(session, "vp_deeplink_generated", {});
      return res.redirect(303, `/ui/openid4vp/sessions/${encodeURIComponent(session.session_id)}`);
    } catch (error) {
      return next(error);
    }
  });

  app.get("/ui/sessions/:sessionId", async (req, res, next) => {
    try {
      const session = store.getSession(req.params.sessionId);
      if (!session) return res.status(404).type("html").send(errorPage("Session not found"));
      const offer = store.credoIssuanceOffers.get(session.session_id);
      if (!offer) return res.status(409).type("html").send(errorPage("Credential offer not ready"));
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
      if (!offer) return res.status(409).type("html").send(errorPage("Credential offer not ready"));
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

/** The same issuers, each credential paired with the DCQL query that requests it. */
async function issuerCredentialChoices(
  config: AppConfig,
  store: CaptureStore,
): Promise<IssuerCredentialChoices[]> {
  return (await issuerCredentialGroups(config, store)).map((group) => ({
    ...group,
    credentials: group.credentials.map((credential) => ({
      credential,
      dcqlQuery: defaultDcqlQuery([credential]),
    })),
  }));
}
