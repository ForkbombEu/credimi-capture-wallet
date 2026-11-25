import type { Express } from "express";
import { revokeStatusListReference } from "../../status-list/allocation.js";
import type { StatusListUpdateCapture } from "../../types.js";
import { type ServerContext, requestParams } from "../context.js";
import { parseIssuanceSessionInput } from "../issuance-session-input.js";
import { CredentialSupersededError, createIssuanceSession } from "../issuance-session.js";

export function registerIssuanceRoutes(app: Express, ctx: ServerContext): void {
  const { config, store } = ctx;

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
}
