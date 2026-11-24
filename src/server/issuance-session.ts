import { attestbookIntegration } from "../attestbook/integration.js";
import type { AttestbookCredentialDefinition } from "../attestbook/types.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import { credentialRegistry } from "../credentials/registry.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import type { CaptureStore } from "../state.js";
import type {
  AppConfig,
  CredentialOfferMode,
  CredentialOfferScheme,
  EvidenceMode,
  SdJwtDigestAlgorithm,
  SessionCapture,
  StatusReferenceFixture,
  VpRequestMutationEdits,
} from "../types.js";
import { DEFAULT_OFFER_SCHEME } from "./issuance-session-input.js";

export async function createIssuanceSession(
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

export class CredentialSupersededError extends Error {}
