import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { requestMutationPointers } from "../fcaf/request-mutation.js";
import {
  type OpenId4VpClientIdScheme,
  type OpenId4VpResponseMode,
  dcApiPresentationExpiresAt,
  defaultPresentationRequest,
  isEncryptedResponseMode,
} from "../openid4vp/authorization-request.js";
import { credoOpenId4VpVerifier } from "../openid4vp/credo-verifier.js";
import type { CredoVpSession } from "../openid4vp/credo-verifier.js";
import {
  generateRequestCertificateMaterial,
  generateUnrelatedSigningKey,
  verifierChainWithTrustAnchor,
} from "../openid4vp/request-certificates.js";
import type { CaptureStore } from "../state.js";
import type {
  AppConfig,
  JsonRecord,
  RequestSigningMaterial,
  VpRequestBehavior,
  VpRequestDelivery,
  VpRequestMutation,
  VpResponseScenario,
  VpSessionCapture,
  VpVerifierAttestation,
} from "../types.js";

export async function createVpSession(
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

export function redirectResponseCodeMatches(
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
