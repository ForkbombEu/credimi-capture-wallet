import { existsSync } from "node:fs";
import { verifierCaCertificatePath } from "../config/paths.js";
import { requestBehaviorOrNull } from "../fcaf/request-behavior.js";
import { requestMutationOrNull } from "../fcaf/request-mutation.js";
import { responseScenarioOrNull } from "../fcaf/response-scenario.js";
import {
  type OpenId4VpClientIdScheme,
  type OpenId4VpResponseMode,
  isDcApiResponseMode,
  isEncryptedResponseMode,
  isOpenId4VpResponseMode,
} from "../openid4vp/authorization-request.js";
import { credoOpenId4VpVerifier } from "../openid4vp/credo-verifier.js";
import { verifierChainWithTrustAnchor } from "../openid4vp/request-certificates.js";
import { RESPONSE_URI_PLACEHOLDER } from "../openid4vp/verifier-attestation.js";
import { errorMessage } from "../shared/errors.js";
import { asRecord, booleanOrNull } from "../shared/json.js";
import type {
  AppConfig,
  JsonRecord,
  VpRequestBehavior,
  VpRequestDelivery,
  VpRequestMutation,
  VpResponseScenario,
  VpSessionCapture,
  VpVerifierAttestation,
} from "../types.js";

export const VP_REQUEST_DELIVERIES: VpRequestDelivery[] = [
  "by_reference",
  "by_value",
  "plain",
  "multisigned",
];

export const VP_CLIENT_ID_SCHEMES: OpenId4VpClientIdScheme[] = [
  "x509_hash",
  "x509_san_dns",
  "decentralized_identifier",
  "verifier_attestation",
  "redirect_uri",
];

const CAPTURE_REDIRECT_URI_TEMPLATE = "{{base_url}}/openid4vp/redirect";

type VpInputRejection = { ok: false; status: 400; body: JsonRecord };
type CheckResult<T> = { ok: true; value: T } | VpInputRejection;

type ParsedVpSessionInput = {
  body: JsonRecord;
  requestUriMethod: string | null;
  requestDelivery: VpRequestDelivery | null;
  clientIdScheme: OpenId4VpClientIdScheme | null;
  responseMode: OpenId4VpResponseMode | null;
  deeplinkScheme: string | null;
  redirectUri: { value: string; capture?: true } | null;
  clientMetadata?: JsonRecord | null;
  allowUndecryptableResponse: boolean;
  requestMutation?: VpRequestMutation;
  requestBehavior?: VpRequestBehavior;
  verifierAttestation?: VpVerifierAttestation;
  responseScenario?: VpResponseScenario;
};

type VpDeliveryOptions = Pick<
  ParsedVpSessionInput,
  "requestUriMethod" | "requestDelivery" | "clientIdScheme" | "responseMode"
>;
type VpPresentationOptions = Pick<
  ParsedVpSessionInput,
  "deeplinkScheme" | "redirectUri" | "clientMetadata" | "allowUndecryptableResponse"
>;

export type VpSessionOptions = ParsedVpSessionInput & {
  selectedResponseMode: OpenId4VpResponseMode;
  selectedClientIdScheme: OpenId4VpClientIdScheme;
  dcApi: boolean;
  selectedRequestDelivery: VpRequestDelivery;
};

export function parseVpSessionInput(
  config: AppConfig,
  body: JsonRecord,
): CheckResult<ParsedVpSessionInput> {
  const deliveryOptions = parseVpDeliveryOptions(body);
  if (!deliveryOptions.ok) return deliveryOptions;
  const presentationOptions = parseVpPresentationOptions(config, body);
  if (!presentationOptions.ok) return presentationOptions;
  const scenarioOptions = parseVpScenarioOptions(config, body);
  if (!scenarioOptions.ok) return scenarioOptions;
  return {
    ok: true,
    value: {
      body,
      ...deliveryOptions.value,
      ...presentationOptions.value,
      ...scenarioOptions.value,
    },
  };
}

function parseVpDeliveryOptions(body: JsonRecord): CheckResult<VpDeliveryOptions> {
  const requestUriMethod = requestUriMethodOrNull(body.request_uri_method);
  if (body.request_uri_method !== undefined && !requestUriMethod) {
    return rejection("unsupported_request_uri_method");
  }
  const requestDelivery = requestDeliveryOrNull(body.request_delivery);
  if (body.request_delivery !== undefined && !requestDelivery) {
    return rejection("unsupported_request_delivery");
  }
  const clientIdScheme = clientIdSchemeOrNull(body.client_id_scheme);
  if (body.client_id_scheme !== undefined && !clientIdScheme) {
    return rejection("unsupported_client_id_scheme");
  }
  if (requestDelivery && requestDelivery !== "by_reference" && requestUriMethod) {
    return rejection("request_uri_method_requires_by_reference_delivery");
  }
  const responseMode = responseModeOrNull(body.response_mode);
  if (body.response_mode !== undefined && !responseMode) {
    return rejection("unsupported_response_mode");
  }
  return { ok: true, value: { requestUriMethod, requestDelivery, clientIdScheme, responseMode } };
}

function parseVpPresentationOptions(
  config: AppConfig,
  body: JsonRecord,
): CheckResult<VpPresentationOptions> {
  const deeplinkScheme = deeplinkSchemeOrNull(body.scheme);
  if (body.scheme !== undefined && !deeplinkScheme) {
    return rejection("invalid_deeplink_scheme");
  }
  const redirectUri = responseRedirectUriInputOrNull(body.redirect_uri, config);
  if (body.redirect_uri !== undefined && !redirectUri) {
    return rejection("invalid_redirect_uri");
  }
  const clientMetadata = clientMetadataOrNull(body.client_metadata);
  if (body.client_metadata !== undefined && clientMetadata === undefined) {
    return rejection("invalid_client_metadata");
  }
  const allowUndecryptableResponse = booleanOrNull(body.allow_undecryptable_response ?? false);
  if (allowUndecryptableResponse === null) {
    return rejection("invalid_allow_undecryptable_response");
  }
  return {
    ok: true,
    value: { deeplinkScheme, redirectUri, clientMetadata, allowUndecryptableResponse },
  };
}

function parseVpScenarioOptions(
  config: AppConfig,
  body: JsonRecord,
): CheckResult<
  Pick<
    ParsedVpSessionInput,
    "requestMutation" | "requestBehavior" | "verifierAttestation" | "responseScenario"
  >
> {
  const requestOptions = parseVpRequestScenarios(config, body);
  if (!requestOptions.ok) return requestOptions;
  const responseOptions = parseVpResponseScenarios(config, body);
  if (!responseOptions.ok) return responseOptions;
  return { ok: true, value: { ...requestOptions.value, ...responseOptions.value } };
}

function parseVpRequestScenarios(
  config: AppConfig,
  body: JsonRecord,
): CheckResult<Pick<ParsedVpSessionInput, "requestMutation" | "requestBehavior">> {
  const requestMutation = requestMutationOrNull(body.request_mutation);
  if (requestMutation === null) {
    return rejection("invalid_request_mutation");
  }
  if (requestMutation && !config.fcaf_scenarios_enabled) {
    return rejection("request_mutation_not_enabled");
  }
  const requestBehavior = requestBehaviorOrNull(body.request_behavior);
  if (requestBehavior === null) {
    return rejection("invalid_request_behavior");
  }
  if (requestBehavior && !config.fcaf_scenarios_enabled) {
    return rejection("request_behavior_not_enabled");
  }
  return { ok: true, value: { requestMutation, requestBehavior } };
}

function parseVpResponseScenarios(
  config: AppConfig,
  body: JsonRecord,
): CheckResult<Pick<ParsedVpSessionInput, "verifierAttestation" | "responseScenario">> {
  const verifierAttestation = verifierAttestationOrNull(body.verifier_attestation);
  if (verifierAttestation === null) {
    return rejection("invalid_verifier_attestation");
  }
  if (verifierAttestation?.signature && !config.fcaf_scenarios_enabled) {
    return rejection("request_behavior_not_enabled");
  }
  const responseScenario = responseScenarioOrNull(body.response_scenario);
  if (responseScenario === null) {
    return rejection("invalid_response_scenario");
  }
  if (responseScenario && !config.fcaf_scenarios_enabled) {
    return rejection("response_scenario_not_enabled");
  }
  return { ok: true, value: { verifierAttestation, responseScenario } };
}

export function deriveVpSessionOptions(input: ParsedVpSessionInput): VpSessionOptions {
  const selectedResponseMode = input.responseMode ?? "direct_post.jwt";
  const selectedClientIdScheme = input.clientIdScheme ?? "x509_hash";
  const dcApi = isDcApiResponseMode(selectedResponseMode);
  return {
    ...input,
    selectedResponseMode,
    selectedClientIdScheme,
    dcApi,
    selectedRequestDelivery: input.requestDelivery ?? (dcApi ? "by_value" : "by_reference"),
  };
}

export async function validateVpSessionCombination(
  config: AppConfig,
  options: VpSessionOptions,
): Promise<VpInputRejection | undefined> {
  const deliveryError = validateDeliveryCombination(options);
  if (deliveryError) return deliveryError;
  const signatureError = await validateSignatureCombination(config, options);
  if (signatureError) return signatureError;
  const attestationError = validateAttestationCombination(options);
  if (attestationError) return attestationError;
  const multisignedError = validateMultisigned(options);
  if (multisignedError) return multisignedError;
  return validateEncryptionCombination(options);
}

function validateDeliveryCombination(options: VpSessionOptions): VpInputRejection | undefined {
  if (options.dcApi && options.selectedRequestDelivery === "by_reference") {
    return rejection("request_delivery_unsupported_for_dc_api");
  }
  if (options.dcApi && options.selectedClientIdScheme === "redirect_uri") {
    return rejection("client_id_scheme_unsupported_for_dc_api");
  }
  if (options.dcApi && options.requestUriMethod) {
    return rejection("request_uri_method_unsupported_for_dc_api");
  }
  if (options.dcApi && options.redirectUri) {
    return rejection("redirect_uri_unsupported_for_dc_api");
  }
  if (
    options.dcApi &&
    options.verifierAttestation?.redirect_uris?.includes(RESPONSE_URI_PLACEHOLDER)
  ) {
    return rejection("response_uri_placeholder_unsupported_for_dc_api");
  }
  return undefined;
}

async function validateSignatureCombination(
  config: AppConfig,
  options: VpSessionOptions,
): Promise<VpInputRejection | undefined> {
  if (
    options.requestBehavior?.signature === "corrupt" &&
    options.selectedClientIdScheme === "redirect_uri"
  ) {
    return rejection("signature_behavior_requires_a_signed_request");
  }
  if (
    (options.requestBehavior?.signing_key || options.requestBehavior?.certificate_chain) &&
    options.selectedClientIdScheme === "redirect_uri"
  ) {
    return rejection("signature_behavior_requires_a_signed_request");
  }
  if (
    options.requestBehavior?.certificate_chain &&
    options.selectedClientIdScheme !== "x509_hash"
  ) {
    return rejection("certificate_chain_requires_x509_hash_client_id");
  }
  if (options.requestBehavior?.certificate_chain === "with_trust_anchor") {
    return validateTrustAnchor(config);
  }
  return undefined;
}

function validateAttestationCombination(options: VpSessionOptions): VpInputRejection | undefined {
  if (options.verifierAttestation && options.selectedClientIdScheme !== "verifier_attestation") {
    return rejection("verifier_attestation_requires_verifier_attestation_client_id");
  }
  if (
    options.selectedClientIdScheme === "redirect_uri" &&
    options.selectedRequestDelivery !== "plain"
  ) {
    return rejection("redirect_uri_client_id_requires_plain_delivery");
  }
  return undefined;
}

function validateEncryptionCombination(options: VpSessionOptions): VpInputRejection | undefined {
  if (options.clientMetadata === null && isEncryptedResponseMode(options.selectedResponseMode)) {
    return rejection("client_metadata_required_for_encrypted_response");
  }
  if (options.allowUndecryptableResponse && !options.clientMetadata) {
    return rejection("allow_undecryptable_response_requires_client_metadata");
  }
  return undefined;
}

export function parseVpRequestOverride(options: VpSessionOptions): CheckResult<JsonRecord> {
  const requestOverride: JsonRecord = {
    ...(asRecord(options.body.presentation_request) ?? vpRequestBody(options.body)),
    ...(options.body.response_type !== undefined
      ? { response_type: options.body.response_type }
      : {}),
  };
  // `state` is generated per request; a caller may only ask for it to be omitted.
  if (requestOverride.state !== undefined && requestOverride.state !== null) {
    return rejection("invalid_state");
  }
  // Appendix A.3.2.2 binds `verifier_info` to one signature's Client Identifier, and a
  // caller-supplied attestation names only one of the two this request is signed under.
  if (
    options.selectedRequestDelivery === "multisigned" &&
    requestOverride.verifier_info !== undefined
  ) {
    return rejection("verifier_info_unsupported_for_multisigned");
  }
  return { ok: true, value: requestOverride };
}

export function serializeVpSession(session: VpSessionCapture): JsonRecord {
  return {
    session_id: session.session_id,
    request_delivery: session.request_delivery,
    ...(session.request_uri === undefined ? {} : { request_uri: session.request_uri }),
    ...(session.request_uri_method === undefined
      ? {}
      : { request_uri_method: session.request_uri_method }),
    response_mode: session.response_mode,
    ...(session.deeplink_scheme === undefined ? {} : { scheme: session.deeplink_scheme }),
    ...(session.response_uri === undefined ? {} : { response_uri: session.response_uri }),
    ...(session.redirect_uri ? { redirect_uri: session.redirect_uri } : {}),
    deeplink: session.deeplink,
    ...(session.dc_api ? { dc_api_request: session.dc_api.request } : {}),
    authorization_request: session.authorization_request,
    status: session.status,
  };
}

async function validateTrustAnchor(config: AppConfig): Promise<VpInputRejection | undefined> {
  if (!existsSync(verifierCaCertificatePath(config.data_dir))) {
    return rejection(
      "verifier_ca_certificate_not_configured",
      "certificate_chain with_trust_anchor needs the CA certificate at verifier/verifier-ca-certificate.pem in the data directory",
    );
  }
  const chainError = await trustAnchorChainError(config);
  return chainError ? rejection("verifier_ca_certificate_invalid", chainError) : undefined;
}

/**
 * `with_trust_anchor` must add exactly one defect, the anchor in `x5c`. A configured CA that did
 * not issue the deployed verifier certificate would also break the chain, and a Wallet could then
 * reject the request for that reason instead, so the chain is validated with Credo first.
 */
async function trustAnchorChainError(config: AppConfig): Promise<string | undefined> {
  let chain: string[];
  try {
    chain = verifierChainWithTrustAnchor(config).x5c ?? [];
  } catch (error) {
    return `verifier/verifier-ca-certificate.pem is not a parseable certificate: ${errorMessage(error)}`;
  }
  const reason = await (await credoOpenId4VpVerifier(config)).certificateChainError(chain);
  return reason === undefined
    ? undefined
    : `the configured CA certificate does not validate the deployed verifier certificate: ${reason}`;
}

function validateMultisigned(options: VpSessionOptions): VpInputRejection | undefined {
  if (options.selectedRequestDelivery !== "multisigned") return undefined;
  if (!options.dcApi) return rejection("multisigned_request_delivery_requires_dc_api");
  if (options.clientIdScheme && options.clientIdScheme !== "x509_hash") {
    return rejection("client_id_scheme_unsupported_for_multisigned");
  }
  if (
    options.requestBehavior?.signature ||
    options.requestBehavior?.signing_key ||
    options.requestBehavior?.certificate_chain ||
    options.requestMutation?.request_object_header ||
    options.verifierAttestation
  ) {
    return rejection("signature_behavior_unsupported_for_multisigned");
  }
  return undefined;
}

function rejection(error: string, errorDescription?: string): VpInputRejection {
  return {
    ok: false,
    status: 400,
    body: { error, ...(errorDescription ? { error_description: errorDescription } : {}) },
  };
}

function requestUriMethodOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function responseModeOrNull(value: unknown): OpenId4VpResponseMode | null {
  if (typeof value !== "string") return null;
  const normalized = value.toLowerCase();
  return isOpenId4VpResponseMode(normalized) ? normalized : null;
}

function requestDeliveryOrNull(value: unknown): VpRequestDelivery | null {
  if (typeof value !== "string") return null;
  const normalized = value.toLowerCase();
  return VP_REQUEST_DELIVERIES.find((delivery) => delivery === normalized) ?? null;
}

function clientIdSchemeOrNull(value: unknown): OpenId4VpClientIdScheme | null {
  return VP_CLIENT_ID_SCHEMES.find((scheme) => scheme === value) ?? null;
}

function responseRedirectUriInputOrNull(
  value: unknown,
  config: AppConfig,
): { value: string; capture?: true } | null {
  if (typeof value !== "string") return null;
  const captureRedirectUri = `${config.issuer_base_url}/openid4vp/redirect`;
  const redirectUri = value === CAPTURE_REDIRECT_URI_TEMPLATE ? captureRedirectUri : value;
  try {
    const url = new URL(redirectUri);
    const isCaptureRedirect = url.toString() === new URL(captureRedirectUri).toString();
    return url.protocol === "http:" || url.protocol === "https:"
      ? { value: url.toString(), ...(isCaptureRedirect ? { capture: true } : {}) }
      : null;
  } catch {
    return null;
  }
}

function clientMetadataOrNull(value: unknown): JsonRecord | null | undefined {
  if (value === null) return null;
  return asRecord(value) ?? undefined;
}

/**
 * Parses the Verifier Attestation content. Returning null refuses the request rather than signing
 * an attestation whose defect is not the one the caller asked for.
 */
function verifierAttestationOrNull(value: unknown): VpVerifierAttestation | null | undefined {
  if (value === undefined) return undefined;
  const attestation = asRecord(value);
  if (!attestation) return null;
  const { subject, issuer, redirect_uris, claims, signature, ...rest } = attestation;
  if (Object.keys(rest).length > 0) return null;
  if (subject !== undefined && typeof subject !== "string") return null;
  if (issuer !== undefined && typeof issuer !== "string") return null;
  if (
    redirect_uris !== undefined &&
    (!Array.isArray(redirect_uris) || redirect_uris.some((uri) => typeof uri !== "string"))
  ) {
    return null;
  }
  if (claims !== undefined && !asRecord(claims)) return null;
  if (signature !== undefined && signature !== "corrupt") return null;
  return {
    ...(subject === undefined ? {} : { subject }),
    ...(issuer === undefined ? {} : { issuer }),
    ...(redirect_uris === undefined ? {} : { redirect_uris: redirect_uris as string[] }),
    ...(claims === undefined ? {} : { claims: claims as JsonRecord }),
    ...(signature === undefined ? {} : { signature: "corrupt" as const }),
  };
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
    redirect_uri: _redirectUri,
    client_metadata: _clientMetadata,
    client_id_scheme: _clientIdScheme,
    scheme: _scheme,
    allow_undecryptable_response: _allowUndecryptableResponse,
    request_mutation: _requestMutation,
    request_behavior: _requestBehavior,
    response_scenario: _responseScenario,
    ...request
  } = body;
  return request;
}
