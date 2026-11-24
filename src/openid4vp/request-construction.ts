import { JsonEncoder } from "@credo-ts/core";
import { type JWK, calculateJwkThumbprint } from "jose";
import { corruptJwsSignature } from "../fcaf/request-behavior.js";
import { applyRequestMutationEdits } from "../fcaf/request-mutation.js";
import { asRecord } from "../shared/json.js";
import type {
  AppConfig,
  JsonRecord,
  OpenId4VpResponseMode,
  RequestSigningMaterial,
  VpDcApiRequest,
  VpRequestBehavior,
  VpRequestDelivery,
  VpRequestMutation,
} from "../types.js";
import {
  type OpenId4VpClientIdScheme,
  type VpDeliveredRequestRecipe,
  dcApiPresentationUrl,
  deliveredAuthorizationRequest,
  isEncryptedResponseMode,
  isOpenId4VpResponseMode,
  signPresentationAuthorizationRequest,
} from "./authorization-request.js";

export class ResponseModeError extends Error {}

export class ClientMetadataError extends Error {}

interface AuthorizationRequestConstruction {
  authorizationRequest: JsonRecord;
  verifierEncryptionKeyPublished: boolean;
  omitDcqlFromDelivery: boolean;
}

export async function authorizationRequestForVerifier(
  requestPayload: JsonRecord,
  request: JsonRecord,
  responseMode: OpenId4VpResponseMode,
  dcApi: boolean,
  clientMetadata: JsonRecord | null | undefined,
  allowUndecryptableResponse: boolean,
): Promise<AuthorizationRequestConstruction> {
  const {
    dcql_query: generatedDcqlQuery,
    state: generatedState,
    ...createdAuthorizationRequest
  } = requestPayload;
  // Section 5.1 makes `state` optional outside the Section 5.3 conditions. It is dropped from
  // the request the verifier holds, not only from the delivered copy, so Credo stops expecting
  // it back; the Section 5.3 consequence is enforced when the response is verified.
  const omitState = request.state === null;
  // Section 5.1 lets a request carry a `scope` representing a DCQL Query instead of the query
  // itself. The query is dropped from the delivered copy only: the verifier keeps it, because
  // Credo matches the Authorization Response against the request object this service signs, and
  // a scope value is resolved by the wallet's profile rather than by anything sent on the wire.
  const omitDcqlFromDelivery = request.dcql_query === null;
  const authorizationRequest: JsonRecord = {
    ...createdAuthorizationRequest,
    ...(omitState || generatedState === undefined ? {} : { state: generatedState }),
    dcql_query: omitDcqlFromDelivery ? generatedDcqlQuery : request.dcql_query,
    ...(request.nonce !== undefined ? { nonce: request.nonce } : {}),
    ...optionalAuthorizationRequestParameters(request),
  };
  // The request object Credo produces carries the JAR audience `https://self-issued.me/v2`,
  // which Section 5.8 defines for discovery-based delivery. Appendix A.2 does not list `aud`
  // among the parameters supported over the DC API, so it is dropped there rather than sent as
  // an undefined claim to a HAIP-strict wallet.
  if (dcApi) authorizationRequest.aud = undefined;
  const generatedClientMetadata = authorizationRequest.client_metadata;
  const shaped = await applyClientMetadata(
    authorizationRequest,
    generatedClientMetadata,
    clientMetadata,
  );
  if (
    isEncryptedResponseMode(responseMode) &&
    !allowUndecryptableResponse &&
    !shaped.verifierEncryptionKeyPublished
  ) {
    throw new ClientMetadataError(
      `client_metadata must retain the verifier encryption public key for ${responseMode}`,
    );
  }
  return { ...shaped, omitDcqlFromDelivery };
}

async function applyClientMetadata(
  authorizationRequest: JsonRecord,
  generatedClientMetadata: unknown,
  clientMetadata: JsonRecord | null | undefined,
): Promise<{ authorizationRequest: JsonRecord; verifierEncryptionKeyPublished: boolean }> {
  const shaped = { ...authorizationRequest };
  if (clientMetadata === null) {
    shaped.client_metadata = undefined;
  } else if (clientMetadata) {
    shaped.client_metadata = mergeClientMetadata(asRecord(generatedClientMetadata), clientMetadata);
  }
  return {
    authorizationRequest: shaped,
    verifierEncryptionKeyPublished: await containsVerifierEncryptionKey(
      asRecord(shaped.client_metadata),
      generatedClientMetadata,
    ),
  };
}

interface SignedDeliveryPlan {
  deliveredAuthorizationRequest: JsonRecord;
  deliveredAuthorizationRequestJwt?: string;
  deliveredRequestRecipe: VpDeliveredRequestRecipe;
}

function requestSigningOptions(
  requestMutation: VpRequestMutation | undefined,
  requestSigningMaterial: RequestSigningMaterial | undefined,
  verifierAttestationJwt: string | undefined,
): {
  headerEdits?: VpRequestMutation["request_object_header"];
  material?: RequestSigningMaterial;
  verifierAttestationJwt?: string;
} {
  return {
    ...(requestMutation?.request_object_header
      ? { headerEdits: requestMutation.request_object_header }
      : {}),
    ...(requestSigningMaterial ? { material: requestSigningMaterial } : {}),
    ...(verifierAttestationJwt ? { verifierAttestationJwt } : {}),
  };
}

export async function signedDeliveryPlan(
  config: AppConfig,
  authorizationRequest: JsonRecord,
  authorizationRequestJwt: string | undefined,
  signer: Exclude<OpenId4VpClientIdScheme, "redirect_uri"> | undefined,
  verifierAttestationJwt: string | undefined,
  deliveredClientId: string | undefined,
  requestMutation: VpRequestMutation | undefined,
  requestBehavior: VpRequestBehavior | undefined,
  requestSigningMaterial: RequestSigningMaterial | undefined,
  omitDcqlFromDelivery: boolean,
): Promise<SignedDeliveryPlan> {
  const deliveredRequestRecipe: VpDeliveredRequestRecipe = {
    ...(signer
      ? {
          signer: {
            clientIdScheme: signer,
            ...(verifierAttestationJwt ? { verifierAttestationJwt } : {}),
          },
        }
      : {}),
    omitDcqlQuery: omitDcqlFromDelivery,
    ...(deliveredClientId ? { clientId: deliveredClientId } : {}),
  };
  // Mutations are applied here, after every internal check: `authorizationRequest` stays the
  // message this service generated and verifies against, `deliveredRequest` is the copy the
  // wallet receives. Both are signed separately because Credo derives the nonce, state, and
  // client identifier it expects in the Authorization Response from the Request Object JWT it
  // holds — handing it the mutated one would move the verifier's own expectations with it.
  const deliveredRequest = deliveredAuthorizationRequest(
    authorizationRequest,
    deliveredRequestRecipe,
    requestMutation?.request_object,
  );
  const mutatesRequestObject = Boolean(
    requestMutation?.request_object ?? requestMutation?.request_object_header,
  );
  const signedDeliveredRequest =
    signer && (mutatesRequestObject || requestSigningMaterial || omitDcqlFromDelivery)
      ? await signPresentationAuthorizationRequest(
          config,
          deliveredRequest,
          signer,
          requestSigningOptions(requestMutation, requestSigningMaterial, verifierAttestationJwt),
        )
      : authorizationRequestJwt;
  const deliveredAuthorizationRequestJwt =
    signedDeliveredRequest && requestBehavior?.signature === "corrupt"
      ? corruptJwsSignature(signedDeliveredRequest)
      : signedDeliveredRequest;
  return {
    deliveredAuthorizationRequest: deliveredRequest,
    deliveredAuthorizationRequestJwt,
    deliveredRequestRecipe,
  };
}

export function requestEnvelope(
  config: AppConfig,
  sessionId: string,
  deliveredAuthorizationRequest: JsonRecord,
  deliveredAuthorizationRequestJwt: string | undefined,
  requestDelivery: VpRequestDelivery,
  requestUri: string | undefined,
  requestUriMethod: string,
  deeplinkScheme: string,
  dcApi: boolean,
  requestMutation: VpRequestMutation | undefined,
  multiSignedRequest: JsonRecord | undefined,
): { outerRequest: JsonRecord; deeplink: string; dcApiRequest?: VpDcApiRequest } {
  const outerRequest = applyRequestMutationEdits(
    dcApi
      ? dcApiBrowserRequest(
          deliveredAuthorizationRequest,
          deliveredAuthorizationRequestJwt,
          multiSignedRequest,
        ).data
      : outerRequestParameters(
          deliveredAuthorizationRequest,
          requestDelivery,
          requestUri ?? "",
          requestUriMethod,
          deliveredAuthorizationRequestJwt,
        ),
    requestMutation?.outer_request,
  );
  const deeplink = dcApi
    ? dcApiPresentationUrl(config, sessionId)
    : `${deeplinkScheme}?${outerRequestQuery(outerRequest)}`;
  return {
    outerRequest,
    deeplink,
    ...(dcApi
      ? {
          dcApiRequest: {
            ...dcApiBrowserRequest(
              deliveredAuthorizationRequest,
              deliveredAuthorizationRequestJwt,
              multiSignedRequest,
            ),
            data: outerRequest,
          },
        }
      : {}),
  };
}

/**
 * The outer Authorization Request: the parameters a wallet sees before it opens anything signed.
 * It is built as an object so that a mutation can address its members, and so a test can make the
 * outer value of a parameter disagree with the value inside the signed Request Object.
 */
function outerRequestParameters(
  authorizationRequest: JsonRecord,
  requestDelivery: VpRequestDelivery,
  requestUri: string,
  requestUriMethod: string,
  authorizationRequestJwt: string | undefined,
): JsonRecord {
  if (requestDelivery === "by_reference") {
    return {
      client_id: String(authorizationRequest.client_id),
      request_uri: requestUri,
      ...(requestUriMethod === "get" ? {} : { request_uri_method: requestUriMethod }),
    };
  }
  if (requestDelivery === "by_value") {
    return {
      client_id: String(authorizationRequest.client_id),
      request: authorizationRequestJwt ?? "",
    };
  }
  const parameters: JsonRecord = {};
  for (const [name, value] of Object.entries(authorizationRequest)) {
    if (name === "aud" || value === undefined) continue;
    parameters[name] = value;
  }
  return parameters;
}

function outerRequestQuery(parameters: JsonRecord): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(parameters)) {
    if (value === undefined) continue;
    query.set(name, typeof value === "string" ? value : JSON.stringify(value));
  }
  return query.toString();
}

/**
 * Caller-supplied `client_metadata` overrides individual members of the generated verifier
 * metadata: an omitted member keeps its generated value and a member set to `null` is dropped
 * from the wallet-facing request. The merge is one level deep, so supplying `jwks` replaces the
 * whole key set rather than editing individual JWK members.
 */
function mergeClientMetadata(generated: JsonRecord | null, overrides: JsonRecord): JsonRecord {
  const merged: JsonRecord = { ...generated };
  for (const [member, value] of Object.entries(overrides)) {
    if (value === null) delete merged[member];
    else merged[member] = value;
  }
  return merged;
}

/**
 * The wallet-facing `client_metadata` must still publish the verifier's own encryption public key,
 * because the service decrypts a `direct_post.jwt` response with the matching private key. Keys
 * are compared by RFC 7638 thumbprint, which covers the public key material only, so optional
 * JOSE members such as `alg`, `use`, and `kid` may be altered or omitted to build the malformed
 * requests that wallet response-encryption negative tests require.
 */
async function containsVerifierEncryptionKey(
  clientMetadata: JsonRecord | null,
  generatedClientMetadata: unknown,
): Promise<boolean> {
  const generatedKeys = asRecord(generatedClientMetadata)?.jwks;
  const clientKeys = asRecord(clientMetadata?.jwks)?.keys;
  const [generated, client] = await Promise.all([
    jwkThumbprints(asRecord(generatedKeys)?.keys),
    jwkThumbprints(clientKeys),
  ]);
  return client.some((thumbprint) => generated.includes(thumbprint));
}

async function jwkThumbprints(keys: unknown): Promise<string[]> {
  if (!Array.isArray(keys)) return [];
  const thumbprints = await Promise.all(keys.map(jwkThumbprintOrNull));
  return thumbprints.filter((thumbprint): thumbprint is string => thumbprint !== null);
}

async function jwkThumbprintOrNull(key: unknown): Promise<string | null> {
  const jwk = asRecord(key);
  if (!jwk) return null;
  return calculateJwkThumbprint(jwk as unknown as JWK, "sha256").catch(() => null);
}

/**
 * An omitted `response_mode` keeps the historical `direct_post.jwt` default. An unrecognised value
 * is rejected rather than collapsed into that default, so a mode the verifier cannot honour never
 * reaches the wallet as a different one.
 */
export function responseModeFromRequest(request: JsonRecord): OpenId4VpResponseMode {
  if (request.response_mode === undefined) return "direct_post.jwt";
  if (!isOpenId4VpResponseMode(request.response_mode)) {
    throw new ResponseModeError(
      `unsupported OpenID4VP response_mode '${String(request.response_mode)}'`,
    );
  }
  return request.response_mode;
}

/**
 * Appendix A.3: a signed request travels as a `request` JWS member, an unsigned one as the
 * Authorization Request parameters themselves. `client_id` and `expected_origins` are dropped from
 * the unsigned form, which Appendix A.2 requires a wallet to ignore there.
 */
function dcApiBrowserRequest(
  authorizationRequest: JsonRecord,
  authorizationRequestJwt: string | undefined,
  multiSignedRequest?: JsonRecord,
): VpDcApiRequest {
  if (multiSignedRequest) {
    return { protocol: "openid4vp-v1-multisigned", data: { request: multiSignedRequest } };
  }
  if (authorizationRequestJwt) {
    return { protocol: "openid4vp-v1-signed", data: { request: authorizationRequestJwt } };
  }
  const data: JsonRecord = {};
  for (const [name, value] of Object.entries(authorizationRequest)) {
    if (value === undefined || name === "client_id" || name === "expected_origins") continue;
    data[name] = value;
  }
  return { protocol: "openid4vp-v1-unsigned", data };
}

function optionalAuthorizationRequestParameters(request: JsonRecord): JsonRecord {
  const parameters: JsonRecord = {};
  if (request.response_type !== undefined) parameters.response_type = request.response_type;
  const scope = authorizationRequestScope(request);
  if (scope !== undefined) parameters.scope = scope;
  if (request.transaction_data !== undefined) {
    parameters.transaction_data = encodedTransactionData(request.transaction_data);
  }
  if (request.verifier_info !== undefined) parameters.verifier_info = request.verifier_info;
  return parameters;
}

/**
 * Section 5.1 carries each transaction data entry as a base64url-encoded JSON string. An entry
 * supplied as an object is encoded here so that a caller can express the defect a test is about —
 * an unknown field, a wrong field type, a mismatched `credential_ids` — inside an entry a Wallet
 * can still decode. Any other entry, a string included, is delivered exactly as supplied, which
 * keeps a deliberately undecodable entry expressible; `request_mutation` can replace the whole
 * parameter when even the array has to be malformed.
 */
function encodedTransactionData(transactionData: unknown): unknown {
  if (!Array.isArray(transactionData)) return transactionData;
  return transactionData.map((entry) =>
    entry !== null && typeof entry === "object" && !Array.isArray(entry)
      ? JsonEncoder.toBase64Url(entry)
      : entry,
  );
}

function authorizationRequestScope(request: JsonRecord): unknown {
  if (request.scope !== undefined) return request.scope;
  if (!Array.isArray(request.scopes)) return request.scopes;
  return request.scopes.map(String).join(" ");
}
