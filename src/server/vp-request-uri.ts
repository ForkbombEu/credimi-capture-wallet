import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { corruptJwsSignature } from "../fcaf/request-behavior.js";
import { redactHttpHeaders } from "../openid4vci/http-capture.js";
import {
  deliveredAuthorizationRequest,
  signPresentationAuthorizationRequest,
} from "../openid4vp/authorization-request.js";
import { credoOpenId4VpVerifier } from "../openid4vp/credo-verifier.js";
import { requestSigningOptions } from "../openid4vp/request-construction.js";
import { negotiateRequestObjectEncryption } from "../openid4vp/request-object-encryption.js";
import type { CaptureStore } from "../state.js";
import type { AppConfig, JsonRecord, RequestUriHttpCapture, VpSessionCapture } from "../types.js";

export function recordWalletNonceRequest(
  store: CaptureStore,
  session: VpSessionCapture,
  body: JsonRecord,
  walletNonce: string | null,
): string | undefined {
  session.status = "request_retrieved";
  session.observed.request_uri_payload = {
    value: body,
    source: "request_uri.post",
    also_seen_in: [],
  };
  // OpenID4VP 5.10: the signed Request Object echoes the `wallet_nonce` the Wallet supplied.
  // A scenario may instead return a different one or omit it, which is what the Wallet is
  // expected to detect, so the value returned is recorded next to the value received.
  const walletNonceBehavior = session.request_behavior?.wallet_nonce ?? "echo";
  const returnedWalletNonce =
    !walletNonce || walletNonceBehavior === "omit"
      ? undefined
      : walletNonceBehavior === "mismatch"
        ? randomBytes(16).toString("base64url")
        : walletNonce;
  store.addEvent(session, "vp_request_retrieved", {
    request_uri_method: "post",
    wallet_nonce_present: Boolean(walletNonce),
    wallet_nonce_behavior: walletNonceBehavior,
    wallet_nonce_returned: returnedWalletNonce ?? null,
    payload: body,
  });
  return returnedWalletNonce;
}

type ResignDeliveredRequestOptions = {
  config: AppConfig;
  store: CaptureStore;
  session: VpSessionCapture;
  walletNonce: string | null;
  returnedWalletNonce: string | undefined;
};

export async function resignDeliveredRequest({
  config,
  store,
  session,
  walletNonce,
  returnedWalletNonce,
}: ResignDeliveredRequestOptions): Promise<void> {
  // The re-signed Request Object must be the one originally delivered plus the nonce: the
  // same signer, mutations, withheld DCQL query, and fixture Client Identifier. Rebuilding it
  // any other way would add defects the scenario never asked for, such as a DID request
  // signed under the X.509 key.
  const recipe = store.vpDeliveredRequestRecipes.get(session.session_id);
  const signer = recipe?.signer;
  if (!walletNonce || !recipe || !signer) return;
  session.authorization_request = {
    ...session.authorization_request,
    wallet_nonce: returnedWalletNonce,
  };
  session.raw ??= {};
  session.raw.authorization_request = session.authorization_request;
  const delivered = deliveredAuthorizationRequest(
    session.authorization_request,
    recipe,
    session.request_mutation?.request_object,
  );
  if (session.request_mutation) session.raw.authorization_request_delivered = delivered;
  const material = store.vpRequestSigningMaterial.get(session.session_id);
  const resigned = await signPresentationAuthorizationRequest(
    config,
    delivered,
    signer.clientIdScheme,
    requestSigningOptions(session.request_mutation, material, signer.verifierAttestationJwt),
  );
  store.vpCredoAuthorizationRequestJwts.set(
    session.session_id,
    session.request_behavior?.signature === "corrupt" ? corruptJwsSignature(resigned) : resigned,
  );
}

type SendNegotiatedRequestObjectOptions = {
  config: AppConfig;
  store: CaptureStore;
  session: VpSessionCapture;
  body: JsonRecord;
  requestObject: string;
  res: Response;
};

export async function sendNegotiatedRequestObject({
  config,
  store,
  session,
  body,
  requestObject,
  res,
}: SendNegotiatedRequestObjectOptions): Promise<Response> {
  // Section 5.10: `jwks` in `wallet_metadata` asks for the Request Object to be encrypted.
  const negotiation = negotiateRequestObjectEncryption(body.wallet_metadata);
  if (negotiation.status === "not_requested") {
    return sendRequestUriResponse(res, session, requestObject);
  }
  if (session.request_behavior?.request_object_encryption === "none") {
    store.addEvent(session, "vp_request_object_encryption_skipped", {});
    return sendRequestUriResponse(res, session, requestObject);
  }
  if (negotiation.status === "unsupported") {
    store.addEvent(session, "vp_request_object_encryption_unsupported", {
      reason: negotiation.reason,
    });
    return sendRequestUriResponse(
      res,
      session,
      JSON.stringify({ error: "invalid_request", error_description: negotiation.reason }),
      { status: 400, contentType: "application/json" },
    );
  }
  const { encryption } = negotiation;
  const encryptedRequestObject = await (await credoOpenId4VpVerifier(config)).encryptRequestObject(
    requestObject,
    encryption,
  );
  session.raw ??= {};
  session.raw.authorization_request_jwe = encryptedRequestObject;
  session.request_object_encryption = {
    alg: encryption.alg,
    enc: encryption.enc,
    kid: typeof encryption.recipientJwk.kid === "string" ? encryption.recipientJwk.kid : null,
    alg_source: encryption.algSource,
    enc_source: encryption.encSource,
  };
  store.addEvent(session, "vp_request_object_encrypted", {
    ...session.request_object_encryption,
  });
  return sendRequestUriResponse(res, session, encryptedRequestObject);
}

/**
 * Serves the Request Object. A session's `request_uri_response` behaviour replaces the status,
 * media type, or body so that a Wallet receives the specifically wrong retrieval response a test
 * requires; the delivered response is recorded either way.
 */
export function sendRequestUriResponse(
  res: Response,
  session: VpSessionCapture,
  requestObject: string,
  generated: { status: number; contentType: string } = {
    status: 200,
    contentType: "application/oauth-authz-req+jwt",
  },
): Response {
  const behavior = session.request_behavior?.request_uri_response;
  const status = behavior?.status ?? generated.status;
  const contentType = behavior?.content_type ?? generated.contentType;
  const body = behavior?.body ?? requestObject;
  res.once("finish", () => {
    session.raw ??= {};
    session.raw.request_uri_response_http = {
      status: res.statusCode,
      headers: redactHttpHeaders(res.getHeaders()),
      body,
    };
  });
  return res.status(status).type(contentType).send(body);
}

export function requestUriHttpCapture(req: Request): RequestUriHttpCapture {
  const rawBody = (req as Request & { rawBody?: string }).rawBody;
  return {
    method: req.method,
    target: req.originalUrl,
    headers: redactHttpHeaders(req.headers),
    ...(rawBody === undefined ? {} : { body: rawBody }),
  };
}
