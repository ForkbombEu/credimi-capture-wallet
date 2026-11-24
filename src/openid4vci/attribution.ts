import {
  type OpenId4VcIssuanceSessionRecord,
  OpenId4VcIssuanceSessionState,
} from "@credo-ts/openid4vc";
import type { Request } from "express";
import { asStringOrNull, isRecord } from "../shared/json.js";
import { decodeJwtForEvidence } from "./proofs.js";

/** RFC 9126 Section 2.2 prefix of a PAR `request_uri`; Credo-TS issues its reference after it. */
const PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

export type IssuanceSessionQuery = {
  issuerState?: string;
  preAuthorizedCode?: string;
  authorizationCode?: string;
  chainedIdentityRequestUriReferenceValue?: string;
  chainedIdentityState?: string;
};

export function captureSessionIdFromCredo(
  issuanceSession: OpenId4VcIssuanceSessionRecord,
): string | null {
  const value = issuanceSession.issuanceMetadata?.captureSessionId;
  return typeof value === "string" ? value : null;
}

export function issuanceSessionQuery(endpoint: string, req: Request): IssuanceSessionQuery | null {
  const body = isRecord(req.body) ? req.body : {};
  switch (endpoint) {
    case "par": {
      const issuerState = asStringOrNull(body.issuer_state);
      return issuerState ? { issuerState } : null;
    }
    case "authorize": {
      const requestUri = asStringOrNull(req.query.request_uri);
      return requestUri?.startsWith(PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX)
        ? {
            chainedIdentityRequestUriReferenceValue: requestUri.slice(
              PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX.length,
            ),
          }
        : null;
    }
    case "redirect": {
      const state = asStringOrNull(req.query.state);
      return state ? { chainedIdentityState: state } : null;
    }
    case "token": {
      const preAuthorizedCode = asStringOrNull(body["pre-authorized_code"]);
      if (preAuthorizedCode) return { preAuthorizedCode };
      const code = asStringOrNull(body.code);
      return code ? { authorizationCode: code } : null;
    }
    case "credential":
    case "deferred-credential":
    case "notification":
      return accessTokenSessionQuery(req.header("authorization"));
    default:
      return null;
  }
}

/**
 * The grant an access token names, as Credo-TS's Credential endpoint reads it.
 * @internal
 */
export function accessTokenSessionQuery(
  authorization: string | undefined,
): IssuanceSessionQuery | null {
  const accessToken = /^(?:DPoP|Bearer) (.+)$/i.exec(authorization ?? "")?.[1];
  if (!accessToken) return null;
  const { payload } = decodeJwtForEvidence(accessToken);
  const preAuthorizedCode = asStringOrNull(payload?.["pre-authorized_code"]);
  if (preAuthorizedCode) return { preAuthorizedCode };
  const issuerState = asStringOrNull(payload?.issuer_state);
  return issuerState ? { issuerState } : null;
}

/** The request headers as a Fetch `Headers`, the form Credo-TS's resource server reads. */
export function requestHeaders(req: Request): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.append(name, value);
    else for (const item of value ?? []) headers.append(name, item);
  }
  return headers;
}

/**
 * Whether a verified access token belongs to the issuance session that received a Credential
 * Response. Credo-TS binds the session to the `sub` of the access token used at its Credential
 * endpoint, and the token's grant, when it names one, must be this session's grant too.
 */
export function issuanceSessionAuthorizes(
  issuanceSession: OpenId4VcIssuanceSessionRecord,
  tokenPayload: { sub?: string; [claim: string]: unknown },
): boolean {
  if (!tokenPayload.sub || issuanceSession.authorization?.subject !== tokenPayload.sub) {
    return false;
  }
  const preAuthorizedCode = asStringOrNull(tokenPayload["pre-authorized_code"]);
  if (preAuthorizedCode !== null && preAuthorizedCode !== issuanceSession.preAuthorizedCode) {
    return false;
  }
  const issuerState = asStringOrNull(tokenPayload.issuer_state);
  return issuerState === null || issuerState === issuanceSession.authorization?.issuerState;
}

export function captureStatus(state: OpenId4VcIssuanceSessionState): string {
  switch (state) {
    case OpenId4VcIssuanceSessionState.OfferCreated:
      return "created";
    case OpenId4VcIssuanceSessionState.OfferUriRetrieved:
      return "offer_retrieved";
    case OpenId4VcIssuanceSessionState.AuthorizationInitiated:
      return "authorization_requested";
    case OpenId4VcIssuanceSessionState.AuthorizationGranted:
      return "authorization_granted";
    case OpenId4VcIssuanceSessionState.AccessTokenRequested:
      return "token_requested";
    case OpenId4VcIssuanceSessionState.AccessTokenCreated:
      return "token_issued";
    case OpenId4VcIssuanceSessionState.CredentialRequestReceived:
      return "credential_requested";
    case OpenId4VcIssuanceSessionState.CredentialsPartiallyIssued:
      return "credentials_partially_issued";
    case OpenId4VcIssuanceSessionState.Completed:
      return "credential_issued";
    case OpenId4VcIssuanceSessionState.Error:
      return "error";
    default:
      return state;
  }
}
