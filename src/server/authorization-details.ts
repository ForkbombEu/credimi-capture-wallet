import type { Request, Response } from "express";
import { resolvedIssuerConfigurationById } from "../configurations/registry.js";
import { credentialRegistry } from "../credentials/registry.js";
import {
  AuthorizationDetailsError,
  authorizedScope,
  grantAuthorizationDetails,
  requestedCredentialConfigurations,
} from "../openid4vci/authorization-details.js";
import { asRecord } from "../shared/json.js";
import type { GrantedCredentialAuthorizationDetail, JsonRecord } from "../types.js";
import type { ServerContext } from "./context.js";

/**
 * Applies OpenID4VCI 1.0 Authorization Details at PAR and the token endpoint before Credo-TS
 * handles the request. At PAR, `scope` is aligned with the requested Credential Configurations and
 * the grant is kept for the session once the PAR succeeds. At the token endpoint, Authorization
 * Details may also be requested (Section 5.1.1), and the session's grant is added to the Token
 * Response (Section 6.2). Returns `false` once it has answered `invalid_authorization_details`.
 */
export function prepareAuthorizationDetails(
  ctx: ServerContext,
  req: Request,
  res: Response,
): boolean {
  const endpoint = /^\/issuers\/([^/]+)\/(par|token)$/.exec(req.path);
  const issuer = endpoint?.[1]
    ? resolvedIssuerConfigurationById(ctx.config, decodeURIComponent(endpoint[1]))
    : null;
  if (!endpoint || !issuer) return true;
  const { store } = ctx;
  const body = asRecord(req.body) ?? {};
  const sessionId = () => ctx.capture(req)?.session_id ?? null;

  let granted: GrantedCredentialAuthorizationDetail[] | undefined;
  try {
    const requested = requestedCredentialConfigurations(
      body.authorization_details,
      credentialRegistry(ctx.config, store).credentialsForIssuer(issuer),
    );
    if (requested) {
      const knownSessionId = sessionId();
      const session = knownSessionId ? store.getSession(knownSessionId) : undefined;
      const other =
        session &&
        requested.find((credential) => credential.id !== session.credential_configuration_id);
      if (other) {
        throw new AuthorizationDetailsError(
          `credential_configuration_id '${other.id}' is not part of this issuance session`,
        );
      }
      if (endpoint[2] === "par") body.scope = authorizedScope(body.scope, requested);
      granted = grantAuthorizationDetails(requested);
    }
  } catch (error) {
    if (!(error instanceof AuthorizationDetailsError)) throw error;
    res.status(400).set("Cache-Control", "no-store").json({
      error: "invalid_authorization_details",
      error_description: error.message,
    });
    return false;
  }

  // The successful PAR decides the session's grant: a later PAR without Authorization Details is
  // authorized by scope alone, and its Token Response carries none.
  const keepGrant = () => {
    const id = sessionId();
    if (!id || res.statusCode < 200 || res.statusCode >= 300) return;
    if (granted) store.authorizationDetails.set(id, granted);
    else if (endpoint[2] === "par") store.authorizationDetails.delete(id);
  };
  res.once("finish", keepGrant);
  if (endpoint[2] === "token") {
    const id = sessionId();
    const tokenGrant = granted ?? (id ? store.authorizationDetails.get(id) : undefined);
    if (tokenGrant) addToTokenResponse(res, tokenGrant);
  }
  return true;
}

/** Adds `authorization_details` to the successful Token Response Credo-TS sends. */
function addToTokenResponse(res: Response, granted: GrantedCredentialAuthorizationDetail[]): void {
  const send = res.send;
  res.send = function (this: Response, responseBody?: unknown) {
    res.send = send;
    if (res.statusCode < 200 || res.statusCode >= 300) return send.call(this, responseBody);
    let tokenResponse: JsonRecord | null = asRecord(responseBody);
    if (typeof responseBody === "string" || Buffer.isBuffer(responseBody)) {
      try {
        tokenResponse = asRecord(JSON.parse(responseBody.toString()));
      } catch {
        tokenResponse = null;
      }
    }
    if (typeof tokenResponse?.access_token !== "string") return send.call(this, responseBody);
    return send.call(this, JSON.stringify({ ...tokenResponse, authorization_details: granted }));
  } as Response["send"];
}
