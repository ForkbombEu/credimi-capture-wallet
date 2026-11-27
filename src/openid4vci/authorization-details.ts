import { randomBytes } from "node:crypto";
import type { SupportedCredential } from "../credentials/catalogue.js";
import { asRecord } from "../shared/json.js";
import type { GrantedCredentialAuthorizationDetail, JsonRecord } from "../types.js";

/**
 * OpenID4VCI 1.0 Authorization Details (Section 5.1.1, RFC 9396) for the issuer. Credo-TS
 * authorizes by `scope` only and never returns `credential_identifiers`
 * (openwallet-foundation-labs/identity-common-ts#242), so this service grants them itself: it
 * validates `openid_credential` entries, maps them to the Credential Configurations' scopes Credo
 * authorizes, returns the grant in the Token Response (Section 6.2), and resolves a
 * `credential_identifier` back to its Credential Configuration (Section 8.2).
 */
const OPENID_CREDENTIAL_TYPE = "openid_credential";

/** An `authorization_details` value this issuer refuses with `invalid_authorization_details`. */
export class AuthorizationDetailsError extends Error {}

/**
 * The Credential Configurations an `authorization_details` request parameter names, in order, or
 * `null` when the parameter is absent. Only the `openid_credential` type is supported; `claims` is
 * accepted but not applied, so the grant covers the whole Credential Configuration.
 */
export function requestedCredentialConfigurations(
  value: unknown,
  credentials: readonly SupportedCredential[],
): SupportedCredential[] | null {
  if (value === undefined) return null;
  let parsed: unknown;
  try {
    parsed = typeof value === "string" ? JSON.parse(value) : undefined;
  } catch {
    parsed = undefined;
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new AuthorizationDetailsError("authorization_details must be a non-empty JSON array");
  }
  return parsed.map((entry) => {
    const detail = asRecord(entry);
    if (!detail) {
      throw new AuthorizationDetailsError("each authorization_details entry must be an object");
    }
    if (detail.type !== OPENID_CREDENTIAL_TYPE) {
      throw new AuthorizationDetailsError(
        `authorization_details type '${String(detail.type)}' is not supported`,
      );
    }
    const credentialConfigurationId = detail.credential_configuration_id;
    if (typeof credentialConfigurationId !== "string") {
      throw new AuthorizationDetailsError(
        "an openid_credential authorization_details entry must name a credential_configuration_id",
      );
    }
    const credential = credentials.find((candidate) => candidate.id === credentialConfigurationId);
    if (!credential) {
      throw new AuthorizationDetailsError(
        `credential_configuration_id '${credentialConfigurationId}' is not supported by this issuer`,
      );
    }
    return credential;
  });
}

/**
 * The `scope` Credo-TS authorizes the request with. A `scope` the Wallet sent must name the scope
 * of every requested Credential Configuration, since the access token covers only that scope;
 * without one, the requested Credential Configurations' scopes are used.
 */
export function authorizedScope(scope: unknown, requested: readonly SupportedCredential[]): string {
  const requestedScopes = [...new Set(requested.map((credential) => credential.scope))];
  if (scope === undefined) return requestedScopes.join(" ");
  const scopes = typeof scope === "string" ? scope.split(" ") : [];
  const missing = requestedScopes.filter((requestedScope) => !scopes.includes(requestedScope));
  if (missing.length > 0) {
    throw new AuthorizationDetailsError(
      `scope does not include '${missing.join(" ")}' of the requested authorization_details`,
    );
  }
  return scopes.join(" ");
}

/** Grants one fresh Credential Dataset identifier for each requested entry. */
export function grantAuthorizationDetails(
  requested: readonly SupportedCredential[],
): GrantedCredentialAuthorizationDetail[] {
  return requested.map((credential) => ({
    type: OPENID_CREDENTIAL_TYPE,
    credential_configuration_id: credential.id,
    credential_identifiers: [randomBytes(16).toString("base64url")],
  }));
}

export type CredentialIdentifierResolution =
  | { ok: true; credentialConfigurationId?: string }
  | { ok: false; error: "invalid_credential_request"; description: string };

/**
 * What a Credential Request names, given the session's grant. Once `credential_identifiers` were
 * returned, `credential_configuration_id` must not be used (Section 8.2). A granted identifier
 * resolves to its Credential Configuration; any other identifier is left for Credo-TS, which
 * answers `unknown_credential_identifier`.
 */
export function resolveCredentialIdentifier(
  granted: readonly GrantedCredentialAuthorizationDetail[] | undefined,
  body: JsonRecord,
): CredentialIdentifierResolution {
  if (!granted) return { ok: true };
  if (body.credential_configuration_id !== undefined) {
    return {
      ok: false,
      error: "invalid_credential_request",
      description:
        "credential_configuration_id must not be used: the Token Response returned credential_identifiers",
    };
  }
  const identifier = body.credential_identifier;
  const detail = granted.find(
    (candidate) =>
      typeof identifier === "string" && candidate.credential_identifiers.includes(identifier),
  );
  return detail
    ? { ok: true, credentialConfigurationId: detail.credential_configuration_id }
    : { ok: true };
}
