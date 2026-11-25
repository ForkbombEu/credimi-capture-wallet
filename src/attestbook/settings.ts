import type { AttestbookSettings } from "../types.js";

/** @internal */
export const ATTESTBOOK_ENABLED_ENV_VAR = "ATTESTBOOK_ENABLED";
/** @internal */
export const ATTESTBOOK_BASE_URL_ENV_VAR = "ATTESTBOOK_BASE_URL";
/** @internal */
export const ATTESTBOOK_RULEBOOK_ID_ENV_VAR = "ATTESTBOOK_RULEBOOK_ID";
/** @internal */
export const ATTESTBOOK_WEBHOOK_SECRET_ENV_VAR = "ATTESTBOOK_WEBHOOK_SECRET";
/** @internal */
export const ATTESTBOOK_ADMIN_TOKEN_ENV_VAR = "ATTESTBOOK_ADMIN_TOKEN";
/** @internal */
export const ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR = "ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS";

export const DISABLED_ATTESTBOOK_SETTINGS: AttestbookSettings = {
  enabled: false,
  base_url: null,
  rulebook_id: null,
  webhook_secret: null,
  admin_token: null,
  allowed_schema_origins: [],
};

/** Attestbook rulebook ids and version labels become part of credential configuration ids. */
export const SAFE_ATTESTBOOK_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Reads the Attestbook integration from the environment. Nothing is read when the integration is
 * disabled, so a deployment without it behaves exactly as before; an enabled but incomplete or
 * unsafe configuration fails startup instead of running half-configured.
 */
export function resolveAttestbookSettings(env: NodeJS.ProcessEnv): AttestbookSettings {
  const enabled = env[ATTESTBOOK_ENABLED_ENV_VAR]?.trim().toLowerCase();
  if (!enabled || ["0", "false", "no", "off"].includes(enabled)) {
    return DISABLED_ATTESTBOOK_SETTINGS;
  }
  if (!["1", "true", "yes", "on"].includes(enabled)) {
    throw new Error(`${ATTESTBOOK_ENABLED_ENV_VAR} must be true or false`);
  }

  const baseUrl = env[ATTESTBOOK_BASE_URL_ENV_VAR]?.trim();
  if (!baseUrl)
    throw new Error(`${ATTESTBOOK_BASE_URL_ENV_VAR} is required when Attestbook is enabled`);
  const rulebookId = env[ATTESTBOOK_RULEBOOK_ID_ENV_VAR]?.trim();
  if (!rulebookId) {
    throw new Error(`${ATTESTBOOK_RULEBOOK_ID_ENV_VAR} is required when Attestbook is enabled`);
  }
  if (!SAFE_ATTESTBOOK_IDENTIFIER.test(rulebookId)) {
    throw new Error(`${ATTESTBOOK_RULEBOOK_ID_ENV_VAR} contains unsupported characters`);
  }

  return {
    enabled: true,
    base_url: trustedOrigin(baseUrl, ATTESTBOOK_BASE_URL_ENV_VAR),
    rulebook_id: rulebookId,
    webhook_secret: env[ATTESTBOOK_WEBHOOK_SECRET_ENV_VAR]?.trim() || null,
    admin_token: env[ATTESTBOOK_ADMIN_TOKEN_ENV_VAR]?.trim() || null,
    allowed_schema_origins: (env[ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR] ?? "")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean)
      .map((origin) => trustedOrigin(origin, ATTESTBOOK_ALLOWED_SCHEMA_ORIGINS_ENV_VAR)),
  };
}

/**
 * An explicitly configured origin: HTTPS, or plain HTTP on a literal loopback host for local
 * fixtures only. Credentials, a path, a query and a fragment are refused so that the value names
 * exactly one origin.
 * @internal
 */
export function trustedOrigin(value: string, variable: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${variable} must be an absolute origin, got '${value}'`);
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "/" && url.pathname !== "")
  ) {
    throw new Error(`${variable} must be an origin without credentials, path, query or fragment`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new Error(`${variable} must use https (plain http is accepted only for loopback hosts)`);
  }
  return url.origin;
}

export function isLoopbackHost(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]";
}
