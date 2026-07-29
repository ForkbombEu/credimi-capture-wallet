import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Express, Request as ExpressRequest, Response as ExpressResponse } from "express";
import type { CaptureStore } from "./state.js";
import type { AppConfig, JsonRecord } from "./types.js";

const FAKE_OAUTH_PATH = "/fake-oauth";
const FAKE_OAUTH_SCOPE = "credimi.capture";
const FAKE_OAUTH_CLIENT_ID = "credimi-capture-wallet";
// Public test credential used only between Credo and this non-production server.
const FAKE_OAUTH_CLIENT_SECRET = "credimi-capture-wallet-test-secret";

interface AuthorizationCode {
  clientId: string;
  codeChallenge: string;
  expiresAt: number;
  redirectUri: string;
  scope: string;
}

interface OAuthErrorBody extends JsonRecord {
  error: string;
  error_description: string;
}

interface OAuthResult {
  body: JsonRecord;
  headers?: Record<string, string>;
  status: number;
}

const servers = new WeakMap<CaptureStore, FakeOAuthServer>();

export function fakeOAuthServer(config: AppConfig, store: CaptureStore): FakeOAuthServer {
  let server = servers.get(store);
  if (!server) {
    server = new FakeOAuthServer(config);
    servers.set(store, server);
  }
  return server;
}

export function registerFakeOAuthServer(
  app: Express,
  config: AppConfig,
  store: CaptureStore,
): void {
  const server = fakeOAuthServer(config, store);

  app.get(server.metadataPath, (_req, res) => {
    res.set("Cache-Control", "no-store").json(server.metadata());
  });

  app.get(`${FAKE_OAUTH_PATH}/authorize`, (req, res) => {
    const result = server.authorize(queryParams(config, req));
    if ("redirect" in result) return res.redirect(302, result.redirect);
    return sendOAuthResult(res, result);
  });

  app.post(`${FAKE_OAUTH_PATH}/token`, (req, res) => {
    const authorization = req.header("authorization");
    return sendOAuthResult(
      res,
      server.token(
        formParams(req.body),
        new Headers(authorization ? { authorization } : undefined),
      ),
    );
  });
}

export class FakeOAuthServer {
  private readonly authorizationCodes = new Map<string, AuthorizationCode>();

  constructor(private readonly config: AppConfig) {}

  get issuer(): string {
    return `${this.config.issuer_base_url}${FAKE_OAUTH_PATH}`;
  }

  get metadataPath(): string {
    return `/.well-known/oauth-authorization-server${FAKE_OAUTH_PATH}`;
  }

  get clientAuthentication(): {
    type: "clientSecret";
    clientId: string;
    clientSecret: string;
  } {
    return {
      type: "clientSecret",
      clientId: FAKE_OAUTH_CLIENT_ID,
      clientSecret: FAKE_OAUTH_CLIENT_SECRET,
    };
  }

  get externalScope(): string {
    return FAKE_OAUTH_SCOPE;
  }

  metadata(): JsonRecord {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post"],
      scopes_supported: [FAKE_OAUTH_SCOPE],
    };
  }

  authorize(params: URLSearchParams): { redirect: string } | OAuthResult {
    const responseType = params.get("response_type");
    const clientId = params.get("client_id");
    const redirectUri = params.get("redirect_uri");
    const state = params.get("state");
    const codeChallenge = params.get("code_challenge");
    const codeChallengeMethod = params.get("code_challenge_method");
    const scope = params.get("scope") ?? "";

    if (responseType !== "code") {
      return oauthError("unsupported_response_type", "response_type must be 'code'");
    }
    if (clientId !== FAKE_OAUTH_CLIENT_ID) {
      return oauthError("invalid_request", "client_id is not registered");
    }
    if (redirectUri !== `${this.config.issuer_base_url}/redirect`) {
      return oauthError("invalid_request", "redirect_uri is not registered");
    }
    if (!state) return oauthError("invalid_request", "state is required");
    if (codeChallengeMethod !== "S256" || !isBase64UrlSha256(codeChallenge)) {
      return oauthError("invalid_request", "S256 PKCE is required");
    }
    if (scope !== FAKE_OAUTH_SCOPE) {
      return oauthError("invalid_scope", "scope is not supported");
    }

    const code = randomBytes(32).toString("base64url");
    this.authorizationCodes.set(code, {
      clientId,
      codeChallenge,
      expiresAt: Date.now() + this.config.authorization_code_ttl_seconds * 1_000,
      redirectUri,
      scope,
    });
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", code);
    callback.searchParams.set("state", state);
    return { redirect: callback.toString() };
  }

  token(params: URLSearchParams, headers: Headers): OAuthResult {
    if (params.get("grant_type") !== "authorization_code") {
      return oauthError("unsupported_grant_type", "grant_type must be 'authorization_code'");
    }
    if (
      params.get("client_id") !== FAKE_OAUTH_CLIENT_ID ||
      params.get("client_secret") !== FAKE_OAUTH_CLIENT_SECRET
    ) {
      return oauthError("invalid_client", "client authentication failed", 401, {
        "WWW-Authenticate": 'Basic realm="fake-oauth"',
      });
    }
    if (headers.has("authorization")) {
      return oauthError("invalid_client", "client_secret_post is required", 401);
    }

    const code = params.get("code");
    if (!code) return oauthError("invalid_grant", "authorization code is required");
    const authorization = this.authorizationCodes.get(code);
    this.authorizationCodes.delete(code);
    if (!authorization || authorization.expiresAt <= Date.now()) {
      return oauthError("invalid_grant", "authorization code is invalid or expired");
    }
    if (
      params.get("client_id") !== authorization.clientId ||
      params.get("redirect_uri") !== authorization.redirectUri
    ) {
      return oauthError("invalid_grant", "authorization code binding is invalid");
    }
    const verifier = params.get("code_verifier");
    if (!verifier || !validPkceVerifier(verifier)) {
      return oauthError("invalid_grant", "code_verifier is invalid");
    }
    const actualChallenge = createHash("sha256").update(verifier).digest("base64url");
    if (!constantTimeEqual(actualChallenge, authorization.codeChallenge)) {
      return oauthError("invalid_grant", "PKCE verification failed");
    }

    return {
      status: 200,
      body: {
        access_token: randomBytes(32).toString("base64url"),
        token_type: "Bearer",
        expires_in: 60,
        scope: authorization.scope,
      },
      headers: {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    };
  }

  async fetch(input: string | URL | globalThis.Request, init?: RequestInit): Promise<Response> {
    const request =
      input instanceof globalThis.Request ? input : new globalThis.Request(input, init);
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === this.metadataPath) {
      return jsonResponse({ status: 200, body: this.metadata() });
    }
    if (request.method === "POST" && url.href === `${this.issuer}/token`) {
      return jsonResponse(this.token(new URLSearchParams(await request.text()), request.headers));
    }
    return jsonResponse(oauthError("invalid_request", "fake OAuth endpoint not found", 404));
  }

  handles(input: string | URL | globalThis.Request): boolean {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
    );
    return (
      url.origin === new URL(this.config.issuer_base_url).origin &&
      (url.pathname === this.metadataPath || url.href === `${this.issuer}/token`)
    );
  }
}

function queryParams(config: AppConfig, req: ExpressRequest): URLSearchParams {
  return new URL(req.originalUrl, config.issuer_base_url).searchParams;
}

function formParams(body: unknown): URLSearchParams {
  const params = new URLSearchParams();
  if (!isRecord(body)) return params;
  for (const [key, value] of Object.entries(body)) {
    if (typeof value === "string") params.append(key, value);
  }
  return params;
}

function sendOAuthResult(res: ExpressResponse, result: OAuthResult): ExpressResponse {
  for (const [name, value] of Object.entries(result.headers ?? {})) res.set(name, value);
  return res.status(result.status).json(result.body);
}

function jsonResponse(result: OAuthResult): Response {
  return new Response(JSON.stringify(result.body), {
    status: result.status,
    headers: {
      "Content-Type": "application/json",
      ...result.headers,
    },
  });
}

function oauthError(
  error: string,
  description: string,
  status = 400,
  headers?: Record<string, string>,
): OAuthResult {
  const body: OAuthErrorBody = {
    error,
    error_description: description,
  };
  return {
    status,
    body,
    headers: {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      ...headers,
    },
  };
}

function isBase64UrlSha256(value: string | null): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function validPkceVerifier(value: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
