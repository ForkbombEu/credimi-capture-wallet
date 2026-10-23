import { randomUUID } from "node:crypto";
import type { Request, Response } from "express";
import type {
  EvidenceMode,
  JsonRecord,
  Oid4vciHttpRequestCapture,
  RawHttpBody,
  RawHttpHeader,
} from "./types.js";

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "dpop",
  "oauth-client-attestation",
  "oauth-client-attestation-pop",
  "proxy-authorization",
  "set-cookie",
]);

/**
 * Headers `full` evidence still redacts. They carry bearer credentials: anyone holding one could
 * act as the Wallet or the operator. The Client Attestation headers are kept, because an FCAF test
 * evaluates them, and their PoP is bound to a key the reader does not hold.
 */
const FULL_EVIDENCE_SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "dpop",
  "proxy-authorization",
  "set-cookie",
]);

const SENSITIVE_VALUES = new Set([
  "access_token",
  "attestation",
  "authorization_code",
  "client_assertion",
  "client_secret",
  "code",
  "code_verifier",
  "credential",
  "dpop",
  "jwt",
  "password",
  "pre-authorized_code",
  "proof",
  "refresh_token",
  "request_uri",
  "tx_code",
]);

/** Members `full` evidence still redacts: tokens, codes, the PKCE verifier, and raw secrets. */
const FULL_EVIDENCE_SENSITIVE_VALUES = new Set([
  "access_token",
  "authorization_code",
  "client_secret",
  "code",
  "code_verifier",
  "password",
  "pre-authorized_code",
  "refresh_token",
  "tx_code",
]);

/** Requests whose exact body `full` evidence keeps: PAR, token, and Credential Requests. */
const RAW_BODY_PATH = /^\/issuers\/[^/]+\/(?:par|token|credential)$/;

export function isOid4vciProtocolPath(path: string): boolean {
  return (
    /^\/\.well-known\/(?:openid-credential-issuer|oauth-authorization-server|jwt-vc-issuer)\/issuers\/[^/]+$/.test(
      path,
    ) ||
    /^\/\.well-known\/oauth-authorization-server\/authorization-servers\/[^/]+$/.test(path) ||
    /^\/issuers\/[^/]+\/(?:credential-jwks\.json|jwks\.json|par|authorize|challenge|redirect|token|nonce|credential|deferred-credential)$/.test(
      path,
    ) ||
    /^\/issuers\/[^/]+\/offers\/[^/]+$/.test(path) ||
    /^\/authorization-servers\/[^/]+\/(?:authorize|token)$/.test(path) ||
    /^\/sessions\/[^/]+\/(?:offer|deeplink)$/.test(path)
  );
}

export function isRawBodyEvidencePath(path: string): boolean {
  return RAW_BODY_PATH.test(path);
}

/**
 * Captures one request twice from the same input: the redacted form, which is the only one the
 * global ledger holds, and the `full` form, which only a session created with
 * `evidence_mode: "full"` exposes. Both share `id` and `at`.
 */
export function createOid4vciRequestCaptures(
  req: Request,
  issuerConfigurationId: string | null = null,
): Record<EvidenceMode, Oid4vciHttpRequestCapture> {
  const id = randomUUID();
  const at = new Date().toISOString();
  const capture = (mode: EvidenceMode): Oid4vciHttpRequestCapture => ({
    id,
    at,
    method: req.method,
    path: req.path,
    session_id: null,
    issuer_configuration_id: issuerConfigurationId,
    headers: redactHttpHeaders(req.headers, mode),
    header_counts: headerCounts(req.rawHeaders),
    ...(mode === "full" ? { raw_headers: rawHttpHeaders(req.rawHeaders) } : {}),
    ...(mode === "full" && RAW_BODY_PATH.test(req.path) ? { raw_body: rawHttpBody(req) } : {}),
    query: redactOid4vciValue(queryRecord(req), undefined, mode),
    body:
      (req.is("application/jwt") === "application/jwt"
        ? redactedValue(req.body)
        : redactOid4vciValue(req.body, undefined, mode)) ?? null,
    response: { status: null, content_type: null },
  });
  return { redacted: capture("redacted"), full: capture("full") };
}

export function completeOid4vciRequestCapture(
  capture: Oid4vciHttpRequestCapture,
  res: Response,
): void {
  capture.response.status = res.statusCode;
  const contentType = res.getHeader("content-type");
  capture.response.content_type = typeof contentType === "string" ? contentType : null;
}

/**
 * The exact received body, which JSON well-formedness checks (duplicate member names, UTF-8, no
 * byte order mark) need and a parsed body cannot show. An `application/jwt` body is kept as text.
 * A token request body is only described: it carries the codes and verifier that `full` evidence
 * still redacts, and no byte-level check applies to its form encoding.
 */
function rawHttpBody(req: Request): RawHttpBody {
  const contentType = req.header("content-type") ?? null;
  const bytes = (req as Request & { rawBodyBytes?: Buffer }).rawBodyBytes;
  if (req.path.endsWith("/token")) {
    return { content_type: contentType, redacted: true, length: bytes?.length ?? 0 };
  }
  if (req.is("application/jwt") === "application/jwt") {
    return { content_type: contentType, text: typeof req.body === "string" ? req.body : "" };
  }
  return { content_type: contentType, base64: bytes?.toString("base64") ?? "" };
}

/** Every received value of one header field, in order, from a `full` capture. */
export function rawHeaderValues(capture: Oid4vciHttpRequestCapture, name: string): string[] {
  const normalizedName = name.toLowerCase();
  return (capture.raw_headers ?? []).flatMap((header) =>
    header.name.toLowerCase() === normalizedName && typeof header.value === "string"
      ? [header.value]
      : [],
  );
}

export function redactOid4vciValue(
  value: unknown,
  key?: string,
  mode: EvidenceMode = "redacted",
): unknown {
  const normalizedKey = key?.toLowerCase();
  if (normalizedKey && isSensitiveValue(normalizedKey, mode)) return redactedValue(value);
  if (Array.isArray(value)) return value.map((entry) => redactOid4vciValue(entry, key, mode));
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entry]) => [
        entryKey,
        redactOid4vciValue(entry, entryKey, mode),
      ]),
    );
  }
  return value;
}

export function redactHttpHeaders(
  headers: Request["headers"] | ReturnType<Response["getHeaders"]>,
  mode: EvidenceMode = "redacted",
): JsonRecord {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name,
      isSensitiveHeader(name, mode) ? redactedValue(value) : (value ?? null),
    ]),
  );
}

function headerCounts(rawHeaders: string[]): Record<string, number> {
  const counts = new Map<string, number>();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]?.toLowerCase();
    if (name) counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return Object.fromEntries(counts);
}

function rawHttpHeaders(rawHeaders: string[]): RawHttpHeader[] {
  const headers: RawHttpHeader[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1] ?? "";
    if (!name) continue;
    headers.push({ name, value: isSensitiveHeader(name, "full") ? redactedValue(value) : value });
  }
  return headers;
}

function isSensitiveHeader(name: string, mode: EvidenceMode): boolean {
  return (mode === "full" ? FULL_EVIDENCE_SENSITIVE_HEADERS : SENSITIVE_HEADERS).has(
    name.toLowerCase(),
  );
}

function queryRecord(req: Request): JsonRecord {
  return Object.fromEntries(
    Object.entries(req.query).map(([name, value]) => [
      name,
      Array.isArray(value) ? value.map(String) : typeof value === "string" ? value : String(value),
    ]),
  );
}

function isSensitiveValue(key: string, mode: EvidenceMode): boolean {
  if (mode === "full") return FULL_EVIDENCE_SENSITIVE_VALUES.has(key) || key.endsWith("_token");
  return (
    SENSITIVE_VALUES.has(key) ||
    key.endsWith("_token") ||
    key.endsWith("_assertion") ||
    key.endsWith("_attestation")
  );
}

function redactedValue(value: unknown): JsonRecord {
  const serialized =
    typeof value === "string" ? value : value === undefined ? "" : JSON.stringify(value);
  return {
    redacted: true,
    present: value !== undefined && value !== null,
    length: serialized.length,
  };
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
