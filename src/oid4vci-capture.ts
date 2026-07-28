import { randomUUID } from "node:crypto";
import type { Request, Response } from "express";
import type { JsonRecord, Oid4vciHttpRequestCapture } from "./types.js";

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "dpop",
  "oauth-client-attestation",
  "oauth-client-attestation-pop",
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

export function isOid4vciProtocolPath(path: string): boolean {
  return (
    path === "/.well-known/openid-credential-issuer" ||
    path === "/.well-known/oauth-authorization-server" ||
    path === "/.well-known/jwt-vc-issuer" ||
    path === "/jwks.json" ||
    path === "/par" ||
    path === "/authorize" ||
    path === "/challenge" ||
    path === "/redirect" ||
    path === "/token" ||
    path === "/nonce" ||
    path === "/credential" ||
    path === "/deferred-credential" ||
    /^\/offers\/[^/]+$/.test(path) ||
    /^\/sessions\/[^/]+\/(?:offer|deeplink)$/.test(path)
  );
}

export function createOid4vciRequestCapture(
  req: Request,
  sessionId: string | null,
): Oid4vciHttpRequestCapture {
  return {
    id: randomUUID(),
    at: new Date().toISOString(),
    method: req.method,
    path: req.path,
    session_id: sessionId,
    headers: redactHeaders(req.headers),
    query: redactOid4vciValue(queryRecord(req)),
    body:
      (req.is("application/jwt") === "application/jwt"
        ? redactedValue(req.body)
        : redactOid4vciValue(req.body)) ?? null,
    response: { status: null, content_type: null },
  };
}

export function completeOid4vciRequestCapture(
  capture: Oid4vciHttpRequestCapture,
  res: Response,
): void {
  capture.response.status = res.statusCode;
  const contentType = res.getHeader("content-type");
  capture.response.content_type = typeof contentType === "string" ? contentType : null;
}

export function redactOid4vciValue(value: unknown, key?: string): unknown {
  const normalizedKey = key?.toLowerCase();
  if (normalizedKey && isSensitiveValue(normalizedKey)) return redactedValue(value);
  if (Array.isArray(value)) return value.map((entry) => redactOid4vciValue(entry, key));
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entry]) => [
        entryKey,
        redactOid4vciValue(entry, entryKey),
      ]),
    );
  }
  return value;
}

function redactHeaders(headers: Request["headers"]): JsonRecord {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name,
      SENSITIVE_HEADERS.has(name.toLowerCase()) ? redactedValue(value) : (value ?? null),
    ]),
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

function isSensitiveValue(key: string): boolean {
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
