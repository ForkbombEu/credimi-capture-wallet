import { isLoopbackHost } from "./settings.js";

export type AttestbookFetchErrorCode =
  | "url_not_allowed"
  | "redirect_not_followed"
  | "not_found"
  | "unexpected_status"
  | "response_too_large"
  | "timeout"
  | "network_failure";

/** A typed retrieval failure. Its message never contains response bytes or credentials. */
export class AttestbookFetchError extends Error {
  constructor(
    readonly code: AttestbookFetchErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AttestbookFetchError";
  }
}

export interface BoundedResponse {
  readonly bytes: Uint8Array;
  readonly contentType: string | null;
  readonly contentDigest: string | null;
}

export interface BoundedGetOptions {
  /** Exact origins the URL may name; every other origin is refused before any request. */
  readonly allowedOrigins: readonly string[];
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly accept: string;
  readonly fetch?: typeof fetch;
}

/**
 * The URL a retrieval may use: an allowed origin over HTTPS (plain HTTP only on a literal loopback
 * host), without embedded credentials or a fragment. It is checked before any connection, so a
 * value taken from a document can never direct a request elsewhere.
 */
export function allowedUrl(value: string, allowedOrigins: readonly string[]): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AttestbookFetchError("url_not_allowed", "URL is not absolute");
  }
  if (url.username || url.password || url.hash) {
    throw new AttestbookFetchError(
      "url_not_allowed",
      "URL must not carry credentials or a fragment",
    );
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new AttestbookFetchError("url_not_allowed", "URL must use https");
  }
  if (!allowedOrigins.includes(url.origin)) {
    throw new AttestbookFetchError("url_not_allowed", `origin ${url.origin} is not trusted`);
  }
  return url;
}

/**
 * One bounded GET: no redirect is followed, the whole exchange shares one deadline and the body
 * is read only up to `maxBytes`.
 */
export async function boundedGet(
  url: string,
  options: BoundedGetOptions,
): Promise<BoundedResponse> {
  const target = allowedUrl(url, options.allowedOrigins);
  const signal = AbortSignal.timeout(options.timeoutMs);
  let response: Response;
  try {
    response = await (options.fetch ?? fetch)(target, {
      method: "GET",
      redirect: "manual",
      headers: { accept: options.accept },
      signal,
    });
  } catch (error) {
    throw transportError(error);
  }
  await assertResponseAcceptable(response, target, options.maxBytes);
  try {
    const bytes = await readBoundedBody(response, options.maxBytes, target);
    return {
      bytes,
      contentType: response.headers.get("content-type"),
      contentDigest: response.headers.get("content-digest"),
    };
  } catch (error) {
    if (error instanceof AttestbookFetchError) throw error;
    throw transportError(error);
  }
}

async function assertResponseAcceptable(
  response: Response,
  target: URL,
  maxBytes: number,
): Promise<void> {
  if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel();
    throw new AttestbookFetchError(
      "redirect_not_followed",
      `${target.pathname} answered a redirect`,
    );
  }
  if (response.status === 404) {
    await response.body?.cancel();
    throw new AttestbookFetchError("not_found", `${target.pathname} was not found`);
  }
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new AttestbookFetchError(
      "unexpected_status",
      `${target.pathname} answered HTTP ${response.status}`,
    );
  }
  const declaredLength = Number(response.headers.get("content-length") ?? Number.NaN);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await response.body?.cancel();
    throw tooLarge(target, maxBytes);
  }
}

async function readBoundedBody(
  response: Response,
  maxBytes: number,
  target: URL,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  const reader = response.body?.getReader();
  while (reader) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maxBytes) {
      await reader.cancel();
      throw tooLarge(target, maxBytes);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

function tooLarge(target: URL, maxBytes: number): AttestbookFetchError {
  return new AttestbookFetchError(
    "response_too_large",
    `${target.pathname} exceeds the ${maxBytes}-byte bound`,
  );
}

function transportError(error: unknown): AttestbookFetchError {
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
    return new AttestbookFetchError("timeout", "request timed out");
  }
  return new AttestbookFetchError("network_failure", "request failed before a response");
}
