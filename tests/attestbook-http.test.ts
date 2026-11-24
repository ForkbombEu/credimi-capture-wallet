import { describe, expect, it, vi } from "vitest";
import { AttestbookFetchError, boundedGet } from "../src/attestbook/http.js";

const target = "https://book.example/rulebook.json";
const options = {
  allowedOrigins: ["https://book.example"],
  maxBytes: 8,
  timeoutMs: 100,
  accept: "application/json",
};

async function expectFailure(operation: Promise<unknown>, code: string, message: string) {
  const error = await operation.catch((value: unknown) => value);
  expect(error).toBeInstanceOf(AttestbookFetchError);
  expect(error).toMatchObject({ name: "AttestbookFetchError", code, message });
}

describe("Attestbook bounded GET", () => {
  it.each([
    ["not absolute", "book.example/rulebook.json", "URL is not absolute"],
    [
      "credentials",
      "https://user:password@book.example/rulebook.json",
      "URL must not carry credentials or a fragment",
    ],
    [
      "fragment",
      "https://book.example/rulebook.json#secret",
      "URL must not carry credentials or a fragment",
    ],
    ["plain HTTP", "http://book.example/rulebook.json", "URL must use https"],
  ])("rejects unsafe URL (%s) before calling fetch", async (_name, value, message) => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    await expectFailure(
      boundedGet(value, {
        ...options,
        allowedOrigins: ["https://book.example", "http://book.example"],
        fetch,
      }),
      "url_not_allowed",
      message,
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects an origin outside the allowlist before calling fetch", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    await expectFailure(
      boundedGet("https://elsewhere.example/rulebook.json", { ...options, fetch }),
      "url_not_allowed",
      "origin https://elsewhere.example is not trusted",
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    [
      "redirect_not_followed",
      new Response(null, { status: 302, headers: { location: "/next" } }),
      "/rulebook.json answered a redirect",
    ],
    ["not_found", new Response(null, { status: 404 }), "/rulebook.json was not found"],
    ["unexpected_status", new Response(null, { status: 503 }), "/rulebook.json answered HTTP 503"],
  ] as const)("maps %s responses to typed failures", async (code, response, message) => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response);
    await expectFailure(boundedGet(target, { ...options, fetch }), code, message);
    expect(fetch).toHaveBeenCalledWith(
      new URL(target),
      expect.objectContaining({
        method: "GET",
        redirect: "manual",
        headers: { accept: "application/json" },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("rejects a response over the bound from declared Content-Length without reading the body", async () => {
    const response = new Response("x", { status: 200, headers: { "content-length": "9" } });
    const getReader = vi.spyOn(response.body as ReadableStream<Uint8Array>, "getReader");
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response);
    await expectFailure(
      boundedGet(target, { ...options, maxBytes: 8, fetch }),
      "response_too_large",
      "/rulebook.json exceeds the 8-byte bound",
    );
    expect(getReader).not.toHaveBeenCalled();
  });

  it("rejects a streamed response as soon as it exceeds the bound", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("12345"));
        controller.enqueue(new TextEncoder().encode("67890"));
      },
    });
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response(body, { status: 200 }));
    await expectFailure(
      boundedGet(target, { ...options, maxBytes: 8, fetch }),
      "response_too_large",
      "/rulebook.json exceeds the 8-byte bound",
    );
  });

  it("maps a body-read error without exposing its message", async () => {
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error("secret"));
      },
    });
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response(body, { status: 200 }));
    const error = await boundedGet(target, { ...options, fetch }).catch((value: unknown) => value);
    expect(error).toMatchObject({
      name: "AttestbookFetchError",
      code: "network_failure",
      message: "request failed before a response",
    });
    expect((error as Error).message).not.toContain("secret");
  });

  it("uses the same deadline while reading the body", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          const signal = init?.signal;
          if (!signal) throw new Error("missing signal");
          if (signal.aborted) controller.error(signal.reason);
          else
            signal.addEventListener("abort", () => controller.error(signal.reason), { once: true });
        },
      });
      return new Response(body, { status: 200 });
    });
    await expectFailure(
      boundedGet(target, { ...options, timeoutMs: 5, fetch }),
      "timeout",
      "request timed out",
    );
  });

  it("maps an aborted request to the single deadline timeout", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
      await new Promise<void>((resolve) => {
        if (init?.signal?.aborted) resolve();
        else init?.signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      const error = new Error("deadline") as Error & { name: string };
      error.name = "TimeoutError";
      throw error;
    });
    await expectFailure(
      boundedGet(target, { ...options, timeoutMs: 5, fetch }),
      "timeout",
      "request timed out",
    );
  });

  it("maps an AbortError to the timeout failure", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockRejectedValue(new DOMException("x", "AbortError"));
    await expectFailure(boundedGet(target, { ...options, fetch }), "timeout", "request timed out");
  });

  it("maps transport failures without exposing the underlying error", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockRejectedValue(new Error("secret network detail"));
    await expectFailure(
      boundedGet(target, { ...options, fetch }),
      "network_failure",
      "request failed before a response",
    );
  });

  it("returns bytes and selected headers on success", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response("hello", {
        status: 200,
        headers: { "content-type": "application/json", "content-digest": "sha-256=:abc:" },
      }),
    );
    await expect(boundedGet(target, { ...options, fetch })).resolves.toEqual({
      bytes: Buffer.from("hello"),
      contentType: "application/json",
      contentDigest: "sha-256=:abc:",
    });
    const [, requestInit] = fetch.mock.calls[0] ?? [];
    expect(requestInit?.redirect).toBe("manual");
    expect(requestInit?.signal).toBeInstanceOf(AbortSignal);
  });
});
