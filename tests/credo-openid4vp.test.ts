import { describe, expect, it } from "vitest";
import { toJsonSafe } from "../src/credo-openid4vp.js";

describe("Credo OpenID4VP decoded presentation helpers", () => {
  it("normalizes common JavaScript values to JSON-safe values", () => {
    const circular: Record<string, unknown> = { name: "loop" };
    circular.self = circular;
    const value = {
      date: new Date("2026-01-02T03:04:05.000Z"),
      map: new Map<unknown, unknown>([["claim", "value"]]),
      set: new Set(["a", "b"]),
      bytes: new Uint8Array([1, 2, 3]),
      buffer: Buffer.from([4, 5, 6]),
      bigint: 123n,
      json: { toJSON: () => ({ public: true }) },
      circular,
    };

    expect(toJsonSafe(value)).toEqual({
      date: "2026-01-02T03:04:05.000Z",
      map: { claim: "value" },
      set: ["a", "b"],
      bytes: { $type: "bytes", base64url: "AQID" },
      buffer: { $type: "bytes", base64url: "BAUG" },
      bigint: "123",
      json: { public: true },
      circular: {
        name: "loop",
        self: "[Circular]",
      },
    });
  });
});
