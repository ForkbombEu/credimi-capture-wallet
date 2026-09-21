import { describe, expect, it } from "vitest";
import {
  isJsonPointer,
  readJsonPointer,
  setJsonPointer,
  unsetJsonPointer,
} from "../src/json-pointer.js";
import type { JsonRecord } from "../src/types.js";

describe("JSON Pointer member addressing", () => {
  it("addresses keys that contain the dots and plus signs used by EUDI protocols", () => {
    const document: JsonRecord = {
      client_metadata: {
        vp_formats_supported: { "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] } },
      },
      credential: { "eu.europa.ec.eudi.pid.1": { family_name: "Rossi" } },
    };

    expect(readJsonPointer(document, "/credential/eu.europa.ec.eudi.pid.1/family_name")).toBe(
      "Rossi",
    );
    setJsonPointer(document, "/client_metadata/vp_formats_supported/dc+sd-jwt/kb-jwt_alg_values", [
      "ES384",
    ]);

    expect(
      readJsonPointer(
        document,
        "/client_metadata/vp_formats_supported/dc+sd-jwt/kb-jwt_alg_values",
      ),
    ).toEqual(["ES384"]);
  });

  it("distinguishes a member set to null from a removed member", () => {
    const document: JsonRecord = {
      state: "abc",
      response_uri: "https://verifier.example/response",
    };

    setJsonPointer(document, "/state", null);
    unsetJsonPointer(document, "/response_uri");

    expect(Object.hasOwn(document, "state")).toBe(true);
    expect(document.state).toBeNull();
    expect(JSON.parse(JSON.stringify(document))).toEqual({ state: null });
  });

  it("unescapes ~1 and ~0 tokens", () => {
    const document: JsonRecord = { "a/b": { "c~d": 1 } };

    expect(readJsonPointer(document, "/a~1b/c~0d")).toBe(1);
  });

  it("addresses array members and appends with '-'", () => {
    const document: JsonRecord = { keys: [{ kid: "one" }, { kid: "two" }] };

    setJsonPointer(document, "/keys/0/alg", "ECDH-ES");
    setJsonPointer(document, "/keys/-", { kid: "three" });
    unsetJsonPointer(document, "/keys/1");

    expect(document.keys).toEqual([{ kid: "one", alg: "ECDH-ES" }, { kid: "three" }]);
  });

  it("creates missing intermediate objects when setting", () => {
    const document: JsonRecord = {};

    setJsonPointer(document, "/verifier_info/0/format", "jwt");

    expect(document).toEqual({ verifier_info: { "0": { format: "jwt" } } });
  });

  it("refuses to traverse a non-container member", () => {
    const document: JsonRecord = { nonce: "abc" };

    expect(() => setJsonPointer(document, "/nonce/inner", 1)).toThrow("non-container member");
  });

  it("reports a removal that matched nothing", () => {
    expect(unsetJsonPointer({ nonce: "abc" }, "/state")).toBe(false);
    expect(unsetJsonPointer({ nonce: "abc" }, "/client_metadata/jwks")).toBe(false);
  });

  it("rejects pointers that are not RFC 6901 member references", () => {
    expect(isJsonPointer("/response_uri")).toBe(true);
    expect(isJsonPointer("response_uri")).toBe(false);
    expect(isJsonPointer("")).toBe(false);
    expect(isJsonPointer(42)).toBe(false);
  });
});
