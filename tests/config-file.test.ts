import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { parseYamlConfig, stringifyYaml } from "../src/config/load.js";

describe("configuration file format", () => {
  it("round-trips every key written by initIssuer", () => {
    const { attestbook: _attestbook, federation: _federation, ...persisted } = DEFAULT_CONFIG;

    expect(parseYamlConfig(stringifyYaml(persisted))).toEqual(persisted);
  });

  it("preserves empty, quoted, and invalid-JSON strings", () => {
    expect(
      parseYamlConfig(
        'empty: ""\ndouble: "quoted value"\nsingle: \'quoted value\'\nq: "value" # note\ninvalid: "a\\q"\nunclosed: "abc\n',
      ),
    ).toEqual({
      empty: "",
      double: "quoted value",
      single: "'quoted value'",
      q: 'value" # note',
      invalid: "a\\q",
      unclosed: "abc",
    });
  });

  it("distinguishes boolean literals from boolean strings case-sensitively", () => {
    expect(
      parseYamlConfig(
        'lower_true: true\nlower_false: false\nstring_true: "true"\nstring_false: "false"\nupper: FALSE\n',
      ),
    ).toEqual({
      lower_true: true,
      lower_false: false,
      string_true: "true",
      string_false: "false",
      upper: "FALSE",
    });
  });

  it("pins empty, numeric, Infinity, and null values", () => {
    expect(
      parseYamlConfig("bare:\nhex: 0x10\nexponent: 1e3\ninfinity: Infinity\nnull_value: null\n"),
    ).toEqual({
      bare: "",
      hex: 16,
      exponent: 1000,
      infinity: "Infinity",
      null_value: null,
    });
  });

  it("parses integer, negative, decimal, array, and object values", () => {
    expect(
      parseYamlConfig(
        'integer: 12\nnegative: -7\ndecimal: 1.25\narray: [1,"two"]\nobject: {"enabled":true}\n',
      ),
    ).toEqual({
      integer: 12,
      negative: -7,
      decimal: 1.25,
      array: [1, "two"],
      object: { enabled: true },
    });
  });

  it("keeps inline hash characters and accepts CRLF, blanks, comments, and duplicate keys", () => {
    expect(
      parseYamlConfig(
        "\r\n# ignored\r\ninline: text # not a comment\r\n\r\nvalue: first\r\nvalue: last\r\n",
      ),
    ).toEqual({ inline: "text # not a comment", value: "last" });
  });
});
