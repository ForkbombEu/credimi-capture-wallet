import { describe, expect, it } from "vitest";
import { claimValueErrors, compileJsonSchema } from "../src/attestbook/json-schema.js";

const attestation = "Example attestation";
const unsupportedType = (name: string) =>
  `claim '${name}' must declare string, integer, number, boolean, object or array, optionally with null; object and array cannot be combined with other types`;
const uri = "https://schemas.example/example.json";

function diagnostics(schema: Record<string, unknown>) {
  return compileJsonSchema(schema, attestation, uri).diagnostics;
}

function codes(schema: Record<string, unknown>) {
  return diagnostics(schema).map(({ code, field, message }) => ({ code, field, message }));
}

describe("Attestbook JSON Schema diagnostics", () => {
  it("reports dialect before an invalid root type", () => {
    expect(
      codes({ $schema: "https://json-schema.org/draft/2019-09/schema", type: "string" }),
    ).toEqual([
      {
        code: "unsupported_schema_dialect",
        field: `${uri}#/$schema`,
        message: "only the JSON Schema 2020-12 dialect is supported",
      },
      {
        code: "unsupported_schema_root",
        field: `${uri}#/type`,
        message: "the schema root must be of type 'object'",
      },
    ]);
  });

  it("reports a root schema without claim properties", () => {
    expect(codes({ type: "object", properties: {} })).toEqual([
      {
        code: "schema_without_claims",
        field: `${uri}#/properties`,
        message: "the schema declares no claim properties",
      },
    ]);
  });

  it("reports unsupported claim types", () => {
    expect(codes({ type: "object", properties: { value: { type: "null" } } })).toEqual([
      {
        code: "unsupported_claim_type",
        field: `${uri}#/properties/value/type`,
        message: unsupportedType("value"),
      },
    ]);
  });

  it("reports too many claims at the first claim over the node bound", () => {
    const properties: Record<string, unknown> = {};
    for (let index = 0; index < 257; index += 1) properties[`claim_${index}`] = { type: "string" };
    const result = compileJsonSchema({ type: "object", properties }, attestation, uri);
    expect(result.claims).toBeNull();
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]).toMatchObject({
      code: "too_many_claims",
      field: `${uri}#/properties/claim_256`,
      message: "at most 256 claims are supported",
    });
  });

  it("reports object keyword and structural errors in traversal order", () => {
    expect(
      codes({
        type: "object",
        additionalProperties: "sometimes",
        properties: "not-an-object",
      }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/additionalProperties`,
        message: "only a boolean additionalProperties is supported",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties`,
        message: "properties must be an object",
      },
    ]);
  });

  it("rejects an empty nested object", () => {
    expect(
      codes({ type: "object", properties: { nested: { type: "object", properties: {} } } }),
    ).toEqual([
      {
        code: "unsupported_claim_schema",
        field: `${uri}#/properties/nested`,
        message: "a nested object must declare its properties",
      },
    ]);
  });

  it("reports invalid required arrays and does not continue compiling them", () => {
    expect(
      codes({ type: "object", properties: { name: { type: "string" } }, required: ["name", 1] }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/required`,
        message: "required must be an array of names",
      },
    ]);
  });

  it("reports required names that have no property", () => {
    expect(
      codes({ type: "object", required: ["missing"], properties: { name: { type: "string" } } }),
    ).toEqual([
      {
        code: "required_claim_undeclared",
        field: `${uri}#/required`,
        message: "required claim 'missing' has no property",
      },
    ]);
  });

  it("reports a property that is not described by an object schema", () => {
    expect(codes({ type: "object", properties: { name: "string" } })).toEqual([
      {
        code: "unsupported_claim_schema",
        field: `${uri}#/properties/name`,
        message: "claim 'name' must be described by an object schema",
      },
    ]);
  });

  it("reports invalid array bounds in keyword order", () => {
    expect(
      codes({
        type: "object",
        properties: {
          values: {
            type: "array",
            minItems: -1,
            maxItems: "many",
            items: { type: "string" },
          },
        },
      }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/values/minItems`,
        message: "minItems must be a non-negative integer",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/values/maxItems`,
        message: "maxItems must be a non-negative integer",
      },
    ]);
  });

  it("retains unknown keyword diagnostics before scalar constraint diagnostics", () => {
    expect(
      codes({
        type: "object",
        properties: {
          value: {
            type: "string",
            pattern: "ignored-by-schema-subset",
            minimum: 4,
          },
        },
      }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/value/pattern`,
        message: "keyword 'pattern' is not supported here",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/value/minimum`,
        message: "'minimum' does not constrain a string claim",
      },
    ]);
  });

  it("reports unknown root keywords before additionalProperties and properties errors", () => {
    expect(
      codes({
        type: "object",
        oneOf: [],
        $defs: {},
        additionalProperties: "sometimes",
        properties: "not-an-object",
      }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/oneOf`,
        message: "keyword 'oneOf' is not supported here",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/$defs`,
        message: "keyword '$defs' is not supported here",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/additionalProperties`,
        message: "only a boolean additionalProperties is supported",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties`,
        message: "properties must be an object",
      },
    ]);
  });

  it("escapes claim names in diagnostic JSON pointers", () => {
    expect(codes({ type: "object", properties: { "a~b/c": { type: "null" } } })).toEqual([
      {
        code: "unsupported_claim_type",
        field: `${uri}#/properties/a~0b~1c/type`,
        message: unsupportedType("a~b/c"),
      },
    ]);
  });

  it("rejects claims deeper than the supported path depth", () => {
    let nested: Record<string, unknown> = { type: "null" };
    for (let index = 0; index < 5; index += 1) {
      nested = { type: "object", properties: { [`level_${index}`]: nested } };
    }
    const result = codes({ type: "object", properties: { deep: nested } });
    expect(result).toEqual([
      {
        code: "claim_too_deep",
        field: `${uri}#/properties/deep/properties/level_4/properties/level_3/properties/level_2/properties/level_1`,
        message: "claims may be at most 4 levels deep",
      },
    ]);
  });

  it("rejects protocol-reserved names at the root and nested levels", () => {
    expect(
      codes({
        type: "object",
        properties: {
          iss: { type: "string" },
          nested: { type: "object", properties: { _sd: { type: "string" } } },
        },
      }),
    ).toEqual([
      {
        code: "reserved_claim_name",
        field: `${uri}#/properties/iss`,
        message: "claim 'iss' is controlled by the issuer protocol",
      },
      {
        code: "reserved_claim_name",
        field: `${uri}#/properties/nested/properties/_sd`,
        message: "claim '_sd' is controlled by the issuer protocol",
      },
    ]);
  });

  it.each([
    ["missing items", undefined],
    ["tuple items", [{ type: "string" }]],
  ])("rejects array schemas with %s", (_name, items) => {
    const schema: Record<string, unknown> = { type: "array" };
    if (items !== undefined) schema.items = items;
    expect(
      codes({
        type: "object",
        properties: { values: schema },
      }),
    ).toEqual([
      {
        code: "unsupported_claim_schema",
        field: `${uri}#/properties/values/items`,
        message: "array claim 'values' must describe its items with one schema",
      },
    ]);
  });

  it("reports scalar bounds, enum and const diagnostics in order", () => {
    expect(
      codes({
        type: "object",
        properties: {
          value: {
            type: "string",
            minimum: 4,
            enum: [1],
            const: 5,
          },
        },
      }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/value/minimum`,
        message: "'minimum' does not constrain a string claim",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/value/enum`,
        message: "enum of 'value' must list string values",
      },
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/value/const`,
        message: "const of 'value' must be a string",
      },
    ]);
  });

  it("accepts type arrays: nullable claims and scalar unions with type-specific bounds", () => {
    const { claims, diagnostics } = compileJsonSchema(
      {
        type: "object",
        properties: {
          issuing_country: { type: ["string", "null"], minLength: 2, maxLength: 2 },
          code: { type: ["string", "integer"], minLength: 3, minimum: 100 },
          address: { type: ["object", "null"], properties: { city: { type: "string" } } },
        },
      },
      attestation,
      uri,
    );

    expect(diagnostics).toEqual([]);
    if (!claims) throw new Error("schema did not compile");
    expect(claimValueErrors(claims, { issuing_country: null, code: "ABC", address: null })).toEqual(
      [],
    );
    expect(claimValueErrors(claims, { code: 250 })).toEqual([]);
    expect(claimValueErrors(claims, { issuing_country: "ITA", code: 99 })).toEqual([
      "$.issuing_country is longer than 2",
      "$.code is below 100",
    ]);
    expect(claimValueErrors(claims, { code: true })).toEqual([
      "$.code must be a string or integer",
    ]);
  });

  it("rejects type arrays that combine object or array with other types", () => {
    expect(
      codes({
        type: "object",
        properties: {
          mixed: { type: ["object", "string"], properties: { a: { type: "string" } } },
          repeated: { type: ["string", "string"] },
          only_null: { type: ["null"] },
        },
      }),
    ).toEqual(
      ["mixed", "repeated", "only_null"].map((name) => ({
        code: "unsupported_claim_type",
        field: `${uri}#/properties/${name}/type`,
        message: unsupportedType(name),
      })),
    );
  });

  it("enforces minProperties on nested objects and refuses an invalid one", () => {
    const { claims, diagnostics } = compileJsonSchema(
      {
        type: "object",
        properties: {
          place_of_birth: {
            type: "object",
            properties: { country: { type: "string" }, locality: { type: "string" } },
            minProperties: 1,
          },
        },
      },
      attestation,
      uri,
    );

    expect(diagnostics).toEqual([]);
    if (!claims) throw new Error("schema did not compile");
    expect(claimValueErrors(claims, { place_of_birth: { country: "IT" } })).toEqual([]);
    expect(claimValueErrors(claims, { place_of_birth: {} })).toEqual([
      "$.place_of_birth has fewer than 1 members",
    ]);
    expect(
      codes({
        type: "object",
        properties: {
          place: { type: "object", properties: { a: { type: "string" } }, minProperties: -1 },
        },
      }),
    ).toEqual([
      {
        code: "unsupported_schema_keyword",
        field: `${uri}#/properties/place/minProperties`,
        message: "minProperties must be a non-negative integer",
      },
    ]);
  });

  it("compiles the root vct apart from the claims, and requires it to be a string", () => {
    const result = compileJsonSchema(
      {
        type: "object",
        required: ["vct", "given_name"],
        properties: {
          vct: { type: "string", const: "urn:eudi:pid:it:1" },
          given_name: { type: "string" },
        },
        additionalProperties: false,
      },
      attestation,
      uri,
    );

    expect(result.diagnostics).toEqual([]);
    expect(result.vct).toMatchObject({ types: ["string"], const: "urn:eudi:pid:it:1" });
    expect(result.claims?.properties.map((property) => property.name)).toEqual(["given_name"]);
    expect(
      codes({
        type: "object",
        properties: { vct: { type: ["string", "null"] }, given_name: { type: "string" } },
      }),
    ).toEqual([
      {
        code: "unsupported_vct_schema",
        field: `${uri}#/properties/vct/type`,
        message: "claim 'vct' must be a string",
      },
    ]);
  });
});
