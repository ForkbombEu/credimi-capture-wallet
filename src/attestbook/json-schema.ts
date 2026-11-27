import { isRecord } from "../shared/json.js";
import type {
  AttestbookArrayClaim,
  AttestbookClaimNode,
  AttestbookClaimProperty,
  AttestbookDiagnostic,
  AttestbookObjectClaim,
  AttestbookScalarClaim,
  AttestbookScalarType,
  AttestbookScalarValue,
} from "./types.js";

const JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema";
/** Claim path segments below the payload root, counting an array's elements as one. */
const MAX_CLAIM_DEPTH = 4;
const MAX_CLAIM_NODES = 256;

const ANNOTATIONS = ["$comment", "title", "description", "examples"];
const ROOT_KEYWORDS = new Set([
  "$schema",
  "$id",
  ...ANNOTATIONS,
  "type",
  "properties",
  "required",
  "additionalProperties",
]);
const OBJECT_KEYWORDS = new Set([
  ...ANNOTATIONS,
  "type",
  "properties",
  "required",
  "additionalProperties",
  "minProperties",
]);
const ARRAY_KEYWORDS = new Set([...ANNOTATIONS, "type", "items", "minItems", "maxItems"]);
const SCALAR_KEYWORDS = new Set([
  ...ANNOTATIONS,
  "type",
  "enum",
  "const",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
]);
const SCALAR_TYPES: readonly AttestbookScalarType[] = ["string", "integer", "number", "boolean"];
const STRING_BOUNDS = ["minLength", "maxLength"] as const;
const NUMBER_BOUNDS = ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] as const;

/**
 * Top-level claims SD-JWT VC and the issuer control. A schema that names one is rejected rather
 * than allowing claim data to replace a protocol field (SD-JWT VC Section 3.2.2). The exception is
 * `vct`: a schema may constrain the credential type, so its `vct` property is compiled apart from
 * the claims, and the issuer still sets the value.
 */
export const RESERVED_CLAIM_NAMES = new Set([
  "iss",
  "sub",
  "iat",
  "nbf",
  "exp",
  "cnf",
  "vct",
  "vct#integrity",
  "status",
]);

/** The root property that describes the protocol `vct` rather than a claim. */
const VCT_CLAIM = "vct";

/** SD-JWT's own members, reserved at every level of the payload. */
function isSdJwtReservedName(name: string): boolean {
  return name.startsWith("_sd") || name === "...";
}

type Report = (code: string, pointer: string, message: string) => void;

/**
 * Compiles the supported JSON Schema 2020-12 subset into the credential's claim tree: an object
 * root whose members are typed scalars (`string`, `integer`, `number`, `boolean` with their value
 * constraints), objects or arrays, at most four path segments deep. A `type` array may combine
 * scalar types, and any one type with `null`. The root `vct` property is not a claim: it
 * constrains the protocol `vct` and is returned apart. Every other construct is reported rather
 * than ignored, because silently dropping a constraint would issue a credential the schema forbids.
 */
export function compileJsonSchema(
  schema: Record<string, unknown>,
  attestation: string,
  uri: string,
): {
  claims: AttestbookObjectClaim | null;
  vct: AttestbookScalarClaim | null;
  diagnostics: AttestbookDiagnostic[];
} {
  const diagnostics: AttestbookDiagnostic[] = [];
  const report: Report = (code, pointer, message) => {
    diagnostics.push({ severity: "error", code, attestation, field: `${uri}#${pointer}`, message });
  };
  if (schema.$schema !== undefined && schema.$schema !== JSON_SCHEMA_2020_12) {
    report(
      "unsupported_schema_dialect",
      "/$schema",
      "only the JSON Schema 2020-12 dialect is supported",
    );
  }
  if (schema.type !== "object") {
    report("unsupported_schema_root", "/type", "the schema root must be of type 'object'");
    return { claims: null, vct: null, diagnostics };
  }
  const counter = { nodes: 0 };
  const claims = compileObject(schema, "", 0, ROOT_KEYWORDS, report, counter, true);
  const properties = isRecord(schema.properties) ? schema.properties : {};
  const vct = VCT_CLAIM in properties ? compileVct(properties[VCT_CLAIM], report, counter) : null;
  if (claims && claims.properties.length === 0) {
    report("schema_without_claims", "/properties", "the schema declares no claim properties");
  }
  const valid = diagnostics.length === 0;
  return { claims: valid ? claims : null, vct: valid ? vct : null, diagnostics };
}

/**
 * The schema of the protocol `vct`, which SD-JWT VC Section 2.2.2.1 makes a string. It is compiled
 * like a claim to read its constraints, but it is never generated or selectively disclosed.
 */
function compileVct(
  schema: unknown,
  report: Report,
  counter: { nodes: number },
): AttestbookScalarClaim | null {
  const pointer = `/properties/${VCT_CLAIM}`;
  if (!isRecord(schema)) {
    report(
      "unsupported_claim_schema",
      pointer,
      `claim '${VCT_CLAIM}' must be described by an object schema`,
    );
    return null;
  }
  const node = compileNode(schema, VCT_CLAIM, pointer, 1, report, counter);
  if (!node) return null;
  if (
    node.kind !== "scalar" ||
    node.nullable ||
    node.types.length !== 1 ||
    node.types[0] !== "string"
  ) {
    report("unsupported_vct_schema", `${pointer}/type`, `claim '${VCT_CLAIM}' must be a string`);
    return null;
  }
  return node;
}

type DeclaredType =
  | { readonly kind: "object" | "array"; readonly nullable: boolean }
  | {
      readonly kind: "scalar";
      readonly types: readonly AttestbookScalarType[];
      readonly nullable: boolean;
    };

/**
 * A schema `type`: one name, or an array of unique names (JSON Schema 2020-12 validation
 * Section 6.1.1). `null` makes the claim nullable, several scalar types make a union, and `object`
 * or `array` stand alone. Null when the declaration is outside that subset.
 */
function declaredType(type: unknown): DeclaredType | null {
  const names: unknown[] = Array.isArray(type) ? type : [type];
  if (names.length === 0 || new Set(names).size !== names.length) return null;
  const nullable = names.includes("null");
  const others = names.filter((name) => name !== "null");
  const [first] = others;
  if (others.length === 1 && (first === "object" || first === "array")) {
    return { kind: first, nullable };
  }
  if (others.length === 0 || !others.every(isScalarType)) return null;
  return { kind: "scalar", types: others, nullable };
}

/**
 * The `type` of a claim schema. Without one, a `const` or `enum` of scalar or null values still
 * fixes the JSON types its value can have (JSON Schema 2020-12 validation Sections 6.1.2-6.1.3),
 * so they are the claim's types; otherwise the type is unknown.
 */
function claimType(schema: Record<string, unknown>): unknown {
  if (schema.type !== undefined) return schema.type;
  const values =
    schema.const !== undefined ? [schema.const] : Array.isArray(schema.enum) ? schema.enum : [];
  const names = values.map((value: unknown) =>
    value === null
      ? "null"
      : typeof value === "number" && Number.isInteger(value)
        ? "integer"
        : typeof value,
  );
  if (names.length === 0 || !names.every((name) => name === "null" || isScalarType(name))) {
    return undefined;
  }
  return [...new Set(names)];
}

function compileNode(
  schema: Record<string, unknown>,
  name: string,
  pointer: string,
  depth: number,
  report: Report,
  counter: { nodes: number },
): AttestbookClaimNode | null {
  counter.nodes += 1;
  if (counter.nodes > MAX_CLAIM_NODES) {
    report("too_many_claims", pointer, `at most ${MAX_CLAIM_NODES} claims are supported`);
    return null;
  }
  if (depth > MAX_CLAIM_DEPTH) {
    report("claim_too_deep", pointer, `claims may be at most ${MAX_CLAIM_DEPTH} levels deep`);
    return null;
  }
  const declared = declaredType(claimType(schema));
  if (!declared) {
    report(
      "unsupported_claim_type",
      `${pointer}/type`,
      `claim '${name}' must declare string, integer, number, boolean, object or array, optionally with null, or a scalar const or enum; object and array cannot be combined with other types`,
    );
    return null;
  }
  if (declared.kind === "scalar") {
    return compileScalar(schema, declared.types, declared.nullable, name, pointer, report);
  }
  const node =
    declared.kind === "object"
      ? compileObject(schema, pointer, depth, OBJECT_KEYWORDS, report, counter, false)
      : compileArray(schema, name, pointer, depth, report, counter);
  return node && declared.nullable ? { ...node, nullable: true } : node;
}

interface ObjectShape {
  readonly valid: boolean;
  readonly properties: Record<string, unknown>;
  readonly required: readonly string[];
}

function validateObjectShape(
  schema: Record<string, unknown>,
  pointer: string,
  keywords: ReadonlySet<string>,
  report: Report,
  root: boolean,
): ObjectShape | null {
  let valid = unknownKeywords(schema, keywords, pointer, report);
  if (
    schema.additionalProperties !== undefined &&
    typeof schema.additionalProperties !== "boolean"
  ) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/additionalProperties`,
      "only a boolean additionalProperties is supported",
    );
    valid = false;
  }
  if (
    keywords.has("minProperties") &&
    schema.minProperties !== undefined &&
    !isNonNegativeInteger(schema.minProperties)
  ) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/minProperties`,
      "minProperties must be a non-negative integer",
    );
    valid = false;
  }
  const properties = schema.properties ?? {};
  if (!isRecord(properties)) {
    report("unsupported_schema_keyword", `${pointer}/properties`, "properties must be an object");
    return null;
  }
  if (!root && Object.keys(properties).length === 0) {
    report("unsupported_claim_schema", pointer, "a nested object must declare its properties");
    valid = false;
  }
  const required = schema.required ?? [];
  if (!Array.isArray(required) || !required.every((name) => typeof name === "string")) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/required`,
      "required must be an array of names",
    );
    return null;
  }
  for (const name of required) {
    if (!(name in properties)) {
      report(
        "required_claim_undeclared",
        `${pointer}/required`,
        `required claim '${name}' has no property`,
      );
      valid = false;
    }
  }
  return { valid, properties, required };
}

function compileProperties(
  properties: Record<string, unknown>,
  required: readonly string[],
  pointer: string,
  depth: number,
  report: Report,
  counter: { nodes: number },
  root: boolean,
): { properties: AttestbookClaimProperty[]; valid: boolean } {
  let valid = true;
  const compiled: AttestbookClaimProperty[] = [];
  for (const [name, property] of Object.entries(properties)) {
    const propertyPointer = `${pointer}/properties/${escapePointer(name)}`;
    // Compiled apart by compileVct: it constrains the protocol vct, not a claim.
    if (root && name === VCT_CLAIM) continue;
    if ((root && RESERVED_CLAIM_NAMES.has(name)) || isSdJwtReservedName(name)) {
      report(
        "reserved_claim_name",
        propertyPointer,
        `claim '${name}' is controlled by the issuer protocol`,
      );
      valid = false;
      continue;
    }
    if (!isRecord(property)) {
      report(
        "unsupported_claim_schema",
        propertyPointer,
        `claim '${name}' must be described by an object schema`,
      );
      valid = false;
      continue;
    }
    const node = compileNode(property, name, propertyPointer, depth + 1, report, counter);
    if (!node) {
      valid = false;
      continue;
    }
    compiled.push({ name, required: required.includes(name), node });
  }
  return { properties: compiled, valid };
}

function compileObject(
  schema: Record<string, unknown>,
  pointer: string,
  depth: number,
  keywords: ReadonlySet<string>,
  report: Report,
  counter: { nodes: number },
  root: boolean,
): AttestbookObjectClaim | null {
  const shape = validateObjectShape(schema, pointer, keywords, report, root);
  if (!shape) return null;
  const compiled = compileProperties(
    shape.properties,
    shape.required,
    pointer,
    depth,
    report,
    counter,
    root,
  );
  if (!shape.valid || !compiled.valid) return null;
  return {
    kind: "object",
    properties: compiled.properties,
    additionalProperties: schema.additionalProperties !== false,
    ...(typeof schema.minProperties === "number" ? { minProperties: schema.minProperties } : {}),
    displayName: typeof schema.title === "string" ? schema.title : null,
    selectivelyDisclosable: true,
  };
}

function compileArray(
  schema: Record<string, unknown>,
  name: string,
  pointer: string,
  depth: number,
  report: Report,
  counter: { nodes: number },
): AttestbookArrayClaim | null {
  let valid = unknownKeywords(schema, ARRAY_KEYWORDS, pointer, report);
  for (const keyword of ["minItems", "maxItems"] as const) {
    const value = schema[keyword];
    if (value !== undefined && !isNonNegativeInteger(value)) {
      report(
        "unsupported_schema_keyword",
        `${pointer}/${keyword}`,
        `${keyword} must be a non-negative integer`,
      );
      valid = false;
    }
  }
  if (!isRecord(schema.items)) {
    report(
      "unsupported_claim_schema",
      `${pointer}/items`,
      `array claim '${name}' must describe its items with one schema`,
    );
    return null;
  }
  const items = compileNode(schema.items, name, `${pointer}/items`, depth + 1, report, counter);
  if (!items || !valid) return null;
  return {
    kind: "array",
    items,
    ...(typeof schema.minItems === "number" ? { minItems: schema.minItems } : {}),
    ...(typeof schema.maxItems === "number" ? { maxItems: schema.maxItems } : {}),
    displayName: typeof schema.title === "string" ? schema.title : null,
    selectivelyDisclosable: true,
  };
}

function checkScalarKeywords(
  schema: Record<string, unknown>,
  types: readonly AttestbookScalarType[],
  nullable: boolean,
  name: string,
  pointer: string,
  report: Report,
): boolean {
  let valid = unknownKeywords(schema, SCALAR_KEYWORDS, pointer, report);
  const label = types.join(" or ");
  for (const keyword of [...STRING_BOUNDS, ...NUMBER_BOUNDS]) {
    const value = schema[keyword];
    if (value === undefined) continue;
    // As in JSON Schema, a bound constrains the values of its type and ignores the others.
    const applies = (STRING_BOUNDS as readonly string[]).includes(keyword)
      ? types.includes("string")
      : types.includes("integer") || types.includes("number");
    if (!applies || typeof value !== "number" || !Number.isFinite(value)) {
      report(
        "unsupported_schema_keyword",
        `${pointer}/${keyword}`,
        `'${keyword}' does not constrain a ${label} claim`,
      );
      valid = false;
    }
  }
  const admits = (value: unknown) =>
    value === null ? nullable : types.some((type) => scalarOfType(value, type));
  const valuesLabel = nullable ? `${label} or null` : label;
  const enumValues = schema.enum;
  if (
    enumValues !== undefined &&
    (!Array.isArray(enumValues) || enumValues.length === 0 || !enumValues.every(admits))
  ) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/enum`,
      `enum of '${name}' must list ${valuesLabel} values`,
    );
    valid = false;
  }
  if (schema.const !== undefined && !admits(schema.const)) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/const`,
      `const of '${name}' must be a ${valuesLabel}`,
    );
    valid = false;
  }
  return valid;
}

function compileScalar(
  schema: Record<string, unknown>,
  types: readonly AttestbookScalarType[],
  nullable: boolean,
  name: string,
  pointer: string,
  report: Report,
): AttestbookScalarClaim | null {
  if (!checkScalarKeywords(schema, types, nullable, name, pointer, report)) return null;
  const enumValues = schema.enum;
  const bounds: Record<string, number> = {};
  for (const keyword of [...STRING_BOUNDS, ...NUMBER_BOUNDS]) {
    const value = schema[keyword];
    if (typeof value === "number") bounds[keyword] = value;
  }
  return {
    kind: "scalar",
    types,
    ...(nullable ? { nullable } : {}),
    displayName: typeof schema.title === "string" ? schema.title : null,
    selectivelyDisclosable: true,
    ...(Array.isArray(enumValues) ? { enum: enumValues as (AttestbookScalarValue | null)[] } : {}),
    ...(schema.const !== undefined ? { const: schema.const as AttestbookScalarValue | null } : {}),
    ...bounds,
  };
}

function unknownKeywords(
  schema: Record<string, unknown>,
  keywords: ReadonlySet<string>,
  pointer: string,
  report: Report,
): boolean {
  let valid = true;
  for (const keyword of Object.keys(schema)) {
    if (!keywords.has(keyword)) {
      report(
        "unsupported_schema_keyword",
        `${pointer}/${escapePointer(keyword)}`,
        `keyword '${keyword}' is not supported here`,
      );
      valid = false;
    }
  }
  return valid;
}

function scalarOfType(value: unknown, type: AttestbookScalarType): boolean {
  switch (type) {
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
  }
}

function isScalarType(value: unknown): value is AttestbookScalarType {
  return SCALAR_TYPES.includes(value as AttestbookScalarType);
}

function isNonNegativeInteger(value: unknown): boolean {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/** Why a scalar value does not satisfy its claim, or null when it does. */
export function scalarValueError(claim: AttestbookScalarClaim, value: unknown): string | null {
  if (value === null ? !claim.nullable : !claim.types.some((type) => scalarOfType(value, type))) {
    return `must be a ${claim.types.join(" or ")}${claim.nullable ? " or null" : ""}`;
  }
  const scalar = value as AttestbookScalarValue | null;
  if (claim.const !== undefined && scalar !== claim.const) return "does not equal the schema const";
  if (claim.enum && !claim.enum.includes(scalar)) return "is not one of the schema enum values";
  if (typeof scalar === "string") {
    const length = [...scalar].length;
    if (claim.minLength !== undefined && length < claim.minLength)
      return `is shorter than ${claim.minLength}`;
    if (claim.maxLength !== undefined && length > claim.maxLength)
      return `is longer than ${claim.maxLength}`;
  }
  if (typeof scalar === "number") {
    if (claim.minimum !== undefined && scalar < claim.minimum) return `is below ${claim.minimum}`;
    if (claim.maximum !== undefined && scalar > claim.maximum) return `is above ${claim.maximum}`;
    if (claim.exclusiveMinimum !== undefined && scalar <= claim.exclusiveMinimum) {
      return `is not above ${claim.exclusiveMinimum}`;
    }
    if (claim.exclusiveMaximum !== undefined && scalar >= claim.exclusiveMaximum) {
      return `is not below ${claim.exclusiveMaximum}`;
    }
  }
  return null;
}

/** Every way a value violates a claim tree, each prefixed with its claim path; empty when valid. */
export function claimValueErrors(node: AttestbookClaimNode, value: unknown, path = "$"): string[] {
  if (node.kind === "scalar") {
    const error = scalarValueError(node, value);
    return error ? [`${path} ${error}`] : [];
  }
  if (value === null && node.nullable) return [];
  if (node.kind === "array") {
    if (!Array.isArray(value)) return [`${path} must be an array`];
    if (node.minItems !== undefined && value.length < node.minItems)
      return [`${path} has fewer than ${node.minItems} items`];
    if (node.maxItems !== undefined && value.length > node.maxItems)
      return [`${path} has more than ${node.maxItems} items`];
    return value.flatMap((element, index) =>
      claimValueErrors(node.items, element, `${path}[${index}]`),
    );
  }
  if (!isRecord(value)) return [`${path} must be an object`];
  const errors: string[] = [];
  if (node.minProperties !== undefined && Object.keys(value).length < node.minProperties) {
    errors.push(`${path} has fewer than ${node.minProperties} members`);
  }
  for (const property of node.properties) {
    const memberPath = `${path}.${property.name}`;
    if (!(property.name in value)) {
      if (property.required) errors.push(`${memberPath} is required`);
      continue;
    }
    errors.push(...claimValueErrors(property.node, value[property.name], memberPath));
  }
  for (const name of Object.keys(value)) {
    if (!node.properties.some((property) => property.name === name)) {
      errors.push(`${path}.${name} is not a declared claim`);
    }
  }
  return errors;
}

function escapePointer(segment: string): string {
  return segment.replaceAll("~", "~0").replaceAll("/", "~1");
}
