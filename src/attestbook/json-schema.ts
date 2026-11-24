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
 * than allowing claim data to replace a protocol field (SD-JWT VC Section 3.2.2).
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

/** SD-JWT's own members, reserved at every level of the payload. */
function isSdJwtReservedName(name: string): boolean {
  return name.startsWith("_sd") || name === "...";
}

type Report = (code: string, pointer: string, message: string) => void;

/**
 * Compiles the supported JSON Schema 2020-12 subset into the credential's claim tree: an object
 * root whose members are typed scalars (`string`, `integer`, `number`, `boolean` with their value
 * constraints), objects or arrays, at most four path segments deep. Every other construct is
 * reported rather than ignored, because silently dropping a constraint would issue a credential
 * the schema forbids.
 */
export function compileJsonSchema(
  schema: Record<string, unknown>,
  attestation: string,
  uri: string,
): { claims: AttestbookObjectClaim | null; diagnostics: AttestbookDiagnostic[] } {
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
    return { claims: null, diagnostics };
  }
  const counter = { nodes: 0 };
  const claims = compileObject(schema, "", 0, ROOT_KEYWORDS, report, counter, true);
  if (claims && claims.properties.length === 0) {
    report("schema_without_claims", "/properties", "the schema declares no claim properties");
  }
  return { claims: diagnostics.length === 0 ? claims : null, diagnostics };
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
  if (schema.type === "object") {
    return compileObject(schema, pointer, depth, OBJECT_KEYWORDS, report, counter, false);
  }
  if (schema.type === "array") return compileArray(schema, name, pointer, depth, report, counter);
  if (
    typeof schema.type !== "string" ||
    !SCALAR_TYPES.includes(schema.type as AttestbookScalarType)
  ) {
    report("unsupported_claim_type", `${pointer}/type`, `claim '${name}' must declare one type`);
    return null;
  }
  return compileScalar(schema, schema.type as AttestbookScalarType, name, pointer, report);
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
  const compiled: AttestbookClaimProperty[] = [];
  for (const [name, property] of Object.entries(properties)) {
    const propertyPointer = `${pointer}/properties/${escapePointer(name)}`;
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
  if (!valid) return null;
  return {
    kind: "object",
    properties: compiled,
    additionalProperties: schema.additionalProperties !== false,
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
    if (
      value !== undefined &&
      !(typeof value === "number" && Number.isInteger(value) && value >= 0)
    ) {
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

function compileScalar(
  schema: Record<string, unknown>,
  type: AttestbookScalarType,
  name: string,
  pointer: string,
  report: Report,
): AttestbookScalarClaim | null {
  let valid = unknownKeywords(schema, SCALAR_KEYWORDS, pointer, report);
  for (const keyword of [...STRING_BOUNDS, ...NUMBER_BOUNDS]) {
    const value = schema[keyword];
    if (value === undefined) continue;
    const applies = (STRING_BOUNDS as readonly string[]).includes(keyword)
      ? type === "string"
      : type === "integer" || type === "number";
    if (!applies || typeof value !== "number" || !Number.isFinite(value)) {
      report(
        "unsupported_schema_keyword",
        `${pointer}/${keyword}`,
        `'${keyword}' does not constrain a ${type} claim`,
      );
      valid = false;
    }
  }
  const enumValues = schema.enum;
  if (
    enumValues !== undefined &&
    (!Array.isArray(enumValues) ||
      enumValues.length === 0 ||
      !enumValues.every((value) => scalarOfType(value, type)))
  ) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/enum`,
      `enum of '${name}' must list ${type} values`,
    );
    valid = false;
  }
  if (schema.const !== undefined && !scalarOfType(schema.const, type)) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/const`,
      `const of '${name}' must be a ${type}`,
    );
    valid = false;
  }
  if (!valid) return null;
  const bounds: Record<string, number> = {};
  for (const keyword of [...STRING_BOUNDS, ...NUMBER_BOUNDS]) {
    const value = schema[keyword];
    if (typeof value === "number") bounds[keyword] = value;
  }
  return {
    kind: "scalar",
    type,
    displayName: typeof schema.title === "string" ? schema.title : null,
    selectivelyDisclosable: true,
    ...(Array.isArray(enumValues) ? { enum: enumValues as AttestbookScalarValue[] } : {}),
    ...(schema.const !== undefined ? { const: schema.const as AttestbookScalarValue } : {}),
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

/** Why a scalar value does not satisfy its claim, or null when it does. */
export function scalarValueError(claim: AttestbookScalarClaim, value: unknown): string | null {
  if (!scalarOfType(value, claim.type)) return `must be a ${claim.type}`;
  const scalar = value as AttestbookScalarValue;
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
