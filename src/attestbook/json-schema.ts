import { isRecord } from "./snapshot.js";
import type {
  AttestbookClaimDefinition,
  AttestbookClaimType,
  AttestbookClaimValue,
  AttestbookDiagnostic,
} from "./types.js";

/** A claim as the JSON Schema alone describes it, before Type Metadata refines it. */
export type SchemaClaim = Omit<
  AttestbookClaimDefinition,
  "selectivelyDisclosable" | "displayName"
> & {
  readonly title: string | null;
};

const JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema";
const ROOT_KEYWORDS = new Set([
  "$schema",
  "$id",
  "$comment",
  "title",
  "description",
  "type",
  "properties",
  "required",
  "additionalProperties",
]);
const PROPERTY_KEYWORDS = new Set([
  "$comment",
  "title",
  "description",
  "examples",
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
const SCALAR_TYPES = new Set<AttestbookClaimType>(["string", "integer", "number", "boolean"]);
const MAX_CLAIMS = 128;

/**
 * Claims SD-JWT VC and the issuer control. A schema that names one is rejected rather than allowing
 * claim data to replace a protocol field (SD-JWT VC Section 3.2.2).
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
  "_sd",
  "_sd_alg",
  "...",
]);

/**
 * Compiles the supported JSON Schema 2020-12 subset into top-level scalar claims: an object root
 * with typed `string`, `integer`, `number` or `boolean` properties and their value constraints.
 * Every other construct, including nested objects and arrays, is reported rather than flattened or
 * ignored, because silently dropping a constraint would issue a credential the schema forbids.
 */
export function compileJsonSchema(
  schema: Record<string, unknown>,
  attestation: string,
  uri: string,
): { claims: SchemaClaim[]; diagnostics: AttestbookDiagnostic[] } {
  const diagnostics: AttestbookDiagnostic[] = [];
  const report = (code: string, pointer: string, message: string): void => {
    diagnostics.push({ severity: "error", code, attestation, field: `${uri}#${pointer}`, message });
  };

  for (const keyword of Object.keys(schema)) {
    if (!ROOT_KEYWORDS.has(keyword)) {
      report(
        "unsupported_schema_keyword",
        `/${escapePointer(keyword)}`,
        `keyword '${keyword}' is not supported`,
      );
    }
  }
  if (schema.$schema !== undefined && schema.$schema !== JSON_SCHEMA_2020_12) {
    report(
      "unsupported_schema_dialect",
      "/$schema",
      "only the JSON Schema 2020-12 dialect is supported",
    );
  }
  if (schema.type !== "object") {
    report("unsupported_schema_root", "/type", "the schema root must be of type 'object'");
  }
  if (
    schema.additionalProperties !== undefined &&
    typeof schema.additionalProperties !== "boolean"
  ) {
    report(
      "unsupported_schema_keyword",
      "/additionalProperties",
      "only a boolean additionalProperties is supported",
    );
  }
  const properties = schema.properties;
  if (!isRecord(properties) || Object.keys(properties).length === 0) {
    report("schema_without_claims", "/properties", "the schema declares no claim properties");
    return { claims: [], diagnostics };
  }
  if (Object.keys(properties).length > MAX_CLAIMS) {
    report("too_many_claims", "/properties", `at most ${MAX_CLAIMS} claims are supported`);
    return { claims: [], diagnostics };
  }
  const required = schema.required ?? [];
  if (!Array.isArray(required) || !required.every((name) => typeof name === "string")) {
    report("unsupported_schema_keyword", "/required", "required must be an array of names");
  }
  const requiredNames = new Set(
    Array.isArray(required) ? required.filter((name) => typeof name === "string") : [],
  );
  for (const name of requiredNames) {
    if (!(name in properties)) {
      report("required_claim_undeclared", "/required", `required claim '${name}' has no property`);
    }
  }

  const claims: SchemaClaim[] = [];
  for (const [name, property] of Object.entries(properties)) {
    const pointer = `/properties/${escapePointer(name)}`;
    if (RESERVED_CLAIM_NAMES.has(name) || name.startsWith("_sd")) {
      report(
        "reserved_claim_name",
        pointer,
        `claim '${name}' is controlled by the issuer protocol`,
      );
      continue;
    }
    if (!isRecord(property)) {
      report(
        "unsupported_claim_schema",
        pointer,
        `claim '${name}' must be described by an object schema`,
      );
      continue;
    }
    const claim = compileProperty(name, property, requiredNames.has(name), pointer, report);
    if (claim) claims.push(claim);
  }
  return { claims, diagnostics };
}

function compileProperty(
  name: string,
  property: Record<string, unknown>,
  required: boolean,
  pointer: string,
  report: (code: string, pointer: string, message: string) => void,
): SchemaClaim | null {
  const type = property.type;
  if (
    type === "object" ||
    type === "array" ||
    property.properties !== undefined ||
    property.items !== undefined
  ) {
    report(
      "unsupported_nested_claim",
      pointer,
      `claim '${name}' is nested; only top-level scalar claims are supported`,
    );
    return null;
  }
  if (typeof type !== "string" || !SCALAR_TYPES.has(type as AttestbookClaimType)) {
    report(
      "unsupported_claim_type",
      `${pointer}/type`,
      `claim '${name}' must declare one scalar type`,
    );
    return null;
  }
  const claimType = type as AttestbookClaimType;
  let valid = true;
  for (const keyword of Object.keys(property)) {
    if (!PROPERTY_KEYWORDS.has(keyword)) {
      report(
        "unsupported_schema_keyword",
        `${pointer}/${escapePointer(keyword)}`,
        `keyword '${keyword}' is not supported`,
      );
      valid = false;
    }
  }
  const stringOnly = ["minLength", "maxLength"];
  const numberOnly = ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"];
  for (const keyword of [...stringOnly, ...numberOnly]) {
    const value = property[keyword];
    if (value === undefined) continue;
    const applies = stringOnly.includes(keyword)
      ? claimType === "string"
      : claimType === "integer" || claimType === "number";
    if (!applies || typeof value !== "number" || !Number.isFinite(value)) {
      report(
        "unsupported_schema_keyword",
        `${pointer}/${keyword}`,
        `'${keyword}' does not constrain a ${claimType} claim`,
      );
      valid = false;
    }
  }
  const enumValues = property.enum;
  if (
    enumValues !== undefined &&
    (!Array.isArray(enumValues) ||
      enumValues.length === 0 ||
      !enumValues.every((value) => scalarOfType(value, claimType)))
  ) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/enum`,
      `enum of '${name}' must list ${claimType} values`,
    );
    valid = false;
  }
  if (property.const !== undefined && !scalarOfType(property.const, claimType)) {
    report(
      "unsupported_schema_keyword",
      `${pointer}/const`,
      `const of '${name}' must be a ${claimType}`,
    );
    valid = false;
  }
  if (!valid) return null;
  return {
    name,
    path: [name],
    type: claimType,
    required,
    title: typeof property.title === "string" ? property.title : null,
    ...(Array.isArray(enumValues) ? { enum: enumValues as AttestbookClaimValue[] } : {}),
    ...(property.const !== undefined ? { const: property.const as AttestbookClaimValue } : {}),
    ...numericConstraint(property, "minLength"),
    ...numericConstraint(property, "maxLength"),
    ...numericConstraint(property, "minimum"),
    ...numericConstraint(property, "maximum"),
    ...numericConstraint(property, "exclusiveMinimum"),
    ...numericConstraint(property, "exclusiveMaximum"),
  };
}

function numericConstraint(
  property: Record<string, unknown>,
  keyword: string,
): Record<string, number> {
  const value = property[keyword];
  return typeof value === "number" ? { [keyword]: value } : {};
}

function scalarOfType(value: unknown, type: AttestbookClaimType): boolean {
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

/** Why a value does not satisfy a compiled claim, or null when it does. */
export function claimValueError(claim: AttestbookClaimDefinition, value: unknown): string | null {
  if (!scalarOfType(value, claim.type)) return `must be a ${claim.type}`;
  const scalar = value as AttestbookClaimValue;
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

function escapePointer(segment: string): string {
  return segment.replaceAll("~", "~0").replaceAll("/", "~1");
}
