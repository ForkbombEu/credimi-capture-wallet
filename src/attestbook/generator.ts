import { createRequire } from "node:module";
import { Faker, base, en } from "@faker-js/faker";
import { PID_PORTRAIT_JPEG } from "../configurations/shared/pid-data.js";
import { sha256Hex } from "./digest.js";
import { claimValueErrors, scalarValueError } from "./json-schema.js";
import type {
  AttestbookClaimNode,
  AttestbookCredentialDefinition,
  AttestbookScalarClaim,
  AttestbookScalarValue,
  AttestbookStringFormat,
} from "./types.js";

/** The exact generator, recorded with every generated claim set: values depend on its version. */
export const CLAIM_GENERATOR = `@faker-js/faker@${
  (createRequire(import.meta.url)("@faker-js/faker/package.json") as { version: string }).version
}`;

/**
 * Faker's date helpers are relative to a reference date, which defaults to the current time. A
 * fixed reference keeps a seed's values identical whenever they are regenerated.
 */
export const CLAIM_GENERATION_REFERENCE_DATE = "2026-01-01T00:00:00.000Z";

const MAX_ATTEMPTS = 20;
const DEFAULT_ARRAY_MAX = 3;
const DEFAULT_STRING_SPAN = 12;
const DEFAULT_NUMBER_SPAN = 1000;

export type GeneratedClaims = Record<string, unknown>;

/**
 * Synthetic claim values cannot satisfy the schema's constraints.
 * @internal
 */
export class ClaimGenerationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClaimGenerationError";
  }
}

/**
 * Generates synthetic values for every claim of a definition, optional ones included, from a seed.
 * The same seed, generator version and definition always produce the same values. Values are
 * chosen by claim name where a name suggests a kind of data (`given_name`, `email`, `birthdate`…)
 * and always within the schema's constraints: `const`, a seeded random `enum` member, string
 * lengths, numeric bounds and array sizes. Values that cannot satisfy the schema throw.
 */
export function generateClaims(
  definition: AttestbookCredentialDefinition,
  seed: string,
): GeneratedClaims {
  const faker = new Faker({ locale: [en, base] });
  faker.seed(seedNumbers(seed));
  faker.setDefaultRefDate(CLAIM_GENERATION_REFERENCE_DATE);
  const claims = generateNode(definition.claims, "", "$", faker) as GeneratedClaims;
  const errors = claimValueErrors(definition.claims, claims);
  if (errors.length > 0) throw new ClaimGenerationError(errors.join("; "));
  return claims;
}

function generateNode(
  node: AttestbookClaimNode,
  name: string,
  path: string,
  faker: Faker,
): unknown {
  switch (node.kind) {
    case "object":
      return Object.fromEntries(
        node.properties.map((property) => [
          property.name,
          generateNode(property.node, property.name, `${path}.${property.name}`, faker),
        ]),
      );
    case "array": {
      const min = node.minItems ?? 1;
      const max = node.maxItems ?? Math.max(min, DEFAULT_ARRAY_MAX);
      if (min > max) throw new ClaimGenerationError(`${path} requires more than ${max} items`);
      const count = faker.number.int({ min, max });
      return Array.from({ length: count }, (_, index) =>
        generateNode(node.items, name, `${path}[${index}]`, faker),
      );
    }
    case "scalar":
      return generateScalar(node, name, path, faker);
  }
}

function generateScalar(
  claim: AttestbookScalarClaim,
  name: string,
  path: string,
  faker: Faker,
): AttestbookScalarValue | null {
  if (claim.const !== undefined) return claim.const;
  if (claim.enum) {
    const allowed = claim.enum.filter(
      (value) => scalarValueError({ ...claim, enum: undefined }, value) === null,
    );
    // A nullable claim still gets a value whenever its enum lists one.
    const values = allowed.filter((value) => value !== null);
    if (allowed.length === 0)
      throw new ClaimGenerationError(`${path} has no enum value within its constraints`);
    return faker.helpers.arrayElement(values.length > 0 ? values : allowed);
  }
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const candidate = scalarCandidate(claim, name, path, faker, attempt);
    if (scalarValueError(claim, candidate) === null) return candidate;
  }
  throw new ClaimGenerationError(
    `${path} has no ${claim.types.join(" or ")} value within its constraints`,
  );
}

/**
 * The first attempt follows the claim name; later ones only aim at the constraints. A union
 * tries its types in turn, starting with the first declared.
 */
function scalarCandidate(
  claim: AttestbookScalarClaim,
  name: string,
  path: string,
  faker: Faker,
  attempt: number,
): AttestbookScalarValue {
  const type = claim.types[attempt % claim.types.length];
  if (type === undefined) throw new ClaimGenerationError(`${path} declares no type`);
  switch (type) {
    case "boolean":
      return faker.datatype.boolean();
    case "integer": {
      const [min, max] = numberRange(claim, name, path, true);
      return faker.number.int({ min, max });
    }
    case "number": {
      const [min, max] = numberRange(claim, name, path, false);
      return faker.number.float({ min, max, fractionDigits: 2 });
    }
    case "string": {
      if (claim.format) return formattedDate(claim.format, name, faker);
      if (claim.contentEncoding === "base64") return base64Content(claim, faker);
      if (attempt === 0) {
        const named = namedString(name, faker);
        if (scalarValueError(claim, named) === null) return named;
      }
      const min = claim.minLength ?? 1;
      const max = claim.maxLength ?? min + DEFAULT_STRING_SPAN;
      if (min > max)
        throw new ClaimGenerationError(`${path} requires a length between ${min} and ${max}`);
      return faker.string.alphanumeric({ length: { min, max } });
    }
  }
}

function numberRange(
  claim: AttestbookScalarClaim,
  name: string,
  path: string,
  integer: boolean,
): [number, number] {
  const step = integer ? 1 : 0.01;
  const lower = Math.max(
    claim.minimum ?? Number.NEGATIVE_INFINITY,
    claim.exclusiveMinimum === undefined ? Number.NEGATIVE_INFINITY : claim.exclusiveMinimum + step,
  );
  const upper = Math.min(
    claim.maximum ?? Number.POSITIVE_INFINITY,
    claim.exclusiveMaximum === undefined ? Number.POSITIVE_INFINITY : claim.exclusiveMaximum - step,
  );
  const [preferredMin, preferredMax] = /(^|_)age($|_)/.test(name.toLowerCase())
    ? [18, 90]
    : /year/.test(name.toLowerCase())
      ? [1950, 2030]
      : [0, DEFAULT_NUMBER_SPAN];
  let min = Number.isFinite(lower) ? lower : Math.min(preferredMin, upper - DEFAULT_NUMBER_SPAN);
  let max = Number.isFinite(upper) ? upper : Math.max(preferredMax, min + DEFAULT_NUMBER_SPAN);
  if (Math.max(min, preferredMin) <= Math.min(max, preferredMax)) {
    min = Math.max(min, preferredMin);
    max = Math.min(max, preferredMax);
  }
  if (integer) {
    min = Math.ceil(min);
    max = Math.floor(max);
  }
  if (min > max) throw new ClaimGenerationError(`${path} has an empty numeric range`);
  return [min, max];
}

/** An RFC 3339 date in the past or, for an expiry, the future; a birth date by the name. */
function formattedDate(format: AttestbookStringFormat, name: string, faker: Faker): string {
  const key = name.toLowerCase();
  const date = /birth/.test(key)
    ? faker.date.birthdate()
    : /expir|valid_until/.test(key)
      ? faker.date.future({ years: 10 })
      : faker.date.past({ years: 10 });
  // Whole seconds in UTC, as the EUDI rulebook template asks of `tdate`.
  return format === "date" ? isoDate(date) : `${date.toISOString().slice(0, 19)}Z`;
}

/** Base64 content: the sample JPEG portrait for `image/jpeg`, random bytes otherwise. */
function base64Content(claim: AttestbookScalarClaim, faker: Faker): string {
  const bytes =
    claim.contentMediaType === "image/jpeg"
      ? PID_PORTRAIT_JPEG
      : Uint8Array.from({ length: 32 }, () => faker.number.int(255));
  return Buffer.from(bytes).toString("base64");
}

/** A value of the kind the claim name suggests, or a few words. */
function namedString(name: string, faker: Faker): string {
  const key = name.toLowerCase();
  if (/e_?mail/.test(key)) return faker.internet.email();
  if (/(given|first|fore)_?name/.test(key)) return faker.person.firstName();
  if (/(family|last|sur)_?name/.test(key)) return faker.person.lastName();
  if (/birth_?date|date_of_birth|^dob$/.test(key)) return isoDate(faker.date.birthdate());
  if (/(_at|_time|timestamp)$/.test(key)) return faker.date.anytime().toISOString();
  if (/date|_on$|expir|issuance/.test(key)) return isoDate(faker.date.anytime());
  if (/phone|mobile/.test(key)) return faker.phone.number({ style: "international" });
  if (/countr|nationalit/.test(key)) return faker.location.countryCode();
  if (/city|locality|town/.test(key)) return faker.location.city();
  if (/house_?number|building/.test(key)) return faker.location.buildingNumber();
  if (/street/.test(key)) return faker.location.street();
  if (/postal|zip/.test(key)) return faker.location.zipCode();
  if (/region|state|province/.test(key)) return faker.location.state();
  if (/url|uri|website/.test(key)) return faker.internet.url();
  if (/compan|organi[sz]ation|employer|universit|institution|issuer|authority/.test(key)) {
    return faker.company.name();
  }
  if (/^(sex|gender)$/.test(key)) return faker.person.sex();
  if (/name/.test(key)) return faker.person.fullName();
  if (/(^|_)(id|number|code|identifier)$/.test(key)) {
    return faker.string.alphanumeric({ length: 10, casing: "upper" });
  }
  return faker.lorem.words({ min: 1, max: 3 });
}

function isoDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** Faker's seed: the SHA-256 of the seed string as eight unsigned 32-bit integers. */
function seedNumbers(seed: string): number[] {
  const digest = Buffer.from(sha256Hex(Buffer.from(seed, "utf8")), "hex");
  return Array.from({ length: 8 }, (_, index) => digest.readUInt32BE(index * 4));
}
