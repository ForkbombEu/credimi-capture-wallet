import { readFileSync } from "node:fs";
import { pidSubject } from "../configurations/shared/pid-data.js";
import { encodeSdJwtPidClaims } from "../configurations/shared/sd-jwt-encoder.js";
import { claimValueError } from "./json-schema.js";
import { isRecord } from "./snapshot.js";
import type { AttestbookClaimValue, AttestbookCredentialDefinition } from "./types.js";

/**
 * The issuer's existing key/value test data: the top-level scalar claims of its default PID test
 * subject, matched to an imported credential's claims by name. It is a named, explicit fixture,
 * not a PID credential: only the claims the imported schema declares are taken from it.
 */
export const ISSUER_TEST_DATA_FIXTURE_ID = "issuer_test_data";

const FIXTURE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export type ClaimFixture = Readonly<Record<string, AttestbookClaimValue>>;

export interface VctMapping {
  readonly rulebookId: string;
  readonly attestation: string;
  readonly vct: string;
}

/** Locally stored claim fixtures and the issuer-owned `vct` mappings. */
export interface ClaimSources {
  readonly fixtures: ReadonlyMap<string, ClaimFixture>;
  readonly vctMappings: readonly VctMapping[];
}

export type ClaimResolution =
  | { readonly ok: true; readonly claims: Readonly<Record<string, AttestbookClaimValue>> }
  | {
      readonly ok: false;
      readonly missing: readonly string[];
      readonly invalid: readonly { readonly claim: string; readonly reason: string }[];
    };

/**
 * Loads the built-in fixture and, when configured, the claims file. A malformed file fails
 * startup: issuing with a silently partial fixture set would hide the operator's mistake.
 */
export function loadClaimSources(claimsFile: string | null): ClaimSources {
  const fixtures = new Map<string, ClaimFixture>([[ISSUER_TEST_DATA_FIXTURE_ID, issuerTestData()]]);
  if (!claimsFile) return { fixtures, vctMappings: [] };

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(claimsFile, "utf8"));
  } catch (error) {
    throw new Error(
      `ATTESTBOOK_CLAIMS_FILE cannot be read as JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isRecord(parsed)) throw new Error("ATTESTBOOK_CLAIMS_FILE must contain a JSON object");
  const unknownMember = Object.keys(parsed).find(
    (key) => key !== "fixtures" && key !== "vct_mappings",
  );
  if (unknownMember)
    throw new Error(`ATTESTBOOK_CLAIMS_FILE has unknown member '${unknownMember}'`);

  const fileFixtures = parsed.fixtures ?? {};
  if (!isRecord(fileFixtures)) throw new Error("ATTESTBOOK_CLAIMS_FILE fixtures must be an object");
  for (const [id, values] of Object.entries(fileFixtures)) {
    if (!FIXTURE_ID.test(id) || id === ISSUER_TEST_DATA_FIXTURE_ID) {
      throw new Error(`ATTESTBOOK_CLAIMS_FILE fixture id '${id}' is invalid or reserved`);
    }
    if (!isRecord(values))
      throw new Error(`ATTESTBOOK_CLAIMS_FILE fixture '${id}' must be an object`);
    for (const [claim, value] of Object.entries(values)) {
      if (
        typeof value !== "string" &&
        typeof value !== "boolean" &&
        !(typeof value === "number" && Number.isFinite(value))
      ) {
        throw new Error(
          `ATTESTBOOK_CLAIMS_FILE fixture '${id}' claim '${claim}' must be a string, number or boolean`,
        );
      }
    }
    fixtures.set(id, values as ClaimFixture);
  }

  const mappings = parsed.vct_mappings ?? [];
  if (!Array.isArray(mappings))
    throw new Error("ATTESTBOOK_CLAIMS_FILE vct_mappings must be an array");
  const vctMappings = mappings.map((mapping, index): VctMapping => {
    if (
      !isRecord(mapping) ||
      typeof mapping.rulebook_id !== "string" ||
      typeof mapping.attestation !== "string" ||
      typeof mapping.vct !== "string" ||
      mapping.vct.length === 0
    ) {
      throw new Error(
        `ATTESTBOOK_CLAIMS_FILE vct_mappings[${index}] needs rulebook_id, attestation and vct strings`,
      );
    }
    return { rulebookId: mapping.rulebook_id, attestation: mapping.attestation, vct: mapping.vct };
  });
  return { fixtures, vctMappings };
}

/** Resolves and validates one fixture's values for every claim the definition declares. */
export function resolveClaimValues(
  definition: AttestbookCredentialDefinition,
  fixture: ClaimFixture,
): ClaimResolution {
  const claims: Record<string, AttestbookClaimValue> = {};
  const missing: string[] = [];
  const invalid: { claim: string; reason: string }[] = [];
  for (const claim of definition.claims) {
    const value = fixture[claim.name];
    if (value === undefined) {
      if (claim.required) missing.push(claim.name);
      continue;
    }
    const error = claimValueError(claim, value);
    if (error) {
      invalid.push({ claim: claim.name, reason: error });
      continue;
    }
    claims[claim.name] = value;
  }
  return missing.length === 0 && invalid.length === 0
    ? { ok: true, claims }
    : { ok: false, missing, invalid };
}

/** The ids of the fixtures that can issue a definition, in a stable order. */
export function satisfyingFixtureIds(
  definition: AttestbookCredentialDefinition,
  sources: ClaimSources,
): string[] {
  return [...sources.fixtures.entries()]
    .filter(([, fixture]) => resolveClaimValues(definition, fixture).ok)
    .map(([id]) => id);
}

function issuerTestData(): ClaimFixture {
  return Object.fromEntries(
    Object.entries(encodeSdJwtPidClaims(pidSubject())).filter(
      (entry): entry is [string, AttestbookClaimValue] =>
        typeof entry[1] === "string" ||
        typeof entry[1] === "number" ||
        typeof entry[1] === "boolean",
    ),
  );
}
