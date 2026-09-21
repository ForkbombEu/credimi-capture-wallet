import { DEFAULT_PID_SUBJECT, type PidSubject } from "./pid-data.js";

/**
 * Predefined PID claim sets, selected per issuance session with `fixture_id`.
 *
 * FCAF tests that check DCQL value matching need several credentials of the same type whose claims
 * differ along one axis each, so that a query constraining that axis matches one and withholds the
 * others. Each fixture below is a full, validly signed PID: only the claim values differ, and no
 * caller-supplied claim override exists, so an issued credential always corresponds to a named
 * fixture that a test can reference.
 */
export const PID_FIXTURES = {
  /** The baseline identity. Matches the value constraints the other fixtures deliberately fail. */
  pid_default: DEFAULT_PID_SUBJECT,

  /** A second, fully valid identity, for the tests that need two credentials of the same type. */
  pid_person_b: {
    ...DEFAULT_PID_SUBJECT,
    address: {
      country: "IT",
      formatted: "Corso Italia 9, 20122 Milano, IT",
      houseNumber: "9",
      locality: "Milano",
      postalCode: "20122",
      region: "Lombardia",
      street: "Corso Italia",
    },
    birthDate: "1985-07-14",
    birthFamilyName: "Bianchi",
    birthGivenName: "Giulia",
    documentNumber: "CREDIMI-DEMO-002",
    email: "giulia.bianchi@example.test",
    familyName: "Bianchi",
    givenName: "Giulia",
    personalAdministrativeNumber: "PID-DEMO-002",
    placeOfBirth: { country: "IT", locality: "Milano", region: "Lombardia" },
    sex: 2,
  },

  /** Fails an `age_over_18` constraint: the holder is a minor. */
  pid_under_18: {
    ...DEFAULT_PID_SUBJECT,
    ageOver18: false,
    birthDate: "2012-03-04",
    documentNumber: "CREDIMI-DEMO-U18",
    personalAdministrativeNumber: "PID-DEMO-U18",
  },

  /** Fails a case-sensitive string constraint: the family name is capitalised differently. */
  pid_family_name_uppercase: {
    ...DEFAULT_PID_SUBJECT,
    familyName: "ROSSI",
    documentNumber: "CREDIMI-DEMO-CASE",
  },

  /** Fails a whitespace-sensitive string constraint: the family name has a trailing space. */
  pid_family_name_trailing_space: {
    ...DEFAULT_PID_SUBJECT,
    familyName: "Rossi ",
    documentNumber: "CREDIMI-DEMO-SPACE",
  },

  /** Carries a locality with diacritics, for the matching pair below. */
  pid_locality_diacritics: {
    ...DEFAULT_PID_SUBJECT,
    address: { ...DEFAULT_PID_SUBJECT.address, locality: "München" },
    placeOfBirth: { ...DEFAULT_PID_SUBJECT.placeOfBirth, locality: "München" },
    documentNumber: "CREDIMI-DEMO-UMLAUT",
  },

  /** Fails a constraint on the value above: the same locality without its umlaut. */
  pid_locality_no_diacritics: {
    ...DEFAULT_PID_SUBJECT,
    address: { ...DEFAULT_PID_SUBJECT.address, locality: "Munchen" },
    placeOfBirth: { ...DEFAULT_PID_SUBJECT.placeOfBirth, locality: "Munchen" },
    documentNumber: "CREDIMI-DEMO-NOUMLAUT",
  },

  /** Fails a single-element array constraint: two nationalities instead of one. */
  pid_multiple_nationalities: {
    ...DEFAULT_PID_SUBJECT,
    nationalities: ["FR", "DE"],
    documentNumber: "CREDIMI-DEMO-ARRAY",
  },

  /** Fails a `date_of_expiry` upper-bound constraint by one year. */
  pid_expiry_2032: {
    ...DEFAULT_PID_SUBJECT,
    expiryDate: "2032-01-01",
    documentNumber: "CREDIMI-DEMO-EXPIRY",
  },
} as const satisfies Record<string, PidSubject>;

export type PidFixtureId = keyof typeof PID_FIXTURES;

export const PID_FIXTURE_IDS = Object.keys(PID_FIXTURES) as PidFixtureId[];

export function pidFixtureIdOrNull(value: unknown): PidFixtureId | null {
  return typeof value === "string" && Object.hasOwn(PID_FIXTURES, value)
    ? (value as PidFixtureId)
    : null;
}

export function pidFixtureSubject(fixtureId: PidFixtureId | undefined): PidSubject {
  return PID_FIXTURES[fixtureId ?? "pid_default"];
}
