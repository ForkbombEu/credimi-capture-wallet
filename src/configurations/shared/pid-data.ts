import { readFileSync } from "node:fs";

export interface PidAddress {
  readonly country: string;
  readonly formatted: string;
  readonly houseNumber: string;
  readonly locality: string;
  readonly postalCode: string;
  readonly region: string;
  readonly street: string;
}

export interface PidPlaceOfBirth {
  readonly locality: string;
}

export interface PidSubject {
  readonly address: PidAddress;
  readonly birthDate: string;
  readonly birthFamilyName: string;
  readonly birthGivenName: string;
  readonly documentNumber: string;
  readonly email: string;
  readonly expiryDate: string;
  readonly familyName: string;
  readonly givenName: string;
  readonly issuanceDate: string;
  readonly issuingAuthority: string;
  readonly issuingCountry: string;
  readonly issuingJurisdiction: string;
  readonly nationalities: readonly string[];
  readonly personalAdministrativeNumber: string;
  readonly phoneNumber: string;
  readonly picture: Uint8Array;
  readonly placeOfBirth: PidPlaceOfBirth;
  readonly sex: number;
}

const PID_PORTRAIT_JPEG = new Uint8Array(
  readFileSync(new URL("../../pid_portrait.jpg", import.meta.url)),
);

const DEFAULT_PID_SUBJECT: PidSubject = {
  address: {
    country: "IT",
    formatted: "Via Europa 1, 00100 Roma, IT",
    houseNumber: "1",
    locality: "Roma",
    postalCode: "00100",
    region: "Lazio",
    street: "Via Europa",
  },
  birthDate: "1990-01-01",
  birthFamilyName: "Rossi",
  birthGivenName: "Mario",
  documentNumber: "CREDIMI-DEMO-001",
  email: "jane.doe@example.test",
  expiryDate: "2031-01-01",
  familyName: "Rossi",
  givenName: "Mario",
  issuanceDate: "2026-01-01",
  issuingAuthority: "Credimi Fake Issuer",
  issuingCountry: "IT",
  issuingJurisdiction: "IT-RM",
  nationalities: ["IT"],
  personalAdministrativeNumber: "PID-DEMO-001",
  phoneNumber: "+390600000000",
  picture: PID_PORTRAIT_JPEG,
  placeOfBirth: { locality: "Roma" },
  sex: 2,
};

export function pidSubject(): PidSubject {
  return DEFAULT_PID_SUBJECT;
}
