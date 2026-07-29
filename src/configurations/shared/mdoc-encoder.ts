import { DateOnly } from "@owf/mdoc";
import type { JsonRecord } from "../../types.js";
import type { PidSubject } from "./pid-data.js";

export function encodeMdocPidClaims(subject: PidSubject): JsonRecord {
  return {
    birth_date: new DateOnly(subject.birthDate),
    document_number: subject.documentNumber,
    email_address: subject.email,
    expiry_date: new DateOnly(subject.expiryDate),
    family_name: subject.familyName,
    family_name_birth: subject.birthFamilyName,
    given_name: subject.givenName,
    given_name_birth: subject.birthGivenName,
    issuance_date: new DateOnly(subject.issuanceDate),
    issuing_authority: subject.issuingAuthority,
    issuing_country: subject.issuingCountry,
    issuing_jurisdiction: subject.issuingJurisdiction,
    mobile_phone_number: subject.phoneNumber,
    nationality: [...subject.nationalities],
    personal_administrative_number: subject.personalAdministrativeNumber,
    place_of_birth: subject.placeOfBirth,
    portrait: new Uint8Array(subject.picture),
    resident_address: subject.address.formatted,
    resident_city: subject.address.locality,
    resident_country: subject.address.country,
    resident_house_number: subject.address.houseNumber,
    resident_postal_code: subject.address.postalCode,
    resident_state: subject.address.region,
    resident_street: subject.address.street,
    sex: subject.sex,
  };
}
