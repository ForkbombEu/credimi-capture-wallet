import type { JsonRecord } from "../../types.js";
import type { PidSubject } from "./pid-data.js";

export function encodeSdJwtPidClaims(subject: PidSubject): JsonRecord {
  return {
    address: {
      country: subject.address.country,
      formatted: subject.address.formatted,
      house_number: subject.address.houseNumber,
      locality: subject.address.locality,
      postal_code: subject.address.postalCode,
      region: subject.address.region,
      street_address: subject.address.street,
    },
    birth_family_name: subject.birthFamilyName,
    birth_given_name: subject.birthGivenName,
    birthdate: subject.birthDate,
    date_of_expiry: subject.expiryDate,
    date_of_issuance: subject.issuanceDate,
    document_number: subject.documentNumber,
    email: subject.email,
    family_name: subject.familyName,
    given_name: subject.givenName,
    issuing_authority: subject.issuingAuthority,
    issuing_country: subject.issuingCountry,
    issuing_jurisdiction: subject.issuingJurisdiction,
    nationalities: [...subject.nationalities],
    personal_administrative_number: subject.personalAdministrativeNumber,
    phone_number: subject.phoneNumber,
    picture: `data:image/jpeg;base64,${Buffer.from(subject.picture).toString("base64")}`,
    place_of_birth: subject.placeOfBirth,
    sex: subject.sex,
  };
}
