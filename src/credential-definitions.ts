export const CREDIMI_WEBSITE = "https://credimi.io";
export const CREDIMI_LOGO_URL =
  "https://raw.githubusercontent.com/ForkbombEu/credimi/main/docs/images/logo/credimi_logo-transp_emblem.png";

export const PID_SD_JWT_VCT = "urn:eudi:pid:1";
export const PID_MDOC_DOCTYPE = "eu.europa.ec.eudi.pid.1";
export const PID_MDOC_NAMESPACE = "eu.europa.ec.eudi.pid.1";

export const PID_SD_JWT_CLAIMS = [
  "address.country",
  "address.formatted",
  "address.house_number",
  "address.locality",
  "address.postal_code",
  "address.region",
  "address.street_address",
  "birth_family_name",
  "birth_given_name",
  "birthdate",
  "date_of_expiry",
  "date_of_issuance",
  "document_number",
  "email",
  "family_name",
  "given_name",
  "issuing_authority",
  "issuing_country",
  "issuing_jurisdiction",
  "nationalities",
  "personal_administrative_number",
  "phone_number",
  "picture",
  "place_of_birth",
  "sex",
] as const;

export const PID_MDOC_CLAIMS = [
  "birth_date",
  "document_number",
  "email_address",
  "expiry_date",
  "family_name",
  "family_name_birth",
  "given_name",
  "given_name_birth",
  "issuance_date",
  "issuing_authority",
  "issuing_country",
  "issuing_jurisdiction",
  "mobile_phone_number",
  "nationality",
  "personal_administrative_number",
  "place_of_birth",
  "portrait",
  "resident_address",
  "resident_city",
  "resident_country",
  "resident_house_number",
  "resident_postal_code",
  "resident_state",
  "resident_street",
  "sex",
] as const;
