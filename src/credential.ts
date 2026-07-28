import { readFileSync } from "node:fs";
import { Kms, type MdocSignOptions, SdJwtVcService, type SdJwtVcSignOptions } from "@credo-ts/core";
import { DateOnly } from "@owf/mdoc";
import { ISSUER_KEY_ID, createIssuerSigningContext, loadIssuerCertificate } from "./config.js";
import {
  CREDIMI_LOGO_URL,
  CREDIMI_WEBSITE,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { AppConfig, JsonRecord } from "./types.js";

export { CREDIMI_LOGO_URL, CREDIMI_WEBSITE };

const PID_PORTRAIT_JPEG = readFileSync(new URL("./pid_portrait.jpg", import.meta.url));
const PID_PICTURE_DATA_URL = `data:image/jpeg;base64,${PID_PORTRAIT_JPEG.toString("base64")}`;

export async function issueSdJwtCredential(options: {
  config: AppConfig;
  credentialConfigurationId: string;
  holderJwk: JsonRecord;
  broken?: boolean;
  now?: Date;
}): Promise<string> {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = ISSUER_KEY_ID;
  const agentContext = createIssuerSigningContext(options.config);
  const service = new SdJwtVcService({} as never);
  const signOptions = sdJwtCredentialSignOptions(options);
  const credential = await service.sign(agentContext as never, signOptions);

  return credential.compact;
}

export function sdJwtCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  broken?: boolean;
  now?: Date;
}): SdJwtVcSignOptions {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = ISSUER_KEY_ID;
  const now = options.now ?? new Date();
  return {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    payload: {
      vct: PID_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      ...sdJwtPidClaims(options.broken ?? false),
    },
    disclosureFrame: {
      _sd: [
        "address",
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
      ],
    },
  };
}

export function mdocCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  broken?: boolean;
  now?: Date;
}): MdocSignOptions {
  const now = options.now ?? new Date();
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = ISSUER_KEY_ID;
  return {
    docType: PID_MDOC_DOCTYPE,
    validityInfo: {
      signed: now,
      validFrom: now,
      validUntil: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000),
    },
    namespaces: { [PID_MDOC_NAMESPACE]: mdocPidClaims(options.broken ?? false) },
    issuerCertificate,
    holderKey: Kms.PublicJwk.fromUnknown(options.holderJwk),
  };
}

function sdJwtPidClaims(broken: boolean): JsonRecord {
  const givenName = broken ? "Jane" : "Mario";
  const familyName = broken ? "Doe" : "Rossi";
  return {
    address: {
      country: "IT",
      formatted: "Via Europa 1, 00100 Roma, IT",
      house_number: "1",
      locality: "Roma",
      postal_code: "00100",
      region: "Lazio",
      street_address: "Via Europa",
    },
    birth_family_name: familyName,
    birth_given_name: givenName,
    birthdate: "1990-01-01",
    date_of_expiry: "2031-01-01",
    date_of_issuance: "2026-01-01",
    document_number: "CREDIMI-DEMO-001",
    email: "jane.doe@example.test",
    family_name: familyName,
    given_name: givenName,
    issuing_authority: "Credimi Fake Issuer",
    issuing_country: "IT",
    issuing_jurisdiction: "IT-RM",
    nationalities: ["IT"],
    personal_administrative_number: "PID-DEMO-001",
    phone_number: "+390600000000",
    picture: PID_PICTURE_DATA_URL,
    place_of_birth: broken ? "Roma" : { locality: "Roma" },
    sex: 2,
  };
}

function mdocPidClaims(broken: boolean): JsonRecord {
  const givenName = broken ? "Jane" : "Mario";
  const familyName = broken ? "Doe" : "Rossi";
  return {
    birth_date: new DateOnly("1990-01-01"),
    document_number: "CREDIMI-DEMO-001",
    email_address: "jane.doe@example.test",
    expiry_date: new DateOnly("2031-01-01"),
    family_name: familyName,
    family_name_birth: familyName,
    given_name: givenName,
    given_name_birth: givenName,
    issuance_date: new DateOnly("2026-01-01"),
    issuing_authority: "Credimi Fake Issuer",
    issuing_country: "IT",
    issuing_jurisdiction: "IT-RM",
    mobile_phone_number: "+390600000000",
    nationality: ["IT"],
    personal_administrative_number: "PID-DEMO-001",
    place_of_birth: broken ? "Roma" : { locality: "Roma" },
    portrait: new Uint8Array(PID_PORTRAIT_JPEG),
    resident_address: "Via Europa 1, 00100 Roma, IT",
    resident_city: "Roma",
    resident_country: "IT",
    resident_house_number: "1",
    resident_postal_code: "00100",
    resident_state: "Lazio",
    resident_street: "Via Europa",
    sex: 2,
  };
}
