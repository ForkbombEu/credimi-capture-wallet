import { Kms, type MdocSignOptions, SdJwtVcService, type SdJwtVcSignOptions } from "@credo-ts/core";
import { createIssuerSigningContext, issuerSigningKeyId, loadIssuerCertificate } from "./config.js";
import { DEGREE_CREDENTIAL_SUBJECT } from "./configurations/shared/degree-data.js";
import { encodeMdocPidClaims } from "./configurations/shared/mdoc-encoder.js";
import { pidSubject } from "./configurations/shared/pid-data.js";
import { encodeSdJwtPidClaims } from "./configurations/shared/sd-jwt-encoder.js";
import {
  CREDIMI_LOGO_URL,
  CREDIMI_WEBSITE,
  DEGREE_SD_JWT_VCT,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { AppConfig, JsonRecord, StatusListReference } from "./types.js";

export { CREDIMI_LOGO_URL, CREDIMI_WEBSITE };

/**
 * Makes the interiors of the `address` object and the `degrees` and `academic_programmes` arrays
 * individually disclosable, so a Wallet can reveal one member, and one claim inside it, without
 * revealing its siblings. `address` mirrors the `address.*` paths in `DEGREE_SD_JWT_CLAIMS`.
 *
 * `@sd-jwt/core` selects disclosable array elements with `sd.includes(i)` against the numeric
 * index, but Credo's `IDisclosureFrame` declares `_sd` as `string[]`. String indices therefore
 * type-check and are then silently ignored, collapsing each array back into one atomic
 * disclosure, so the numeric indices are asserted through the too-narrow library type.
 */
const DEGREE_DISCLOSURE_FRAME = {
  _sd: Object.keys(DEGREE_CREDENTIAL_SUBJECT),
  address: { _sd: ["street_address", "locality", "postal_code"] },
  degrees: {
    _sd: [0, 1, 2],
    0: { _sd: ["type", "university"] },
    1: { _sd: ["type", "university"] },
    2: { _sd: ["university"] },
  },
  academic_programmes: {
    _sd: [0, 1],
    0: { _sd: [0] },
    1: { _sd: [0, 1] },
  },
} as unknown as SdJwtVcSignOptions["disclosureFrame"];

export async function issueSdJwtCredential(options: {
  config: AppConfig;
  credentialConfigurationId: string;
  holderJwk: JsonRecord;
  statusListReference?: StatusListReference;
  now?: Date;
}): Promise<string> {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  const agentContext = createIssuerSigningContext(options.config);
  const service = new SdJwtVcService({} as never);
  const signOptions = sdJwtCredentialSignOptions(options);
  const credential = await service.sign(agentContext as never, signOptions);

  return credential.compact;
}

export function sdJwtCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  statusListReference?: StatusListReference;
  now?: Date;
}): SdJwtVcSignOptions {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  const now = options.now ?? new Date();
  return {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    payload: {
      vct: PID_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      ...encodeSdJwtPidClaims(pidSubject()),
      ...(options.statusListReference
        ? { status: { status_list: options.statusListReference } }
        : {}),
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

export function degreeSdJwtCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  statusListReference?: StatusListReference;
  now?: Date;
}): SdJwtVcSignOptions {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  const now = options.now ?? new Date();
  return {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    payload: {
      vct: DEGREE_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      ...DEGREE_CREDENTIAL_SUBJECT,
      ...(options.statusListReference
        ? { status: { status_list: options.statusListReference } }
        : {}),
    },
    disclosureFrame: DEGREE_DISCLOSURE_FRAME,
  };
}

export function mdocCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  statusListReference?: StatusListReference;
  now?: Date;
}): MdocSignOptions {
  const now = options.now ?? new Date();
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  return {
    docType: PID_MDOC_DOCTYPE,
    validityInfo: {
      signed: now,
      validFrom: now,
      validUntil: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000),
    },
    namespaces: {
      [PID_MDOC_NAMESPACE]: encodeMdocPidClaims(pidSubject()),
    },
    issuerCertificate,
    holderKey: Kms.PublicJwk.fromUnknown(options.holderJwk),
    ...(options.statusListReference
      ? {
          statusInfo: {
            index: options.statusListReference.idx,
            uri: options.statusListReference.uri,
          },
        }
      : {}),
  };
}
