import { Kms, type MdocSignOptions, SdJwtVcService, type SdJwtVcSignOptions } from "@credo-ts/core";
import { createIssuerSigningContext, issuerSigningKeyId, loadIssuerCertificate } from "./config.js";
import { DEGREE_CREDENTIAL_SUBJECT } from "./configurations/shared/degree-data.js";
import { encodeMdocPidClaims } from "./configurations/shared/mdoc-encoder.js";
import { type PidSubject, pidSubject } from "./configurations/shared/pid-data.js";
import { encodeSdJwtPidClaims } from "./configurations/shared/sd-jwt-encoder.js";
import {
  CREDIMI_LOGO_URL,
  CREDIMI_WEBSITE,
  DEGREE_SD_JWT_VCT,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { MdocSignOptionsWithStatusReference } from "./malformed-mdoc-status.js";
import type {
  AppConfig,
  JsonRecord,
  SdJwtDigestAlgorithm,
  StatusListReference,
  StatusReferenceFixture,
} from "./types.js";

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
  subject?: PidSubject;
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
  statusReference?: StatusReferenceFixture;
  digestAlgorithm?: SdJwtDigestAlgorithm;
  subject?: PidSubject;
  now?: Date;
}): SdJwtVcSignOptions {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  const now = options.now ?? new Date();
  return {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    ...(options.digestAlgorithm ? { hashingAlgorithm: options.digestAlgorithm } : {}),
    payload: {
      vct: PID_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      ...encodeSdJwtPidClaims(options.subject ?? pidSubject()),
      ...sdJwtStatusClaim(options.statusListReference, options.statusReference),
    },
    disclosureFrame: {
      _sd: [
        "address",
        "age_over_18",
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
  statusReference?: StatusReferenceFixture;
  digestAlgorithm?: SdJwtDigestAlgorithm;
  now?: Date;
}): SdJwtVcSignOptions {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  const now = options.now ?? new Date();
  return {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    ...(options.digestAlgorithm ? { hashingAlgorithm: options.digestAlgorithm } : {}),
    payload: {
      vct: DEGREE_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      ...DEGREE_CREDENTIAL_SUBJECT,
      ...sdJwtStatusClaim(options.statusListReference, options.statusReference),
    },
    disclosureFrame: DEGREE_DISCLOSURE_FRAME,
  };
}

/**
 * The numeric test credential intentionally carries a float. It exists solely to exercise DCQL
 * value-type matching when a verifier expects an integer `kg` claim.
 */
export function numericSdJwtCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  statusListReference?: StatusListReference;
  statusReference?: StatusReferenceFixture;
  digestAlgorithm?: SdJwtDigestAlgorithm;
  now?: Date;
}): SdJwtVcSignOptions {
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = issuerSigningKeyId(options.config);
  const now = options.now ?? new Date();
  return {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    ...(options.digestAlgorithm ? { hashingAlgorithm: options.digestAlgorithm } : {}),
    payload: {
      vct: NUMERIC_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      kg: 70.5,
      ...sdJwtStatusClaim(options.statusListReference, options.statusReference),
    },
    disclosureFrame: { _sd: ["kg"] },
  };
}

/**
 * Builds the `status` claim of an SD-JWT VC. `valid` is the normal Token Status List reference;
 * the other fixtures deliberately malform it for the revocation-metadata tests, which check that
 * a Wallet rejects a negative or missing index and a missing or unparseable URI. The reference is
 * always allocated normally first, so the fixture only reshapes a real allocation.
 */
function sdJwtStatusClaim(
  reference: StatusListReference | undefined,
  fixture: StatusReferenceFixture = "valid",
): JsonRecord {
  if (!reference) return {};
  switch (fixture) {
    case "valid":
      return { status: { status_list: reference } };
    case "status_without_status_list":
      return { status: {} };
    case "negative_index":
      return { status: { status_list: { uri: reference.uri, idx: -1 } } };
    case "missing_index":
      return { status: { status_list: { uri: reference.uri } } };
    case "malformed_uri":
      return { status: { status_list: { uri: "not a uri", idx: reference.idx } } };
    case "missing_uri":
      return { status: { status_list: { idx: reference.idx } } };
  }
}

export function mdocCredentialSignOptions(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  statusListReference?: StatusListReference;
  statusReference?: StatusReferenceFixture;
  subject?: PidSubject;
  now?: Date;
}): MdocSignOptionsWithStatusReference {
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
      [PID_MDOC_NAMESPACE]: encodeMdocPidClaims(options.subject ?? pidSubject()),
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
    ...(options.statusListReference &&
    options.statusReference &&
    options.statusReference !== "valid"
      ? { statusReference: options.statusReference }
      : {}),
  };
}
