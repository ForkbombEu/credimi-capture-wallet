import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { Document, type MdocContext, cborEncode } from "@animo-id/mdoc";
import { Kms, SdJwtVcService } from "@credo-ts/core";
import {
  ISSUER_KEY_ID,
  issuerCertificatePath,
  loadIssuerCertificate,
  privateJwkPath,
} from "./config.js";
import {
  CREDIMI_LOGO_URL,
  CREDIMI_WEBSITE,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { AppConfig, JsonRecord } from "./types.js";

export { CREDIMI_LOGO_URL, CREDIMI_WEBSITE };

export async function issueSdJwtCredential(options: {
  config: AppConfig;
  credentialConfigurationId: string;
  holderJwk: JsonRecord;
  now?: Date;
}): Promise<string> {
  const privateJwk = loadPrivateJwk(options.config);
  const issuerCertificate = loadIssuerCertificate(options.config);
  issuerCertificate.keyId = ISSUER_KEY_ID;
  const agentContext = createSigningContext(privateJwk);
  const service = new SdJwtVcService({} as never);
  const now = options.now ?? new Date();

  const credential = await service.sign(agentContext as never, {
    issuer: { method: "x5c", issuer: options.config.issuer_base_url, x5c: [issuerCertificate] },
    holder: { method: "jwk", jwk: Kms.PublicJwk.fromUnknown(options.holderJwk) },
    headerType: "dc+sd-jwt",
    payload: {
      vct: PID_SD_JWT_VCT,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      ...sdJwtPidClaims(),
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
  });

  return credential.compact;
}

export async function issueMdocCredential(options: {
  config: AppConfig;
  holderJwk: JsonRecord;
  now?: Date;
}): Promise<string> {
  const privateJwk = loadPrivateJwk(options.config);
  const issuerCertificatePem = readFileSync(issuerCertificatePath(options.config.data_dir), "utf8");
  const now = options.now ?? new Date();
  const validUntil = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  const context = createMdocContext(privateJwk);

  const document = await new Document(PID_MDOC_DOCTYPE, { crypto: context.crypto })
    .addIssuerNameSpace(PID_MDOC_NAMESPACE, mdocPidClaims())
    .useDigestAlgorithm("SHA-256")
    .addValidityInfo({ signed: now, validFrom: now, validUntil })
    .addDeviceKeyInfo({ deviceKey: options.holderJwk as never })
    .sign(
      {
        issuerPrivateKey: privateJwk as never,
        issuerCertificate: issuerCertificatePem,
        alg: "ES256",
        kid: ISSUER_KEY_ID,
      },
      context,
    );

  const issuerSigned = document.prepare().get("issuerSigned");
  if (!issuerSigned) throw new Error("MDOC issuer-signed structure was not generated");

  return Buffer.from(cborEncode(issuerSigned)).toString("base64url");
}

function sdJwtPidClaims(): JsonRecord {
  return {
    address: {
      country: "EU",
      formatted: "Via Europa 1, 00100 Roma, EU",
      house_number: "1",
      locality: "Roma",
      postal_code: "00100",
      region: "Lazio",
      street_address: "Via Europa",
    },
    birth_family_name: "Doe",
    birth_given_name: "Jane",
    birthdate: "1990-01-01",
    date_of_expiry: "2031-01-01",
    date_of_issuance: "2026-01-01",
    document_number: "CREDIMI-DEMO-001",
    email: "jane.doe@example.test",
    family_name: "Doe",
    given_name: "Jane",
    issuing_authority: "Credimi Fake Issuer",
    issuing_country: "EU",
    issuing_jurisdiction: "EU",
    nationalities: ["EU"],
    personal_administrative_number: "PID-DEMO-001",
    phone_number: "+390600000000",
    picture: CREDIMI_LOGO_URL,
    place_of_birth: "Roma",
    sex: "2",
  };
}

function mdocPidClaims(): JsonRecord {
  return {
    birth_date: "1990-01-01",
    document_number: "CREDIMI-DEMO-001",
    email_address: "jane.doe@example.test",
    expiry_date: "2031-01-01",
    family_name: "Doe",
    family_name_birth: "Doe",
    given_name: "Jane",
    given_name_birth: "Jane",
    issuance_date: "2026-01-01",
    issuing_authority: "Credimi Fake Issuer",
    issuing_country: "EU",
    issuing_jurisdiction: "EU",
    mobile_phone_number: "+390600000000",
    nationality: "EU",
    personal_administrative_number: "PID-DEMO-001",
    place_of_birth: "Roma",
    portrait: CREDIMI_LOGO_URL,
    resident_address: "Via Europa 1, 00100 Roma, EU",
    resident_city: "Roma",
    resident_country: "EU",
    resident_house_number: "1",
    resident_postal_code: "00100",
    resident_state: "Lazio",
    resident_street: "Via Europa",
    sex: "2",
  };
}

function loadPrivateJwk(config: AppConfig): JsonRecord {
  return JSON.parse(readFileSync(privateJwkPath(config.data_dir), "utf8")) as JsonRecord;
}

function createSigningContext(privateJwk: JsonRecord): object {
  const kms = {
    randomBytes: ({ length }: { length: number }) => randomBytes(length),
    sign: async ({ keyId, data }: { keyId: string; data: Uint8Array }) => {
      if (keyId !== ISSUER_KEY_ID) throw new Error(`Unknown issuer key id '${keyId}'`);
      return {
        signature: sign("sha256", data, {
          key: createPrivateKey({ key: privateJwk as never, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        }),
      };
    },
  };
  const resolve = (token: unknown) => {
    if (token === Kms.KeyManagementApi) return kms;
    throw new Error("Unsupported Credo dependency requested while issuing SD-JWT VC");
  };

  return {
    resolve,
    dependencyManager: { resolve },
    config: {
      allowInsecureHttpUrls: true,
      agentDependencies: { fetch: globalThis.fetch },
    },
  };
}

function createMdocContext(privateJwk: JsonRecord): {
  crypto: MdocContext["crypto"];
  cose: MdocContext["cose"];
} {
  return {
    crypto: {
      random: (length) => randomBytes(length),
      digest: ({ digestAlgorithm, bytes }) => {
        if (digestAlgorithm !== "SHA-256") {
          throw new Error(`Unsupported MDOC digest algorithm '${digestAlgorithm}'`);
        }
        return createHash("sha256").update(bytes).digest();
      },
      calculateEphemeralMacKeyJwk: () => {
        throw new Error("MDOC MAC authentication is not supported by this issuer");
      },
    },
    cose: {
      sign1: {
        sign: ({ sign1 }) =>
          sign("sha256", sign1.getRawSigningData().data, {
            key: createPrivateKey({ key: privateJwk as never, format: "jwk" }),
            dsaEncoding: "ieee-p1363",
          }),
        verify: () => {
          throw new Error("MDOC verification is not supported by this issuer");
        },
      },
      mac0: {
        sign: () => {
          throw new Error("MDOC MAC authentication is not supported by this issuer");
        },
        verify: () => {
          throw new Error("MDOC MAC authentication is not supported by this issuer");
        },
      },
    },
  };
}
