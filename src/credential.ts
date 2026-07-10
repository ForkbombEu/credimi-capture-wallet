import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { Kms, SdJwtVcService } from "@credo-ts/core";
import {
  CoseKey,
  DateOnly,
  DeviceKey,
  Issuer,
  type MdocContext,
  SignatureAlgorithm,
} from "@owf/mdoc";
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

const PID_PORTRAIT_JPEG = readFileSync(new URL("./pid_portrait.jpg", import.meta.url));
const PID_PICTURE_DATA_URL = `data:image/jpeg;base64,${PID_PORTRAIT_JPEG.toString("base64")}`;

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
  const issuerCertificate = Buffer.from(
    readFileSync(issuerCertificatePath(options.config.data_dir), "utf8")
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, ""),
    "base64",
  );
  const now = options.now ?? new Date();
  const validUntil = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  const context = createMdocContext(privateJwk);

  const issuerSigned = await new Issuer(PID_MDOC_DOCTYPE, context)
    .addIssuerNamespace(PID_MDOC_NAMESPACE, mdocPidClaims())
    .sign({
      signingKey: CoseKey.fromJwk(privateJwk),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: "SHA-256",
      validityInfo: { signed: now, validFrom: now, validUntil },
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(options.holderJwk) as DeviceKey },
      certificates: [issuerCertificate],
    });

  return issuerSigned.encodedForOid4Vci;
}

function sdJwtPidClaims(): JsonRecord {
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
    issuing_country: "IT",
    issuing_jurisdiction: "IT",
    nationalities: ["IT"],
    personal_administrative_number: "PID-DEMO-001",
    phone_number: "+390600000000",
    picture: PID_PICTURE_DATA_URL,
    place_of_birth: "Roma", // WRONG DO NOT MODIFY - must be object, and at least one of country, region, or locality must be present.
    sex: 2,
  };
}

function mdocPidClaims(): JsonRecord {
  return {
    birth_date: new DateOnly("1990-01-01"),
    document_number: "CREDIMI-DEMO-001",
    email_address: "jane.doe@example.test",
    expiry_date: new DateOnly("2031-01-01"),
    family_name: "Doe",
    family_name_birth: "Doe",
    given_name: "Jane",
    given_name_birth: "Jane",
    issuance_date: new DateOnly("2026-01-01"),
    issuing_authority: "Credimi Fake Issuer",
    issuing_country: "IT",
    issuing_jurisdiction: "IT",
    mobile_phone_number: "+390600000000",
    nationality: ["IT"],
    personal_administrative_number: "PID-DEMO-001",
    place_of_birth: "Roma", // WRONG DO NOT MODIFY - must be object, and at least one of country, region, or locality must be present.
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
      calculateEphemeralMacKey: () => {
        throw new Error("MDOC MAC authentication is not supported by this issuer");
      },
    },
    cose: {
      sign1: {
        sign: async ({ toBeSigned }) =>
          sign("sha256", toBeSigned, {
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
