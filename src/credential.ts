import { createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { Kms, SdJwtVcService } from "@credo-ts/core";
import { ISSUER_KEY_ID, loadIssuerCertificate, privateJwkPath } from "./config.js";
import type { AppConfig, JsonRecord } from "./types.js";

export const CREDIMI_WEBSITE = "https://credimi.io";
export const CREDIMI_LOGO_URL =
  "https://raw.githubusercontent.com/ForkbombEu/credimi/main/docs/images/logo/credimi_logo-transp_emblem.png";

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
      vct: options.credentialConfigurationId,
      exp: Math.floor(now.getTime() / 1000) + 365 * 24 * 60 * 60,
      family_name: "Doe",
      given_name: "Jane",
      birth_date: "1990-01-01",
      issuing_country: "EU",
      issuing_authority: "Credimi Fake Issuer",
      document_number: "CREDIMI-DEMO-001",
      website: CREDIMI_WEBSITE,
      logo_uri: CREDIMI_LOGO_URL,
    },
    disclosureFrame: {
      _sd: [
        "family_name",
        "given_name",
        "birth_date",
        "issuing_country",
        "issuing_authority",
        "document_number",
        "website",
        "logo_uri",
      ],
    },
  });

  return credential.compact;
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
