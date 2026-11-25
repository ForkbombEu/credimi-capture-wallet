import { afterEach, describe, expect, it } from "vitest";
import type { AttestbookCredentialDefinition } from "../src/attestbook/types.js";
import { issuerSigningKeyId, loadIssuerCertificate } from "../src/config/key-material.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import {
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_VCT,
  PID_SD_JWT_VCT,
} from "../src/credentials/definitions.js";
import {
  degreeSdJwtCredentialSignOptions,
  domesticPidSdJwtCredentialSignOptions,
  importedSdJwtCredentialSignOptions,
  numericSdJwtCredentialSignOptions,
  sdJwtCredentialSignOptions,
} from "../src/credentials/signing.js";
import { createIssuerTestEnvironment, requireIssuer } from "./support/environment.js";
import { generateEs256Key } from "./support/keys.js";

const NOW = new Date("2026-01-02T03:04:05.000Z");
const STATUS_REFERENCE = { uri: "https://issuer.example.test/status/0", idx: 7 };

const PID_DISCLOSURE_FRAME = {
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
};
const DOMESTIC_PID_DISCLOSURE_FRAME = {
  _sd: [...PID_DISCLOSURE_FRAME._sd, "credimi_domestic_claim"],
};
const DEGREE_DISCLOSURE_FRAME = {
  _sd: ["name", "address", "degrees", "academic_programmes", "nationalities"],
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
};
const NUMERIC_DISCLOSURE_FRAME = { _sd: ["kg"] };

async function createIssuerSigningEnvironment(prefix: string) {
  const environment = await createIssuerTestEnvironment({ prefix });
  return {
    ...environment,
    config: issuerAppConfig(
      environment.config,
      requireIssuer(environment.config, "eu-pid-device-bound"),
    ),
  };
}

const importedDefinition: AttestbookCredentialDefinition = {
  origin: "https://attestbook.example.test",
  rulebookId: "rulebook",
  version: "1",
  contentDigest: "a".repeat(64),
  attestation: {
    name: "Membership Card",
    index: 0,
    attestationLoS: "basic",
    bindingType: "holder-bound",
  },
  credentialConfigurationId: "urn:example:membership-card",
  scope: "membership_card",
  format: "dc+sd-jwt",
  vct: "urn:example:membership-card",
  vctSource: "attestation_name",
  displayName: "Membership Card",
  claims: {
    kind: "object",
    displayName: null,
    selectivelyDisclosable: true,
    additionalProperties: false,
    properties: [
      {
        name: "member_id",
        required: true,
        node: {
          kind: "scalar",
          type: "string",
          displayName: null,
          selectivelyDisclosable: true,
        },
      },
      {
        name: "active",
        required: true,
        node: {
          kind: "scalar",
          type: "boolean",
          displayName: null,
          selectivelyDisclosable: false,
        },
      },
    ],
  },
  claimMetadata: [],
  schemaReferences: [],
  proofPolicy: "jwt-proof",
  claimValueProvider: "faker-js",
  disclosurePolicy: "issuer-default-selective",
};

const importedClaims = { member_id: "member-123", active: true };

describe("SD-JWT signing option builders", () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => cleanup?.());

  it.each([
    [
      "pid",
      (options: Parameters<typeof sdJwtCredentialSignOptions>[0]) =>
        sdJwtCredentialSignOptions(options),
      PID_SD_JWT_VCT,
      PID_DISCLOSURE_FRAME,
    ],
    [
      "domestic PID",
      (options: Parameters<typeof sdJwtCredentialSignOptions>[0]) =>
        domesticPidSdJwtCredentialSignOptions(options),
      DOMESTIC_PID_SD_JWT_VCT,
      DOMESTIC_PID_DISCLOSURE_FRAME,
    ],
    [
      "degree",
      (options: Parameters<typeof degreeSdJwtCredentialSignOptions>[0]) =>
        degreeSdJwtCredentialSignOptions(options),
      DEGREE_SD_JWT_VCT,
      DEGREE_DISCLOSURE_FRAME,
    ],
    [
      "numeric",
      (options: Parameters<typeof numericSdJwtCredentialSignOptions>[0]) =>
        numericSdJwtCredentialSignOptions(options),
      NUMERIC_SD_JWT_VCT,
      NUMERIC_DISCLOSURE_FRAME,
    ],
  ] as const)("builds the common envelope for %s", async (_name, builder, vct, disclosureFrame) => {
    const environment = await createIssuerSigningEnvironment("sd-jwt-options-");
    cleanup = environment.cleanup;
    const holder = await generateEs256Key();
    const options = builder({
      config: environment.config,
      holderJwk: holder.publicJwk,
      statusListReference: STATUS_REFERENCE,
      statusReference: "valid",
      digestAlgorithm: "sha-384",
      now: NOW,
    });

    expect(options.issuer).toMatchObject({
      method: "x5c",
      issuer: environment.config.issuer_base_url,
      x5c: [
        expect.objectContaining({
          rawCertificate: loadIssuerCertificate(environment.config).rawCertificate,
          keyId: issuerSigningKeyId(environment.config),
        }),
      ],
    });
    expect(options.holder).toMatchObject({
      method: "jwk",
      jwk: { jwk: { jwk: holder.publicJwk } },
    });
    expect(options.headerType).toBe("dc+sd-jwt");
    expect(options.hashingAlgorithm).toBe("sha-384");
    expect(options.payload).toMatchObject({
      vct,
      exp: Math.floor(NOW.getTime() / 1000) + 365 * 24 * 60 * 60,
      status: { status_list: STATUS_REFERENCE },
    });
    expect(options.payload).not.toHaveProperty("iat");
    expect(options.disclosureFrame).toEqual(disclosureFrame);
  });

  it("omits hashingAlgorithm when the digest algorithm is omitted", async () => {
    const environment = await createIssuerSigningEnvironment("sd-jwt-default-");
    cleanup = environment.cleanup;
    const holder = await generateEs256Key();
    const options = sdJwtCredentialSignOptions({
      config: environment.config,
      holderJwk: holder.publicJwk,
      now: NOW,
    });

    expect(options).not.toHaveProperty("hashingAlgorithm");
  });

  it.each(["sha-256", "sha-384", "sha-512"] as const)(
    "retains the explicit %s digest algorithm",
    async (digestAlgorithm) => {
      const environment = await createIssuerSigningEnvironment("sd-jwt-digest-");
      cleanup = environment.cleanup;
      const holder = await generateEs256Key();
      const options = sdJwtCredentialSignOptions({
        config: environment.config,
        holderJwk: holder.publicJwk,
        digestAlgorithm,
        now: NOW,
      });

      expect(options.hashingAlgorithm).toBe(digestAlgorithm);
    },
  );

  it("validates imported claims before building its envelope and frames disclosures", async () => {
    const environment = await createIssuerSigningEnvironment("sd-jwt-imported-");
    cleanup = environment.cleanup;
    const holder = await generateEs256Key();
    const options = importedSdJwtCredentialSignOptions({
      config: environment.config,
      holderJwk: holder.publicJwk,
      definition: importedDefinition,
      claims: importedClaims,
      digestAlgorithm: "sha-512",
      now: NOW,
    });

    expect(options.issuer).toMatchObject({
      method: "x5c",
      issuer: environment.config.issuer_base_url,
      x5c: [
        expect.objectContaining({
          rawCertificate: loadIssuerCertificate(environment.config).rawCertificate,
          keyId: issuerSigningKeyId(environment.config),
        }),
      ],
    });
    expect(options.holder).toMatchObject({
      method: "jwk",
      jwk: { jwk: { jwk: holder.publicJwk } },
    });
    expect(options.headerType).toBe("dc+sd-jwt");
    expect(options.hashingAlgorithm).toBe("sha-512");
    expect(options.payload).toEqual({
      ...importedClaims,
      vct: importedDefinition.vct,
      exp: Math.floor(NOW.getTime() / 1000) + 365 * 24 * 60 * 60,
    });
    expect(options.payload).not.toHaveProperty("iat");
    expect(options.disclosureFrame).toEqual({ _sd: ["member_id"] });

    expect(() =>
      importedSdJwtCredentialSignOptions({
        config: environment.config,
        holderJwk: {},
        definition: importedDefinition,
        claims: { ...importedClaims, exp: 1 },
        now: NOW,
      }),
    ).toThrow("Claims are not issuable");
  });
});
