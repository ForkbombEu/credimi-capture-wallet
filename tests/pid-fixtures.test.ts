import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Mdoc, SdJwtVcService } from "@credo-ts/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, createIssuerSigningContext, initIssuer } from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { PID_FIXTURE_IDS, pidFixtureSubject } from "../src/configurations/shared/pid-fixtures.js";
import { PID_MDOC_NAMESPACE } from "../src/credential-definitions.js";
import { mdocCredentialSignOptions, sdJwtCredentialSignOptions } from "../src/credential.js";
import type { AppConfig, JsonRecord } from "../src/types.js";

const holderJwk: JsonRecord = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF4PabXB8yiT4rHXkLExz-b8l2kKj7sKk1g",
  y: "x_FEzRu9S2Z9ZvRI4fOMrPCvPj0S6TBOA4jI8tKXPjo",
};

describe("PID claim-set fixtures", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "pid-fixtures-test-"));
  let config: AppConfig = { ...DEFAULT_CONFIG, data_dir: dataDir };

  beforeAll(async () => {
    const initialized = await initIssuer({ data_dir: dataDir, force: true });
    const issuer = resolvedIssuerConfigurationById(initialized, "eu-pid-device-bound");
    if (!issuer) throw new Error("device-bound issuer configuration unavailable");
    config = issuerAppConfig(initialized, issuer);
  });

  afterAll(() => {
    rmSync(dataDir, { force: true, recursive: true });
  });

  async function issuedSdJwtClaims(fixtureId: string): Promise<JsonRecord> {
    const service = new SdJwtVcService({} as never);
    const signed = await service.sign(
      createIssuerSigningContext(config) as never,
      sdJwtCredentialSignOptions({
        config,
        holderJwk,
        subject: pidFixtureSubject(fixtureId as never),
      }),
    );
    return service.fromCompact(signed.compact).prettyClaims as JsonRecord;
  }

  it("issues the baseline identity when no fixture is selected", async () => {
    const service = new SdJwtVcService({} as never);
    const signed = await service.sign(
      createIssuerSigningContext(config) as never,
      sdJwtCredentialSignOptions({ config, holderJwk }),
    );

    expect(service.fromCompact(signed.compact).prettyClaims).toMatchObject({
      family_name: "Rossi",
      age_over_18: true,
      document_number: "CREDIMI-DEMO-001",
    });
  });

  it.each([
    ["pid_under_18", { age_over_18: false, birthdate: "2012-03-04" }],
    ["pid_family_name_uppercase", { family_name: "ROSSI" }],
    ["pid_family_name_trailing_space", { family_name: "Rossi " }],
    ["pid_multiple_nationalities", { nationalities: ["FR", "DE"] }],
    ["pid_expiry_2032", { date_of_expiry: "2032-01-01" }],
    ["pid_person_b", { family_name: "Bianchi", given_name: "Giulia" }],
  ])("issues %s with the claim values the DCQL constraint targets", async (fixtureId, expected) => {
    expect(await issuedSdJwtClaims(fixtureId)).toMatchObject(expected);
  });

  it("varies only the targeted claim between a fixture pair", async () => {
    const withDiacritics = await issuedSdJwtClaims("pid_locality_diacritics");
    const withoutDiacritics = await issuedSdJwtClaims("pid_locality_no_diacritics");

    expect((withDiacritics.address as JsonRecord).locality).toBe("München");
    expect((withoutDiacritics.address as JsonRecord).locality).toBe("Munchen");
    expect(withDiacritics.family_name).toBe(withoutDiacritics.family_name);
    expect(withDiacritics.birthdate).toBe(withoutDiacritics.birthdate);
  });

  it("gives every fixture a distinct document number, so two credentials are not identical", async () => {
    const documentNumbers = PID_FIXTURE_IDS.map(
      (fixtureId) => pidFixtureSubject(fixtureId).documentNumber,
    );

    expect(new Set(documentNumbers).size).toBe(documentNumbers.length);
  });

  it("carries the fixture claims into an issued mdoc as well", async () => {
    const signOptions = mdocCredentialSignOptions({
      config,
      holderJwk,
      subject: pidFixtureSubject("pid_under_18"),
    });
    const mdoc = await Mdoc.sign(createIssuerSigningContext(config) as never, signOptions);

    expect(mdoc.issuerSignedNamespaces[PID_MDOC_NAMESPACE]).toMatchObject({
      age_over_18: false,
      document_number: "CREDIMI-DEMO-U18",
    });
  });
});
