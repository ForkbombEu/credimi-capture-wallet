import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SdJwtVcService } from "@credo-ts/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, createIssuerSigningContext, initIssuer } from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { sdJwtCredentialSignOptions } from "../src/credential.js";
import { STATUS_REFERENCE_FIXTURES } from "../src/status-reference.js";
import type {
  AppConfig,
  JsonRecord,
  StatusListReference,
  StatusReferenceFixture,
} from "../src/types.js";

const holderJwk: JsonRecord = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF4PabXB8yiT4rHXkLExz-b8l2kKj7sKk1g",
  y: "x_FEzRu9S2Z9ZvRI4fOMrPCvPj0S6TBOA4jI8tKXPjo",
};

const allocated: StatusListReference = {
  uri: "https://status-list.example.test/statuslists/1",
  idx: 42,
};

describe("Token Status List reference fixtures", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "status-reference-test-"));
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

  async function issuedStatusClaim(fixture?: StatusReferenceFixture): Promise<unknown> {
    const service = new SdJwtVcService({} as never);
    const signed = await service.sign(
      createIssuerSigningContext(config) as never,
      sdJwtCredentialSignOptions({
        config,
        holderJwk,
        statusListReference: allocated,
        ...(fixture ? { statusReference: fixture } : {}),
      }),
    );
    return (service.fromCompact(signed.compact).prettyClaims as JsonRecord).status;
  }

  it("embeds the allocated reference when no fixture is selected", async () => {
    expect(await issuedStatusClaim()).toEqual({ status_list: allocated });
    expect(await issuedStatusClaim("valid")).toEqual({ status_list: allocated });
  });

  it.each([
    ["status_without_status_list", {}],
    ["negative_index", { status_list: { uri: allocated.uri, idx: -1 } }],
    ["missing_index", { status_list: { uri: allocated.uri } }],
    ["malformed_uri", { status_list: { uri: "not a uri", idx: allocated.idx } }],
    ["missing_uri", { status_list: { idx: allocated.idx } }],
  ])("issues the %s structure the wallet must reject", async (fixture, expected) => {
    expect(await issuedStatusClaim(fixture as StatusReferenceFixture)).toEqual(expected);
  });

  it("omits the claim entirely when no reference was allocated", async () => {
    const service = new SdJwtVcService({} as never);
    const signed = await service.sign(
      createIssuerSigningContext(config) as never,
      sdJwtCredentialSignOptions({ config, holderJwk, statusReference: "negative_index" }),
    );

    expect(service.fromCompact(signed.compact).prettyClaims).not.toHaveProperty("status");
  });

  it("exposes every fixture of the union", () => {
    expect(STATUS_REFERENCE_FIXTURES).toEqual([
      "valid",
      "status_without_status_list",
      "negative_index",
      "missing_index",
      "malformed_uri",
      "missing_uri",
    ]);
  });
});
