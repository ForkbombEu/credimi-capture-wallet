import { SdJwtVcService } from "@credo-ts/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { createIssuerSigningContext } from "../src/config/key-material.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { sdJwtCredentialSignOptions } from "../src/credentials/signing.js";
import {
  STATUS_REFERENCE_FIXTURES,
  derivedStatusListUri,
} from "../src/status-list/reference-fixtures.js";
import type {
  AppConfig,
  JsonRecord,
  StatusListReference,
  StatusReferenceFixture,
} from "../src/types.js";
import { createIssuerTestEnvironmentFactory, requireIssuer } from "./support/environment.js";
import { holderJwk } from "./support/keys.js";

const allocated: StatusListReference = {
  uri: "https://status-list.example.test/statuslists/1",
  idx: 42,
};

describe("Token Status List reference fixtures", () => {
  const environment = createIssuerTestEnvironmentFactory({
    prefix: "status-reference-test-",
    config: { issuer_base_url: DEFAULT_CONFIG.issuer_base_url },
  });
  let config!: AppConfig;

  beforeAll(async () => {
    await environment.initialize();
    config = issuerAppConfig(
      environment.config,
      requireIssuer(environment.config, "eu-pid-device-bound"),
    );
  });

  afterAll(() => {
    environment.cleanup();
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
    [
      "uri_missing_scheme",
      { status_list: { uri: "//status-list.example.test/statuslists/1", idx: allocated.idx } },
    ],
    [
      "uri_space_in_host",
      { status_list: { uri: "https://status-list. example.test/statuslists/1", idx: 42 } },
    ],
    [
      "uri_invalid_percent_encoding",
      { status_list: { uri: `${allocated.uri}%GG`, idx: allocated.idx } },
    ],
    [
      "uri_illegal_characters",
      { status_list: { uri: `${allocated.uri}<token>|1`, idx: allocated.idx } },
    ],
    ["uri_empty", { status_list: { uri: "", idx: allocated.idx } }],
  ])("issues the %s structure the wallet must reject", async (fixture, expected) => {
    expect(await issuedStatusClaim(fixture as StatusReferenceFixture)).toEqual(expected);
  });

  it("keeps the port and userinfo when inserting a space into the host", () => {
    expect(
      derivedStatusListUri(
        "http://user@localhost:8000/token_status_list/EU/x",
        "uri_space_in_host",
      ),
    ).toBe("http://user@loca lhost:8000/token_status_list/EU/x");
    expect(derivedStatusListUri("http://localhost:8000/s?x=1", "uri_missing_scheme")).toBe(
      "//localhost:8000/s?x=1",
    );
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
      "uri_missing_scheme",
      "uri_space_in_host",
      "uri_invalid_percent_encoding",
      "uri_illegal_characters",
      "uri_empty",
    ]);
  });
});
