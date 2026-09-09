import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Kms, SdJwtVcService } from "@credo-ts/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, createIssuerSigningContext, initIssuer } from "../src/config.js";
import { resolvedIssuerConfigurationById } from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { DEGREE_SD_JWT_VCT } from "../src/credential-definitions.js";
import {
  degreeSdJwtCredentialSignOptions,
  mdocCredentialSignOptions,
  sdJwtCredentialSignOptions,
} from "../src/credential.js";
import type { JsonRecord } from "../src/types.js";

describe("degree SD-JWT VC", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "degree-credential-test-"));
  let config = { ...DEFAULT_CONFIG, data_dir: dataDir };

  beforeAll(async () => {
    const initialized = await initIssuer({ data_dir: dataDir, force: true });
    const issuer = resolvedIssuerConfigurationById(initialized, "eu-pid-device-bound");
    if (!issuer) throw new Error("device-bound issuer configuration unavailable");
    config = issuerAppConfig(initialized, issuer);
  });

  afterAll(() => {
    rmSync(dataDir, { force: true, recursive: true });
  });

  it("contains the degree claims used by textual-encoding conformance tests", async () => {
    const holderJwk: JsonRecord = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF4PabXB8yiT4rHXkLExz-b8l2kKj7sKk1g",
      y: "x_FEzRu9S2Z9ZvRI4fOMrPCvPj0S6TBOA4jI8tKXPjo",
    };
    const service = new SdJwtVcService({} as never);
    const compact = (
      await service.sign(
        createIssuerSigningContext(config) as never,
        degreeSdJwtCredentialSignOptions({ config, holderJwk }),
      )
    ).compact;

    const decoded = service.fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject({
      vct: DEGREE_SD_JWT_VCT,
      name: "Arthur Dent",
      address: {
        street_address: "42 Market Street",
        locality: "Milliways",
        postal_code: "12345",
      },
      degrees: [
        { type: "Bachelor of Science", university: "University of Betelgeuse" },
        { type: "Master of Science", university: "University of Betelgeuse" },
        { university: "University of Betelgeuse" },
      ],
      academic_programmes: [["Bachelor of Science"], ["Master of Science", "Doctor of Philosophy"]],
      nationalities: ["British", "Betelgeusian"],
    });
    expect(decoded.holder?.method).toBe("jwk");
    if (decoded.holder?.method !== "jwk") throw new Error("expected JWK holder binding");
    expect(Kms.PublicJwk.fromUnknown(holderJwk).equals(decoded.holder.jwk)).toBe(true);
  });
  it("adds status references only when explicitly requested", () => {
    const holderJwk: JsonRecord = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF4PabXB8yiT4rHXkLExz-b8l2kKj7sKk1g",
      y: "x_FEzRu9S2Z9ZvRI4fOMrPCvPj0S6TBOA4jI8tKXPjo",
    };
    const reference = { uri: "https://tsl.example.test/status/1", idx: 7 };

    expect(sdJwtCredentialSignOptions({ config, holderJwk }).payload).not.toHaveProperty("status");
    expect(
      sdJwtCredentialSignOptions({ config, holderJwk, statusListReference: reference }).payload,
    ).toMatchObject({ status: { status_list: reference } });
    expect(mdocCredentialSignOptions({ config, holderJwk }).statusInfo).toBeUndefined();
    expect(
      mdocCredentialSignOptions({ config, holderJwk, statusListReference: reference }),
    ).toMatchObject({
      statusInfo: { index: 7, uri: reference.uri },
    });
  });
});
