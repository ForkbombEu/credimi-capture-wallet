import { DateOnly } from "@owf/cose";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import {
  DEFAULT_ISSUER_CONFIGURATION_ID,
  issuerConfigurations,
  resolvedIssuerConfigurations,
} from "../src/configurations/registry.js";
import { encodeMdocPidClaims } from "../src/configurations/shared/mdoc-encoder.js";
import { pidSubject } from "../src/configurations/shared/pid-data.js";
import { encodeSdJwtPidClaims } from "../src/configurations/shared/sd-jwt-encoder.js";
import type { IssuerConfiguration } from "../src/configurations/types.js";
import { validateIssuerConfigurations } from "../src/configurations/validate.js";

describe("always-on issuer configurations", () => {
  it("registers exactly the conforming and deliberately non-conforming PID issuers", () => {
    expect(DEFAULT_ISSUER_CONFIGURATION_ID).toBe("eu-pid-device-bound");
    expect(issuerConfigurations.map((issuer) => issuer.id)).toEqual([
      "eu-pid-device-bound",
      "eu-pid-jwt-proof-only",
    ]);
    expect(issuerConfigurations.map((issuer) => issuer.compliance)).toEqual([
      "eudi-pid-device-bound",
      "deliberately-nonconforming",
    ]);
  });

  it("derives specification well-known paths from the public service origin", () => {
    const issuers = resolvedIssuerConfigurations({
      ...DEFAULT_CONFIG,
      issuer_base_url: "https://capture.example.test",
      data_dir: "/var/lib/capture",
    });

    expect(issuers[0]).toMatchObject({
      issuerIdentifier: "https://capture.example.test/issuers/eu-pid-device-bound",
      issuerMetadataUrl:
        "https://capture.example.test/.well-known/openid-credential-issuer/issuers/eu-pid-device-bound",
      authorizationServerMetadataUrl:
        "https://capture.example.test/.well-known/oauth-authorization-server/issuers/eu-pid-device-bound",
      upstreamAuthorizationServerIdentifier:
        "https://capture.example.test/authorization-servers/eu-pid-device-bound",
    });
    expect(issuers[1]?.materialDirectory).toBe("/var/lib/capture/issuers/eu-pid-jwt-proof-only");
  });

  it("rejects unsafe, duplicate, and incorrectly labelled issuer configurations", () => {
    const conforming = issuerConfigurations[0];
    const unsafe = {
      ...conforming,
      id: "eu-pid-device-bound",
      routeSlug: "../unsafe",
    } as unknown as IssuerConfiguration;
    const incorrectlyLabelled = {
      ...conforming,
      proofPolicy: "jwt-proof",
    } as IssuerConfiguration;

    expect(() => validateIssuerConfigurations([conforming, conforming])).toThrow(
      "Duplicate issuer configuration id",
    );
    expect(() => validateIssuerConfigurations([unsafe])).toThrow("Unsafe issuer route slug");
    expect(() => validateIssuerConfigurations([incorrectlyLabelled])).toThrow(
      "must require key attestation",
    );
  });

  it("encodes the shared PID fixture with native mdoc value types", () => {
    const subject = pidSubject();
    const sdJwt = encodeSdJwtPidClaims(subject);
    const mdoc = encodeMdocPidClaims(subject);

    expect(sdJwt).toMatchObject({
      given_name: "Mario",
      family_name: "Rossi",
      birthdate: "1990-01-01",
      place_of_birth: { locality: "Roma" },
    });
    expect(mdoc.birth_date).toBeInstanceOf(DateOnly);
    expect(String(mdoc.birth_date)).toBe("1990-01-01");
    expect(mdoc.expiry_date).toBeInstanceOf(DateOnly);
    expect(mdoc.issuance_date).toBeInstanceOf(DateOnly);
    expect(mdoc.portrait).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(mdoc.portrait as Uint8Array).subarray(0, 3)).toEqual(
      Buffer.from([0xff, 0xd8, 0xff]),
    );
  });
});
