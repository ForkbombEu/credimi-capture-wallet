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

  it("discloses degree object and array interiors claim by claim", async () => {
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
    const disclosures = decodeDisclosures(compact);
    const [issuerJwt] = compact.split("~");

    // Each degree entry is its own disclosure and keeps `type`/`university` separate inside it,
    // so `degrees[2].university` is withholdable while the other entries disclose `type`. Entry 2
    // carries a single digest because it has no `type`.
    const entryDigests = disclosures.flatMap((disclosure) =>
      disclosure.kind === "selective-element" ? [disclosure.digests] : [],
    );
    expect(entryDigests).toEqual([2, 2, 1]);
    expect(
      disclosures.filter(
        (disclosure) => disclosure.kind === "property" && disclosure.name === "university",
      ),
    ).toHaveLength(3);

    // Every academic programme string is addressable on its own, including academic_programmes[1][1].
    expect(
      disclosures.flatMap((disclosure) =>
        disclosure.kind === "value-element" ? [disclosure.value] : [],
      ),
    ).toEqual(["Bachelor of Science", "Master of Science", "Doctor of Philosophy"]);

    // `address` members are separate disclosures, matching the `address.*` paths advertised in
    // the credential configuration, so `locality` can be revealed on its own.
    expect(
      disclosures
        .flatMap((disclosure) =>
          disclosure.kind === "property" &&
          ["street_address", "locality", "postal_code"].includes(disclosure.name)
            ? [disclosure.name]
            : [],
        )
        .sort(),
    ).toEqual(["locality", "postal_code", "street_address"]);

    const addressLocality = disclosures.filter(
      (disclosure) =>
        disclosure.kind === "property" &&
        (disclosure.name === "address" || disclosure.name === "locality"),
    );
    const addressLocalityOnly = service.fromCompact(
      `${issuerJwt}~${addressLocality.map((disclosure) => disclosure.raw).join("~")}~`,
    );
    expect(addressLocalityOnly.prettyClaims.address).toEqual({ locality: "Milliways" });

    const degreeTypes = disclosures.filter(
      (disclosure) =>
        (disclosure.kind === "property" &&
          (disclosure.name === "degrees" || disclosure.name === "type")) ||
        (disclosure.kind === "selective-element" && disclosure.digests === 2),
    );
    const degreeTypesOnly = service.fromCompact(
      `${issuerJwt}~${degreeTypes.map((disclosure) => disclosure.raw).join("~")}~`,
    );
    expect(degreeTypesOnly.prettyClaims.degrees).toEqual([
      { type: "Bachelor of Science" },
      { type: "Master of Science" },
    ]);
    expect(JSON.stringify(degreeTypesOnly.prettyClaims)).not.toContain("University of Betelgeuse");

    const lastProgramme = disclosures.filter(
      (disclosure) =>
        (disclosure.kind === "property" && disclosure.name === "academic_programmes") ||
        (disclosure.kind === "array-element" && disclosure.elements === 2) ||
        (disclosure.kind === "value-element" && disclosure.value === "Doctor of Philosophy"),
    );
    const lastProgrammeOnly = service.fromCompact(
      `${issuerJwt}~${lastProgramme.map((disclosure) => disclosure.raw).join("~")}~`,
    );
    expect(lastProgrammeOnly.prettyClaims.academic_programmes).toEqual([["Doctor of Philosophy"]]);
    expect(JSON.stringify(lastProgrammeOnly.prettyClaims)).not.toContain("Bachelor of Science");
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

/**
 * A decoded SD-JWT disclosure, classified by what it makes disclosable: an object property, an
 * array element whose own members stay selectively disclosable, a nested array, or a plain value.
 */
type DecodedDisclosure = { raw: string } & (
  | { kind: "property"; name: string; value: unknown }
  | { kind: "selective-element"; digests: number }
  | { kind: "array-element"; elements: number }
  | { kind: "value-element"; value: unknown }
);

function decodeDisclosures(compact: string): DecodedDisclosure[] {
  const [, ...parts] = compact.split("~");
  return parts
    .filter((part) => part.length > 0)
    .map((raw): DecodedDisclosure => {
      const decoded: unknown = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
      if (!Array.isArray(decoded) || decoded.length < 2) {
        throw new Error(`malformed disclosure: ${raw}`);
      }
      if (decoded.length > 2) {
        return { raw, kind: "property", name: String(decoded[1]), value: decoded[2] };
      }
      const value: unknown = decoded[1];
      if (Array.isArray(value)) return { raw, kind: "array-element", elements: value.length };
      if (
        value !== null &&
        typeof value === "object" &&
        "_sd" in value &&
        Array.isArray(value._sd)
      ) {
        return { raw, kind: "selective-element", digests: value._sd.length };
      }
      return { raw, kind: "value-element", value };
    });
}
