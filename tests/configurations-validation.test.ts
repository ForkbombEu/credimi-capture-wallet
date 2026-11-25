import { describe, expect, it } from "vitest";
import { attestbookExperimental } from "../src/configurations/attestbook-experimental/index.js";
import { euPidDeviceBound } from "../src/configurations/eu-pid-device-bound/index.js";
import { euPidJwtKeyAttestation } from "../src/configurations/eu-pid-jwt-key-attestation/index.js";
import { euPidJwtProofOnly } from "../src/configurations/eu-pid-jwt-proof-only/index.js";
import { issuerConfigurations } from "../src/configurations/registry.js";
import type { IssuerConfiguration } from "../src/configurations/types.js";
import { validateIssuerConfigurations } from "../src/configurations/validate.js";

type ValidationCase = {
  name: string;
  configurations: readonly IssuerConfiguration[];
  message: string;
};

const validationCases = [
  {
    name: "an empty issuer list",
    configurations: [],
    message: "At least one issuer must be configured",
  },
  {
    name: "a duplicate issuer id",
    configurations: [
      euPidDeviceBound,
      {
        ...euPidJwtKeyAttestation,
        id: euPidDeviceBound.id,
        routeSlug: euPidJwtProofOnly.routeSlug,
        authorizationServer: {
          ...euPidJwtKeyAttestation.authorizationServer,
          externalScope: euPidJwtProofOnly.authorizationServer.externalScope,
        },
      },
    ],
    message: "Duplicate issuer configuration id 'eu-pid-device-bound'",
  },
  {
    name: "a duplicate route slug",
    configurations: [
      euPidDeviceBound,
      {
        ...euPidJwtKeyAttestation,
        routeSlug: euPidDeviceBound.routeSlug,
      },
    ],
    message: "Duplicate issuer route slug 'eu-pid-device-bound'",
  },
  {
    name: "an unsafe route slug",
    configurations: [
      {
        ...euPidDeviceBound,
        routeSlug: "../unsafe",
      } as unknown as IssuerConfiguration,
    ],
    message: "Unsafe issuer route slug '../unsafe'",
  },
  {
    name: "a duplicate upstream authorization scope",
    configurations: [
      euPidDeviceBound,
      {
        ...euPidJwtKeyAttestation,
        authorizationServer: {
          ...euPidJwtKeyAttestation.authorizationServer,
          externalScope: euPidDeviceBound.authorizationServer.externalScope,
        },
      },
    ],
    message: "Duplicate upstream authorization scope 'credimi.capture.eu-pid-device-bound'",
  },
  {
    name: "a conforming JWT-only issuer",
    configurations: [
      {
        ...euPidDeviceBound,
        proofPolicy: "jwt-proof",
      },
    ],
    message: "Conforming issuer 'eu-pid-device-bound' must require key attestation",
  },
  {
    name: "a JWT-only issuer without an explicit non-conforming label",
    configurations: [
      {
        ...euPidJwtProofOnly,
        compliance: "invalid-compliance",
      } as unknown as IssuerConfiguration,
    ],
    message: "JWT-only PID issuer 'eu-pid-jwt-proof-only' must be explicitly non-conforming",
  },
  {
    name: "an experimental issuer without a feature flag",
    configurations: [
      {
        ...euPidDeviceBound,
        compliance: "experimental",
      },
    ],
    message: "Experimental issuer 'eu-pid-device-bound' must be behind a feature flag",
  },
  {
    name: "an Attestbook-importing issuer outside the Attestbook feature",
    configurations: [
      {
        ...euPidDeviceBound,
        importsAttestbookCredentials: true,
      },
    ],
    message:
      "Issuer 'eu-pid-device-bound' imports Attestbook credentials outside the Attestbook feature",
  },
] satisfies readonly ValidationCase[];

describe("issuer configuration validation", () => {
  it.each(validationCases)("rejects $name", ({ configurations, message }) => {
    expect(() => validateIssuerConfigurations(configurations)).toThrow(new Error(message));
  });

  it("accepts the real issuer configuration registry", () => {
    expect(() => validateIssuerConfigurations(issuerConfigurations)).not.toThrow();
    expect(issuerConfigurations).toContain(attestbookExperimental);
  });

  it("allows an experimental JWT-only issuer", () => {
    expect(() =>
      validateIssuerConfigurations([
        {
          ...attestbookExperimental,
          proofPolicy: "jwt-proof",
        },
      ]),
    ).not.toThrow();
  });
});
