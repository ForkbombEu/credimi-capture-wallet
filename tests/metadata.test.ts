import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { euPidDeviceBound } from "../src/configurations/eu-pid-device-bound/index.js";
import { euPidJwtProofOnly } from "../src/configurations/eu-pid-jwt-proof-only/index.js";
import {
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "../src/credential-definitions.js";
import { CREDIMI_LOGO_URL } from "../src/credential.js";
import {
  credentialIssuerMetadata,
  jwtVcIssuerMetadata,
  mdocCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/metadata.js";
import type { JsonRecord } from "../src/types.js";

describe("metadata", () => {
  it("uses the credential issuer identifier for authorization server discovery", () => {
    const issuerMetadata = credentialIssuerMetadata(DEFAULT_CONFIG, euPidDeviceBound) as JsonRecord;

    expect(issuerMetadata.authorization_servers).toBeUndefined();
  });

  it("advertises credential scope in issuer metadata", () => {
    const conforming = credentialIssuerMetadata(DEFAULT_CONFIG, euPidDeviceBound) as JsonRecord;
    const jwtOnly = credentialIssuerMetadata(DEFAULT_CONFIG, euPidJwtProofOnly) as JsonRecord;
    const configurations = {
      ...(conforming.credential_configurations_supported as JsonRecord),
      ...(jwtOnly.credential_configurations_supported as JsonRecord),
    };
    const expectedScopes = {
      [sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required")]:
        `${DEFAULT_CONFIG.credential_scope}.sd-jwt.key-attestation-required`,
      [sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof")]:
        `${DEFAULT_CONFIG.credential_scope}.sd-jwt.jwt-proof`,
      [mdocCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required")]:
        `${DEFAULT_CONFIG.credential_scope}.mdoc.key-attestation-required`,
      [mdocCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof")]:
        `${DEFAULT_CONFIG.credential_scope}.mdoc.jwt-proof`,
    };

    expect(
      Object.fromEntries(
        Object.entries(configurations).map(([id, configuration]) => [
          id,
          (configuration as JsonRecord).scope,
        ]),
      ),
    ).toEqual(expectedScopes);
  });

  it("advertises explicit display names in issuer metadata", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG, euPidJwtProofOnly) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof")
    ] as JsonRecord;
    const credentialMetadata = configuration.credential_metadata as JsonRecord;

    expect(configuration.vct).toBe(PID_SD_JWT_VCT);
    expect(configuration.display).toBeUndefined();
    expect(credentialMetadata.display).toEqual([
      {
        name: "Credimi Demo PID (SD-JWT VC, JWT proof, no key attestation)",
        locale: "en-US",
        logo: { uri: CREDIMI_LOGO_URL, alt_text: "Credimi" },
      },
    ]);
    expect(credentialMetadata.claims).toContainEqual({
      path: ["given_name"],
      mandatory: true,
      display: [{ name: "Given Name", locale: "en-US" }],
    });
    expect((credentialMetadata.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      PID_SD_JWT_CLAIMS.map((claim) => claim.split(".")),
    );
  });

  it("advertises separate JWT-only and key-attestation-required configurations", () => {
    const conforming = credentialIssuerMetadata(DEFAULT_CONFIG, euPidDeviceBound) as JsonRecord;
    const jwtOnly = credentialIssuerMetadata(DEFAULT_CONFIG, euPidJwtProofOnly) as JsonRecord;
    const conformingConfigurations = conforming.credential_configurations_supported as JsonRecord;
    const jwtOnlyConfigurations = jwtOnly.credential_configurations_supported as JsonRecord;
    const sdJwtAttested = conformingConfigurations[
      sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required")
    ] as JsonRecord;
    const sdJwtProof = jwtOnlyConfigurations[
      sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof")
    ] as JsonRecord;
    const mdocAttested = conformingConfigurations[
      mdocCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required")
    ] as JsonRecord;
    const mdocJwtProof = jwtOnlyConfigurations[
      mdocCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof")
    ] as JsonRecord;

    expect(Object.keys(conformingConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required"),
      mdocCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required"),
    ]);
    expect(Object.keys(jwtOnlyConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof"),
      mdocCredentialConfigurationId(DEFAULT_CONFIG, "jwt-proof"),
    ]);
    const keyAttestationRequired = {
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
      attestation: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
    };
    const jwtProof = {
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
      },
    };
    expect(sdJwtAttested.proof_types_supported).toEqual(keyAttestationRequired);
    expect(sdJwtProof.proof_types_supported).toEqual(jwtProof);
    expect(sdJwtAttested.vct).toBe(PID_SD_JWT_VCT);
    expect(sdJwtProof.vct).toBe(PID_SD_JWT_VCT);
    expect(sdJwtAttested.cryptographic_binding_methods_supported).toEqual(["jwk"]);
    expect(sdJwtProof.credential_signing_alg_values_supported).toEqual(["ES256"]);

    expect(mdocAttested.proof_types_supported).toEqual(keyAttestationRequired);
    expect(mdocJwtProof.proof_types_supported).toEqual(jwtProof);
    expect(mdocAttested.doctype).toBe(PID_MDOC_DOCTYPE);
    expect(mdocJwtProof.doctype).toBe(PID_MDOC_DOCTYPE);
    expect(mdocAttested.cryptographic_binding_methods_supported).toEqual(["cose_key"]);
    expect(mdocJwtProof.credential_signing_alg_values_supported).toEqual([-7]);
  });

  it("advertises the MDOC PID credential configuration", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG, euPidDeviceBound) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      mdocCredentialConfigurationId(DEFAULT_CONFIG, "key-attestation-required")
    ] as JsonRecord;
    const credentialMetadata = configuration.credential_metadata as JsonRecord;
    const claims = credentialMetadata.claims as JsonRecord[];

    expect(configuration.format).toBe("mso_mdoc");
    expect(configuration.doctype).toBe(PID_MDOC_DOCTYPE);
    expect(configuration.display).toBeUndefined();
    expect(configuration.claims).toBeUndefined();
    expect(credentialMetadata.display).toEqual([
      {
        name: "Credimi Demo PID (MDOC, JWT or attestation proof, key attestation required)",
        locale: "en-US",
        logo: { uri: CREDIMI_LOGO_URL, alt_text: "Credimi" },
      },
    ]);
    expect(claims).toContainEqual({
      path: [PID_MDOC_NAMESPACE, "given_name"],
      mandatory: true,
      display: [{ name: "Given Name", locale: "en-US" }],
    });
    expect(claims.map((claim) => claim.path)).toEqual(
      PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
    );
  });

  it("advertises JWT VC issuer metadata for the HTTPS issuer identifier", () => {
    const metadata = jwtVcIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;

    expect(metadata).toEqual({
      issuer: DEFAULT_CONFIG.issuer_base_url,
      jwks_uri: `${DEFAULT_CONFIG.issuer_base_url}/credential-jwks.json`,
    });
  });
});
