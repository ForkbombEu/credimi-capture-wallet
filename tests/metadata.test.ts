import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { euPidDeviceBound } from "../src/configurations/eu-pid-device-bound/index.js";
import { euPidJwtKeyAttestation } from "../src/configurations/eu-pid-jwt-key-attestation/index.js";
import { euPidJwtProofOnly } from "../src/configurations/eu-pid-jwt-proof-only/index.js";
import {
  degreeSdJwtCredentialConfigurationId,
  domesticPidCredentialConfigurationId,
  mdocCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import {
  DEGREE_SD_JWT_CLAIMS,
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_MDOC_NAMESPACE,
  DOMESTIC_PID_SD_JWT_CLAIMS,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_CLAIMS,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "../src/credentials/definitions.js";
import { CREDIMI_LOGO_URL } from "../src/credentials/signing.js";
import { credentialIssuerMetadata, jwtVcIssuerMetadata } from "../src/openid4vci/metadata.js";
import type { JsonRecord } from "../src/types.js";

// An empty data directory, so the metadata never depends on key material in the working tree: with
// no issuer encryption key, it advertises no credential request or response encryption.
const config = { ...DEFAULT_CONFIG, data_dir: mkdtempSync(join(tmpdir(), "metadata-test-")) };
afterAll(() => rmSync(config.data_dir, { recursive: true, force: true }));

describe("metadata", () => {
  it("uses the credential issuer identifier for authorization server discovery", () => {
    const issuerMetadata = credentialIssuerMetadata(config, euPidDeviceBound) as JsonRecord;

    expect(issuerMetadata.authorization_servers).toBeUndefined();
  });

  it("advertises no encryption without an issuer encryption key", () => {
    const issuerMetadata = credentialIssuerMetadata(config, euPidDeviceBound) as JsonRecord;

    expect(issuerMetadata.credential_request_encryption).toBeUndefined();
    expect(issuerMetadata.credential_response_encryption).toBeUndefined();
  });

  it("advertises credential scope in issuer metadata", () => {
    const conforming = credentialIssuerMetadata(config, euPidDeviceBound) as JsonRecord;
    const jwtOnly = credentialIssuerMetadata(config, euPidJwtProofOnly) as JsonRecord;
    const configurations = {
      ...(conforming.credential_configurations_supported as JsonRecord),
      ...(jwtOnly.credential_configurations_supported as JsonRecord),
    };
    const expectedScopes = {
      [sdJwtCredentialConfigurationId(config, "key-attestation-required")]:
        `${config.credential_scope}.sd-jwt.key-attestation-required`,
      [sdJwtCredentialConfigurationId(config, "jwt-proof")]:
        `${config.credential_scope}.sd-jwt.jwt-proof`,
      [mdocCredentialConfigurationId(config, "key-attestation-required")]:
        `${config.credential_scope}.mdoc.key-attestation-required`,
      [mdocCredentialConfigurationId(config, "jwt-proof")]:
        `${config.credential_scope}.mdoc.jwt-proof`,
      [degreeSdJwtCredentialConfigurationId(config, "key-attestation-required")]:
        "urn:credimi:degree:1.sd-jwt.key-attestation-required",
      [degreeSdJwtCredentialConfigurationId(config, "jwt-proof")]:
        "urn:credimi:degree:1.sd-jwt.jwt-proof",
      [numericSdJwtCredentialConfigurationId(config, "key-attestation-required")]:
        "urn:credimi:numeric-claims:1.sd-jwt.key-attestation-required",
      [numericSdJwtCredentialConfigurationId(config, "jwt-proof")]:
        "urn:credimi:numeric-claims:1.sd-jwt.jwt-proof",
      [domesticPidCredentialConfigurationId("dc+sd-jwt", "key-attestation-required")]:
        "urn:eudi:pid:xx:1.sd-jwt.key-attestation-required",
      [domesticPidCredentialConfigurationId("mso_mdoc", "key-attestation-required")]:
        "urn:eudi:pid:xx:1.mdoc.key-attestation-required",
      [domesticPidCredentialConfigurationId("dc+sd-jwt", "jwt-proof")]:
        "urn:eudi:pid:xx:1.sd-jwt.jwt-proof",
      [domesticPidCredentialConfigurationId("mso_mdoc", "jwt-proof")]:
        "urn:eudi:pid:xx:1.mdoc.jwt-proof",
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
    const metadata = credentialIssuerMetadata(config, euPidJwtProofOnly) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      sdJwtCredentialConfigurationId(config, "jwt-proof")
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

  it("advertises only JWT proofs with key attestation for the dedicated PID issuer", () => {
    const metadata = credentialIssuerMetadata(config, euPidJwtKeyAttestation) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const sdJwtId = sdJwtCredentialConfigurationId(config, "jwt-key-attestation-required");
    const mdocId = mdocCredentialConfigurationId(config, "jwt-key-attestation-required");
    const sdJwt = configurations[sdJwtId] as JsonRecord;
    const mdoc = configurations[mdocId] as JsonRecord;
    const proofTypes = {
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
    };

    expect(Object.keys(configurations)).toEqual([sdJwtId, mdocId]);
    expect(sdJwt.scope).toBe(`${config.credential_scope}.sd-jwt.jwt-key-attestation-required`);
    expect(mdoc.scope).toBe(`${config.credential_scope}.mdoc.jwt-key-attestation-required`);
    expect(sdJwt.vct).toBe(PID_SD_JWT_VCT);
    expect(mdoc.doctype).toBe(PID_MDOC_DOCTYPE);
    expect(sdJwt.proof_types_supported).toEqual(proofTypes);
    expect(mdoc.proof_types_supported).toEqual(proofTypes);
  });

  it("advertises separate JWT-only and key-attestation-required configurations", () => {
    const conforming = credentialIssuerMetadata(config, euPidDeviceBound) as JsonRecord;
    const jwtOnly = credentialIssuerMetadata(config, euPidJwtProofOnly) as JsonRecord;
    const conformingConfigurations = conforming.credential_configurations_supported as JsonRecord;
    const jwtOnlyConfigurations = jwtOnly.credential_configurations_supported as JsonRecord;
    const sdJwtAttested = conformingConfigurations[
      sdJwtCredentialConfigurationId(config, "key-attestation-required")
    ] as JsonRecord;
    const sdJwtProof = jwtOnlyConfigurations[
      sdJwtCredentialConfigurationId(config, "jwt-proof")
    ] as JsonRecord;
    const mdocAttested = conformingConfigurations[
      mdocCredentialConfigurationId(config, "key-attestation-required")
    ] as JsonRecord;
    const mdocJwtProof = jwtOnlyConfigurations[
      mdocCredentialConfigurationId(config, "jwt-proof")
    ] as JsonRecord;
    const degree = conformingConfigurations[
      degreeSdJwtCredentialConfigurationId(config, "key-attestation-required")
    ] as JsonRecord;
    const numeric = conformingConfigurations[
      numericSdJwtCredentialConfigurationId(config, "key-attestation-required")
    ] as JsonRecord;

    expect(Object.keys(conformingConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(config, "key-attestation-required"),
      mdocCredentialConfigurationId(config, "key-attestation-required"),
      degreeSdJwtCredentialConfigurationId(config, "key-attestation-required"),
      numericSdJwtCredentialConfigurationId(config, "key-attestation-required"),
      domesticPidCredentialConfigurationId("dc+sd-jwt", "key-attestation-required"),
      domesticPidCredentialConfigurationId("mso_mdoc", "key-attestation-required"),
    ]);
    expect(Object.keys(jwtOnlyConfigurations)).toEqual([
      sdJwtCredentialConfigurationId(config, "jwt-proof"),
      mdocCredentialConfigurationId(config, "jwt-proof"),
      degreeSdJwtCredentialConfigurationId(config, "jwt-proof"),
      numericSdJwtCredentialConfigurationId(config, "jwt-proof"),
      domesticPidCredentialConfigurationId("dc+sd-jwt", "jwt-proof"),
      domesticPidCredentialConfigurationId("mso_mdoc", "jwt-proof"),
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
    expect(degree.vct).toBe(DEGREE_SD_JWT_VCT);
    expect(
      ((degree.credential_metadata as JsonRecord).claims as JsonRecord[]).map(
        (claim) => claim.path,
      ),
    ).toEqual(DEGREE_SD_JWT_CLAIMS.map((claim) => claim.split(".")));
    expect(numeric.vct).toBe(NUMERIC_SD_JWT_VCT);
    expect(
      ((numeric.credential_metadata as JsonRecord).claims as JsonRecord[]).map(
        (claim) => claim.path,
      ),
    ).toEqual(NUMERIC_SD_JWT_CLAIMS.map((claim) => claim.split(".")));
  });

  it("advertises the MDOC PID credential configuration", () => {
    const metadata = credentialIssuerMetadata(config, euPidDeviceBound) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      mdocCredentialConfigurationId(config, "key-attestation-required")
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

  it("advertises the domestic PID with its domestic type and namespace", () => {
    const metadata = credentialIssuerMetadata(config, euPidJwtProofOnly) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const sdJwt = configurations[
      domesticPidCredentialConfigurationId("dc+sd-jwt", "jwt-proof")
    ] as JsonRecord;
    const mdoc = configurations[
      domesticPidCredentialConfigurationId("mso_mdoc", "jwt-proof")
    ] as JsonRecord;
    const claimPaths = (configuration: JsonRecord) =>
      ((configuration.credential_metadata as JsonRecord).claims as JsonRecord[]).map(
        (claim) => claim.path,
      );

    expect(sdJwt.vct).toBe(DOMESTIC_PID_SD_JWT_VCT);
    expect(claimPaths(sdJwt)).toEqual(DOMESTIC_PID_SD_JWT_CLAIMS.map((claim) => claim.split(".")));
    expect(mdoc.doctype).toBe(PID_MDOC_DOCTYPE);
    expect(claimPaths(mdoc)).toEqual([
      ...PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
      [DOMESTIC_PID_MDOC_NAMESPACE, "credimi_domestic_claim"],
    ]);
    expect((mdoc.credential_metadata as JsonRecord).claims).toContainEqual({
      path: [DOMESTIC_PID_MDOC_NAMESPACE, "credimi_domestic_claim"],
      mandatory: true,
      display: [{ name: "Credimi Domestic Claim", locale: "en-US" }],
    });
  });

  it("advertises JWT VC issuer metadata for the HTTPS issuer identifier", () => {
    const metadata = jwtVcIssuerMetadata(config) as JsonRecord;

    expect(metadata).toEqual({
      issuer: config.issuer_base_url,
      jwks_uri: `${config.issuer_base_url}/credential-jwks.json`,
    });
  });
});
