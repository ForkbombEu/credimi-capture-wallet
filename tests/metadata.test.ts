import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import {
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "../src/credential-definitions.js";
import { CREDIMI_LOGO_URL } from "../src/credential.js";
import {
  authorizationServerMetadata,
  credentialIssuerMetadata,
  credentialOffer,
  jwtVcIssuerMetadata,
  mdocCredentialConfigurationId,
} from "../src/metadata.js";
import type { JsonRecord } from "../src/types.js";

describe("metadata", () => {
  it("advertises credential scope in issuer metadata", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const jwtConfiguration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`
    ] as JsonRecord;
    const mdocConfiguration = configurations[
      mdocCredentialConfigurationId(DEFAULT_CONFIG)
    ] as JsonRecord;

    expect(jwtConfiguration.scope).toBe(`${DEFAULT_CONFIG.credential_scope}.jwt`);
    expect(mdocConfiguration.scope).toBe(`${DEFAULT_CONFIG.credential_scope}.mdoc.jwt`);
  });

  it("advertises explicit display names in issuer metadata", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`
    ] as JsonRecord;
    const credentialMetadata = configuration.credential_metadata as JsonRecord;

    expect(configuration.vct).toBe(PID_SD_JWT_VCT);
    expect(configuration.display).toBeUndefined();
    expect(credentialMetadata.display).toEqual([
      {
        name: "Credimi Demo PID (SD-JWT VC, proof JWT)",
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

  it("advertises the supported JWT proof credential configurations", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const jwtConfiguration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`
    ] as JsonRecord;
    const mdocConfiguration = configurations[
      mdocCredentialConfigurationId(DEFAULT_CONFIG)
    ] as JsonRecord;

    expect(Object.keys(configurations)).toEqual([
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`,
      mdocCredentialConfigurationId(DEFAULT_CONFIG),
    ]);
    expect(jwtConfiguration.proof_types_supported).toEqual({
      jwt: { proof_signing_alg_values_supported: ["ES256"] },
    });
    expect(jwtConfiguration.cryptographic_binding_methods_supported).toEqual(["jwk"]);
    expect(jwtConfiguration.credential_signing_alg_values_supported).toEqual(["ES256"]);
    expect(mdocConfiguration.proof_types_supported).toEqual({
      jwt: { proof_signing_alg_values_supported: ["ES256"] },
    });
    expect(mdocConfiguration.cryptographic_binding_methods_supported).toEqual(["cose_key"]);
    expect(mdocConfiguration.credential_signing_alg_values_supported).toEqual([-7, -9]);
  });

  it("advertises the MDOC PID credential configuration", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      mdocCredentialConfigurationId(DEFAULT_CONFIG)
    ] as JsonRecord;
    const credentialMetadata = configuration.credential_metadata as JsonRecord;
    const claims = credentialMetadata.claims as JsonRecord[];

    expect(configuration.format).toBe("mso_mdoc");
    expect(configuration.doctype).toBe(PID_MDOC_DOCTYPE);
    expect(configuration.display).toBeUndefined();
    expect(configuration.claims).toBeUndefined();
    expect(credentialMetadata.display).toEqual([
      {
        name: "Credimi Demo PID (MDOC, proof JWT)",
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

  it("advertises client attestation support in authorization server metadata", () => {
    const metadata = authorizationServerMetadata(DEFAULT_CONFIG) as JsonRecord;

    expect(metadata.token_endpoint_auth_methods_supported).toEqual([
      "none",
      "private_key_jwt",
      "attest_jwt_client_auth",
    ]);
    expect(metadata.token_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
    expect(metadata.client_attestation_signing_alg_values_supported).toEqual(["ES256"]);
    expect(metadata.client_attestation_pop_signing_alg_values_supported).toEqual(["ES256"]);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);
  });

  it("advertises JWT VC issuer metadata for the HTTPS issuer identifier", () => {
    const metadata = jwtVcIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;

    expect(metadata).toEqual({
      issuer: DEFAULT_CONFIG.issuer_base_url,
      jwks_uri: `${DEFAULT_CONFIG.issuer_base_url}/jwks.json`,
    });
  });

  it("does not put scope inside authorization_code credential offers", () => {
    const offer = credentialOffer(
      DEFAULT_CONFIG,
      "session-id",
      mdocCredentialConfigurationId(DEFAULT_CONFIG),
    ) as JsonRecord;
    const grants = offer.grants as JsonRecord;
    const authorizationCode = grants.authorization_code as JsonRecord;

    expect(offer.credential_configuration_ids).toEqual([
      mdocCredentialConfigurationId(DEFAULT_CONFIG),
    ]);
    expect(authorizationCode).toEqual({ issuer_state: "session-id" });
  });
});
