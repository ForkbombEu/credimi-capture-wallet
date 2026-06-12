import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { CREDIMI_LOGO_URL } from "../src/credential.js";
import {
  authorizationServerMetadata,
  credentialIssuerMetadata,
  credentialOffer,
} from "../src/metadata.js";
import type { JsonRecord } from "../src/types.js";

describe("metadata", () => {
  it("advertises credential scope in issuer metadata", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const jwtConfiguration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`
    ] as JsonRecord;
    const attestationConfiguration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.attestation`
    ] as JsonRecord;

    expect(jwtConfiguration.scope).toBe(`${DEFAULT_CONFIG.credential_scope}.jwt`);
    expect(attestationConfiguration.scope).toBe(`${DEFAULT_CONFIG.credential_scope}.attestation`);
  });

  it("advertises the SD-JWT VC type in issuer metadata", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`
    ] as JsonRecord;

    expect(configuration.vct).toBe(`${DEFAULT_CONFIG.credential_configuration_id}.jwt`);
    expect(configuration.display).toEqual([
      {
        name: "Credimi Demo PID",
        locale: "en-US",
        logo: { uri: CREDIMI_LOGO_URL, alt_text: "Credimi" },
      },
    ]);
  });

  it("advertises separate credential configurations for jwt and attestation proofs", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const jwtConfiguration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`
    ] as JsonRecord;
    const attestationConfiguration = configurations[
      `${DEFAULT_CONFIG.credential_configuration_id}.attestation`
    ] as JsonRecord;

    expect(Object.keys(configurations)).toEqual([
      `${DEFAULT_CONFIG.credential_configuration_id}.jwt`,
      `${DEFAULT_CONFIG.credential_configuration_id}.attestation`,
    ]);
    expect(jwtConfiguration.proof_types_supported).toEqual({
      jwt: { proof_signing_alg_values_supported: ["ES256"] },
    });
    expect(attestationConfiguration.proof_types_supported).toEqual({
      attestation: {
        key_attestations_required: {},
        proof_signing_alg_values_supported: ["ES256"],
      },
    });
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
  });

  it("does not put scope inside authorization_code credential offers", () => {
    const offer = credentialOffer(
      DEFAULT_CONFIG,
      "session-id",
      `${DEFAULT_CONFIG.credential_configuration_id}.attestation`,
    ) as JsonRecord;
    const grants = offer.grants as JsonRecord;
    const authorizationCode = grants.authorization_code as JsonRecord;

    expect(offer.credential_configuration_ids).toEqual([
      `${DEFAULT_CONFIG.credential_configuration_id}.attestation`,
    ]);
    expect(authorizationCode).toEqual({ issuer_state: "session-id" });
  });
});
