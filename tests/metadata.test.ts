import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
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
    const configuration = configurations[DEFAULT_CONFIG.credential_configuration_id] as JsonRecord;

    expect(configuration.scope).toBe(DEFAULT_CONFIG.credential_scope);
  });

  it("advertises the SD-JWT VC type in issuer metadata", () => {
    const metadata = credentialIssuerMetadata(DEFAULT_CONFIG) as JsonRecord;
    const configurations = metadata.credential_configurations_supported as JsonRecord;
    const configuration = configurations[DEFAULT_CONFIG.credential_configuration_id] as JsonRecord;

    expect(configuration.vct).toBe(DEFAULT_CONFIG.credential_configuration_id);
  });

  it("advertises client attestation support in authorization server metadata", () => {
    const metadata = authorizationServerMetadata(DEFAULT_CONFIG) as JsonRecord;

    expect(metadata.token_endpoint_auth_methods_supported).toEqual([
      "none",
      "attest_jwt_client_auth",
    ]);
    expect(metadata.client_attestation_signing_alg_values_supported).toEqual(["ES256"]);
    expect(metadata.client_attestation_pop_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("does not put scope inside authorization_code credential offers", () => {
    const offer = credentialOffer(DEFAULT_CONFIG, "session-id") as JsonRecord;
    const grants = offer.grants as JsonRecord;
    const authorizationCode = grants.authorization_code as JsonRecord;

    expect(authorizationCode).toEqual({ issuer_state: "session-id" });
  });
});
