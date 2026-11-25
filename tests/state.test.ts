import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CaptureStore } from "../src/state.js";
import { createIssuerTestEnvironment, requireIssuer } from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";

let environment: IssuerTestEnvironment;

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({ prefix: "state-" });
});

afterAll(() => environment?.cleanup());

describe("CaptureStore.createSession", () => {
  it("creates the default capture shape", () => {
    const store = new CaptureStore(environment.config);
    const issuer = requireIssuer(environment.config, "eu-pid-device-bound");
    const session = store.createSession(issuer, {
      credentialConfigurationId: "eu-pid-sd-jwt",
    });
    expect(Object.keys(session)).toEqual([
      "session_id",
      "issuer_configuration_id",
      "issuer_identifier",
      "authorization_server_identifier",
      "status",
      "credential_configuration_id",
      "flow",
      "credential_offer_mode",
      "status_list_enabled",
      "observed",
      "checks",
      "events",
      "raw",
    ]);
    expect(session).toMatchObject({
      issuer_configuration_id: issuer.id,
      issuer_identifier: issuer.issuerIdentifier,
      authorization_server_identifier: issuer.issuerIdentifier,
      status: "created",
      credential_configuration_id: "eu-pid-sd-jwt",
      flow: "authorization_code",
      credential_offer_mode: "credential_offer",
      status_list_enabled: false,
      raw: {},
    });
    expect(session.observed).toEqual({
      client_id: { value: null, source: null, also_seen_in: [] },
      redirect_uri: { value: null, source: null, also_seen_in: [] },
      wallet_jwks: {
        observed: false,
        source: null,
        jwks: null,
        observed_proof_header_fields: [],
      },
      dpop_jwk: { observed: false, source: null, jwk: null, thumbprint: null },
      client_authentication: {
        method: "none",
        private_key_jwt: {
          present: false,
          source: null,
          header: null,
          claims: null,
          error: null,
          assertion_type: null,
          assertion_type_valid: false,
          client_id_matches: null,
          audience_matches: null,
        },
        wallet_attestation: {
          present: false,
          source: null,
          header: null,
          claims: null,
          error: null,
          cnf_jwk: null,
          client_id_matches: null,
        },
        wallet_attestation_pop: {
          present: false,
          source: null,
          header: null,
          claims: null,
          error: null,
          audience_matches: null,
          challenge: null,
        },
      },
    });
    expect(session.checks).toEqual({
      pkce_present: false,
      pkce_valid: false,
      state_present: false,
      issuer_state_present: false,
      proof_jwt_present: false,
      proof_attestation_present: false,
      proof_jwt_header_jwk_present: false,
      key_attestation_verified: false,
      nonce_verified: false,
      private_key_jwt_present: false,
      private_key_jwt_client_id_matches: null,
      wallet_attestation_present: false,
      wallet_attestation_pop_present: false,
      wallet_attestation_client_id_matches: null,
      wallet_attestation_pop_audience_matches: null,
    });
    expect(session.events).toHaveLength(1);
    expect(session.events[0]?.type).toBe("session_created");
    expect(JSON.stringify(session.events[0]?.detail)).toBe(
      JSON.stringify({
        issuer_configuration_id: issuer.id,
        issuer_identifier: issuer.issuerIdentifier,
        authorization_server_identifier: issuer.issuerIdentifier,
        credential_configuration_id: "eu-pid-sd-jwt",
        flow: "authorization_code",
        credential_offer_mode: "credential_offer",
        status_list_enabled: false,
      }),
    );
    expect(session.events[0]?.at).toEqual(expect.any(String));
  });
  it("preserves explicit unset caller values", () => {
    const store = new CaptureStore(environment.config);
    const issuer = requireIssuer(environment.config, "eu-pid-device-bound");
    const session = store.createSession(issuer, {
      credentialConfigurationId: "eu-pid-sd-jwt",
      statusReference: "valid",
      digestAlgorithm: "sha-256",
      evidenceMode: "redacted",
      fixtureId: "",
      documentNumber: "",
    });

    expect(Object.keys(session)).toEqual([
      "session_id",
      "issuer_configuration_id",
      "issuer_identifier",
      "authorization_server_identifier",
      "status",
      "credential_configuration_id",
      "flow",
      "credential_offer_mode",
      "status_list_enabled",
      "document_number",
      "observed",
      "checks",
      "events",
      "raw",
    ]);
    expect(session.document_number).toBe("");
    expect(session).not.toHaveProperty("fixture_id");
    expect(session).not.toHaveProperty("status_reference");
    expect(session).not.toHaveProperty("digest_algorithm");
    expect(session).not.toHaveProperty("evidence_mode");
    expect(JSON.stringify(session.events[0]?.detail)).toBe(
      JSON.stringify({
        issuer_configuration_id: issuer.id,
        issuer_identifier: issuer.issuerIdentifier,
        authorization_server_identifier: issuer.issuerIdentifier,
        credential_configuration_id: "eu-pid-sd-jwt",
        flow: "authorization_code",
        credential_offer_mode: "credential_offer",
        status_list_enabled: false,
      }),
    );
  });
  it("keeps every non-default option in the capture", () => {
    const store = new CaptureStore(environment.config);
    const issuer = requireIssuer(environment.config, "eu-pid-device-bound");
    const session = store.createSession(issuer, {
      credentialConfigurationId: "eu-pid-sd-jwt",
      flow: "pre_authorized_code",
      credentialOfferMode: "credential_offer_uri",
      statusListEnabled: true,
      fixtureId: "pid-data-minimal",
      documentNumber: "DOC-123",
      statusReference: "status_without_status_list",
      digestAlgorithm: "sha-512",
      evidenceMode: "full",
    });

    expect(Object.keys(session)).toEqual([
      "session_id",
      "issuer_configuration_id",
      "issuer_identifier",
      "authorization_server_identifier",
      "status",
      "credential_configuration_id",
      "flow",
      "credential_offer_mode",
      "status_list_enabled",
      "fixture_id",
      "document_number",
      "status_reference",
      "digest_algorithm",
      "evidence_mode",
      "observed",
      "checks",
      "events",
      "raw",
    ]);
    expect(session).toMatchObject({
      credential_configuration_id: "eu-pid-sd-jwt",
      flow: "pre_authorized_code",
      credential_offer_mode: "credential_offer_uri",
      status_list_enabled: true,
      fixture_id: "pid-data-minimal",
      document_number: "DOC-123",
      status_reference: "status_without_status_list",
      digest_algorithm: "sha-512",
      evidence_mode: "full",
    });
    expect(session.events).toHaveLength(1);
    expect(session.events[0]?.type).toBe("session_created");
    expect(JSON.stringify(session.events[0]?.detail)).toBe(
      JSON.stringify({
        issuer_configuration_id: issuer.id,
        issuer_identifier: issuer.issuerIdentifier,
        authorization_server_identifier: issuer.issuerIdentifier,
        credential_configuration_id: "eu-pid-sd-jwt",
        flow: "pre_authorized_code",
        credential_offer_mode: "credential_offer_uri",
        status_list_enabled: true,
        evidence_mode: "full",
      }),
    );
  });
});
