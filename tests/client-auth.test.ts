import { describe, expect, it } from "vitest";
import { PRIVATE_KEY_JWT_ASSERTION_TYPE, captureClientAuthentication } from "../src/client-auth.js";
import { unsignedJwt } from "./helpers.js";

const issuerBaseUrl = "https://issuer.example.test";
const tokenEndpointUrl = `${issuerBaseUrl}/token`;
const clientId = "wallet-client";

describe("client authentication capture", () => {
  it("captures private_key_jwt client assertions from token request parameters", () => {
    const assertion = unsignedJwt(
      { alg: "ES256", typ: "JWT", kid: "wallet-signing-key" },
      { sub: clientId, aud: tokenEndpointUrl },
    );

    const capture = captureClientAuthentication({
      issuerBaseUrl,
      endpointUrl: tokenEndpointUrl,
      params: {
        client_id: clientId,
        client_assertion_type: PRIVATE_KEY_JWT_ASSERTION_TYPE,
        client_assertion: assertion,
      },
      oauthClientAttestation: undefined,
      oauthClientAttestationPop: undefined,
    });

    expect(capture.method).toBe("private_key_jwt");
    expect(capture.private_key_jwt.present).toBe(true);
    expect(capture.private_key_jwt.assertion_type_valid).toBe(true);
    expect(capture.private_key_jwt.client_id_matches).toBe(true);
    expect(capture.private_key_jwt.audience_matches).toBe(true);
  });

  it("captures wallet attestation and proof-of-possession headers", () => {
    const cnfJwk = {
      kty: "EC",
      crv: "P-256",
      x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    };
    const attestation = unsignedJwt(
      { alg: "ES256", typ: "oauth-client-attestation+jwt", kid: "attester-key" },
      { sub: clientId, cnf: { jwk: cnfJwk } },
    );
    const pop = unsignedJwt(
      { alg: "ES256", typ: "oauth-client-attestation-pop+jwt", kid: "instance-key" },
      { iss: clientId, aud: tokenEndpointUrl, challenge: "token-nonce" },
    );

    const capture = captureClientAuthentication({
      issuerBaseUrl,
      endpointUrl: tokenEndpointUrl,
      params: { client_id: clientId },
      oauthClientAttestation: attestation,
      oauthClientAttestationPop: pop,
    });

    expect(capture.method).toBe("wallet_attestation");
    expect(capture.wallet_attestation.present).toBe(true);
    expect(capture.wallet_attestation.client_id_matches).toBe(true);
    expect(capture.wallet_attestation.cnf_jwk).toEqual(cnfJwk);
    expect(capture.wallet_attestation_pop.present).toBe(true);
    expect(capture.wallet_attestation_pop.audience_matches).toBe(true);
    expect(capture.wallet_attestation_pop.challenge).toBe("token-nonce");
  });
});
