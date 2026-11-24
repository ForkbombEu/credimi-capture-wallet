import { describe, expect, it } from "vitest";
import {
  captureProofHeaders,
  decodeJwtHeader,
  extractProofJwts,
} from "../src/openid4vci/proofs.js";
import { unsignedJwt } from "./helpers.js";

const walletJwk = {
  kty: "EC",
  crv: "P-256",
  x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
};

describe("proof JWT capture", () => {
  it("decodes a proof JWT JOSE header", () => {
    const jwt = unsignedJwt({ typ: "openid4vci-proof+jwt", alg: "ES256", kid: "wallet-key-1" });

    expect(decodeJwtHeader(jwt)).toMatchObject({
      typ: "openid4vci-proof+jwt",
      alg: "ES256",
      kid: "wallet-key-1",
    });
  });

  it("captures jwk from proof JWT header", () => {
    const jwt = unsignedJwt({ alg: "ES256", jwk: walletJwk });
    const headers = captureProofHeaders({ proof: { proof_type: "jwt", jwt } });

    expect(headers[0]?.jwk).toEqual(walletJwk);
    expect(headers[0]?.source).toBe("credential_request.proof.jwt.header.jwk");
  });

  it("captures kid-only proof headers", () => {
    const jwt = unsignedJwt({ alg: "ES256", kid: "did:key:z6Mk..." });
    const headers = captureProofHeaders({ proof: { jwt } });

    expect(headers[0]?.kid).toBe("did:key:z6Mk...");
    expect(headers[0]?.jwk).toBeUndefined();
  });

  it("detects x5c proof headers", () => {
    const jwt = unsignedJwt({ alg: "ES256", x5c: ["leaf-cert"] });
    const headers = captureProofHeaders({ proof: { jwt } });

    expect(headers[0]?.x5c).toEqual(["leaf-cert"]);
  });

  it("parses single proof.jwt and multiple proofs.jwt entries", () => {
    const first = unsignedJwt({ kid: "first" });
    const second = unsignedJwt({ kid: "second" });
    const third = unsignedJwt({ kid: "third" });

    expect(extractProofJwts({ proof: { jwt: first } })).toHaveLength(1);
    expect(extractProofJwts({ proofs: { jwt: [second, third] } })).toEqual([
      { jwt: second, source: "credential_request.proofs.jwt[0]" },
      { jwt: third, source: "credential_request.proofs.jwt[1]" },
    ]);
  });

  it("captures the attestation proof header and its proof type", () => {
    const attestation = unsignedJwt({
      alg: "ES256",
      typ: "key-attestation+jwt",
      x5c: ["attester-leaf"],
    });

    expect(captureProofHeaders({ proofs: { attestation: [attestation] } })).toEqual([
      {
        alg: "ES256",
        key_attestation_present: false,
        proof_type: "attestation",
        source: "credential_request.proofs.attestation[0].header",
        typ: "key-attestation+jwt",
        x5c: ["attester-leaf"],
      },
    ]);
  });
});
