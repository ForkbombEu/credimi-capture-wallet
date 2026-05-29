import { describe, expect, it } from "vitest";
import {
  captureProofHeaders,
  decodeJwtHeader,
  extractProofJwts,
  firstWalletJwks,
  jwkToJwks,
} from "../src/proofs.js";
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

  it("extracts jwk from proof JWT header and converts it to JWKS", () => {
    const jwt = unsignedJwt({ alg: "ES256", jwk: walletJwk });
    const headers = captureProofHeaders({ proof: { proof_type: "jwt", jwt } });
    const wallet = firstWalletJwks(headers);

    expect(wallet.source).toBe("credential_request.proof.jwt.header.jwk");
    expect(wallet.jwks).toEqual(jwkToJwks(walletJwk));
    expect(wallet.jwks?.keys[0]).toMatchObject({ alg: "ES256", use: "sig" });
  });

  it("detects kid-only proof headers without treating a key as observable", () => {
    const jwt = unsignedJwt({ alg: "ES256", kid: "did:key:z6Mk..." });
    const headers = captureProofHeaders({ proof: { jwt } });
    const wallet = firstWalletJwks(headers);

    expect(headers[0]?.kid).toBe("did:key:z6Mk...");
    expect(wallet.jwks).toBeNull();
    expect(wallet.observedFields).toContain("kid");
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
});
