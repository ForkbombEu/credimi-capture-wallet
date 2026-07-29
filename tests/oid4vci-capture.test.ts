import { describe, expect, it } from "vitest";
import { isOid4vciProtocolPath, redactOid4vciValue } from "../src/oid4vci-capture.js";

describe("OpenID4VCI HTTP capture redaction", () => {
  it("preserves protocol structure without retaining secret-bearing values", () => {
    const captured = redactOid4vciValue({
      client_id: "wallet-client",
      issuer_state: "capture-session",
      code: "authorization-code",
      code_verifier: "pkce-secret",
      proofs: {
        jwt: ["header.payload.signature"],
        attestation: ["attestation.payload.signature"],
      },
      credential_response_encryption: {
        jwk: { kty: "EC", crv: "P-256", x: "public-x", y: "public-y" },
        enc: "A256GCM",
      },
    });

    expect(captured).toMatchObject({
      client_id: "wallet-client",
      issuer_state: "capture-session",
      code: { redacted: true, present: true },
      code_verifier: { redacted: true, present: true },
      proofs: {
        jwt: { redacted: true, present: true },
        attestation: { redacted: true, present: true },
      },
      credential_response_encryption: {
        jwk: { kty: "EC", crv: "P-256", x: "public-x", y: "public-y" },
        enc: "A256GCM",
      },
    });
    expect(JSON.stringify(captured)).not.toContain("authorization-code");
    expect(JSON.stringify(captured)).not.toContain("header.payload.signature");
  });

  it("recognizes every public OpenID4VCI protocol route", () => {
    for (const path of [
      "/.well-known/openid-credential-issuer/issuers/eu-pid-device-bound",
      "/.well-known/oauth-authorization-server/issuers/eu-pid-device-bound",
      "/.well-known/jwt-vc-issuer/issuers/eu-pid-device-bound",
      "/issuers/eu-pid-device-bound/jwks.json",
      "/issuers/eu-pid-device-bound/credential-jwks.json",
      "/sessions/session-id/offer",
      "/sessions/session-id/deeplink",
      "/issuers/eu-pid-device-bound/par",
      "/issuers/eu-pid-device-bound/authorize",
      "/issuers/eu-pid-device-bound/token",
      "/issuers/eu-pid-device-bound/nonce",
      "/issuers/eu-pid-device-bound/credential",
      "/authorization-servers/eu-pid-device-bound/authorize",
    ]) {
      expect(isOid4vciProtocolPath(path), path).toBe(true);
    }
    expect(isOid4vciProtocolPath("/openid4vp/response")).toBe(false);
  });
});
