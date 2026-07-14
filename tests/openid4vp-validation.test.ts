import { createHash } from "node:crypto";
import { cborEncode } from "@owf/mdoc";
import { calculateJwkThumbprint } from "jose";
import { describe, expect, it } from "vitest";
import { mdocSessionTranscript } from "../src/openid4vp-validation.js";

describe("OpenID4VP 1.0 final mdoc session transcript", () => {
  it("uses the redirect handover defined by Appendix B.2.6.1", async () => {
    const authorizationRequest = {
      client_id: "x509_hash:verifier",
      nonce: "verifier-nonce",
      response_uri: "https://verifier.example/response",
    };
    const transcript = await mdocSessionTranscript(authorizationRequest);
    const handoverInfo = cborEncode([
      authorizationRequest.client_id,
      authorizationRequest.nonce,
      null,
      authorizationRequest.response_uri,
    ]);

    expect(transcript.deviceEngagement).toBeNull();
    expect(transcript.eReaderKey).toBeNull();
    expect(transcript.handover.encodedStructure).toEqual([
      "OpenID4VPHandover",
      createHash("sha256").update(handoverInfo).digest(),
    ]);
  });

  it("includes the JARM encryption JWK thumbprint for direct_post.jwt", async () => {
    const encryptionJwk = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF4ZcL06bGQmHslUUT4kq27QFT5uO9j6d5w",
      y: "x_FEzRu9dMQ-Z5n6bTLtJIOtJ8o2B1ye5q6jz1I7E0Y",
      use: "enc",
      alg: "ECDH-ES",
      kid: "verifier-jarm-key",
    };
    const authorizationRequest = {
      client_id: "x509_hash:verifier",
      nonce: "verifier-nonce",
      response_uri: "https://verifier.example/response",
      response_mode: "direct_post.jwt",
      client_metadata: {
        jwks: { keys: [encryptionJwk] },
      },
    };
    const transcript = await mdocSessionTranscript(authorizationRequest);
    const thumbprint = Buffer.from(
      await calculateJwkThumbprint(encryptionJwk, "sha256"),
      "base64url",
    );
    const handoverInfo = cborEncode([
      authorizationRequest.client_id,
      authorizationRequest.nonce,
      thumbprint,
      authorizationRequest.response_uri,
    ]);

    expect(transcript.handover.encodedStructure).toEqual([
      "OpenID4VPHandover",
      createHash("sha256").update(handoverInfo).digest(),
    ]);
  });
});
