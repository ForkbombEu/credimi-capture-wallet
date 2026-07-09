import { createHash } from "node:crypto";
import { cborEncode } from "@owf/mdoc";
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
});
