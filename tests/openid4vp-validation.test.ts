import { createHash } from "node:crypto";
import { DataItem, cborDecode, cborEncode } from "@animo-id/mdoc";
import { describe, expect, it } from "vitest";
import { mdocSessionTranscript } from "../src/openid4vp-validation.js";

describe("OpenID4VP 1.0 final mdoc session transcript", () => {
  it("uses the redirect handover defined by Appendix B.2.6.1", () => {
    const authorizationRequest = {
      client_id: "x509_hash:verifier",
      nonce: "verifier-nonce",
      response_uri: "https://verifier.example/response",
    };
    const transcript = cborDecode(mdocSessionTranscript(authorizationRequest)) as DataItem<
      [null, null, [string, Uint8Array]]
    >;
    const handoverInfo = cborEncode(
      DataItem.fromData([
        authorizationRequest.client_id,
        authorizationRequest.nonce,
        null,
        authorizationRequest.response_uri,
      ]),
    );

    expect(transcript.data[0]).toBeNull();
    expect(transcript.data[1]).toBeNull();
    expect(transcript.data[2][0]).toBe("OpenID4VPHandover");
    expect(transcript.data[2][1]).toEqual(createHash("sha256").update(handoverInfo).digest());
  });
});
