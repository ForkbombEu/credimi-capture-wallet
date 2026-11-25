import { X509Certificate } from "node:crypto";
import type * as NodeCrypto from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { issuerCertificatePath, verifierCertificatePath } from "../src/config/paths.js";
import { createIssuerTestEnvironment, requireIssuer } from "./support/environment.js";

// The worst case for a random 16-byte certificate serial number: a leading zero byte followed by
// one below 0x80, which DER must encode without the zero. Real randomness hits it about once in
// 512 certificates; forcing it makes the regression deterministic.
const LEADING_ZERO_SERIAL = Uint8Array.from([
  0x00,
  0x12,
  ...Array.from({ length: 14 }, () => 0x5a),
]);

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeCrypto>();
  return {
    ...actual,
    // Like crypto.randomBytes, a Buffer over its own ArrayBuffer rather than Node's shared pool.
    randomBytes: (size: number) =>
      size === LEADING_ZERO_SERIAL.length
        ? Buffer.from(LEADING_ZERO_SERIAL.slice().buffer)
        : actual.randomBytes(size),
  };
});

describe("generated certificates", () => {
  const cleanups: (() => void)[] = [];
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup();
  });

  it("encode a serial number with a leading zero byte as valid DER", async () => {
    const environment = await createIssuerTestEnvironment({ prefix: "certificate-serial-" });
    cleanups.push(environment.cleanup);

    for (const path of [
      issuerCertificatePath(
        requireIssuer(environment.config, "eu-pid-device-bound").materialDirectory,
      ),
      verifierCertificatePath(environment.dataDir),
    ]) {
      const certificate = new X509Certificate(readFileSync(path, "utf8"));
      // The minimal encoding drops the zero; the parser refused the certificate that kept it.
      expect(certificate.serialNumber, path).toBe("125A5A5A5A5A5A5A5A5A5A5A5A5A5A");
    }
  });
});
