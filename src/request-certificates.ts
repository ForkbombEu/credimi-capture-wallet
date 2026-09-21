import { createHash } from "node:crypto";
import { CredoWebCrypto, Kms, X509Certificate, X509KeyUsage } from "@credo-ts/core";
import { exportJWK, generateKeyPair } from "jose";
import { createJwkSigningContext } from "./config.js";
import type { JsonRecord, RequestCertificateFixture, RequestSigningMaterial } from "./types.js";

const FIXTURE_VALIDITY = {
  notBefore: new Date("2024-01-01T00:00:00Z"),
  notAfter: new Date("2034-01-01T00:00:00Z"),
};

/**
 * Builds the signing key and `x5c` chain for a request-integrity scenario.
 *
 * Every fixture keeps the request itself validly signed by the key of the leaf certificate it
 * presents, so the only defect is the one the test is about: an unrelated self-signed certificate,
 * a chain whose root is unknown, or a chain missing its issuer. The certificates are generated
 * through Credo's X.509 module with the same options the service uses for its own material, so no
 * separate certificate implementation exists for tests.
 */
export async function generateRequestCertificateMaterial(
  fixture: RequestCertificateFixture,
): Promise<RequestSigningMaterial> {
  const leaf = await generateSigningKey();
  if (fixture === "unrelated_self_signed") {
    const certificate = await createCertificate({
      subject: leaf,
      authority: leaf,
      commonName: "unrelated-verifier.invalid",
      ca: false,
    });
    return { privateJwk: leaf.privateJwk, x5c: [encodeDer(certificate)] };
  }

  const authority = await generateSigningKey();
  const authorityCertificate = await createCertificate({
    subject: authority,
    authority,
    commonName: "untrusted-test-root.invalid",
    ca: true,
  });
  const leafCertificate = await createCertificate({
    subject: leaf,
    authority,
    commonName: "unrelated-verifier.invalid",
    issuerCommonName: "untrusted-test-root.invalid",
    ca: false,
  });
  return {
    privateJwk: leaf.privateJwk,
    x5c:
      fixture === "untrusted_root"
        ? [encodeDer(leafCertificate), encodeDer(authorityCertificate)]
        : [encodeDer(leafCertificate)],
  };
}

/** Signs with a key that is not the one bound to the advertised client identifier. */
export async function generateUnrelatedSigningKey(): Promise<RequestSigningMaterial> {
  const { privateJwk } = await generateSigningKey();
  return { privateJwk };
}

/** The `x509_hash` Client Identifier for a leaf certificate, per OpenID4VP Section 5.9.3. */
export function x509HashClientId(leafDerBase64: string): string {
  const hash = createHash("sha256")
    .update(Buffer.from(leafDerBase64, "base64"))
    .digest("base64url");
  return `x509_hash:${hash}`;
}

interface SigningKey {
  keyId: string;
  privateJwk: JsonRecord;
  publicJwk: Kms.PublicJwk;
}

async function generateSigningKey(): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = (await exportJWK(privateKey)) as unknown as JsonRecord;
  const keyId = `fcaf-fixture-${Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex")}`;
  privateJwk.alg = "ES256";
  privateJwk.use = "sig";
  privateJwk.kid = keyId;
  const publicJwk = Kms.PublicJwk.fromUnknown(
    (await exportJWK(publicKey)) as unknown as JsonRecord,
  );
  publicJwk.keyId = keyId;
  return { keyId, privateJwk, publicJwk };
}

async function createCertificate(options: {
  subject: SigningKey;
  authority: SigningKey;
  commonName: string;
  ca: boolean;
  issuerCommonName?: string;
}): Promise<X509Certificate> {
  const selfSigned = options.subject.keyId === options.authority.keyId;
  const name = (commonName: string) => ({
    countryName: "IT",
    commonName,
    organizationalUnit: "FCAF",
  });
  return X509Certificate.create(
    {
      authorityKey: options.authority.publicJwk,
      ...(selfSigned
        ? {}
        : { subjectPublicKey: options.subject.publicJwk, subject: name(options.commonName) }),
      issuer: name(options.issuerCommonName ?? options.commonName),
      validity: FIXTURE_VALIDITY,
      extensions: {
        subjectKeyIdentifier: { include: true },
        authorityKeyIdentifier: { include: true },
        keyUsage: {
          usages: options.ca ? [X509KeyUsage.KeyCertSign] : [X509KeyUsage.DigitalSignature],
        },
        basicConstraints: { ca: options.ca },
      },
    },
    new CredoWebCrypto(
      createJwkSigningContext(options.authority.privateJwk, options.authority.keyId) as never,
    ),
  );
}

function encodeDer(certificate: X509Certificate): string {
  return Buffer.from(certificate.rawCertificate).toString("base64");
}
