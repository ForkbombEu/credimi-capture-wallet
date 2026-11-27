import { Kms, Mdoc, SdJwtVcService, X509Certificate } from "@credo-ts/core";
import {
  CompactEncrypt,
  type JWK,
  SignJWT,
  compactDecrypt,
  compactVerify,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  domesticPidCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import {
  DOMESTIC_PID_MDOC_NAMESPACE,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_VCT,
} from "../src/credentials/definitions.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { unsignedJwt } from "./helpers.js";
import { getJson, postJson } from "./support/http.js";
import {
  type CredentialResponse,
  type SessionCreateResponse,
  credentialNonce,
  credentialProofJwt,
  keyAttestationJwt,
  preAuthorizedToken,
} from "./support/issuance.js";
import { type TestKey, generateEs256Key } from "./support/keys.js";
import { type JwksResponse, issuerProtocolPath, serverTestSuite } from "./support/server.js";
const {
  config,
  conformingIssuerId,
  jwtKeyAttestationIssuerId,
  jwtOnlyIssuerId,
  conformingIssuerPath,
  jwtKeyAttestationIssuerPath,
  jwtOnlyIssuerPath,
  conformingMetadataPath,
  conformingIssuerConfig,
  conformingProofJwt,
  postDpopProof,
} = serverTestSuite("fake-issuer-test-");
async function eudiCredentialProofJwt(
  attestedKey: TestKey,
  nonce: string,
  audience: string,
  signingKey = attestedKey,
): Promise<string> {
  const keyAttestation = await keyAttestationJwt(conformingIssuerConfig, attestedKey, nonce);
  return new SignJWT({
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      key_attestation: keyAttestation,
    })
    .sign(signingKey.privateKey);
}

async function credentialProofJwtWithoutKeyAttestation(
  key: TestKey,
  nonce: string,
  audience = `${config.issuer_base_url}${conformingIssuerPath}`,
): Promise<string> {
  return new SignJWT({
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: key.publicJwk as unknown as JWK,
    })
    .sign(key.privateKey);
}

const credentialEncryptionTestState = vi.hoisted(() => ({ responseDelayMs: 0 }));
vi.mock("../src/openid4vci/credential-encryption.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../src/openid4vci/credential-encryption.js")>();
  return {
    ...actual,
    encryptCredentialResponse: async (
      ...args: Parameters<typeof actual.encryptCredentialResponse>
    ) => {
      if (credentialEncryptionTestState.responseDelayMs > 0) {
        await new Promise((resolve) =>
          setTimeout(resolve, credentialEncryptionTestState.responseDelayMs),
        );
      }
      return actual.encryptCredentialResponse(...args);
    },
  };
});

afterEach(() => {
  credentialEncryptionTestState.responseDelayMs = 0;
});

describe("capture issuer server", () => {
  it("enforces the selected JWT proof key-attestation policy", async () => {
    const app = createApp(config);
    const requiredSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: sdJwtCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
      flow: "pre_authorized_code",
    });
    const requiredDpop = await generateEs256Key();
    const requiredToken = await preAuthorizedToken(
      app,
      requiredSession,
      requiredDpop,
      config.issuer_base_url,
    );
    const holderKey = await generateEs256Key();
    const requiredNonce = await credentialNonce(app, requiredSession.issuer_configuration_id);
    const proofWithoutAttestation = await credentialProofJwtWithoutKeyAttestation(
      holderKey,
      requiredNonce,
    );
    const requiredCredentialPath = issuerProtocolPath(requiredSession, "/credential");

    const rejected = await request(app)
      .post(requiredCredentialPath)
      .set("authorization", `DPoP ${requiredToken.access_token}`)
      .set(
        "DPoP",
        await postDpopProof(requiredDpop, requiredCredentialPath, requiredToken.access_token),
      )
      .send({
        credential_configuration_id: requiredSession.credential_configuration_id,
        proofs: { jwt: [proofWithoutAttestation] },
      });

    expect(rejected.status).toBe(400);
    expect(rejected.body).toMatchObject({
      error: "invalid_proof",
      error_description: expect.stringContaining("Missing required key attestation"),
    });

    const jwtProofSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      issuer_configuration_id: jwtOnlyIssuerId,
      credential_configuration_id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
      flow: "pre_authorized_code",
    });
    const jwtProofDpop = await generateEs256Key();
    const jwtProofToken = await preAuthorizedToken(
      app,
      jwtProofSession,
      jwtProofDpop,
      config.issuer_base_url,
    );
    const jwtProofNonce = await credentialNonce(app, jwtProofSession.issuer_configuration_id);
    const acceptedProof = await credentialProofJwtWithoutKeyAttestation(
      holderKey,
      jwtProofNonce,
      `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
    );
    const jwtOnlyCredentialPath = issuerProtocolPath(jwtProofSession, "/credential");
    const accepted = await request(app)
      .post(jwtOnlyCredentialPath)
      .set("authorization", `DPoP ${jwtProofToken.access_token}`)
      .set(
        "DPoP",
        await postDpopProof(jwtProofDpop, jwtOnlyCredentialPath, jwtProofToken.access_token),
      )
      .send({
        credential_configuration_id: jwtProofSession.credential_configuration_id,
        proofs: { jwt: [acceptedProof] },
      });

    expect(accepted.status).toBe(200);
    const capture = await getJson<SessionCapture>(app, `/sessions/${jwtProofSession.session_id}`);
    expect(capture.checks.proof_jwt_present).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(false);
    expect(capture.status).toBe("credential_issued");
  });

  it("issues the numeric credential with a floating-point kg claim", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      issuer_configuration_id: jwtOnlyIssuerId,
      credential_configuration_id: numericSdJwtCredentialConfigurationId(config, "jwt-proof"),
      flow: "pre_authorized_code",
    });
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const holderKey = await generateEs256Key();
    const nonce = await credentialNonce(app, session.issuer_configuration_id);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: {
          jwt: [
            await credentialProofJwtWithoutKeyAttestation(
              holderKey,
              nonce,
              `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
            ),
          ],
        },
      });

    expect(credential.status, credential.text).toBe(200);
    const compact = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = new SdJwtVcService({} as never).fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject({ vct: NUMERIC_SD_JWT_VCT, kg: 70.5 });
    expect(typeof decoded.prettyClaims.kg).toBe("number");
  });

  it.each(["dc+sd-jwt", "mso_mdoc"] as const)(
    "issues the %s domestic PID with the PID claims and the domestic claim",
    async (format) => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        issuer_configuration_id: jwtOnlyIssuerId,
        credential_configuration_id: domesticPidCredentialConfigurationId(format, "jwt-proof"),
        flow: "pre_authorized_code",
      });
      const dpop = await generateEs256Key();
      const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const holderKey = await generateEs256Key();
      const nonce = await credentialNonce(app, session.issuer_configuration_id);
      const credentialPath = issuerProtocolPath(session, "/credential");
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: {
            jwt: [
              await credentialProofJwtWithoutKeyAttestation(
                holderKey,
                nonce,
                `${config.issuer_base_url}${jwtOnlyIssuerPath}`,
              ),
            ],
          },
        });

      expect(credential.status, credential.text).toBe(200);
      const encoded = (credential.body as CredentialResponse).credentials[0].credential;
      if (format === "dc+sd-jwt") {
        const decoded = new SdJwtVcService({} as never).fromCompact(encoded);
        expect(decoded.prettyClaims).toMatchObject({
          vct: DOMESTIC_PID_SD_JWT_VCT,
          given_name: "Mario",
          credimi_domestic_claim: "credimi-domestic-value",
        });
        expect(decoded.payload).not.toHaveProperty("credimi_domestic_claim");
        return;
      }
      const decoded = Mdoc.fromBase64Url(encoded);
      expect(decoded.docType).toBe(PID_MDOC_DOCTYPE);
      expect(decoded.issuerSignedNamespaces[PID_MDOC_NAMESPACE]).toMatchObject({
        given_name: "Mario",
      });
      expect(decoded.issuerSignedNamespaces[DOMESTIC_PID_MDOC_NAMESPACE]).toEqual({
        credimi_domestic_claim: "credimi-domestic-value",
      });
    },
  );

  it("uses Credo to verify JWT proof, key attestation, nonce, and holder binding", async () => {
    const app = createApp(config);
    const invalidSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const invalidDpop = await generateEs256Key();
    const invalidToken = await preAuthorizedToken(
      app,
      invalidSession,
      invalidDpop,
      config.issuer_base_url,
    );
    const walletKey = await generateEs256Key();
    const unrelatedAttestedKey = await generateEs256Key();
    const invalidNonce = await credentialNonce(app, invalidSession.issuer_configuration_id);
    const mismatchedProof = await credentialProofJwt(
      walletKey,
      invalidNonce,
      config.issuer_base_url,
      conformingIssuerConfig,
      unrelatedAttestedKey,
    );
    const invalidCredentialPath = issuerProtocolPath(invalidSession, "/credential");
    const mismatchedCredential = await request(app)
      .post(invalidCredentialPath)
      .set("authorization", `DPoP ${invalidToken.access_token}`)
      .set(
        "DPoP",
        await postDpopProof(invalidDpop, invalidCredentialPath, invalidToken.access_token),
      )
      .send({
        credential_configuration_id: invalidSession.credential_configuration_id,
        proofs: { jwt: [mismatchedProof] },
      });
    expect(mismatchedCredential.status).toBe(400);
    expect(mismatchedCredential.body).toMatchObject({ error: "invalid_proof" });

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const nonce = await credentialNonce(app, session.issuer_configuration_id);
    const proof = await conformingProofJwt(walletKey, nonce);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { jwt: [proof] },
      });

    expect(credential.status).toBe(200);
    expect(credential.body).toMatchObject({
      credentials: [
        {
          credential: expect.any(String),
        },
      ],
    });
    const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
    expect(compactSdJwt.split("~").length).toBeGreaterThan(2);
    const issuerJwt = compactSdJwt.split("~")[0];
    const issuerPayload = JSON.parse(
      Buffer.from(issuerJwt.split(".")[1], "base64url").toString("utf8"),
    ) as JsonRecord;
    const issuerHeader = JSON.parse(
      Buffer.from(issuerJwt.split(".")[0], "base64url").toString("utf8"),
    ) as JsonRecord;
    const issuerCertificate = X509Certificate.fromEncodedCertificate(
      (issuerHeader.x5c as string[])[0],
    );
    const verified = await compactVerify(
      issuerJwt,
      await importJWK(issuerCertificate.publicJwk.toJson(), "ES256"),
    );
    expect(issuerPayload.iss).toBe(`${config.issuer_base_url}${conformingIssuerPath}`);
    expect(issuerPayload.iss).not.toMatch(/^did:/);
    expect(verified.protectedHeader).toMatchObject({
      alg: "ES256",
      typ: "dc+sd-jwt",
      x5c: expect.any(Array),
    });

    const decoded = new SdJwtVcService({} as never).fromCompact(compactSdJwt);
    expect(decoded.prettyClaims).toMatchObject({
      vct: PID_SD_JWT_VCT,
      address: {
        country: "IT",
        formatted: "Via Europa 1, 00100 Roma, IT",
        house_number: "1",
        locality: "Roma",
        postal_code: "00100",
        region: "Lazio",
        street_address: "Via Europa",
      },
      birth_family_name: "Rossi",
      birth_given_name: "Mario",
      birthdate: "1990-01-01",
      date_of_expiry: "2031-01-01",
      date_of_issuance: "2026-01-01",
      document_number: "CREDIMI-DEMO-001",
      email: "jane.doe@example.test",
      given_name: "Mario",
      family_name: "Rossi",
      issuing_authority: "Credimi Fake Issuer",
      issuing_country: "IT",
      issuing_jurisdiction: "IT-RM",
      nationalities: ["IT"],
      personal_administrative_number: "PID-DEMO-001",
      phone_number: "+390600000000",
      picture: expect.stringMatching(/^data:image\/jpeg;base64,\/9j\//),
      place_of_birth: { locality: "Roma" },
      sex: 2,
      cnf: { jwk: walletKey.publicJwk },
    });
    expect(decoded.holder?.method).toBe("jwk");
    if (decoded.holder?.method !== "jwk") throw new Error("expected JWK holder binding");
    expect(Kms.PublicJwk.fromUnknown(walletKey.publicJwk).equals(decoded.holder.jwk)).toBe(true);
    const walletJwks = await getJson<JwksResponse>(app, `/sessions/${session.session_id}/jwks`);
    expect(walletJwks.keys).toHaveLength(1);
    expect(walletJwks.keys[0]).toMatchObject(walletKey.publicJwk);

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.flow).toBe("pre_authorized_code");
    expect(capture.checks.nonce_verified).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(true);
    expect(capture.checks.proof_jwt_header_jwk_present).toBe(true);
    expect(capture.status).toBe("credential_issued");
  });

  it.each([
    { signedByFirstAttestedKey: true, expectedStatus: 200 },
    { signedByFirstAttestedKey: false, expectedStatus: 400 },
  ])(
    "verifies an EUDI JWT proof without jwk or kid (signed by first key: $signedByFirstAttestedKey)",
    async ({ signedByFirstAttestedKey, expectedStatus }) => {
      const app = createApp(config);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        issuer_configuration_id: jwtKeyAttestationIssuerId,
        credential_configuration_id: sdJwtCredentialConfigurationId(
          config,
          "jwt-key-attestation-required",
        ),
        flow: "pre_authorized_code",
      });
      const dpop = await generateEs256Key();
      const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const nonce = await credentialNonce(app, session.issuer_configuration_id);
      const attestedKey = await generateEs256Key();
      const signingKey = signedByFirstAttestedKey ? attestedKey : await generateEs256Key();
      const proof = await eudiCredentialProofJwt(
        attestedKey,
        nonce,
        `${config.issuer_base_url}${jwtKeyAttestationIssuerPath}`,
        signingKey,
      );
      const credentialPath = issuerProtocolPath(session, "/credential");
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: { jwt: [proof] },
        });

      expect(credential.status, JSON.stringify(credential.body)).toBe(expectedStatus);
      if (expectedStatus === 400) {
        expect(credential.body).toMatchObject({ error: "invalid_proof" });
        return;
      }
      const compactSdJwt = (credential.body as CredentialResponse).credentials[0].credential;
      const decoded = new SdJwtVcService({} as never).fromCompact(compactSdJwt);
      expect(decoded.prettyClaims).toMatchObject({ cnf: { jwk: attestedKey.publicJwk } });
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.checks.proof_jwt_header_jwk_present).toBe(false);
      expect(capture.checks.key_attestation_verified).toBe(true);
    },
  );

  it("decrypts the Credential Request and encrypts the Credential Response", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      flow: "pre_authorized_code",
    });
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const holderKey = await generateEs256Key();
    const nonce = await credentialNonce(app, session.issuer_configuration_id);
    const proof = await conformingProofJwt(holderKey, nonce);
    const responseEncryptionKeyPair = await generateKeyPair("ECDH-ES", {
      crv: "P-256",
      extractable: true,
    });
    const responseEncryptionJwk = {
      ...(await exportJWK(responseEncryptionKeyPair.publicKey)),
      alg: "ECDH-ES",
      use: "enc",
      kid: "wallet-credential-response-key",
    };
    const credentialRequest = {
      credential_configuration_id: session.credential_configuration_id,
      proofs: { jwt: [proof] },
      credential_response_encryption: {
        jwk: responseEncryptionJwk,
        enc: "A256GCM",
      },
    };
    const credentialPath = issuerProtocolPath(session, "/credential");

    const plaintextResponseEncryptionRequest = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send(credentialRequest);
    expect(plaintextResponseEncryptionRequest.status).toBe(400);
    expect(plaintextResponseEncryptionRequest.body).toMatchObject({
      error: "invalid_encryption_parameters",
      error_description: "credential_response_encryption requires an encrypted Credential Request",
    });

    const metadata = await getJson<JsonRecord>(app, conformingMetadataPath);
    const requestEncryption = metadata.credential_request_encryption as {
      jwks: { keys: JWK[] };
    };
    const issuerEncryptionJwk = requestEncryption.jwks.keys[0];
    const encryptedRequest = await new CompactEncrypt(
      Buffer.from(JSON.stringify(credentialRequest), "utf8"),
    )
      .setProtectedHeader({
        alg: "ECDH-ES",
        enc: "A256GCM",
        kid: issuerEncryptionJwk.kid,
      })
      .encrypt(await importJWK(issuerEncryptionJwk, "ECDH-ES"));

    credentialEncryptionTestState.responseDelayMs = 25;
    const credentialResponse = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .type("application/jwt")
      .send(encryptedRequest);
    credentialEncryptionTestState.responseDelayMs = 0;

    expect(credentialResponse.status, credentialResponse.text).toBe(200);
    expect(credentialResponse.type, credentialResponse.text).toBe("application/jwt");
    const decryptedResponse = await compactDecrypt(
      credentialResponse.text,
      responseEncryptionKeyPair.privateKey,
    );
    expect(decryptedResponse.protectedHeader).toMatchObject({
      alg: "ECDH-ES",
      enc: "A256GCM",
      kid: "wallet-credential-response-key",
    });
    const responsePayload = JSON.parse(
      Buffer.from(decryptedResponse.plaintext).toString("utf8"),
    ) as CredentialResponse;
    expect(responsePayload.credentials).toEqual([{ credential: expect.any(String) }]);

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.raw?.credential_request_raw).toMatchObject({
      redacted: true,
      present: true,
      length: encryptedRequest.length,
    });
    expect(capture.raw?.credential_request).toMatchObject({
      credential_configuration_id: session.credential_configuration_id,
      proofs: {
        jwt: { redacted: true, present: true },
      },
      credential_response_encryption: credentialRequest.credential_response_encryption,
    });
    expect(capture.status).toBe("credential_issued");
  });

  it("rejects credential issuance without an access token", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post(`${conformingIssuerPath}/credential`)
      .send({ proof: { proof_type: "jwt", jwt: unsignedJwt({ alg: "ES256", kid: "key-1" }) } });

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toContain("DPoP");
  });

  it("returns a clear JWKS failure before a wallet key is observed", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const response = await request(app).get(`/sessions/${session.session_id}/jwks`);

    expect(response.status).toBe(409);
    expect(response.body).toMatchObject({ error: "wallet_jwks_not_observed" });
  });

  it("rejects sessions for unsupported credential configurations", async () => {
    const app = createApp(config);
    const response = await request(app)
      .post("/sessions")
      .send({ credential_configuration_id: "unknown.credential" });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "unsupported_credential_configuration" });
  });

  it("rejects unknown issuers and credential configurations belonging to another issuer", async () => {
    const app = createApp(config);
    const unknownIssuer = await request(app)
      .post("/sessions")
      .send({ issuer_configuration_id: "missing-issuer" });
    const crossIssuerCredential = await request(app)
      .post("/sessions")
      .send({
        issuer_configuration_id: conformingIssuerId,
        credential_configuration_id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
      });

    expect(unknownIssuer.status).toBe(400);
    expect(unknownIssuer.body).toMatchObject({
      error: "unsupported_issuer_configuration",
      supported_issuer_configuration_ids: [
        conformingIssuerId,
        jwtKeyAttestationIssuerId,
        jwtOnlyIssuerId,
      ],
    });
    expect(crossIssuerCredential.status).toBe(400);
    expect(crossIssuerCredential.body).toMatchObject({
      error: "unsupported_credential_configuration",
      issuer_configuration_id: conformingIssuerId,
    });
  });
});
