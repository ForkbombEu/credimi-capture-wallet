import { createHash, createPrivateKey, sign as nodeSign, randomBytes } from "node:crypto";
import { SignatureAlgorithm } from "@owf/cose";
import {
  CoseKey,
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  IssuerSigned,
  ItemsRequest,
  type MdocContext,
} from "@owf/mdoc";
import type { Express } from "express";
import { type KeyLike, exportJWK } from "jose";
import request from "supertest";
import { expect } from "vitest";
import { issuerAppConfig } from "../../src/configurations/resolve-urls.js";
import { mdocCredentialConfigurationId } from "../../src/credentials/catalogue.js";
import { PID_MDOC_DOCTYPE, PID_MDOC_NAMESPACE } from "../../src/credentials/definitions.js";
import type { AppConfig, JsonRecord } from "../../src/types.js";
import {
  CONFORMING_ISSUER_ID,
  issuerPath as issuerConfigurationPath,
  requireIssuer,
} from "./environment.js";
import {
  type CredentialResponse,
  createIssuanceSession,
  keyAttestationJwt,
  preAuthorizedToken,
} from "./issuance.js";
import { type TestKey, dpopProof, generateEs256Key } from "./keys.js";
import { mdocSessionTranscript } from "./mdoc-session-transcript.js";

export interface MdocCredential {
  credential: string;
  holder: TestKey;
}

export function mdocDcqlForClaims(claims: string[]): JsonRecord {
  return {
    credentials: [
      {
        id: "query_0",
        format: "mso_mdoc",
        meta: { doctype_value: PID_MDOC_DOCTYPE },
        claims: claims.map((claim) => ({ path: [PID_MDOC_NAMESPACE, claim] })),
      },
    ],
  };
}

export async function issueMdocCredential(
  app: Express,
  config: AppConfig,
): Promise<MdocCredential> {
  const issuerConfigurationId = mdocCredentialConfigurationId(config, "key-attestation-required");
  const session = await createIssuanceSession(app, {
    credential_configuration_id: issuerConfigurationId,
    flow: "pre_authorized_code",
  });
  const dpopKey = await generateEs256Key();
  const token = await preAuthorizedToken(app, session, dpopKey, config.issuer_base_url);
  const holder = await generateEs256Key();
  const issuerConfig = issuerAppConfig(config, requireIssuer(config, CONFORMING_ISSUER_ID));
  const credentialPath = `${issuerConfigurationPath(session.issuer_configuration_id)}/credential`;
  const proof = await keyAttestationJwt(issuerConfig, holder, token.c_nonce);
  const response = await request(app)
    .post(credentialPath)
    .set("authorization", `DPoP ${token.access_token}`)
    .set(
      "DPoP",
      await dpopProof(dpopKey, {
        method: "POST",
        url: `${config.issuer_base_url}${credentialPath}`,
        accessToken: token.access_token,
      }),
    )
    .send({
      credential_configuration_id: session.credential_configuration_id,
      proofs: { attestation: [proof] },
    });
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  const credential = (response.body as CredentialResponse).credentials[0]?.credential;
  expect(credential).toEqual(expect.any(String));
  return { credential: String(credential), holder };
}

function signingContext(): Pick<MdocContext, "crypto" | "cose"> {
  return {
    crypto: {
      random: (length) => randomBytes(length),
      digest: ({ digestAlgorithm, bytes }) => {
        if (digestAlgorithm !== "SHA-256")
          throw new Error(`unsupported digest algorithm '${digestAlgorithm}'`);
        return new Uint8Array(createHash("sha256").update(bytes).digest());
      },
      hdkf: () => {
        throw new Error("mdoc HKDF is not supported");
      },
    },
    cose: {
      sign1: {
        sign: async ({ key, toBeSigned, algorithm }) => {
          if (algorithm !== SignatureAlgorithm.ES256)
            throw new Error(`unsupported mdoc algorithm '${algorithm}'`);
          return new Uint8Array(
            nodeSign("sha256", toBeSigned, {
              key: createPrivateKey({ key: key.jwk as never, format: "jwk" }),
              dsaEncoding: "ieee-p1363",
            }),
          );
        },
        verify: async () => false,
      },
      mac0: {
        authenticate: () => {
          throw new Error("mdoc MAC signing is not supported");
        },
        verify: async () => false,
      },
    },
  };
}

export async function createMdocDeviceResponse(options: {
  credential: string;
  holder: TestKey;
  authorizationRequest: JsonRecord;
  claims: string[];
  mutateTranscript?: (request: JsonRecord) => JsonRecord;
  transcriptOrigin?: string;
  documents?: number;
}): Promise<string> {
  const transcriptRequest = options.mutateTranscript
    ? options.mutateTranscript(options.authorizationRequest)
    : options.authorizationRequest;
  const context = signingContext();
  const sessionTranscript = await mdocSessionTranscript(
    transcriptRequest,
    context,
    options.transcriptOrigin,
  );
  const namespaces = Object.fromEntries(options.claims.map((claim) => [claim, false]));
  const docRequest = DocRequest.create({
    itemsRequest: ItemsRequest.create({
      docType: PID_MDOC_DOCTYPE,
      namespaces: { [PID_MDOC_NAMESPACE]: namespaces },
    }),
  });
  const deviceRequest = DeviceRequest.create({ version: "1.0", docRequests: [docRequest] });
  const privateJwk = { ...(await exportJWK(options.holder.privateKey as KeyLike)), alg: "ES256" };
  const signingKey = CoseKey.fromJwk(privateJwk);
  const issuerSigned = IssuerSigned.fromEncodedForOid4Vci(options.credential);
  const deviceResponse = await DeviceResponse.createWithDeviceRequest(
    {
      deviceRequest,
      sessionTranscript,
      documents: Array.from({ length: options.documents ?? 1 }, () => ({
        issuerSigned,
        docRequestIndex: 0,
        signature: { signingKey },
      })),
    },
    context,
  );
  return deviceResponse.encodedForOid4Vp;
}
