import { type JsonWebKey as NodeJsonWebKey, createPublicKey, verify } from "node:crypto";
import { Mdoc, SdJwtVcService } from "@credo-ts/core";
import { CoseKey, DateOnly } from "@owf/cose";
import { IssuerSigned } from "@owf/mdoc";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { loadIssuerCertificate } from "../src/config/key-material.js";
import {
  mdocCredentialConfigurationId,
  sdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import {
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
} from "../src/credentials/definitions.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type CredentialOfferResponse,
  type CredentialResponse,
  type SessionCreateResponse,
  keyAttestationJwt,
  preAuthorizedToken,
} from "./support/issuance.js";
import { generateEs256Key } from "./support/keys.js";
import { mdocStatusAndSignature } from "./support/mdoc.js";
import { type JwksResponse, issuerProtocolPath, serverTestSuite } from "./support/server.js";
const {
  config,
  conformingIssuerId,
  jwtKeyAttestationIssuerId,
  conformingIssuerPath,
  jwtKeyAttestationIssuerPath,
  jwtOnlyIssuerPath,
  conformingIssuerConfig,
  postDpopProof,
} = serverTestSuite("fake-issuer-test-");

describe("capture issuer server", () => {
  it("creates GUI sessions backed by a Credo credential offer", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    const initial = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(initial.status).toBe("created");
    expect(initial.flow).toBe("authorization_code");
    expect(initial).not.toHaveProperty("broken");
    expect(initial.issuer_configuration_id).toBe(conformingIssuerId);
    expect(initial.issuer_identifier).toBe(`${config.issuer_base_url}${conformingIssuerPath}`);
    expect(initial.credential_offer_mode).toBe("credential_offer");

    const deeplink = await getJson<{ deeplink: string }>(app, `/sessions/${sessionId}/deeplink`);
    const deeplinkUrl = new URL(deeplink.deeplink);
    expect(deeplinkUrl.searchParams.get("credential_offer_uri")).toBeNull();
    expect(JSON.parse(String(deeplinkUrl.searchParams.get("credential_offer")))).toMatchObject({
      credential_configuration_ids: expect.any(Array),
    });

    const unchanged = await getJson<SessionCapture>(app, `/sessions/${sessionId}`);
    expect(unchanged.status).toBe("created");
  });

  it("embeds credential offers by value by default", async () => {
    const app = createApp(config);
    const requestedCredentialConfigurationId = mdocCredentialConfigurationId(
      config,
      "key-attestation-required",
    );

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: requestedCredentialConfigurationId,
    });
    const offer = await getJson<CredentialOfferResponse>(
      app,
      `/sessions/${session.session_id}/offer`,
    );

    expect(session.credential_configuration_id).toBe(requestedCredentialConfigurationId);
    expect(session.flow).toBe("authorization_code");
    expect(session.credential_offer_mode).toBe("credential_offer");
    expect(session.issuer_configuration_id).toBe(conformingIssuerId);
    expect(offer.credential_configuration_ids).toEqual([requestedCredentialConfigurationId]);
    expect(offer.grants.authorization_code).toMatchObject({
      issuer_state: expect.any(String),
    });
    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("credential_offer_uri")).toBeNull();
    expect(JSON.parse(String(deeplink.searchParams.get("credential_offer")))).toEqual(offer);
  });
  it("creates a PID offer for the JWT key-attestation issuer", async () => {
    const app = createApp(config);
    const credentialConfigurationId = sdJwtCredentialConfigurationId(
      config,
      "jwt-key-attestation-required",
    );

    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      issuer_configuration_id: jwtKeyAttestationIssuerId,
      credential_configuration_id: credentialConfigurationId,
    });
    const offer = await getJson<CredentialOfferResponse>(
      app,
      `/sessions/${session.session_id}/offer`,
    );

    expect(session.issuer_configuration_id).toBe(jwtKeyAttestationIssuerId);
    expect(session.issuer_identifier).toBe(
      `${config.issuer_base_url}${jwtKeyAttestationIssuerPath}`,
    );
    expect(session.credential_configuration_id).toBe(credentialConfigurationId);
    expect(offer.credential_issuer).toBe(session.issuer_identifier);
    expect(offer.credential_configuration_ids).toEqual([credentialConfigurationId]);
  });

  it("keeps status-list references opt-in per issuance session", async () => {
    const app = createApp(config);

    const defaultSession = await postJson<SessionCreateResponse>(app, "/sessions", {});
    expect(defaultSession.status_list_enabled).toBe(false);
    expect(
      (await getJson<SessionCapture>(app, `/sessions/${defaultSession.session_id}`))
        .status_list_enabled,
    ).toBe(false);

    const enabledSession = await postJson<SessionCreateResponse>(app, "/sessions", {
      status_list_enabled: true,
    });
    expect(enabledSession.status_list_enabled).toBe(true);
    expect(
      (await getJson<SessionCapture>(app, `/sessions/${enabledSession.session_id}`))
        .status_list_enabled,
    ).toBe(true);

    const invalid = await request(app).post("/sessions").send({ status_list_enabled: "sometimes" });
    expect(invalid.status).toBe(400);
    expect(invalid.body).toMatchObject({ error: "invalid_status_list_enabled" });
  });

  it("creates credential-offer URI deeplinks when requested", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_offer_mode: "credential_offer_uri",
    });
    const deeplink = new URL(session.deeplink);

    expect(session.credential_offer_mode).toBe("credential_offer_uri");
    expect(deeplink.searchParams.get("credential_offer")).toBeNull();
    expect(deeplink.searchParams.get("credential_offer_uri")).toBe(session.offer_url);

    const offer = await request(app).get(new URL(session.offer_url).pathname);
    expect(offer.status).toBe(200);
    expect(offer.type).toBe("application/json");
    const consumed = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(consumed.status).toBe("offer_retrieved");
  });

  it("rejects the removed legacy broken credential fixture", async () => {
    const app = createApp(config);

    const removed = await request(app).post("/sessions").send({
      broken: true,
    });
    const invalid = await request(app).post("/sessions").send({ broken: "true" });

    expect(removed.status).toBe(400);
    expect(invalid.status).toBe(400);
    expect(removed.body).toEqual({
      error: "invalid_request",
      error_description: "'broken' is unavailable because the legacy root issuer has been removed",
    });
    expect(invalid.body).toEqual(removed.body);
  });

  it("serves Credo authorization-server JWKS without private material", async () => {
    const app = createApp(config);
    const jwks = await getJson<JwksResponse>(app, `${conformingIssuerPath}/jwks.json`);

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("publishes distinct authorization and credential-signing JWKS for each issuer", async () => {
    const app = createApp(config);
    const [deviceBoundAuthorizationJwks, jwtOnlyAuthorizationJwks, deviceBoundCredentialJwks] =
      await Promise.all([
        getJson<JwksResponse>(app, `${conformingIssuerPath}/jwks.json`),
        getJson<JwksResponse>(app, `${jwtOnlyIssuerPath}/jwks.json`),
        getJson<JwksResponse>(app, `${conformingIssuerPath}/credential-jwks.json`),
      ]);
    const jwtVcMetadata = await getJson<JsonRecord>(
      app,
      `/.well-known/jwt-vc-issuer/issuers/${conformingIssuerId}`,
    );

    expect(deviceBoundAuthorizationJwks.keys[0]).not.toEqual(jwtOnlyAuthorizationJwks.keys[0]);
    expect(deviceBoundCredentialJwks.keys[0]).not.toHaveProperty("d");
    expect(deviceBoundCredentialJwks.keys[0]?.x5c).toEqual([expect.any(String)]);
    expect(deviceBoundCredentialJwks.keys[0]).not.toEqual(deviceBoundAuthorizationJwks.keys[0]);
    expect(jwtVcMetadata).toEqual({
      issuer: `${config.issuer_base_url}${conformingIssuerPath}`,
      jwks_uri: `${config.issuer_base_url}${conformingIssuerPath}/credential-jwks.json`,
    });
  });

  it("issues an MDOC PID credential for the selected MDOC configuration", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: mdocCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
      flow: "pre_authorized_code",
    });
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const walletKey = await generateEs256Key();
    const credentialPath = issuerProtocolPath(session, "/credential");
    const refreshedNonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
    expect(refreshedNonce.status).toBe(200);
    const proof = await keyAttestationJwt(
      conformingIssuerConfig,
      walletKey,
      String(refreshedNonce.body.c_nonce),
    );

    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { attestation: [proof] },
      });

    expect(
      credential.status,
      JSON.stringify({ body: credential.body, headers: credential.headers, text: credential.text }),
    ).toBe(200);
    const encodedMdoc = (credential.body as CredentialResponse).credentials[0].credential;
    const decoded = IssuerSigned.fromEncodedForOid4Vci(encodedMdoc);
    const credoDecoded = Mdoc.fromBase64Url(encodedMdoc);

    expect(session.credential_configuration_id).toBe(
      mdocCredentialConfigurationId(config, "key-attestation-required"),
    );
    expect(decoded.issuerAuth.mobileSecurityObject.docType).toBe(PID_MDOC_DOCTYPE);
    const namespace = decoded.getPrettyClaims(PID_MDOC_NAMESPACE) as JsonRecord | undefined;
    expect(Object.keys(namespace ?? {}).sort()).toEqual([...PID_MDOC_CLAIMS].sort());
    expect(namespace).toMatchObject({
      document_number: "CREDIMI-DEMO-001",
      email_address: "jane.doe@example.test",
      family_name: "Rossi",
      family_name_birth: "Rossi",
      given_name: "Mario",
      given_name_birth: "Mario",
      issuing_authority: "Credimi Fake Issuer",
      issuing_country: "IT",
      issuing_jurisdiction: "IT-RM",
      mobile_phone_number: "+390600000000",
      nationality: ["IT"],
      personal_administrative_number: "PID-DEMO-001",
      resident_address: "Via Europa 1, 00100 Roma, IT",
      resident_city: "Roma",
      resident_country: "IT",
      resident_house_number: "1",
      resident_postal_code: "00100",
      resident_state: "Lazio",
      resident_street: "Via Europa",
      sex: 2,
    });
    expect(namespace?.birth_date).toBeInstanceOf(DateOnly);
    expect(String(namespace?.birth_date)).toBe("1990-01-01");
    expect(namespace?.expiry_date).toBeInstanceOf(DateOnly);
    expect(String(namespace?.expiry_date)).toBe("2031-01-01");
    expect(namespace?.issuance_date).toBeInstanceOf(DateOnly);
    expect(String(namespace?.issuance_date)).toBe("2026-01-01");
    expect(namespace?.place_of_birth).toEqual(
      new Map([
        ["country", "IT"],
        ["locality", "Roma"],
        ["region", "Lazio"],
      ]),
    );
    const portrait = namespace?.portrait;
    expect(portrait).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(portrait as Uint8Array).subarray(0, 3)).toEqual(
      Buffer.from([0xff, 0xd8, 0xff]),
    );
    expect(credoDecoded.issuerSignedNamespaces[PID_MDOC_NAMESPACE]).toEqual(namespace);
    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.status).toBe("credential_issued");
    expect(capture.checks.proof_attestation_present).toBe(true);
    expect(capture.checks.key_attestation_verified).toBe(true);
    expect(capture.observed.wallet_jwks.source).toBe("credo.verified_holder_binding");
  });

  it.each([
    ["status_without_status_list", new Map()],
    [
      "negative_index",
      new Map<unknown, unknown>([
        [
          "status_list",
          new Map<unknown, unknown>([
            ["uri", "https://status.example.test/1"],
            ["idx", -1],
          ]),
        ],
      ]),
    ],
    [
      "missing_index",
      new Map<unknown, unknown>([
        ["status_list", new Map<unknown, unknown>([["uri", "https://status.example.test/1"]])],
      ]),
    ],
    [
      "malformed_uri",
      new Map<unknown, unknown>([
        [
          "status_list",
          new Map<unknown, unknown>([
            ["uri", "not a uri"],
            ["idx", 42],
          ]),
        ],
      ]),
    ],
    [
      "missing_uri",
      new Map<unknown, unknown>([["status_list", new Map<unknown, unknown>([["idx", 42]])]]),
    ],
    ...(
      [
        ["uri_missing_scheme", "//status.example.test/1"],
        ["uri_space_in_host", "https://status.ex ample.test/1"],
        ["uri_invalid_percent_encoding", "https://status.example.test/1%GG"],
        ["uri_illegal_characters", "https://status.example.test/1<token>|1"],
        ["uri_empty", ""],
      ] as const
    ).map(
      ([statusReference, uri]) =>
        [
          statusReference,
          new Map<unknown, unknown>([
            [
              "status_list",
              new Map<unknown, unknown>([
                ["uri", uri],
                ["idx", 42],
              ]),
            ],
          ]),
        ] as const,
    ),
  ] as const)(
    "issues a signed mdoc with the %s status fixture",
    async (statusReference, expectedStatus) => {
      const allocation = vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ status_list: { uri: "https://status.example.test/1", idx: 42 } }),
            { headers: { "content-type": "application/json" }, status: 200 },
          ),
        );
      vi.stubGlobal("fetch", allocation);
      const app = createApp({ ...config, fcaf_scenarios_enabled: true });
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
        flow: "pre_authorized_code",
        status_list_enabled: true,
        status_reference: statusReference,
      });
      const dpop = await generateEs256Key();
      const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const walletKey = await generateEs256Key();
      const credentialPath = issuerProtocolPath(session, "/credential");
      const nonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
      const proof = await keyAttestationJwt(
        conformingIssuerConfig,
        walletKey,
        String(nonce.body.c_nonce),
      );
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: { attestation: [proof] },
        });

      expect(credential.status, JSON.stringify(credential.body)).toBe(200);
      expect(allocation).toHaveBeenCalledOnce();
      const encodedMdoc = (credential.body as CredentialResponse).credentials[0].credential;
      const { signature, status } = mdocStatusAndSignature(encodedMdoc);
      const issuerKey = CoseKey.fromJwk(
        loadIssuerCertificate(conformingIssuerConfig).publicJwk.toJson(),
      );

      expect(status).toEqual(expectedStatus);
      expect(
        await signature.verifySignature(
          { key: issuerKey },
          {
            verify: async ({ key, signature: value, toBeVerified }) =>
              verify(
                "sha256",
                toBeVerified,
                {
                  dsaEncoding: "ieee-p1363",
                  key: createPublicKey({
                    format: "jwk",
                    key: key.jwk as unknown as NodeJsonWebKey,
                  }),
                },
                value,
              ),
          },
        ),
      ).toBe(true);
    },
  );

  it.each([
    ["uri_missing_scheme", "//status.example.test/1"],
    ["uri_space_in_host", "https://status.ex ample.test/1"],
    ["uri_invalid_percent_encoding", "https://status.example.test/1%GG"],
    ["uri_illegal_characters", "https://status.example.test/1<token>|1"],
    ["uri_empty", ""],
  ])("issues an SD-JWT VC with the %s status reference", async (statusReference, uri) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ status_list: { uri: "https://status.example.test/1", idx: 42 } }),
            { headers: { "content-type": "application/json" }, status: 200 },
          ),
        ),
    );
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {
      credential_configuration_id: sdJwtCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
      flow: "pre_authorized_code",
      status_list_enabled: true,
      status_reference: statusReference,
    });
    const dpop = await generateEs256Key();
    const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
    const credentialPath = issuerProtocolPath(session, "/credential");
    const nonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
    const proof = await keyAttestationJwt(
      conformingIssuerConfig,
      await generateEs256Key(),
      String(nonce.body.c_nonce),
    );
    const credential = await request(app)
      .post(credentialPath)
      .set("authorization", `DPoP ${token.access_token}`)
      .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
      .send({
        credential_configuration_id: session.credential_configuration_id,
        proofs: { attestation: [proof] },
      });

    expect(credential.status, JSON.stringify(credential.body)).toBe(200);
    const compact = (credential.body as CredentialResponse).credentials[0].credential;
    const claims = new SdJwtVcService({} as never).fromCompact(compact).prettyClaims as JsonRecord;
    expect(claims.status).toEqual({ status_list: { uri, idx: 42 } });
  });
});
