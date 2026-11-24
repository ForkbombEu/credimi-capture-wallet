import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import {
  CompactEncrypt,
  type JWK,
  type KeyLike,
  SignJWT,
  compactDecrypt,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { initIssuer } from "../src/config/key-material.js";
import { issuerCertificatePath, privateJwkPath } from "../src/config/paths.js";
import {
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../src/configurations/registry.js";
import {
  mdocCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import { createApp } from "../src/server/app.js";
import type { AppConfig, JsonRecord, SessionCapture } from "../src/types.js";

const dataDir = mkdtempSync(join(tmpdir(), "notification-test-"));
const baseConfig: AppConfig = {
  ...DEFAULT_CONFIG,
  issuer_base_url: "http://issuer.example.test",
  data_dir: dataDir,
};
const config: AppConfig = {
  ...baseConfig,
  oid4vci_notifications_enabled: true,
  fcaf_scenarios_enabled: true,
};
const DEVICE_BOUND = "eu-pid-device-bound";
const JWT_ONLY = "eu-pid-jwt-proof-only";

interface Key {
  publicJwk: JWK;
  privateKey: KeyLike | Uint8Array;
}

interface Issued {
  session: JsonRecord & { session_id: string; issuer_configuration_id: string };
  dpop: Key;
  accessToken: string;
  response: request.Response;
}

beforeAll(async () => {
  await initIssuer({
    issuer_base_url: baseConfig.issuer_base_url,
    data_dir: dataDir,
    credential_configuration_id: baseConfig.credential_configuration_id,
    force: true,
  });
});

afterAll(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

afterEach(() => {
  vi.useRealTimers();
});

async function key(): Promise<Key> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  return { publicJwk: await exportJWK(publicKey), privateKey };
}

function issuerIdentifier(issuerId: string): string {
  return `${config.issuer_base_url}/issuers/${issuerId}`;
}

async function dpopProof(
  dpop: Key,
  path: string,
  accessToken?: string,
  overrides: JsonRecord = {},
): Promise<string> {
  return new SignJWT({
    htm: "POST",
    htu: `${config.issuer_base_url}${path}`,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}),
    ...overrides,
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpop.publicJwk })
    .sign(dpop.privateKey);
}

/** A key attestation signed with the device-bound issuer's key, which the tests trust. */
async function keyAttestation(attested: Key[], nonce: string): Promise<string> {
  const materialDirectory = resolvedIssuerConfigurationById(
    config,
    DEVICE_BOUND,
  )?.materialDirectory;
  if (!materialDirectory) throw new Error("device-bound issuer unavailable");
  const privateJwk = JSON.parse(readFileSync(privateJwkPath(materialDirectory), "utf8")) as JWK;
  const certificate = readFileSync(issuerCertificatePath(materialDirectory), "utf8")
    .replace(/-----(?:BEGIN|END) CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iat: now,
    exp: now + 300,
    nonce,
    attested_keys: attested.map((attestedKey) => attestedKey.publicJwk),
  })
    .setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", x5c: [certificate] })
    .sign(await importJWK(privateJwk, "ES256"));
}

/**
 * The Credential Request proofs each test issuer accepts. An authorization-code client names
 * itself in `iss` (OpenID4VCI 1.0 Appendix F.1).
 */
async function credentialProofs(
  issuerId: string,
  nonce: string,
  clientId?: string,
): Promise<JsonRecord> {
  const holder = await key();
  const keyAttestationHeader =
    issuerId === DEVICE_BOUND ? { key_attestation: await keyAttestation([holder], nonce) } : {};
  const proof = await new SignJWT({
    ...(clientId ? { iss: clientId } : {}),
    aud: issuerIdentifier(issuerId),
    nonce,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: holder.publicJwk,
      ...keyAttestationHeader,
    })
    .sign(holder.privateKey);
  return { jwt: [proof] };
}

async function preAuthorizedSession(
  app: Express,
  issuerId: string,
  extra: JsonRecord = {},
): Promise<{ session: Issued["session"]; dpop: Key; accessToken: string; cNonce: string }> {
  const created = await request(app)
    .post("/sessions")
    .send({
      issuer_configuration_id: issuerId,
      flow: "pre_authorized_code",
      ...(issuerId === JWT_ONLY
        ? {
            credential_configuration_id: numericSdJwtCredentialConfigurationId(config, "jwt-proof"),
          }
        : {}),
      ...extra,
    });
  expect(created.status, created.text).toBe(201);
  const session = created.body as Issued["session"];
  const offer = await request(app).get(new URL(String(session.offer_url)).pathname);
  const grants = offer.body.grants as Record<string, JsonRecord>;
  const preAuthorizedCode = String(
    grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]?.["pre-authorized_code"],
  );
  const dpop = await key();
  const tokenPath = `/issuers/${issuerId}/token`;
  const token = await request(app)
    .post(tokenPath)
    .set("DPoP", await dpopProof(dpop, tokenPath))
    .type("form")
    .send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode,
    });
  expect(token.status, token.text).toBe(200);
  return {
    session,
    dpop,
    accessToken: String(token.body.access_token),
    cNonce: String(token.body.c_nonce),
  };
}

async function requestCredential(
  app: Express,
  issuerId: string,
  dpop: Key,
  accessToken: string,
  body: JsonRecord,
): Promise<request.Response> {
  const credentialPath = `/issuers/${issuerId}/credential`;
  return request(app)
    .post(credentialPath)
    .set("Authorization", `DPoP ${accessToken}`)
    .set("DPoP", await dpopProof(dpop, credentialPath, accessToken))
    .send(body);
}

async function issue(app: Express, issuerId = JWT_ONLY, extra: JsonRecord = {}): Promise<Issued> {
  const { session, dpop, accessToken, cNonce } = await preAuthorizedSession(app, issuerId, extra);
  const response = await requestCredential(app, issuerId, dpop, accessToken, {
    credential_configuration_id: session.credential_configuration_id,
    proofs: await credentialProofs(issuerId, cNonce),
  });
  return { session, dpop, accessToken, response };
}

async function notify(
  app: Express,
  issued: Pick<Issued, "dpop" | "accessToken">,
  body: unknown,
  issuerId = JWT_ONLY,
): Promise<request.Response> {
  const path = `/issuers/${issuerId}/notification`;
  return request(app)
    .post(path)
    .set("Authorization", `DPoP ${issued.accessToken}`)
    .set("DPoP", await dpopProof(issued.dpop, path, issued.accessToken))
    .send(body as object);
}

async function capture(app: Express, sessionId: string): Promise<SessionCapture> {
  return (await request(app).get(`/sessions/${sessionId}`).expect(200)).body as SessionCapture;
}

function eventTypes(session: SessionCapture): string[] {
  return session.events.map((event) => event.type);
}

describe("notification endpoint metadata", () => {
  it("advertises each enabled issuer's own endpoint in JSON, signed, and federation metadata", async () => {
    const app = createApp({
      ...config,
      federation: { enabled: true, authority_hints: ["https://federation.test.example"] },
    });
    for (const issuer of resolvedIssuerConfigurations(config)) {
      const expected = `${issuer.issuerIdentifier}/notification`;
      const metadata = await request(app)
        .get(`/.well-known/openid-credential-issuer/issuers/${issuer.id}`)
        .expect(200);
      expect(metadata.body.notification_endpoint).toBe(expected);
      const signed = await request(app)
        .get(`/.well-known/openid-credential-issuer/issuers/${issuer.id}`)
        .set("Accept", "application/jwt")
        .expect(200);
      expect(decodeJwt(signed.text).notification_endpoint).toBe(expected);
      const entity = await request(app)
        .get(`/issuers/${issuer.id}/.well-known/openid-federation`)
        .expect(200);
      const entityMetadata = decodeJwt(entity.text).metadata as Record<string, JsonRecord>;
      // The federated issuer metadata adds only its signing `jwks` to the ordinary metadata.
      const { jwks, ...federatedIssuerMetadata } = entityMetadata.openid_credential_issuer ?? {};
      expect(jwks).toBeDefined();
      expect(federatedIssuerMetadata).toEqual(metadata.body);
      expect(entityMetadata.oauth_authorization_server).not.toHaveProperty("notification_endpoint");
      const authorizationServer = await request(app)
        .get(`/.well-known/oauth-authorization-server/issuers/${issuer.id}`)
        .expect(200);
      expect(authorizationServer.body).not.toHaveProperty("notification_endpoint");
    }
  });

  it("has no endpoint, metadata entry, or notification_id when notifications are disabled", async () => {
    const app = createApp(baseConfig);
    const metadata = await request(app)
      .get(`/.well-known/openid-credential-issuer/issuers/${JWT_ONLY}`)
      .expect(200);
    expect(metadata.body).not.toHaveProperty("notification_endpoint");
    const issued = await issue(app);
    expect(issued.response.status, issued.response.text).toBe(200);
    expect(issued.response.body).not.toHaveProperty("notification_id");
    const response = await notify(app, issued, {
      notification_id: "anything",
      event: "credential_accepted",
    });
    expect(response.status).toBe(404);
  });

  it("answers 404 for an unknown or disabled issuer", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    for (const issuerId of ["no-such-issuer", "attestbook-experimental"]) {
      const response = await notify(
        app,
        issued,
        { notification_id: issued.response.body.notification_id, event: "credential_accepted" },
        issuerId,
      );
      expect(response.status).toBe(404);
      expect(response.body).toEqual({ error: "issuer_not_found" });
    }
  });
});

describe("notification_id in Credential Responses", () => {
  it("issues an unguessable id bound to the session and records it as evidence", async () => {
    const app = createApp(config);
    const first = await issue(app);
    const second = await issue(app);

    expect(first.response.status, first.response.text).toBe(200);
    const notificationId = first.response.body.notification_id;
    expect(notificationId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second.response.body.notification_id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second.response.body.notification_id).not.toBe(notificationId);
    const session = await capture(app, first.session.session_id);
    expect(session.notifications).toEqual([
      {
        notification_id: notificationId,
        issued_at: expect.any(String),
        credential_configuration_id: first.session.credential_configuration_id,
        credential_count: 1,
        received: [],
      },
    ]);
    expect(session.events.find((event) => event.type === "notification_issued")?.detail).toEqual({
      notification_id: notificationId,
      credential_configuration_id: first.session.credential_configuration_id,
      credential_count: 1,
    });
  });

  it("covers every Credential of a multi-credential response with one id", async () => {
    const app = createApp(config);
    const { session, dpop, accessToken, cNonce } = await preAuthorizedSession(app, DEVICE_BOUND, {
      credential_configuration_id: mdocCredentialConfigurationId(
        config,
        "key-attestation-required",
      ),
    });
    const response = await requestCredential(app, DEVICE_BOUND, dpop, accessToken, {
      credential_configuration_id: session.credential_configuration_id,
      proofs: { attestation: [await keyAttestation([await key(), await key()], cNonce)] },
    });

    expect(response.status, response.text).toBe(200);
    expect(response.body.credentials).toHaveLength(2);
    expect(typeof response.body.notification_id).toBe("string");
    const captured = await capture(app, session.session_id);
    expect(captured.notifications).toMatchObject([
      { notification_id: response.body.notification_id, credential_count: 2 },
    ]);
  });

  it("sends and registers no id for a failed Credential Request", async () => {
    const app = createApp(config);
    const { session, dpop, accessToken } = await preAuthorizedSession(app, JWT_ONLY);
    const response = await requestCredential(app, JWT_ONLY, dpop, accessToken, {
      credential_configuration_id: session.credential_configuration_id,
      proofs: await credentialProofs(JWT_ONLY, "not-the-issued-nonce"),
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.body).not.toHaveProperty("notification_id");
    const captured = await capture(app, session.session_id);
    expect(captured.notifications).toBeUndefined();
    expect(eventTypes(captured)).not.toContain("notification_issued");
  });

  it("includes the id inside an encrypted Credential Response", async () => {
    const app = createApp(config);
    const { session, dpop, accessToken, cNonce } = await preAuthorizedSession(app, JWT_ONLY);
    const metadata = await request(app)
      .get(`/.well-known/openid-credential-issuer/issuers/${JWT_ONLY}`)
      .expect(200);
    const issuerEncryptionJwk = metadata.body.credential_request_encryption.jwks.keys[0] as JWK;
    const responseKeys = await generateKeyPair("ECDH-ES", { crv: "P-256", extractable: true });
    const encryptedRequest = await new CompactEncrypt(
      Buffer.from(
        JSON.stringify({
          credential_configuration_id: session.credential_configuration_id,
          proofs: await credentialProofs(JWT_ONLY, cNonce),
          credential_response_encryption: {
            jwk: { ...(await exportJWK(responseKeys.publicKey)), alg: "ECDH-ES", use: "enc" },
            enc: "A256GCM",
          },
        }),
      ),
    )
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM", kid: issuerEncryptionJwk.kid })
      .encrypt(await importJWK(issuerEncryptionJwk, "ECDH-ES"));
    const credentialPath = `/issuers/${JWT_ONLY}/credential`;

    const response = await request(app)
      .post(credentialPath)
      .set("Authorization", `DPoP ${accessToken}`)
      .set("DPoP", await dpopProof(dpop, credentialPath, accessToken))
      .type("application/jwt")
      .send(encryptedRequest);

    expect(response.status, response.text).toBe(200);
    expect(response.type).toBe("application/jwt");
    const { plaintext } = await compactDecrypt(response.text, responseKeys.privateKey);
    const decrypted = JSON.parse(Buffer.from(plaintext).toString("utf8")) as JsonRecord;
    expect(decrypted.credentials).toHaveLength(1);
    expect(typeof decrypted.notification_id).toBe("string");
    const accepted = await notify(
      app,
      { dpop, accessToken },
      { notification_id: decrypted.notification_id, event: "credential_accepted" },
    );
    expect(accepted.status, accepted.text).toBe(204);
  });

  it("lets an FCAF scenario remove the id, and registers none for a scenario error", async () => {
    const app = createApp(config);
    const omitted = await issue(app, JWT_ONLY, {
      issuance_response_scenario: { credential: { omit_parameters: ["/notification_id"] } },
    });
    expect(omitted.response.status, omitted.response.text).toBe(200);
    expect(omitted.response.body).not.toHaveProperty("notification_id");
    const omittedCapture = await capture(app, omitted.session.session_id);
    const applied = omittedCapture.events.find(
      (event) => event.type === "issuance_response_scenario_applied",
    );
    const original = (applied?.detail.original as JsonRecord).body as JsonRecord;
    expect(original.notification_id).toBe(omittedCapture.notifications?.[0]?.notification_id);

    const denied = await issue(app, JWT_ONLY, {
      issuance_response_scenario: {
        credential: {
          status: 400,
          content_type: "application/json",
          body: '{"error":"credential_request_denied"}',
        },
      },
    });
    expect(denied.response.status).toBe(400);
    expect((await capture(app, denied.session.session_id)).notifications).toBeUndefined();
  });
});

describe("notification endpoint authentication", () => {
  it("rejects a missing or invalid access token with an RFC 6750 challenge", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    const path = `/issuers/${JWT_ONLY}/notification`;
    const body = {
      notification_id: issued.response.body.notification_id,
      event: "credential_accepted",
    };

    const missing = await request(app).post(path).send(body);
    expect(missing.status).toBe(401);
    expect(missing.headers["www-authenticate"]).toMatch(/DPoP|Bearer/);

    const [header, payload] = issued.accessToken.split(".");
    const forged = `${header}.${payload}.${Buffer.from(randomBytes(64)).toString("base64url")}`;
    const invalid = await request(app)
      .post(path)
      .set("Authorization", `DPoP ${forged}`)
      .set("DPoP", await dpopProof(issued.dpop, path, forged))
      .send(body);
    expect(invalid.status).toBe(401);
    expect(invalid.headers["www-authenticate"]).toContain('error="invalid_token"');

    // Authentication is checked before the body, so a malformed request learns nothing.
    const unauthenticatedMalformed = await request(app)
      .post(path)
      .type("application/json")
      .send("{not json");
    expect(unauthenticatedMalformed.status).toBe(401);
  });

  it("rejects an expired access token", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + (config.access_token_ttl_seconds + 120) * 1000);

    const response = await notify(app, issued, {
      notification_id: issued.response.body.notification_id,
      event: "credential_accepted",
    });

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toContain('error="invalid_token"');
  });

  it("rejects a missing, foreign-key, or mismatched DPoP proof", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    const other = await issue(app);
    const path = `/issuers/${JWT_ONLY}/notification`;
    const body = {
      notification_id: issued.response.body.notification_id,
      event: "credential_accepted",
    };
    const authorization = `DPoP ${issued.accessToken}`;
    const proofs: Record<string, string | undefined> = {
      missing: undefined,
      "another key": await dpopProof(await key(), path, issued.accessToken),
      "another target URI": await dpopProof(
        issued.dpop,
        `/issuers/${JWT_ONLY}/credential`,
        issued.accessToken,
      ),
      "another method": await dpopProof(issued.dpop, path, issued.accessToken, { htm: "GET" }),
      "another access token": await dpopProof(issued.dpop, path, other.accessToken),
    };

    for (const [label, proof] of Object.entries(proofs)) {
      const pending = request(app).post(path).set("Authorization", authorization);
      const response = await (proof ? pending.set("DPoP", proof) : pending).send(body);
      expect(response.status, label).toBe(401);
      expect(response.headers["www-authenticate"], label).toContain('error="invalid_dpop_proof"');
    }
    // A DPoP-bound token presented as a Bearer token still requires its proof.
    const bearer = await request(app)
      .post(path)
      .set("Authorization", `Bearer ${issued.accessToken}`)
      .send(body);
    expect(bearer.status).toBe(401);
    expect((await capture(app, issued.session.session_id)).notifications?.[0]?.received).toEqual(
      [],
    );
  });

  it("refuses an id from another issuance session or another issuer", async () => {
    const app = createApp(config);
    const first = await issue(app);
    const second = await issue(app);
    const deviceBound = await issue(app, DEVICE_BOUND);
    expect(deviceBound.response.status, deviceBound.response.text).toBe(200);

    const crossSession = await notify(app, second, {
      notification_id: first.response.body.notification_id,
      event: "credential_accepted",
    });
    expect(crossSession.status).toBe(400);
    expect(crossSession.body).toEqual({ error: "invalid_notification_id" });

    const crossIssuer = await notify(app, first, {
      notification_id: deviceBound.response.body.notification_id,
      event: "credential_accepted",
    });
    expect(crossIssuer.status).toBe(400);
    expect(crossIssuer.body).toEqual({ error: "invalid_notification_id" });

    // One issuer's token is not accepted at another issuer's Notification Endpoint.
    const foreignToken = await notify(
      app,
      first,
      { notification_id: deviceBound.response.body.notification_id, event: "credential_accepted" },
      DEVICE_BOUND,
    );
    expect(foreignToken.status).toBe(401);
    for (const issued of [first, deviceBound]) {
      const session = await capture(app, issued.session.session_id);
      expect(session.notifications?.[0]?.received).toEqual([]);
    }
  });

  it("accepts a notification after an authorization-code issuance", async () => {
    const app = createApp(config);
    const created = await request(app)
      .post("/sessions")
      .send({ issuer_configuration_id: JWT_ONLY, flow: "authorization_code" })
      .expect(201);
    const session = created.body as Issued["session"];
    const offer = await request(app).get(new URL(String(session.offer_url)).pathname);
    const issuerState = String(offer.body.grants.authorization_code.issuer_state);
    const dpop = await key();
    const clientId = "https://wallet.example.test";
    const redirectUri = "https://wallet.example.test/callback";
    const codeVerifier = randomBytes(48).toString("base64url");
    const parPath = `/issuers/${JWT_ONLY}/par`;
    const par = await request(app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, parPath))
      .type("form")
      .send({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: session.credential_configuration_id,
        issuer_state: issuerState,
        code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
        code_challenge_method: "S256",
      });
    expect(par.status, par.text).toBe(201);
    const authorize = await request(app)
      .get(`/issuers/${JWT_ONLY}/authorize`)
      .query({ client_id: clientId, request_uri: String(par.body.request_uri) })
      .redirects(0)
      .expect(302);
    const upstream = new URL(String(authorize.headers.location));
    const approval = await request(app)
      .get(`${upstream.pathname}${upstream.search}`)
      .redirects(0)
      .expect(302);
    const callback = new URL(String(approval.headers.location));
    const walletRedirect = await request(app)
      .get(`${callback.pathname}${callback.search}`)
      .redirects(0)
      .expect(302);
    const code = new URL(String(walletRedirect.headers.location)).searchParams.get("code");
    const tokenPath = `/issuers/${JWT_ONLY}/token`;
    const token = await request(app)
      .post(tokenPath)
      .set("DPoP", await dpopProof(dpop, tokenPath))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(code),
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      });
    expect(token.status, token.text).toBe(200);
    const accessToken = String(token.body.access_token);
    const nonce = await request(app).post(`/issuers/${JWT_ONLY}/nonce`).expect(200);
    const credential = await requestCredential(app, JWT_ONLY, dpop, accessToken, {
      credential_configuration_id: session.credential_configuration_id,
      proofs: await credentialProofs(JWT_ONLY, String(nonce.body.c_nonce), clientId),
    });
    expect(credential.status, credential.text).toBe(200);

    const response = await notify(
      app,
      { dpop, accessToken },
      { notification_id: credential.body.notification_id, event: "credential_accepted" },
    );

    expect(response.status, response.text).toBe(204);
  });
});

describe("notification request handling", () => {
  it("accepts every event, ignores unknown parameters, and keeps distinct reports", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    const notificationId = issued.response.body.notification_id;

    for (const body of [
      { notification_id: notificationId, event: "credential_accepted", wallet_extension: 1 },
      {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: "Could not store the Credential. Out of storage.",
      },
      { notification_id: notificationId, event: "credential_deleted" },
    ]) {
      const response = await notify(app, issued, body);
      expect(response.status, response.text).toBe(204);
      expect(response.text).toBe("");
    }

    const session = await capture(app, issued.session.session_id);
    expect(session.notifications?.[0]?.received).toEqual([
      expect.objectContaining({ event: "credential_accepted", received_count: 1 }),
      expect.objectContaining({
        event: "credential_failure",
        event_description: "Could not store the Credential. Out of storage.",
      }),
      expect.objectContaining({ event: "credential_deleted" }),
    ]);
    const events = (await request(app).get(`/sessions/${issued.session.session_id}/events`))
      .body as SessionCapture["events"];
    expect(
      events.filter((event) => event.type === "notification_received").map((event) => event.detail),
    ).toEqual([
      { notification_id: notificationId, event: "credential_accepted" },
      {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: "Could not store the Credential. Out of storage.",
      },
      { notification_id: notificationId, event: "credential_deleted" },
    ]);
    expect(
      session.raw?.oid4vci_requests?.filter((entry) => entry.path.endsWith("/notification")),
    ).toHaveLength(3);
  });

  it("is idempotent for identical notifications", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    const body = {
      notification_id: issued.response.body.notification_id,
      event: "credential_accepted",
    };

    expect((await notify(app, issued, body)).status).toBe(204);
    expect((await notify(app, issued, body)).status).toBe(204);

    const session = await capture(app, issued.session.session_id);
    expect(session.notifications?.[0]?.received).toEqual([
      expect.objectContaining({ event: "credential_accepted", received_count: 2 }),
    ]);
    expect(eventTypes(session).filter((type) => type === "notification_received")).toHaveLength(1);
  });

  it("answers invalid_notification_id for an unknown id", async () => {
    const app = createApp(config);
    const issued = await issue(app);

    const response = await notify(app, issued, {
      notification_id: randomBytes(32).toString("base64url"),
      event: "credential_accepted",
    });

    expect(response.status).toBe(400);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toEqual({ error: "invalid_notification_id" });
  });

  it("answers invalid_notification_request for a malformed request", async () => {
    const app = createApp(config);
    const issued = await issue(app);
    const notificationId = issued.response.body.notification_id;
    const malformed: Record<string, unknown> = {
      "missing notification_id": { event: "credential_accepted" },
      "empty notification_id": { notification_id: "", event: "credential_accepted" },
      "non-string notification_id": { notification_id: 7, event: "credential_accepted" },
      "missing event": { notification_id: notificationId },
      "wrong-case event": { notification_id: notificationId, event: "CREDENTIAL_ACCEPTED" },
      "unknown event": { notification_id: notificationId, event: "credential_revoked" },
      "quote in description": {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: 'say "no"',
      },
      "backslash in description": {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: "a\\b",
      },
      "non-ASCII description": {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: "échec",
      },
      "control character in description": {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: "line\nbreak",
      },
      "non-string description": {
        notification_id: notificationId,
        event: "credential_failure",
        event_description: 1,
      },
      "array body": [{ notification_id: notificationId, event: "credential_accepted" }],
    };
    for (const [label, body] of Object.entries(malformed)) {
      const response = await notify(app, issued, body);
      expect(response.status, label).toBe(400);
      expect(response.body, label).toEqual({ error: "invalid_notification_request" });
    }

    const path = `/issuers/${JWT_ONLY}/notification`;
    const authenticated = async () => ({
      Authorization: `DPoP ${issued.accessToken}`,
      DPoP: await dpopProof(issued.dpop, path, issued.accessToken),
    });
    const form = await request(app)
      .post(path)
      .set(await authenticated())
      .type("form")
      .send({ notification_id: notificationId, event: "credential_accepted" });
    expect(form.status).toBe(400);
    expect(form.body).toEqual({ error: "invalid_notification_request" });
    const invalidJson = await request(app)
      .post(path)
      .set(await authenticated())
      .type("application/json")
      .send("{not json");
    expect(invalidJson.status).toBe(400);
    expect(invalidJson.body).toEqual({ error: "invalid_notification_request" });

    const session = await capture(app, issued.session.session_id);
    expect(session.notifications?.[0]?.received).toEqual([]);
  });
});
