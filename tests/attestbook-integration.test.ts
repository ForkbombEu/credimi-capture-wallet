import { X509Certificate, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SdJwtVcService } from "@credo-ts/core";
import type { Express } from "express";
import {
  type JWK,
  type KeyLike,
  SignJWT,
  compactVerify,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  importX509,
} from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { attestbookIntegration } from "../src/attestbook/integration.js";
import { attestbookStatePath } from "../src/attestbook/persistence.js";
import {
  readSubscription,
  registerSubscription,
  verifySubscription,
  webhookCallbackUrl,
} from "../src/attestbook/subscription.js";
import {
  DEFAULT_CONFIG,
  initIssuer,
  issuerCertificatePath,
  privateJwkPath,
} from "../src/config.js";
import { credoOpenId4VciIssuer } from "../src/credo-openid4vci.js";
import { createApp } from "../src/server.js";
import { CaptureStore } from "../src/state.js";
import type { AppConfig, JsonRecord } from "../src/types.js";
import {
  AttestbookFixture,
  type FixtureAttestation,
  type FixtureEvent,
  signedDelivery,
} from "./attestbook-fixture.js";

const issuerId = "attestbook-experimental";
const issuerBaseUrl = "http://issuer.example.test";
const issuerIdentifier = `${issuerBaseUrl}/issuers/${issuerId}`;
const webhookSecret = "atw_test-subscription-secret-0000000000000000";
const adminToken = "test-admin-token";
const dataDir = mkdtempSync(join(tmpdir(), "attestbook-e2e-"));
const fixture = new AttestbookFixture();
let config: AppConfig;

const membershipVct = "urn:attestbook:membership-card";

function membership(version: number, extra: Record<string, unknown> = {}): FixtureAttestation {
  return {
    name: "Membership Card",
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["member_id", "given_name", "family_name"],
      properties: {
        member_id: { type: "string", minLength: 3 },
        given_name: { type: "string" },
        family_name: { type: "string" },
        tier: { type: "string", enum: ["gold", "silver"] },
        active: { type: "boolean" },
        ...extra,
      },
    },
    typeMetadata: {
      vct: membershipVct,
      display: [{ locale: "en-US", name: `Membership card v${version}` }],
      claims: [
        { path: ["active"], sd: "never" },
        ...("memberships" in extra ? [{ path: ["memberships", null, "club"], sd: "never" }] : []),
      ],
    },
  };
}

/** Nested claims added by version 2: an object and an array of objects. */
const nestedClaims = {
  address: {
    type: "object",
    required: ["locality"],
    properties: {
      street_address: { type: "string" },
      locality: { type: "string" },
      country: { type: "string", minLength: 2, maxLength: 2 },
    },
  },
  memberships: {
    type: "array",
    minItems: 1,
    maxItems: 3,
    items: {
      type: "object",
      required: ["club"],
      properties: {
        club: { type: "string", enum: ["chess", "rowing", "go"] },
        since: { type: "integer", minimum: 1990, maximum: 2026 },
      },
    },
  },
};

interface Harness {
  app: Express;
  store: CaptureStore;
  logs: { event: string; fields: JsonRecord }[];
}

async function startIssuer(): Promise<Harness> {
  const store = new CaptureStore(config);
  const logs: Harness["logs"] = [];
  attestbookIntegration(config, store, { logger: (event, fields) => logs.push({ event, fields }) });
  const app = createApp(config, store);
  await credoOpenId4VciIssuer(config, store);
  await attestbookIntegration(config, store).idle();
  return { app, store, logs };
}

async function deliver(
  harness: Harness,
  event: FixtureEvent,
  options: { secret?: string; timestamp?: string } = {},
) {
  const delivery = signedDelivery(options.secret ?? webhookSecret, event, options.timestamp);
  const response = await request(harness.app)
    .post("/integrations/attestbook/webhook")
    .set(delivery.headers)
    // A string is sent as-is; supertest would JSON-encode a Buffer under application/json.
    .send(delivery.body.toString("utf8"));
  await attestbookIntegration(config, harness.store).idle();
  return response;
}

async function status(harness: Harness): Promise<JsonRecord> {
  return (await request(harness.app).get("/integrations/attestbook/status")).body as JsonRecord;
}

async function issuerCredentialIds(harness: Harness): Promise<string[]> {
  const issuers = (await request(harness.app).get("/issuers")).body as {
    id: string;
    credential_configuration_ids: string[];
  }[];
  return issuers.find((issuer) => issuer.id === issuerId)?.credential_configuration_ids ?? [];
}

async function advertisedIds(harness: Harness): Promise<string[]> {
  const metadata = await request(harness.app).get(
    `/.well-known/openid-credential-issuer/issuers/${issuerId}`,
  );
  return Object.keys(metadata.body.credential_configurations_supported as JsonRecord);
}

interface Key {
  publicJwk: JsonRecord;
  privateKey: KeyLike;
}

async function key(): Promise<Key> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  return { publicJwk: (await exportJWK(publicKey)) as unknown as JsonRecord, privateKey };
}

async function dpopProof(
  dpop: Key,
  method: string,
  path: string,
  accessToken?: string,
): Promise<string> {
  return new SignJWT({
    htm: method,
    htu: `${issuerBaseUrl}${path}`,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpop.publicJwk as unknown as JWK })
    .sign(dpop.privateKey);
}

/**
 * A key attestation for the holder key, signed by an issuer key and certificate already in the
 * data directory: the test issuer trusts the chain a key attestation presents.
 */
async function keyAttestationJwt(holder: Key, nonce: string): Promise<string> {
  const material = join(dataDir, "issuers", "eu-pid-device-bound");
  const certificate = readFileSync(issuerCertificatePath(material), "utf8")
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iat: now, exp: now + 300, nonce, attested_keys: [holder.publicJwk] })
    .setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", x5c: [certificate] })
    .sign(
      await importJWK(JSON.parse(readFileSync(privateJwkPath(material), "utf8")) as JWK, "ES256"),
    );
}

/**
 * A key-attested JWT proof, as the experimental issuer requires. OpenID4VCI 1.0 Appendix F.1:
 * `iss` is the client_id, omitted for anonymous pre-authorized access.
 */
async function proofJwt(holder: Key, nonce: string, clientId?: string): Promise<string> {
  return new SignJWT({
    aud: issuerIdentifier,
    nonce,
    iat: Math.floor(Date.now() / 1000),
    ...(clientId ? { iss: clientId } : {}),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: holder.publicJwk as unknown as JWK,
      key_attestation: await keyAttestationJwt(holder, nonce),
    })
    .sign(holder.privateKey);
}

interface SessionResponse {
  session_id: string;
  credential_configuration_id: string;
  offer_url: string;
  deeplink: string;
  fixture_id: string;
  credential_definition?: JsonRecord;
  generated_claims?: { generator: string; seed: string; claims: JsonRecord };
}

async function createSession(harness: Harness, body: JsonRecord): Promise<SessionResponse> {
  const response = await request(harness.app)
    .post("/sessions")
    .send({ issuer_configuration_id: issuerId, ...body });
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return response.body as SessionResponse;
}

async function preAuthorizedToken(harness: Harness, session: SessionResponse, dpop: Key) {
  const offer = (await request(harness.app).get(new URL(session.offer_url).pathname)).body as {
    grants: Record<string, JsonRecord>;
  };
  const grant = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] ?? {};
  const tokenPath = `/issuers/${issuerId}/token`;
  const token = await request(harness.app)
    .post(tokenPath)
    .set("DPoP", await dpopProof(dpop, "POST", tokenPath))
    .type("form")
    .send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": String(grant["pre-authorized_code"]),
    });
  expect(token.status, JSON.stringify(token.body)).toBe(200);
  return token.body as { access_token: string; c_nonce?: string };
}

async function requestCredential(
  harness: Harness,
  session: SessionResponse,
  dpop: Key,
  accessToken: string,
  holder: Key,
  clientId?: string,
): Promise<string> {
  const noncePath = `/issuers/${issuerId}/nonce`;
  const nonce = (await request(harness.app).post(noncePath)).body.c_nonce as string;
  const credentialPath = `/issuers/${issuerId}/credential`;
  const response = await request(harness.app)
    .post(credentialPath)
    .set("authorization", `DPoP ${accessToken}`)
    .set("DPoP", await dpopProof(dpop, "POST", credentialPath, accessToken))
    .send({
      credential_configuration_id: session.credential_configuration_id,
      proofs: { jwt: [await proofJwt(holder, nonce, clientId)] },
    });
  expect(response.status, response.text).toBe(200);
  return (
    (response.body as { credentials: { credential: string }[] }).credentials[0]?.credential ?? ""
  );
}

async function issuePreAuthorized(
  harness: Harness,
  body: JsonRecord,
): Promise<{ compact: string; holder: Key; session: SessionResponse }> {
  const session = await createSession(harness, { flow: "pre_authorized_code", ...body });
  const dpop = await key();
  const holder = await key();
  const token = await preAuthorizedToken(harness, session, dpop);
  return {
    compact: await requestCredential(harness, session, dpop, token.access_token, holder),
    holder,
    session,
  };
}

/** The issuer signature over the SD-JWT, checked against the issuer certificate it carries. */
async function verifyIssuerSignature(compact: string): Promise<void> {
  const jwt = compact.split("~")[0] ?? "";
  const header = JSON.parse(Buffer.from(jwt.split(".")[0] ?? "", "base64url").toString("utf8")) as {
    x5c: string[];
    typ: string;
  };
  expect(header.typ).toBe("dc+sd-jwt");
  const certificate = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
  expect(new X509Certificate(certificate).subjectAltName).toContain(issuerIdentifier);
  await compactVerify(jwt, await importX509(certificate, "ES256"));
}

beforeAll(async () => {
  await fixture.start();
  config = {
    ...DEFAULT_CONFIG,
    issuer_base_url: issuerBaseUrl,
    public_base_url: issuerBaseUrl,
    data_dir: dataDir,
    attestbook: {
      enabled: true,
      base_url: fixture.origin,
      rulebook_id: fixture.rulebookId,
      webhook_secret: webhookSecret,
      admin_token: adminToken,
      allowed_schema_origins: [],
    },
  };
  await initIssuer({ issuer_base_url: issuerBaseUrl, data_dir: dataDir, force: true });
});

afterAll(async () => {
  await fixture.stop();
  rmSync(dataDir, { recursive: true, force: true });
});

describe("Attestbook-defined credentials, end to end", () => {
  it("keeps the integration invisible while the feature flag is off", async () => {
    const app = createApp({ ...config, attestbook: DEFAULT_CONFIG.attestbook });

    expect((await request(app).get("/integrations/attestbook/status")).body).toEqual({
      enabled: false,
    });
    expect((await request(app).post("/integrations/attestbook/webhook").send({})).status).toBe(404);
    expect(
      ((await request(app).get("/issuers")).body as { id: string }[]).map((issuer) => issuer.id),
    ).not.toContain(issuerId);
  });

  it("runs the full publication, activation, issuance, update and recovery workflow", async () => {
    // A rulebook published before the issuer starts is discovered by the startup reconciliation.
    const v1 = fixture.publish("1.0", [membership(1)]);
    let issuer = await startIssuer();
    expect(await status(issuer)).toMatchObject({
      enabled: true,
      rulebook_id: fixture.rulebookId,
      subscription: {
        webhook_secret_configured: true,
        callback_url: `${issuerBaseUrl}/integrations/attestbook/webhook`,
      },
      active: { version: "1.0", content_digest: v1.contentDigest },
      sync: { state: "idle", failure: null },
    });
    // The configuration id and the scope are the vct, and nothing else is served.
    const v1Id = membershipVct;
    expect(await issuerCredentialIds(issuer)).toEqual([v1Id]);
    expect(await advertisedIds(issuer)).toEqual([v1Id]);

    // Unsigned and signed issuer metadata, and the authorization server, advertise it consistently.
    const signed = await request(issuer.app)
      .get(`/.well-known/openid-credential-issuer/issuers/${issuerId}`)
      .set("Accept", "application/jwt");
    expect(signed.status).toBe(200);
    const signedConfiguration = (
      decodeJwt(signed.text).credential_configurations_supported as JsonRecord
    )[v1Id];
    expect(signedConfiguration).toMatchObject({
      format: "dc+sd-jwt",
      vct: membershipVct,
      scope: v1Id,
      // The ETSI wallet profile accepts only proof types that require key attestation.
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ["ES256"], key_attestations_required: {} },
        attestation: {
          proof_signing_alg_values_supported: ["ES256"],
          key_attestations_required: {},
        },
      },
    });
    const authorizationServer = await request(issuer.app).get(
      `/.well-known/oauth-authorization-server/issuers/${issuerId}`,
    );
    expect(authorizationServer.body.scopes_supported).toContain(v1Id);

    // PID-specific options, and claim fixtures, have no meaning for an imported credential.
    const pidOption = await request(issuer.app).post("/sessions").send({
      issuer_configuration_id: issuerId,
      credential_configuration_id: v1Id,
      fixture_id: "pid_default",
      document_number: "X1",
      status_list_enabled: true,
    });
    expect(pidOption.status).toBe(400);
    expect(pidOption.body).toMatchObject({
      error: "unsupported_for_imported_credential",
      unsupported_parameters: ["status_list_enabled", "document_number", "fixture_id"],
    });

    // Pre-authorized code flow: a correctly signed SD-JWT VC of the new type, with the claim
    // values generated for the session and recorded on it.
    const { compact, holder, session } = await issuePreAuthorized(issuer, {
      credential_configuration_id: v1Id,
    });
    expect(session.fixture_id).toBeUndefined();
    expect(session.generated_claims).toMatchObject({
      generator: "@faker-js/faker@10.6.0",
      seed: session.session_id,
    });
    const generated = session.generated_claims?.claims ?? {};
    expect(generated).toMatchObject({
      member_id: expect.any(String),
      given_name: expect.any(String),
      family_name: expect.any(String),
      tier: expect.stringMatching(/^(gold|silver)$/),
      active: expect.any(Boolean),
    });
    expect(String(generated.member_id).length).toBeGreaterThanOrEqual(3);
    const recorded = (await request(issuer.app).get(`/sessions/${session.session_id}`)).body;
    expect(recorded.generated_claims).toEqual(session.generated_claims);
    const decoded = new SdJwtVcService({} as never).fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject({
      ...generated,
      vct: membershipVct,
      iss: issuerIdentifier,
      cnf: { jwk: holder.publicJwk },
    });
    // `active` is never selectively disclosable per Type Metadata; `member_id` follows issuer policy.
    const issuerSignedPayload = decodeJwt(compact.split("~")[0] ?? "");
    expect(issuerSignedPayload.active).toBe(generated.active);
    expect(issuerSignedPayload.member_id).toBeUndefined();
    expect(issuerSignedPayload._sd).toEqual(expect.any(Array));
    await verifyIssuerSignature(compact);

    // Authorization code flow: the imported scope is mapped through the chained authorization server.
    const codeSession = await createSession(issuer, { credential_configuration_id: v1Id });
    const offer = JSON.parse(
      String(new URL(codeSession.deeplink).searchParams.get("credential_offer")),
    ) as {
      grants: { authorization_code: { issuer_state: string } };
    };
    const dpop = await key();
    const clientId = "https://wallet.example.test";
    const redirectUri = `${clientId}/callback`;
    const codeVerifier = randomBytes(48).toString("base64url");
    const parPath = `/issuers/${issuerId}/par`;
    const par = await request(issuer.app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, "POST", parPath))
      .type("form")
      .send({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: v1Id,
        issuer_state: offer.grants.authorization_code.issuer_state,
        code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
        code_challenge_method: "S256",
      });
    expect(par.status, JSON.stringify(par.body)).toBe(201);
    const authorize = await request(issuer.app)
      .get(`/issuers/${issuerId}/authorize`)
      .query({ client_id: clientId, request_uri: String(par.body.request_uri) })
      .redirects(0);
    expect(authorize.status).toBe(302);
    const upstream = new URL(String(authorize.headers.location));
    const approved = await request(issuer.app)
      .get(`${upstream.pathname}${upstream.search}`)
      .redirects(0);
    const callback = new URL(String(approved.headers.location));
    const walletRedirect = await request(issuer.app)
      .get(`${callback.pathname}${callback.search}`)
      .redirects(0);
    const code = new URL(String(walletRedirect.headers.location)).searchParams.get("code");
    const tokenPath = `/issuers/${issuerId}/token`;
    const token = await request(issuer.app)
      .post(tokenPath)
      .set("DPoP", await dpopProof(dpop, "POST", tokenPath))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(code),
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      });
    expect(token.status, JSON.stringify(token.body)).toBe(200);
    const authorizationCodeCredential = await requestCredential(
      issuer,
      codeSession,
      dpop,
      token.body.access_token,
      await key(),
      clientId,
    );
    expect(
      new SdJwtVcService({} as never).fromCompact(authorizationCodeCredential).prettyClaims,
    ).toMatchObject({ ...codeSession.generated_claims?.claims, vct: membershipVct });

    // Wallet-initiated: a PAR naming the imported scope and no issuer_state gets its own session,
    // pinned to the active definition with generated values, as an offered session is.
    const walletVerifier = randomBytes(48).toString("base64url");
    const walletDpop = await key();
    const walletPar = await request(issuer.app)
      .post(parPath)
      .set("DPoP", await dpopProof(walletDpop, "POST", parPath))
      .type("form")
      .send({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: v1Id,
        code_challenge: createHash("sha256").update(walletVerifier).digest("base64url"),
        code_challenge_method: "S256",
      });
    expect(walletPar.status, JSON.stringify(walletPar.body)).toBe(201);
    const walletSession = [...issuer.store.sessions.values()].find(
      (candidate) => candidate.initiated_by === "wallet",
    );
    expect(walletSession).toMatchObject({
      credential_configuration_id: v1Id,
      credential_definition: { version: "1.0", content_digest: v1.contentDigest },
      generated_claims: { seed: walletSession?.session_id },
    });
    const walletAuthorize = await request(issuer.app)
      .get(`/issuers/${issuerId}/authorize`)
      .query({ client_id: clientId, request_uri: String(walletPar.body.request_uri) })
      .redirects(0);
    const walletUpstream = new URL(String(walletAuthorize.headers.location));
    const walletApproved = await request(issuer.app)
      .get(`${walletUpstream.pathname}${walletUpstream.search}`)
      .redirects(0);
    const walletCallback = new URL(String(walletApproved.headers.location));
    const walletInitiatedRedirect = await request(issuer.app)
      .get(`${walletCallback.pathname}${walletCallback.search}`)
      .redirects(0);
    const walletToken = await request(issuer.app)
      .post(tokenPath)
      .set("DPoP", await dpopProof(walletDpop, "POST", tokenPath))
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: String(
          new URL(String(walletInitiatedRedirect.headers.location)).searchParams.get("code"),
        ),
        code_verifier: walletVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      });
    expect(walletToken.status, JSON.stringify(walletToken.body)).toBe(200);
    const walletCredential = await requestCredential(
      issuer,
      codeSession,
      walletDpop,
      walletToken.body.access_token,
      await key(),
      clientId,
    );
    expect(
      new SdJwtVcService({} as never).fromCompact(walletCredential).prettyClaims,
    ).toMatchObject({ ...walletSession?.generated_claims?.claims, vct: membershipVct });
    expect(walletSession?.status).toBe("credential_issued");

    // A session left in flight across the update is refused at its Credential Request.
    const inFlight = await createSession(issuer, {
      credential_configuration_id: v1Id,
      flow: "pre_authorized_code",
    });
    expect(inFlight.credential_definition).toMatchObject({
      source: "attestbook",
      rulebook_id: fixture.rulebookId,
      version: "1.0",
      content_digest: v1.contentDigest,
      vct: membershipVct,
      vct_source: "attestation_name",
    });

    // Publishing a new version activates it without a restart, from one signed webhook.
    const v2 = fixture.publish("2.0", [membership(2, nestedClaims)]);
    const accepted = await deliver(issuer, v2);
    expect(accepted.status).toBe(202);
    expect(accepted.body).toEqual({ status: "accepted", event_id: v2.id });
    expect(await status(issuer)).toMatchObject({
      active: {
        version: "2.0",
        content_digest: v2.contentDigest,
        credential_configuration_ids: [membershipVct],
      },
      last_observed_event: { event_id: v2.id },
    });
    const v2Id = membershipVct;
    expect(await advertisedIds(issuer)).toEqual([v2Id]);
    const v2Metadata = await request(issuer.app).get(
      `/.well-known/openid-credential-issuer/issuers/${issuerId}`,
    );
    expect(
      v2Metadata.body.credential_configurations_supported[v2Id].credential_metadata.claims,
    ).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: ["memberships", null, "club"] })]),
    );

    const inFlightDpop = await key();
    const inFlightToken = await preAuthorizedToken(issuer, inFlight, inFlightDpop);
    const noncePath = `/issuers/${issuerId}/nonce`;
    const inFlightNonce = (await request(issuer.app).post(noncePath)).body.c_nonce as string;
    const credentialPath = `/issuers/${issuerId}/credential`;
    const refused = await request(issuer.app)
      .post(credentialPath)
      .set("authorization", `DPoP ${inFlightToken.access_token}`)
      .set(
        "DPoP",
        await dpopProof(inFlightDpop, "POST", credentialPath, inFlightToken.access_token),
      )
      .send({
        credential_configuration_id: inFlight.credential_configuration_id,
        proofs: { jwt: [await proofJwt(await key(), inFlightNonce)] },
      });
    expect(refused.status).toBe(400);
    expect(refused.body).toMatchObject({ error: "invalid_credential_request" });
    const refusedCapture = (await request(issuer.app).get(`/sessions/${inFlight.session_id}`)).body;
    expect(refusedCapture.events).toContainEqual(
      expect.objectContaining({
        type: "credential_definition_superseded",
        detail: { pinned_version: "1.0", active_version: "2.0" },
      }),
    );

    // Nested claims: an object and an array of objects, disclosable member by member and element
    // by element, except where Type Metadata says `sd: "never"`.
    const { compact: v2Credential, session: v2Session } = await issuePreAuthorized(issuer, {
      credential_configuration_id: v2Id,
    });
    const v2Generated = v2Session.generated_claims?.claims ?? {};
    expect(v2Generated).toMatchObject({
      address: { locality: expect.any(String), country: expect.stringMatching(/^.{2}$/) },
      memberships: expect.arrayContaining([
        expect.objectContaining({ club: expect.stringMatching(/^(chess|rowing|go)$/) }),
      ]),
    });
    const v2Decoded = new SdJwtVcService({} as never).fromCompact(v2Credential);
    expect(v2Decoded.prettyClaims).toMatchObject({ ...v2Generated, vct: membershipVct });
    const v2Payload = decodeJwt(v2Credential.split("~")[0] ?? "");
    expect(v2Payload.address).toBeUndefined();
    const v2Disclosures = v2Credential
      .split("~")
      .slice(1)
      .filter(Boolean)
      .map(
        (disclosure) =>
          JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[],
      );
    const memberships = v2Generated.memberships as JsonRecord[];
    // One disclosure per array element; inside each, `club` stays in clear text.
    const elementDisclosures = v2Disclosures.filter(
      (disclosure) => disclosure.length === 2 && typeof disclosure[1] === "object",
    );
    expect(elementDisclosures).toHaveLength(memberships.length);
    for (const [, element] of elementDisclosures) {
      expect(element).toMatchObject({ club: expect.any(String) });
    }
    expect(v2Disclosures.some((disclosure) => disclosure[1] === "locality")).toBe(true);

    // Re-sending the same event is harmless; an older event never downgrades.
    const exportsBefore = fixture.requests.filter((entry) => entry.includes("/export")).length;
    const duplicate = await deliver(issuer, v2);
    expect(duplicate.status).toBe(200);
    expect(duplicate.body).toEqual({ status: "duplicate", event_id: v2.id });
    const older = await deliver(issuer, v1);
    expect(older.status).toBe(202);
    expect(await status(issuer)).toMatchObject({
      active: { version: "2.0" },
      sync: { state: "idle" },
    });
    expect(fixture.requests.filter((entry) => entry.includes("/export")).length).toBe(
      exportsBefore,
    );

    // An invalid signature or a stale delivery is rejected without fetching anything.
    const requestsBefore = fixture.requests.length;
    const forged = await deliver(issuer, v2, { secret: "atw_wrong" });
    expect(forged.status).toBe(401);
    expect(forged.body).toMatchObject({ error: "invalid_signature" });
    const stale = await deliver(
      issuer,
      { ...v2, id: `event-${randomUUID()}` },
      {
        timestamp: new Date(Date.now() - 3_600_000).toISOString(),
      },
    );
    expect(stale.status).toBe(401);
    expect(stale.body).toMatchObject({ error: "stale_timestamp" });
    expect(fixture.requests.length).toBe(requestsBefore);

    // A tampered export is rejected and the working version kept.
    const v3 = fixture.publish("3.0", [membership(3)]);
    fixture.overrides.set(fixture.exportPath("3.0"), Buffer.from('{"tampered":true}'));
    expect((await deliver(issuer, v3)).status).toBe(202);
    fixture.overrides.clear();
    expect(await status(issuer)).toMatchObject({
      active: { version: "2.0" },
      sync: {
        state: "failed",
        failure: { stage: "verify", code: "rulebook_digest_mismatch", version: "3.0" },
      },
    });
    expect(issuer.logs.map((entry) => entry.event)).toEqual(
      expect.arrayContaining([
        "notification_received",
        "snapshot_verified",
        "rulebook_compiled",
        "catalogue_activated",
        "sync_failed",
      ]),
    );

    // An unsupported schema is explained by diagnostics; the issuer stays healthy.
    const v4 = fixture.publish("4.0", [
      membership(4, { joined: { type: "string", format: "date" } }),
    ]);
    expect((await deliver(issuer, v4)).status).toBe(202);
    const rejected = await status(issuer);
    expect(rejected).toMatchObject({
      active: { version: "2.0" },
      sync: {
        state: "failed",
        failure: { stage: "compile", code: "credential_unsupported", version: "4.0" },
      },
    });
    expect((rejected.sync as { diagnostics: JsonRecord[] }).diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "unsupported_schema_keyword",
          attestation: "Membership Card",
        }),
      ]),
    );
    expect(await advertisedIds(issuer)).toContain(v2Id);
    expect(JSON.stringify(rejected)).not.toContain(webhookSecret);
    expect(JSON.stringify(rejected)).not.toContain(String(generated.member_id));

    // Manual resynchronisation is token-protected and reports the outcome.
    expect((await request(issuer.app).post("/integrations/attestbook/sync")).status).toBe(401);
    const manual = await request(issuer.app)
      .post("/integrations/attestbook/sync")
      .set("authorization", `Bearer ${adminToken}`);
    expect(manual.status).toBe(502);
    expect(manual.body).toMatchObject({
      sync: { last_trigger: "manual", failure: { stage: "compile" } },
    });

    // A restart while Attestbook is offline restores the last-known-good catalogue from disk.
    expect(existsSync(attestbookStatePath(dataDir))).toBe(true);
    expect(readFileSync(attestbookStatePath(dataDir), "utf8")).not.toContain(webhookSecret);
    const port = fixture.port;
    await fixture.stop();
    issuer = await startIssuer();
    expect(await status(issuer)).toMatchObject({
      active: { version: "2.0", content_digest: v2.contentDigest },
      sync: { state: "failed", failure: { stage: "fetch" } },
    });
    expect(await issuerCredentialIds(issuer)).toContain(v2Id);
    expect(issuer.logs.map((entry) => entry.event)).toContain("recovery_restored");
    const { compact: offline } = await issuePreAuthorized(issuer, {
      credential_configuration_id: v2Id,
    });
    expect(new SdJwtVcService({} as never).fromCompact(offline).prettyClaims.vct).toBe(
      membershipVct,
    );

    // A publication missed while the issuer was down is caught up by the next startup reconciliation.
    await fixture.start(port);
    const v5 = fixture.publish("5.0", [membership(5)]);
    issuer = await startIssuer();
    expect(await status(issuer)).toMatchObject({
      active: { version: "5.0", content_digest: v5.contentDigest },
      sync: { state: "idle", last_trigger: "startup" },
    });
    expect(await issuerCredentialIds(issuer)).toEqual([membershipVct]);
  });

  it("offers the imported credential on the issuer page and the verifier page", async () => {
    fixture.publish("6.0", [membership(6)]);
    const issuer = await startIssuer();
    const issuerPage = await request(issuer.app)
      .get(`/issuers/${issuerId}`)
      .set("Accept", "text/html");
    expect(issuerPage.status).toBe(200);
    expect(issuerPage.text).toContain(
      `<option value="${membershipVct}" data-format="dc+sd-jwt" data-imported="true">`,
    );

    const verifierPage = await request(issuer.app).get("/openid4vp");
    expect(verifierPage.status).toBe(200);
    const dcql = new RegExp(`<option value="${membershipVct}" data-dcql="([^"]+)"`).exec(
      verifierPage.text,
    )?.[1];
    if (!dcql) throw new Error("verifier page does not offer the imported credential");
    expect(JSON.parse(dcql.replaceAll("&quot;", '"'))).toMatchObject({
      credentials: [{ format: "dc+sd-jwt", meta: { vct_values: [membershipVct] } }],
    });
  });

  it("advertises no credential configuration before a rulebook version is active", async () => {
    const empty = new AttestbookFixture();
    await empty.start();
    const emptyDir = mkdtempSync(join(tmpdir(), "attestbook-empty-"));
    try {
      await initIssuer({ issuer_base_url: issuerBaseUrl, data_dir: emptyDir });
      const emptyConfig: AppConfig = {
        ...config,
        data_dir: emptyDir,
        attestbook: { ...config.attestbook, base_url: empty.origin, rulebook_id: empty.rulebookId },
      };
      const store = new CaptureStore(emptyConfig);
      attestbookIntegration(emptyConfig, store, { logger: () => undefined });
      const app = createApp(emptyConfig, store);
      await credoOpenId4VciIssuer(emptyConfig, store);
      await attestbookIntegration(emptyConfig, store).idle();

      const metadata = await request(app).get(
        `/.well-known/openid-credential-issuer/issuers/${issuerId}`,
      );
      expect(metadata.status).toBe(200);
      expect(metadata.body.credential_configurations_supported).toEqual({});
      const session = await request(app)
        .post("/sessions")
        .send({ issuer_configuration_id: issuerId });
      expect(session.status).toBe(400);
      expect(session.body).toMatchObject({
        error: "unsupported_credential_configuration",
        supported_credential_configuration_ids: [],
      });
      expect(attestbookIntegration(emptyConfig, store).status()).toMatchObject({
        active: null,
        sync: { state: "failed", failure: { stage: "fetch", code: "no_publication" } },
      });
    } finally {
      await empty.stop();
      rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  it("answers Attestbook's callback verification challenge exactly", async () => {
    const harness = await startIssuer();
    const challenge = `atv_${randomBytes(32).toString("base64url")}`;
    const response = await request(harness.app)
      .post("/integrations/attestbook/webhook")
      .set("content-type", "application/json")
      .send(
        JSON.stringify({
          type: "attestbook.subscription.verification@1",
          challenge,
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
        }),
      );

    expect(response.status).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.body).toEqual({ challenge });
    expect(
      ((await status(harness)).subscription as JsonRecord).last_verification_challenge_at,
    ).toEqual(expect.any(String));
  });

  it("completes the one-time subscription registration and callback verification over HTTP", async () => {
    const server = createServer((req, res) => listener(req, res));
    let listener: (req: IncomingMessage, res: ServerResponse) => void = () => undefined;
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const publicBaseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const serving = { ...config, public_base_url: publicBaseUrl };
    const store = new CaptureStore(serving);
    attestbookIntegration(serving, store, { logger: () => undefined });
    listener = createApp(serving, store);
    try {
      const target = { origin: fixture.origin, rulebookId: fixture.rulebookId };
      const registered = await registerSubscription(target, webhookCallbackUrl(publicBaseUrl));
      expect(registered).toMatchObject({
        state: "pending",
        callbackUrl: `${publicBaseUrl}/integrations/attestbook/webhook`,
        managementToken: expect.stringMatching(/^ats_/),
        webhookSecret: expect.stringMatching(/^atw_/),
      });

      const verified = await verifySubscription(target, registered.id, registered.managementToken);
      expect(verified.state).toBe("active");
      expect(
        (await readSubscription(target, registered.id, registered.managementToken)).state,
      ).toBe("active");
      await expect(readSubscription(target, registered.id, "ats_wrong")).rejects.toThrow(/401/);
      expect(attestbookIntegration(serving, store).status()).toMatchObject({
        subscription: { last_verification_challenge_at: expect.any(String) },
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
