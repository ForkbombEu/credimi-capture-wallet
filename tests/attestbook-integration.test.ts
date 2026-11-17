import { X509Certificate, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import { DEFAULT_CONFIG, initIssuer } from "../src/config.js";
import { DEGREE_SD_JWT_VCT } from "../src/credential-definitions.js";
import { credentialRegistry } from "../src/credential-registry.js";
import { credoOpenId4VciIssuer } from "../src/credo-openid4vci.js";
import { degreeSdJwtCredentialConfigurationId } from "../src/metadata.js";
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
const claimsFile = join(dataDir, "claims.json");
const fixture = new AttestbookFixture();
let config: AppConfig;

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
      vct: `https://credentials.example.test/membership/${version}`,
      display: [{ locale: "en-US", name: `Membership card v${version}` }],
      claims: [{ path: ["active"], sd: "never" }],
    },
  };
}

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

function importedId(ids: string[], version: string): string {
  const id = ids.find((candidate) => candidate.includes(`:${version}:`));
  if (!id) throw new Error(`no imported credential for version ${version} in ${ids.join(", ")}`);
  return id;
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

/** OpenID4VCI 1.0 Appendix F.1: `iss` is the client_id, omitted for anonymous pre-authorized access. */
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
): Promise<{ compact: string; holder: Key }> {
  const session = await createSession(harness, { flow: "pre_authorized_code", ...body });
  const dpop = await key();
  const holder = await key();
  const token = await preAuthorizedToken(harness, session, dpop);
  return {
    compact: await requestCredential(harness, session, dpop, token.access_token, holder),
    holder,
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
  writeFileSync(
    claimsFile,
    JSON.stringify({
      fixtures: {
        membership: {
          member_id: "M-0042",
          given_name: "Ada",
          family_name: "Lovelace",
          tier: "gold",
          active: true,
          points: 120,
        },
      },
    }),
  );
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
      claims_file: claimsFile,
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
    const v1Ids = await issuerCredentialIds(issuer);
    const v1Id = importedId(v1Ids, "1.0");
    expect(v1Ids).toContain(degreeSdJwtCredentialConfigurationId(config, "jwt-proof"));
    expect(await advertisedIds(issuer)).toEqual(expect.arrayContaining(v1Ids));

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
      vct: "https://credentials.example.test/membership/1",
      scope: v1Id,
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } },
    });
    const authorizationServer = await request(issuer.app).get(
      `/.well-known/oauth-authorization-server/issuers/${issuerId}`,
    );
    expect(authorizationServer.body.scopes_supported).toContain(v1Id);

    // The issuer's PID-flavoured default data cannot silently stand in for the imported claims.
    const incomplete = await request(issuer.app)
      .post("/sessions")
      .send({ issuer_configuration_id: issuerId, credential_configuration_id: v1Id });
    expect(incomplete.status).toBe(400);
    expect(incomplete.body).toMatchObject({
      error: "claim_fixture_incomplete",
      fixture_id: "issuer_test_data",
      missing_claims: ["member_id"],
      supported_fixture_ids: ["membership"],
    });
    const pidOption = await request(issuer.app).post("/sessions").send({
      issuer_configuration_id: issuerId,
      credential_configuration_id: v1Id,
      fixture_id: "membership",
      document_number: "X1",
      status_list_enabled: true,
    });
    expect(pidOption.status).toBe(400);
    expect(pidOption.body).toMatchObject({
      error: "unsupported_for_imported_credential",
      unsupported_parameters: ["status_list_enabled", "document_number"],
    });

    // Pre-authorized code flow: a correctly signed SD-JWT VC of the new type.
    const { compact, holder } = await issuePreAuthorized(issuer, {
      credential_configuration_id: v1Id,
      fixture_id: "membership",
    });
    const decoded = new SdJwtVcService({} as never).fromCompact(compact);
    expect(decoded.prettyClaims).toMatchObject({
      vct: "https://credentials.example.test/membership/1",
      iss: issuerIdentifier,
      member_id: "M-0042",
      given_name: "Ada",
      family_name: "Lovelace",
      tier: "gold",
      active: true,
      cnf: { jwk: holder.publicJwk },
    });
    expect(decoded.prettyClaims).not.toHaveProperty("points");
    // `active` is never selectively disclosable per Type Metadata; `member_id` follows issuer policy.
    const issuerSignedPayload = decodeJwt(compact.split("~")[0] ?? "");
    expect(issuerSignedPayload.active).toBe(true);
    expect(issuerSignedPayload.member_id).toBeUndefined();
    expect(issuerSignedPayload._sd).toEqual(expect.any(Array));
    await verifyIssuerSignature(compact);

    // Authorization code flow: the imported scope is mapped through the chained authorization server.
    const codeSession = await createSession(issuer, {
      credential_configuration_id: v1Id,
      fixture_id: "membership",
    });
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
      new SdJwtVcService({} as never).fromCompact(authorizationCodeCredential).prettyClaims.vct,
    ).toBe("https://credentials.example.test/membership/1");

    // A session left in flight across the update keeps its pinned definition.
    const inFlight = await createSession(issuer, {
      credential_configuration_id: v1Id,
      fixture_id: "membership",
      flow: "pre_authorized_code",
    });
    expect(inFlight.credential_definition).toMatchObject({
      source: "attestbook",
      rulebook_id: fixture.rulebookId,
      version: "1.0",
      content_digest: v1.contentDigest,
      vct: "https://credentials.example.test/membership/1",
    });

    // Publishing a new version activates it without a restart, from one signed webhook.
    const v2 = fixture.publish("2.0", [membership(2, { points: { type: "integer", minimum: 0 } })]);
    const accepted = await deliver(issuer, v2);
    expect(accepted.status).toBe(202);
    expect(accepted.body).toEqual({ status: "accepted", event_id: v2.id });
    expect(await status(issuer)).toMatchObject({
      active: { version: "2.0", content_digest: v2.contentDigest },
      retained_credential_configuration_ids: [v1Id],
      last_observed_event: { event_id: v2.id },
    });
    const v2Id = importedId(await issuerCredentialIds(issuer), "2.0");
    expect(await issuerCredentialIds(issuer)).not.toContain(v1Id);
    expect(await advertisedIds(issuer)).toEqual(expect.arrayContaining([v1Id, v2Id]));
    const superseded = await request(issuer.app).post("/sessions").send({
      issuer_configuration_id: issuerId,
      credential_configuration_id: v1Id,
      fixture_id: "membership",
    });
    expect(superseded.status).toBe(400);

    const inFlightDpop = await key();
    const inFlightToken = await preAuthorizedToken(issuer, inFlight, inFlightDpop);
    const pinned = await requestCredential(
      issuer,
      inFlight,
      inFlightDpop,
      inFlightToken.access_token,
      await key(),
    );
    expect(new SdJwtVcService({} as never).fromCompact(pinned).prettyClaims).toMatchObject({
      vct: "https://credentials.example.test/membership/1",
    });
    await credentialRegistry(config, issuer.store).serialize(async () => undefined);
    expect(await advertisedIds(issuer)).not.toContain(v1Id);

    const { compact: v2Credential } = await issuePreAuthorized(issuer, {
      credential_configuration_id: v2Id,
      fixture_id: "membership",
    });
    expect(new SdJwtVcService({} as never).fromCompact(v2Credential).prettyClaims).toMatchObject({
      vct: "https://credentials.example.test/membership/2",
      points: 120,
    });

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
      membership(4, { address: { type: "object", properties: { city: { type: "string" } } } }),
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
          code: "unsupported_nested_claim",
          attestation: "Membership Card",
        }),
      ]),
    );
    expect(await advertisedIds(issuer)).toContain(v2Id);
    expect(JSON.stringify(rejected)).not.toContain(webhookSecret);
    expect(JSON.stringify(rejected)).not.toContain("M-0042");

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
      fixture_id: "membership",
    });
    expect(new SdJwtVcService({} as never).fromCompact(offline).prettyClaims.vct).toBe(
      "https://credentials.example.test/membership/2",
    );

    // A publication missed while the issuer was down is caught up by the next startup reconciliation.
    await fixture.start(port);
    const v5 = fixture.publish("5.0", [membership(5)]);
    issuer = await startIssuer();
    expect(await status(issuer)).toMatchObject({
      active: { version: "5.0", content_digest: v5.contentDigest },
      sync: { state: "idle", last_trigger: "startup" },
    });
    expect(importedId(await issuerCredentialIds(issuer), "5.0")).toContain(fixture.rulebookId);
  });

  it("issues the static test degree from the experimental issuer through the ordinary Credo flow", async () => {
    const harness = await startIssuer();
    const { compact } = await issuePreAuthorized(harness, {
      credential_configuration_id: degreeSdJwtCredentialConfigurationId(config, "jwt-proof"),
    });
    expect(new SdJwtVcService({} as never).fromCompact(compact).prettyClaims.vct).toBe(
      DEGREE_SD_JWT_VCT,
    );
    const [capture] = [...harness.store.sessions.values()];
    expect(capture?.credential_definition).toBeUndefined();
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
