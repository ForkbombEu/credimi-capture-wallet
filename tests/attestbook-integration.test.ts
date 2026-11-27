import { X509Certificate, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Mdoc, SdJwtVcService } from "@credo-ts/core";
import type { Express } from "express";
import { type JWK, compactVerify, createLocalJWKSet, decodeJwt, importX509 } from "jose";
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
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { initIssuer } from "../src/config/key-material.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { credoOpenId4VciIssuer } from "../src/openid4vci/credo-issuer.js";
import { createApp } from "../src/server/app.js";
import { CaptureStore } from "../src/state.js";
import type { AppConfig, JsonRecord } from "../src/types.js";
import {
  AttestbookFixture,
  type FixtureAttestation,
  type FixtureEvent,
  signedDelivery,
} from "./attestbook-fixture.js";
import { createIssuerTestEnvironment, requireIssuer } from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import { credentialProofJwt } from "./support/issuance.js";
import { type TestKey, dpopProof, generateEs256Key } from "./support/keys.js";

const issuerId = "attestbook-experimental";
const issuerBaseUrl = "http://issuer.example.test";
const issuerIdentifier = `${issuerBaseUrl}/issuers/${issuerId}`;
const webhookSecret = "atw_test-subscription-secret-0000000000000000";
const adminToken = "test-admin-token";
let dataDir: string;
const fixture = new AttestbookFixture();
let environment: IssuerTestEnvironment;
let config: AppConfig;
let deviceBoundConfig: AppConfig;

const membershipVct = "urn:attestbook:membership-card";
const membershipId = `${membershipVct}:sd_jwt`;

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

async function preAuthorizedToken(harness: Harness, session: SessionResponse, dpop: TestKey) {
  const offer = (await request(harness.app).get(new URL(session.offer_url).pathname)).body as {
    grants: Record<string, JsonRecord>;
  };
  const grant = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] ?? {};
  const tokenPath = `/issuers/${issuerId}/token`;
  const token = await request(harness.app)
    .post(tokenPath)
    .set("DPoP", await dpopProof(dpop, { method: "POST", url: `${issuerBaseUrl}${tokenPath}` }))
    .type("form")
    .send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": String(grant["pre-authorized_code"]),
    });
  expect(token.status, JSON.stringify(token.body)).toBe(200);
  return token.body as { access_token: string };
}

async function requestCredential(
  harness: Harness,
  session: SessionResponse,
  dpop: TestKey,
  accessToken: string,
  holder: TestKey,
  clientId?: string,
): Promise<string> {
  const noncePath = `/issuers/${issuerId}/nonce`;
  const nonce = (await request(harness.app).post(noncePath)).body.c_nonce as string;
  const credentialPath = `/issuers/${issuerId}/credential`;
  const response = await request(harness.app)
    .post(credentialPath)
    .set("authorization", `DPoP ${accessToken}`)
    .set(
      "DPoP",
      await dpopProof(dpop, {
        method: "POST",
        url: `${issuerBaseUrl}${credentialPath}`,
        accessToken,
      }),
    )
    .send({
      credential_configuration_id: session.credential_configuration_id,
      proofs: {
        jwt: [
          await credentialProofJwt(
            holder,
            nonce,
            issuerIdentifier,
            deviceBoundConfig,
            holder,
            clientId,
          ),
        ],
      },
    });
  expect(response.status, response.text).toBe(200);
  return (
    (response.body as { credentials: { credential: string }[] }).credentials[0]?.credential ?? ""
  );
}

async function issuePreAuthorized(
  harness: Harness,
  body: JsonRecord,
): Promise<{ compact: string; holder: TestKey; session: SessionResponse }> {
  const session = await createSession(harness, { flow: "pre_authorized_code", ...body });
  const dpop = await generateEs256Key();
  const holder = await generateEs256Key();
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
  environment = await createIssuerTestEnvironment({
    prefix: "attestbook-e2e-",
    config: {
      issuer_base_url: issuerBaseUrl,
      public_base_url: issuerBaseUrl,
      attestbook: {
        enabled: true,
        base_url: fixture.origin,
        rulebook_id: fixture.rulebookId,
        webhook_secret: webhookSecret,
        admin_token: adminToken,
        allowed_schema_origins: [],
      },
    },
  });
  dataDir = environment.dataDir;
  config = environment.config;
  deviceBoundConfig = issuerAppConfig(config, requireIssuer(config, "eu-pid-device-bound"));
});

afterAll(async () => {
  await fixture.stop();
  environment?.cleanup();
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
    // The configuration id and the scope derive from the name and format; nothing else is served.
    const v1Id = membershipId;
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
    // The federation Entity Configuration publishes the key that signed this credential.
    const federated = createApp(
      { ...config, federation: { enabled: true, authority_hints: ["https://ta.example.test"] } },
      issuer.store,
    );
    const entityConfiguration = await request(federated).get(
      `/issuers/${issuerId}/.well-known/openid-federation`,
    );
    expect(entityConfiguration.status).toBe(200);
    // Decoded from an Entity Configuration this service just signed.
    const federation = decodeJwt(entityConfiguration.text) as {
      metadata: { openid_credential_issuer: { jwks: { keys: JWK[] } } };
    };
    const publishedIssuerJwks = federation.metadata.openid_credential_issuer.jwks;
    expect(JSON.stringify(publishedIssuerJwks)).not.toContain('"d"');
    await compactVerify(compact.split("~")[0] ?? "", createLocalJWKSet(publishedIssuerJwks));

    // Authorization code flow: the imported scope is mapped through the chained authorization server.
    const codeSession = await createSession(issuer, { credential_configuration_id: v1Id });
    const offer = JSON.parse(
      String(new URL(codeSession.deeplink).searchParams.get("credential_offer")),
    ) as {
      grants: { authorization_code: { issuer_state: string } };
    };
    const dpop = await generateEs256Key();
    const clientId = "https://wallet.example.test";
    const redirectUri = `${clientId}/callback`;
    const codeVerifier = randomBytes(48).toString("base64url");
    const parPath = `/issuers/${issuerId}/par`;
    const par = await request(issuer.app)
      .post(parPath)
      .set("DPoP", await dpopProof(dpop, { method: "POST", url: `${issuerBaseUrl}${parPath}` }))
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
      .set("DPoP", await dpopProof(dpop, { method: "POST", url: `${issuerBaseUrl}${tokenPath}` }))
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
      await generateEs256Key(),
      clientId,
    );
    expect(
      new SdJwtVcService({} as never).fromCompact(authorizationCodeCredential).prettyClaims,
    ).toMatchObject({ ...codeSession.generated_claims?.claims, vct: membershipVct });

    // Wallet-initiated: a PAR naming the imported scope and no issuer_state gets its own session,
    // pinned to the active definition with generated values, as an offered session is.
    const walletVerifier = randomBytes(48).toString("base64url");
    const walletDpop = await generateEs256Key();
    const walletPar = await request(issuer.app)
      .post(parPath)
      .set(
        "DPoP",
        await dpopProof(walletDpop, { method: "POST", url: `${issuerBaseUrl}${parPath}` }),
      )
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
      .set(
        "DPoP",
        await dpopProof(walletDpop, { method: "POST", url: `${issuerBaseUrl}${tokenPath}` }),
      )
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
      await generateEs256Key(),
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
        credential_configuration_ids: [membershipId],
      },
      last_observed_event: { event_id: v2.id },
    });
    const v2Id = membershipId;
    expect(await advertisedIds(issuer)).toEqual([v2Id]);
    const v2Metadata = await request(issuer.app).get(
      `/.well-known/openid-credential-issuer/issuers/${issuerId}`,
    );
    expect(
      v2Metadata.body.credential_configurations_supported[v2Id].credential_metadata.claims,
    ).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: ["memberships", null, "club"] })]),
    );

    const inFlightDpop = await generateEs256Key();
    const inFlightToken = await preAuthorizedToken(issuer, inFlight, inFlightDpop);
    const noncePath = `/issuers/${issuerId}/nonce`;
    const inFlightNonce = (await request(issuer.app).post(noncePath)).body.c_nonce as string;
    const credentialPath = `/issuers/${issuerId}/credential`;
    const refused = await request(issuer.app)
      .post(credentialPath)
      .set("authorization", `DPoP ${inFlightToken.access_token}`)
      .set(
        "DPoP",
        await dpopProof(inFlightDpop, {
          method: "POST",
          url: `${issuerBaseUrl}${credentialPath}`,
          accessToken: inFlightToken.access_token,
        }),
      )
      .send({
        credential_configuration_id: inFlight.credential_configuration_id,
        proofs: {
          jwt: [
            await credentialProofJwt(
              await generateEs256Key(),
              inFlightNonce,
              issuerIdentifier,
              deviceBoundConfig,
            ),
          ],
        },
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
      membership(4, { joined: { type: "string", format: "email" } }),
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
    expect(await issuerCredentialIds(issuer)).toEqual([membershipId]);
  });

  it("offers the imported credential on the launcher, the issuer page, and the verifier page", async () => {
    fixture.publish("6.0", [membership(6)]);
    const issuer = await startIssuer();
    const issuerPage = await request(issuer.app)
      .get(`/issuers/${issuerId}`)
      .set("Accept", "text/html");
    expect(issuerPage.status).toBe(200);
    expect(issuerPage.text).toContain(
      `<option value="${membershipId}" data-format="dc+sd-jwt" data-imported="true">`,
    );

    const verifierPage = await request(issuer.app).get("/openid4vp");
    expect(verifierPage.status).toBe(200);
    const dcql = new RegExp(`<option value="${membershipId}" data-dcql="([^"]+)"`).exec(
      verifierPage.text,
    )?.[1];
    if (!dcql) throw new Error("verifier page does not offer the imported credential");
    expect(JSON.parse(dcql.replaceAll("&quot;", '"'))).toMatchObject({
      credentials: [{ format: "dc+sd-jwt", meta: { vct_values: [membershipVct] } }],
    });

    // The launcher marks it imported, so its Token Status List switch is disabled: the API
    // refuses a status list for it.
    const launcher = await request(issuer.app).get("/");
    expect(launcher.text).toMatch(
      new RegExp(
        `<option value="${membershipId}" data-issuer="${issuerId}" data-dcql="[^"]+" data-imported="true"`,
      ),
    );
  });

  it("issues an imported mdoc over OpenID4VCI and requests it by doctype over OpenID4VP", async () => {
    const namespace = "org.iso.18013.5.1";
    fixture.publish("7.0", [
      {
        name: "Driving Licence",
        mdocSchema: {
          type: "object",
          required: [namespace],
          properties: {
            docType: { const: "org.iso.18013.5.1.mDL" },
            [namespace]: {
              type: "object",
              required: ["family_name", "birth_date", "portrait"],
              properties: {
                family_name: { type: "string", minLength: 1 },
                birth_date: { type: "string", format: "date" },
                portrait: { type: "string", contentEncoding: "base64" },
                place_of_birth: {
                  type: "object",
                  minProperties: 1,
                  properties: { country: { type: "string" } },
                },
              },
            },
          },
        },
      },
    ]);
    const issuer = await startIssuer();
    const mdlId = "urn:attestbook:driving-licence:mso_mdoc";
    expect(await status(issuer)).toMatchObject({
      active: { version: "7.0", credential_configuration_ids: [mdlId] },
      sync: { state: "idle", failure: null },
    });

    const metadata = await request(issuer.app).get(
      `/.well-known/openid-credential-issuer/issuers/${issuerId}`,
    );
    const configuration = metadata.body.credential_configurations_supported[mdlId] as JsonRecord;
    expect(configuration).toMatchObject({
      format: "mso_mdoc",
      doctype: "org.iso.18013.5.1.mDL",
      scope: mdlId,
      cryptographic_binding_methods_supported: ["cose_key"],
    });
    const claimPaths = (
      (configuration.credential_metadata as JsonRecord).claims as { path: unknown[] }[]
    ).map((claim) => claim.path);
    expect(claimPaths).toEqual(
      expect.arrayContaining([
        [namespace, "family_name"],
        [namespace, "place_of_birth", "country"],
      ]),
    );

    const { compact, session } = await issuePreAuthorized(issuer, {
      credential_configuration_id: mdlId,
    });
    expect(session.credential_definition).toMatchObject({
      format: "mso_mdoc",
      doctype: "org.iso.18013.5.1.mDL",
      doctype_source: "json_schema",
    });
    const mdoc = Mdoc.fromBase64Url(compact);
    expect(mdoc.docType).toBe("org.iso.18013.5.1.mDL");
    const elements = mdoc.issuerSignedNamespaces[namespace] ?? {};
    const generated = session.generated_claims?.claims[namespace] as JsonRecord;
    expect(elements.family_name).toBe(generated.family_name);
    expect(String(elements.birth_date)).toBe(generated.birth_date);
    expect(Buffer.from(elements.portrait as Uint8Array).toString("base64")).toBe(
      generated.portrait,
    );

    const verifierPage = await request(issuer.app).get("/openid4vp");
    const dcql = new RegExp(`<option value="${mdlId}" data-dcql="([^"]+)"`).exec(
      verifierPage.text,
    )?.[1];
    if (!dcql) throw new Error("verifier page does not offer the imported mdoc");
    const query = JSON.parse(dcql.replaceAll("&quot;", '"')) as {
      credentials: { format: string; meta: JsonRecord; claims: { path: unknown[] }[] }[];
    };
    expect(query.credentials[0]).toMatchObject({
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.18013.5.1.mDL" },
    });
    // OpenID4VP Section 7.2: an mdoc claims path pointer is exactly [namespace, data element].
    expect(query.credentials[0]?.claims.every((claim) => claim.path.length === 2)).toBe(true);
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
