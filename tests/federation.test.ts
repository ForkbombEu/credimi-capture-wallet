import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type EntityId,
  type JWK as OidfedJwk,
  createTrustAnchorSet,
  resolveTrustChains,
  validateTrustChain,
} from "@oidfed/core";
import {
  type JWK,
  SignJWT,
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
} from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  initIssuer,
  issuerFederationPrivateJwkPath,
  loadConfig,
  resolveFederationSettings,
} from "../src/config.js";
import {
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../src/configurations/registry.js";
import { credoOpenId4VciIssuer } from "../src/credo-openid4vci.js";
import { ENTITY_STATEMENT_MEDIA_TYPE } from "../src/federation/entity-configuration.js";
import {
  issuerFederationJwks,
  issuerFederationRegistration,
} from "../src/federation/registration.js";
import { createApp } from "../src/server.js";
import { CaptureStore } from "../src/state.js";
import type { AppConfig, JsonRecord } from "../src/types.js";

const TRUST_ANCHOR = "https://federation.test.example";
const dataDir = mkdtempSync(join(tmpdir(), "capture-wallet-federation-test-"));
let config: AppConfig;

beforeAll(async () => {
  const initialized = await initIssuer({
    issuer_base_url: "https://capture-wallet.test.example",
    data_dir: dataDir,
    force: true,
  });
  config = {
    ...initialized,
    federation: { enabled: true, authority_hints: [TRUST_ANCHOR] },
  };
});

afterAll(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

async function entityConfiguration(issuerId: string): Promise<string> {
  const response = await request(createApp(config))
    .get(`/issuers/${issuerId}/.well-known/openid-federation`)
    .expect(200);
  expect(response.headers["content-type"]).toContain(ENTITY_STATEMENT_MEDIA_TYPE);
  return response.text;
}

async function signingJwk(): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return {
    privateJwk: { ...(await exportJWK(privateKey)), alg: "ES256", use: "sig", kid },
    publicJwk: { ...publicJwk, alg: "ES256", use: "sig", kid },
  };
}

async function signedEntityStatement(options: {
  privateJwk: JWK;
  kid: string;
  issuer: string;
  subject: string;
  claims: JsonRecord;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ ...options.claims, iss: options.issuer, sub: options.subject })
    .setProtectedHeader({ alg: "ES256", typ: "entity-statement+jwt", kid: options.kid })
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(await importJWK(options.privateJwk, "ES256"));
}

describe("OpenID Federation issuer leaf entities", () => {
  it("validates environment-only federation settings", () => {
    expect(resolveFederationSettings({})).toEqual({ enabled: false, authority_hints: [] });
    expect(() =>
      resolveFederationSettings({
        FEDERATION_ENABLED: "true",
        FEDERATION_AUTHORITY_HINTS: '["http://federation.test.example"]',
      }),
    ).toThrow("HTTPS Entity Identifiers");
    expect(() =>
      loadConfig(dataDir, {
        FEDERATION_ENABLED: "true",
        FEDERATION_AUTHORITY_HINTS: JSON.stringify([TRUST_ANCHOR]),
      }),
    ).not.toThrow();
  });

  it("provisions distinct persistent federation identities for every configured issuer", async () => {
    const allIssuers = resolvedIssuerConfigurations(config);
    const before = allIssuers.map((issuer) =>
      readFileSync(issuerFederationPrivateJwkPath(issuer.materialDirectory), "utf8"),
    );

    await initIssuer({
      issuer_base_url: config.issuer_base_url,
      data_dir: dataDir,
    });

    const privateJwks = allIssuers.map(
      (issuer) =>
        JSON.parse(
          readFileSync(issuerFederationPrivateJwkPath(issuer.materialDirectory), "utf8"),
        ) as JsonRecord,
    );
    expect(privateJwks.map((jwk) => jwk.kid)).toHaveLength(
      new Set(privateJwks.map((jwk) => jwk.kid)).size,
    );
    expect(
      allIssuers.map((issuer) =>
        readFileSync(issuerFederationPrivateJwkPath(issuer.materialDirectory), "utf8"),
      ),
    ).toEqual(before);
    expect(privateJwks.every((jwk) => jwk.kty === "EC" && jwk.crv === "P-256")).toBe(true);
  });

  it("serves live Credo metadata in self-signed Entity Configurations", async () => {
    const liveIssuer = await credoOpenId4VciIssuer(config, new CaptureStore(config));
    const issuers = resolvedIssuerConfigurations(config);
    const configurations = await Promise.all(
      issuers.map(async (issuer) => ({ issuer, jwt: await entityConfiguration(issuer.id) })),
    );

    for (const { issuer, jwt } of configurations) {
      const jwks = issuerFederationJwks(issuer) as { keys: JWK[] };
      const verified = await jwtVerify(jwt, createLocalJWKSet(jwks), {
        typ: "entity-statement+jwt",
        issuer: issuer.issuerIdentifier,
        subject: issuer.issuerIdentifier,
      });
      const header = decodeProtectedHeader(jwt);
      const payload = verified.payload as JsonRecord;
      const metadata = await liveIssuer.credentialIssuerMetadata(issuer.id);

      expect(header).toMatchObject({ alg: "ES256", typ: "entity-statement+jwt" });
      expect(payload.authority_hints).toEqual([TRUST_ANCHOR]);
      expect(payload.jwks).toEqual(jwks);
      expect(payload.metadata).toEqual({ openid_credential_issuer: metadata });
      expect(JSON.stringify(payload.jwks)).not.toContain('"d"');
    }
  });

  it("does not publish disabled or unknown issuer Entity Configurations", async () => {
    const app = createApp(config);
    await request(app)
      .get("/issuers/attestbook-experimental/.well-known/openid-federation")
      .expect(404);
    await request(app).get("/issuers/not-an-issuer/.well-known/openid-federation").expect(404);
    await request(createApp({ ...config, federation: { enabled: false, authority_hints: [] } }))
      .get("/issuers/eu-pid-device-bound/.well-known/openid-federation")
      .expect(404);
  });

  it("exports Trust Anchor registration entries without private material", () => {
    for (const issuer of resolvedIssuerConfigurations(config)) {
      const registration = issuerFederationRegistration(issuer);
      expect(registration).toMatchObject({
        entity_id: issuer.issuerIdentifier,
        enabled: true,
        entity_types: ["openid_credential_issuer"],
        constraints: { max_path_length: 0 },
      });
      expect(JSON.stringify(registration)).not.toContain('"d"');
    }
  });

  it("validates a registered leaf through an @oidfed/core Trust Chain", async () => {
    const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
    if (!issuer) throw new Error("device-bound issuer unavailable");
    const leaf = await entityConfiguration(issuer.id);
    const trustAnchor = await signingJwk();
    const trustAnchorKid = trustAnchor.publicJwk.kid;
    if (typeof trustAnchorKid !== "string") throw new Error("Trust Anchor key has no kid");
    const leafJwks = issuerFederationJwks(issuer) as { keys: JWK[] };
    const subordinateStatement = await signedEntityStatement({
      privateJwk: trustAnchor.privateJwk,
      kid: trustAnchorKid,
      issuer: TRUST_ANCHOR,
      subject: issuer.issuerIdentifier,
      claims: {
        jwks: leafJwks,
        constraints: { max_path_length: 0 },
      },
    });
    const trustAnchorConfiguration = await signedEntityStatement({
      privateJwk: trustAnchor.privateJwk,
      kid: trustAnchorKid,
      issuer: TRUST_ANCHOR,
      subject: TRUST_ANCHOR,
      claims: {
        jwks: { keys: [trustAnchor.publicJwk] },
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${TRUST_ANCHOR}/federation_fetch`,
          },
        },
      },
    });
    const anchors = createTrustAnchorSet([
      {
        entityId: TRUST_ANCHOR,
        jwks: { keys: [trustAnchor.publicJwk as OidfedJwk] },
      },
    ]);
    const fetchStub = async (input: string | URL | Request): Promise<Response> => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (
        `${url.origin}${url.pathname}` ===
        `${issuer.issuerIdentifier}/.well-known/openid-federation`
      ) {
        return new Response(leaf, { headers: { "content-type": ENTITY_STATEMENT_MEDIA_TYPE } });
      }
      if (`${url.origin}${url.pathname}` === `${TRUST_ANCHOR}/.well-known/openid-federation`) {
        return new Response(trustAnchorConfiguration, {
          headers: { "content-type": ENTITY_STATEMENT_MEDIA_TYPE },
        });
      }
      if (`${url.origin}${url.pathname}` === `${TRUST_ANCHOR}/federation_fetch`) {
        return new Response(subordinateStatement, {
          headers: { "content-type": ENTITY_STATEMENT_MEDIA_TYPE },
        });
      }
      return new Response("not found", { status: 404 });
    };

    const resolved = await resolveTrustChains(issuer.issuerIdentifier as EntityId, anchors, {
      httpClient: fetchStub,
    });
    expect(resolved.errors).toEqual([]);
    expect(resolved.chains).toHaveLength(1);
    const valid = await validateTrustChain(resolved.chains[0]?.statements ?? [], anchors, {
      httpClient: fetchStub,
    });
    expect(valid.valid).toBe(true);

    const impostor = await signingJwk();
    const impostorKid = impostor.publicJwk.kid;
    if (typeof impostorKid !== "string") throw new Error("Impostor key has no kid");
    const originalPayload = decodeJwt(leaf);
    const unregisteredLeaf = await new SignJWT({
      ...originalPayload,
      jwks: { keys: [impostor.publicJwk] },
    })
      .setProtectedHeader({ alg: "ES256", typ: "entity-statement+jwt", kid: impostorKid })
      .sign(await importJWK(impostor.privateJwk, "ES256"));
    const invalid = await validateTrustChain(
      [unregisteredLeaf, subordinateStatement, trustAnchorConfiguration],
      anchors,
      { httpClient: fetchStub },
    );
    expect(invalid.valid).toBe(false);
  });

  it("fails safely when enabled federation material is missing", () => {
    const issuer = resolvedIssuerConfigurationById(config, "eu-pid-jwt-proof-only");
    if (!issuer) throw new Error("JWT-only issuer unavailable");
    const path = issuerFederationPrivateJwkPath(issuer.materialDirectory);
    const original = readFileSync(path, "utf8");
    try {
      unlinkSync(path);
      expect(() => createApp(config)).toThrow("is missing federation material");
    } finally {
      writeFileSync(path, original);
    }
  });
});
