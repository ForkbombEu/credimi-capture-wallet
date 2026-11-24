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
  compactVerify,
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
  loadConfig,
  loadIssuerFederationJwks,
  loadIssuerJwks,
  resolveFederationSettings,
} from "../src/config.js";
import {
  issuerCertificatePath,
  issuerFederationPrivateJwkPath,
  privateJwkPath,
} from "../src/config/paths.js";
import {
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../src/configurations/registry.js";
import { issuerAppConfig } from "../src/configurations/resolve-urls.js";
import { issueSdJwtCredential } from "../src/credentials/signing.js";
import {
  ENTITY_STATEMENT_MEDIA_TYPE,
  signIssuerEntityConfiguration,
} from "../src/federation/entity-configuration.js";
import { issuerFederationRegistration } from "../src/federation/registration.js";
import { createApp } from "../src/server/app.js";
import type { AppConfig, JsonRecord } from "../src/types.js";

const TRUST_ANCHOR = "https://federation.test.example";
const dataDir = mkdtempSync(join(tmpdir(), "capture-wallet-federation-test-"));
let config: AppConfig;

/** RFC 7517/7518 members that would expose private or symmetric key material. */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

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
    const app = createApp(config);
    const issuers = resolvedIssuerConfigurations(config);
    const configurations = await Promise.all(
      issuers.map(async (issuer) => ({ issuer, jwt: await entityConfiguration(issuer.id) })),
    );

    for (const { issuer, jwt } of configurations) {
      const jwks = loadIssuerFederationJwks(issuer) as unknown as { keys: JWK[] };
      const issuerJwks = loadIssuerJwks(issuerAppConfig(config, issuer));
      const verified = await jwtVerify(jwt, createLocalJWKSet(jwks), {
        typ: "entity-statement+jwt",
        issuer: issuer.issuerIdentifier,
        subject: issuer.issuerIdentifier,
      });
      const header = decodeProtectedHeader(jwt);
      const payload = verified.payload as JsonRecord;
      const issuerMetadata = (
        await request(app)
          .get(`/.well-known/openid-credential-issuer/issuers/${issuer.id}`)
          .expect(200)
      ).body as JsonRecord;
      const authorizationServerMetadata = (
        await request(app)
          .get(`/.well-known/oauth-authorization-server/issuers/${issuer.id}`)
          .expect(200)
      ).body as JsonRecord;

      expect(header).toMatchObject({ alg: "ES256", typ: "entity-statement+jwt" });
      expect(payload.authority_hints).toEqual([TRUST_ANCHOR]);
      expect(payload.jwks).toEqual(jwks);
      // The federated Credential Issuer metadata is the live Credo metadata plus the issuer's
      // signing JWKS; the ordinary well-known metadata does not carry `jwks`.
      expect(payload.metadata).toEqual({
        openid_credential_issuer: { ...issuerMetadata, jwks: issuerJwks },
        oauth_authorization_server: authorizationServerMetadata,
      });
      expect(issuerMetadata).not.toHaveProperty("jwks");
      expect(issuerMetadata.credential_issuer).toBe(issuer.issuerIdentifier);
      expect(authorizationServerMetadata.issuer).toBe(issuer.issuerIdentifier);
      expect(JSON.stringify(payload.jwks)).not.toContain('"d"');
    }
  });

  it("publishes each issuer's credential signing keys separately from its federation keys", async () => {
    const issuers = resolvedIssuerConfigurations(config);
    const signingThumbprints = new Set<string>();

    for (const issuer of issuers) {
      // Decoded from an Entity Configuration this service just signed.
      const payload = decodeJwt(await entityConfiguration(issuer.id)) as {
        jwks: { keys: JWK[] };
        metadata: { openid_credential_issuer: { jwks: { keys: JWK[] } } };
      };
      const published = payload.metadata.openid_credential_issuer.jwks;
      const signingPrivateJwk: JWK = JSON.parse(
        readFileSync(privateJwkPath(issuer.materialDirectory), "utf8"),
      );
      const { d: _d, ...signingPublicJwk } = signingPrivateJwk;
      const certificate = readFileSync(issuerCertificatePath(issuer.materialDirectory), "utf8")
        .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
        .replace(/\s+/g, "");

      expect(published.keys).toEqual([
        { ...signingPublicJwk, alg: "ES256", use: "sig", x5c: [certificate] },
      ]);
      for (const jwk of published.keys) {
        for (const member of PRIVATE_JWK_MEMBERS) expect(jwk).not.toHaveProperty(member);
      }

      const federationThumbprints = await Promise.all(
        payload.jwks.keys.map((jwk) => calculateJwkThumbprint(jwk)),
      );
      for (const jwk of published.keys) {
        const thumbprint = await calculateJwkThumbprint(jwk);
        expect(federationThumbprints).not.toContain(thumbprint);
        expect(signingThumbprints.has(thumbprint)).toBe(false);
        signingThumbprints.add(thumbprint);
      }

      // A credential signed by the issuer verifies against the published key alone.
      const { publicKey } = await generateKeyPair("ES256", { extractable: true });
      const holderJwk: JsonRecord = { ...(await exportJWK(publicKey)) };
      const compact = await issueSdJwtCredential({
        config: issuerAppConfig(config, issuer),
        credentialConfigurationId: config.credential_configuration_id,
        holderJwk,
      });
      await expect(
        compactVerify(compact.split("~")[0] ?? "", createLocalJWKSet(published)),
      ).resolves.toBeDefined();
    }
  });

  it("refuses to publish private credential signing key material", async () => {
    const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
    if (!issuer) throw new Error("device-bound issuer unavailable");
    const privateSigningJwk: JsonRecord = JSON.parse(
      readFileSync(privateJwkPath(issuer.materialDirectory), "utf8"),
    );

    await expect(
      signIssuerEntityConfiguration({
        issuer,
        authorityHints: [TRUST_ANCHOR],
        issuerMetadata: { credential_issuer: issuer.issuerIdentifier },
        issuerJwks: { keys: [privateSigningJwk] },
        authorizationServerMetadata: { issuer: issuer.issuerIdentifier },
      }),
    ).rejects.toThrow("credential signing JWKS contains private key material");
  });

  it("rejects metadata that does not identify the federation entity", async () => {
    const issuer = resolvedIssuerConfigurationById(config, "eu-pid-device-bound");
    if (!issuer) throw new Error("device-bound issuer unavailable");

    await expect(
      signIssuerEntityConfiguration({
        issuer,
        authorityHints: [TRUST_ANCHOR],
        issuerMetadata: { credential_issuer: issuer.issuerIdentifier },
        issuerJwks: loadIssuerJwks(issuerAppConfig(config, issuer)),
        authorizationServerMetadata: { issuer: "https://other.example/authorization-server" },
      }),
    ).rejects.toThrow("authorization server metadata identifier does not match");
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
        entity_types: ["openid_credential_issuer", "oauth_authorization_server"],
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
    const leafJwks = loadIssuerFederationJwks(issuer) as unknown as { keys: JWK[] };
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
