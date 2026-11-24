import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent, Kms } from "@credo-ts/core";
import { OpenId4VcIssuerService, OpenId4VcModule } from "@credo-ts/openid4vc";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import {
  InMemoryStorageModule,
  NodeKmsBackend,
  nodeAgentDependencies,
} from "../src/openid4vp/credo-verifier.js";

/**
 * Phase 0 feasibility: the pinned Credo-TS issuer serves credential configurations and the chained
 * authorization server's scope mapping from its stored issuer record, so a record update changes
 * what it advertises and offers without restarting the agent.
 */
const dataDir = mkdtempSync(join(tmpdir(), "credo-hot-update-"));
const baseUrl = "http://issuer.example.test";
const issuerId = "hot-update-issuer";
const chainedAuthorizationServer = `${baseUrl}/authorization-servers/${issuerId}`;
let agent: Agent;

interface SdJwtConfiguration {
  format: "dc+sd-jwt";
  vct: string;
  scope: string;
  cryptographic_binding_methods_supported: string[];
  credential_signing_alg_values_supported: string[];
  proof_types_supported: { jwt: { proof_signing_alg_values_supported: string[] } };
}

function sdJwtConfiguration(vct: string, scope: string): SdJwtConfiguration {
  return {
    format: "dc+sd-jwt" as const,
    vct,
    scope,
    cryptographic_binding_methods_supported: ["jwk"],
    credential_signing_alg_values_supported: ["ES256"],
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } },
  };
}

function authorizationServerConfig(scopes: string[]) {
  return {
    type: "chained" as const,
    issuer: chainedAuthorizationServer,
    clientAuthentication: {
      type: "clientSecret" as const,
      clientId: "hot-update-client",
      clientSecret: "hot-update-secret",
    },
    scopesMapping: Object.fromEntries(scopes.map((scope) => [scope, ["external-scope"]])),
  };
}

beforeAll(async () => {
  const kms = new NodeKmsBackend();
  agent = new Agent({
    config: { allowInsecureHttpUrls: true, autoUpdateStorageOnStartup: true },
    dependencies: nodeAgentDependencies({ ...DEFAULT_CONFIG, data_dir: dataDir }),
    modules: {
      storage: new InMemoryStorageModule(),
      kms: new Kms.KeyManagementModule({ backends: [kms], defaultBackend: kms.backend }),
      openid4vc: new OpenId4VcModule({
        app: express() as never,
        issuer: {
          baseUrl: `${baseUrl}/issuers`,
          credentialRequestToCredentialMapper: () => {
            throw new Error("not used");
          },
        },
      }),
    },
  });
  await agent.initialize();
  await agent.openid4vc.issuer?.createIssuer({
    issuerId,
    accessTokenSignerKeyType: { kty: "EC", crv: "P-256" },
    credentialConfigurationsSupported: {
      static: sdJwtConfiguration("urn:test:static:1", "static-scope"),
    } as never,
    authorizationServerConfigs: [authorizationServerConfig(["static-scope"])],
  });
});

afterAll(async () => {
  await agent?.shutdown();
  rmSync(dataDir, { recursive: true, force: true });
});

function issuerApi() {
  const issuer = agent.openid4vc.issuer;
  if (!issuer) throw new Error("issuer API unavailable");
  return issuer;
}

async function replaceConfigurations(configurations: Record<string, SdJwtConfiguration>) {
  const record = await issuerApi().getIssuerByIssuerId(issuerId);
  record.credentialConfigurationsSupported = configurations as never;
  record.authorizationServerConfigs = [
    authorizationServerConfig(
      Object.values(configurations).map((configuration) => configuration.scope),
    ),
  ];
  await issuerApi().updateIssuer(record);
}

describe("Credo-TS issuer record hot update", () => {
  it("advertises, offers and scope-maps a configuration added at runtime, keeping existing ones", async () => {
    const before = await issuerApi().getIssuerMetadata(issuerId);
    expect(Object.keys(before.credentialIssuer.credential_configurations_supported)).toEqual([
      "static",
    ]);

    await replaceConfigurations({
      static: sdJwtConfiguration("urn:test:static:1", "static-scope"),
      imported: sdJwtConfiguration("urn:test:imported:1", "imported-scope"),
    });

    const after = await issuerApi().getIssuerMetadata(issuerId);
    expect(after.credentialIssuer.credential_configurations_supported).toMatchObject({
      static: { vct: "urn:test:static:1" },
      imported: { vct: "urn:test:imported:1", scope: "imported-scope" },
    });

    const preAuthorized = await issuerApi().createCredentialOffer({
      issuerId,
      credentialConfigurationIds: ["imported"],
      preAuthorizedCodeFlowConfig: {},
      version: "v1",
    });
    expect(
      preAuthorized.issuanceSession.credentialOfferPayload.credential_configuration_ids,
    ).toEqual(["imported"]);

    const authorizationCode = await issuerApi().createCredentialOffer({
      issuerId,
      credentialConfigurationIds: ["imported"],
      authorizationCodeFlowConfig: {
        authorizationServerUrl: chainedAuthorizationServer,
        scope: "imported-scope",
      },
      version: "v1",
    });
    expect(authorizationCode.issuanceSession.credentialOfferPayload.grants).toHaveProperty(
      "authorization_code",
    );

    const record = await issuerApi().getIssuerByIssuerId(issuerId);
    const chained = record.authorizationServerConfigs?.find(
      (server: { issuer: string }) => server.issuer === chainedAuthorizationServer,
    );
    expect(
      agent.dependencyManager.resolve(OpenId4VcIssuerService).getStaticChainedAuthorizationScopes({
        authorizationServerConfig: chained as never,
        requestedScopes: ["imported-scope", "static-scope"],
      }),
    ).toEqual(["external-scope", "external-scope"]);

    const existing = await issuerApi().createCredentialOffer({
      issuerId,
      credentialConfigurationIds: ["static"],
      preAuthorizedCodeFlowConfig: {},
      version: "v1",
    });
    expect(existing.issuanceSession.credentialOfferPayload.credential_configuration_ids).toEqual([
      "static",
    ]);
  });

  it("stops offering a configuration removed at runtime", async () => {
    await replaceConfigurations({
      static: sdJwtConfiguration("urn:test:static:1", "static-scope"),
    });

    await expect(
      issuerApi().createCredentialOffer({
        issuerId,
        credentialConfigurationIds: ["imported"],
        preAuthorizedCodeFlowConfig: {},
        version: "v1",
      }),
    ).rejects.toThrow(/imported/);
    const metadata = await issuerApi().getIssuerMetadata(issuerId);
    expect(Object.keys(metadata.credentialIssuer.credential_configurations_supported)).toEqual([
      "static",
    ]);
  });
});
