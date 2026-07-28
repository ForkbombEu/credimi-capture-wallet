import { readFile } from "node:fs/promises";
import { Agent, type AgentContext, ConsoleLogger, Kms, LogLevel, X509Module } from "@credo-ts/core";
import { OpenId4VcModule } from "@credo-ts/openid4vc";
import express from "express";
import { ISSUER_KEY_ID, privateJwkPath } from "./config.js";
import { InMemoryStorageModule, NodeKmsBackend, nodeAgentDependencies } from "./credo-openid4vp.js";
import type { AppConfig, JsonRecord } from "./types.js";

const issuerPromises = new Map<string, Promise<CredoOpenId4VciIssuer>>();

export async function credoOpenId4VciIssuer(config: AppConfig): Promise<CredoOpenId4VciIssuer> {
  const key = `${config.issuer_base_url}|${config.data_dir}`;
  let issuerPromise = issuerPromises.get(key);
  if (!issuerPromise) {
    issuerPromise = CredoOpenId4VciIssuer.create(config);
    issuerPromises.set(key, issuerPromise);
  }
  return issuerPromise;
}

export class CredoOpenId4VciIssuer {
  private constructor(private readonly agent: Agent) {}

  static async create(config: AppConfig): Promise<CredoOpenId4VciIssuer> {
    const kms = new NodeKmsBackend();
    const internalApp = express();
    const agent = new Agent({
      config: {
        allowInsecureHttpUrls: true,
        autoUpdateStorageOnStartup: false,
        logger: new ConsoleLogger(LogLevel.Error),
      },
      dependencies: nodeAgentDependencies(config),
      modules: {
        storage: new InMemoryStorageModule(),
        kms: new Kms.KeyManagementModule({
          backends: [kms],
          defaultBackend: kms.backend,
        }),
        x509: new X509Module({
          getTrustedCertificatesForVerification: (_agentContext, verificationContext) =>
            verificationContext.certificateChain.map((certificate) => certificate.toString("pem")),
        }),
        openid4vc: new OpenId4VcModule({
          issuer: {
            app: internalApp,
            baseUrl: config.issuer_base_url,
            cNonceExpiresInSeconds: config.nonce_ttl_seconds,
            authorizationCodeExpiresInSeconds: config.authorization_code_ttl_seconds,
            accessTokenExpiresInSeconds: config.access_token_ttl_seconds,
            requestUriExpiresInSeconds: config.par_request_uri_ttl_seconds,
            dpopRequired: true,
            credentialRequestToCredentialMapper: () => {
              throw new Error("Credential mapping is handled by the capture-aware route adapter");
            },
            endpoints: { jwks: "/jwks.json" },
          },
        }),
      },
    });

    const privateJwk = JSON.parse(
      await readFile(privateJwkPath(config.data_dir), "utf8"),
    ) as JsonRecord;
    privateJwk.kid = ISSUER_KEY_ID;
    await agent.kms.importKey({ privateJwk: privateJwk as never });
    return new CredoOpenId4VciIssuer(agent);
  }

  get context(): AgentContext {
    return this.agent.context;
  }

  get sdJwtVc() {
    return this.agent.sdJwtVc;
  }

  get mdoc() {
    return this.agent.mdoc;
  }
}
