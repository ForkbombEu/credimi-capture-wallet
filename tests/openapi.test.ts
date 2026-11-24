import request from "supertest";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.js";
import { openApiDocument } from "../src/openapi/document.js";
import { createApp } from "../src/server/app.js";
import type { AppConfig, JsonRecord } from "../src/types.js";

const enabledAttestbook = {
  enabled: true,
  base_url: "https://attestbook.example.test",
  rulebook_id: "pid-rulebook",
  webhook_secret: "webhook-secret",
  admin_token: "admin-token",
  allowed_schema_origins: [],
};

const conditionalPathKeys = {
  federation: "/issuers/{issuerConfigurationId}/.well-known/openid-federation",
  attestbookWebhook: "/integrations/attestbook/webhook",
  attestbookSync: "/integrations/attestbook/sync",
  notification: "/issuers/{issuerConfigurationId}/notification",
} as const;

const baseTagNames = [
  "Service",
  "Issuance sessions",
  "Presentation sessions",
  "OpenID4VCI",
  "OpenID4VP",
  "Fake OAuth",
];

const allOnPathKeys = [
  "/healthz",
  "/.well-known/openid-credential-issuer/issuers/{issuerConfigurationId}",
  "/issuers/{issuerConfigurationId}/.well-known/openid-federation",
  "/.well-known/oauth-authorization-server/issuers/{issuerConfigurationId}",
  "/.well-known/oauth-authorization-server/authorization-servers/{issuerConfigurationId}",
  "/.well-known/jwt-vc-issuer/issuers/{issuerConfigurationId}",
  "/issuers/{issuerConfigurationId}/jwks.json",
  "/issuers/{issuerConfigurationId}/credential-jwks.json",
  "/oid4vci/requests",
  "/issuers",
  "/integrations/attestbook/status",
  "/integrations/attestbook/webhook",
  "/integrations/attestbook/sync",
  "/sessions",
  "/sessions/{sessionId}",
  "/sessions/{sessionId}/offer",
  "/sessions/{sessionId}/deeplink",
  "/sessions/{sessionId}/jwks",
  "/sessions/{sessionId}/events",
  "/sessions/{sessionId}/requests",
  "/sessions/{sessionId}/status",
  "/openid4vp/sessions",
  "/openid4vp/did.json",
  "/openid4vp/sessions/{sessionId}",
  "/openid4vp/sessions/{sessionId}/request",
  "/openid4vp/sessions/{sessionId}/deeplink",
  "/openid4vp/sessions/{sessionId}/response",
  "/openid4vp/sessions/{sessionId}/dc_api_invocation",
  "/openid4vp/response",
  "/openid4vp/sessions/{sessionId}/events",
  "/issuers/{issuerConfigurationId}/offers/{credentialOfferId}",
  "/issuers/{issuerConfigurationId}/par",
  "/issuers/{issuerConfigurationId}/authorize",
  "/issuers/{issuerConfigurationId}/redirect",
  "/authorization-servers/{issuerConfigurationId}/authorize",
  "/authorization-servers/{issuerConfigurationId}/token",
  "/issuers/{issuerConfigurationId}/token",
  "/issuers/{issuerConfigurationId}/nonce",
  "/issuers/{issuerConfigurationId}/credential",
  "/issuers/{issuerConfigurationId}/notification",
];

type Flags = {
  federation: boolean;
  attestbook: boolean;
  notifications: boolean;
};

function configFor(flags: Flags, issuerBaseUrl = "https://capture.example.test"): AppConfig {
  return {
    ...DEFAULT_CONFIG,
    issuer_base_url: issuerBaseUrl,
    public_base_url: "https://public.capture.example.test",
    federation: {
      enabled: flags.federation,
      authority_hints: flags.federation ? ["https://trust-anchor.example.test"] : [],
    },
    attestbook: flags.attestbook
      ? enabledAttestbook
      : {
          enabled: false,
          base_url: null,
          rulebook_id: null,
          webhook_secret: null,
          admin_token: null,
          allowed_schema_origins: [],
        },
    oid4vci_notifications_enabled: flags.notifications,
  };
}

function operation(document: JsonRecord, path: string, method: "get" | "post"): JsonRecord {
  const paths = document.paths as JsonRecord;
  return ((paths[path] as JsonRecord)[method] as JsonRecord) ?? {};
}

function issuerIds(flags: Flags): string[] {
  return [
    "eu-pid-device-bound",
    "eu-pid-jwt-key-attestation",
    "eu-pid-jwt-proof-only",
    ...(flags.attestbook ? ["attestbook-experimental"] : []),
  ];
}

function expectedPathKeys(flags: Flags): string[] {
  return allOnPathKeys.filter((path) => {
    if (path === conditionalPathKeys.federation) return flags.federation;
    if (path === conditionalPathKeys.attestbookWebhook) return flags.attestbook;
    if (path === conditionalPathKeys.attestbookSync) return flags.attestbook;
    if (path === conditionalPathKeys.notification) return flags.notifications;
    return true;
  });
}

const flagCases: Array<Flags & { name: string }> = [
  { name: "all flags disabled", federation: false, attestbook: false, notifications: false },
  { name: "federation only", federation: true, attestbook: false, notifications: false },
  { name: "Attestbook only", federation: false, attestbook: true, notifications: false },
  { name: "notifications only", federation: false, attestbook: false, notifications: true },
  { name: "all flags enabled", federation: true, attestbook: true, notifications: true },
];

describe("OpenAPI feature-dependent structure", () => {
  it.each(flagCases)("describes conditional paths and tags for $name", (flags) => {
    const config = configFor(flags);
    const document = openApiDocument(config);
    const paths = document.paths as JsonRecord;
    const conditionalKeys: readonly string[] = Object.values(conditionalPathKeys);
    const expectedConditionalKeys = [
      ...(flags.federation ? [conditionalPathKeys.federation] : []),
      ...(flags.attestbook
        ? [conditionalPathKeys.attestbookWebhook, conditionalPathKeys.attestbookSync]
        : []),
      ...(flags.notifications ? [conditionalPathKeys.notification] : []),
    ];

    expect(Object.keys(paths).filter((path) => conditionalKeys.includes(path))).toEqual(
      expectedConditionalKeys,
    );

    expect(Object.keys(paths)).toEqual(expectedPathKeys(flags));
    expect((document.tags as unknown[]).map((tag) => (tag as JsonRecord).name)).toEqual([
      ...baseTagNames,
      ...(flags.attestbook ? ["Attestbook"] : []),
      ...(flags.federation ? ["OpenID Federation"] : []),
    ]);
    expect((document.servers as JsonRecord[])[0]?.url).toBe(config.issuer_base_url);

    const metadata = operation(
      document,
      "/.well-known/openid-credential-issuer/issuers/{issuerConfigurationId}",
      "get",
    );
    const metadataParameters = metadata.parameters as JsonRecord[];
    expect((metadataParameters[0]?.schema as JsonRecord).enum).toEqual(issuerIds(flags));

    const issuerParameterEnums: unknown[] = [];
    for (const pathItem of Object.values(paths)) {
      if (typeof pathItem !== "object" || pathItem === null || Array.isArray(pathItem)) continue;
      for (const operationValue of Object.values(pathItem as JsonRecord)) {
        if (
          typeof operationValue !== "object" ||
          operationValue === null ||
          Array.isArray(operationValue)
        )
          continue;
        const operationRecord = operationValue as JsonRecord;
        if (!Array.isArray(operationRecord.parameters)) continue;
        for (const parameter of operationRecord.parameters) {
          if (typeof parameter !== "object" || parameter === null || Array.isArray(parameter))
            continue;
          const parameterRecord = parameter as JsonRecord;
          if (parameterRecord.name !== "issuerConfigurationId") continue;
          const schema = parameterRecord.schema;
          if (typeof schema !== "object" || schema === null || Array.isArray(schema)) continue;
          issuerParameterEnums.push((schema as JsonRecord).enum);
        }
      }
    }
    expect(issuerParameterEnums.length).toBeGreaterThan(0);
    for (const issuerParameterEnum of issuerParameterEnums) {
      expect(issuerParameterEnum).toEqual(issuerIds(flags));
    }

    expect(
      Object.keys(
        operation(document, "/issuers/{issuerConfigurationId}/credential", "post")
          .responses as JsonRecord,
      ),
    ).toEqual(["200", "400", "401"]);
    if (flags.notifications) {
      expect(
        Object.keys(
          operation(document, "/issuers/{issuerConfigurationId}/notification", "post")
            .responses as JsonRecord,
        ),
      ).toEqual(["204", "400", "401", "404"]);
    }
  });

  it("keeps the all-on tag and path order stable", () => {
    const document = openApiDocument(
      configFor({ federation: true, attestbook: true, notifications: true }),
    );

    expect((document.tags as unknown[]).map((tag) => (tag as JsonRecord).name)).toEqual([
      ...baseTagNames,
      "Attestbook",
      "OpenID Federation",
    ]);
    expect(Object.keys(document.paths as JsonRecord)).toEqual(allOnPathKeys);
  });
});

describe("OpenAPI HTTP surface", () => {
  it("serves the configured document from GET /openapi.json", async () => {
    const config = configFor(
      { federation: false, attestbook: false, notifications: false },
      "https://wallet.example.test",
    );
    const response = await request(createApp(config)).get("/openapi.json");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toMatch(/^application\/json/);
    expect(response.body).toEqual(openApiDocument(config));
  });

  it("serves the interactive docs page pointing at the OpenAPI document", async () => {
    const config = configFor({ federation: false, attestbook: false, notifications: false });
    const response = await request(createApp(config)).get("/docs");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toMatch(/^text\/html/);
    expect(response.text).toContain('<elements-api apiDescriptionUrl="/openapi.json"');
  });
});
