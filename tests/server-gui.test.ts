import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  degreeSdJwtCredentialConfigurationId,
  domesticPidCredentialConfigurationId,
  mdocCredentialConfigurationId,
  numericSdJwtCredentialConfigurationId,
} from "../src/credentials/catalogue.js";
import {
  DEGREE_SD_JWT_CLAIMS,
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_MDOC_NAMESPACE,
  NUMERIC_SD_JWT_CLAIMS,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
} from "../src/credentials/definitions.js";
import { createApp } from "../src/server/app.js";
import type { JsonRecord } from "../src/types.js";
import { serverTestSuite } from "./support/server.js";
const { config } = serverTestSuite("fake-issuer-test-");

describe("capture issuer server", () => {
  it("creates GUI sessions and renders a QR deeplink page", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/sessions").redirects(0);

    expect(created.status).toBe(303);
    expect(created.headers.location).toMatch(/^\/ui\/sessions\//);

    const page = await request(app).get(created.headers.location ?? "");
    expect(page.status).toBe(200);
    expect(page.text).toContain("<svg");
    expect(page.text).toContain("openid-credential-offer://");
    expect(page.text).toContain("Scan the credential offer");
    expect(page.text).toContain(
      '<img class="brand-logo" src="/assets/credimi_logo.svg" alt="" aria-hidden="true"><span class="brand-name">Wallet metadata capture</span>',
    );
    expect(page.text).toContain("Scan the offer and accept it in the wallet");
    expect(page.text).toContain('<a class="btn btn-outline btn-md" href="/docs">API docs</a>');
    expect(page.text).toContain(
      '<a class="btn btn-outline btn-md" href="/openapi.json" download="openapi.json">OpenAPI</a>',
    );
    expect(page.text).toContain("Same content as the QR code");
    expect(page.text).toContain("metadata-pending");
    expect(page.text).toContain("metadata-state-waiting");
    expect(page.text).toContain("metadata-state-receiving");
    expect(page.text).toContain("credentialRequestArrived");
    expect(page.text).toContain("window.clearInterval(pollTimer)");
    expect(page.text).toContain("pollTimer = setInterval");
    expect(page.text).toContain(
      '<span class="status-chip status-issuer" id="status-label">waiting</span><a class="btn btn-outline btn-md" href="/docs">API docs</a><a class="btn btn-outline btn-md" href="/openapi.json" download="openapi.json">OpenAPI</a><a class="btn btn-outline btn-md" href="https://github.com/ForkbombEu/credimi-capture-wallet"',
    );
    expect(page.text).not.toContain("updated-label");
    expect(page.text).toContain("Wallet metadata");
    expect(page.text.match(/<details class="metadata-row"><summary>/g)).toHaveLength(5);
    expect(page.text).toContain("<summary>wallet_notification</summary><code>pending</code>");
    expect(page.text).toContain("<summary>client_id</summary><code>pending</code>");
    expect(page.text).toContain('querySelectorAll(".metadata-row[open]")');
    expect(page.text).toContain("openFields.has(row[0])");
  });

  it("creates GUI OpenID4VP sessions and renders a presentation QR page", async () => {
    const app = createApp(config);
    const created = await request(app).post("/ui/openid4vp/sessions").redirects(0);

    expect(created.status).toBe(303);
    expect(created.headers.location).toMatch(/^\/ui\/openid4vp\/sessions\//);

    const page = await request(app).get(created.headers.location ?? "");
    expect(page.status).toBe(200);
    expect(page.text).toContain("<svg");
    expect(page.text).toContain("openid4vp://");
    expect(page.text).toContain("Scan the presentation request");
    expect(page.text).toContain("Presentation response");
    expect(page.text).toContain("authorization_request");
    expect(page.text).toContain("request_uri_payload");
    expect(page.text).toContain("wallet_response");
    expect(page.text).toContain("presentation_response_decrypted");
    expect(page.text).not.toContain("presentation_submission");
    expect(page.text).toContain("formatJsonValue(session.authorization_request)");
    expect(page.text).toContain("formatJsonValue(session.raw.presentation_response_decrypted)");
    expect(page.text).toContain("formatJsonValue(session.raw.decoded_presentations)");
    expect(page.text).toContain("JSON.stringify(parsed, null, 4)");
    expect(page.text).toContain("white-space: pre-wrap");
    expect(page.text.indexOf("authorization_request")).toBeLessThan(
      page.text.indexOf("request_uri_payload"),
    );
    expect(page.text.indexOf("request_uri_payload")).toBeLessThan(
      page.text.indexOf("wallet_response"),
    );
    expect(page.text).toContain("window.clearInterval(pollTimer)");
    expect(page.text).toContain("pollTimer = setInterval");
    expect(page.text).toContain("__FAKE_ISSUER_VP_SESSION_ID__");
    expect(page.text.match(/<details class="metadata-row"><summary>/g)).toHaveLength(6);
    expect(page.text).toContain(
      "<summary>presentation_response_decrypted</summary><code>pending</code>",
    );
    expect(page.text).toContain("<summary>decoded_presentations</summary><code>pending</code>");
    expect(page.text).toContain("<summary>presentation_validation</summary><code>pending</code>");
    expect(page.text).toContain('querySelectorAll(".metadata-row[open]")');
    expect(page.text).toContain("openFields.has(row[0])");
  });

  it("creates GUI OpenID4VP sessions for the selected credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = mdocCredentialConfigurationId(
      config,
      "key-attestation-required",
    );
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const requestObjectClaims = decodeJwt(requestObject.text) as JsonRecord;
    const dcqlQuery = requestObjectClaims.dcql_query as JsonRecord;
    const dcqlCredentials = dcqlQuery.credentials as JsonRecord[];

    expect(requestObjectClaims.presentation_definition).toBeUndefined();
    expect(dcqlCredentials).toHaveLength(1);
    expect(dcqlCredentials[0]?.format).toBe("mso_mdoc");
    expect(dcqlCredentials[0]?.meta).toEqual({ doctype_value: PID_MDOC_DOCTYPE });
    expect((dcqlCredentials[0]?.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
    );
  });

  it("creates OpenID4VP requests for the degree credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = degreeSdJwtCredentialConfigurationId(
      config,
      "key-attestation-required",
    );
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const dcqlQuery = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];

    expect(credential).toMatchObject({
      format: "dc+sd-jwt",
      meta: { vct_values: [DEGREE_SD_JWT_VCT] },
    });
    expect((credential.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      DEGREE_SD_JWT_CLAIMS.map((claim) => claim.split(".")),
    );
  });

  it("creates OpenID4VP requests for the numeric credential", async () => {
    const app = createApp(config);
    const selectedCredentialConfigurationId = numericSdJwtCredentialConfigurationId(
      config,
      "key-attestation-required",
    );
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({ credential_configuration_id: selectedCredentialConfigurationId })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const dcqlQuery = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];

    expect(credential).toMatchObject({
      format: "dc+sd-jwt",
      meta: { vct_values: [NUMERIC_SD_JWT_VCT] },
    });
    expect((credential.claims as JsonRecord[]).map((claim) => claim.path)).toEqual(
      NUMERIC_SD_JWT_CLAIMS.map((claim) => claim.split(".")),
    );
  });

  it("creates OpenID4VP requests for the domestic PID mdoc across both namespaces", async () => {
    const app = createApp(config);
    const created = await request(app)
      .post("/ui/openid4vp/sessions")
      .type("form")
      .send({
        credential_configuration_id: domesticPidCredentialConfigurationId("mso_mdoc", "jwt-proof"),
      })
      .redirects(0);
    const sessionId = (created.headers.location ?? "").split("/").pop() ?? "";

    expect(created.status).toBe(303);
    const requestObject = await request(app).get(`/openid4vp/sessions/${sessionId}/request`);
    const dcqlQuery = (decodeJwt(requestObject.text) as JsonRecord).dcql_query as JsonRecord;
    const credential = (dcqlQuery.credentials as JsonRecord[])[0];

    expect(credential).toMatchObject({
      format: "mso_mdoc",
      meta: { doctype_value: PID_MDOC_DOCTYPE },
    });
    expect((credential.claims as JsonRecord[]).map((claim) => claim.path)).toEqual([
      ...PID_MDOC_CLAIMS.map((claim) => [PID_MDOC_NAMESPACE, claim]),
      [DOMESTIC_PID_MDOC_NAMESPACE, "credimi_domestic_claim"],
    ]);
  });
});
