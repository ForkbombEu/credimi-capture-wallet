import type { Express } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { mdocCredentialConfigurationId } from "../src/credentials/catalogue.js";
import { createApp } from "../src/server/app.js";
import type { SessionCapture } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type SessionCreateResponse,
  keyAttestationJwt,
  preAuthorizedToken,
} from "./support/issuance.js";
import { generateEs256Key } from "./support/keys.js";
import { issuerProtocolPath, serverTestSuite } from "./support/server.js";
const { config, conformingIssuerConfig, postDpopProof } = serverTestSuite("fake-issuer-test-");

describe("capture issuer server", () => {
  describe("revocation through POST /sessions/{sessionId}/status", () => {
    const scenarioConfig = { ...config, fcaf_scenarios_enabled: true };
    const allocated = { uri: "https://status.example.test/token_status_list/EU/pid/1", idx: 42 };

    function stubStatusList(setResponse: () => Response) {
      const statusList = vi.fn<typeof fetch>(async (input) =>
        String(input).endsWith("/token_status_list/take")
          ? new Response(JSON.stringify({ status_list: allocated }), {
              headers: { "content-type": "application/json" },
              status: 200,
            })
          : setResponse(),
      );
      vi.stubGlobal("fetch", statusList);
      return statusList;
    }

    async function issuedMdocSession(app: Express, statusListEnabled = true) {
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        credential_configuration_id: mdocCredentialConfigurationId(
          config,
          "key-attestation-required",
        ),
        flow: "pre_authorized_code",
        status_list_enabled: statusListEnabled,
      });
      const dpop = await generateEs256Key();
      const token = await preAuthorizedToken(app, session, dpop, config.issuer_base_url);
      const credentialPath = issuerProtocolPath(session, "/credential");
      const nonce = await request(app).post(issuerProtocolPath(session, "/nonce"));
      const credential = await request(app)
        .post(credentialPath)
        .set("authorization", `DPoP ${token.access_token}`)
        .set("DPoP", await postDpopProof(dpop, credentialPath, token.access_token))
        .send({
          credential_configuration_id: session.credential_configuration_id,
          proofs: {
            attestation: [
              await keyAttestationJwt(
                conformingIssuerConfig,
                await generateEs256Key(),
                String(nonce.body.c_nonce),
              ),
            ],
          },
        });
      expect(credential.status, JSON.stringify(credential.body)).toBe(200);
      return session;
    }

    it("records the allocated reference and revokes it through the Status List service", async () => {
      const statusList = stubStatusList(() => new Response("Status Changed\n", { status: 200 }));
      const app = createApp(scenarioConfig);
      const session = await issuedMdocSession(app);
      const issued = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(issued.status_list_references).toEqual([
        { allocation_id: `${session.session_id}:0`, ...allocated },
      ]);

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const setCall = statusList.mock.calls.find(([input]) =>
        String(input).endsWith("/token_status_list/set"),
      );
      expect(String(setCall?.[0])).toBe("http://localhost:8000/token_status_list/set");
      expect(setCall?.[1]?.method).toBe("POST");
      expect(new Headers(setCall?.[1]?.headers).get("x-api-key")).toBe(config.status_list_api_key);
      expect(Object.fromEntries(new URLSearchParams(String(setCall?.[1]?.body)))).toEqual({
        uri: allocated.uri,
        idx: "42",
        status: "1",
      });
      const expectedResult = {
        ...allocated,
        status: 1,
        ok: true,
        http_status: 200,
        response_body: "Status Changed\n",
      };
      expect(response.body).toMatchObject({
        session_id: session.session_id,
        requested_status: "revoked",
        results: [expectedResult],
      });
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.status_list_updates).toEqual([
        { at: expect.any(String), requested_status: "revoked", results: [expectedResult] },
      ]);
      expect(
        capture.events.find((event) => event.type === "status_list_status_updated"),
      ).toMatchObject({
        detail: {
          requested_status: "revoked",
          results: [{ ...allocated, ok: true, http_status: 200 }],
        },
      });
      expect(JSON.stringify(capture)).not.toContain(`"${config.status_list_api_key}"`);
    });

    it("answers 502 and records the Status List service's refusal", async () => {
      stubStatusList(
        () =>
          new Response(JSON.stringify({ detail: "Wrong Status Change" }), {
            headers: { "content-type": "application/json" },
            status: 400,
          }),
      );
      const app = createApp(scenarioConfig);
      const session = await issuedMdocSession(app);

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status).toBe(502);
      expect(response.body).toMatchObject({
        error: "status_list_update_failed",
        results: [
          {
            ...allocated,
            ok: false,
            http_status: 400,
            response_body: '{"detail":"Wrong Status Change"}',
          },
        ],
      });
      const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
      expect(capture.status_list_updates?.[0]?.results[0]).toMatchObject({
        ok: false,
        http_status: 400,
      });
    });

    it("refuses a session issued without a status list", async () => {
      stubStatusList(() => new Response("unexpected", { status: 500 }));
      const app = createApp(scenarioConfig);
      const session = await issuedMdocSession(app, false);

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: "status_list_not_enabled" });
    });

    it("refuses before any reference was allocated", async () => {
      const app = createApp(scenarioConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        status_list_enabled: true,
      });

      const response = await request(app)
        .post(`/sessions/${session.session_id}/status`)
        .send({ status: "revoked" });

      expect(response.status).toBe(409);
      expect(response.body).toEqual({ error: "status_list_references_not_allocated" });
    });

    it.each([
      ["scenarios are disabled", config, { status: "revoked" }, "status_update_not_enabled"],
      ["the status is not revoked", scenarioConfig, { status: "valid" }, "unsupported_status"],
    ])("refuses the call when %s", async (_label, appConfig, body, error) => {
      const app = createApp(appConfig);
      const session = await postJson<SessionCreateResponse>(app, "/sessions", {
        status_list_enabled: true,
      });

      const response = await request(app).post(`/sessions/${session.session_id}/status`).send(body);

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ error });
    });
  });
});
