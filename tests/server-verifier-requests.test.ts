import { createHash } from "node:crypto";
import { SignJWT, decodeJwt, generateKeyPair } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import type { JsonRecord } from "../src/types.js";
import { getJson, postJson } from "./support/http.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  dcqlForClaims,
  sdJwtPresentation,
} from "./support/presentation.js";
import { serverTestSuite } from "./support/server.js";
const { config, pidSdJwtCredential } = serverTestSuite("fake-issuer-test-");
describe("scope-based presentation requests", () => {
  const scope = "eu.europa.ec.eudi.pid.1";

  it("delivers the scope without a dcql_query while keeping the query for verification", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: null, scope },
    });

    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    const delivered = decodeJwt(requestObject.text) as JsonRecord;
    expect(delivered.scope).toBe(scope);
    expect(delivered.dcql_query).toBeUndefined();
    // The verifier keeps a query: Credo matches the response against the request it holds, and a
    // scope value is resolved by the wallet's profile rather than by anything sent on the wire.
    expect(session.authorization_request.dcql_query).toBeDefined();

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.raw?.authorization_request_delivered?.dcql_query).toBeUndefined();
  });

  it("omits dcql_query from a plain deeplink while still carrying the scope", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      request_delivery: "plain",
      presentation_request: { dcql_query: null, scope },
    });

    const deeplink = new URL(session.deeplink);
    expect(deeplink.searchParams.get("scope")).toBe(scope);
    expect(deeplink.searchParams.has("dcql_query")).toBe(false);
  });

  it("verifies a presentation returned for a scope-only request", async () => {
    const app = createApp({ ...config, fcaf_scenarios_enabled: true });
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]), scope },
      request_mutation: { request_object: { unset: ["/dcql_query"] } },
    });
    const requestObject = await request(app).get(
      `/openid4vp/sessions/${session.session_id}/request`,
    );
    expect((decodeJwt(requestObject.text) as JsonRecord).dcql_query).toBeUndefined();

    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.dcql_query_matched).toBe(true);
    expect(capture.checks.presentation_valid).toBe(true);
  });

  it("sends a scope alongside dcql_query when both are requested", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]), scope },
    });

    const delivered = decodeJwt(
      (await request(app).get(`/openid4vp/sessions/${session.session_id}/request`)).text,
    ) as JsonRecord;
    expect(delivered.scope).toBe(scope);
    expect(delivered.dcql_query).toEqual(dcqlForClaims(["family_name"]));
  });
});

describe("presentation digest algorithms", () => {
  it("records the digest algorithm the presented credential used", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({ state: session.authorization_request.state, vp_token: { query_0: [presentation] } });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    const presented = (capture.decoded_presentations?.query_0 as JsonRecord[])[0];
    // Section 4.1.1 defaults an absent _sd_alg to sha-256, so the evidence states it either way.
    expect(presented.digest_algorithm).toBe("sha-256");
    expect(presented.claims).not.toHaveProperty("_sd_alg");
  });
});

describe("caller-supplied verifier info", () => {
  it("publishes the client identifier for every supported prefix", async () => {
    const app = createApp(config);
    const identifiers = await getJson<JsonRecord>(app, "/openid4vp/client-identifiers");
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {});

    expect(identifiers.x509_hash).toBe(session.authorization_request.client_id);
    expect(identifiers.decentralized_identifier).toMatch(/^decentralized_identifier:did:web:/);
    expect(identifiers.verifier_attestation).toMatch(/^verifier_attestation:/);
  });

  it("delivers a caller-signed attestation bound to the caller's own nonce", async () => {
    const app = createApp(config);
    const identifiers = await getJson<JsonRecord>(app, "/openid4vp/client-identifiers");
    const nonce = "caller-chosen-nonce";
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    // The harness signs the attestation and its proof of possession, because the structure is
    // defined by the profile under test rather than by this service.
    const attestation = await new SignJWT({ sub: String(identifiers.x509_hash) })
      .setProtectedHeader({ alg: "ES256", typ: "jwt" })
      .sign(privateKey);
    const proofOfPossession = await new SignJWT({
      nonce,
      client_id: identifiers.x509_hash,
    })
      .setProtectedHeader({ alg: "ES256" })
      .sign(privateKey);
    const verifierInfo = [
      {
        format: "jwt",
        data: attestation,
        proof_of_possession: proofOfPossession,
        credential_ids: ["query_0"],
      },
    ];

    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      presentation_request: { nonce, verifier_info: verifierInfo },
    });

    expect(session.authorization_request.nonce).toBe(nonce);
    const delivered = decodeJwt(
      (await request(app).get(`/openid4vp/sessions/${session.session_id}/request`)).text,
    ) as JsonRecord;
    expect(delivered.verifier_info).toEqual(verifierInfo);
    const deliveredProof = decodeJwt(
      (delivered.verifier_info as JsonRecord[])[0].proof_of_possession as string,
    );
    expect(deliveredProof.nonce).toBe(nonce);
    expect(deliveredProof.client_id).toBe(identifiers.x509_hash);
  });
});

describe("transaction data binding", () => {
  const entry = {
    type: "qes_authorization",
    credential_ids: ["query_0"],
    transaction_data_hashes_alg: ["sha-256"],
  };

  async function presentWithTransactionData(options: {
    transactionData: unknown[];
    hashes: (delivered: string[]) => string[] | undefined;
    hashesAlg?: string;
  }) {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: {
        dcql_query: dcqlForClaims(["family_name"]),
        transaction_data: options.transactionData,
      },
    });
    const delivered = session.authorization_request.transaction_data as string[];
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
      transactionDataHashes: options.hashes(delivered),
      // Credo rejects a Key Binding JWT that carries hashes without naming their algorithm.
      transactionDataHashesAlg: options.hashesAlg ?? "sha-256",
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });
    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    return capture;
  }

  function hashOf(entry: string, algorithm = "sha256"): string {
    return createHash(algorithm).update(entry, "ascii").digest("base64url");
  }

  it("accepts a presentation whose hashes cover the entries sent", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: (delivered) => delivered.map((value) => hashOf(value)),
    });

    expect(capture.checks.transaction_data_verified).toBe(true);
    expect(capture.checks.presentation_valid).toBe(true);
  });

  it("rejects hashes computed with an algorithm the entry did not offer", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: (delivered) => delivered.map((value) => hashOf(value, "sha384")),
      hashesAlg: "sha-384",
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.join(" ")).toContain("sha-384");
  });

  it("rejects a presentation whose hash covers no entry that was sent", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: () => [hashOf("an entry the verifier never sent")],
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.join(" ")).toContain("invalid_transaction_data");
  });

  it("rejects a presentation that omits the hashes for transaction data that was sent", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry],
      hashes: () => undefined,
      hashesAlg: undefined,
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
    expect(capture.checks.errors.join(" ")).toContain("invalid_transaction_data");
  });

  it("rejects a presentation leaving an entry for another credential uncovered", async () => {
    const capture = await presentWithTransactionData({
      transactionData: [entry, { ...entry, credential_ids: ["query_1"] }],
      hashes: (delivered) => [hashOf(delivered[0])],
    });

    expect(capture.checks.transaction_data_verified).toBe(false);
    expect(capture.checks.presentation_valid).toBe(false);
  });

  it("records no transaction data result when the request sent none", async () => {
    const app = createApp(config);
    const session = await postJson<VpSessionCreateResponse>(app, "/openid4vp/sessions", {
      response_mode: "direct_post",
      presentation_request: { dcql_query: dcqlForClaims(["family_name"]) },
    });
    const credential = await pidSdJwtCredential();
    const presentation = await sdJwtPresentation({
      credential,
      authorizationRequest: session.authorization_request,
      disclosedClaims: ["family_name"],
    });
    await request(app)
      .post(`/openid4vp/sessions/${session.session_id}/response`)
      .send({
        state: session.authorization_request.state,
        vp_token: { query_0: [presentation] },
      });

    const capture = await getJson<VpSessionResponse>(
      app,
      `/openid4vp/sessions/${session.session_id}`,
    );
    expect(capture.checks.transaction_data_verified).toBeNull();
    expect(capture.checks.presentation_valid).toBe(true);
  });
});
