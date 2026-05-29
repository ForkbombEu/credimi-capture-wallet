import { createHash } from "node:crypto";
import type { Express } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { createApp } from "../src/server.js";
import type { JsonRecord, SessionCapture } from "../src/types.js";
import { unsignedJwt } from "./helpers.js";

const config = {
  ...DEFAULT_CONFIG,
  issuer_base_url: "http://issuer.example.test",
  data_dir: "./data-test",
};

describe("capture issuer server", () => {
  it("stores PAR and merges it into authorize requests", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "correct horse battery staple";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postForm<ParResponse>(app, "/par", {
      client_id: "wallet-client",
      redirect_uri: "eudi-wallet://callback",
      response_type: "code",
      state: "wallet-state",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);

    expect(authorize.status).toBe(302);
    const location = new URL(authorize.headers.location ?? "");
    expect(location.protocol).toBe("eudi-wallet:");
    expect(location.searchParams.get("state")).toBe("wallet-state");
    expect(location.searchParams.get("code")).toBeTruthy();

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.observed.client_id.value).toBe("wallet-client");
    expect(capture.observed.redirect_uri.value).toBe("eudi-wallet://callback");
    expect(capture.raw?.authorization_request?.client_id).toBe("wallet-client");
  });

  it("verifies PKCE and captures credential proof JWKS", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const verifier = "pkce-verifier";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const par = await postForm<ParResponse>(app, "/par", {
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      state: "abc",
      issuer_state: session.session_id,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const authorize = await request(app)
      .get(`/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)
      .redirects(0);
    const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
    const token = await postForm<TokenResponse>(app, "/token", {
      grant_type: "authorization_code",
      code: code ?? "",
      client_id: "wallet-client",
      redirect_uri: "https://wallet.example/callback",
      code_verifier: verifier,
    });

    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    };
    const proof = unsignedJwt({ alg: "ES256", jwk });
    const credential = await request(app)
      .post("/credential")
      .set("authorization", `Bearer ${token.access_token}`)
      .send({ proof: { proof_type: "jwt", jwt: proof } });

    expect(credential.status).toBe(200);
    const walletJwks = await getJson<JwksResponse>(app, `/sessions/${session.session_id}/jwks`);
    expect(walletJwks.keys).toHaveLength(1);
    expect(walletJwks.keys[0]).toMatchObject({ ...jwk, alg: "ES256", use: "sig" });

    const capture = await getJson<SessionCapture>(app, `/sessions/${session.session_id}`);
    expect(capture.checks.pkce_valid).toBe(true);
    expect(capture.checks.proof_jwt_header_jwk_present).toBe(true);
  });

  it("returns a clear JWKS failure before a wallet key is observed", async () => {
    const app = createApp(config);
    const session = await postJson<SessionCreateResponse>(app, "/sessions", {});
    const response = await request(app).get(`/sessions/${session.session_id}/jwks`);

    expect(response.status).toBe(409);
    expect(response.body).toMatchObject({ error: "wallet_jwks_not_observed" });
  });
});

async function postJson<T>(app: Express, path: string, body: object): Promise<T> {
  const response = await request(app).post(path).send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function postForm<T>(app: Express, path: string, body: Record<string, string>): Promise<T> {
  const response = await request(app).post(path).type("form").send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

async function getJson<T>(app: Express, path: string): Promise<T> {
  const response = await request(app).get(path);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

interface SessionCreateResponse extends JsonRecord {
  session_id: string;
}

interface ParResponse extends JsonRecord {
  request_uri: string;
}

interface TokenResponse extends JsonRecord {
  access_token: string;
}

interface JwksResponse extends JsonRecord {
  keys: JsonRecord[];
}
