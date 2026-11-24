import {
  type OpenId4VcIssuanceSessionRecord,
  OpenId4VcIssuanceSessionState,
} from "@credo-ts/openid4vc";
import type { Request } from "express";
import { describe, expect, it } from "vitest";
import {
  accessTokenSessionQuery,
  captureSessionIdFromCredo,
  captureStatus,
  issuanceSessionAuthorizes,
  issuanceSessionQuery,
  requestHeaders,
} from "../src/openid4vci/attribution.js";
import {
  captureAuthorizationEvidence,
  redactCredentialRequest,
  setObservedString,
} from "../src/openid4vci/evidence.js";
import { wwwAuthenticateChallenge } from "../src/openid4vci/notification.js";
import type { Oid4vciHttpRequestCapture, SessionCapture } from "../src/types.js";

function request(body: unknown = {}, query: Record<string, unknown> = {}, authorization?: string) {
  return {
    body,
    query,
    headers: { authorization },
    header(name: string) {
      return name.toLowerCase() === "authorization" ? authorization : undefined;
    },
  } as unknown as Request;
}

function unsignedToken(payload: Record<string, unknown>): string {
  const segment = (value: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${segment({ alg: "none", typ: "JWT" })}.${segment(payload)}.`;
}

function issuanceSession(overrides: Record<string, unknown> = {}) {
  return {
    authorization: { subject: "wallet-subject", issuerState: "issuer-state" },
    preAuthorizedCode: "pre-authorized-code",
    ...overrides,
  } as unknown as OpenId4VcIssuanceSessionRecord;
}

function evidenceSession(): SessionCapture {
  return {
    observed: {
      client_id: { value: null, source: null, also_seen_in: [] },
      redirect_uri: { value: null, source: null, also_seen_in: [] },
    },
    checks: {
      pkce_present: false,
      state_present: false,
      issuer_state_present: false,
    },
  } as unknown as SessionCapture;
}

function capture(path: string, body: unknown): Oid4vciHttpRequestCapture {
  return { path, body } as Oid4vciHttpRequestCapture;
}

describe("OpenID4VCI issuance attribution", () => {
  it.each([
    ["par", request({ issuer_state: "issuer-state" }), { issuerState: "issuer-state" }],
    ["par", request(), null],
    [
      "authorize",
      request({}, { request_uri: "urn:ietf:params:oauth:request_uri:reference" }),
      { chainedIdentityRequestUriReferenceValue: "reference" },
    ],
    [
      "redirect",
      request({}, { state: "redirect-state" }),
      { chainedIdentityState: "redirect-state" },
    ],
    ["redirect", request(), null],
    [
      "token",
      request({ "pre-authorized_code": "pre-authorized-code", code: "authorization-code" }),
      { preAuthorizedCode: "pre-authorized-code" },
    ],
    [
      "token",
      request({ "pre-authorized_code": "pre-authorized-code" }),
      { preAuthorizedCode: "pre-authorized-code" },
    ],
    ["token", request({ code: "authorization-code" }), { authorizationCode: "authorization-code" }],
    [
      "credential",
      request({}, {}, `Bearer ${unsignedToken({ issuer_state: "issuer-state" })}`),
      { issuerState: "issuer-state" },
    ],
    [
      "deferred-credential",
      request({}, {}, `DPoP ${unsignedToken({ "pre-authorized_code": "pre-authorized-code" })}`),
      { preAuthorizedCode: "pre-authorized-code" },
    ],
    [
      "notification",
      request({}, {}, `bearer ${unsignedToken({ issuer_state: "issuer-state" })}`),
      { issuerState: "issuer-state" },
    ],
  ] as const)("maps %s to its issuance query", (endpoint, req, expected) => {
    expect(issuanceSessionQuery(endpoint, req)).toEqual(expected);
  });

  it("returns null for an authorize request without RFC 9126 prefix and unknown endpoint", () => {
    expect(
      issuanceSessionQuery("authorize", request({}, { request_uri: "plain-request-uri" })),
    ).toBeNull();
    expect(
      issuanceSessionQuery(
        "unknown",
        request({}, {}, `Bearer ${unsignedToken({ issuer_state: "issuer-state" })}`),
      ),
    ).toBeNull();
  });

  it.each([
    ["missing", undefined, null],
    ["wrong scheme", "Basic token", null],
    [
      "Bearer issuer state",
      `Bearer ${unsignedToken({ issuer_state: "issuer-state" })}`,
      { issuerState: "issuer-state" },
    ],
    [
      "DPoP pre-authorized",
      `DPoP ${unsignedToken({ "pre-authorized_code": "pre-authorized-code" })}`,
      { preAuthorizedCode: "pre-authorized-code" },
    ],
    [
      "pre-authorized code takes precedence",
      `Bearer ${unsignedToken({
        "pre-authorized_code": "pre-authorized-code",
        issuer_state: "issuer-state",
      })}`,
      { preAuthorizedCode: "pre-authorized-code" },
    ],
    ["XBearer prefix", `XBearer ${unsignedToken({ issuer_state: "issuer-state" })}`, null],
  ] as const)("extracts %s access-token grant", (_name, authorization, expected) => {
    expect(accessTokenSessionQuery(authorization)).toEqual(expected);
  });

  it("retains duplicate request headers when converting to Fetch Headers", () => {
    const headers = request({}, {}, undefined);
    Object.assign(headers.headers, {
      authorization: ["Bearer first", "Bearer second"],
      "x-test": "one",
    });
    const result = requestHeaders(headers);
    expect(result.get("authorization")).toBe("Bearer first, Bearer second");
    expect(result.get("x-test")).toBe("one");
  });

  it("reads the capture session id from Credo metadata", () => {
    expect(
      captureSessionIdFromCredo({ issuanceMetadata: { captureSessionId: "capture-id" } } as never),
    ).toBe("capture-id");
    expect(
      captureSessionIdFromCredo({ issuanceMetadata: { captureSessionId: 42 } } as never),
    ).toBeNull();
  });

  it.each([
    ["subject mismatch", { sub: "other" }, false],
    [
      "pre-authorized code mismatch",
      { sub: "wallet-subject", "pre-authorized_code": "other" },
      false,
    ],
    ["issuer state mismatch", { sub: "wallet-subject", issuer_state: "other" }, false],
    ["matching subject without optional grants", { sub: "wallet-subject" }, true],
    [
      "matching subject and grants",
      {
        sub: "wallet-subject",
        issuer_state: "issuer-state",
        "pre-authorized_code": "pre-authorized-code",
      },
      true,
    ],
  ] as const)("checks issuance authorization: %s", (_name, payload, expected) => {
    expect(issuanceSessionAuthorizes(issuanceSession(), payload)).toBe(expected);
  });

  it("rejects a token without sub when the session has no authorization subject", () => {
    expect(issuanceSessionAuthorizes(issuanceSession({ authorization: {} }), {})).toBe(false);
  });

  it("maps every Credo state and preserves unknown states", () => {
    const states: Array<[OpenId4VcIssuanceSessionState, string]> = [
      [OpenId4VcIssuanceSessionState.OfferCreated, "created"],
      [OpenId4VcIssuanceSessionState.OfferUriRetrieved, "offer_retrieved"],
      [OpenId4VcIssuanceSessionState.AuthorizationInitiated, "authorization_requested"],
      [OpenId4VcIssuanceSessionState.AuthorizationGranted, "authorization_granted"],
      [OpenId4VcIssuanceSessionState.AccessTokenRequested, "token_requested"],
      [OpenId4VcIssuanceSessionState.AccessTokenCreated, "token_issued"],
      [OpenId4VcIssuanceSessionState.CredentialRequestReceived, "credential_requested"],
      [OpenId4VcIssuanceSessionState.CredentialsPartiallyIssued, "credentials_partially_issued"],
      [OpenId4VcIssuanceSessionState.Completed, "credential_issued"],
      [OpenId4VcIssuanceSessionState.Error, "error"],
    ];
    for (const [state, expected] of states) expect(captureStatus(state)).toBe(expected);
    expect(captureStatus("unknown" as OpenId4VcIssuanceSessionState)).toBe("unknown");
  });
});

describe("OpenID4VCI issuance evidence", () => {
  it("captures PAR and token evidence and observed values", () => {
    const session = evidenceSession();
    captureAuthorizationEvidence(
      session,
      capture("/issuers/example/par", {
        client_id: "wallet-client",
        redirect_uri: "https://wallet.example/callback",
        code_challenge: "challenge",
        code_challenge_method: "S256",
        state: "state",
        issuer_state: "issuer-state",
      }),
    );
    captureAuthorizationEvidence(session, capture("/issuers/example/token", { code: "code" }));
    expect(session.raw).toEqual({
      par_request: expect.objectContaining({ client_id: "wallet-client" }),
      token_request: { code: "code" },
    });
    expect(session.observed.client_id).toEqual({
      value: "wallet-client",
      source: "/issuers/example/par.body.client_id",
      also_seen_in: [],
    });
    expect(session.observed.redirect_uri).toEqual({
      value: "https://wallet.example/callback",
      source: "/issuers/example/par.body.redirect_uri",
      also_seen_in: [],
    });
    expect(session.checks).toMatchObject({
      pkce_present: true,
      state_present: true,
      issuer_state_present: true,
    });
  });

  it("records duplicate observed values only as conflicting sources", () => {
    const observed = { value: null, source: null, also_seen_in: [] as string[] };
    setObservedString(observed, "", "empty-source");
    setObservedString(observed, "first", "first-source");
    setObservedString(observed, "first", "duplicate-source");
    setObservedString(observed, "second", "conflict-source");
    expect(observed).toEqual({
      value: "first",
      source: "first-source",
      also_seen_in: ["conflict-source"],
    });
  });

  it.each([
    ["proof", { proof: { jwt: "secret" } }, { proof: { redacted: true, present: true } }],
    ["null proof", { proof: null }, { proof: { redacted: true, present: true } }],
    [
      "proofs",
      { proofs: { jwt: ["secret"], attestation: ["other"] } },
      {
        proofs: {
          jwt: { redacted: true, present: true },
          attestation: { redacted: true, present: true },
        },
      },
    ],
  ] as const)("redacts %s while retaining the request shape", (_name, requestBody, expected) => {
    const original = structuredClone(requestBody);
    expect(redactCredentialRequest(requestBody)).toEqual(expected);
    expect(requestBody).toEqual(original);
  });
});

describe("OpenID4VCI notification challenges", () => {
  it("encodes RFC 6750 parameters and sanitizes forbidden characters", () => {
    const error = Object.assign(new Error("unauthorized"), {
      wwwAuthenticateHeaders: [
        {
          scheme: "Bearer",
          error: "invalid_token",
          error_description: 'bad\n"quoted"\\reason',
          scope: "openid",
        },
        { scheme: "DPoP" },
      ],
    });
    expect(wwwAuthenticateChallenge(error)).toBe(
      'Bearer error="invalid_token", error_description="bad  quoted  reason", scope="openid", DPoP',
    );
  });

  it("returns null for errors without valid challenge headers", () => {
    expect(wwwAuthenticateChallenge(new Error("other"))).toBeNull();
    expect(wwwAuthenticateChallenge({ wwwAuthenticateHeaders: [{ scheme: "Bearer" }] })).toBeNull();
    expect(
      wwwAuthenticateChallenge(Object.assign(new Error(), { wwwAuthenticateHeaders: [] })),
    ).toBeNull();
    expect(
      wwwAuthenticateChallenge(
        Object.assign(new Error(), { wwwAuthenticateHeaders: [{ scheme: 42 }] }),
      ),
    ).toBeNull();
  });
});
