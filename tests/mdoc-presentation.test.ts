import type { Express } from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createIssuerTestEnvironment, createTestApp } from "./support/environment.js";
import type { IssuerTestEnvironment } from "./support/environment.js";
import { getJson } from "./support/http.js";
import {
  type MdocCredential,
  createMdocDeviceResponse,
  issueMdocCredential,
  mdocDcqlForClaims,
} from "./support/mdoc.js";
import {
  type VpSessionCreateResponse,
  type VpSessionResponse,
  createVpSession,
  encryptedAuthorizationResponse,
  fetchRequestObject,
} from "./support/presentation.js";

const CLAIMS = ["family_name", "given_name"];
const TRANSCRIPT_ERROR =
  '\t- query_0[0]: Mdoc with doctype eu.europa.ec.eudi.pid.1 is not valid, Unable to verify deviceAuth signature (ECDSA/EdDSA): Device signature must be valid\n{\n  "error": "invalid_request",\n  "error_description": "One or more presentations failed verification."\n}';
const MULTIPLE_DOCUMENT_ERROR =
  'Presentation submission does not satisfy presentation request.\n{\n  "error": "invalid_request",\n  "error_description": "Presentation submission does not satisfy presentation request."\n} MDOC presentations must contain exactly one document';
const MULTIPLE_PRESENTATIONS_ERROR =
  'Presentation submission does not satisfy presentation request.\n{\n  "error": "invalid_request",\n  "error_description": "Presentation submission does not satisfy presentation request."\n} Query credential \'query_0\' has not enabled \'multiple\', but multiple presentations were provided. Only a single presentation is allowed for each query credential when \'multiple\' is not enabled on the query.';

let environment: IssuerTestEnvironment | undefined;
let app!: Express;
let credential!: MdocCredential;

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({
    prefix: "mdoc-presentation-test-",
    config: { public_base_url: "https://wallet-capture.example.test/" },
  });
  app = createTestApp(environment.config);
  credential = await issueMdocCredential(app, environment.config);
});

afterAll(() => environment?.cleanup());

async function submitDeviceResponse(
  session: VpSessionCreateResponse,
  deviceResponses: string | string[],
): Promise<request.Response> {
  const responses = Array.isArray(deviceResponses) ? deviceResponses : [deviceResponses];
  const payload = {
    vp_token: { query_0: responses },
    ...(session.authorization_request.state ? { state: session.authorization_request.state } : {}),
  };
  const response = String(session.authorization_request.response_mode).endsWith(".jwt")
    ? { response: await encryptedAuthorizationResponse(session.authorization_request, payload) }
    : payload;
  const responsePath = session.response_uri
    ? new URL(session.response_uri).pathname
    : `/openid4vp/sessions/${session.session_id}/response`;
  return request(app).post(responsePath).send(response);
}

async function readSession(sessionId: string): Promise<VpSessionResponse> {
  return getJson<VpSessionResponse>(app, `/openid4vp/sessions/${sessionId}`);
}

async function newSession(
  options: { multiple?: boolean; responseMode?: string } = {},
): Promise<VpSessionCreateResponse> {
  const query = mdocDcqlForClaims(CLAIMS);
  const queryCredential = (query.credentials as Record<string, unknown>[])[0];
  if (options.multiple) queryCredential.multiple = true;
  return createVpSession(app, {
    ...(options.responseMode ? { response_mode: options.responseMode } : {}),
    ...(options.responseMode?.startsWith("dc_api")
      ? {}
      : { redirect_uri: "https://rp.example.test/complete" }),
    presentation_request: { dcql_query: query },
  });
}

describe("mso_mdoc OpenID4VP presentation", () => {
  it("validates a DeviceResponse and captures decoded mdoc claims", async () => {
    const session = await newSession();
    const requestObject = await fetchRequestObject(app, session);
    expect(requestObject.split(".")).toHaveLength(3);
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
    });

    const response = await submitDeviceResponse(session, deviceResponse);
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body).toEqual({ redirect_uri: session.redirect_uri });

    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks).toEqual({
      presentation_valid: true,
      vp_token_format_valid: true,
      nonce_verified: true,
      transaction_data_verified: null,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
    expect(capture.decoded_presentations).toEqual({
      query_0: [
        {
          format: "mso_mdoc",
          document_types: ["eu.europa.ec.eudi.pid.1"],
          issuer_claims: {
            "eu.europa.ec.eudi.pid.1": {
              "eu.europa.ec.eudi.pid.1": {
                family_name: "Rossi",
                given_name: "Mario",
              },
            },
          },
          device_claims: {
            "eu.europa.ec.eudi.pid.1": {},
          },
        },
      ],
    });
    expect(capture.events.map((event) => event.type)).toEqual([
      "vp_session_created",
      "vp_deeplink_generated",
      "vp_request_retrieved",
      "vp_presentation_response_received",
    ]);
  });

  it.each([
    {
      name: "wrong nonce",
      mutateTranscript: (request: Record<string, unknown>) => ({
        ...request,
        nonce: "wrong-nonce",
      }),
    },
    {
      name: "wrong client binding",
      mutateTranscript: (request: Record<string, unknown>) => ({
        ...request,
        client_id: "https://wrong-client.example.test",
      }),
    },
  ])("rejects a DeviceResponse with $name transcript binding", async ({ mutateTranscript }) => {
    const session = await newSession();
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
      mutateTranscript,
    });

    const response = await submitDeviceResponse(session, deviceResponse);
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_presentation", errors: [TRANSCRIPT_ERROR] });

    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks).toMatchObject({
      presentation_valid: false,
      vp_token_format_valid: true,
      nonce_verified: false,
      holder_binding_verified: false,
      dcql_query_matched: false,
    });
    expect(capture.checks.errors).toEqual([TRANSCRIPT_ERROR]);
  });

  it("rejects two DeviceResponses when the DCQL query does not allow multiple", async () => {
    const session = await newSession();
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
    });

    const response = await submitDeviceResponse(session, [deviceResponse, deviceResponse]);
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "invalid_presentation",
      errors: [MULTIPLE_PRESENTATIONS_ERROR],
    });
    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks).toMatchObject({
      presentation_valid: false,
      vp_token_format_valid: true,
      nonce_verified: false,
      holder_binding_verified: false,
      dcql_query_matched: false,
    });
    expect(capture.checks.errors).toEqual([MULTIPLE_PRESENTATIONS_ERROR]);
    expect(capture.status).toBe("presentation_invalid");
  });

  it("validates multiple DeviceResponses when the DCQL query enables multiple", async () => {
    const session = await newSession({ multiple: true });
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
    });

    const response = await submitDeviceResponse(session, [deviceResponse, deviceResponse]);
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body).toEqual({ redirect_uri: session.redirect_uri });
    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks).toMatchObject({
      presentation_valid: true,
      vp_token_format_valid: true,
      nonce_verified: true,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
  });
  it("validates a DC API DeviceResponse bound to the expected browser origin", async () => {
    const session = await newSession({ responseMode: "dc_api" });
    const sessionCapture = await readSession(session.session_id);
    const origin = sessionCapture.dc_api?.expected_origin;
    expect(origin).toBe("https://wallet-capture.example.test");
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
      transcriptOrigin: origin,
    });
    const response = await submitDeviceResponse(session, deviceResponse);
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body).toEqual({});
    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_validated");
    expect(capture.checks).toMatchObject({
      presentation_valid: true,
      vp_token_format_valid: true,
      nonce_verified: true,
      holder_binding_verified: true,
      dcql_query_matched: true,
      errors: [],
    });
  });

  it("rejects a DC API DeviceResponse bound to the wrong browser origin", async () => {
    const session = await newSession({ responseMode: "dc_api" });
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
      transcriptOrigin: "https://evil.example.test",
    });
    const response = await submitDeviceResponse(session, deviceResponse);
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_presentation", errors: [TRANSCRIPT_ERROR] });
    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks).toMatchObject({
      presentation_valid: false,
      vp_token_format_valid: true,
      nonce_verified: false,
      holder_binding_verified: false,
      dcql_query_matched: false,
    });
    expect(capture.checks.errors).toEqual([TRANSCRIPT_ERROR]);
  });

  it("rejects a DeviceResponse with more than one document", async () => {
    const session = await newSession();
    const deviceResponse = await createMdocDeviceResponse({
      credential: credential.credential,
      holder: credential.holder,
      authorizationRequest: session.authorization_request,
      claims: CLAIMS,
      documents: 2,
    });

    const response = await submitDeviceResponse(session, deviceResponse);
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: "invalid_presentation",
      errors: [MULTIPLE_DOCUMENT_ERROR],
    });

    const capture = await readSession(session.session_id);
    expect(capture.status).toBe("presentation_invalid");
    expect(capture.checks).toMatchObject({
      presentation_valid: false,
      vp_token_format_valid: true,
      nonce_verified: false,
      holder_binding_verified: false,
      dcql_query_matched: false,
    });
    expect(capture.checks.errors).toEqual([MULTIPLE_DOCUMENT_ERROR]);
  });
});
