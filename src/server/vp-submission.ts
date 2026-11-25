import type { Request, Response } from "express";
import { redactHttpHeaders } from "../openid4vci/http-capture.js";
import { type CredoVpVerification, credoOpenId4VpVerifier } from "../openid4vp/credo-verifier.js";
import { asStringOrNull } from "../shared/json.js";
import type { CaptureStore } from "../state.js";
import type {
  AppConfig,
  JsonRecord,
  PresentationResponseHttpCapture,
  VpSessionCapture,
} from "../types.js";

export async function submitPresentation({
  config,
  store,
  req,
  res,
  session,
  body,
}: {
  config: AppConfig;
  store: CaptureStore;
  req: Request;
  res: Response;
  session: VpSessionCapture;
  body: JsonRecord;
}): Promise<Response> {
  const verificationSessionId = store.vpCredoVerificationSessionIds.get(session.session_id);
  if (!verificationSessionId) return res.status(404).json({ error: "vp_request_not_found" });
  const validation = await (await credoOpenId4VpVerifier(config)).verifyResponse(
    session,
    body,
    verificationSessionId,
  );
  captureVpResponse(store, session, body, presentationResponseHttpCapture(req, body), validation);
  if (!validation.valid) {
    const authorizationError =
      (session.response_mode === "direct_post" || session.response_mode === "direct_post.jwt") &&
      typeof validation.authorization_response?.error === "string";
    return sendVpSubmissionResponse(
      res,
      session,
      authorizationError ? 200 : 400,
      authorizationError ? {} : { error: "invalid_presentation", errors: validation.errors },
    );
  }
  return sendVpSubmissionResponse(
    res,
    session,
    200,
    session.redirect_uri ? { redirect_uri: session.redirect_uri } : {},
  );
}

function captureVpResponse(
  store: CaptureStore,
  session: VpSessionCapture,
  body: JsonRecord,
  http: PresentationResponseHttpCapture,
  validation: CredoVpVerification,
): void {
  session.status = validation.valid ? "presentation_validated" : "presentation_invalid";
  session.checks = {
    presentation_valid: validation.valid,
    vp_token_format_valid: validation.vp_token_format_valid,
    nonce_verified: validation.nonce_verified,
    holder_binding_verified: validation.holder_binding_verified,
    dcql_query_matched: validation.dcql_query_matched,
    transaction_data_verified: validation.transaction_data_verified,
    errors: validation.errors,
  };
  session.raw ??= {};
  session.raw.presentation_response = body;
  if (validation.authorization_response) {
    session.raw.presentation_response_decrypted = validation.authorization_response;
  }
  if (validation.authorization_response_raw) {
    session.raw.presentation_response_decrypted_raw = validation.authorization_response_raw;
  }
  if (validation.decoded_presentations) {
    session.decoded_presentations = validation.decoded_presentations;
    session.raw.decoded_presentations = validation.decoded_presentations;
  }
  session.raw.presentation_response_raw = http.body;
  session.raw.presentation_response_http = http;
  session.observed.wallet_response = {
    value: body,
    source: "presentation_response",
    also_seen_in: [],
  };
  store.addEvent(session, "vp_presentation_response_received", {
    vp_token_observed: validation.authorization_response?.vp_token !== undefined,
    presentation_valid: validation.valid,
    errors: validation.errors,
  });
}

/**
 * The single HTTP boundary for a submitted Authorization Response. A session's `response_scenario`
 * replaces the status, media type, or body delivered to the Wallet. It is applied here and nowhere
 * else, so the recorded verification outcome written by `captureVpResponse` cannot move with it: a
 * test-selected 400 never marks a valid presentation invalid, and a test-selected 200 never marks
 * an invalid one verified.
 */
function sendVpSubmissionResponse(
  res: Response,
  session: VpSessionCapture,
  status: number,
  body: JsonRecord,
): Response {
  const scenario = session.response_scenario;
  const deliveredStatus = scenario?.status ?? status;
  const serializedBody =
    scenario?.body ?? JSON.stringify({ ...body, ...(scenario?.extra_parameters ?? {}) });
  res.once("finish", () => {
    session.raw ??= {};
    session.raw.presentation_response_verifier_http = {
      status: res.statusCode,
      headers: redactHttpHeaders(res.getHeaders()),
      body: serializedBody,
    };
  });
  return res
    .status(deliveredStatus)
    .set("Cache-Control", "no-store")
    .type(scenario?.content_type ?? "application/json")
    .send(serializedBody);
}

export function presentationResponseHttpCapture(
  req: Request,
  body: JsonRecord,
): PresentationResponseHttpCapture {
  return {
    method: req.method,
    headers: redactHttpHeaders(req.headers),
    body: (req as Request & { rawBody?: string }).rawBody ?? JSON.stringify(body),
  };
}

export function vpPresentationCaptured(session: VpSessionCapture): boolean {
  return session.raw?.presentation_response !== undefined;
}

/**
 * DC API submissions carry no `state`, so the session is addressed by path. Correlation is
 * therefore enforced here instead: a session that already holds a presentation keeps it, an
 * expired presentation window is closed, and a browser-reported Origin that disagrees with the
 * session's trusted origin is refused rather than used to pick a different expected audience.
 * Redirect sessions are untouched, so wallet retries keep being captured as evidence.
 */
export function dcApiSubmissionRejectionOrNull(
  session: VpSessionCapture,
  req: Request,
): { status: number; error: string } | null {
  const dcApi = session.dc_api;
  if (!dcApi) return null;
  if (vpPresentationCaptured(session)) {
    return { status: 409, error: "vp_session_already_completed" };
  }
  if (Date.parse(dcApi.expires_at) <= Date.now()) {
    return { status: 400, error: "vp_session_expired" };
  }
  const origin = asStringOrNull(req.headers.origin);
  if (origin && origin !== dcApi.expected_origin) {
    return { status: 403, error: "unexpected_dc_api_origin" };
  }
  return null;
}
