import { isRecord } from "../shared/json.js";
import type { JsonRecord, Oid4vciHttpRequestCapture, SessionCapture } from "../types.js";

export function captureAuthorizationEvidence(
  session: SessionCapture,
  capture: Oid4vciHttpRequestCapture,
): void {
  const body = isRecord(capture.body) ? capture.body : {};
  session.raw ??= {};
  if (capture.path.endsWith("/par")) {
    session.raw.par_request = body;
    setObservedString(session.observed.client_id, body.client_id, `${capture.path}.body.client_id`);
    setObservedString(
      session.observed.redirect_uri,
      body.redirect_uri,
      `${capture.path}.body.redirect_uri`,
    );
    session.checks.pkce_present =
      typeof body.code_challenge === "string" && body.code_challenge_method === "S256";
    session.checks.state_present = typeof body.state === "string";
    session.checks.issuer_state_present = typeof body.issuer_state === "string";
  }
  if (capture.path.endsWith("/token")) {
    session.raw.token_request = body;
  }
}

export function setObservedString(
  observed: SessionCapture["observed"]["client_id"],
  value: unknown,
  source: string,
): void {
  if (typeof value !== "string" || value.length === 0) return;
  if (observed.value && observed.value !== value) {
    observed.also_seen_in ??= [];
    observed.also_seen_in.push(source);
    return;
  }
  observed.value = value;
  observed.source ??= source;
}

export function redactCredentialRequest(request: JsonRecord): JsonRecord {
  const redacted = structuredClone(request);
  const proofs = redacted.proofs as JsonRecord | undefined;
  if (proofs) {
    for (const proofType of Object.keys(proofs)) {
      proofs[proofType] = { redacted: true, present: true };
    }
  }
  if (redacted.proof !== undefined) {
    redacted.proof = { redacted: true, present: true };
  }
  return redacted;
}
