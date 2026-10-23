import { rawHeaderValues } from "./oid4vci-capture.js";
import { decodeJwtForEvidence } from "./proofs.js";
import type { JsonRecord, JwtCapture, Oid4vciHttpRequestCapture, SessionCapture } from "./types.js";

const CLIENT_ATTESTATION_HEADER = "oauth-client-attestation";
const CLIENT_ATTESTATION_POP_HEADER = "oauth-client-attestation-pop";

/**
 * Records the OAuth 2.0 Attestation-Based Client Authentication headers of one request in
 * `observed.client_authentication`. Decoding only: whether the signatures verify, the algorithms
 * are acceptable, or the claims conform is left to the consumer, which has the compact values in a
 * `full` session's `raw.oid4vci_requests[].raw_headers`. Credo-TS verifies them independently.
 *
 * The first request carrying either header is recorded, as for the other observed values; every
 * later request keeps its own `header_counts` and, in `full` evidence, its raw headers. When a
 * header is repeated, the first value is decoded and `header_counts` shows the repetition.
 */
export function recordClientAuthentication(
  session: SessionCapture,
  capture: Oid4vciHttpRequestCapture,
): void {
  const attestations = rawHeaderValues(capture, CLIENT_ATTESTATION_HEADER);
  const pops = rawHeaderValues(capture, CLIENT_ATTESTATION_POP_HEADER);
  if (attestations.length === 0 && pops.length === 0) return;
  const clientAuthentication = session.observed.client_authentication;
  if (clientAuthentication.method !== "none") return;

  const clientId = requestClientId(capture);
  const attestation = jwtCapture(
    attestations,
    `${capture.path}.headers.${CLIENT_ATTESTATION_HEADER}`,
  );
  const pop = jwtCapture(pops, `${capture.path}.headers.${CLIENT_ATTESTATION_POP_HEADER}`);
  const cnf = asRecord(attestation.claims?.cnf);
  const walletAttestation = {
    ...attestation,
    cnf_jwk: asRecord(cnf?.jwk) ?? null,
    client_id_matches:
      attestation.claims && clientId !== null ? attestation.claims.sub === clientId : null,
  };
  const walletAttestationPop = {
    ...pop,
    audience_matches: pop.claims
      ? audienceIncludes(pop.claims.aud, session.authorization_server_identifier)
      : null,
    challenge: typeof pop.claims?.challenge === "string" ? pop.claims.challenge : null,
  };

  clientAuthentication.method = "wallet_attestation";
  clientAuthentication.wallet_attestation = walletAttestation;
  clientAuthentication.wallet_attestation_pop = walletAttestationPop;
  session.checks.wallet_attestation_present = walletAttestation.present;
  session.checks.wallet_attestation_pop_present = walletAttestationPop.present;
  session.checks.wallet_attestation_client_id_matches = walletAttestation.client_id_matches;
  session.checks.wallet_attestation_pop_audience_matches = walletAttestationPop.audience_matches;
}

function jwtCapture(values: string[], source: string): JwtCapture {
  const [value] = values;
  if (value === undefined) {
    return { present: false, source: null, header: null, claims: null, error: null };
  }
  const decoded = decodeJwtForEvidence(value);
  return {
    present: true,
    source: values.length > 1 ? `${source}[0]` : source,
    header: decoded.header,
    claims: decoded.payload,
    error: decoded.error,
  };
}

/** The `client_id` the request itself states, from its body or, for a GET, its query. */
function requestClientId(capture: Oid4vciHttpRequestCapture): string | null {
  const clientId = asRecord(capture.body)?.client_id ?? asRecord(capture.query)?.client_id;
  return typeof clientId === "string" ? clientId : null;
}

function audienceIncludes(audience: unknown, expected: string): boolean {
  if (typeof audience === "string") return audience === expected;
  return Array.isArray(audience) && audience.includes(expected);
}

function asRecord(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}
