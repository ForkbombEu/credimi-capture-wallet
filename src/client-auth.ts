import type { ClientAuthenticationCapture, JsonRecord, JwtCapture } from "./types.js";

export const PRIVATE_KEY_JWT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface ClientAuthenticationInput {
  params: JsonRecord;
  oauthClientAttestation: string | undefined;
  oauthClientAttestationPop: string | undefined;
  issuerBaseUrl: string;
}

export function captureClientAuthentication(
  input: ClientAuthenticationInput,
): ClientAuthenticationCapture {
  const privateKeyJwt = capturePrivateKeyJwt(input);
  const walletAttestation = captureWalletAttestation(input);
  const walletAttestationPop = captureWalletAttestationPop(input);
  const observedMethods = [
    privateKeyJwt.present ? "private_key_jwt" : null,
    walletAttestation.present || walletAttestationPop.present ? "wallet_attestation" : null,
  ].filter((method): method is "private_key_jwt" | "wallet_attestation" => method !== null);

  return {
    method:
      observedMethods.length === 0
        ? "none"
        : observedMethods.length === 1
          ? observedMethods[0]
          : "multiple",
    private_key_jwt: privateKeyJwt,
    wallet_attestation: walletAttestation,
    wallet_attestation_pop: walletAttestationPop,
  };
}

function capturePrivateKeyJwt(
  input: ClientAuthenticationInput,
): ClientAuthenticationCapture["private_key_jwt"] {
  const assertion = asString(input.params.client_assertion);
  const assertionType = asString(input.params.client_assertion_type);
  const decoded = decodeJwt(assertion ?? undefined, "token_request.client_assertion");
  const subject = asString(decoded.claims?.sub);
  const clientId = asString(input.params.client_id);

  return {
    ...decoded,
    assertion_type: assertionType,
    assertion_type_valid: assertionType === PRIVATE_KEY_JWT_ASSERTION_TYPE,
    client_id_matches: clientId && subject ? clientId === subject : null,
    audience_matches: audienceMatches(decoded.claims?.aud, `${input.issuerBaseUrl}/token`),
  };
}

function captureWalletAttestation(
  input: ClientAuthenticationInput,
): ClientAuthenticationCapture["wallet_attestation"] {
  const decoded = decodeJwt(
    input.oauthClientAttestation,
    "token_request.headers.oauth_client_attestation",
  );
  const subject = asString(decoded.claims?.sub);
  const clientId = asString(input.params.client_id);
  const cnf = asRecord(decoded.claims?.cnf);

  return {
    ...decoded,
    cnf_jwk: asRecord(cnf?.jwk) ?? null,
    client_id_matches: clientId && subject ? clientId === subject : null,
  };
}

function captureWalletAttestationPop(
  input: ClientAuthenticationInput,
): ClientAuthenticationCapture["wallet_attestation_pop"] {
  const decoded = decodeJwt(
    input.oauthClientAttestationPop,
    "token_request.headers.oauth_client_attestation_pop",
  );

  return {
    ...decoded,
    audience_matches: audienceMatches(decoded.claims?.aud, input.issuerBaseUrl),
    challenge: asString(decoded.claims?.challenge) ?? null,
  };
}

function decodeJwt(jwt: string | undefined, source: string): JwtCapture {
  if (!jwt) return { present: false, source: null, header: null, claims: null, error: null };
  const parts = jwt.split(".");
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    return { present: true, source, header: null, claims: null, error: "jwt_malformed" };
  }

  try {
    return {
      present: true,
      source,
      header: decodePart(parts[0]),
      claims: decodePart(parts[1]),
      error: null,
    };
  } catch (error) {
    return {
      present: true,
      source,
      header: null,
      claims: null,
      error: error instanceof Error ? error.message : "jwt_decode_failed",
    };
  }
}

function decodePart(part: string): JsonRecord {
  const decoded = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("jwt_part_not_object");
  }
  return decoded as JsonRecord;
}

function audienceMatches(audience: unknown, expected: string): boolean | null {
  if (typeof audience === "string") return audience === expected;
  if (Array.isArray(audience)) return audience.some((entry) => entry === expected);
  return null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function asRecord(value: unknown): JsonRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as JsonRecord;
}
