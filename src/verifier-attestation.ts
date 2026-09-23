import { readFileSync } from "node:fs";
import { type JWK, SignJWT, importJWK } from "jose";
import {
  VERIFIER_ATTESTATION_ISSUER_KEY_ID,
  verifierAttestationIssuer,
  verifierAttestationIssuerPrivateJwkPath,
  verifierAttestationSubject,
  verifierJwksPath,
} from "./config.js";
import { corruptJwsSignature } from "./request-behavior.js";
import type { AppConfig, JsonRecord, VpVerifierAttestation } from "./types.js";

/** Section 5.10: the attestation is short-lived, since a wallet checks it at request time. */
const ATTESTATION_LIFETIME_SECONDS = 300;

/**
 * Builds the Verifier Attestation JWT that travels in the `jwt` JOSE header of a Request Object
 * signed under the `verifier_attestation` Client Identifier Prefix.
 *
 * The attestation binds three things a wallet checks separately, and each is individually
 * controllable so that a test can break exactly one: `sub` must equal the Client Identifier after
 * the prefix, `cnf.jwk` must be the key that signed the Request Object, and `iss` must name an
 * attestation issuer the wallet trusts. `redirect_uris` is omitted unless asked for, which is the
 * case where a wallet must not enforce a redirect URI match.
 */
export async function createVerifierAttestation(
  config: AppConfig,
  attestation: VpVerifierAttestation | undefined,
): Promise<string> {
  const issued = Math.floor(Date.now() / 1000);
  const payload: JsonRecord = {
    iss: attestation?.issuer ?? verifierAttestationIssuer(config),
    sub: attestation?.subject ?? verifierAttestationSubject(config),
    iat: issued,
    exp: issued + ATTESTATION_LIFETIME_SECONDS,
    cnf: { jwk: verifierRequestSigningPublicJwk(config) },
    ...(attestation?.redirect_uris ? { redirect_uris: attestation.redirect_uris } : {}),
    ...(attestation?.claims ?? {}),
  };
  const privateJwk = JSON.parse(
    readFileSync(verifierAttestationIssuerPrivateJwkPath(config.data_dir), "utf8"),
  ) as JWK;
  const signed = await new SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: "verifier-attestation+jwt",
      kid: VERIFIER_ATTESTATION_ISSUER_KEY_ID,
    })
    .sign(await importJWK(privateJwk, "ES256"));
  return attestation?.signature === "corrupt" ? corruptJwsSignature(signed) : signed;
}

export function verifierAttestationClientId(
  config: AppConfig,
  attestation: VpVerifierAttestation | undefined,
): string {
  // The Client Identifier keeps the real subject even when the attestation carries a different
  // one: the mismatch between the two is the defect under test, not a different verifier identity.
  return `verifier_attestation:${verifierAttestationSubject(config)}`;
}

/** The public half of the request signing key, which the attestation confirms in `cnf`. */
function verifierRequestSigningPublicJwk(config: AppConfig): JsonRecord {
  const jwks = JSON.parse(readFileSync(verifierJwksPath(config.data_dir), "utf8")) as {
    keys: JsonRecord[];
  };
  const key = jwks.keys[0];
  if (!key) throw new Error("verifier JWKS contains no request signing key");
  return key;
}
