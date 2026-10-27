import { type AgentContext, Kms, injectable } from "@credo-ts/core";
import {
  type OpenId4VcIssuanceSessionRecord,
  OpenId4VcIssuerService,
  getOid4vcCallbacks,
} from "@credo-ts/openid4vc";
import { Openid4vciIssuer } from "@openid4vc/openid4vci";
import { decodeJwtForEvidence } from "./proofs.js";
import type { JsonRecord } from "./types.js";

/**
 * Adds the EUDI TS3 JWT PoP signer rule to Credo's OpenID4VCI issuer. TS3 §2.2.2 requires the
 * outer proof to be signed by attested_keys[0], and permits the proof header to omit jwk and kid.
 */
@injectable()
export class EudiKeyAttestationIssuerService extends OpenId4VcIssuerService {
  public override getIssuer(
    agentContext: AgentContext,
    options: { issuanceSession?: OpenId4VcIssuanceSessionRecord } = {},
  ): Openid4vciIssuer {
    const callbacks = getOid4vcCallbacks(agentContext, options);
    const verifyJwt = callbacks.verifyJwt;
    callbacks.verifyJwt = async (signer, jwt) => {
      if (signer.method === "custom") {
        const publicJwk = firstEudiAttestedKey(jwt.header);
        if (publicJwk) {
          // Credo returns this original signer to its holder-binding checks after verification.
          // Updating it lets Credo verify the JWS now and the key attestation immediately after.
          Object.assign(signer, { method: "jwk", publicJwk });
        }
      }
      return verifyJwt(signer, jwt);
    };
    return new Openid4vciIssuer({ callbacks });
  }
}

function firstEudiAttestedKey(header: JsonRecord): JsonRecord | null {
  if (header.typ !== "openid4vci-proof+jwt" || typeof header.key_attestation !== "string") {
    return null;
  }
  const { payload } = decodeJwtForEvidence(header.key_attestation);
  const attestedKeys = payload?.attested_keys;
  if (!Array.isArray(attestedKeys)) return null;
  try {
    return Kms.PublicJwk.fromUnknown(attestedKeys[0]).toJson() as JsonRecord;
  } catch {
    return null;
  }
}
