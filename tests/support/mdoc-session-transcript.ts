import { createHash } from "node:crypto";
import { type MdocContext, SessionTranscript } from "@owf/mdoc";
import { type JWK, calculateJwkThumbprint } from "jose";
import {
  isDcApiResponseMode,
  isEncryptedResponseMode,
  isOpenId4VpResponseMode,
} from "../../src/openid4vp.js";
import type { JsonRecord } from "../../src/types.js";

/**
 * Appendix B.2.6: a redirect exchange uses the `OpenID4VPHandover`, a DC API exchange the
 * `OpenID4VPDCAPIHandover` over the bare browser origin — unprefixed, unlike the presentation
 * audience — the request nonce, and the response-encryption key thumbprint, which is absent for
 * the unencrypted `dc_api` response mode.
 */
export async function mdocSessionTranscript(
  authorizationRequest: JsonRecord,
  context: Pick<MdocContext, "crypto"> = mdocVerificationContext(),
  origin?: string,
): Promise<SessionTranscript> {
  const nonce = asString(authorizationRequest.nonce) ?? "";
  const jwkThumbprint = await oid4vpJwkThumbprint(authorizationRequest);
  const responseMode = authorizationRequest.response_mode;
  if (isOpenId4VpResponseMode(responseMode) && isDcApiResponseMode(responseMode)) {
    const dcApiOrigin =
      origin ?? asString(asArray(authorizationRequest.expected_origins)[0]) ?? null;
    if (!dcApiOrigin) {
      throw new Error("DC API mdoc session transcript requires the browser origin");
    }
    return SessionTranscript.forOid4VpDcApi(
      {
        origin: dcApiOrigin,
        nonce,
        ...(jwkThumbprint ? { jwkThumbprint } : {}),
      },
      context,
    );
  }
  return SessionTranscript.forOid4Vp(
    {
      clientId: asString(authorizationRequest.client_id) ?? "",
      nonce,
      responseUri: asString(authorizationRequest.response_uri) ?? "",
      ...(jwkThumbprint ? { jwkThumbprint } : {}),
    },
    context,
  );
}

async function oid4vpJwkThumbprint(authorizationRequest: JsonRecord): Promise<Uint8Array | null> {
  const responseMode = authorizationRequest.response_mode;
  if (!isOpenId4VpResponseMode(responseMode) || !isEncryptedResponseMode(responseMode)) return null;
  const jwks = asRecord(asRecord(authorizationRequest.client_metadata)?.jwks);
  const encryptionJwk = asArray(jwks?.keys)
    .filter(isRecord)
    .find((key) => key.use === "enc");
  if (!encryptionJwk) return null;
  const thumbprint = await calculateJwkThumbprint(encryptionJwk as unknown as JWK, "sha256");
  return Buffer.from(thumbprint, "base64url");
}

function mdocVerificationContext(): Pick<MdocContext, "crypto"> {
  return {
    crypto: {
      random: (length) => Buffer.alloc(length),
      digest: ({ digestAlgorithm, bytes }) => {
        if (digestAlgorithm !== "SHA-256") {
          throw new Error(`unsupported mdoc digest algorithm '${digestAlgorithm}'`);
        }
        return createHash("sha256").update(bytes).digest();
      },
      hdkf: () => {
        throw new Error("mdoc HKDF is not supported");
      },
    },
  };
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asRecord(value: unknown): JsonRecord | null {
  return isRecord(value) ? value : null;
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}
