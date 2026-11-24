import type { NextFunction, Request, Response } from "express";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import { credentialRegistry } from "../credentials/registry.js";
import {
  CredentialEncryptionError,
  type CredentialResponseEncryption,
  credentialResponseEncryption,
  decryptCredentialRequest,
  encryptCredentialResponse,
} from "../openid4vci/credential-encryption.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import { redactOid4vciValue } from "../openid4vci/http-capture.js";
import {
  credentialRequestProofNonces,
  credentialRequestProofsCapture,
} from "../openid4vci/proofs.js";
import type { CaptureStore } from "../state.js";
import type { AppConfig, JsonRecord, Oid4vciHttpRequestCapture, SessionCapture } from "../types.js";

export type CredentialRequestBody = {
  body: JsonRecord;
  encryptedRequest: boolean;
  responseEncryption: CredentialResponseEncryption | null;
};

export async function readCredentialRequestBody(
  req: Request,
  issuerConfig: AppConfig,
): Promise<CredentialRequestBody> {
  const encryptedRequest = req.is("application/jwt") === "application/jwt";
  let body: JsonRecord;
  if (encryptedRequest) {
    if (typeof req.body !== "string" || !req.body) {
      throw new CredentialEncryptionError(
        "Encrypted Credential Request body must be a compact JWE",
      );
    }
    body = await decryptCredentialRequest(issuerConfig, req.body);
  } else {
    body = { ...(req.body as JsonRecord) };
  }
  const responseEncryption = credentialResponseEncryption(body);
  if (responseEncryption && !encryptedRequest) {
    throw new CredentialEncryptionError(
      "credential_response_encryption requires an encrypted Credential Request",
    );
  }
  return { body, encryptedRequest, responseEncryption };
}

export function recordCredentialRequestEvidence(
  capture: Oid4vciHttpRequestCapture | null,
  store: CaptureStore,
  issuer: ResolvedIssuerConfiguration,
  body: JsonRecord,
): void {
  if (!capture) return;
  capture.body = redactOid4vciValue(body);
  const fullCapture = store.fullOid4vciRequests.get(capture);
  if (fullCapture) fullCapture.body = redactOid4vciValue(body, undefined, "full");
  // Recorded before Credo-TS verifies the proofs, so a rejected proof leaves evidence too.
  // The proof nonces also attribute the Nonce Endpoint responses that issued them, since the
  // Nonce Endpoint itself takes no session context.
  const session = capture.session_id ? store.getSession(capture.session_id) : undefined;
  if (session) {
    const proofs = credentialRequestProofsCapture(capture, body);
    store.linkNonceResponses(session.session_id, issuer.id, credentialRequestProofNonces(proofs));
    if (session.evidence_mode === "full") {
      session.raw ??= {};
      session.raw.credential_request_proofs = proofs;
    }
  }
}

export function pinnedDefinitionMismatch(
  config: AppConfig,
  store: CaptureStore,
  issuer: ResolvedIssuerConfiguration,
  session: SessionCapture | undefined,
): string | null {
  const pinned = session?.credential_definition;
  if (!session || !pinned) return null;
  // An imported credential keeps its configuration id across rulebook versions. A session
  // created under a version that has since been replaced is refused rather than issued under a
  // definition the Wallet was not offered (OpenID4VCI 1.0 Section 8.3.1.2).
  const active = credentialRegistry(config, store).credentialById(
    issuer,
    session.credential_configuration_id,
  )?.attestbook;
  if (active?.contentDigest === pinned.content_digest) return null;
  store.addEvent(session, "credential_definition_superseded", {
    pinned_version: pinned.version,
    active_version: active?.version ?? null,
  });
  return pinned.version;
}

export async function forwardCredentialRequest(
  config: AppConfig,
  store: CaptureStore,
  req: Request,
  res: Response,
  credentialEndpointNext: NextFunction,
  capture: Oid4vciHttpRequestCapture | null,
  body: JsonRecord,
  credentialRequestRaw: Oid4vciHttpRequestCapture["body"],
): Promise<void> {
  const { credential_response_encryption: _credentialResponseEncryption, ...credoBody } = body;
  req.body = credoBody;
  req.headers["content-type"] = "application/json";
  return await (await credoOpenId4VciIssuer(config, store)).forward(
    req,
    res,
    credentialEndpointNext,
    capture,
    {
      body,
      raw: credentialRequestRaw,
    },
  );
}

export function interceptCredentialResponse(
  res: Response,
  next: NextFunction,
  issuerConfig: AppConfig,
  responseEncryption: CredentialResponseEncryption,
): { isPending: () => boolean } {
  const send = res.send.bind(res);
  let pending = false;
  let settled = false;
  res.send = ((responseBody: unknown) => {
    if (pending || settled) return res;
    // OpenID4VCI 1.0 Section 8.3.1: Credential Error Responses are never encrypted, even when a
    // valid Credential Response would have been.
    if (res.statusCode < 200 || res.statusCode >= 300) {
      settled = true;
      res.send = send;
      return send(responseBody);
    }
    const serialized =
      typeof responseBody === "string"
        ? responseBody
        : Buffer.isBuffer(responseBody)
          ? responseBody.toString("utf8")
          : JSON.stringify(responseBody);
    let json: JsonRecord;
    try {
      json = JSON.parse(serialized) as JsonRecord;
    } catch {
      settled = true;
      res.send = send;
      return send(responseBody);
    }

    const statusCode = res.statusCode;
    pending = true;
    void encryptCredentialResponse(issuerConfig, responseEncryption, json)
      .then((jwe) => {
        pending = false;
        settled = true;
        res.send = send;
        res.status(statusCode);
        res.setHeader("Content-Type", "application/jwt");
        send(jwe);
      })
      .catch((error: unknown) => {
        pending = false;
        settled = true;
        res.send = send;
        next(error);
      });
    return res;
  }) as typeof res.send;
  return { isPending: () => pending };
}
