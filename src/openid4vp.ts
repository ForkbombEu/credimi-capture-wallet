import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { X509Certificate } from "@credo-ts/core";
import { type JWK, SignJWT, importJWK } from "jose";
import {
  VERIFIER_DID_KEY_ID,
  VERIFIER_KEY_ID,
  verifierAttestationSubject,
  verifierCertificatePath,
  verifierDid,
  verifierDidPrivateJwkPath,
  verifierPrivateJwkPath,
} from "./config.js";
import { PID_MDOC_DOCTYPE, PID_SD_JWT_VCT } from "./credential-definitions.js";
import {
  type SupportedCredential,
  supportedCredentialById,
  supportedCredentials,
} from "./metadata.js";
import { x509HashClientId } from "./request-certificates.js";
import { applyRequestMutationEdits } from "./request-mutation.js";
import type {
  AppConfig,
  JsonRecord,
  OpenId4VpResponseMode,
  RequestSigningMaterial,
  VpRequestMutationEdits,
} from "./types.js";

/**
 * How long a DC API session stays presentable. The browser invocation is user-driven and cannot be
 * correlated by `state`, so the window is bounded here rather than left open until process exit.
 */
export const DC_API_PRESENTATION_TTL_SECONDS = 600;

export type { OpenId4VpResponseMode } from "./types.js";
export type OpenId4VpClientIdScheme =
  | "x509_hash"
  | "x509_san_dns"
  | "redirect_uri"
  | "decentralized_identifier"
  | "verifier_attestation";

/** The signer a session's Request Object was created with, reused whenever it is re-signed. */
export interface VpRequestSigner {
  clientIdScheme: Exclude<OpenId4VpClientIdScheme, "redirect_uri">;
  verifierAttestationJwt?: string;
}

/**
 * How the wallet-facing Authorization Request is derived from the verifier's own request, kept
 * per session so that a `wallet_nonce` re-sign reproduces the original delivery exactly.
 */
export interface VpDeliveredRequestRecipe {
  /** Absent when the request is delivered unsigned. */
  signer?: VpRequestSigner;
  /** A Section 5.1 scope-based request: the verifier keeps its query, the wallet never sees it. */
  omitDcqlQuery: boolean;
  /** Replaces any mutated `client_id`: the attested subject, or a fixture chain's `x509_hash`. */
  clientId?: string;
}

/**
 * The wallet-facing copy of `request`. Mutation edits apply first, so a scenario can also replace
 * a value the verifier set, such as an echoed `wallet_nonce`; the recipe's own adjustments apply
 * last because they define the scenario's single intended defect.
 */
export function deliveredAuthorizationRequest(
  request: JsonRecord,
  recipe: VpDeliveredRequestRecipe,
  requestObjectEdits?: VpRequestMutationEdits,
): JsonRecord {
  const delivered = applyRequestMutationEdits(request, requestObjectEdits);
  if (recipe.omitDcqlQuery) delivered.dcql_query = undefined;
  if (recipe.clientId !== undefined) delivered.client_id = recipe.clientId;
  return delivered;
}

/** Exhaustive over the union, so adding a response mode without handling it fails to compile. */
const OPENID4VP_RESPONSE_MODES: Record<OpenId4VpResponseMode, true> = {
  direct_post: true,
  "direct_post.jwt": true,
  dc_api: true,
  "dc_api.jwt": true,
};

export function isOpenId4VpResponseMode(value: unknown): value is OpenId4VpResponseMode {
  return typeof value === "string" && Object.hasOwn(OPENID4VP_RESPONSE_MODES, value);
}

export const OPENID4VP_RESPONSE_MODE_VALUES = Object.keys(
  OPENID4VP_RESPONSE_MODES,
) as OpenId4VpResponseMode[];

/** Whether the request is delivered through the W3C Digital Credentials API instead of a redirect. */
export function isDcApiResponseMode(mode: OpenId4VpResponseMode): boolean {
  return mode === "dc_api" || mode === "dc_api.jwt";
}

/** Whether the wallet returns the Authorization Response encrypted in a `response` JWE. */
export function isEncryptedResponseMode(mode: OpenId4VpResponseMode): boolean {
  return mode === "direct_post.jwt" || mode === "dc_api.jwt";
}

/**
 * Origin the wallet binds a DC API presentation to. Derived from trusted configuration: the
 * presentation page is served from it and a request Host header is never used.
 */
export function verifierOrigin(config: AppConfig): string {
  return new URL(config.public_base_url).origin;
}

export function dcApiPresentationUrl(config: AppConfig, sessionId: string): string {
  const base = config.public_base_url.replace(/\/+$/, "");
  return `${base}/ui/openid4vp/sessions/${encodeURIComponent(sessionId)}/dc_api_presentation`;
}

export function dcApiPresentationExpiresAt(from: Date = new Date()): string {
  return new Date(from.getTime() + DC_API_PRESENTATION_TTL_SECONDS * 1000).toISOString();
}

export function defaultPresentationRequest(
  config: AppConfig,
  credentialConfigurationIds?: string[],
  responseMode: OpenId4VpResponseMode = "direct_post.jwt",
): JsonRecord {
  const credentials = selectedSupportedCredentials(config, credentialConfigurationIds);
  return {
    response_type: "vp_token",
    response_mode: responseMode,
    nonce: randomUUID(),
    dcql_query: defaultDcqlQuery(credentials),
  };
}

/**
 * Signs the Request Object.
 *
 * `headerEdits` deliberately alters the JOSE header for an FCAF scenario — a missing or wrong
 * `typ`, for instance — and is applied after the normal header is built, so a scenario cannot
 * accidentally change the algorithm selection. `material` replaces the signing key, and its
 * certificate chain when it carries one, which is how a request signed by the wrong key or
 * presenting an untrusted chain is produced without a second signing implementation.
 */
export async function signPresentationAuthorizationRequest(
  config: AppConfig,
  request: JsonRecord,
  clientIdScheme: Exclude<OpenId4VpClientIdScheme, "redirect_uri"> = "x509_hash",
  options: {
    headerEdits?: VpRequestMutationEdits;
    material?: RequestSigningMaterial;
    verifierAttestationJwt?: string;
  } = {},
): Promise<string> {
  const isDid = clientIdScheme === "decentralized_identifier";
  const isVerifierAttestation = clientIdScheme === "verifier_attestation";
  const privateJwk = (options.material?.privateJwk ??
    JSON.parse(
      readFileSync(
        isDid
          ? verifierDidPrivateJwkPath(config.data_dir)
          : verifierPrivateJwkPath(config.data_dir),
        "utf8",
      ),
    )) as JWK;
  const key = await importJWK(privateJwk, "ES256");
  const header = applyRequestMutationEdits(
    {
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      ...(isDid ? { kid: `${verifierDid(config)}#${VERIFIER_DID_KEY_ID}` } : {}),
      // Section 5.10 carries the attestation in the `jwt` header, and the key it confirms is the
      // one that signs the request, so no certificate or key identifier is published beside it.
      ...(isVerifierAttestation ? { jwt: options.verifierAttestationJwt } : {}),
      ...(isDid || isVerifierAttestation
        ? {}
        : {
            kid: VERIFIER_KEY_ID,
            x5c: options.material?.x5c ?? [verifierCertificateBase64Der(config)],
          }),
    } as JsonRecord,
    options.headerEdits,
  );
  return new SignJWT(request).setProtectedHeader(header as never).sign(key);
}

/**
 * The Client Identifier this verifier presents under each prefix it supports. A caller that signs
 * its own `verifier_info` attestation has to bind it to the Client Identifier, and learning that
 * value should not require creating a throwaway session first.
 */
export function verifierClientIdentifiers(config: AppConfig): JsonRecord {
  const certificate = X509Certificate.fromEncodedCertificate(verifierCertificateBase64Der(config));
  const dnsName = certificate.sanDnsNames[0];
  return {
    x509_hash: x509HashClientId(verifierCertificateBase64Der(config)),
    ...(dnsName === undefined ? {} : { x509_san_dns: `x509_san_dns:${dnsName}` }),
    decentralized_identifier: `decentralized_identifier:${verifierDid(config)}`,
    verifier_attestation: `verifier_attestation:${verifierAttestationSubject(config)}`,
  };
}

export function verifierCertificateBase64Der(config: AppConfig): string {
  return readFileSync(verifierCertificatePath(config.data_dir), "utf8")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

export function vpRequestUri(config: AppConfig, sessionId: string): string {
  return `${config.issuer_base_url}/openid4vp/sessions/${sessionId}/request`;
}

/** The DCQL query requesting every listed credential with all of its claims. */
export function defaultDcqlQuery(credentials: readonly SupportedCredential[]): JsonRecord {
  return {
    credentials: credentials.map((credential) => ({
      id: dcqlCredentialId(credential.id),
      format: credential.format,
      meta:
        credential.format === "mso_mdoc"
          ? { doctype_value: PID_MDOC_DOCTYPE }
          : { vct_values: [credential.vct ?? PID_SD_JWT_VCT] },
      claims: credential.claimPaths.map((path) => ({ path: [...path] })),
    })),
  };
}

function selectedSupportedCredentials(
  config: AppConfig,
  credentialConfigurationIds: string[] | undefined,
): SupportedCredential[] {
  if (!credentialConfigurationIds || credentialConfigurationIds.length === 0) {
    return supportedCredentials(config).filter(
      (credential, index, credentials) =>
        credentials.findIndex((candidate) => candidate.format === credential.format) === index,
    );
  }
  return credentialConfigurationIds
    .map((credentialConfigurationId) => supportedCredentialById(config, credentialConfigurationId))
    .filter((credential): credential is SupportedCredential => credential !== null);
}

function dcqlCredentialId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
}
