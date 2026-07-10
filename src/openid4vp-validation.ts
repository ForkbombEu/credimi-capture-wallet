import {
  type JsonWebKey as NodeJsonWebKey,
  X509Certificate,
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from "node:crypto";
import { Kms, SdJwtVcService, X509ModuleConfig } from "@credo-ts/core";
import {
  CoseKey,
  DeviceResponse,
  type IssuerSigned,
  type MdocContext,
  SessionTranscript,
  Verifier,
} from "@owf/mdoc";
import {
  type DcqlCredentialPresentation,
  DcqlPresentationResult,
  DcqlQuery,
  type DcqlQuery as ParsedDcqlQuery,
} from "dcql";
import { type JWK, compactDecrypt, decodeJwt, importJWK } from "jose";
import type { AppConfig, JsonRecord, VpSessionCapture } from "./types.js";

interface VpPresentationValidation {
  valid: boolean;
  vp_token_format_valid: boolean;
  nonce_verified: boolean;
  holder_binding_verified: boolean;
  dcql_query_matched: boolean;
  authorization_response?: JsonRecord;
  errors: string[];
}

interface PresentationCandidate {
  queryId: string;
  query: JsonRecord;
  presentation: unknown;
}

type DcqlPresentationRecord = Record<string, DcqlCredentialPresentation[]>;

export async function validateVpPresentationResponse(
  config: AppConfig,
  session: VpSessionCapture,
  body: JsonRecord,
  jarmPrivateJwk?: JsonRecord,
): Promise<VpPresentationValidation> {
  const result: VpPresentationValidation = {
    valid: false,
    vp_token_format_valid: false,
    nonce_verified: false,
    holder_binding_verified: false,
    dcql_query_matched: false,
    errors: [],
  };

  try {
    const dcqlQuery = parseDcqlQuery(session.authorization_request.dcql_query);
    const authorizationResponse = await normalizeAuthorizationResponse(
      session,
      body,
      jarmPrivateJwk,
    );
    result.authorization_response = authorizationResponse;
    const vpToken = parseVpToken(authorizationResponse.vp_token);
    const candidates = presentationCandidates(dcqlQuery, vpToken);
    result.vp_token_format_valid = true;

    if (candidates.length === 0) {
      result.errors.push("vp_token does not contain presentations for the requested DCQL queries");
      return result;
    }

    const validations = await Promise.all(
      candidates.map((candidate) => validatePresentation(config, session, candidate)),
    );
    result.nonce_verified = validations.every((validation) => validation.nonceVerified);
    result.holder_binding_verified = validations.every(
      (validation) => validation.holderBindingVerified,
    );
    const dcqlValidation = validateDcqlPresentation(
      dcqlQuery,
      dcqlPresentationRecord(candidates, validations),
    );
    result.dcql_query_matched = dcqlValidation.matched;
    result.errors.push(...validations.flatMap((validation) => validation.errors));
    if (!dcqlValidation.matched) result.errors.push(...dcqlValidation.errors);
    result.valid =
      result.vp_token_format_valid &&
      result.nonce_verified &&
      result.holder_binding_verified &&
      result.dcql_query_matched &&
      result.errors.length === 0;
    return result;
  } catch (error) {
    result.errors.push(errorMessage(error));
    return result;
  }
}

async function validatePresentation(
  config: AppConfig,
  session: VpSessionCapture,
  candidate: PresentationCandidate,
): Promise<{
  nonceVerified: boolean;
  holderBindingVerified: boolean;
  dcqlPresentations: DcqlCredentialPresentation[];
  errors: string[];
}> {
  const format = asString(candidate.query.format);
  if (format === "dc+sd-jwt") {
    return validateSdJwtPresentation(config, session, candidate);
  }
  if (format === "mso_mdoc") {
    return validateMdocPresentation(session, candidate);
  }
  return {
    nonceVerified: false,
    holderBindingVerified: false,
    dcqlPresentations: [],
    errors: [`unsupported DCQL credential format '${format ?? "unknown"}'`],
  };
}

async function validateSdJwtPresentation(
  config: AppConfig,
  session: VpSessionCapture,
  candidate: PresentationCandidate,
): Promise<{
  nonceVerified: boolean;
  holderBindingVerified: boolean;
  dcqlPresentations: DcqlCredentialPresentation[];
  errors: string[];
}> {
  const errors: string[] = [];
  const presentation = asString(candidate.presentation);
  if (!presentation) {
    return {
      nonceVerified: false,
      holderBindingVerified: false,
      dcqlPresentations: [],
      errors: ["SD-JWT VC presentation must be a compact string"],
    };
  }

  let claims: JsonRecord | null = null;
  let nonceVerified = false;
  let holderBindingVerified = false;

  try {
    const verified = await new SdJwtVcService({} as never).verify(
      credoVerificationContext() as never,
      {
        compactSdJwtVc: presentation,
        keyBinding: {
          audience: String(session.authorization_request.client_id),
          nonce: String(session.authorization_request.nonce),
        },
      },
    );
    if (verified.isValid) {
      claims = verified.sdJwtVc.prettyClaims as JsonRecord;
      nonceVerified = verified.sdJwtVc.kbJwt?.payload.nonce === session.authorization_request.nonce;
      holderBindingVerified = true;
    } else {
      claims = (verified.sdJwtVc?.prettyClaims as JsonRecord | undefined) ?? null;
      errors.push(`SD-JWT VC verification failed: ${errorMessage(verified.error)}`);
    }
  } catch (error) {
    errors.push(`SD-JWT VC verification failed: ${errorMessage(error)}`);
  }

  const vct = claims ? asString(claims.vct) : null;
  const dcqlPresentations =
    claims && vct
      ? [
          {
            credential_format: "dc+sd-jwt",
            vct,
            claims: claims as never,
            cryptographic_holder_binding: holderBindingVerified,
          } satisfies DcqlCredentialPresentation,
        ]
      : [];

  return { nonceVerified, holderBindingVerified, dcqlPresentations, errors };
}

async function normalizeAuthorizationResponse(
  session: VpSessionCapture,
  body: JsonRecord,
  jarmPrivateJwk: JsonRecord | undefined,
): Promise<JsonRecord> {
  if (session.response_mode !== "direct_post.jwt") return body;
  const response = asString(body.response);
  if (!response) throw new Error("direct_post.jwt response must contain a response JWE");
  if (!jarmPrivateJwk) throw new Error("missing verifier JARM decryption key for session");
  const { plaintext } = await compactDecrypt(
    response,
    await importJWK(jarmPrivateJwk as unknown as JWK, "ECDH-ES"),
  );
  const decoded = Buffer.from(plaintext).toString("utf8");
  if (decoded.includes(".") && decoded.split(".").length === 3) {
    return decodeJwt(decoded) as JsonRecord;
  }
  const parsed = JSON.parse(decoded) as unknown;
  if (!isRecord(parsed))
    throw new Error("direct_post.jwt response did not decrypt to a JSON object");
  return parsed;
}

function credoVerificationContext(): object {
  const kms = {
    randomBytes: ({ length }: { length: number }) => randomBytes(length),
    supportedBackendsForOperation: () => ["fake-issuer-verifier"],
    verify: async ({
      key,
      algorithm,
      data,
      signature,
    }: {
      key: { publicJwk?: JsonRecord };
      algorithm: string;
      data: Uint8Array;
      signature: Uint8Array;
    }) => {
      const publicJwk = key.publicJwk;
      if (!publicJwk) return { verified: false };
      const verified = verifySignature(
        algorithm === "EdDSA" || algorithm === "Ed25519" ? null : "sha256",
        data,
        {
          key: createPublicKey({
            key: publicJwk as unknown as NodeJsonWebKey,
            format: "jwk",
          }),
          dsaEncoding: "ieee-p1363",
        },
        signature,
      );
      return verified ? { verified, publicJwk } : { verified };
    },
  };
  const x509Config = {
    trustedCertificates: [],
    getTrustedCertificatesForVerification: async (
      _agentContext: unknown,
      options: { certificateChain?: unknown[] },
    ) =>
      (options.certificateChain ?? [])
        .map((certificate) =>
          certificate &&
          typeof certificate === "object" &&
          "toString" in certificate &&
          typeof certificate.toString === "function"
            ? (certificate.toString as (format: string) => string)("base64")
            : null,
        )
        .filter((certificate): certificate is string => typeof certificate === "string"),
  };
  const resolve = (token: unknown) => {
    if (token === Kms.KeyManagementApi) return kms;
    if (token === X509ModuleConfig) return x509Config;
    throw new Error("Unsupported Credo dependency requested while verifying SD-JWT VC");
  };
  return {
    resolve,
    dependencyManager: { resolve },
    config: {
      allowInsecureHttpUrls: true,
      validitySkewSeconds: 300,
      agentDependencies: { fetch: globalThis.fetch },
    },
  };
}

async function validateMdocPresentation(
  session: VpSessionCapture,
  candidate: PresentationCandidate,
): Promise<{
  nonceVerified: boolean;
  holderBindingVerified: boolean;
  dcqlPresentations: DcqlCredentialPresentation[];
  errors: string[];
}> {
  const presentation = asString(candidate.presentation);
  if (!presentation) {
    return {
      nonceVerified: false,
      holderBindingVerified: false,
      dcqlPresentations: [],
      errors: ["mdoc presentation must be a base64url-encoded DeviceResponse string"],
    };
  }

  const errors: string[] = [];
  let deviceResponse: DeviceResponse;
  try {
    deviceResponse = DeviceResponse.fromEncodedForOid4Vp(presentation);
  } catch (error) {
    return {
      nonceVerified: false,
      holderBindingVerified: false,
      dcqlPresentations: [],
      errors: [`mdoc DeviceResponse parsing failed: ${errorMessage(error)}`],
    };
  }
  const context = mdocVerificationContext();
  const sessionTranscript = await mdocSessionTranscript(session.authorization_request, context);
  let verified = false;

  try {
    await Verifier.verifyDeviceResponse(
      {
        deviceResponse,
        sessionTranscript,
        disableCertificateChainValidation: true,
        trustedCertificates: [],
      },
      context,
    );
    verified = true;
  } catch (error) {
    errors.push(`mdoc DeviceResponse verification failed: ${errorMessage(error)}`);
  }

  let dcqlPresentations: DcqlCredentialPresentation[] = [];
  try {
    dcqlPresentations = (deviceResponse.documents ?? []).map(
      (document) =>
        ({
          credential_format: "mso_mdoc",
          doctype: document.docType,
          namespaces: mdocNamespaces(document.issuerSigned),
          cryptographic_holder_binding: verified,
        }) satisfies DcqlCredentialPresentation,
    );
  } catch (error) {
    errors.push(`mdoc claim extraction failed: ${errorMessage(error)}`);
  }

  return {
    nonceVerified: verified,
    holderBindingVerified: verified,
    dcqlPresentations,
    errors: verified ? errors.filter((error) => !error.startsWith("mdoc DeviceResponse")) : errors,
  };
}

export function parseDcqlQuery(value: unknown): ParsedDcqlQuery {
  const query = (DcqlQuery.parse as (input: unknown) => ParsedDcqlQuery)(value);
  DcqlQuery.validate(query);
  return query;
}

function parseVpToken(value: unknown): JsonRecord {
  if (typeof value === "string") {
    const parsed = JSON.parse(value) as unknown;
    if (isRecord(parsed)) return parsed;
  }
  if (isRecord(value)) return value;
  throw new Error("vp_token must be a JSON object or a JSON-encoded object");
}

function presentationCandidates(
  dcqlQuery: ParsedDcqlQuery,
  vpToken: JsonRecord,
): PresentationCandidate[] {
  const queries = dcqlQuery.credentials as JsonRecord[];
  const queryById = new Map(
    queries
      .map((query) => [asString(query.id), query] as const)
      .filter((entry): entry is readonly [string, JsonRecord] => Boolean(entry[0])),
  );
  const candidates: PresentationCandidate[] = [];

  for (const queryId of Object.keys(vpToken)) {
    const query = queryById.get(queryId);
    if (!query) throw new Error(`vp_token contains unknown DCQL credential '${queryId}'`);
    const entries = asArray(vpToken[queryId]);
    if (entries.length === 0) {
      throw new Error(`vp_token is missing presentation array for DCQL credential '${queryId}'`);
    }
    if (query.multiple !== true && entries.length !== 1) {
      throw new Error(`DCQL credential '${queryId}' expects exactly one presentation`);
    }
    candidates.push(...entries.map((presentation) => ({ queryId, query, presentation })));
  }

  return candidates;
}

export function mdocSessionTranscript(
  authorizationRequest: JsonRecord,
  context: Pick<MdocContext, "crypto"> = mdocVerificationContext(),
): Promise<SessionTranscript> {
  const clientId = asString(authorizationRequest.client_id) ?? "";
  const nonce = asString(authorizationRequest.nonce) ?? "";
  const responseUri = asString(authorizationRequest.response_uri) ?? "";
  return SessionTranscript.forOid4Vp({ clientId, nonce, responseUri }, context);
}

function mdocNamespaces(issuerSigned: IssuerSigned): Record<string, Record<string, unknown>> {
  const namespaces = issuerSigned.issuerNamespaces.issuerNamespaces;
  return Object.fromEntries(
    [...namespaces.keys()].map((namespace) => [
      namespace,
      issuerSigned.getPrettyClaims(namespace) ?? {},
    ]),
  );
}

function dcqlPresentationRecord(
  candidates: PresentationCandidate[],
  validations: Array<{ dcqlPresentations: DcqlCredentialPresentation[] }>,
): DcqlPresentationRecord {
  const presentations: DcqlPresentationRecord = {};
  for (const [index, candidate] of candidates.entries()) {
    const validatedPresentations = validations[index]?.dcqlPresentations ?? [];
    presentations[candidate.queryId] ??= [];
    presentations[candidate.queryId]?.push(...validatedPresentations);
  }
  return presentations;
}

function validateDcqlPresentation(
  dcqlQuery: ParsedDcqlQuery,
  presentations: DcqlPresentationRecord,
): { matched: boolean; errors: string[] } {
  try {
    const result = DcqlPresentationResult.fromDcqlPresentation(presentations, { dcqlQuery });
    if (result.can_be_satisfied) return { matched: true, errors: [] };
    return {
      matched: false,
      errors: dcqlPresentationErrors(result),
    };
  } catch (error) {
    return {
      matched: false,
      errors: [`DCQL presentation validation failed: ${errorMessage(error)}`],
    };
  }
}

function dcqlPresentationErrors(result: unknown): string[] {
  const credentialMatches = asRecord(asRecord(result)?.credential_matches);
  const errors: string[] = [];
  for (const [queryId, match] of Object.entries(credentialMatches ?? {})) {
    const matchRecord = asRecord(match);
    if (matchRecord?.success === true) continue;
    const failedCredentials = asArray(matchRecord?.failed_credentials).filter(isRecord);
    if (failedCredentials.length === 0) {
      errors.push(`DCQL credential '${queryId}' was not satisfied`);
      continue;
    }
    for (const failedCredential of failedCredentials) {
      errors.push(...dcqlFailedCredentialErrors(queryId, failedCredential));
    }
  }
  return errors.length > 0 ? errors : ["DCQL presentation does not satisfy the query"];
}

function dcqlFailedCredentialErrors(queryId: string, failedCredential: JsonRecord): string[] {
  const errors: string[] = [];
  const meta = asRecord(failedCredential.meta);
  if (meta?.success === false) {
    errors.push(`DCQL credential '${queryId}' meta did not match: ${JSON.stringify(meta.issues)}`);
  }
  const claims = asRecord(failedCredential.claims);
  for (const failedClaim of asArray(claims?.failed_claims).filter(isRecord)) {
    errors.push(
      `DCQL credential '${queryId}' claim did not match: ${JSON.stringify(failedClaim.issues)}`,
    );
  }
  for (const failedClaimSet of asArray(claims?.failed_claim_sets).filter(isRecord)) {
    errors.push(
      `DCQL credential '${queryId}' claim set did not match: ${JSON.stringify(
        failedClaimSet.issues,
      )}`,
    );
  }
  return errors.length > 0 ? errors : [`DCQL credential '${queryId}' was not satisfied`];
}

function mdocVerificationContext(): MdocContext {
  return {
    crypto: {
      random: (length) => Buffer.alloc(length),
      digest: ({ digestAlgorithm, bytes }) => {
        if (digestAlgorithm !== "SHA-256") {
          throw new Error(`unsupported mdoc digest algorithm '${digestAlgorithm}'`);
        }
        return createHash("sha256").update(bytes).digest();
      },
      calculateEphemeralMacKey: () => {
        throw new Error("mdoc DeviceMac holder binding is not supported");
      },
    },
    cose: {
      sign1: {
        sign: () => {
          throw new Error("mdoc signing is not supported by the verifier");
        },
        verify: async ({ key, sign1 }) =>
          verifySignature(
            sign1.signatureAlgorithmName === "EdDSA" ? null : "sha256",
            sign1.toBeSigned,
            {
              key: createPublicKey({
                key: key.jwk as unknown as NodeJsonWebKey,
                format: "jwk",
              }),
              dsaEncoding: "ieee-p1363",
            },
            sign1.signature,
          ),
      },
      mac0: {
        sign: () => {
          throw new Error("mdoc MAC signing is not supported by the verifier");
        },
        verify: () => {
          throw new Error("mdoc DeviceMac holder binding is not supported");
        },
      },
    },
    x509: {
      getIssuerNameField: ({ certificate, field }) => {
        const cert = new X509Certificate(certificate);
        const source = field === "issuer" ? cert.issuer : cert.subject;
        return source.split("\n");
      },
      getPublicKey: async ({ certificate }) =>
        CoseKey.fromJwk(
          new X509Certificate(certificate).publicKey.export({
            format: "jwk",
          }) as unknown as Record<string, unknown>,
        ),
      verifyCertificateChain: () => undefined,
      getCertificateData: ({ certificate }) => {
        const cert = new X509Certificate(certificate);
        return {
          issuerName: cert.issuer,
          subjectName: cert.subject,
          serialNumber: cert.serialNumber,
          thumbprint: createHash("sha256").update(cert.raw).digest("hex"),
          notBefore: new Date(cert.validFrom),
          notAfter: new Date(cert.validTo),
          pem: cert.toString(),
        };
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
