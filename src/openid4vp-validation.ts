import {
  type JsonWebKey as NodeJsonWebKey,
  X509Certificate,
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import {
  DataItem,
  type MdocContext,
  Verifier,
  type X509Context,
  cborEncode,
  parseDeviceResponse,
} from "@animo-id/mdoc";
import {
  type JWK,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
} from "jose";
import type { AppConfig, JsonRecord, VpSessionCapture } from "./types.js";

interface VpPresentationValidation {
  valid: boolean;
  vp_token_format_valid: boolean;
  nonce_verified: boolean;
  holder_binding_verified: boolean;
  dcql_query_matched: boolean;
  errors: string[];
}

interface PresentationCandidate {
  query: JsonRecord;
  presentation: unknown;
}

export async function validateVpPresentationResponse(
  config: AppConfig,
  session: VpSessionCapture,
  body: JsonRecord,
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
    const vpToken = parseVpToken(body.vp_token);
    const candidates = presentationCandidates(session.authorization_request, vpToken);
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
    result.dcql_query_matched = validations.every((validation) => validation.dcqlQueryMatched);
    result.errors.push(...validations.flatMap((validation) => validation.errors));
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
  dcqlQueryMatched: boolean;
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
    dcqlQueryMatched: false,
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
  dcqlQueryMatched: boolean;
  errors: string[];
}> {
  const errors: string[] = [];
  const presentation = asString(candidate.presentation);
  if (!presentation) {
    return {
      nonceVerified: false,
      holderBindingVerified: false,
      dcqlQueryMatched: false,
      errors: ["SD-JWT VC presentation must be a compact string"],
    };
  }

  const { issuerJwt, disclosures, kbJwt, withoutKeyBinding } = splitSdJwt(presentation);
  if (!kbJwt) errors.push("SD-JWT VC presentation is missing key-binding JWT");

  try {
    await verifyIssuerJwt(issuerJwt);
  } catch (error) {
    errors.push(`SD-JWT VC issuer signature verification failed: ${errorMessage(error)}`);
  }

  let claims: JsonRecord | null = null;
  try {
    const issuerPayload = decodeJwt(issuerJwt) as JsonRecord;
    claims = unpackSdJwtClaims(issuerPayload, disclosures);
  } catch (error) {
    errors.push(`SD-JWT VC disclosure verification failed: ${errorMessage(error)}`);
  }

  let nonceVerified = false;
  let holderBindingVerified = false;
  if (kbJwt && claims) {
    try {
      const kbPayload = await verifyKeyBindingJwt(
        kbJwt,
        claims,
        withoutKeyBinding,
        session.authorization_request,
      );
      nonceVerified = kbPayload.nonce === session.authorization_request.nonce;
      holderBindingVerified = true;
      if (!audienceMatches(kbPayload.aud, config.issuer_base_url, session.authorization_request)) {
        errors.push("SD-JWT VC key-binding JWT audience does not match this verifier");
      }
      if (!nonceVerified) errors.push("SD-JWT VC key-binding JWT nonce does not match the request");
    } catch (error) {
      errors.push(`SD-JWT VC holder binding verification failed: ${errorMessage(error)}`);
    }
  }

  const dcqlQueryMatched = claims ? matchCredentialQuery(candidate.query, claims).matched : false;
  if (claims) {
    const match = matchCredentialQuery(candidate.query, claims);
    if (!match.matched) errors.push(...match.errors);
  }

  return { nonceVerified, holderBindingVerified, dcqlQueryMatched, errors };
}

async function validateMdocPresentation(
  session: VpSessionCapture,
  candidate: PresentationCandidate,
): Promise<{
  nonceVerified: boolean;
  holderBindingVerified: boolean;
  dcqlQueryMatched: boolean;
  errors: string[];
}> {
  const presentation = asString(candidate.presentation);
  if (!presentation) {
    return {
      nonceVerified: false,
      holderBindingVerified: false,
      dcqlQueryMatched: false,
      errors: ["mdoc presentation must be a base64url-encoded DeviceResponse string"],
    };
  }

  const errors: string[] = [];
  const encodedDeviceResponse = Buffer.from(presentation, "base64url");
  const context = mdocVerificationContext();
  const sessionTranscript = mdocSessionTranscript(session.authorization_request);
  let verified = false;

  try {
    await new Verifier().verifyDeviceResponse(
      {
        encodedDeviceResponse,
        encodedSessionTranscript: sessionTranscript,
        disableCertificateChainValidation: true,
        trustedCertificates: [],
      },
      context,
    );
    verified = true;
  } catch (error) {
    errors.push(`mdoc DeviceResponse verification failed: ${errorMessage(error)}`);
  }

  let dcqlQueryMatched = false;
  try {
    const parsed = await parseDeviceResponse(encodedDeviceResponse);
    const matches = parsed.documents.map((document) =>
      matchCredentialQuery(
        candidate.query,
        mdocClaims(document.docType, document.allIssuerSignedNamespaces),
      ),
    );
    const match = matches.find((entry) => entry.matched);
    dcqlQueryMatched = Boolean(match);
    if (!dcqlQueryMatched) {
      errors.push(...(matches[0]?.errors ?? ["mdoc presentation does not match DCQL query"]));
    }
  } catch (error) {
    errors.push(`mdoc claim extraction failed: ${errorMessage(error)}`);
  }

  return {
    nonceVerified: verified,
    holderBindingVerified: verified,
    dcqlQueryMatched,
    errors: verified ? errors.filter((error) => !error.startsWith("mdoc DeviceResponse")) : errors,
  };
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
  authorizationRequest: JsonRecord,
  vpToken: JsonRecord,
): PresentationCandidate[] {
  const dcqlQuery = asRecord(authorizationRequest.dcql_query);
  const queries = asArray(dcqlQuery?.credentials).filter(isRecord);
  const candidates: PresentationCandidate[] = [];

  for (const query of queries) {
    const queryId = asString(query.id);
    if (!queryId) continue;
    const entries = asArray(vpToken[queryId]);
    if (entries.length === 0) {
      throw new Error(`vp_token is missing presentation array for DCQL credential '${queryId}'`);
    }
    if (query.multiple !== true && entries.length !== 1) {
      throw new Error(`DCQL credential '${queryId}' expects exactly one presentation`);
    }
    candidates.push(...entries.map((presentation) => ({ query, presentation })));
  }

  return candidates;
}

function splitSdJwt(sdJwt: string): {
  issuerJwt: string;
  disclosures: string[];
  kbJwt: string | null;
  withoutKeyBinding: string;
} {
  const parts = sdJwt.split("~");
  const issuerJwt = parts[0];
  if (!issuerJwt) throw new Error("SD-JWT VC presentation is missing issuer JWT");
  const nonEmptyTail = parts.slice(1).filter((part) => part.length > 0);
  const maybeKbJwt = nonEmptyTail.at(-1);
  const hasKbJwt = Boolean(maybeKbJwt?.includes("."));
  const disclosures = hasKbJwt ? nonEmptyTail.slice(0, -1) : nonEmptyTail;
  return {
    issuerJwt,
    disclosures,
    kbJwt: hasKbJwt ? (maybeKbJwt ?? null) : null,
    withoutKeyBinding: `${issuerJwt}~${disclosures.join("~")}~`,
  };
}

async function verifyIssuerJwt(issuerJwt: string): Promise<void> {
  const header = decodeProtectedHeader(issuerJwt) as JsonRecord;
  const key = await verificationKeyFromHeader(header);
  await compactVerify(issuerJwt, key);
}

async function verificationKeyFromHeader(header: JsonRecord) {
  const jwk = asRecord(header.jwk);
  if (jwk) return importJWK(jwk as unknown as JWK, asString(header.alg) ?? "ES256");
  const x5c = asArray(header.x5c);
  const leaf = asString(x5c[0]);
  if (leaf) return new X509Certificate(Buffer.from(leaf, "base64")).publicKey;
  throw new Error("JOSE header does not contain jwk or x5c key material");
}

function unpackSdJwtClaims(payload: JsonRecord, encodedDisclosures: string[]): JsonRecord {
  const alg = asString(payload._sd_alg) ?? "sha-256";
  if (alg !== "sha-256") throw new Error(`unsupported SD-JWT hash algorithm '${alg}'`);
  const disclosureByDigest = new Map(
    encodedDisclosures.map((encoded) => {
      const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as unknown;
      if (!Array.isArray(decoded) || decoded.length < 2) {
        throw new Error("invalid SD-JWT disclosure encoding");
      }
      return [sha256Base64Url(encoded), { encoded, decoded }] as const;
    }),
  );
  return unpackSdValue(payload, disclosureByDigest) as JsonRecord;
}

function unpackSdValue(
  value: unknown,
  disclosureByDigest: Map<string, { encoded: string; decoded: unknown[] }>,
): unknown {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => {
      if (isRecord(entry) && typeof entry["..."] === "string") {
        const disclosure = disclosureByDigest.get(entry["..."]);
        if (!disclosure) return [];
        return [unpackSdValue(disclosure.decoded[1], disclosureByDigest)];
      }
      return [unpackSdValue(entry, disclosureByDigest)];
    });
  }
  if (!isRecord(value)) return value;

  const output: JsonRecord = {};
  for (const [key, nested] of Object.entries(value)) {
    if (key === "_sd" || key === "_sd_alg") continue;
    output[key] = unpackSdValue(nested, disclosureByDigest);
  }
  const sd = asArray(value._sd);
  for (const digest of sd) {
    if (typeof digest !== "string") continue;
    const disclosure = disclosureByDigest.get(digest);
    if (!disclosure) continue;
    const key = asString(disclosure.decoded[1]);
    if (!key) throw new Error("object disclosure does not contain a claim name");
    output[key] = unpackSdValue(disclosure.decoded[2], disclosureByDigest);
  }
  return output;
}

async function verifyKeyBindingJwt(
  kbJwt: string,
  claims: JsonRecord,
  sdJwtWithoutKeyBinding: string,
  authorizationRequest: JsonRecord,
): Promise<JsonRecord> {
  const cnf = asRecord(claims.cnf);
  const jwk = asRecord(cnf?.jwk);
  if (!jwk) throw new Error("credential does not contain cnf.jwk holder key");
  const header = decodeProtectedHeader(kbJwt);
  const verified = await jwtVerify(kbJwt, await importJWK(jwk as unknown as JWK, header.alg));
  const payload = verified.payload as JsonRecord;
  if (payload.nonce !== authorizationRequest.nonce) throw new Error("nonce mismatch");
  const sdHash = asString(payload.sd_hash) ?? asString(payload._sd_hash);
  if (sdHash !== sha256Base64Url(sdJwtWithoutKeyBinding)) throw new Error("sd_hash mismatch");
  return payload;
}

function audienceMatches(
  aud: unknown,
  issuerBaseUrl: string,
  authorizationRequest: JsonRecord,
): boolean {
  const allowed = new Set(
    [authorizationRequest.client_id, authorizationRequest.response_uri, issuerBaseUrl].filter(
      (value): value is string => typeof value === "string",
    ),
  );
  if (typeof aud === "string") return allowed.has(aud);
  if (Array.isArray(aud))
    return aud.some((entry) => typeof entry === "string" && allowed.has(entry));
  return false;
}

function matchCredentialQuery(
  query: JsonRecord,
  claims: JsonRecord,
): { matched: boolean; errors: string[] } {
  const errors: string[] = [];
  const format = asString(query.format);
  const meta = asRecord(query.meta);
  if (format === "dc+sd-jwt") {
    const vctValues = asArray(meta?.vct_values).filter(
      (value): value is string => typeof value === "string",
    );
    if (vctValues.length > 0 && !vctValues.includes(asString(claims.vct) ?? "")) {
      errors.push("SD-JWT VC vct does not match DCQL meta.vct_values");
    }
  }
  if (format === "mso_mdoc") {
    const doctype = asString(meta?.doctype_value);
    if (doctype && claims.doctype !== doctype)
      errors.push("mdoc doctype does not match DCQL meta.doctype_value");
  }

  errors.push(...matchClaimQueries(query, claims));

  return { matched: errors.length === 0, errors };
}

function matchClaimQueries(query: JsonRecord, claims: JsonRecord): string[] {
  const claimQueries = asArray(query.claims).filter(isRecord);
  const claimSets = asArray(query.claim_sets).filter(Array.isArray);
  if (claimSets.length === 0) return missingClaimPathErrors(claimQueries, claims);

  const claimById = new Map(
    claimQueries
      .map((claim) => [asString(claim.id), claim] as const)
      .filter((entry): entry is readonly [string, JsonRecord] => Boolean(entry[0])),
  );
  const candidateErrors = claimSets.map((claimSet) => {
    const selectedClaims = claimSet
      .map((claimId) => (typeof claimId === "string" ? claimById.get(claimId) : undefined))
      .filter((claim): claim is JsonRecord => Boolean(claim));
    if (selectedClaims.length !== claimSet.length) {
      return ["DCQL claim_set references an unknown claim id"];
    }
    return missingClaimPathErrors(selectedClaims, claims);
  });
  return candidateErrors.some((entry) => entry.length === 0)
    ? []
    : (candidateErrors[0] ?? ["DCQL claim_sets did not match"]);
}

function missingClaimPathErrors(claimQueries: JsonRecord[], claims: JsonRecord): string[] {
  return claimQueries.flatMap((claim) => {
    const path = asArray(claim.path);
    return pathExists(claims, path) ? [] : [`missing DCQL claim path ${JSON.stringify(path)}`];
  });
}

function pathExists(value: unknown, path: unknown[]): boolean {
  if (path.length === 0) return value !== undefined;
  const [head, ...tail] = path;
  if (head === null) {
    return (
      Array.isArray(value) && value.length > 0 && value.every((entry) => pathExists(entry, tail))
    );
  }
  if (typeof head !== "string") return false;
  if (!isRecord(value) || !(head in value)) return false;
  return pathExists(value[head], tail);
}

export function mdocSessionTranscript(authorizationRequest: JsonRecord): Uint8Array {
  const clientId = asString(authorizationRequest.client_id) ?? "";
  const nonce = asString(authorizationRequest.nonce) ?? "";
  const responseUri = asString(authorizationRequest.response_uri) ?? "";
  const handoverInfo = cborEncode(DataItem.fromData([clientId, nonce, null, responseUri]));
  const handover = DataItem.fromData([
    null,
    null,
    ["OpenID4VPHandover", createHash("sha256").update(handoverInfo).digest()],
  ]);
  return cborEncode(handover);
}

function mdocClaims(doctype: string, namespaces: Map<string, Map<string, unknown>>): JsonRecord {
  return {
    doctype,
    ...Object.fromEntries(
      [...namespaces.entries()].map(([namespace, values]) => [
        namespace,
        Object.fromEntries(values),
      ]),
    ),
  };
}

function mdocVerificationContext(): {
  crypto: MdocContext["crypto"];
  cose: MdocContext["cose"];
  x509: X509Context;
} {
  return {
    crypto: {
      random: (length) => Buffer.alloc(length),
      digest: ({ digestAlgorithm, bytes }) => {
        if (digestAlgorithm !== "SHA-256") {
          throw new Error(`unsupported mdoc digest algorithm '${digestAlgorithm}'`);
        }
        return createHash("sha256").update(bytes).digest();
      },
      calculateEphemeralMacKeyJwk: () => {
        throw new Error("mdoc DeviceMac holder binding is not supported");
      },
    },
    cose: {
      sign1: {
        sign: () => {
          throw new Error("mdoc signing is not supported by the verifier");
        },
        verify: ({ jwk, sign1, options }) => {
          const verification = sign1.getRawVerificationData(options);
          return verifySignature(
            "sha256",
            verification.data,
            {
              key: createPublicKey({ key: jwk as unknown as NodeJsonWebKey, format: "jwk" }),
              dsaEncoding: "ieee-p1363",
            },
            verification.signature,
          );
        },
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
      getPublicKey: ({ certificate }) =>
        new X509Certificate(certificate).publicKey.export({ format: "jwk" }) as JWK,
      validateCertificateChain: () => undefined,
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

function sha256Base64Url(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
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
