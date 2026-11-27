import { isRecord } from "../shared/json.js";
import type { CredentialFormat } from "../types.js";
import { contentDigestSha256, sha256Hex, sriMatches } from "./digest.js";
import { SAFE_ATTESTBOOK_IDENTIFIER } from "./settings.js";
import type {
  AttestbookRulebookAttestation,
  AttestbookRulebookDocument,
  AttestbookSchemaDocumentRecord,
  AttestbookSchemaKind,
  AttestbookSchemaReference,
  AttestbookSnapshot,
} from "./types.js";

export const SD_JWT_VC_FORMAT = "dc+sd-jwt";
const MDOC_FORMAT = "mso_mdoc";
/** The credential formats an attestation type is imported in, each from its own schema. */
export const IMPORTED_FORMATS: readonly CredentialFormat[] = [SD_JWT_VC_FORMAT, MDOC_FORMAT];
const MAX_ATTESTATIONS = 64;
const MAX_REFERENCES = 32;

export type AttestbookIntegrityErrorCode =
  | "snapshot_identity_mismatch"
  | "rulebook_digest_mismatch"
  | "rulebook_malformed"
  | "unsafe_identifier"
  | "schema_references_mismatch"
  | "schema_document_missing"
  | "schema_document_unexpected"
  | "schema_digest_mismatch"
  | "integrity_pin_mismatch"
  | "integrity_pin_missing"
  | "schema_origin_not_allowed"
  | "schema_document_malformed";

/** The snapshot, or a document it carries, is not exactly what was published. */
export class AttestbookIntegrityError extends Error {
  constructor(
    readonly code: AttestbookIntegrityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AttestbookIntegrityError";
  }
}

export interface VerifiedSchemaDocument {
  readonly record: AttestbookSchemaDocumentRecord;
  readonly reference: AttestbookSchemaReference;
  readonly json: Record<string, unknown>;
}

/** A snapshot whose every byte has been checked against its pins. */
export interface VerifiedRulebook {
  readonly snapshot: AttestbookSnapshot;
  readonly document: AttestbookRulebookDocument;
  readonly documents: ReadonlyMap<string, VerifiedSchemaDocument>;
}

export interface SnapshotTrust {
  readonly origin: string;
  readonly rulebookId: string;
  readonly allowedSchemaOrigins: readonly string[];
}

/**
 * Verifies a snapshot completely before anything is compiled from it: its identity, the exact
 * rulebook bytes against the published SHA-256 digest, the schema references Attestbook reported
 * against those frozen in the bytes, and every schema document against its digest and SRI pin. It
 * is the single verification path for a freshly downloaded snapshot and a persisted one alike.
 */
export function verifySnapshot(
  snapshot: AttestbookSnapshot,
  trust: SnapshotTrust,
): VerifiedRulebook {
  const document = verifyRulebook(snapshot, trust);
  const documents = new Map<string, VerifiedSchemaDocument>();
  const required = requiredSchemaReferences(snapshot.schemaReferences, document);
  for (const reference of required) {
    if (documents.has(reference.uri)) continue;
    const record = snapshot.schemaDocuments.find((candidate) => candidate.uri === reference.uri);
    if (!record) {
      throw new AttestbookIntegrityError(
        "schema_document_missing",
        `schema document ${reference.uri} referenced by '${reference.attestation}' is missing`,
      );
    }
    documents.set(reference.uri, verifySchemaDocument(record, reference, trust));
  }
  const unexpected = snapshot.schemaDocuments.find((record) => !documents.has(record.uri));
  if (unexpected) {
    throw new AttestbookIntegrityError(
      "schema_document_unexpected",
      `schema document ${unexpected.uri} is not referenced by a supported attestation`,
    );
  }
  return { snapshot, document, documents };
}

/**
 * The first verification step, which needs no schema document: the snapshot's identity, its exact
 * rulebook bytes, and the reported schema references against those the bytes freeze.
 */
export function verifyRulebook(
  snapshot: AttestbookSnapshot,
  trust: SnapshotTrust,
): AttestbookRulebookDocument {
  if (
    snapshot.format !== "credimi.attestbook-snapshot@1" ||
    snapshot.origin !== trust.origin ||
    snapshot.rulebookId !== trust.rulebookId
  ) {
    throw new AttestbookIntegrityError(
      "snapshot_identity_mismatch",
      "snapshot does not belong to the configured Attestbook origin and rulebook",
    );
  }
  if (!SAFE_ATTESTBOOK_IDENTIFIER.test(snapshot.version)) {
    throw new AttestbookIntegrityError(
      "unsafe_identifier",
      "version label has unsupported characters",
    );
  }
  const bytes = Buffer.from(snapshot.rulebookBase64, "base64");
  if (
    !/^[0-9a-f]{64}$/.test(snapshot.contentDigest) ||
    sha256Hex(bytes) !== snapshot.contentDigest
  ) {
    throw new AttestbookIntegrityError(
      "rulebook_digest_mismatch",
      `rulebook ${snapshot.version} bytes do not match the published digest`,
    );
  }
  const document = parseRulebookDocument(bytes, snapshot);
  verifyReportedReferences(snapshot.schemaReferences, document);
  return document;
}

/** The references of imported formats whose documents a snapshot must carry. */
export function requiredSchemaReferences(
  references: readonly AttestbookSchemaReference[],
  document: AttestbookRulebookDocument,
): AttestbookSchemaReference[] {
  return references.filter(
    (reference) =>
      reference.attestation !== null &&
      IMPORTED_FORMATS.some(
        (format) =>
          reference.formatIdentifier === format &&
          document.attestations.some(
            (attestation) =>
              attestation.name === reference.attestation &&
              attestation.supportedFormats.includes(format),
          ),
      ),
  );
}

/** The bytes Attestbook exported must hash to the digest the publication event pinned. */
export function verifyExportedBytes(
  bytes: Uint8Array,
  expectedDigest: string,
  contentDigestHeader: string | null,
): void {
  const digest = sha256Hex(bytes);
  const headerDigest = contentDigestSha256(contentDigestHeader);
  if (digest !== expectedDigest || (headerDigest !== null && headerDigest !== digest)) {
    throw new AttestbookIntegrityError(
      "rulebook_digest_mismatch",
      "exported rulebook bytes do not match the published digest",
    );
  }
}

function verifySchemaDocument(
  record: AttestbookSchemaDocumentRecord,
  reference: AttestbookSchemaReference,
  trust: SnapshotTrust,
): VerifiedSchemaDocument {
  const bytes = Buffer.from(record.base64, "base64");
  const digest = sha256Hex(bytes);
  if (digest !== record.contentDigest) {
    throw new AttestbookIntegrityError(
      "schema_digest_mismatch",
      `schema document ${reference.uri} does not match its recorded digest`,
    );
  }
  const origin = new URL(reference.uri).origin;
  if (reference.hosted) {
    if (origin !== trust.origin) {
      throw new AttestbookIntegrityError(
        "schema_origin_not_allowed",
        `hosted schema document ${reference.uri} is outside the trusted Attestbook origin`,
      );
    }
    if (
      digest !== reference.hosted.contentDigest ||
      !sriMatches(reference.hosted.integrity, bytes) ||
      record.kind !== reference.hosted.kind
    ) {
      throw new AttestbookIntegrityError(
        "schema_digest_mismatch",
        `hosted schema document ${reference.uri} does not match its stored digest`,
      );
    }
  } else {
    if (!trust.allowedSchemaOrigins.includes(origin)) {
      throw new AttestbookIntegrityError(
        "schema_origin_not_allowed",
        `external schema origin ${origin} is not explicitly allowed`,
      );
    }
    if (reference.integrity === null) {
      throw new AttestbookIntegrityError(
        "integrity_pin_missing",
        `external schema document ${reference.uri} has no integrity pin`,
      );
    }
  }
  if (reference.integrity !== null && !sriMatches(reference.integrity, bytes)) {
    throw new AttestbookIntegrityError(
      "integrity_pin_mismatch",
      `schema document ${reference.uri} does not match the integrity pin frozen in the rulebook`,
    );
  }
  let json: unknown;
  try {
    json = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new AttestbookIntegrityError(
      "schema_document_malformed",
      `schema document ${reference.uri} is not JSON`,
    );
  }
  if (!isRecord(json) || detectSchemaKind(json) !== record.kind) {
    throw new AttestbookIntegrityError(
      "schema_document_malformed",
      `schema document ${reference.uri} is not a ${record.kind} document`,
    );
  }
  return { record, reference, json };
}

/**
 * Classifies a document that Attestbook does not host: SD-JWT VC Type Metadata names a `vct`; a
 * JSON Schema declares the 2020-12 dialect or an object type. Anything else is unsupported.
 */
export function detectSchemaKind(json: unknown): AttestbookSchemaKind | null {
  if (!isRecord(json)) return null;
  if (typeof json.vct === "string") return "sd_jwt_vc_type_metadata";
  if (json.$schema === "https://json-schema.org/draft/2020-12/schema" || json.type === "object") {
    return "json_schema_2020_12";
  }
  return null;
}

function parseRulebookDocument(
  bytes: Uint8Array,
  snapshot: AttestbookSnapshot,
): AttestbookRulebookDocument {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw malformed("rulebook version is not JSON");
  }
  if (
    !isRecord(value) ||
    value.format !== "attestbook.rulebook-version@1" ||
    typeof value.specVersion !== "string" ||
    typeof value.name !== "string" ||
    typeof value.description !== "string" ||
    !(value.sourceUrl === null || typeof value.sourceUrl === "string") ||
    !Array.isArray(value.attestations) ||
    !Array.isArray(value.schemaReferences)
  ) {
    throw malformed("rulebook version is not an attestbook.rulebook-version@1 document");
  }
  if (value.rulebookId !== snapshot.rulebookId || value.version !== snapshot.version) {
    throw new AttestbookIntegrityError(
      "snapshot_identity_mismatch",
      "rulebook bytes name a different rulebook or version",
    );
  }
  if (value.attestations.length > MAX_ATTESTATIONS) throw malformed("too many attestation types");
  return {
    format: "attestbook.rulebook-version@1",
    rulebookId: snapshot.rulebookId,
    version: snapshot.version,
    specVersion: value.specVersion,
    name: value.name,
    description: value.description,
    sourceUrl: value.sourceUrl,
    attestations: value.attestations.map(parseAttestation),
  };
}

function parseAttestation(value: unknown): AttestbookRulebookAttestation {
  if (
    !isRecord(value) ||
    typeof value.name !== "string" ||
    typeof value.attestationLoS !== "string" ||
    typeof value.bindingType !== "string" ||
    !Array.isArray(value.supportedFormats) ||
    !value.supportedFormats.every((format) => typeof format === "string") ||
    !Array.isArray(value.schemaReferences) ||
    value.schemaReferences.length > MAX_REFERENCES
  ) {
    throw malformed("rulebook version has a malformed attestation type");
  }
  return {
    name: value.name,
    attestationLoS: value.attestationLoS,
    bindingType: value.bindingType,
    supportedFormats: value.supportedFormats as string[],
    schemaReferences: value.schemaReferences.map((reference) => {
      if (
        !isRecord(reference) ||
        typeof reference.formatIdentifier !== "string" ||
        typeof reference.uri !== "string" ||
        !(reference.integrity === null || typeof reference.integrity === "string")
      ) {
        throw malformed("rulebook version has a malformed schema reference");
      }
      return {
        formatIdentifier: reference.formatIdentifier,
        uri: reference.uri,
        integrity: reference.integrity,
      };
    }),
  };
}

/** What `/schema-references` reported must be exactly what the immutable bytes freeze. */
function verifyReportedReferences(
  reported: readonly AttestbookSchemaReference[],
  document: AttestbookRulebookDocument,
): void {
  const frozen = document.attestations.flatMap((attestation) =>
    attestation.schemaReferences.map((reference) => ({
      attestation: attestation.name,
      ...reference,
    })),
  );
  const reportedAttestationReferences = reported.filter(
    (reference) => reference.attestation !== null,
  );
  const matches =
    frozen.length === reportedAttestationReferences.length &&
    frozen.every((reference, index) => {
      const candidate = reportedAttestationReferences[index];
      return (
        candidate?.attestation === reference.attestation &&
        candidate.formatIdentifier === reference.formatIdentifier &&
        candidate.uri === reference.uri &&
        candidate.integrity === reference.integrity
      );
    });
  if (!matches) {
    throw new AttestbookIntegrityError(
      "schema_references_mismatch",
      "reported schema references differ from those frozen in the rulebook bytes",
    );
  }
}

function malformed(message: string): AttestbookIntegrityError {
  return new AttestbookIntegrityError("rulebook_malformed", message);
}
