import {
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_VCT,
  PID_SD_JWT_VCT,
} from "../credential-definitions.js";
import type { VctMapping } from "./claims.js";
import { sha256Hex } from "./digest.js";
import { type SchemaClaim, compileJsonSchema } from "./json-schema.js";
import {
  SD_JWT_VC_FORMAT,
  type VerifiedRulebook,
  type VerifiedSchemaDocument,
  isRecord,
} from "./snapshot.js";
import type {
  AttestbookClaimDefinition,
  AttestbookCredentialDefinition,
  AttestbookDiagnostic,
  AttestbookRulebookAttestation,
} from "./types.js";

/** `vct` values the static catalogue owns; an imported type must never impersonate them. */
const STATIC_VCTS = new Set([
  PID_SD_JWT_VCT,
  DOMESTIC_PID_SD_JWT_VCT,
  DEGREE_SD_JWT_VCT,
  NUMERIC_SD_JWT_VCT,
]);
/** TS11/OWF `bindingType` for a credential bound to a holder key, the only binding issued here. */
const KEY_BINDING = "key";

export interface CompilationResult {
  /** Empty whenever any error diagnostic is present: a catalogue activates whole or not at all. */
  readonly definitions: readonly AttestbookCredentialDefinition[];
  readonly diagnostics: readonly AttestbookDiagnostic[];
}

interface TypeMetadataClaim {
  readonly selectivelyDisclosable: boolean | null;
  readonly displayName: string | null;
  readonly mandatory: boolean;
}

interface TypeMetadata {
  readonly vct: string;
  readonly displayName: string | null;
  readonly claims: ReadonlyMap<string, TypeMetadataClaim>;
}

/**
 * Compiles every SD-JWT VC attestation type of a verified rulebook version into an executable
 * credential definition. Attestation types without `dc+sd-jwt` are reported and skipped; any
 * unsupported construct in a selected type is an error that blocks the whole catalogue, so a
 * partially trusted definition is never produced.
 */
export function compileRulebook(
  rulebook: VerifiedRulebook,
  vctMappings: readonly VctMapping[],
): CompilationResult {
  const diagnostics: AttestbookDiagnostic[] = [];
  const definitions: AttestbookCredentialDefinition[] = [];
  const names = new Set<string>();
  const vcts = new Map<string, string>();

  rulebook.document.attestations.forEach((attestation, index) => {
    if (names.has(attestation.name)) {
      diagnostics.push(
        error(
          "duplicate_attestation_name",
          attestation.name,
          null,
          "attestation type names must be unique",
        ),
      );
      return;
    }
    names.add(attestation.name);
    if (!attestation.supportedFormats.includes(SD_JWT_VC_FORMAT)) {
      diagnostics.push({
        severity: "info",
        code: "attestation_format_not_supported",
        attestation: attestation.name,
        field: "supportedFormats",
        message: "attestation type does not support dc+sd-jwt and is not imported",
      });
      return;
    }
    const definition = compileAttestation(rulebook, attestation, index, vctMappings, diagnostics);
    if (!definition) return;
    const owner = vcts.get(definition.vct);
    if (owner) {
      diagnostics.push(
        error(
          "duplicate_vct",
          attestation.name,
          "vct",
          `vct is already used by attestation '${owner}'`,
        ),
      );
      return;
    }
    vcts.set(definition.vct, attestation.name);
    definitions.push(definition);
  });

  if (
    definitions.length === 0 &&
    !diagnostics.some((diagnostic) => diagnostic.severity === "error")
  ) {
    diagnostics.push(
      error(
        "no_supported_attestations",
        null,
        "attestations",
        "rulebook defines no dc+sd-jwt attestation type",
      ),
    );
  }
  const failed = diagnostics.some((diagnostic) => diagnostic.severity === "error");
  return { definitions: failed ? [] : definitions, diagnostics };
}

function compileAttestation(
  rulebook: VerifiedRulebook,
  attestation: AttestbookRulebookAttestation,
  index: number,
  vctMappings: readonly VctMapping[],
  diagnostics: AttestbookDiagnostic[],
): AttestbookCredentialDefinition | null {
  const before = diagnostics.length;
  if (attestation.bindingType !== KEY_BINDING) {
    diagnostics.push(
      error(
        "unsupported_binding_type",
        attestation.name,
        "bindingType",
        `binding type '${attestation.bindingType}' is not supported; only 'key' holder binding is issued`,
      ),
    );
  }
  const documents = attestation.schemaReferences
    .filter((reference) => reference.formatIdentifier === SD_JWT_VC_FORMAT)
    .map((reference) => rulebook.documents.get(reference.uri))
    .filter((document): document is VerifiedSchemaDocument => document !== undefined);
  const schemas = documents.filter((document) => document.record.kind === "json_schema_2020_12");
  const typeMetadataDocuments = documents.filter(
    (document) => document.record.kind === "sd_jwt_vc_type_metadata",
  );
  if (schemas.length !== 1) {
    diagnostics.push(
      error(
        schemas.length === 0 ? "json_schema_missing" : "ambiguous_json_schema",
        attestation.name,
        "schemaReferences",
        "exactly one dc+sd-jwt JSON Schema 2020-12 reference is required to derive the claims",
      ),
    );
  }
  if (typeMetadataDocuments.length > 1) {
    diagnostics.push(
      error(
        "ambiguous_type_metadata",
        attestation.name,
        "schemaReferences",
        "at most one SD-JWT VC Type Metadata reference is supported",
      ),
    );
  }
  const [schemaDocument] = schemas;
  const compiled = schemaDocument
    ? compileJsonSchema(schemaDocument.json, attestation.name, schemaDocument.record.uri)
    : { claims: [], diagnostics: [] };
  diagnostics.push(...compiled.diagnostics);

  const [typeMetadataDocument] = typeMetadataDocuments;
  const typeMetadata = typeMetadataDocument
    ? parseTypeMetadata(typeMetadataDocument, attestation.name, diagnostics)
    : null;
  const mapping = vctMappings.find(
    (candidate) =>
      candidate.rulebookId === rulebook.document.rulebookId &&
      candidate.attestation === attestation.name,
  );
  const vct = typeMetadata?.vct ?? mapping?.vct ?? null;
  if (vct === null) {
    diagnostics.push(
      error(
        "vct_unresolved",
        attestation.name,
        "vct",
        "no SD-JWT VC Type Metadata reference or issuer-owned vct mapping names the credential type",
      ),
    );
  } else if (typeMetadata && mapping && mapping.vct !== typeMetadata.vct) {
    diagnostics.push(
      error(
        "vct_conflict",
        attestation.name,
        "vct",
        "issuer-owned vct mapping contradicts the Type Metadata vct",
      ),
    );
  } else if (STATIC_VCTS.has(vct)) {
    diagnostics.push(
      error(
        "vct_reserved",
        attestation.name,
        "vct",
        "vct belongs to a static credential of this issuer",
      ),
    );
  }
  const claims = typeMetadata
    ? refineClaims(compiled.claims, typeMetadata, attestation.name, diagnostics)
    : compiled.claims.map(defaultClaim);

  if (
    diagnostics.length > before &&
    diagnostics.slice(before).some((entry) => entry.severity === "error")
  ) {
    return null;
  }
  if (vct === null || !schemaDocument) return null;
  const credentialConfigurationId = credentialConfigurationIdFor(rulebook, attestation.name);
  return {
    origin: rulebook.snapshot.origin,
    rulebookId: rulebook.document.rulebookId,
    version: rulebook.document.version,
    contentDigest: rulebook.snapshot.contentDigest,
    attestation: {
      name: attestation.name,
      index,
      attestationLoS: attestation.attestationLoS,
      bindingType: attestation.bindingType,
    },
    credentialConfigurationId,
    scope: credentialConfigurationId,
    format: "dc+sd-jwt",
    vct,
    vctSource: typeMetadata ? "type_metadata" : "issuer_mapping",
    displayName: typeMetadata?.displayName ?? attestation.name,
    claims,
    schemaReferences: [schemaDocument, ...typeMetadataDocuments].map((document) => ({
      uri: document.record.uri,
      kind: document.record.kind,
      contentDigest: document.record.contentDigest,
      integrity: document.reference.integrity,
      hosted: document.reference.hosted !== null,
    })),
    proofPolicy: "jwt-proof",
    claimValueProvider: "local-fixtures",
    disclosurePolicy: "issuer-default-selective",
  };
}

/**
 * A deterministic, version-specific identifier, also used as the OAuth scope. The readable part
 * names the rulebook, version and attestation; the digest over the origin and those identities
 * keeps two attestations whose names slug alike, or two origins, from colliding.
 */
export function credentialConfigurationIdFor(
  rulebook: VerifiedRulebook,
  attestationName: string,
): string {
  const { rulebookId, version } = rulebook.document;
  const slug =
    attestationName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40) || "attestation";
  const digest = sha256Hex(
    Buffer.from(
      [rulebook.snapshot.origin, rulebookId, version, attestationName].join("\n"),
      "utf8",
    ),
  ).slice(0, 12);
  return `urn:attestbook:${rulebookId}:${version}:${slug}-${digest}`;
}

function parseTypeMetadata(
  document: VerifiedSchemaDocument,
  attestation: string,
  diagnostics: AttestbookDiagnostic[],
): TypeMetadata | null {
  const { json } = document;
  const field = (pointer: string): string => `${document.record.uri}#${pointer}`;
  const vct = json.vct;
  if (typeof vct !== "string" || vct.length === 0 || vct.length > 2048) {
    diagnostics.push(
      error("type_metadata_invalid", attestation, field("/vct"), "vct must be a non-empty string"),
    );
    return null;
  }
  if (json.extends !== undefined || json["extends#integrity"] !== undefined) {
    diagnostics.push(
      error(
        "unsupported_type_metadata_extends",
        attestation,
        field("/extends"),
        "extending another type is not supported",
      ),
    );
  }
  for (const member of ["schema", "schema_uri", "schema_uri#integrity"]) {
    if (json[member] !== undefined) {
      diagnostics.push({
        severity: "info",
        code: "type_metadata_schema_ignored",
        attestation,
        field: field(`/${member}`),
        message:
          "claims are derived from the rulebook's JSON Schema reference, not from Type Metadata",
      });
    }
  }
  const claims = new Map<string, TypeMetadataClaim>();
  const entries = json.claims ?? [];
  if (!Array.isArray(entries)) {
    diagnostics.push(
      error("type_metadata_invalid", attestation, field("/claims"), "claims must be an array"),
    );
    return null;
  }
  entries.forEach((entry, index) => {
    const pointer = `/claims/${index}`;
    if (!isRecord(entry) || !Array.isArray(entry.path) || entry.path.length === 0) {
      diagnostics.push(
        error("type_metadata_invalid", attestation, field(pointer), "claim entry needs a path"),
      );
      return;
    }
    const [name] = entry.path;
    if (entry.path.length !== 1 || typeof name !== "string") {
      diagnostics.push(
        error(
          "unsupported_nested_claim",
          attestation,
          field(`${pointer}/path`),
          "only top-level claim paths are supported",
        ),
      );
      return;
    }
    if (
      entry.sd !== undefined &&
      entry.sd !== "always" &&
      entry.sd !== "allowed" &&
      entry.sd !== "never"
    ) {
      diagnostics.push(
        error(
          "type_metadata_invalid",
          attestation,
          field(`${pointer}/sd`),
          "sd must be always, allowed or never",
        ),
      );
      return;
    }
    claims.set(name, {
      selectivelyDisclosable: entry.sd === "never" ? false : entry.sd === "always" ? true : null,
      displayName: localizedName(entry.display),
      mandatory: entry.mandatory === true,
    });
  });
  return {
    vct,
    displayName: localizedName(json.display) ?? (typeof json.name === "string" ? json.name : null),
    claims,
  };
}

/** Type Metadata refines disclosure and labels; it cannot add a claim the schema does not declare. */
function refineClaims(
  schemaClaims: readonly SchemaClaim[],
  typeMetadata: TypeMetadata,
  attestation: string,
  diagnostics: AttestbookDiagnostic[],
): AttestbookClaimDefinition[] {
  for (const name of typeMetadata.claims.keys()) {
    if (!schemaClaims.some((claim) => claim.name === name)) {
      diagnostics.push(
        error(
          "type_metadata_claim_not_in_schema",
          attestation,
          `claims.${name}`,
          `Type Metadata describes claim '${name}', which the JSON Schema does not declare`,
        ),
      );
    }
  }
  return schemaClaims.map((claim) => {
    const refinement = typeMetadata.claims.get(claim.name);
    const base = defaultClaim(claim);
    return refinement
      ? {
          ...base,
          required: base.required || refinement.mandatory,
          selectivelyDisclosable: refinement.selectivelyDisclosable ?? base.selectivelyDisclosable,
          displayName: refinement.displayName ?? base.displayName,
        }
      : base;
  });
}

/** The issuer's disclosure policy: every top-level claim is individually disclosable. */
function defaultClaim(claim: SchemaClaim): AttestbookClaimDefinition {
  const { title, ...rest } = claim;
  return { ...rest, selectivelyDisclosable: true, displayName: title };
}

function localizedName(display: unknown): string | null {
  if (!Array.isArray(display)) return null;
  const entries = display.filter(isRecord);
  const preferred =
    entries.find((entry) => entry.locale === "en-US" || entry.lang === "en-US") ??
    entries.find((entry) => String(entry.locale ?? entry.lang ?? "").startsWith("en")) ??
    entries[0];
  return typeof preferred?.name === "string" ? preferred.name : null;
}

function error(
  code: string,
  attestation: string | null,
  field: string | null,
  message: string,
): AttestbookDiagnostic {
  return { severity: "error", code, attestation, field, message };
}
