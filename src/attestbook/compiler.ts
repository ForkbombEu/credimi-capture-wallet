import type { CredentialProofPolicy } from "../openid4vci/metadata.js";
import { compileJsonSchema } from "./json-schema.js";
import {
  SD_JWT_VC_FORMAT,
  type VerifiedRulebook,
  type VerifiedSchemaDocument,
  isRecord,
} from "./snapshot.js";
import type {
  AttestbookClaimMetadata,
  AttestbookClaimNode,
  AttestbookClaimPath,
  AttestbookCredentialDefinition,
  AttestbookDiagnostic,
  AttestbookObjectClaim,
  AttestbookRulebookAttestation,
} from "./types.js";

/** TS11/OWF `bindingType` for a credential bound to a holder key, the only binding issued here. */
const KEY_BINDING = "key";
const VCT_PREFIX = "urn:attestbook:";
const MAX_VCT_SLUG_LENGTH = 128;

export interface CompilationResult {
  /** Empty whenever any error diagnostic is present: a catalogue activates whole or not at all. */
  readonly definitions: readonly AttestbookCredentialDefinition[];
  readonly diagnostics: readonly AttestbookDiagnostic[];
}

interface TypeMetadataClaim {
  readonly path: AttestbookClaimPath;
  readonly selectivelyDisclosable: boolean | null;
  readonly displayName: string | null;
  readonly mandatory: boolean;
}

interface TypeMetadata {
  readonly vct: string;
  readonly displayName: string | null;
  readonly claims: readonly TypeMetadataClaim[];
}

/**
 * Compiles every SD-JWT VC attestation type of a verified rulebook version into an executable
 * credential definition. Attestation types without `dc+sd-jwt` are reported and skipped; any
 * unsupported construct in a selected type is an error that blocks the whole catalogue, so a
 * partially trusted definition is never produced. Every definition takes the importing issuer's
 * proof policy: a rulebook does not choose how holders prove key possession.
 */
export function compileRulebook(
  rulebook: VerifiedRulebook,
  proofPolicy: CredentialProofPolicy,
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
    const definition = compileAttestation(rulebook, attestation, index, proofPolicy, diagnostics);
    if (!definition) return;
    const owner = vcts.get(definition.vct);
    if (owner) {
      diagnostics.push(
        error(
          "duplicate_vct",
          attestation.name,
          "name",
          `name derives the same vct as attestation '${owner}'`,
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

/**
 * The credential type of an attestation, derived from its name alone: `urn:attestbook:<slug>`.
 * It stays the same across rulebook versions and changes when the attestation is renamed. The
 * rulebook is deliberately not part of it, so two rulebooks naming a type alike share its vct.
 */
export function vctForAttestationName(name: string): string | null {
  const slug = slugify(name).slice(0, MAX_VCT_SLUG_LENGTH).replace(/-+$/, "");
  return slug ? `${VCT_PREFIX}${slug}` : null;
}

function compileAttestation(
  rulebook: VerifiedRulebook,
  attestation: AttestbookRulebookAttestation,
  index: number,
  proofPolicy: CredentialProofPolicy,
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
    : { claims: null, diagnostics: [] };
  diagnostics.push(...compiled.diagnostics);

  const vct = vctForAttestationName(attestation.name);
  if (vct === null) {
    diagnostics.push(
      error(
        "vct_unresolved",
        attestation.name,
        "name",
        "the attestation name has no letters or digits to derive a vct from",
      ),
    );
  }
  const [typeMetadataDocument] = typeMetadataDocuments;
  const typeMetadata = typeMetadataDocument
    ? parseTypeMetadata(typeMetadataDocument, attestation.name, diagnostics)
    : null;
  if (typeMetadata && vct !== null && typeMetadata.vct !== vct) {
    diagnostics.push(
      error(
        "vct_conflict",
        attestation.name,
        typeMetadataDocument ? `${typeMetadataDocument.record.uri}#/vct` : "vct",
        `Type Metadata states vct '${typeMetadata.vct}', but the attestation name derives '${vct}'`,
      ),
    );
  }
  const claims =
    compiled.claims && typeMetadata
      ? refineClaims(compiled.claims, typeMetadata, attestation.name, diagnostics)
      : compiled.claims;

  if (diagnostics.slice(before).some((entry) => entry.severity === "error")) return null;
  if (vct === null || !schemaDocument || !claims) return null;
  // The vct is also the credential configuration id and the OAuth scope: stable across versions,
  // and unique within the rulebook (`duplicate_vct`).
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
    credentialConfigurationId: vct,
    scope: vct,
    format: "dc+sd-jwt",
    vct,
    vctSource: "attestation_name",
    displayName: typeMetadata?.displayName ?? attestation.name,
    claims,
    claimMetadata: claimMetadata(claims, [], true),
    schemaReferences: [schemaDocument, ...typeMetadataDocuments].map((document) => ({
      uri: document.record.uri,
      kind: document.record.kind,
      contentDigest: document.record.contentDigest,
      integrity: document.reference.integrity,
      hosted: document.reference.hosted !== null,
    })),
    proofPolicy,
    claimValueProvider: "faker-js",
    disclosurePolicy: "issuer-default-selective",
  };
}

/** Lowercase ASCII letters and digits separated by single hyphens; diacritics are dropped. */
function slugify(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * One OpenID4VCI claims description per object member, nested ones included; an array's elements
 * are addressed with `null`. A member is mandatory when it and every enclosing member is required.
 */
function claimMetadata(
  node: AttestbookClaimNode,
  path: AttestbookClaimPath,
  mandatory: boolean,
): AttestbookClaimMetadata[] {
  if (node.kind === "array") return claimMetadata(node.items, [...path, null], mandatory);
  if (node.kind !== "object") return [];
  return node.properties.flatMap((property) => {
    const memberPath = [...path, property.name];
    const memberMandatory = mandatory && property.required;
    return [
      { path: memberPath, mandatory: memberMandatory, displayName: property.node.displayName },
      ...claimMetadata(property.node, memberPath, memberMandatory),
    ];
  });
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
  const entries = json.claims ?? [];
  if (!Array.isArray(entries)) {
    diagnostics.push(
      error("type_metadata_invalid", attestation, field("/claims"), "claims must be an array"),
    );
    return null;
  }
  const claims: TypeMetadataClaim[] = [];
  entries.forEach((entry, index) => {
    const pointer = `/claims/${index}`;
    if (!isRecord(entry) || !Array.isArray(entry.path) || entry.path.length === 0) {
      diagnostics.push(
        error("type_metadata_invalid", attestation, field(pointer), "claim entry needs a path"),
      );
      return;
    }
    if (!entry.path.every((segment) => typeof segment === "string" || segment === null)) {
      diagnostics.push(
        error(
          "unsupported_claim_path",
          attestation,
          field(`${pointer}/path`),
          "claim paths may name members or all array elements (null), not one element by index",
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
    claims.push({
      path: entry.path as (string | null)[],
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

/**
 * Type Metadata refines disclosure, labels and mandatoriness of claims the schema declares; it
 * cannot add a claim. A path the schema does not declare is an error.
 */
function refineClaims(
  root: AttestbookObjectClaim,
  typeMetadata: TypeMetadata,
  attestation: string,
  diagnostics: AttestbookDiagnostic[],
): AttestbookObjectClaim {
  let refined = root;
  for (const claim of typeMetadata.claims) {
    const next = refineAt(refined, claim.path, claim);
    if (next?.kind !== "object") {
      diagnostics.push(
        error(
          "type_metadata_claim_not_in_schema",
          attestation,
          `claims.${claim.path.map((segment) => segment ?? "[]").join(".")}`,
          "Type Metadata describes a claim the JSON Schema does not declare",
        ),
      );
      continue;
    }
    refined = next;
  }
  return refined;
}

/**
 * The node tree with the claim at `path` refined, or null when no claim has that path. `mandatory`
 * makes the addressed object member required; it never relaxes a schema requirement.
 */
function refineAt(
  node: AttestbookClaimNode,
  path: AttestbookClaimPath,
  claim: TypeMetadataClaim,
): AttestbookClaimNode | null {
  const [segment, ...rest] = path;
  if (segment === undefined) {
    return {
      ...node,
      selectivelyDisclosable: claim.selectivelyDisclosable ?? node.selectivelyDisclosable,
      displayName: claim.displayName ?? node.displayName,
    };
  }
  if (segment === null) {
    if (node.kind !== "array") return null;
    const items = refineAt(node.items, rest, claim);
    return items ? { ...node, items } : null;
  }
  if (node.kind !== "object") return null;
  const index = node.properties.findIndex((property) => property.name === segment);
  const property = node.properties[index];
  if (!property) return null;
  const refined = refineAt(property.node, rest, claim);
  if (!refined) return null;
  const properties = [...node.properties];
  properties[index] = {
    name: property.name,
    required: property.required || (rest.length === 0 && claim.mandatory),
    node: refined,
  };
  return { ...node, properties };
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
