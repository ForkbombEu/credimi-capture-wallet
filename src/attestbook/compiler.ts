import { isRecord } from "../shared/json.js";
import type { CredentialFormat, CredentialProofPolicy } from "../types.js";
import { compileJsonSchema, scalarValueError } from "./json-schema.js";
import {
  IMPORTED_FORMATS,
  SD_JWT_VC_FORMAT,
  type VerifiedRulebook,
  type VerifiedSchemaDocument,
} from "./snapshot.js";
import type {
  AttestbookClaimMetadata,
  AttestbookClaimNode,
  AttestbookClaimPath,
  AttestbookCredentialDefinition,
  AttestbookDiagnostic,
  AttestbookObjectClaim,
  AttestbookRulebookAttestation,
  AttestbookScalarClaim,
} from "./types.js";

/** TS11/OWF `bindingType` for a credential bound to a holder key, the only binding issued here. */
const KEY_BINDING = "key";
const VCT_PREFIX = "urn:attestbook:";
const MAX_VCT_SLUG_LENGTH = 128;
/** The configuration id suffix per format; `+` is avoided, form encoding reads it as a space. */
const FORMAT_SUFFIX: Readonly<Record<CredentialFormat, string>> = {
  "dc+sd-jwt": "sd_jwt",
  mso_mdoc: "mso_mdoc",
};
/** The credential type per format, and the schema root property that may pin it. */
const CREDENTIAL_TYPE: Readonly<Record<CredentialFormat, { label: string; property: string }>> = {
  "dc+sd-jwt": { label: "vct", property: "vct" },
  mso_mdoc: { label: "doctype", property: "docType" },
};

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
 * Compiles every attestation type of a verified rulebook version into one executable credential
 * definition per supported format: `dc+sd-jwt` and `mso_mdoc`, each from its own JSON Schema
 * reference. Attestation types with neither are reported and skipped; any unsupported construct
 * in a selected type is an error that blocks the whole catalogue, so a partially trusted definition
 * is never produced. Every definition takes the importing issuer's proof policy: a rulebook does
 * not choose how holders prove key possession.
 */
export function compileRulebook(
  rulebook: VerifiedRulebook,
  proofPolicy: CredentialProofPolicy,
): CompilationResult {
  const diagnostics: AttestbookDiagnostic[] = [];
  const definitions: AttestbookCredentialDefinition[] = [];
  const names = new Set<string>();
  const types = new Map<string, string>();
  const ids = new Map<string, string>();

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
    const formats = IMPORTED_FORMATS.filter((format) =>
      attestation.supportedFormats.includes(format),
    );
    if (formats.length === 0) {
      diagnostics.push({
        severity: "info",
        code: "attestation_format_not_supported",
        attestation: attestation.name,
        field: "supportedFormats",
        message: "attestation type supports neither dc+sd-jwt nor mso_mdoc and is not imported",
      });
      return;
    }
    if (attestation.bindingType !== KEY_BINDING) {
      diagnostics.push(
        error(
          "unsupported_binding_type",
          attestation.name,
          "bindingType",
          `binding type '${attestation.bindingType}' is not supported; only 'key' holder binding is issued`,
        ),
      );
      return;
    }
    for (const format of formats) {
      const definition = compileAttestation(
        rulebook,
        attestation,
        index,
        format,
        proofPolicy,
        diagnostics,
      );
      if (!definition) continue;
      const { label } = CREDENTIAL_TYPE[format];
      const [type, source] =
        definition.format === SD_JWT_VC_FORMAT
          ? [definition.vct, definition.vctSource]
          : [definition.doctype, definition.doctypeSource];
      const typeOwner = types.get(`${format} ${type}`);
      const idOwner = ids.get(definition.credentialConfigurationId);
      if (typeOwner || idOwner) {
        diagnostics.push(
          typeOwner
            ? error(
                `duplicate_${label}`,
                attestation.name,
                source === "json_schema" ? "schemaReferences" : "name",
                `${source === "json_schema" ? "the JSON Schema states" : "name derives"} the same ${label} as attestation '${typeOwner}'`,
              )
            : error(
                "duplicate_credential_configuration_id",
                attestation.name,
                "name",
                `name derives the same credential configuration id as attestation '${idOwner}'`,
              ),
        );
        continue;
      }
      types.set(`${format} ${type}`, attestation.name);
      ids.set(definition.credentialConfigurationId, attestation.name);
      definitions.push(definition);
    }
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
        "rulebook defines no dc+sd-jwt or mso_mdoc attestation type",
      ),
    );
  }
  const failed = diagnostics.some((diagnostic) => diagnostic.severity === "error");
  return { definitions: failed ? [] : definitions, diagnostics };
}

/**
 * The identifier derived from an attestation name alone: `urn:attestbook:<slug>`. Suffixed with the
 * format it is the credential configuration id and the OAuth scope, and as is it is the vct or
 * doctype unless the JSON Schema pins one. It stays the same across rulebook versions and changes
 * when the attestation is renamed. The rulebook is deliberately not part of it, so two rulebooks
 * naming a type alike share it.
 * @internal
 */
export function vctForAttestationName(name: string): string | null {
  const slug = slugify(name).slice(0, MAX_VCT_SLUG_LENGTH).replace(/-+$/, "");
  return slug ? `${VCT_PREFIX}${slug}` : null;
}

function compileAttestation(
  rulebook: VerifiedRulebook,
  attestation: AttestbookRulebookAttestation,
  index: number,
  format: CredentialFormat,
  proofPolicy: CredentialProofPolicy,
  diagnostics: AttestbookDiagnostic[],
): AttestbookCredentialDefinition | null {
  const before = diagnostics.length;
  const sdJwt = format === SD_JWT_VC_FORMAT;
  const { label, property } = CREDENTIAL_TYPE[format];
  const documents = attestation.schemaReferences
    .filter((reference) => reference.formatIdentifier === format)
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
        `exactly one ${format} JSON Schema 2020-12 reference is required to derive the claims`,
      ),
    );
  }
  if (!sdJwt && typeMetadataDocuments.length > 0) {
    diagnostics.push(
      error(
        "type_metadata_not_applicable",
        attestation.name,
        "schemaReferences",
        "SD-JWT VC Type Metadata does not describe an mso_mdoc credential",
      ),
    );
  } else if (typeMetadataDocuments.length > 1) {
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
    ? compileJsonSchema(schemaDocument.json, attestation.name, schemaDocument.record.uri, format)
    : { claims: null, typeIdentifier: null, diagnostics: [] };
  diagnostics.push(...compiled.diagnostics);

  const derived = vctForAttestationName(attestation.name);
  if (derived === null) {
    diagnostics.push(
      error(
        `${label}_unresolved`,
        attestation.name,
        "name",
        "the attestation name has no letters or digits to derive an identifier from",
      ),
    );
  }
  // A schema `vct` or `docType` property constrains the credential type; one pinned value is it.
  const pinned = compiled.typeIdentifier ? pinnedValue(compiled.typeIdentifier) : null;
  const type = pinned ?? derived;
  if (
    schemaDocument &&
    compiled.typeIdentifier &&
    type !== null &&
    scalarValueError(compiled.typeIdentifier, type)
  ) {
    diagnostics.push(
      error(
        `${label}_conflict`,
        attestation.name,
        `${schemaDocument.record.uri}#/properties/${property}`,
        `the JSON Schema does not admit ${label} '${type}'`,
      ),
    );
  }
  const [typeMetadataDocument] = sdJwt ? typeMetadataDocuments : [];
  const typeMetadata = typeMetadataDocument
    ? parseTypeMetadata(typeMetadataDocument, attestation.name, diagnostics)
    : null;
  if (typeMetadata && type !== null && typeMetadata.vct !== type) {
    diagnostics.push(
      error(
        "vct_conflict",
        attestation.name,
        typeMetadataDocument ? `${typeMetadataDocument.record.uri}#/vct` : "vct",
        `Type Metadata states vct '${typeMetadata.vct}', but ${pinned ? "the JSON Schema states" : "the attestation name derives"} '${type}'`,
      ),
    );
  }
  const claims =
    compiled.claims && typeMetadata
      ? refineClaims(compiled.claims, typeMetadata, attestation.name, diagnostics)
      : compiled.claims;

  if (diagnostics.slice(before).some((entry) => entry.severity === "error")) return null;
  if (type === null || derived === null || !schemaDocument || !claims) return null;
  // The configuration id and OAuth scope derive from the name and format: stable across versions,
  // and unique within the rulebook (`duplicate_credential_configuration_id`), like the type.
  const id = `${derived}:${FORMAT_SUFFIX[format]}`;
  const common = {
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
    credentialConfigurationId: id,
    scope: id,
    claims,
    schemaReferences: [schemaDocument, ...(sdJwt ? typeMetadataDocuments : [])].map((document) => ({
      uri: document.record.uri,
      kind: document.record.kind,
      contentDigest: document.record.contentDigest,
      integrity: document.reference.integrity,
      hosted: document.reference.hosted !== null,
    })),
    proofPolicy,
    claimValueProvider: "faker-js" as const,
  };
  const source = pinned ? "json_schema" : "attestation_name";
  if (sdJwt) {
    return {
      ...common,
      format: "dc+sd-jwt",
      vct: type,
      vctSource: source,
      displayName: typeMetadata?.displayName ?? attestation.name,
      claimMetadata: claimMetadata(claims, [], true),
      disclosurePolicy: "issuer-default-selective",
    };
  }
  return {
    ...common,
    format: "mso_mdoc",
    doctype: type,
    doctypeSource: source,
    displayName: attestation.name,
    // OpenID4VCI Appendix C.2: an mdoc claims path starts with the namespace and the data element.
    claimMetadata: claims.properties.flatMap((namespace) =>
      claimMetadata(namespace.node, [namespace.name], namespace.required),
    ),
    disclosurePolicy: "data-element",
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

/** The one value a `vct` or `docType` schema allows: its `const`, or a one-value `enum`'s member. */
function pinnedValue(claim: AttestbookScalarClaim): string | null {
  if (typeof claim.const === "string") return claim.const;
  const [only] = claim.enum ?? [];
  return claim.enum?.length === 1 && typeof only === "string" ? only : null;
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
