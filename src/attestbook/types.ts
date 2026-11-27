import type { CredentialProofPolicy } from "../types.js";

export interface AttestbookIssuerSummary {
  readonly syncState: AttestbookSyncState;
  readonly activeVersion: string | null;
  readonly activeContentDigest: string | null;
  readonly failureStage: AttestbookSyncFailureStage | null;
}

/** Kinds of schema documents a compiled definition can be built from. */
export type AttestbookSchemaKind = "json_schema_2020_12" | "sd_jwt_vc_type_metadata";

/** One schema reference frozen in a rulebook version, as Attestbook reports it. */
export interface AttestbookSchemaReference {
  /** Attestation type name, or null for a rulebook-level reference. */
  readonly attestation: string | null;
  readonly formatIdentifier: string;
  readonly uri: string;
  /** W3C SRI pin frozen in the snapshot, or null when the provider recorded none. */
  readonly integrity: string | null;
  /** Present when the URI is a document Attestbook hosts immutably. */
  readonly hosted: {
    readonly kind: AttestbookSchemaKind;
    readonly contentDigest: string;
    readonly integrity: string;
  } | null;
}

/** The exact bytes of one fetched schema document. */
export interface AttestbookSchemaDocumentRecord {
  readonly uri: string;
  readonly kind: AttestbookSchemaKind;
  /** Lowercase hex SHA-256 of `base64`'s bytes. */
  readonly contentDigest: string;
  readonly base64: string;
}

/**
 * An integrity-verified, immutable published rulebook version together with every schema
 * document its SD-JWT VC attestation types reference. It is what is persisted as the
 * last-known-good catalogue and is re-verified whenever it is loaded.
 */
export interface AttestbookSnapshot {
  readonly format: "credimi.attestbook-snapshot@1";
  readonly origin: string;
  readonly rulebookId: string;
  readonly version: string;
  readonly contentDigest: string;
  readonly publishedAt: string | null;
  /** The publication event the snapshot was retrieved for, when known. */
  readonly eventId: string | null;
  readonly retrievedAt: string;
  /** Exact exported rulebook version bytes. */
  readonly rulebookBase64: string;
  readonly schemaReferences: readonly AttestbookSchemaReference[];
  readonly schemaDocuments: readonly AttestbookSchemaDocumentRecord[];
}

/** One `attestbook.rulebook-version@1` attestation type. */
export interface AttestbookRulebookAttestation {
  readonly name: string;
  readonly attestationLoS: string;
  readonly bindingType: string;
  readonly supportedFormats: readonly string[];
  readonly schemaReferences: readonly {
    readonly formatIdentifier: string;
    readonly uri: string;
    readonly integrity: string | null;
  }[];
}

/** The parsed `attestbook.rulebook-version@1` document. */
export interface AttestbookRulebookDocument {
  readonly format: "attestbook.rulebook-version@1";
  readonly rulebookId: string;
  readonly version: string;
  readonly specVersion: string;
  readonly name: string;
  readonly description: string;
  readonly sourceUrl: string | null;
  readonly attestations: readonly AttestbookRulebookAttestation[];
}

export type AttestbookScalarType = "string" | "integer" | "number" | "boolean";
export type AttestbookScalarValue = string | number | boolean;

interface AttestbookClaimNodeBase {
  /** Display label from the schema `title`, refined by Type Metadata `display`. */
  readonly displayName: string | null;
  /**
   * Whether this claim is selectively disclosable where it appears: as an object member, or as
   * each element of its array. The issuer default is true, refined by Type Metadata `sd`.
   */
  readonly selectivelyDisclosable: boolean;
  /** Whether the schema `type` also admits `null` (a type array naming `"null"`). */
  readonly nullable?: boolean;
}

export interface AttestbookScalarClaim extends AttestbookClaimNodeBase {
  readonly kind: "scalar";
  /** The non-null types the value may have: one, or several from a schema type array. */
  readonly types: readonly AttestbookScalarType[];
  readonly enum?: readonly (AttestbookScalarValue | null)[];
  readonly const?: AttestbookScalarValue | null;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly exclusiveMinimum?: number;
  readonly exclusiveMaximum?: number;
}

export interface AttestbookClaimProperty {
  readonly name: string;
  readonly required: boolean;
  readonly node: AttestbookClaimNode;
}

export interface AttestbookObjectClaim extends AttestbookClaimNodeBase {
  readonly kind: "object";
  readonly properties: readonly AttestbookClaimProperty[];
  readonly additionalProperties: boolean;
  readonly minProperties?: number;
}

export interface AttestbookArrayClaim extends AttestbookClaimNodeBase {
  readonly kind: "array";
  readonly items: AttestbookClaimNode;
  readonly minItems?: number;
  readonly maxItems?: number;
}

export type AttestbookClaimNode =
  | AttestbookScalarClaim
  | AttestbookObjectClaim
  | AttestbookArrayClaim;

/** An OpenID4VCI claims path: a member name, or null for every element of an array. */
export type AttestbookClaimPath = readonly (string | null)[];

/** One `credential_metadata.claims` entry the issuer advertises. */
export interface AttestbookClaimMetadata {
  readonly path: AttestbookClaimPath;
  readonly mandatory: boolean;
  readonly displayName: string | null;
}

interface AttestbookValidatedSchemaReference {
  readonly uri: string;
  readonly kind: AttestbookSchemaKind;
  readonly contentDigest: string;
  readonly integrity: string | null;
  readonly hosted: boolean;
}

/**
 * The executable form of one attestation type. Everything a session needs to issue it is pinned
 * here, so an issuance completes under the exact definition it was offered with.
 */
export interface AttestbookCredentialDefinition {
  readonly origin: string;
  readonly rulebookId: string;
  readonly version: string;
  readonly contentDigest: string;
  readonly attestation: {
    readonly name: string;
    readonly index: number;
    readonly attestationLoS: string;
    readonly bindingType: string;
  };
  /** Derived from the attestation name: `urn:attestbook:<slug>`. */
  readonly credentialConfigurationId: string;
  readonly scope: string;
  readonly format: "dc+sd-jwt";
  readonly vct: string;
  /**
   * `json_schema` when the schema's `vct` property pins one value (`const`, or a one-member
   * `enum`); otherwise `attestation_name`, and the vct equals the credential configuration id.
   */
  readonly vctSource: AttestbookVctSource;
  readonly displayName: string;
  /** The credential's claim structure: the root object of the issued payload. */
  readonly claims: AttestbookObjectClaim;
  readonly claimMetadata: readonly AttestbookClaimMetadata[];
  readonly schemaReferences: readonly AttestbookValidatedSchemaReference[];
  /** The importing issuer's proof policy. */
  readonly proofPolicy: CredentialProofPolicy;
  readonly claimValueProvider: "faker-js";
  readonly disclosurePolicy: "issuer-default-selective";
}

type AttestbookVctSource = "attestation_name" | "json_schema";

type AttestbookDiagnosticSeverity = "error" | "info";

/** A typed compilation or validation finding, naming the attestation and field it concerns. */
export interface AttestbookDiagnostic {
  readonly severity: AttestbookDiagnosticSeverity;
  readonly code: string;
  readonly attestation: string | null;
  readonly field: string | null;
  readonly message: string;
}

export type AttestbookSyncState = "idle" | "fetching" | "validating" | "activating" | "failed";

export type AttestbookSyncTrigger = "startup" | "webhook" | "manual" | "retry";

/** Where a synchronization stopped; each names a distinct operator diagnosis. */
export type AttestbookSyncFailureStage =
  | "fetch"
  | "verify"
  | "compile"
  | "issuability"
  | "activate"
  | "persist";

export interface AttestbookSyncFailure {
  readonly stage: AttestbookSyncFailureStage;
  readonly code: string;
  readonly message: string;
  readonly at: string;
  readonly version: string | null;
  readonly content_digest: string | null;
}

export interface AttestbookObservedEvent {
  readonly event_id: string;
  readonly version: string;
  readonly content_digest: string;
  readonly published_at: string;
  readonly observed_at: string;
  readonly source: "webhook" | "event_feed";
}

export interface AttestbookSyncStatus {
  // Keep status assignable to JsonRecord for existing status-route consumers.
  readonly [key: string]: unknown;
  readonly enabled: true;
  readonly issuer_configuration_id: string;
  readonly origin: string;
  readonly rulebook_id: string;
  readonly subscription: {
    readonly callback_url: string;
    readonly webhook_secret_configured: boolean;
    readonly manual_sync_enabled: boolean;
    readonly last_verification_challenge_at: string | null;
    readonly last_signed_notification_at: string | null;
  };
  readonly last_observed_event: AttestbookObservedEvent | null;
  readonly pending_notifications: number;
  readonly active: {
    readonly version: string;
    readonly content_digest: string;
    readonly published_at: string | null;
    readonly event_id: string | null;
    readonly activated_at: string;
    readonly credential_configuration_ids: readonly string[];
  } | null;
  readonly last_successful_sync_at: string | null;
  readonly sync: {
    readonly state: AttestbookSyncState;
    readonly last_trigger: AttestbookSyncTrigger | null;
    readonly failure: AttestbookSyncFailure | null;
    readonly diagnostics: readonly AttestbookDiagnostic[];
  };
}
