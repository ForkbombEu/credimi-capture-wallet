import type { AttestbookCredentialDefinition } from "../attestbook/types.js";
import { resolvedIssuerConfigurationById } from "../configurations/registry.js";
import type { IssuerConfiguration, ResolvedIssuerConfiguration } from "../configurations/types.js";
import { errorMessage } from "../shared/errors.js";
import type { CaptureStore } from "../state.js";
import type { AppConfig } from "../types.js";
import { type SupportedCredential, supportedCredentialsForIssuer } from "./catalogue.js";

/** One activated, integrity-verified rulebook version's credentials for one issuer. */
export interface ImportedCatalogue {
  readonly issuerId: string;
  readonly origin: string;
  readonly rulebookId: string;
  readonly version: string;
  readonly contentDigest: string;
  readonly publishedAt: string | null;
  readonly eventId: string | null;
  readonly activatedAt: string;
  readonly definitions: readonly AttestbookCredentialDefinition[];
}

/** Applies the registry's current credentials to the issuer's real Credo-TS record. */
export type IssuerRecordSynchronizer = (issuer: ResolvedIssuerConfiguration) => Promise<void>;

/** @internal */
export class CatalogueConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CatalogueConflictError";
  }
}

const registries = new WeakMap<CaptureStore, CredentialRegistry>();

export function credentialRegistry(config: AppConfig, store: CaptureStore): CredentialRegistry {
  let registry = registries.get(store);
  if (!registry) {
    registry = new CredentialRegistry(config);
    registries.set(store, registry);
  }
  return registry;
}

/**
 * The credentials each issuer serves: its static catalogue and the active imported catalogue. An
 * imported credential's configuration id is its `vct`, stable across rulebook versions, so only
 * the active version of each is ever served. Every change is serialized and applied to the
 * Credo-TS issuer record before it counts as active; a failed application restores the previous,
 * last-known-good catalogue.
 */
export class CredentialRegistry {
  private readonly imports = new Map<string, ImportedCatalogue>();
  private synchronizer: IssuerRecordSynchronizer | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly config: AppConfig) {}

  /** Everything the issuer serves, which is what its metadata advertises. */
  credentialsForIssuer(issuer: IssuerConfiguration): SupportedCredential[] {
    return [
      ...supportedCredentialsForIssuer(this.config, issuer),
      ...(this.imports.get(issuer.id)?.definitions.map(importedCredential) ?? []),
    ];
  }

  credentialById(
    issuer: IssuerConfiguration,
    credentialConfigurationId: string,
  ): SupportedCredential | null {
    return (
      this.credentialsForIssuer(issuer).find(
        (credential) => credential.id === credentialConfigurationId,
      ) ?? null
    );
  }

  activeCatalogue(issuerId: string): ImportedCatalogue | null {
    return this.imports.get(issuerId) ?? null;
  }

  attachIssuerSynchronizer(synchronizer: IssuerRecordSynchronizer): void {
    this.synchronizer = synchronizer;
  }

  /** Runs one registry-changing or registry-dependent operation at a time. */
  serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation);
    this.queue = result.catch(() => undefined);
    return result;
  }

  /**
   * Activates a validated catalogue in place of the previous one. Sessions created under the
   * previous version are not carried over; their credential request is refused. If the Credo-TS
   * record cannot be brought in line, the previous catalogue is restored and the error propagates.
   */
  activate(catalogue: ImportedCatalogue): Promise<void> {
    return this.serialize(async () => {
      const issuer = resolvedIssuerConfigurationById(this.config, catalogue.issuerId);
      if (!issuer?.importsAttestbookCredentials) {
        throw new CatalogueConflictError(
          `Issuer '${catalogue.issuerId}' does not import Attestbook credentials`,
        );
      }
      this.assertNoConflicts(issuer, catalogue);
      const previous = this.imports.get(issuer.id);
      this.imports.set(issuer.id, catalogue);
      if (!this.synchronizer) return;
      try {
        await this.synchronizer(issuer);
      } catch (error) {
        if (previous) this.imports.set(issuer.id, previous);
        else this.imports.delete(issuer.id);
        try {
          await this.synchronizer(issuer);
        } catch (restoreError) {
          throw new Error(
            `${errorMessage(error)}; restoring the previous issuer record also failed: ${errorMessage(restoreError)}`,
          );
        }
        throw error;
      }
    });
  }

  private assertNoConflicts(issuer: IssuerConfiguration, catalogue: ImportedCatalogue): void {
    const statics = supportedCredentialsForIssuer(this.config, issuer);
    const ids = new Set<string>();
    for (const definition of catalogue.definitions) {
      const id = definition.credentialConfigurationId;
      if (ids.has(id)) {
        throw new CatalogueConflictError(`Duplicate credential configuration id '${id}'`);
      }
      ids.add(id);
      if (
        statics.some(
          (credential) =>
            credential.id === id ||
            credential.scope === definition.scope ||
            (definition.format === "dc+sd-jwt" && credential.vct === definition.vct),
        )
      ) {
        throw new CatalogueConflictError(
          `Imported credential '${id}' conflicts with a static credential`,
        );
      }
    }
  }
}

/** The issuer catalogue entry of one compiled definition. */
function importedCredential(definition: AttestbookCredentialDefinition): SupportedCredential {
  return {
    id: definition.credentialConfigurationId,
    scope: definition.scope,
    format: definition.format,
    proofPolicy: definition.proofPolicy,
    displayName: definition.displayName,
    ...(definition.format === "dc+sd-jwt"
      ? { vct: definition.vct }
      : { doctype: definition.doctype }),
    claimPaths: definition.claimMetadata.map((claim) => claim.path),
    attestbook: definition,
  };
}
