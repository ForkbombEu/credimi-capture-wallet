import type { AttestbookCredentialDefinition } from "./attestbook/types.js";
import { resolvedIssuerConfigurationById } from "./configurations/registry.js";
import type { IssuerConfiguration, ResolvedIssuerConfiguration } from "./configurations/types.js";
import { type SupportedCredential, supportedCredentialsForIssuer } from "./metadata.js";
import type { CaptureStore } from "./state.js";
import type { AppConfig, SessionCapture } from "./types.js";

/**
 * How long an unfinished issuance session keeps the definition it was offered with after a newer
 * catalogue replaces it. It bounds the lifetime of an abandoned session's pin.
 */
export const RETAINED_SESSION_WINDOW_SECONDS = 3600;

const TERMINAL_SESSION_STATUSES = new Set(["credential_issued", "error"]);

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

interface IssuerImports {
  readonly active: ImportedCatalogue | null;
  /** Earlier definitions still pinned by unfinished sessions, by credential configuration id. */
  readonly retained: ReadonlyMap<string, SupportedCredential>;
}

/** Applies the registry's current credentials to the issuer's real Credo-TS record. */
export type IssuerRecordSynchronizer = (issuer: ResolvedIssuerConfiguration) => Promise<void>;

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
    registry = new CredentialRegistry(config, store);
    registries.set(store, registry);
  }
  return registry;
}

/**
 * The credentials each issuer serves: its static catalogue, the active imported catalogue, and the
 * imported definitions temporarily retained for unfinished sessions. Every change is serialized
 * and applied to the Credo-TS issuer record before it counts as active; a failed application
 * restores the previous, last-known-good state.
 */
export class CredentialRegistry {
  private readonly imports = new Map<string, IssuerImports>();
  private synchronizer: IssuerRecordSynchronizer | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly config: AppConfig,
    private readonly store: CaptureStore,
  ) {}

  /** Credentials a new session may select: static and active imported ones. */
  credentialsForIssuer(issuer: IssuerConfiguration): SupportedCredential[] {
    const active = this.imports.get(issuer.id)?.active;
    return [
      ...supportedCredentialsForIssuer(this.config, issuer),
      ...(active?.definitions.map(importedCredential) ?? []),
    ];
  }

  /** Everything the issuer can issue right now, which is what its metadata advertises. */
  issuableCredentialsForIssuer(issuer: IssuerConfiguration): SupportedCredential[] {
    return [
      ...this.credentialsForIssuer(issuer),
      ...(this.imports.get(issuer.id)?.retained.values() ?? []),
    ];
  }

  credentialForNewSession(
    issuer: IssuerConfiguration,
    credentialConfigurationId: string,
  ): SupportedCredential | null {
    return (
      this.credentialsForIssuer(issuer).find(
        (credential) => credential.id === credentialConfigurationId,
      ) ?? null
    );
  }

  /** The exact definition an existing session is pinned to, active or retained. */
  issuableCredentialById(
    issuer: IssuerConfiguration,
    credentialConfigurationId: string,
  ): SupportedCredential | null {
    return (
      this.issuableCredentialsForIssuer(issuer).find(
        (credential) => credential.id === credentialConfigurationId,
      ) ?? null
    );
  }

  activeCatalogue(issuerId: string): ImportedCatalogue | null {
    return this.imports.get(issuerId)?.active ?? null;
  }

  retainedCredentialIds(issuerId: string): string[] {
    return [...(this.imports.get(issuerId)?.retained.keys() ?? [])];
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
   * Activates a validated catalogue. Definitions of the previous catalogue that unfinished
   * sessions still use stay issuable; nothing else of it survives. If the Credo-TS record cannot
   * be brought in line, the previous state is restored and the error propagates.
   */
  activate(catalogue: ImportedCatalogue): Promise<void> {
    return this.serialize(async () => {
      const issuer = this.importingIssuer(catalogue.issuerId);
      this.assertNoConflicts(issuer, catalogue);
      const previous = this.imports.get(issuer.id) ?? { active: null, retained: new Map() };
      const incoming = new Set(
        catalogue.definitions.map((definition) => definition.credentialConfigurationId),
      );
      const pinned = this.livePinnedCredentialIds(issuer.id);
      const retained = new Map<string, SupportedCredential>();
      for (const credential of [
        ...(previous.active?.definitions.map(importedCredential) ?? []),
        ...previous.retained.values(),
      ]) {
        if (pinned.has(credential.id) && !incoming.has(credential.id)) {
          retained.set(credential.id, credential);
        }
      }
      await this.apply(issuer, { active: catalogue, retained }, previous);
    });
  }

  /** Releases retained definitions no unfinished session uses any more. */
  pruneRetained(issuerId: string): Promise<void> {
    return this.serialize(async () => {
      const issuer = resolvedIssuerConfigurationById(this.config, issuerId);
      const current = this.imports.get(issuerId);
      if (!issuer || !current || current.retained.size === 0) return;
      const pinned = this.livePinnedCredentialIds(issuerId);
      const retained = new Map([...current.retained].filter(([id]) => pinned.has(id)));
      if (retained.size === current.retained.size) return;
      await this.apply(issuer, { active: current.active, retained }, current);
    });
  }

  private async apply(
    issuer: ResolvedIssuerConfiguration,
    next: IssuerImports,
    previous: IssuerImports,
  ): Promise<void> {
    this.imports.set(issuer.id, next);
    if (!this.synchronizer) return;
    try {
      await this.synchronizer(issuer);
    } catch (error) {
      this.imports.set(issuer.id, previous);
      try {
        await this.synchronizer(issuer);
      } catch (restoreError) {
        throw new Error(
          `${errorMessage(error)}; restoring the previous issuer record also failed: ${errorMessage(restoreError)}`,
        );
      }
      throw error;
    }
  }

  private importingIssuer(issuerId: string): ResolvedIssuerConfiguration {
    const issuer = resolvedIssuerConfigurationById(this.config, issuerId);
    if (!issuer?.importsAttestbookCredentials) {
      throw new CatalogueConflictError(
        `Issuer '${issuerId}' does not import Attestbook credentials`,
      );
    }
    return issuer;
  }

  private assertNoConflicts(
    issuer: ResolvedIssuerConfiguration,
    catalogue: ImportedCatalogue,
  ): void {
    const statics = supportedCredentialsForIssuer(this.config, issuer);
    const ids = new Set<string>();
    for (const definition of catalogue.definitions) {
      const id = definition.credentialConfigurationId;
      if (ids.has(id))
        throw new CatalogueConflictError(`Duplicate credential configuration id '${id}'`);
      ids.add(id);
      if (
        statics.some(
          (credential) =>
            credential.id === id ||
            credential.scope === definition.scope ||
            credential.vct === definition.vct,
        )
      ) {
        throw new CatalogueConflictError(
          `Imported credential '${id}' conflicts with a static credential`,
        );
      }
      const retained = this.imports.get(issuer.id)?.retained.get(id);
      if (retained?.attestbook && retained.attestbook.contentDigest !== definition.contentDigest) {
        throw new CatalogueConflictError(
          `Credential configuration id '${id}' names another definition`,
        );
      }
    }
  }

  private livePinnedCredentialIds(issuerId: string): Set<string> {
    const cutoff = Date.now() - RETAINED_SESSION_WINDOW_SECONDS * 1000;
    return new Set(
      [...this.store.sessions.values()]
        .filter(
          (session) =>
            session.issuer_configuration_id === issuerId &&
            !TERMINAL_SESSION_STATUSES.has(session.status) &&
            sessionCreatedAt(session) >= cutoff,
        )
        .map((session) => session.credential_configuration_id),
    );
  }
}

/** The issuer catalogue entry of one compiled definition. */
export function importedCredential(
  definition: AttestbookCredentialDefinition,
): SupportedCredential {
  return {
    id: definition.credentialConfigurationId,
    scope: definition.scope,
    format: definition.format,
    proofPolicy: definition.proofPolicy,
    displayName: definition.displayName,
    vct: definition.vct,
    claimPaths: definition.claims.map((claim) => [...claim.path]),
    attestbook: definition,
  };
}

function sessionCreatedAt(session: SessionCapture): number {
  const created = session.events.find((event) => event.type === "session_created")?.at;
  return created ? Date.parse(created) : 0;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
