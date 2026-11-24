import { SdJwtVcService } from "@credo-ts/core";
import { exportJWK, generateKeyPair } from "jose";
import { createIssuerSigningContext } from "../config.js";
import { resolvedIssuerConfigurations } from "../configurations/registry.js";
import { issuerAppConfig } from "../configurations/resolve-urls.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import { type ImportedCatalogue, credentialRegistry } from "../credentials/registry.js";
import { importedSdJwtCredentialSignOptions } from "../credentials/signing.js";
import { errorMessage } from "../shared/errors.js";
import { isRecord } from "../shared/json.js";
import type { CaptureStore } from "../state.js";
import type { AppConfig, JsonRecord, SessionCapture } from "../types.js";
import {
  AttestbookClient,
  AttestbookContractError,
  type AttestbookPublicationEvent,
  publicationEventOrNull,
} from "./client.js";
import { compileRulebook } from "./compiler.js";
import { CLAIM_GENERATION_REFERENCE_DATE, CLAIM_GENERATOR, generateClaims } from "./generator.js";
import { AttestbookFetchError } from "./http.js";
import {
  AttestbookStateStore,
  type PersistedNotification,
  attestbookStatePath,
} from "./persistence.js";
import {
  AttestbookIntegrityError,
  type SnapshotTrust,
  type VerifiedRulebook,
  verifySnapshot,
} from "./snapshot.js";
import type {
  AttestbookCredentialDefinition,
  AttestbookDiagnostic,
  AttestbookIssuerSummary,
  AttestbookSnapshot,
} from "./types.js";
import {
  PUBLICATION_EVENT_TYPE,
  WEBHOOK_PATH,
  verificationChallengeOrNull,
  webhookSignatureValid,
  webhookTimestampFresh,
} from "./webhook.js";

export type SyncState = "idle" | "fetching" | "validating" | "activating" | "failed";
export type SyncTrigger = "startup" | "webhook" | "manual" | "retry";
/** Where a synchronization stopped; each names a distinct operator diagnosis. */
type SyncFailureStage = "fetch" | "verify" | "compile" | "issuability" | "activate" | "persist";

export interface SyncFailure {
  readonly stage: SyncFailureStage;
  readonly code: string;
  readonly message: string;
  readonly at: string;
  readonly version: string | null;
  readonly content_digest: string | null;
}

export interface ObservedEvent {
  readonly event_id: string;
  readonly version: string;
  readonly content_digest: string;
  readonly published_at: string;
  readonly observed_at: string;
  readonly source: "webhook" | "event_feed";
}

export interface WebhookResult {
  readonly status: number;
  readonly body: JsonRecord;
}

/** Structured, secret-free log sink; one JSON object per integration event. */
export type AttestbookLogger = (event: string, fields: JsonRecord) => void;

const defaultLogger: AttestbookLogger = (event, fields) => {
  console.info(
    JSON.stringify({ at: new Date().toISOString(), component: "attestbook", event, ...fields }),
  );
};

const RETRY_BASE_MS = 5_000;
const RETRY_MAX_MS = 5 * 60_000;
const MAX_RETRIES = 8;

class SyncStageError extends Error {
  constructor(
    readonly stage: SyncFailureStage,
    readonly code: string,
    message: string,
    readonly diagnostics: readonly AttestbookDiagnostic[] = [],
  ) {
    super(message);
  }
}

const integrations = new WeakMap<CaptureStore, AttestbookIntegration>();

export interface AttestbookIntegrationOptions {
  readonly fetch?: typeof fetch;
  readonly logger?: AttestbookLogger;
}

/** The store's integration; options apply only when it is first created. */
export function attestbookIntegration(
  config: AppConfig,
  store: CaptureStore,
  options: AttestbookIntegrationOptions = {},
): AttestbookIntegration {
  let integration = integrations.get(store);
  if (!integration) {
    integration = new AttestbookIntegration(config, store, options);
    integrations.set(store, integration);
  }
  return integration;
}

/**
 * Keeps the experimental issuer's imported catalogue in line with the subscribed rulebook. A signed
 * webhook or a restart only triggers a reconciliation; what is activated is always the latest
 * publication of the authoritative event feed, after its bytes, schema documents, compilation and
 * a dry-run Credo-TS signature have all succeeded. Any failure keeps the last-known-good catalogue.
 */
export class AttestbookIntegration {
  readonly issuer: ResolvedIssuerConfiguration;
  private readonly trust: SnapshotTrust;
  private readonly client: AttestbookClient;
  private readonly persistence: AttestbookStateStore;
  private readonly logger: AttestbookLogger;
  private queue: Promise<unknown> = Promise.resolve();
  private retryTimer: NodeJS.Timeout | null = null;
  private retryAttempts = 0;
  private restored = false;

  private state: SyncState = "idle";
  private lastTrigger: SyncTrigger | null = null;
  private failure: SyncFailure | null = null;
  private diagnostics: readonly AttestbookDiagnostic[] = [];
  private lastObservedEvent: ObservedEvent | null = null;
  private lastSuccessfulSyncAt: string | null = null;
  private lastVerificationChallengeAt: string | null = null;
  private lastSignedNotificationAt: string | null = null;
  private pendingNotifications = 0;
  /** Content digests whose verification or compilation failed; not retried automatically. */
  private readonly rejectedDigests = new Map<string, SyncFailure>();

  constructor(
    private readonly config: AppConfig,
    private readonly store: CaptureStore,
    options: AttestbookIntegrationOptions = {},
  ) {
    const { base_url: origin, rulebook_id: rulebookId } = config.attestbook;
    if (!config.attestbook.enabled || !origin || !rulebookId) {
      throw new Error("The Attestbook integration is not enabled");
    }
    const issuer = resolvedIssuerConfigurations(config).find(
      (candidate) => candidate.importsAttestbookCredentials,
    );
    if (!issuer) throw new Error("No issuer imports Attestbook credentials");
    this.issuer = issuer;
    this.trust = {
      origin,
      rulebookId,
      allowedSchemaOrigins: config.attestbook.allowed_schema_origins,
    };
    this.client = new AttestbookClient(this.trust, options.fetch);
    this.persistence = new AttestbookStateStore(attestbookStatePath(config.data_dir), {
      origin,
      rulebookId,
    });
    this.logger = options.logger ?? defaultLogger;
  }

  get callbackUrl(): string {
    return `${this.config.public_base_url}${WEBHOOK_PATH}`;
  }

  get syncState(): SyncState {
    return this.state;
  }

  /**
   * Restores the last-known-good catalogue from disk, without contacting Attestbook. It runs
   * before the Credo-TS issuer record is created, so the record starts with those credentials.
   * A persisted snapshot that no longer verifies or compiles is not advertised.
   */
  async restore(): Promise<void> {
    if (this.restored) return;
    this.restored = true;
    const { state, warning } = await this.persistence.load();
    if (warning) this.logger("recovery_state_ignored", { reason: warning });
    this.lastSuccessfulSyncAt = state.last_successful_sync_at;
    this.pendingNotifications = state.notifications.filter(
      (entry) => entry.status === "pending",
    ).length;
    const lastNotification = state.notifications.at(-1);
    if (lastNotification) this.lastObservedEvent = observedFromNotification(lastNotification);
    if (!state.active) {
      this.logger("recovery_no_snapshot", {});
      return;
    }
    try {
      const catalogue = await this.prepareCatalogue(
        state.active.snapshot,
        state.active.activated_at,
      );
      await credentialRegistry(this.config, this.store).activate(catalogue);
      this.logger("recovery_restored", catalogueLogFields(catalogue));
    } catch (error) {
      const failure = this.recordFailure(error, state.active.snapshot);
      this.logger("recovery_failed", { ...failureLogFields(failure) });
    }
  }

  /** Begins the startup reconciliation that discovers publications missed while offline. */
  start(): void {
    void this.reconcile("startup").catch(() => undefined);
  }

  /** Resolves when no reconciliation is queued or running. */
  async idle(): Promise<void> {
    let observed: Promise<unknown>;
    do {
      observed = this.queue;
      await observed.catch(() => undefined);
    } while (observed !== this.queue);
  }

  /** Reconciles against the authoritative event feed; one reconciliation runs at a time. */
  reconcile(trigger: SyncTrigger): Promise<void> {
    const run = this.queue.then(() => this.runReconcile(trigger));
    this.queue = run.catch(() => undefined);
    return run;
  }

  /** Handles one callback request; the raw body bytes are what the signature commits to. */
  async handleWebhook(
    rawBody: Buffer,
    header: (name: string) => string | undefined,
  ): Promise<WebhookResult> {
    let body: unknown;
    try {
      body = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return reject(400, "invalid_request", "body is not JSON");
    }
    if (!isRecord(body)) return reject(400, "invalid_request", "body is not a JSON object");

    if (
      header("x-attestbook-event-type") === undefined &&
      header("x-attestbook-signature") === undefined
    ) {
      const challenge = verificationChallengeOrNull(body, Date.now());
      if (!challenge) return reject(400, "invalid_request", "not a valid verification challenge");
      this.lastVerificationChallengeAt = new Date().toISOString();
      this.logger("subscription_verification_answered", {});
      return { status: 200, body: { challenge } };
    }

    if (header("x-attestbook-event-type") !== PUBLICATION_EVENT_TYPE) {
      return reject(
        400,
        "unsupported_event_type",
        "only rulebook.published notifications are accepted",
      );
    }
    const secret = this.config.attestbook.webhook_secret;
    if (!secret) {
      this.logger("notification_refused", { reason: "webhook_secret_not_configured" });
      return reject(
        503,
        "webhook_secret_not_configured",
        "the subscription webhook secret is not configured",
      );
    }
    const eventId = header("x-attestbook-event-id");
    const timestamp = header("x-attestbook-timestamp");
    const signature = header("x-attestbook-signature");
    if (!eventId || !timestamp || !signature) {
      return reject(400, "invalid_request", "signature headers are missing");
    }
    if (!webhookSignatureValid({ secret, timestamp, eventId, body: rawBody, signature })) {
      this.logger("notification_rejected", { reason: "invalid_signature" });
      return reject(401, "invalid_signature", "the notification signature is not valid");
    }
    if (!webhookTimestampFresh(timestamp, Date.now())) {
      this.logger("notification_rejected", { reason: "stale_timestamp" });
      return reject(
        401,
        "stale_timestamp",
        "the delivery timestamp is outside the accepted window",
      );
    }
    const event = publicationEventOrNull(body);
    if (!event) return reject(400, "invalid_event", "the body is not a rulebook publication event");
    if (event.id !== eventId) {
      return reject(400, "event_id_mismatch", "the event id header and body disagree");
    }
    if (event.rulebookId !== this.trust.rulebookId) {
      this.logger("notification_rejected", {
        reason: "rulebook_not_subscribed",
        event_id: event.id,
      });
      return reject(
        403,
        "rulebook_not_subscribed",
        "the notification is for a rulebook that is not configured",
      );
    }

    const receivedAt = new Date().toISOString();
    let duplicate = false;
    try {
      await this.persistence.update((state) => {
        duplicate = state.notifications.some((entry) => entry.event_id === event.id);
        if (duplicate) return state;
        return {
          ...state,
          notifications: [
            ...state.notifications,
            {
              event_id: event.id,
              version: event.version,
              content_digest: event.contentDigest,
              published_at: event.publishedAt,
              received_at: receivedAt,
              delivery_timestamp: timestamp,
              raw_body_base64: rawBody.toString("base64"),
              status: "pending",
              processed_at: null,
              outcome: null,
            },
          ],
        };
      });
    } catch {
      this.logger("notification_not_recorded", { event_id: event.id });
      return reject(
        503,
        "notification_not_recorded",
        "the notification could not be recorded durably",
      );
    }
    this.lastSignedNotificationAt = receivedAt;
    if (duplicate) {
      this.logger("notification_duplicate", { event_id: event.id });
      return { status: 200, body: { status: "duplicate", event_id: event.id } };
    }
    this.pendingNotifications += 1;
    this.observe(event, "webhook");
    this.logger("notification_received", {
      event_id: event.id,
      version: event.version,
      content_digest: event.contentDigest,
    });
    void this.reconcile("webhook").catch(() => undefined);
    return { status: 202, body: { status: "accepted", event_id: event.id } };
  }

  /**
   * Pins a session to the imported definition it is issued under, with synthetic claim values
   * seeded by the session id and recorded with everything needed to regenerate them. Done before
   * the session is offered or authorized, so it never exists without its values.
   */
  pinSession(session: SessionCapture, definition: AttestbookCredentialDefinition): void {
    session.credential_definition = {
      source: "attestbook",
      origin: definition.origin,
      rulebook_id: definition.rulebookId,
      version: definition.version,
      content_digest: definition.contentDigest,
      attestation: definition.attestation.name,
      vct: definition.vct,
      vct_source: definition.vctSource,
    };
    this.store.addEvent(session, "credential_definition_pinned", {
      ...session.credential_definition,
    });
    session.generated_claims = {
      generator: CLAIM_GENERATOR,
      seed: session.session_id,
      reference_date: CLAIM_GENERATION_REFERENCE_DATE,
      claims: generateClaims(definition, session.session_id),
    };
    this.store.addEvent(session, "credential_claims_generated", {
      generator: session.generated_claims.generator,
      seed: session.generated_claims.seed,
    });
  }

  /** The operator UI's one-line view of the integration. */
  summary(): AttestbookIssuerSummary {
    const active = credentialRegistry(this.config, this.store).activeCatalogue(this.issuer.id);
    return {
      syncState: this.state,
      activeVersion: active?.version ?? null,
      activeContentDigest: active?.contentDigest ?? null,
      failureStage: this.failure?.stage ?? null,
    };
  }

  /** Non-sensitive integration status: no secret, token, key or claim value. */
  status(): JsonRecord {
    const registry = credentialRegistry(this.config, this.store);
    const active = registry.activeCatalogue(this.issuer.id);
    return {
      enabled: true,
      issuer_configuration_id: this.issuer.id,
      origin: this.trust.origin,
      rulebook_id: this.trust.rulebookId,
      subscription: {
        callback_url: this.callbackUrl,
        webhook_secret_configured: Boolean(this.config.attestbook.webhook_secret),
        manual_sync_enabled: Boolean(this.config.attestbook.admin_token),
        last_verification_challenge_at: this.lastVerificationChallengeAt,
        last_signed_notification_at: this.lastSignedNotificationAt,
      },
      last_observed_event: this.lastObservedEvent as JsonRecord | null,
      pending_notifications: this.pendingNotifications,
      active: active
        ? {
            version: active.version,
            content_digest: active.contentDigest,
            published_at: active.publishedAt,
            event_id: active.eventId,
            activated_at: active.activatedAt,
            credential_configuration_ids: active.definitions.map(
              (definition) => definition.credentialConfigurationId,
            ),
          }
        : null,
      last_successful_sync_at: this.lastSuccessfulSyncAt,
      sync: {
        state: this.state,
        last_trigger: this.lastTrigger,
        failure: this.failure as JsonRecord | null,
        diagnostics: this.diagnostics as unknown as JsonRecord[],
      },
    };
  }

  private async runReconcile(trigger: SyncTrigger): Promise<void> {
    this.lastTrigger = trigger;
    this.state = "fetching";
    this.logger("sync_started", { trigger });
    let latest: AttestbookPublicationEvent | undefined;
    try {
      const events = await this.client.publicationEvents().catch((error: unknown) => {
        throw fetchStageError(error);
      });
      latest = events.at(-1);
      if (!latest) {
        throw new SyncStageError(
          "fetch",
          "no_publication",
          "the rulebook has no publication event yet",
        );
      }
      this.observe(latest, "event_feed");
      const registry = credentialRegistry(this.config, this.store);
      const active = registry.activeCatalogue(this.issuer.id);
      if (active?.contentDigest === latest.contentDigest && active.version === latest.version) {
        await this.completeSync("up_to_date", trigger);
        return;
      }
      const rejected = this.rejectedDigests.get(latest.contentDigest);
      if (rejected && trigger !== "manual") {
        this.failure = rejected;
        this.state = "failed";
        await this.markNotificationsProcessed(`rejected:${rejected.code}`);
        this.logger("sync_skipped_rejected", { ...failureLogFields(rejected) });
        return;
      }
      const snapshot = await this.client.downloadSnapshot(latest).catch((error: unknown) => {
        throw fetchStageError(error);
      });
      this.logger("snapshot_verified", {
        version: snapshot.version,
        content_digest: snapshot.contentDigest,
        schema_documents: snapshot.schemaDocuments.length,
      });
      this.state = "validating";
      const catalogue = await this.prepareCatalogue(snapshot, new Date().toISOString());
      this.state = "activating";
      try {
        await registry.activate(catalogue);
      } catch (error) {
        throw new SyncStageError("activate", "activation_failed", errorMessage(error));
      }
      this.logger("catalogue_activated", catalogueLogFields(catalogue));
      try {
        await this.persistence.update((state) => ({
          ...state,
          active: { snapshot, activated_at: catalogue.activatedAt },
        }));
      } catch (error) {
        throw new SyncStageError("persist", "persist_failed", errorMessage(error));
      }
      await this.completeSync("activated", trigger);
    } catch (error) {
      const failure = this.recordFailure(error, null, latest);
      this.logger(failure.stage === "activate" ? "activation_rolled_back" : "sync_failed", {
        trigger,
        ...failureLogFields(failure),
      });
      if (
        failure.stage === "verify" ||
        failure.stage === "compile" ||
        failure.stage === "issuability"
      ) {
        this.rejectedDigests.set(failure.content_digest ?? "", failure);
        await this.markNotificationsProcessed(`rejected:${failure.code}`).catch(() => undefined);
      } else {
        this.scheduleRetry();
      }
      throw error;
    }
  }

  /**
   * Verifies, compiles and proves a snapshot issuable before anything about it becomes visible:
   * each definition needs a claim fixture that satisfies it, and a dry-run signature through the
   * same Credo-TS SD-JWT VC signer issuance uses must succeed.
   */
  private async prepareCatalogue(
    snapshot: AttestbookSnapshot,
    activatedAt: string,
  ): Promise<ImportedCatalogue> {
    let verified: VerifiedRulebook;
    try {
      verified = verifySnapshot(snapshot, this.trust);
    } catch (error) {
      throw new SyncStageError(
        "verify",
        error instanceof AttestbookIntegrityError ? error.code : "integrity_failed",
        errorMessage(error),
      );
    }
    const compiled = compileRulebook(verified, this.issuer.proofPolicy);
    this.diagnostics = compiled.diagnostics;
    if (compiled.definitions.length === 0) {
      throw new SyncStageError(
        "compile",
        "credential_unsupported",
        `rulebook ${snapshot.version} has no issuable SD-JWT VC credential definition`,
        compiled.diagnostics,
      );
    }
    this.logger("rulebook_compiled", {
      version: snapshot.version,
      definitions: compiled.definitions.length,
      diagnostics: compiled.diagnostics.length,
    });
    const issuability: AttestbookDiagnostic[] = [];
    for (const definition of compiled.definitions) {
      let claims: JsonRecord;
      try {
        // A seed fixed by the version, so a constraint no generated value can meet is found here.
        claims = generateClaims(
          definition,
          `${definition.contentDigest}:${definition.credentialConfigurationId}`,
        );
      } catch (error) {
        issuability.push({
          severity: "error",
          code: "claim_generation_failed",
          attestation: definition.attestation.name,
          field: "claims",
          message: errorMessage(error),
        });
        continue;
      }
      try {
        await this.dryRunSign(definition, claims);
      } catch (error) {
        issuability.push({
          severity: "error",
          code: "dry_run_signing_failed",
          attestation: definition.attestation.name,
          field: null,
          message: errorMessage(error),
        });
      }
    }
    if (issuability.length > 0) {
      this.diagnostics = [...compiled.diagnostics, ...issuability];
      throw new SyncStageError(
        "issuability",
        "credential_not_issuable",
        `rulebook ${snapshot.version} defines a credential this issuer cannot issue`,
        this.diagnostics,
      );
    }
    return {
      issuerId: this.issuer.id,
      origin: snapshot.origin,
      rulebookId: snapshot.rulebookId,
      version: snapshot.version,
      contentDigest: snapshot.contentDigest,
      publishedAt: snapshot.publishedAt,
      eventId: snapshot.eventId,
      activatedAt,
      definitions: compiled.definitions,
    };
  }

  private async dryRunSign(
    definition: AttestbookCredentialDefinition,
    claims: JsonRecord,
  ): Promise<void> {
    const { publicKey } = await generateKeyPair("ES256");
    const signingConfig = issuerAppConfig(this.config, this.issuer);
    const service = new SdJwtVcService({} as never);
    const signed = await service.sign(
      createIssuerSigningContext(signingConfig) as never,
      importedSdJwtCredentialSignOptions({
        config: signingConfig,
        holderJwk: (await exportJWK(publicKey)) as unknown as JsonRecord,
        definition,
        claims,
      }),
    );
    if (service.fromCompact(signed.compact).prettyClaims.vct !== definition.vct) {
      throw new Error("dry-run credential does not carry the definition's vct");
    }
  }

  private async completeSync(
    outcome: "up_to_date" | "activated",
    trigger: SyncTrigger,
  ): Promise<void> {
    const now = new Date().toISOString();
    this.state = "idle";
    this.failure = null;
    this.lastSuccessfulSyncAt = now;
    this.retryAttempts = 0;
    await this.persistence.update((state) => ({ ...state, last_successful_sync_at: now }));
    await this.markNotificationsProcessed(outcome);
    this.logger("sync_completed", { trigger, outcome });
  }

  private async markNotificationsProcessed(outcome: string): Promise<void> {
    const now = new Date().toISOString();
    await this.persistence.update((state) => ({
      ...state,
      notifications: state.notifications.map((entry) =>
        entry.status === "pending"
          ? { ...entry, status: "processed", processed_at: now, outcome }
          : entry,
      ),
    }));
    this.pendingNotifications = 0;
  }

  private scheduleRetry(): void {
    if (this.pendingNotifications === 0 || this.retryTimer || this.retryAttempts >= MAX_RETRIES)
      return;
    const delay = Math.min(RETRY_BASE_MS * 2 ** this.retryAttempts, RETRY_MAX_MS);
    this.retryAttempts += 1;
    this.logger("sync_retry_scheduled", { attempt: this.retryAttempts, delay_ms: delay });
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.reconcile("retry").catch(() => undefined);
    }, delay);
    this.retryTimer.unref();
  }

  private observe(event: AttestbookPublicationEvent, source: ObservedEvent["source"]): void {
    if (
      this.lastObservedEvent &&
      Date.parse(this.lastObservedEvent.published_at) > Date.parse(event.publishedAt)
    ) {
      return;
    }
    this.lastObservedEvent = {
      event_id: event.id,
      version: event.version,
      content_digest: event.contentDigest,
      published_at: event.publishedAt,
      observed_at: new Date().toISOString(),
      source,
    };
  }

  private recordFailure(
    error: unknown,
    snapshot: AttestbookSnapshot | null,
    event?: AttestbookPublicationEvent,
  ): SyncFailure {
    const stageError =
      error instanceof SyncStageError
        ? error
        : new SyncStageError("activate", "unexpected_error", errorMessage(error));
    if (stageError.diagnostics.length > 0) this.diagnostics = stageError.diagnostics;
    this.state = "failed";
    this.failure = {
      stage: stageError.stage,
      code: stageError.code,
      message: stageError.message,
      at: new Date().toISOString(),
      version: snapshot?.version ?? event?.version ?? null,
      content_digest: snapshot?.contentDigest ?? event?.contentDigest ?? null,
    };
    return this.failure;
  }
}

function fetchStageError(error: unknown): SyncStageError {
  if (error instanceof SyncStageError) return error;
  if (error instanceof AttestbookIntegrityError)
    return new SyncStageError("verify", error.code, error.message);
  if (error instanceof AttestbookFetchError)
    return new SyncStageError("fetch", error.code, error.message);
  if (error instanceof AttestbookContractError) {
    return new SyncStageError("fetch", "contract_violation", error.message);
  }
  return new SyncStageError("fetch", "fetch_failed", errorMessage(error));
}

function reject(status: number, error: string, description: string): WebhookResult {
  return { status, body: { error, error_description: description } };
}

function observedFromNotification(entry: PersistedNotification): ObservedEvent {
  return {
    event_id: entry.event_id,
    version: entry.version,
    content_digest: entry.content_digest,
    published_at: entry.published_at,
    observed_at: entry.received_at,
    source: "webhook",
  };
}

function catalogueLogFields(catalogue: ImportedCatalogue): JsonRecord {
  return {
    version: catalogue.version,
    content_digest: catalogue.contentDigest,
    credential_configuration_ids: catalogue.definitions.map(
      (definition) => definition.credentialConfigurationId,
    ),
  };
}

function failureLogFields(failure: SyncFailure): JsonRecord {
  return {
    stage: failure.stage,
    code: failure.code,
    message: failure.message,
    version: failure.version,
    content_digest: failure.content_digest,
  };
}
