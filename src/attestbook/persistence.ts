import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { isRecord } from "./snapshot.js";
import type { AttestbookSnapshot } from "./types.js";

const STATE_FORMAT = "credimi.attestbook-state@1";
/** Bound on remembered notifications; deduplication beyond it falls back to the event feed. */
const MAX_NOTIFICATIONS = 500;

/** A verified publication notification, durably recorded before it was acknowledged. */
export interface PersistedNotification {
  readonly event_id: string;
  readonly version: string;
  readonly content_digest: string;
  readonly published_at: string;
  readonly received_at: string;
  /** `X-AttestBook-Timestamp` of the accepted delivery attempt. */
  readonly delivery_timestamp: string;
  /** The exact request body bytes, preserved as captured evidence. */
  readonly raw_body_base64: string;
  readonly status: "pending" | "processed";
  readonly processed_at: string | null;
  readonly outcome: string | null;
}

export interface PersistedAttestbookState {
  readonly format: typeof STATE_FORMAT;
  readonly origin: string;
  readonly rulebook_id: string;
  /** The last successfully activated snapshot: the last-known-good catalogue. */
  readonly active: { readonly snapshot: AttestbookSnapshot; readonly activated_at: string } | null;
  readonly notifications: readonly PersistedNotification[];
  readonly last_successful_sync_at: string | null;
}

export function attestbookStatePath(dataDir: string): string {
  return join(dataDir, "attestbook", "state.json");
}

/**
 * The integration's durable state under the data directory. Every write replaces the file
 * atomically (write, fsync, rename), so a crash leaves either the previous or the new state and
 * never a torn file. Writes are serialized.
 */
export class AttestbookStateStore {
  private writes: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly path: string,
    private readonly identity: { readonly origin: string; readonly rulebookId: string },
  ) {}

  /**
   * The persisted state, or an empty one. A file for another origin or rulebook, or one that
   * cannot be read, is not trusted; an unreadable file is moved aside so it is kept for diagnosis.
   */
  async load(): Promise<{ state: PersistedAttestbookState; warning: string | null }> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT")
        return { state: this.empty(), warning: null };
      throw error;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    if (
      !isRecord(parsed) ||
      parsed.format !== STATE_FORMAT ||
      !Array.isArray(parsed.notifications) ||
      !(parsed.active === null || isRecord(parsed.active))
    ) {
      await rename(this.path, `${this.path}.unreadable-${Date.now()}`);
      return {
        state: this.empty(),
        warning: "persisted state was unreadable and has been set aside",
      };
    }
    if (parsed.origin !== this.identity.origin || parsed.rulebook_id !== this.identity.rulebookId) {
      return {
        state: this.empty(),
        warning: "persisted state belongs to another Attestbook origin or rulebook and is ignored",
      };
    }
    return { state: parsed as unknown as PersistedAttestbookState, warning: null };
  }

  /** Applies a change to the latest persisted state and writes it atomically. */
  update(
    change: (state: PersistedAttestbookState) => PersistedAttestbookState,
  ): Promise<PersistedAttestbookState> {
    const result = this.writes.then(async () => {
      const { state } = await this.load();
      const next = change(state);
      await this.write({ ...next, notifications: next.notifications.slice(-MAX_NOTIFICATIONS) });
      return next;
    });
    this.writes = result.catch(() => undefined);
    return result;
  }

  private async write(state: PersistedAttestbookState): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    const handle = await open(temporary, "w", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, this.path);
  }

  private empty(): PersistedAttestbookState {
    return {
      format: STATE_FORMAT,
      origin: this.identity.origin,
      rulebook_id: this.identity.rulebookId,
      active: null,
      notifications: [],
      last_successful_sync_at: null,
    };
  }
}
