import type { Request, Response } from "express";
import { resolvedIssuerConfigurationById } from "../configurations/registry.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import { unsetJsonPointer } from "../fcaf/json-pointer.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import {
  completeOid4vciRequestCapture,
  createOid4vciRequestCaptures,
  recordResponseBody,
  responseBodyEvidence,
} from "../openid4vci/http-capture.js";
import type { CaptureStore } from "../state.js";
import type {
  AppConfig,
  IssuanceEndpointResponseScenario,
  IssuanceResponseScenario,
  JsonRecord,
  Oid4vciHttpRequestCapture,
} from "../types.js";

export class ServerContext {
  readonly config: AppConfig;
  readonly store: CaptureStore;
  private readonly oid4vciCaptures = new WeakMap<Request, Oid4vciHttpRequestCapture>();

  constructor(config: AppConfig, store: CaptureStore) {
    this.config = config;
    this.store = store;
  }

  capture(req: Request): Oid4vciHttpRequestCapture | undefined {
    return this.oid4vciCaptures.get(req);
  }

  // Every OpenID4VCI request is recorded before any handler runs, and attributed to its capture
  // session there too, so a request Credo-TS rejects still leaves session evidence. A request with
  // no matching route or configured issuer resource is recorded as `unmatched`.
  async captureOid4vciRequest(req: Request, res: Response, unmatched = false): Promise<void> {
    const captures = createOid4vciRequestCaptures(
      req,
      oid4vciRequestIssuerConfigurationId(this.store, req),
    );
    if (unmatched) {
      captures.redacted.unmatched = true;
      captures.full.unmatched = true;
    }
    this.oid4vciCaptures.set(req, captures.redacted);
    this.store.recordOid4vciRequest(captures.redacted, captures.full);
    const responseBody = recordResponseBody(res);
    res.once("finish", () => {
      completeOid4vciRequestCapture(captures.redacted, res, responseBody(), "redacted");
      completeOid4vciRequestCapture(captures.full, res, responseBody(), "full");
    });
    const sessionId = unmatched
      ? unmatchedRequestSessionId(this.store, req)
      : (oid4vciRequestSessionId(this.store, req) ??
        (isCredoSessionEndpoint(req.path)
          ? await (await credoOpenId4VciIssuer(this.config, this.store)).captureSessionIdForRequest(
              req,
            )
          : null));
    if (sessionId) this.store.linkOid4vciRequestToSession(captures.redacted, sessionId);
  }

  markOid4vciRequestUnmatched(req: Request): void {
    const capture = this.oid4vciCaptures.get(req);
    if (!capture) return;
    capture.unmatched = true;
    const fullCapture = this.store.fullOid4vciRequests.get(capture);
    if (fullCapture) fullCapture.unmatched = true;
  }

  matchedIssuerOrNull(req: Request): ResolvedIssuerConfiguration | null {
    const issuer = resolvedIssuerConfigurationById(this.config, req.params.issuerConfigurationId);
    if (!issuer) this.markOid4vciRequestUnmatched(req);
    return issuer;
  }

  // A session's issuance_response_scenario replaces what the Wallet receives from its PAR or
  // Credential endpoint. Credo-TS has already produced the real response, which is recorded next to
  // the delivered one, redacted for the session's evidence mode.
  applyIssuanceResponseScenario(
    req: Request,
    res: Response,
    endpoint: keyof IssuanceResponseScenario,
  ): void {
    const capture = this.oid4vciCaptures.get(req);
    const session = capture?.session_id ? this.store.getSession(capture.session_id) : undefined;
    const scenario = session?.issuance_response_scenario?.[endpoint];
    if (!capture || !session || !scenario) return;
    const mode = session.evidence_mode ?? "redacted";
    const evidence = (response: ScenarioHttpResponse): JsonRecord => ({
      status: response.status,
      content_type: response.content_type,
      body: responseBodyEvidence(Buffer.from(response.body), response.content_type, mode),
    });
    interceptIssuanceResponse(res, scenario, (original, delivered) => {
      this.store.addEvent(session, "issuance_response_scenario_applied", {
        endpoint,
        request_id: capture.id,
        scenario: { ...scenario },
        original: evidence(original),
        delivered: evidence(delivered),
      });
    });
  }
}

export function requestParams(req: Request): JsonRecord {
  return { ...(req.body as JsonRecord) };
}
interface ScenarioHttpResponse {
  status: number;
  content_type: string | null;
  body: string;
}

/**
 * The single HTTP boundary for an `issuance_response_scenario`. The response Credo-TS produced is
 * replaced once, as it is sent, so Credo's own state and the session's checks keep the real
 * outcome. `body` replaces the body exactly; otherwise `extra_parameters` are merged into the JSON
 * body and `omit_parameters` then removed from it.
 */
function interceptIssuanceResponse(
  res: Response,
  scenario: IssuanceEndpointResponseScenario,
  onApplied: (original: ScenarioHttpResponse, delivered: ScenarioHttpResponse) => void,
): void {
  const send = res.send;
  res.send = function (this: Response, responseBody?: unknown) {
    res.send = send;
    const original = {
      status: res.statusCode,
      content_type: res.get("Content-Type") ?? null,
      body:
        typeof responseBody === "string"
          ? responseBody
          : Buffer.isBuffer(responseBody)
            ? responseBody.toString("utf8")
            : (JSON.stringify(responseBody) ?? ""),
    };
    const body = scenario.body ?? scenarioJsonBody(original.body, scenario);
    if (scenario.status !== undefined) res.status(scenario.status);
    if (scenario.content_type !== undefined) res.type(scenario.content_type);
    onApplied(original, {
      status: res.statusCode,
      content_type: res.get("Content-Type") ?? null,
      body,
    });
    return send.call(this, body);
  } as Response["send"];
}

function scenarioJsonBody(text: string, scenario: IssuanceEndpointResponseScenario): string {
  if (!scenario.extra_parameters && !scenario.omit_parameters) return text;
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return text;
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) return text;
  const edited: JsonRecord = { ...json, ...(scenario.extra_parameters ?? {}) };
  for (const pointer of scenario.omit_parameters ?? []) unsetJsonPointer(edited, pointer);
  return JSON.stringify(edited);
}

function oid4vciRequestSessionId(store: CaptureStore, req: Request): string | null {
  const sessionPath = /^\/sessions\/([^/]+)\/(?:offer|deeplink)$/.exec(req.path);
  if (sessionPath?.[1]) return decodeURIComponent(sessionPath[1]);
  const offerPath = /^\/issuers\/[^/]+\/offers\/([^/]+)$/.exec(req.path);
  if (offerPath?.[1]) {
    return store.captureSessionIdsByCredentialOffer.get(offerPath[1]) ?? null;
  }
  return null;
}

/** The existing session an unrouted request names in its path, such as a mistyped session route. */
function unmatchedRequestSessionId(store: CaptureStore, req: Request): string | null {
  const sessionId = /^\/(?:ui\/)?sessions\/([^/]+)/.exec(req.path)?.[1];
  return sessionId && store.getSession(sessionId) ? sessionId : null;
}

function oid4vciRequestIssuerConfigurationId(store: CaptureStore, req: Request): string | null {
  const issuerPath =
    /^\/issuers\/([^/]+)\//.exec(req.path) ??
    /^\/(?:authorization-servers)\/([^/]+)\//.exec(req.path) ??
    /^\/\.well-known\/(?:openid-credential-issuer|jwt-vc-issuer)\/issuers\/([^/]+)$/.exec(
      req.path,
    ) ??
    /^\/\.well-known\/oauth-authorization-server\/(?:issuers|authorization-servers)\/([^/]+)$/.exec(
      req.path,
    );
  if (issuerPath?.[1]) return decodeURIComponent(issuerPath[1]);
  const sessionId = oid4vciRequestSessionId(store, req);
  return sessionId ? (store.getSession(sessionId)?.issuer_configuration_id ?? null) : null;
}

/** Issuer endpoints whose requests carry something Credo-TS can map back to an issuance session. */
function isCredoSessionEndpoint(path: string): boolean {
  return /^\/issuers\/[^/]+\/(?:par|authorize|redirect|token|credential|deferred-credential|notification)$/.test(
    path,
  );
}
