import type { AttestbookCredentialDefinition } from "../attestbook/types.js";
import {
  DEFAULT_ISSUER_CONFIGURATION_ID,
  resolvedIssuerConfigurationById,
  resolvedIssuerConfigurations,
} from "../configurations/registry.js";
import { PID_FIXTURE_IDS, pidFixtureIdOrNull } from "../configurations/shared/pid-fixtures.js";
import type { ResolvedIssuerConfiguration } from "../configurations/types.js";
import type { SupportedCredential } from "../credentials/catalogue.js";
import {
  DEFAULT_SD_JWT_DIGEST_ALGORITHM,
  SD_JWT_DIGEST_ALGORITHMS,
  sdJwtDigestAlgorithmOrNull,
} from "../credentials/digest-algorithm.js";
import { type CredentialRegistry, credentialRegistry } from "../credentials/registry.js";
import { offerMutationOrNull } from "../fcaf/request-mutation.js";
import { issuanceResponseScenarioOrNull } from "../fcaf/response-scenario.js";
import { credoOpenId4VciIssuer } from "../openid4vci/credo-issuer.js";
import { asStringOrNull, booleanOrNull } from "../shared/json.js";
import type { CaptureStore } from "../state.js";
import {
  STATUS_REFERENCE_FIXTURES,
  statusReferenceFixtureOrNull,
} from "../status-list/reference-fixtures.js";
import type {
  AppConfig,
  CredentialOfferMode,
  CredentialOfferScheme,
  EvidenceMode,
  JsonRecord,
  SdJwtDigestAlgorithm,
  SessionCapture,
  StatusReferenceFixture,
  VpRequestMutationEdits,
} from "../types.js";

export const ISSUANCE_FLOWS: SessionCapture["flow"][] = [
  "authorization_code",
  "pre_authorized_code",
];
export const CREDENTIAL_OFFER_MODES: CredentialOfferMode[] = [
  "credential_offer",
  "credential_offer_uri",
];
export const EVIDENCE_MODES: EvidenceMode[] = ["redacted", "full"];
export const DEFAULT_OFFER_SCHEME: CredentialOfferScheme = "openid-credential-offer://";
export const OFFER_SCHEMES: CredentialOfferScheme[] = [
  DEFAULT_OFFER_SCHEME,
  "eu-eaa-offer://",
  "haip-vci://",
];

export type IssuanceSessionInput = {
  issuer: ResolvedIssuerConfiguration;
  credentialConfigurationId: string;
  flow: SessionCapture["flow"];
  credentialOfferMode: CredentialOfferMode;
  statusListEnabled: boolean;
  fixtureId?: string;
  documentNumber?: string;
  statusReference: StatusReferenceFixture;
  digestAlgorithm: SdJwtDigestAlgorithm;
  evidenceMode: EvidenceMode;
  issuanceResponseScenario: SessionCapture["issuance_response_scenario"];
  offerScheme: CredentialOfferScheme;
  offerMutation?: VpRequestMutationEdits;
  importedDefinition?: AttestbookCredentialDefinition;
};

export type IssuanceSessionInputResult =
  | { ok: true; value: IssuanceSessionInput }
  | { ok: false; status: number; body: JsonRecord };

type IssuanceInputRejection = { ok: false; status: 400; body: JsonRecord };
type CheckResult<T> = { ok: true; value: T } | IssuanceInputRejection;

type OfferShape = {
  flow: SessionCapture["flow"];
  credentialOfferMode: CredentialOfferMode;
  statusListEnabled: boolean;
};

type IssuanceTarget = {
  issuer: ResolvedIssuerConfiguration;
  credentialConfigurationId: string;
  credential: SupportedCredential;
};

type StatusReferenceResult = {
  statusReference: StatusReferenceFixture;
};

type PidOptions = {
  fixtureId?: string;
  documentNumber?: string;
};

type DigestResult = {
  digestAlgorithm: SdJwtDigestAlgorithm;
};

type FcafOptions = {
  evidenceMode: EvidenceMode;
  issuanceResponseScenario: SessionCapture["issuance_response_scenario"];
  offerScheme: CredentialOfferScheme;
  offerMutation?: VpRequestMutationEdits;
};

export async function parseIssuanceSessionInput(
  config: AppConfig,
  store: CaptureStore,
  body: JsonRecord,
): Promise<IssuanceSessionInputResult> {
  const offerShape = parseOfferShape(body);
  if (!offerShape.ok) return offerShape;
  const target = await resolveIssuanceTarget(config, store, body);
  if (!target.ok) return target;
  const importedRejection = importedCredentialExclusions(
    body,
    offerShape.value.statusListEnabled,
    target.value.credential.attestbook,
  );
  if (importedRejection) return importedRejection;
  const statusReference = parseStatusReference(config, body, offerShape.value.statusListEnabled);
  if (!statusReference.ok) return statusReference;
  const pidOptions = parsePidOptions(body, target.value.credential.attestbook);
  if (!pidOptions.ok) return pidOptions;
  const digest = parseDigestAlgorithm(body, target.value.credential);
  if (!digest.ok) return digest;
  const fcafOptions = parseFcafOptions(config, body, offerShape.value.credentialOfferMode);
  if (!fcafOptions.ok) return fcafOptions;
  return {
    ok: true,
    value: {
      ...target.value,
      ...offerShape.value,
      ...statusReference.value,
      ...pidOptions.value,
      ...digest.value,
      ...fcafOptions.value,
      importedDefinition: target.value.credential.attestbook,
    },
  };
}

/** The issuer's credential registry, with any restored imported catalogue already loaded. */
export async function issuerCredentialRegistry(
  config: AppConfig,
  store: CaptureStore,
): Promise<CredentialRegistry> {
  if (config.attestbook.enabled) await credoOpenId4VciIssuer(config, store);
  return credentialRegistry(config, store);
}

function parseOfferShape(body: JsonRecord): CheckResult<OfferShape> {
  if (body.broken !== undefined) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "invalid_request",
        error_description:
          "'broken' is unavailable because the legacy root issuer has been removed",
      },
    };
  }
  const flow = ISSUANCE_FLOWS.find((candidate) => candidate === body.flow) ?? null;
  if (body.flow !== undefined && !flow) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_issuance_flow",
        supported_flows: ["pre_authorized_code", "authorization_code"],
      },
    };
  }
  const credentialOfferMode =
    CREDENTIAL_OFFER_MODES.find((candidate) => candidate === body.credential_offer_mode) ?? null;
  if (body.credential_offer_mode !== undefined && !credentialOfferMode) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_credential_offer_mode",
        supported_credential_offer_modes: ["credential_offer", "credential_offer_uri"],
      },
    };
  }
  const statusListEnabled = booleanOrNull(body.status_list_enabled);
  if (body.status_list_enabled !== undefined && statusListEnabled === null) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "invalid_status_list_enabled",
        error_description: "status_list_enabled must be a boolean",
      },
    };
  }
  return {
    ok: true,
    value: {
      flow: flow ?? "authorization_code",
      credentialOfferMode: credentialOfferMode ?? "credential_offer",
      statusListEnabled: statusListEnabled ?? false,
    },
  };
}

async function resolveIssuanceTarget(
  config: AppConfig,
  store: CaptureStore,
  body: JsonRecord,
): Promise<CheckResult<IssuanceTarget>> {
  const issuer = issuerFromRequest(config, body.issuer_configuration_id);
  if (!issuer) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_issuer_configuration",
        supported_issuer_configuration_ids: resolvedIssuerConfigurations(config).map(
          (candidate) => candidate.id,
        ),
      },
    };
  }
  const registry = await issuerCredentialRegistry(config, store);
  const supportedCredentialIds = registry
    .credentialsForIssuer(issuer)
    .map((credential) => credential.id);
  const credentialConfigurationId =
    asStringOrNull(body.credential_configuration_id) ?? supportedCredentialIds[0];
  const credential = credentialConfigurationId
    ? registry.credentialById(issuer, credentialConfigurationId)
    : null;
  if (!credentialConfigurationId || !credential) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_credential_configuration",
        issuer_configuration_id: issuer.id,
        supported_credential_configuration_ids: supportedCredentialIds,
      },
    };
  }
  return { ok: true, value: { issuer, credentialConfigurationId, credential } };
}

function importedCredentialExclusions(
  body: JsonRecord,
  statusListEnabled: boolean,
  imported: AttestbookCredentialDefinition | undefined,
): IssuanceInputRejection | undefined {
  if (!imported) return undefined;
  // PID-specific and status-list options have no meaning for an imported credential type.
  const unsupported = [
    ...(statusListEnabled ? ["status_list_enabled"] : []),
    ...(body.status_reference !== undefined ? ["status_reference"] : []),
    ...(body.document_number !== undefined ? ["document_number"] : []),
    ...(body.fixture_id !== undefined ? ["fixture_id"] : []),
  ];
  if (unsupported.length === 0) return undefined;
  return {
    ok: false,
    status: 400,
    body: {
      error: "unsupported_for_imported_credential",
      error_description: "these parameters are not supported for an imported Attestbook credential",
      unsupported_parameters: unsupported,
    },
  };
}

function parseStatusReference(
  config: AppConfig,
  body: JsonRecord,
  statusListEnabled: boolean,
): CheckResult<StatusReferenceResult> {
  const statusReference = statusReferenceFixtureOrNull(body.status_reference ?? "valid");
  if (!statusReference) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_status_reference",
        supported_status_references: STATUS_REFERENCE_FIXTURES,
      },
    };
  }
  if (statusReference !== "valid" && !config.fcaf_scenarios_enabled) {
    return { ok: false, status: 400, body: { error: "status_reference_not_enabled" } };
  }
  if (statusReference !== "valid" && !statusListEnabled) {
    return { ok: false, status: 400, body: { error: "status_reference_requires_status_list" } };
  }
  return { ok: true, value: { statusReference } };
}

function parsePidOptions(
  body: JsonRecord,
  imported: AttestbookCredentialDefinition | undefined,
): CheckResult<PidOptions> {
  if (imported) return { ok: true, value: {} };
  const fixtureId = pidFixtureIdOrNull(body.fixture_id ?? "pid_default");
  if (!fixtureId) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_fixture_id",
        supported_fixture_ids: PID_FIXTURE_IDS,
      },
    };
  }
  const documentNumber =
    typeof body.document_number === "string" && body.document_number.length > 0
      ? body.document_number
      : null;
  if (body.document_number !== undefined && documentNumber === null) {
    return { ok: false, status: 400, body: { error: "invalid_document_number" } };
  }
  return { ok: true, value: { fixtureId, documentNumber: documentNumber ?? undefined } };
}

function parseDigestAlgorithm(
  body: JsonRecord,
  credential: NonNullable<IssuanceTarget["credential"]>,
): CheckResult<DigestResult> {
  const digestAlgorithm = sdJwtDigestAlgorithmOrNull(
    body.digest_algorithm ?? DEFAULT_SD_JWT_DIGEST_ALGORITHM,
  );
  if (!digestAlgorithm) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_digest_algorithm",
        supported_digest_algorithms: SD_JWT_DIGEST_ALGORITHMS,
      },
    };
  }
  if (digestAlgorithm !== DEFAULT_SD_JWT_DIGEST_ALGORITHM && credential.format === "mso_mdoc") {
    return { ok: false, status: 400, body: { error: "digest_algorithm_unsupported_for_mdoc" } };
  }
  return { ok: true, value: { digestAlgorithm } };
}

function parseFcafOptions(
  config: AppConfig,
  body: JsonRecord,
  credentialOfferMode: CredentialOfferMode,
): CheckResult<FcafOptions> {
  const evidenceMode =
    EVIDENCE_MODES.find((candidate) => candidate === (body.evidence_mode ?? "redacted")) ?? null;
  if (!evidenceMode) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_evidence_mode",
        supported_evidence_modes: EVIDENCE_MODES,
      },
    };
  }
  if (evidenceMode === "full" && !config.fcaf_scenarios_enabled) {
    return { ok: false, status: 400, body: { error: "evidence_mode_not_enabled" } };
  }
  const issuanceResponseScenario = issuanceResponseScenarioOrNull(body.issuance_response_scenario);
  if (issuanceResponseScenario === null) {
    return {
      ok: false,
      status: 400,
      body: { error: "invalid_issuance_response_scenario" },
    };
  }
  if (issuanceResponseScenario && !config.fcaf_scenarios_enabled) {
    return {
      ok: false,
      status: 400,
      body: { error: "issuance_response_scenario_not_enabled" },
    };
  }
  const offerScheme =
    OFFER_SCHEMES.find((candidate) => candidate === (body.offer_scheme ?? DEFAULT_OFFER_SCHEME)) ??
    null;
  if (!offerScheme) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "unsupported_offer_scheme",
        supported_offer_schemes: OFFER_SCHEMES,
      },
    };
  }
  const offerMutation = offerMutationOrNull(body.offer_mutation);
  if (offerMutation === null) {
    return { ok: false, status: 400, body: { error: "invalid_offer_mutation" } };
  }
  if (offerMutation && !config.fcaf_scenarios_enabled) {
    return { ok: false, status: 400, body: { error: "offer_mutation_not_enabled" } };
  }
  if (offerMutation && credentialOfferMode === "credential_offer_uri") {
    return { ok: false, status: 400, body: { error: "offer_mutation_requires_by_value_offer" } };
  }
  return {
    ok: true,
    value: { evidenceMode, issuanceResponseScenario, offerScheme, offerMutation },
  };
}

export function issuerFromRequest(
  config: AppConfig,
  value: unknown,
): ResolvedIssuerConfiguration | null {
  const id = asStringOrNull(value) ?? DEFAULT_ISSUER_CONFIGURATION_ID;
  return resolvedIssuerConfigurationById(config, id);
}
