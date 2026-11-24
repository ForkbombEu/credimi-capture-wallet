import { ClaimFormat } from "@credo-ts/core";
import type { OpenId4VciSignCredentials } from "@credo-ts/openid4vc";
import { pidFixtureIdOrNull, pidFixtureSubject } from "../configurations/shared/pid-fixtures.js";
import { type SupportedCredential, isDomesticPidCredential } from "../credentials/catalogue.js";
import { DEGREE_SD_JWT_VCT, NUMERIC_SD_JWT_VCT } from "../credentials/definitions.js";
import {
  degreeSdJwtCredentialSignOptions,
  domesticPidMdocCredentialSignOptions,
  domesticPidSdJwtCredentialSignOptions,
  importedSdJwtCredentialSignOptions,
  mdocCredentialSignOptions,
  numericSdJwtCredentialSignOptions,
  sdJwtCredentialSignOptions,
} from "../credentials/signing.js";
import {
  allocateStatusListReference,
  statusListCredentialType,
} from "../status-list/allocation.js";
import type {
  AppConfig,
  JsonRecord,
  ProofHeaderCapture,
  SessionCapture,
  StatusListReference,
} from "../types.js";
import { redactCredentialRequest } from "./evidence.js";

export interface CredentialRequestEvidence {
  body: JsonRecord;
  raw?: unknown;
}

export function recordCredentialRequestEvidence(options: {
  captureSession: SessionCapture;
  request: JsonRecord;
  evidence: CredentialRequestEvidence | undefined;
  holderJwks: JsonRecord[];
  proofHeaders: ProofHeaderCapture[];
  proofType: string | undefined;
}): void {
  const { captureSession, request, evidence, holderJwks, proofHeaders, proofType } = options;

  captureSession.raw ??= {};
  captureSession.raw.credential_request = redactCredentialRequest(evidence?.body ?? request);
  if (evidence?.raw !== undefined) {
    captureSession.raw.credential_request_raw = evidence.raw;
  }
  captureSession.raw.proof_headers = proofHeaders;
  captureSession.checks.proof_jwt_present = proofType === "jwt";
  captureSession.checks.proof_attestation_present = proofType === "attestation";
  captureSession.checks.proof_jwt_header_jwk_present = proofHeaders.some(
    (header) => header.proof_type === "jwt" && Boolean(header.jwk),
  );
  captureSession.checks.key_attestation_verified =
    proofType === "attestation" || proofHeaders.some((header) => header.key_attestation_present);
  captureSession.checks.nonce_verified = true;
  captureSession.observed.wallet_jwks = {
    observed: true,
    source: "credo.verified_holder_binding",
    jwks: { keys: holderJwks },
    observed_proof_header_fields: Array.from(
      new Set(
        proofHeaders.flatMap((header) =>
          ["typ", "alg", "kid", "jwk", "x5c"].filter(
            (field) => header[field as keyof typeof header] !== undefined,
          ),
        ),
      ),
    ),
  };
}

export async function allocateStatusListReferences(options: {
  config: AppConfig;
  captureSession: SessionCapture;
  credential: SupportedCredential;
  holderJwks: JsonRecord[];
}): Promise<Array<StatusListReference | undefined>> {
  const { config, captureSession, credential, holderJwks } = options;
  return captureSession.status_list_enabled
    ? await Promise.all(
        holderJwks.map(async (_, index) => {
          const allocationId = statusAllocationId(captureSession, index);
          const reference = await allocateStatusListReference({
            config,
            allocationId,
            doctype: statusListCredentialType(credential),
          });
          // Kept at the credential's index, so a retried request replaces rather than appends,
          // and `POST /sessions/{id}/status` can revoke exactly what was allocated.
          captureSession.status_list_references ??= [];
          captureSession.status_list_references[index] = {
            allocation_id: allocationId,
            ...reference,
          };
          return reference;
        }),
      )
    : holderJwks.map(() => undefined);
}

export function signingOptionsForCredential(options: {
  signingConfig: AppConfig;
  credential: SupportedCredential;
  captureSession: SessionCapture;
  holderJwks: JsonRecord[];
  statusListReferences: Array<StatusListReference | undefined>;
}): OpenId4VciSignCredentials {
  const { signingConfig, credential, captureSession, holderJwks, statusListReferences } = options;
  const definition = credential.attestbook;
  if (definition) {
    // Refused earlier at the Credential Endpoint with `invalid_credential_request`; this guards
    // a newer version activated between that check and signing.
    if (captureSession.credential_definition?.content_digest !== definition.contentDigest) {
      throw new Error("Capture session was created under a superseded credential definition");
    }
    const generated = captureSession.generated_claims;
    if (!generated) throw new Error("Capture session has no generated claims");
    return {
      type: "credentials" as const,
      format: ClaimFormat.SdJwtDc,
      credentials: holderJwks.map((holderJwk) =>
        importedSdJwtCredentialSignOptions({
          config: signingConfig,
          holderJwk,
          definition,
          claims: generated.claims,
          digestAlgorithm: captureSession.digest_algorithm,
        }),
      ),
    };
  }
  const fixtureSubject = pidFixtureSubject(
    pidFixtureIdOrNull(captureSession.fixture_id) ?? undefined,
  );
  const subject =
    captureSession.document_number === undefined
      ? fixtureSubject
      : { ...fixtureSubject, documentNumber: captureSession.document_number };
  const domesticPid = isDomesticPidCredential(credential);
  if (credential.format === "mso_mdoc") {
    return {
      type: "credentials" as const,
      format: ClaimFormat.MsoMdoc,
      credentials: holderJwks.map((holderJwk, index) => {
        const signingOptions = {
          config: signingConfig,
          holderJwk,
          statusListReference: statusListReferences[index],
          statusReference: captureSession.status_reference,
          subject,
        };
        return domesticPid
          ? domesticPidMdocCredentialSignOptions(signingOptions)
          : mdocCredentialSignOptions(signingOptions);
      }),
    };
  }
  return {
    type: "credentials" as const,
    format: ClaimFormat.SdJwtDc,
    credentials: holderJwks.map((holderJwk, index) => {
      const signingOptions = {
        config: signingConfig,
        holderJwk,
        statusListReference: statusListReferences[index],
        statusReference: captureSession.status_reference,
        digestAlgorithm: captureSession.digest_algorithm,
      };
      if (credential.vct === DEGREE_SD_JWT_VCT) {
        return degreeSdJwtCredentialSignOptions(signingOptions);
      }
      if (credential.vct === NUMERIC_SD_JWT_VCT) {
        return numericSdJwtCredentialSignOptions(signingOptions);
      }
      if (domesticPid) {
        return domesticPidSdJwtCredentialSignOptions({ ...signingOptions, subject });
      }
      return sdJwtCredentialSignOptions({ ...signingOptions, subject });
    }),
  };
}

function statusAllocationId(session: SessionCapture, index: number): string {
  let allocationIds = session.status_list_allocation_ids;
  if (!allocationIds) {
    allocationIds = [];
    session.status_list_allocation_ids = allocationIds;
  }
  if (!allocationIds[index]) allocationIds[index] = `${session.session_id}:${index}`;
  const allocationId = allocationIds[index];
  if (!allocationId) throw new Error(`Missing status allocation id at index ${index}`);
  return allocationId;
}
