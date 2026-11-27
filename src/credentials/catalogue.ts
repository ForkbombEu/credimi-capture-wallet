import type { AttestbookCredentialDefinition } from "../attestbook/types.js";
import type { IssuerConfiguration } from "../configurations/types.js";
import type { AppConfig, CredentialFormat, CredentialProofPolicy } from "../types.js";
import {
  DEGREE_SD_JWT_CLAIMS,
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_CLAIM,
  DOMESTIC_PID_MDOC_NAMESPACE,
  DOMESTIC_PID_SD_JWT_CLAIMS,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_CLAIMS,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_CLAIMS,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "./definitions.js";

export interface SupportedCredential {
  id: string;
  scope: string;
  format: CredentialFormat;
  proofPolicy: CredentialProofPolicy;
  displayName: string;
  vct?: string;
  /** An mdoc's doctype; static mdoc credentials use the PID doctype when it is absent. */
  doctype?: string;
  /**
   * Full claim paths: JSON path segments for SD-JWT VC, with `null` for every element of an
   * array, and `[namespace, element]` for mdoc.
   */
  claimPaths: readonly (readonly (string | null)[])[];
  /** Present for a credential compiled from an Attestbook rulebook version. */
  attestbook?: AttestbookCredentialDefinition;
}

/** The issuer fields that select its static credential catalogue. */
export type StaticCatalogueIssuer = Pick<
  IssuerConfiguration,
  "proofPolicy" | "staticCredentialVcts"
>;

function credentialConfigurationId(
  config: AppConfig,
  format: CredentialFormat,
  proofPolicy: CredentialProofPolicy,
): string {
  return `${config.credential_configuration_id}.${credentialFormatId(format)}.${proofPolicy}`;
}

/** @internal */
export function sdJwtCredentialConfigurationId(
  config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return credentialConfigurationId(config, "dc+sd-jwt", proofPolicy);
}

/** @internal */
export function mdocCredentialConfigurationId(
  config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return credentialConfigurationId(config, "mso_mdoc", proofPolicy);
}

/** @internal */
export function degreeSdJwtCredentialConfigurationId(
  _config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return `urn:credimi:degree:1.sd-jwt.${proofPolicy}`;
}

/** @internal */
export function numericSdJwtCredentialConfigurationId(
  _config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return `urn:credimi:numeric-claims:1.sd-jwt.${proofPolicy}`;
}

/** Fixed identifier, also used as scope, for a domestic PID configuration.
 * @internal
 */
export function domesticPidCredentialConfigurationId(
  format: CredentialFormat,
  proofPolicy: CredentialProofPolicy,
): string {
  return `${DOMESTIC_PID_SD_JWT_VCT}.${credentialFormatId(format)}.${proofPolicy}`;
}

export function isDomesticPidCredential(credential: SupportedCredential): boolean {
  return (
    credential.id ===
    domesticPidCredentialConfigurationId(credential.format, credential.proofPolicy)
  );
}

function credentialScope(
  config: AppConfig,
  format: CredentialFormat,
  proofPolicy: CredentialProofPolicy,
): string {
  return `${config.credential_scope}.${credentialFormatId(format)}.${proofPolicy}`;
}

function credentialFormatId(format: CredentialFormat): "sd-jwt" | "mdoc" {
  return format === "dc+sd-jwt" ? "sd-jwt" : "mdoc";
}

export function supportedCredentials(config: AppConfig): SupportedCredential[] {
  return [
    {
      id: sdJwtCredentialConfigurationId(config, "key-attestation-required"),
      scope: credentialScope(config, "dc+sd-jwt", "key-attestation-required"),
      format: "dc+sd-jwt",
      proofPolicy: "key-attestation-required",
      displayName:
        "Credimi Demo PID (SD-JWT VC, JWT or attestation proof, key attestation required)",
      vct: PID_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(PID_SD_JWT_CLAIMS),
    },
    {
      id: sdJwtCredentialConfigurationId(config, "jwt-key-attestation-required"),
      scope: credentialScope(config, "dc+sd-jwt", "jwt-key-attestation-required"),
      format: "dc+sd-jwt",
      proofPolicy: "jwt-key-attestation-required",
      displayName: "Credimi Demo PID (SD-JWT VC, JWT proof, key attestation required)",
      vct: PID_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(PID_SD_JWT_CLAIMS),
    },
    {
      id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
      scope: credentialScope(config, "dc+sd-jwt", "jwt-proof"),
      format: "dc+sd-jwt",
      proofPolicy: "jwt-proof",
      displayName: "Credimi Demo PID (SD-JWT VC, JWT proof, no key attestation)",
      vct: PID_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(PID_SD_JWT_CLAIMS),
    },
    {
      id: mdocCredentialConfigurationId(config, "key-attestation-required"),
      scope: credentialScope(config, "mso_mdoc", "key-attestation-required"),
      format: "mso_mdoc",
      proofPolicy: "key-attestation-required",
      displayName: "Credimi Demo PID (MDOC, JWT or attestation proof, key attestation required)",
      claimPaths: mdocClaimPaths(PID_MDOC_NAMESPACE, PID_MDOC_CLAIMS),
    },
    {
      id: mdocCredentialConfigurationId(config, "jwt-key-attestation-required"),
      scope: credentialScope(config, "mso_mdoc", "jwt-key-attestation-required"),
      format: "mso_mdoc",
      proofPolicy: "jwt-key-attestation-required",
      displayName: "Credimi Demo PID (MDOC, JWT proof, key attestation required)",
      claimPaths: mdocClaimPaths(PID_MDOC_NAMESPACE, PID_MDOC_CLAIMS),
    },
    {
      id: mdocCredentialConfigurationId(config, "jwt-proof"),
      scope: credentialScope(config, "mso_mdoc", "jwt-proof"),
      format: "mso_mdoc",
      proofPolicy: "jwt-proof",
      displayName: "Credimi Demo PID (MDOC, JWT proof, no key attestation)",
      claimPaths: mdocClaimPaths(PID_MDOC_NAMESPACE, PID_MDOC_CLAIMS),
    },
    {
      id: degreeSdJwtCredentialConfigurationId(config, "key-attestation-required"),
      scope: "urn:credimi:degree:1.sd-jwt.key-attestation-required",
      format: "dc+sd-jwt",
      proofPolicy: "key-attestation-required",
      displayName:
        "Credimi test degree (SD-JWT VC, JWT or attestation proof, key attestation required)",
      vct: DEGREE_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(DEGREE_SD_JWT_CLAIMS),
    },
    {
      id: degreeSdJwtCredentialConfigurationId(config, "jwt-proof"),
      scope: "urn:credimi:degree:1.sd-jwt.jwt-proof",
      format: "dc+sd-jwt",
      proofPolicy: "jwt-proof",
      displayName: "Credimi test degree (SD-JWT VC, JWT proof, no key attestation)",
      vct: DEGREE_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(DEGREE_SD_JWT_CLAIMS),
    },
    {
      id: numericSdJwtCredentialConfigurationId(config, "key-attestation-required"),
      scope: "urn:credimi:numeric-claims:1.sd-jwt.key-attestation-required",
      format: "dc+sd-jwt",
      proofPolicy: "key-attestation-required",
      displayName:
        "Credimi test numeric claims (SD-JWT VC, JWT or attestation proof, key attestation required)",
      vct: NUMERIC_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(NUMERIC_SD_JWT_CLAIMS),
    },
    {
      id: numericSdJwtCredentialConfigurationId(config, "jwt-proof"),
      scope: "urn:credimi:numeric-claims:1.sd-jwt.jwt-proof",
      format: "dc+sd-jwt",
      proofPolicy: "jwt-proof",
      displayName: "Credimi test numeric claims (SD-JWT VC, JWT proof, no key attestation)",
      vct: NUMERIC_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(NUMERIC_SD_JWT_CLAIMS),
    },
    ...(["key-attestation-required", "jwt-proof"] as const).flatMap(domesticPidCredentials),
  ];
}

function domesticPidCredentials(proofPolicy: CredentialProofPolicy): SupportedCredential[] {
  const proofDescription =
    proofPolicy === "jwt-proof"
      ? "JWT proof, no key attestation"
      : "JWT or attestation proof, key attestation required";
  return [
    {
      id: domesticPidCredentialConfigurationId("dc+sd-jwt", proofPolicy),
      scope: domesticPidCredentialConfigurationId("dc+sd-jwt", proofPolicy),
      format: "dc+sd-jwt",
      proofPolicy,
      displayName: `Credimi Demo domestic PID XX (SD-JWT VC, ${proofDescription})`,
      vct: DOMESTIC_PID_SD_JWT_VCT,
      claimPaths: sdJwtClaimPaths(DOMESTIC_PID_SD_JWT_CLAIMS),
    },
    {
      id: domesticPidCredentialConfigurationId("mso_mdoc", proofPolicy),
      scope: domesticPidCredentialConfigurationId("mso_mdoc", proofPolicy),
      format: "mso_mdoc",
      proofPolicy,
      displayName: `Credimi Demo domestic PID XX (MDOC, ${proofDescription})`,
      claimPaths: [
        ...mdocClaimPaths(PID_MDOC_NAMESPACE, PID_MDOC_CLAIMS),
        ...mdocClaimPaths(DOMESTIC_PID_MDOC_NAMESPACE, [DOMESTIC_PID_CLAIM]),
      ],
    },
  ];
}

export function supportedCredentialsForIssuer(
  config: AppConfig,
  issuer: StaticCatalogueIssuer,
): SupportedCredential[] {
  return supportedCredentials(config).filter(
    (credential) =>
      credential.proofPolicy === issuer.proofPolicy &&
      (issuer.staticCredentialVcts === undefined ||
        (credential.vct !== undefined && issuer.staticCredentialVcts.includes(credential.vct))),
  );
}

export function supportedCredentialConfigurationIds(config: AppConfig): string[] {
  return supportedCredentials(config).map((credential) => credential.id);
}

export function supportedCredentialById(
  config: AppConfig,
  credentialConfigurationId: string,
  issuer?: StaticCatalogueIssuer,
): SupportedCredential | null {
  return (
    (issuer ? supportedCredentialsForIssuer(config, issuer) : supportedCredentials(config)).find(
      (credential) => credential.id === credentialConfigurationId,
    ) ?? null
  );
}

function sdJwtClaimPaths(claims: readonly string[]): string[][] {
  return claims.map((claim) => claim.split("."));
}

function mdocClaimPaths(namespace: string, elements: readonly string[]): string[][] {
  return elements.map((element) => [namespace, element]);
}
