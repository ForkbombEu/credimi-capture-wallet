import { type AgentContext, JwsService, JwtPayload, Kms } from "@credo-ts/core";
import {
  createIssuerSigningContext,
  issuerSigningKeyId,
  loadIssuerEncryptionPublicJwk,
  loadIssuerJwks,
  loadIssuerPublicJwk,
} from "./config.js";
import type { IssuerConfiguration } from "./configurations/types.js";
import {
  CREDIMI_LOGO_URL,
  DEGREE_SD_JWT_CLAIMS,
  DEGREE_SD_JWT_VCT,
  DOMESTIC_PID_CLAIM,
  DOMESTIC_PID_MDOC_NAMESPACE,
  DOMESTIC_PID_SD_JWT_CLAIMS,
  DOMESTIC_PID_SD_JWT_VCT,
  NUMERIC_SD_JWT_CLAIMS,
  NUMERIC_SD_JWT_VCT,
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { AppConfig, JsonRecord } from "./types.js";

export type CredentialFormat = "dc+sd-jwt" | "mso_mdoc";
export type CredentialProofPolicy =
  | "jwt-proof"
  | "jwt-key-attestation-required"
  | "key-attestation-required";

export interface SupportedCredential {
  id: string;
  scope: string;
  format: CredentialFormat;
  proofPolicy: CredentialProofPolicy;
  displayName: string;
  vct?: string;
  /** Full claim paths: JSON path segments for SD-JWT VC, `[namespace, element]` for mdoc. */
  claimPaths: readonly (readonly string[])[];
}

export { PID_MDOC_DOCTYPE, PID_MDOC_NAMESPACE, PID_SD_JWT_VCT };

export function credentialIssuerMetadata(
  config: AppConfig,
  issuer: IssuerConfiguration,
): JsonRecord {
  const credentials = supportedCredentialsForIssuer(config, issuer);
  const encryptionJwk = loadIssuerEncryptionPublicJwk(config);

  return {
    credential_issuer: config.issuer_base_url,
    credential_endpoint: `${config.issuer_base_url}/credential`,
    nonce_endpoint: `${config.issuer_base_url}/nonce`,
    ...(encryptionJwk
      ? {
          credential_request_encryption: {
            jwks: { keys: [encryptionJwk] },
            enc_values_supported: ["A256GCM"],
            encryption_required: false,
          },
          credential_response_encryption: {
            alg_values_supported: ["ECDH-ES"],
            enc_values_supported: ["A256GCM"],
            encryption_required: false,
          },
        }
      : {}),
    display: [
      {
        locale: "en-US",
        logo: {
          alt_text: "Credimi Capture Issuer Logo",
          uri: CREDIMI_LOGO_URL,
        },
        name: issuer.display.name,
      },
    ],
    credential_configurations_supported: Object.fromEntries(
      credentials.map((credential) => [
        credential.id,
        credentialConfiguration(credential, proofTypesSupported(credential.proofPolicy)),
      ]),
    ),
  };
}

export async function signedCredentialIssuerMetadata(
  config: AppConfig,
  issuer: IssuerConfiguration,
  now = new Date(),
): Promise<string> {
  return signCredentialIssuerMetadata(
    config,
    credentialIssuerMetadata(config, issuer),
    createIssuerSigningContext(config) as never,
    now,
  );
}

export async function signCredentialIssuerMetadata(
  config: AppConfig,
  metadata: JsonRecord,
  agentContext: AgentContext,
  now = new Date(),
): Promise<string> {
  const certificateChain = issuerCertificateChain(config);

  return new JwsService().createJwsCompact(agentContext, {
    payload: new JwtPayload({
      iss: config.issuer_base_url,
      sub: config.issuer_base_url,
      iat: Math.floor(now.getTime() / 1000),
      additionalClaims: metadata,
    }),
    keyId: issuerSigningKeyId(config),
    protectedHeaderOptions: {
      alg: "ES256",
      typ: "openidvci-issuer-metadata+jwt",
      x5c: certificateChain,
    },
  });
}

function issuerCertificateChain(config: AppConfig): string[] {
  const issuerPublicJwk = Kms.PublicJwk.fromUnknown(loadIssuerPublicJwk(config));
  for (const jwk of loadIssuerJwks(config).keys) {
    if (publicJwkMatches(jwk, issuerPublicJwk) && isStringArray(jwk.x5c)) {
      return jwk.x5c;
    }
  }
  throw new Error("Certificate chain for the issuer signing key is unavailable");
}

function publicJwkMatches(candidate: JsonRecord, expected: Kms.PublicJwk): boolean {
  try {
    return Kms.PublicJwk.fromUnknown(candidate).equals(expected);
  } catch {
    return false;
  }
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

export function jwtVcIssuerMetadata(config: AppConfig): unknown {
  return {
    issuer: config.issuer_base_url,
    jwks_uri: `${config.issuer_base_url}/credential-jwks.json`,
  };
}

export function credentialConfigurationId(
  config: AppConfig,
  format: CredentialFormat,
  proofPolicy: CredentialProofPolicy,
): string {
  return `${config.credential_configuration_id}.${credentialFormatId(format)}.${proofPolicy}`;
}

export function sdJwtCredentialConfigurationId(
  config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return credentialConfigurationId(config, "dc+sd-jwt", proofPolicy);
}

export function mdocCredentialConfigurationId(
  config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return credentialConfigurationId(config, "mso_mdoc", proofPolicy);
}

export function degreeSdJwtCredentialConfigurationId(
  _config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return `urn:credimi:degree:1.sd-jwt.${proofPolicy}`;
}

export function numericSdJwtCredentialConfigurationId(
  _config: AppConfig,
  proofPolicy: CredentialProofPolicy,
): string {
  return `urn:credimi:numeric-claims:1.sd-jwt.${proofPolicy}`;
}

/** Fixed identifier, also used as scope, for a domestic PID configuration. */
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

export function credentialScope(
  config: AppConfig,
  format: CredentialFormat,
  proofPolicy: CredentialProofPolicy,
): string {
  return `${config.credential_scope}.${credentialFormatId(format)}.${proofPolicy}`;
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
  issuer: Pick<IssuerConfiguration, "proofPolicy">,
): SupportedCredential[] {
  return supportedCredentials(config).filter(
    (credential) => credential.proofPolicy === issuer.proofPolicy,
  );
}

export function supportedCredentialConfigurationIdsForIssuer(
  config: AppConfig,
  issuer: Pick<IssuerConfiguration, "proofPolicy">,
): string[] {
  return supportedCredentialsForIssuer(config, issuer).map((credential) => credential.id);
}

export function supportedCredentialConfigurationIds(config: AppConfig): string[] {
  return supportedCredentials(config).map((credential) => credential.id);
}

export function supportedCredentialById(
  config: AppConfig,
  credentialConfigurationId: string,
  issuer?: Pick<IssuerConfiguration, "proofPolicy">,
): SupportedCredential | null {
  return (
    (issuer ? supportedCredentialsForIssuer(config, issuer) : supportedCredentials(config)).find(
      (credential) => credential.id === credentialConfigurationId,
    ) ?? null
  );
}

function proofTypesSupported(proofPolicy: CredentialProofPolicy): Record<
  string,
  {
    key_attestations_required?: Record<string, unknown>;
    proof_signing_alg_values_supported: string[];
  }
> {
  if (proofPolicy === "jwt-proof") {
    return {
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
      },
    };
  }

  if (proofPolicy === "jwt-key-attestation-required") {
    return {
      jwt: {
        proof_signing_alg_values_supported: ["ES256"],
        key_attestations_required: {},
      },
    };
  }

  return {
    jwt: {
      proof_signing_alg_values_supported: ["ES256"],
      key_attestations_required: {},
    },
    attestation: {
      proof_signing_alg_values_supported: ["ES256"],
      key_attestations_required: {},
    },
  };
}

function credentialFormatId(format: CredentialFormat): "sd-jwt" | "mdoc" {
  return format === "dc+sd-jwt" ? "sd-jwt" : "mdoc";
}

function credentialConfiguration(
  credential: SupportedCredential,
  proofTypesSupported: Record<
    string,
    {
      key_attestations_required?: Record<string, unknown>;
      proof_signing_alg_values_supported: string[];
    }
  >,
): unknown {
  const common = {
    format: credential.format,
    scope: credential.scope,
    credential_metadata: {
      display: [
        {
          name: credential.displayName,
          locale: "en-US",
          logo: {
            uri: CREDIMI_LOGO_URL,
            alt_text: "Credimi",
          },
        },
      ],
      claims: credential.claimPaths.map((path) => ({
        path: [...path],
        mandatory: true,
        display: [
          {
            name: (path.at(-1) ?? "")
              .split("_")
              .filter(Boolean)
              .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
              .join(" "),
            locale: "en-US",
          },
        ],
      })),
    },
    cryptographic_binding_methods_supported:
      credential.format === "mso_mdoc" ? ["cose_key"] : ["jwk"],
    credential_signing_alg_values_supported: credential.format === "mso_mdoc" ? [-7] : ["ES256"],
    proof_types_supported: proofTypesSupported,
  };

  return credential.format === "mso_mdoc"
    ? { ...common, doctype: PID_MDOC_DOCTYPE }
    : { ...common, vct: credential.vct };
}

function sdJwtClaimPaths(claims: readonly string[]): string[][] {
  return claims.map((claim) => claim.split("."));
}

function mdocClaimPaths(namespace: string, elements: readonly string[]): string[][] {
  return elements.map((element) => [namespace, element]);
}
