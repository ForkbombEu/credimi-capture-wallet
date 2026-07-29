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
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { AppConfig, JsonRecord } from "./types.js";

export type CredentialFormat = "dc+sd-jwt" | "mso_mdoc";
export type CredentialProofPolicy = "jwt-proof" | "key-attestation-required";

export interface SupportedCredential {
  id: string;
  scope: string;
  format: CredentialFormat;
  proofPolicy: CredentialProofPolicy;
  displayName: string;
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
    },
    {
      id: sdJwtCredentialConfigurationId(config, "jwt-proof"),
      scope: credentialScope(config, "dc+sd-jwt", "jwt-proof"),
      format: "dc+sd-jwt",
      proofPolicy: "jwt-proof",
      displayName: "Credimi Demo PID (SD-JWT VC, JWT proof, no key attestation)",
    },
    {
      id: mdocCredentialConfigurationId(config, "key-attestation-required"),
      scope: credentialScope(config, "mso_mdoc", "key-attestation-required"),
      format: "mso_mdoc",
      proofPolicy: "key-attestation-required",
      displayName: "Credimi Demo PID (MDOC, JWT or attestation proof, key attestation required)",
    },
    {
      id: mdocCredentialConfigurationId(config, "jwt-proof"),
      scope: credentialScope(config, "mso_mdoc", "jwt-proof"),
      format: "mso_mdoc",
      proofPolicy: "jwt-proof",
      displayName: "Credimi Demo PID (MDOC, JWT proof, no key attestation)",
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
    },
    cryptographic_binding_methods_supported:
      credential.format === "mso_mdoc" ? ["cose_key"] : ["jwk"],
    credential_signing_alg_values_supported: credential.format === "mso_mdoc" ? [-7] : ["ES256"],
    proof_types_supported: proofTypesSupported,
  };

  if (credential.format === "mso_mdoc") {
    return {
      ...common,
      doctype: PID_MDOC_DOCTYPE,
      credential_metadata: {
        ...common.credential_metadata,
        claims: pidClaimDescriptions(PID_MDOC_CLAIMS, (claim) => [PID_MDOC_NAMESPACE, claim]),
      },
    };
  }

  return {
    ...common,
    vct: PID_SD_JWT_VCT,
    credential_metadata: {
      ...common.credential_metadata,
      claims: pidClaimDescriptions(PID_SD_JWT_CLAIMS, sdJwtClaimPath),
    },
  };
}

function pidClaimDescriptions(
  claims: readonly string[],
  pathForClaim: (claim: string) => string[],
): Array<{
  path: string[];
  mandatory: boolean;
  display: Array<{ name: string; locale: string }>;
}> {
  return claims.map((claim) => ({
    path: pathForClaim(claim),
    mandatory: true,
    display: [
      {
        name: claimDisplayName(claim),
        locale: "en-US",
      },
    ],
  }));
}

function sdJwtClaimPath(claim: string): string[] {
  return claim.split(".");
}

function claimDisplayName(claim: string): string {
  return (
    claim
      .split(".")
      .at(-1)
      ?.split("_")
      .filter(Boolean)
      .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
      .join(" ") ?? claim
  );
}
