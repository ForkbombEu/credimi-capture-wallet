import {
  CREDIMI_LOGO_URL,
  PID_MDOC_CLAIMS,
  PID_MDOC_DOCTYPE,
  PID_MDOC_NAMESPACE,
  PID_SD_JWT_CLAIMS,
  PID_SD_JWT_VCT,
} from "./credential-definitions.js";
import type { AppConfig } from "./types.js";

export type CredentialProofType = "jwt" | "attestation";
export type CredentialFormat = "dc+sd-jwt" | "mso_mdoc";

export interface SupportedCredential {
  id: string;
  scope: string;
  format: CredentialFormat;
  proofType: CredentialProofType;
  displayName: string;
}

export { PID_MDOC_DOCTYPE, PID_MDOC_NAMESPACE, PID_SD_JWT_VCT };

export function credentialIssuerMetadata(config: AppConfig): unknown {
  const credentials = supportedCredentials(config);

  return {
    credential_issuer: config.issuer_base_url,
    authorization_servers: [config.issuer_base_url],
    credential_endpoint: `${config.issuer_base_url}/credential`,
    nonce_endpoint: `${config.issuer_base_url}/nonce`,
    credential_configurations_supported: Object.fromEntries(
      credentials.map((credential) => [
        credential.id,
        credentialConfiguration(credential, proofTypesSupported(credential.proofType)),
      ]),
    ),
  };
}

export function authorizationServerMetadata(config: AppConfig): unknown {
  return {
    issuer: config.issuer_base_url,
    authorization_endpoint: `${config.issuer_base_url}/authorize`,
    token_endpoint: `${config.issuer_base_url}/token`,
    pushed_authorization_request_endpoint: `${config.issuer_base_url}/par`,
    jwks_uri: `${config.issuer_base_url}/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    token_endpoint_auth_methods_supported: ["private_key_jwt", "attest_jwt_client_auth"],
    token_endpoint_auth_signing_alg_values_supported: ["ES256"],
    client_attestation_signing_alg_values_supported: ["ES256"],
    client_attestation_pop_signing_alg_values_supported: ["ES256"],
    dpop_signing_alg_values_supported: ["ES256"],
  };
}

export function jwtVcIssuerMetadata(config: AppConfig): unknown {
  return {
    issuer: config.issuer_base_url,
    jwks_uri: `${config.issuer_base_url}/jwks.json`,
  };
}

export function credentialConfigurationId(
  config: AppConfig,
  proofType: CredentialProofType,
): string {
  return `${config.credential_configuration_id}.${proofType}`;
}

export function mdocCredentialConfigurationId(config: AppConfig): string {
  return `${config.credential_configuration_id}.mdoc.jwt`;
}

export function credentialScope(config: AppConfig, proofType: CredentialProofType): string {
  return `${config.credential_scope}.${proofType}`;
}

export function supportedCredentials(config: AppConfig): SupportedCredential[] {
  return [
    {
      id: credentialConfigurationId(config, "jwt"),
      scope: credentialScope(config, "jwt"),
      format: "dc+sd-jwt",
      proofType: "jwt",
      displayName: "Credimi Demo PID (SD-JWT VC, proof JWT)",
    },
    {
      id: mdocCredentialConfigurationId(config),
      scope: `${config.credential_scope}.mdoc.jwt`,
      format: "mso_mdoc",
      proofType: "jwt",
      displayName: "Credimi Demo PID (MDOC, proof JWT)",
    },
  ];
}

export function supportedCredentialConfigurationIds(config: AppConfig): string[] {
  return supportedCredentials(config).map((credential) => credential.id);
}

export function supportedCredentialById(
  config: AppConfig,
  credentialConfigurationId: string,
): SupportedCredential | null {
  return (
    supportedCredentials(config).find(
      (credential) => credential.id === credentialConfigurationId,
    ) ?? null
  );
}

export function supportedCredentialByScope(
  config: AppConfig,
  scope: string,
): SupportedCredential | null {
  return supportedCredentials(config).find((credential) => credential.scope === scope) ?? null;
}

export function credentialOffer(
  config: AppConfig,
  sessionId: string,
  credentialConfigurationId = supportedCredentialConfigurationIds(config)[0],
): unknown {
  const credential = supportedCredentialById(config, credentialConfigurationId);
  return {
    credential_issuer: config.issuer_base_url,
    credential_configuration_ids: [credentialConfigurationId],
    grants: {
      authorization_code: {
        issuer_state: sessionId,
        scope: credential?.scope,
      },
    },
  };
}

export function credentialOfferDeeplink(offer: unknown): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

function proofTypesSupported(proofType: CredentialProofType): Record<
  string,
  {
    key_attestations_required?: Record<string, unknown>;
    proof_signing_alg_values_supported: string[];
  }
> {
  if (proofType === "attestation") {
    return {
      attestation: {
        key_attestations_required: {},
        proof_signing_alg_values_supported: ["ES256"],
      },
    };
  }
  return {
    jwt: {
      proof_signing_alg_values_supported: ["ES256"],
    },
  };
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
    credential_signing_alg_values_supported:
      credential.format === "mso_mdoc" ? [-7, -9] : ["ES256"],
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
