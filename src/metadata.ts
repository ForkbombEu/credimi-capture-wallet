import { CREDIMI_LOGO_URL } from "./credential.js";
import type { AppConfig } from "./types.js";

export function credentialIssuerMetadata(config: AppConfig): unknown {
  const jwtConfigurationId = credentialConfigurationId(config, "jwt");
  const attestationConfigurationId = credentialConfigurationId(config, "attestation");

  return {
    credential_issuer: config.issuer_base_url,
    authorization_servers: [config.issuer_base_url],
    credential_endpoint: `${config.issuer_base_url}/credential`,
    nonce_endpoint: `${config.issuer_base_url}/nonce`,
    credential_configurations_supported: {
      [jwtConfigurationId]: credentialConfiguration(
        config,
        jwtConfigurationId,
        credentialScope(config, "jwt"),
        {
          jwt: {
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
      ),
      [attestationConfigurationId]: credentialConfiguration(
        config,
        attestationConfigurationId,
        credentialScope(config, "attestation"),
        {
          attestation: {
            key_attestations_required: {},
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
      ),
    },
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
    token_endpoint_auth_methods_supported: ["none", "private_key_jwt", "attest_jwt_client_auth"],
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
  proofType: "jwt" | "attestation",
): string {
  return `${config.credential_configuration_id}.${proofType}`;
}

export function credentialScope(config: AppConfig, proofType: "jwt" | "attestation"): string {
  return `${config.credential_scope}.${proofType}`;
}

export function supportedCredentialConfigurationIds(config: AppConfig): string[] {
  return [
    credentialConfigurationId(config, "jwt"),
    credentialConfigurationId(config, "attestation"),
  ];
}

export function credentialOffer(
  config: AppConfig,
  sessionId: string,
  credentialConfigurationId = supportedCredentialConfigurationIds(config)[0],
): unknown {
  return {
    credential_issuer: config.issuer_base_url,
    credential_configuration_ids: [credentialConfigurationId],
    grants: {
      authorization_code: {
        issuer_state: sessionId,
      },
    },
  };
}

export function credentialOfferDeeplink(offer: unknown): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

function credentialConfiguration(
  config: AppConfig,
  id: string,
  scope: string,
  proofTypesSupported: Record<
    string,
    {
      key_attestations_required?: Record<string, unknown>;
      proof_signing_alg_values_supported: string[];
    }
  >,
): unknown {
  return {
    format: config.credential_format,
    scope,
    display: [
      {
        name: "Credimi Demo PID",
        locale: "en-US",
        logo: {
          uri: CREDIMI_LOGO_URL,
          alt_text: "Credimi",
        },
      },
    ],
    cryptographic_binding_methods_supported: ["jwk"],
    credential_signing_alg_values_supported: ["ES256"],
    vct: id,
    proof_types_supported: proofTypesSupported,
  };
}
