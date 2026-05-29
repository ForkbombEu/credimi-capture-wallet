import type { AppConfig } from "./types.js";

export function credentialIssuerMetadata(config: AppConfig): unknown {
  return {
    credential_issuer: config.issuer_base_url,
    authorization_servers: [config.issuer_base_url],
    credential_endpoint: `${config.issuer_base_url}/credential`,
    nonce_endpoint: `${config.issuer_base_url}/nonce`,
    credential_configurations_supported: {
      [config.credential_configuration_id]: {
        format: config.credential_format,
        scope: config.credential_scope,
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
      },
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
    token_endpoint_auth_methods_supported: ["none"],
    dpop_signing_alg_values_supported: ["ES256"],
  };
}

export function credentialOffer(config: AppConfig, sessionId: string): unknown {
  return {
    credential_issuer: config.issuer_base_url,
    credential_configuration_ids: [config.credential_configuration_id],
    grants: {
      authorization_code: {
        issuer_state: sessionId,
        scope: config.credential_scope,
      },
    },
  };
}

export function credentialOfferDeeplink(offer: unknown): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}
