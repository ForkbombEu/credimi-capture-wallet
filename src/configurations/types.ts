import type { CredentialProofPolicy } from "../metadata.js";

export type IssuerConfigurationId = "eu-pid-device-bound" | "eu-pid-jwt-proof-only";

export type IssuerCompliance = "eudi-pid-device-bound" | "deliberately-nonconforming";

export interface IssuerDisplayConfiguration {
  readonly name: string;
  readonly description: string;
  readonly warning?: string;
}

export interface IssuerAuthorizationServerConfiguration {
  readonly externalScope: string;
}

export interface IssuerConfiguration {
  readonly id: IssuerConfigurationId;
  readonly routeSlug: IssuerConfigurationId;
  readonly compliance: IssuerCompliance;
  readonly proofPolicy: CredentialProofPolicy;
  readonly display: IssuerDisplayConfiguration;
  readonly authorizationServer: IssuerAuthorizationServerConfiguration;
}

export interface ResolvedIssuerEndpoints {
  readonly authorization: string;
  readonly credential: string;
  readonly credentialJwks: string;
  readonly credentialOffer: string;
  readonly jwks: string;
  readonly nonce: string;
  readonly par: string;
  readonly redirect: string;
  readonly token: string;
}

export interface ResolvedIssuerConfiguration extends IssuerConfiguration {
  readonly issuerIdentifier: string;
  readonly issuerMetadataUrl: string;
  readonly authorizationServerMetadataUrl: string;
  readonly upstreamAuthorizationServerIdentifier: string;
  readonly upstreamAuthorizationServerMetadataUrl: string;
  readonly materialDirectory: string;
  readonly issuerKeyId: string;
  readonly issuerEncryptionKeyId: string;
  readonly accessTokenKeyId: string;
  readonly endpoints: ResolvedIssuerEndpoints;
}

export interface IssuerCatalogueEntry {
  readonly id: IssuerConfigurationId;
  readonly compliance: IssuerCompliance;
  readonly credential_issuer: string;
  readonly credential_issuer_metadata: string;
  readonly authorization_server_metadata: string;
  readonly upstream_authorization_server: string;
  readonly name: string;
  readonly description: string;
  readonly warning?: string;
  readonly credential_configuration_ids: readonly string[];
}
