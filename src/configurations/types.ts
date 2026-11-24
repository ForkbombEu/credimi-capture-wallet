import type { CredentialProofPolicy } from "../types.js";

export type IssuerConfigurationId =
  | "eu-pid-device-bound"
  | "eu-pid-jwt-key-attestation"
  | "eu-pid-jwt-proof-only"
  | "attestbook-experimental";

type IssuerCompliance = "eudi-pid-device-bound" | "deliberately-nonconforming" | "experimental";

/** Opt-in feature an issuer belongs to; the issuer is served only when the feature is enabled. */
type IssuerFeature = "attestbook";

interface IssuerDisplayConfiguration {
  readonly name: string;
  readonly description: string;
  readonly warning?: string;
}

interface IssuerAuthorizationServerConfiguration {
  readonly externalScope: string;
}

export interface IssuerConfiguration {
  readonly id: IssuerConfigurationId;
  readonly routeSlug: IssuerConfigurationId;
  readonly compliance: IssuerCompliance;
  readonly proofPolicy: CredentialProofPolicy;
  readonly display: IssuerDisplayConfiguration;
  readonly authorizationServer: IssuerAuthorizationServerConfiguration;
  /** Absent for the always-served issuers. */
  readonly feature?: IssuerFeature;
  /**
   * Restricts the static catalogue to credentials of these `vct` values. Absent serves every
   * static credential of the issuer's proof policy, as every issuer did before this field existed.
   */
  readonly staticCredentialVcts?: readonly string[];
  /** Present when the issuer also serves credentials compiled from Attestbook rulebooks. */
  readonly importsAttestbookCredentials?: true;
}

interface ResolvedIssuerEndpoints {
  readonly authorization: string;
  readonly credential: string;
  readonly credentialJwks: string;
  readonly credentialOffer: string;
  readonly jwks: string;
  readonly nonce: string;
  /** OpenID4VCI 1.0 Section 11; advertised only when notifications are enabled. */
  readonly notification: string;
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
