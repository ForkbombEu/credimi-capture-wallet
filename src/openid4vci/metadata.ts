import { type AgentContext, JwsService, JwtPayload, Kms } from "@credo-ts/core";
import {
  issuerSigningKeyId,
  loadIssuerEncryptionPublicJwk,
  loadIssuerJwks,
  loadIssuerPublicJwk,
} from "../config/key-material.js";
import type { IssuerConfiguration } from "../configurations/types.js";
import {
  type SupportedCredential,
  supportedCredentialsForIssuer,
} from "../credentials/catalogue.js";
import { CREDIMI_LOGO_URL, PID_MDOC_DOCTYPE } from "../credentials/definitions.js";
import type { AppConfig, CredentialProofPolicy, JsonRecord } from "../types.js";

export function credentialIssuerMetadata(
  config: AppConfig,
  issuer: IssuerConfiguration,
  credentials: readonly SupportedCredential[] = supportedCredentialsForIssuer(config, issuer),
): JsonRecord {
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
    credential_configurations_supported: credentialConfigurationsSupported(credentials),
  };
}

/** The `credential_configurations_supported` object for a set of credentials. */
export function credentialConfigurationsSupported(
  credentials: readonly SupportedCredential[],
): JsonRecord {
  return Object.fromEntries(
    credentials.map((credential) => [
      credential.id,
      credentialConfiguration(credential, proofTypesSupported(credential.proofPolicy)),
    ]),
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
    key: { keyId: issuerSigningKeyId(config) },
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
      claims: (
        credential.attestbook?.claimMetadata ??
        credential.claimPaths.map((path) => ({ path, mandatory: true, displayName: null }))
      ).map(({ path, mandatory, displayName }) => ({
        path: [...path],
        mandatory,
        display: [
          {
            name:
              displayName ??
              claimDisplayName(path.filter((segment) => segment !== null).at(-1) ?? ""),
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

function claimDisplayName(claim: string): string {
  return claim
    .split("_")
    .filter(Boolean)
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
    .join(" ");
}
