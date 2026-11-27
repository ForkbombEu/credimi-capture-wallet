import type { IssuerConfiguration } from "../types.js";

/**
 * Opt-in issuer for credential types compiled from one subscribed Attestbook rulebook. It keeps
 * the PID issuers untouched and serves imported credentials only: until a rulebook version has
 * been activated, it advertises no credential configuration. Like `eu-pid-device-bound`, it
 * requires key attestation for both `jwt` and `attestation` proofs, which is what EUDI Wallets
 * following the ETSI profile accept.
 */
export const attestbookExperimental: IssuerConfiguration = {
  id: "attestbook-experimental",
  routeSlug: "attestbook-experimental",
  compliance: "experimental",
  proofPolicy: "key-attestation-required",
  feature: "attestbook",
  staticCredentialVcts: [],
  importsAttestbookCredentials: true,
  display: {
    name: "Attestbook issuer",
    description:
      "SD-JWT VC and mdoc credential types imported from a subscribed Attestbook rulebook, issued with generated test claim values. Requires key attestation.",
    warning:
      "Experimental: issuance success does not establish EUDI trust or interoperability compliance.",
  },
  authorizationServer: {
    externalScope: "credimi.capture.attestbook-experimental",
  },
};
