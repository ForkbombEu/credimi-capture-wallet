import { DEGREE_SD_JWT_VCT } from "../../credential-definitions.js";
import type { IssuerConfiguration } from "../types.js";

/**
 * Opt-in issuer for credential types compiled from one subscribed Attestbook rulebook. It keeps
 * the PID issuers untouched: its static catalogue is only the Credimi test degree, so it always
 * advertises one issuable configuration even before any rulebook has been imported.
 */
export const attestbookExperimental: IssuerConfiguration = {
  id: "attestbook-experimental",
  routeSlug: "attestbook-experimental",
  compliance: "experimental",
  proofPolicy: "jwt-proof",
  feature: "attestbook",
  staticCredentialVcts: [DEGREE_SD_JWT_VCT],
  importsAttestbookCredentials: true,
  display: {
    name: "Attestbook experimental issuer",
    description:
      "SD-JWT VC credential types imported from a subscribed Attestbook rulebook, issued with local test claim values.",
    warning:
      "Experimental: issuance success does not establish EUDI trust or interoperability compliance.",
  },
  authorizationServer: {
    externalScope: "credimi.capture.attestbook-experimental",
  },
};
