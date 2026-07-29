import type { IssuerConfiguration } from "../types.js";

export const euPidJwtProofOnly: IssuerConfiguration = {
  id: "eu-pid-jwt-proof-only",
  routeSlug: "eu-pid-jwt-proof-only",
  compliance: "deliberately-nonconforming",
  proofPolicy: "jwt-proof",
  display: {
    name: "EUDI PID — JWT proof only",
    description: "PID interoperability test issuer advertising JWT proof without key attestation.",
    warning:
      "Deliberately non-conforming for a device-bound EUDI PID; a conforming wallet may reject issuance.",
  },
  authorizationServer: {
    externalScope: "credimi.capture.eu-pid-jwt-proof-only",
  },
};
