import type { IssuerConfiguration } from "../types.js";

export const euPidJwtKeyAttestation: IssuerConfiguration = {
  id: "eu-pid-jwt-key-attestation",
  routeSlug: "eu-pid-jwt-key-attestation",
  compliance: "eudi-pid-device-bound",
  proofPolicy: "jwt-key-attestation-required",
  display: {
    name: "EUDI PID — JWT key attestation",
    description: "PID issuer advertising only JWT proofs with key attestation required.",
  },
  authorizationServer: {
    externalScope: "credimi.capture.eu-pid-jwt-key-attestation",
  },
};
