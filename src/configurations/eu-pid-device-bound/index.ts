import type { IssuerConfiguration } from "../types.js";

export const euPidDeviceBound: IssuerConfiguration = {
  id: "eu-pid-device-bound",
  routeSlug: "eu-pid-device-bound",
  compliance: "eudi-pid-device-bound",
  proofPolicy: "key-attestation-required",
  display: {
    name: "EUDI PID — device-bound conforming",
    description: "PID issuer advertising JWT and attestation proofs with key attestation required.",
  },
  authorizationServer: {
    externalScope: "credimi.capture.eu-pid-device-bound",
  },
};
