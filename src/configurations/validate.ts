import type { IssuerConfiguration } from "./types.js";

const SAFE_ROUTE_SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function validateIssuerConfigurations(configurations: readonly IssuerConfiguration[]): void {
  if (configurations.length === 0) throw new Error("At least one issuer must be configured");

  const ids = new Set<string>();
  const slugs = new Set<string>();
  const scopes = new Set<string>();

  for (const configuration of configurations) {
    if (ids.has(configuration.id)) {
      throw new Error(`Duplicate issuer configuration id '${configuration.id}'`);
    }
    ids.add(configuration.id);

    if (!SAFE_ROUTE_SLUG.test(configuration.routeSlug)) {
      throw new Error(`Unsafe issuer route slug '${configuration.routeSlug}'`);
    }
    if (slugs.has(configuration.routeSlug)) {
      throw new Error(`Duplicate issuer route slug '${configuration.routeSlug}'`);
    }
    slugs.add(configuration.routeSlug);

    if (scopes.has(configuration.authorizationServer.externalScope)) {
      throw new Error(
        `Duplicate upstream authorization scope '${configuration.authorizationServer.externalScope}'`,
      );
    }
    scopes.add(configuration.authorizationServer.externalScope);

    if (
      configuration.compliance === "eudi-pid-device-bound" &&
      configuration.proofPolicy !== "key-attestation-required"
    ) {
      throw new Error(`Conforming issuer '${configuration.id}' must require key attestation`);
    }
    if (
      configuration.proofPolicy === "jwt-proof" &&
      configuration.compliance !== "deliberately-nonconforming"
    ) {
      throw new Error(
        `JWT-only PID issuer '${configuration.id}' must be explicitly non-conforming`,
      );
    }
  }
}
