import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { DISABLED_ATTESTBOOK_SETTINGS } from "../src/attestbook/settings.js";
import type { AttestbookCredentialDefinition } from "../src/attestbook/types.js";
import { attestbookExperimental } from "../src/configurations/attestbook-experimental/index.js";
import type { ResolvedIssuerConfiguration } from "../src/configurations/types.js";
import {
  CatalogueConflictError,
  CredentialRegistry,
  type ImportedCatalogue,
  type IssuerRecordSynchronizer,
} from "../src/credential-registry.js";
import { type SupportedCredential, supportedCredentialsForIssuer } from "../src/metadata.js";
import {
  type IssuerTestEnvironment,
  createIssuerTestEnvironment,
  requireIssuer,
} from "./support/environment.js";

let environment: IssuerTestEnvironment;
let importingIssuer: ResolvedIssuerConfiguration;
let nonImportingIssuer: ResolvedIssuerConfiguration;
let staticCredential: SupportedCredential & { vct: string };

beforeAll(async () => {
  environment = await createIssuerTestEnvironment({
    prefix: "credential-registry-test-",
    config: {
      attestbook: {
        ...DISABLED_ATTESTBOOK_SETTINGS,
        enabled: true,
        base_url: "http://127.0.0.1:43123",
        rulebook_id: "registry-test-rulebook",
      },
    },
  });
  importingIssuer = requireIssuer(environment.config, "attestbook-experimental");
  nonImportingIssuer = requireIssuer(environment.config, "eu-pid-device-bound");
  const staticIssuer = { ...importingIssuer, staticCredentialVcts: undefined };
  const candidate = supportedCredentialsForIssuer(environment.config, staticIssuer).find(
    (credential): credential is SupportedCredential & { vct: string } =>
      credential.format === "dc+sd-jwt" && credential.vct !== undefined,
  );
  if (!candidate) throw new Error("No SD-JWT static credential available for conflict tests");
  staticCredential = candidate;
});

afterAll(() => environment.cleanup());

/**
 * No configured issuer currently reaches the static-conflict branches: the Attestbook issuer's
 * static catalogue is deliberately empty. The registry resolves by id, so temporarily expose the
 * static catalogue only around each conflict operation and always restore the shared configuration.
 */
async function withStaticCatalogue<T>(operation: () => Promise<T>): Promise<T> {
  const descriptor = Object.getOwnPropertyDescriptor(
    attestbookExperimental,
    "staticCredentialVcts",
  );
  if (!descriptor) throw new Error("Attestbook issuer static catalogue descriptor is missing");
  Object.defineProperty(attestbookExperimental, "staticCredentialVcts", {
    configurable: true,
    value: undefined,
    writable: true,
  });
  try {
    return await operation();
  } finally {
    Object.defineProperty(attestbookExperimental, "staticCredentialVcts", descriptor);
  }
}

function definition(
  overrides: {
    credentialConfigurationId?: string;
    scope?: string;
    vct?: string;
  } = {},
): AttestbookCredentialDefinition {
  const id = overrides.credentialConfigurationId ?? "urn:attestbook:membership-card";
  const vct = overrides.vct ?? id;
  return {
    origin: "https://attestbook.example.test",
    rulebookId: "registry-test-rulebook",
    version: "2026.11",
    contentDigest: "a".repeat(64),
    attestation: {
      name: "Membership Card",
      index: 0,
      attestationLoS: "substantial",
      bindingType: "holder-binding",
    },
    credentialConfigurationId: id,
    scope: overrides.scope ?? id,
    format: "dc+sd-jwt",
    vct,
    vctSource: "attestation_name",
    displayName: "Membership Card",
    claims: {
      kind: "object",
      displayName: null,
      selectivelyDisclosable: true,
      properties: [
        {
          name: "member_id",
          required: true,
          node: {
            kind: "scalar",
            type: "string",
            displayName: "Member ID",
            selectivelyDisclosable: true,
          },
        },
      ],
      additionalProperties: false,
    },
    claimMetadata: [{ path: ["member_id"], mandatory: true, displayName: "Member ID" }],
    schemaReferences: [
      {
        uri: "https://attestbook.example.test/schemas/membership.json",
        kind: "json_schema_2020_12",
        contentDigest: "b".repeat(64),
        integrity: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        hosted: true,
      },
    ],
    proofPolicy: "key-attestation-required",
    claimValueProvider: "faker-js",
    disclosurePolicy: "issuer-default-selective",
  };
}

function catalogue(
  definitions: readonly AttestbookCredentialDefinition[],
  issuerId: string = importingIssuer.id,
): ImportedCatalogue {
  return {
    issuerId,
    origin: "https://attestbook.example.test",
    rulebookId: "registry-test-rulebook",
    version: "2026.11",
    contentDigest: "a".repeat(64),
    publishedAt: "2026-11-24T00:00:00.000Z",
    eventId: "event-registry-test",
    activatedAt: "2026-11-24T00:00:01.000Z",
    definitions,
  };
}

async function captureRejection(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
  } catch (error) {
    return error;
  }
  throw new Error("Expected operation to reject");
}

describe("CredentialRegistry catalogue validation", () => {
  it("rejects duplicate credential configuration ids", async () => {
    const registry = new CredentialRegistry(environment.config);
    const duplicate = definition();
    const error = await captureRejection(
      registry.activate(
        catalogue([
          duplicate,
          { ...duplicate, attestation: { ...duplicate.attestation, index: 1 } },
        ]),
      ),
    );

    expect(error).toBeInstanceOf(CatalogueConflictError);
    expect(error).toEqual(
      expect.objectContaining({
        message: "Duplicate credential configuration id 'urn:attestbook:membership-card'",
      }),
    );
  });

  it.each([
    {
      conflict: "id",
      imported: () =>
        definition({
          credentialConfigurationId: staticCredential.id,
          scope: "urn:attestbook:id-conflict",
          vct: "urn:attestbook:id-conflict",
        }),
    },
    {
      conflict: "scope",
      imported: () =>
        definition({
          credentialConfigurationId: "urn:attestbook:scope-conflict",
          scope: staticCredential.scope,
        }),
    },
    {
      conflict: "vct",
      imported: () =>
        definition({
          credentialConfigurationId: "urn:attestbook:vct-conflict",
          vct: staticCredential.vct,
        }),
    },
  ])("rejects a static credential conflict by $conflict", async ({ imported }) => {
    const registry = new CredentialRegistry(environment.config);
    const importedDefinition = imported();
    const error = await withStaticCatalogue(() =>
      captureRejection(registry.activate(catalogue([importedDefinition]))),
    );

    expect(error).toBeInstanceOf(CatalogueConflictError);
    expect(error).toEqual(
      expect.objectContaining({
        message: `Imported credential '${importedDefinition.credentialConfigurationId}' conflicts with a static credential`,
      }),
    );
  });

  it("rejects an issuer that does not import Attestbook credentials", async () => {
    const registry = new CredentialRegistry(environment.config);
    const error = await captureRejection(
      registry.activate(catalogue([definition()], nonImportingIssuer.id)),
    );

    expect(error).toBeInstanceOf(CatalogueConflictError);
    expect(error).toEqual(
      expect.objectContaining({
        message: "Issuer 'eu-pid-device-bound' does not import Attestbook credentials",
      }),
    );
  });
  it("rejects an unknown issuer id", async () => {
    const registry = new CredentialRegistry(environment.config);
    const error = await captureRejection(
      registry.activate(catalogue([definition()], "unknown-issuer")),
    );

    expect(error).toBeInstanceOf(CatalogueConflictError);
    expect(error).toEqual(
      expect.objectContaining({
        message: "Issuer 'unknown-issuer' does not import Attestbook credentials",
      }),
    );
  });
});

describe("CredentialRegistry synchronization rollback", () => {
  it("restores a previous catalogue and rethrows the original synchronizer error", async () => {
    const registry = new CredentialRegistry(environment.config);
    const previous = catalogue([
      definition({ credentialConfigurationId: "urn:attestbook:previous" }),
    ]);
    const next = catalogue([definition({ credentialConfigurationId: "urn:attestbook:next" })]);
    await registry.activate(previous);
    const originalError = new Error("record update failed");
    const seen: (ImportedCatalogue | null)[] = [];
    const synchronizer = vi.fn<IssuerRecordSynchronizer>(async (issuer) => {
      seen.push(registry.activeCatalogue(issuer.id));
      if (seen.length === 1) throw originalError;
    });
    registry.attachIssuerSynchronizer(synchronizer);

    const error = await captureRejection(registry.activate(next));

    expect(error).toBe(originalError);
    expect(registry.activeCatalogue(importingIssuer.id)).toBe(previous);
    expect(seen).toEqual([next, previous]);
    expect(synchronizer).toHaveBeenCalledTimes(2);
    expect(synchronizer).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: importingIssuer.id }),
    );
    expect(synchronizer).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ id: importingIssuer.id }),
    );
  });

  it("clears imports when synchronization fails without a previous catalogue", async () => {
    const registry = new CredentialRegistry(environment.config);
    const initial = catalogue([
      definition({ credentialConfigurationId: "urn:attestbook:initial" }),
    ]);
    const originalError = new Error("initial record update failed");
    const seen: (ImportedCatalogue | null)[] = [];
    const synchronizer = vi.fn<IssuerRecordSynchronizer>(async (issuer) => {
      seen.push(registry.activeCatalogue(issuer.id));
      if (seen.length === 1) throw originalError;
    });
    registry.attachIssuerSynchronizer(synchronizer);

    const error = await captureRejection(registry.activate(initial));

    expect(error).toBe(originalError);
    expect(registry.activeCatalogue(importingIssuer.id)).toBeNull();
    expect(seen).toEqual([initial, null]);
    expect(synchronizer).toHaveBeenCalledTimes(2);
    expect(synchronizer).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: importingIssuer.id }),
    );
    expect(synchronizer).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ id: importingIssuer.id }),
    );
  });

  it("reports both synchronization and restoration failures", async () => {
    const registry = new CredentialRegistry(environment.config);
    const previous = catalogue([
      definition({ credentialConfigurationId: "urn:attestbook:previous" }),
    ]);
    const next = catalogue([definition({ credentialConfigurationId: "urn:attestbook:next" })]);
    await registry.activate(previous);
    const firstError = new Error("record update failed");
    const restoreError = new Error("restore update failed");
    const seen: (ImportedCatalogue | null)[] = [];
    const synchronizer = vi.fn<IssuerRecordSynchronizer>(async (issuer) => {
      seen.push(registry.activeCatalogue(issuer.id));
      if (seen.length === 1) throw firstError;
      throw restoreError;
    });
    registry.attachIssuerSynchronizer(synchronizer);

    const error = await captureRejection(registry.activate(next));

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(CatalogueConflictError);
    expect(error).toEqual(
      expect.objectContaining({
        message:
          "record update failed; restoring the previous issuer record also failed: restore update failed",
      }),
    );
    expect(registry.activeCatalogue(importingIssuer.id)).toBe(previous);
    expect(seen).toEqual([next, previous]);
    expect(synchronizer).toHaveBeenCalledTimes(2);
    expect(synchronizer).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: importingIssuer.id }),
    );
    expect(synchronizer).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ id: importingIssuer.id }),
    );
  });

  it("accepts the next activation after a failed one", async () => {
    const registry = new CredentialRegistry(environment.config);
    const synchronizer = vi.fn<IssuerRecordSynchronizer>().mockResolvedValue(undefined);
    registry.attachIssuerSynchronizer(synchronizer);
    const duplicate = definition();
    const duplicateError = await captureRejection(
      registry.activate(
        catalogue([
          duplicate,
          { ...duplicate, attestation: { ...duplicate.attestation, index: 1 } },
        ]),
      ),
    );
    expect(duplicateError).toBeInstanceOf(CatalogueConflictError);

    const valid = catalogue([
      definition({ credentialConfigurationId: "urn:attestbook:valid-after-failure" }),
    ]);
    await expect(registry.activate(valid)).resolves.toBeUndefined();
    expect(registry.activeCatalogue(importingIssuer.id)).toBe(valid);
    expect(synchronizer).toHaveBeenCalledTimes(1);
  });
  it("serializes concurrent activations without overlapping synchronizer calls", async () => {
    const registry = new CredentialRegistry(environment.config);
    const first = catalogue([
      definition({ credentialConfigurationId: "urn:attestbook:concurrent-first" }),
    ]);
    const second = catalogue([
      definition({ credentialConfigurationId: "urn:attestbook:concurrent-second" }),
    ]);
    let release!: () => void;
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const seen: string[] = [];
    const synchronizer = vi.fn<IssuerRecordSynchronizer>(async (issuer) => {
      seen.push(
        registry.activeCatalogue(issuer.id)?.definitions[0]?.credentialConfigurationId ?? "none",
      );
      markStarted();
      await gate;
    });
    registry.attachIssuerSynchronizer(synchronizer);

    const firstActivation = registry.activate(first);
    await started;
    const secondActivation = registry.activate(second);
    await Promise.resolve();
    expect(synchronizer).toHaveBeenCalledTimes(1);

    release();
    await Promise.all([firstActivation, secondActivation]);
    expect(seen).toEqual(["urn:attestbook:concurrent-first", "urn:attestbook:concurrent-second"]);
    expect(synchronizer).toHaveBeenCalledTimes(2);
    expect(synchronizer).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: importingIssuer.id }),
    );
    expect(synchronizer).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ id: importingIssuer.id }),
    );
  });

  it("exposes successfully activated credentials through registry lookup", async () => {
    const registry = new CredentialRegistry(environment.config);
    const importedDefinition = definition({ credentialConfigurationId: "urn:attestbook:lookup" });
    await registry.activate(catalogue([importedDefinition]));

    expect(registry.credentialsForIssuer(importingIssuer)).toContainEqual({
      id: importedDefinition.credentialConfigurationId,
      scope: importedDefinition.scope,
      format: importedDefinition.format,
      proofPolicy: importedDefinition.proofPolicy,
      displayName: importedDefinition.displayName,
      vct: importedDefinition.vct,
      claimPaths: importedDefinition.claimMetadata.map((claim) => claim.path),
      attestbook: importedDefinition,
    });
    expect(
      registry.credentialById(importingIssuer, importedDefinition.credentialConfigurationId),
    ).toEqual(
      expect.objectContaining({
        id: importedDefinition.credentialConfigurationId,
        attestbook: importedDefinition,
      }),
    );
  });
});
