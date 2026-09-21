import type { JsonRecord, VpResponseScenario } from "./types.js";

/**
 * Validates untrusted response-scenario input. Returns `undefined` when absent and `null` when
 * malformed, following the existing `clientMetadataOrNull` convention.
 */
export function responseScenarioOrNull(value: unknown): VpResponseScenario | null | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const scenario: VpResponseScenario = {};
  for (const [member, memberValue] of Object.entries(value)) {
    if (member === "status") {
      if (!Number.isInteger(memberValue)) return null;
      const status = memberValue as number;
      if (status < 100 || status > 599) return null;
      scenario.status = status;
      continue;
    }
    if (member === "content_type" || member === "body") {
      if (typeof memberValue !== "string") return null;
      scenario[member] = memberValue;
      continue;
    }
    if (member === "extra_parameters") {
      if (typeof memberValue !== "object" || memberValue === null || Array.isArray(memberValue)) {
        return null;
      }
      scenario.extra_parameters = memberValue as JsonRecord;
      continue;
    }
    return null;
  }
  return Object.keys(scenario).length === 0 ? null : scenario;
}
