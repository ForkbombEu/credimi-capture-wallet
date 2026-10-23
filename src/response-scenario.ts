import { isJsonPointer } from "./json-pointer.js";
import type {
  IssuanceEndpointResponseScenario,
  IssuanceResponseScenario,
  JsonRecord,
  VpResponseScenario,
} from "./types.js";

const ISSUANCE_SCENARIO_ENDPOINTS = ["par", "credential"] as const;

/**
 * Validates untrusted response-scenario input. Returns `undefined` when absent and `null` when
 * malformed, following the existing `clientMetadataOrNull` convention.
 */
export function responseScenarioOrNull(value: unknown): VpResponseScenario | null | undefined {
  if (value === undefined) return undefined;
  return endpointScenarioOrNull(value, false);
}

/**
 * Validates an `issuance_response_scenario`: one VP-style response scenario per issuer endpoint,
 * which may also remove members of the normal JSON body by JSON Pointer. Unknown endpoints and
 * members are rejected, so a misspelling cannot silently leave the response untouched.
 */
export function issuanceResponseScenarioOrNull(
  value: unknown,
): IssuanceResponseScenario | null | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const scenario: IssuanceResponseScenario = {};
  for (const [endpoint, endpointValue] of Object.entries(value)) {
    if (!isIssuanceScenarioEndpoint(endpoint)) return null;
    const endpointScenario = endpointScenarioOrNull(endpointValue, true);
    if (!endpointScenario) return null;
    scenario[endpoint] = endpointScenario;
  }
  return Object.keys(scenario).length === 0 ? null : scenario;
}

function endpointScenarioOrNull(
  value: unknown,
  allowOmitParameters: boolean,
): IssuanceEndpointResponseScenario | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const scenario: IssuanceEndpointResponseScenario = {};
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
    if (member === "omit_parameters" && allowOmitParameters) {
      if (!Array.isArray(memberValue) || !memberValue.every(isJsonPointer)) return null;
      scenario.omit_parameters = memberValue;
      continue;
    }
    return null;
  }
  return Object.keys(scenario).length === 0 ? null : scenario;
}

function isIssuanceScenarioEndpoint(
  value: string,
): value is (typeof ISSUANCE_SCENARIO_ENDPOINTS)[number] {
  return ISSUANCE_SCENARIO_ENDPOINTS.some((endpoint) => endpoint === value);
}
