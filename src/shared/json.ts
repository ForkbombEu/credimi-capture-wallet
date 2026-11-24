import type { JsonRecord } from "../types.js";

export function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown): JsonRecord | null {
  return isRecord(value) ? value : null;
}

export function asStringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}
