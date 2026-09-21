import type { StatusReferenceFixture } from "./types.js";

/** Exhaustive over the union, so a new fixture cannot be added without exposing it here. */
const FIXTURES: Record<StatusReferenceFixture, true> = {
  valid: true,
  status_without_status_list: true,
  negative_index: true,
  missing_index: true,
  malformed_uri: true,
  missing_uri: true,
};

export const STATUS_REFERENCE_FIXTURES = Object.keys(FIXTURES) as StatusReferenceFixture[];

export function statusReferenceFixtureOrNull(value: unknown): StatusReferenceFixture | null {
  return typeof value === "string" && Object.hasOwn(FIXTURES, value)
    ? (value as StatusReferenceFixture)
    : null;
}
