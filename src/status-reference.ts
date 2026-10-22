import type { StatusReferenceFixture } from "./types.js";

/** Exhaustive over the union, so a new fixture cannot be added without exposing it here. */
const FIXTURES: Record<StatusReferenceFixture, true> = {
  valid: true,
  status_without_status_list: true,
  negative_index: true,
  missing_index: true,
  malformed_uri: true,
  missing_uri: true,
  uri_missing_scheme: true,
  uri_space_in_host: true,
  uri_invalid_percent_encoding: true,
  uri_illegal_characters: true,
  uri_empty: true,
};

export const STATUS_REFERENCE_FIXTURES = Object.keys(FIXTURES) as StatusReferenceFixture[];

export function statusReferenceFixtureOrNull(value: unknown): StatusReferenceFixture | null {
  return typeof value === "string" && Object.hasOwn(FIXTURES, value)
    ? (value as StatusReferenceFixture)
    : null;
}

/** Fixtures whose `uri` is the allocated URI with exactly one RFC 3986 violation. */
export type DerivedStatusUriFixture = Extract<
  StatusReferenceFixture,
  | "uri_missing_scheme"
  | "uri_space_in_host"
  | "uri_invalid_percent_encoding"
  | "uri_illegal_characters"
  | "uri_empty"
>;

/** RFC 3986 Appendix B: scheme, authority, and the remainder of a URI reference. */
const URI_COMPONENTS = /^([^:/?#]+):\/\/([^/?#]*)(.*)$/s;

/**
 * Derives a malformed status-list `uri` from the one the Status List service actually allocated,
 * so the only difference from a valid reference is the violation under test:
 *
 * - `uri_missing_scheme` drops the `scheme:` component, leaving the `//authority` reference;
 * - `uri_space_in_host` inserts a space in the middle of the host;
 * - `uri_invalid_percent_encoding` appends `%GG`, which is not two hex digits;
 * - `uri_illegal_characters` appends `<token>|1`, characters RFC 3986 does not permit;
 * - `uri_empty` is the empty string.
 */
export function derivedStatusListUri(allocated: string, fixture: DerivedStatusUriFixture): string {
  switch (fixture) {
    case "uri_invalid_percent_encoding":
      return `${allocated}%GG`;
    case "uri_illegal_characters":
      return `${allocated}<token>|1`;
    case "uri_empty":
      return "";
  }
  const components = URI_COMPONENTS.exec(allocated);
  if (!components) {
    throw new Error(`Allocated status list URI '${allocated}' has no scheme and authority`);
  }
  const [, scheme, authority, rest] = components;
  if (fixture === "uri_missing_scheme") return `//${authority}${rest}`;
  // The host sits between any `userinfo@` and any `:port`; an IP literal keeps its brackets.
  const userinfoEnd = authority.lastIndexOf("@") + 1;
  const port = /:\d*$/.exec(authority.slice(userinfoEnd))?.[0] ?? "";
  const host = authority.slice(userinfoEnd, authority.length - port.length);
  if (host.length < 2) {
    throw new Error(`Allocated status list URI '${allocated}' has no host to insert a space into`);
  }
  const middle = Math.floor(host.length / 2);
  const spaced = `${host.slice(0, middle)} ${host.slice(middle)}`;
  return `${scheme}://${authority.slice(0, userinfoEnd)}${spaced}${port}${rest}`;
}
