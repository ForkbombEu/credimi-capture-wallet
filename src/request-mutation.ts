import { isJsonPointer, setJsonPointer, unsetJsonPointer } from "./json-pointer.js";
import type { JsonRecord, VpRequestMutation, VpRequestMutationEdits } from "./types.js";

const MUTATION_TARGETS = ["outer_request", "request_object", "request_object_header"] as const;

/**
 * Applies a set of deliberately malformed edits to a generated protocol message and returns the
 * result. The input document is always copied, even with no edits: the caller keeps the message
 * the verifier generated and verifies against, and only the returned copy is delivered to the
 * wallet. Returning the same object for an empty edit set would let a later change to the
 * delivered copy move the verifier's own expectations with it.
 *
 * `set` writes a value at a JSON Pointer, including `null` and values of the wrong JSON type.
 * `unset` removes the member entirely, which is a different wire outcome from a `null` value.
 * Removals are applied after writes, so a mutation can replace a subtree and then prune part of it.
 */
export function applyRequestMutationEdits<T extends JsonRecord>(
  document: T,
  edits: VpRequestMutationEdits | undefined,
): T {
  const mutated = structuredClone(document);
  for (const [pointer, value] of Object.entries(edits?.set ?? {})) {
    setJsonPointer(mutated, pointer, value);
  }
  for (const pointer of edits?.unset ?? []) {
    unsetJsonPointer(mutated, pointer);
  }
  return mutated;
}

/** Every pointer the mutation touches, for the capture event. */
export function requestMutationPointers(mutation: VpRequestMutation): string[] {
  return MUTATION_TARGETS.flatMap((target) => {
    const edits = mutation[target];
    if (!edits) return [];
    return [...Object.keys(edits.set ?? {}), ...(edits.unset ?? [])].map(
      (pointer) => `${target}${pointer}`,
    );
  });
}

/**
 * Validates untrusted mutation input. Returns `undefined` when absent and `null` when malformed,
 * following the existing `clientMetadataOrNull` convention. Unknown members are rejected rather
 * than ignored, so a misspelled target cannot silently produce an unmutated request that the test
 * then reports as a wallet failure.
 */
export function requestMutationOrNull(value: unknown): VpRequestMutation | null | undefined {
  if (value === undefined) return undefined;
  const members = jsonObjectMembers(value);
  if (!members) return null;
  const mutation: VpRequestMutation = {};
  for (const [member, memberValue] of members) {
    if (member === "verification_applies") {
      if (typeof memberValue !== "boolean") return null;
      mutation.verification_applies = memberValue;
      continue;
    }
    if (!isMutationTarget(member)) return null;
    const edits = mutationEditsOrNull(memberValue);
    if (!edits) return null;
    mutation[member] = edits;
  }
  return Object.keys(mutation).length === 0 ? null : mutation;
}

function mutationEditsOrNull(value: unknown): VpRequestMutationEdits | null {
  const members = jsonObjectMembers(value);
  if (!members) return null;
  const edits: VpRequestMutationEdits = {};
  for (const [member, memberValue] of members) {
    if (member === "set") {
      const pointers = jsonObjectMembers(memberValue);
      if (!pointers || !pointers.every(([pointer]) => isJsonPointer(pointer))) return null;
      edits.set = Object.fromEntries(pointers);
      continue;
    }
    if (member === "unset") {
      if (!Array.isArray(memberValue) || !memberValue.every(isJsonPointer)) return null;
      edits.unset = memberValue;
      continue;
    }
    return null;
  }
  return edits.set === undefined && edits.unset === undefined ? null : edits;
}

function isMutationTarget(value: string): value is (typeof MUTATION_TARGETS)[number] {
  return MUTATION_TARGETS.some((target) => target === value);
}

/** Entries of an untrusted JSON object, or `null` when the value is not one. */
function jsonObjectMembers(value: unknown): [string, unknown][] | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return Object.entries(value);
}
