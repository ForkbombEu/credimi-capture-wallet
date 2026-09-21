import type { JsonRecord } from "./types.js";

type JsonContainer = JsonRecord | unknown[];

/**
 * RFC 6901 JSON Pointer, used to address a single member of a generated protocol message.
 *
 * Dotted paths cannot be used for this: object keys in the EUDI protocols contain dots and plus
 * signs, such as the mdoc namespace `eu.europa.ec.eudi.pid.1` and the credential format
 * `dc+sd-jwt`, so a dotted path could not address them unambiguously.
 */
export function parseJsonPointer(pointer: string): string[] {
  if (pointer === "") {
    throw new Error("JSON Pointer must address a member, not the whole document");
  }
  if (!pointer.startsWith("/")) {
    throw new Error(`JSON Pointer must start with '/', received '${pointer}'`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
}

export function isJsonPointer(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    parseJsonPointer(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Writes `value` at `pointer`, creating missing intermediate objects. A `null` value is written as
 * a member holding null, which is a different wire outcome from removing the member.
 */
export function setJsonPointer(document: JsonRecord, pointer: string, value: unknown): void {
  const tokens = parseJsonPointer(pointer);
  const member = tokens.pop() as string;
  let node: JsonContainer = document;
  for (const token of tokens) {
    const child = readMember(node, token);
    if (isJsonContainer(child)) {
      node = child;
      continue;
    }
    if (child !== undefined) {
      throw new Error(`JSON Pointer '${pointer}' traverses the non-container member '${token}'`);
    }
    const created: JsonRecord = {};
    writeMember(node, token, created);
    node = created;
  }
  writeMember(node, member, value);
}

/** Removes the member at `pointer`. Returns whether a member was present to remove. */
export function unsetJsonPointer(document: JsonRecord, pointer: string): boolean {
  const tokens = parseJsonPointer(pointer);
  const member = tokens.pop() as string;
  let node: JsonContainer = document;
  for (const token of tokens) {
    const child = readMember(node, token);
    if (!isJsonContainer(child)) return false;
    node = child;
  }
  if (Array.isArray(node)) {
    const index = arrayIndex(node, member);
    if (index === null || index >= node.length) return false;
    node.splice(index, 1);
    return true;
  }
  if (!Object.hasOwn(node, member)) return false;
  node[member] = undefined;
  return true;
}

export function readJsonPointer(document: JsonRecord, pointer: string): unknown {
  const tokens = parseJsonPointer(pointer);
  let node: unknown = document;
  for (const token of tokens) {
    if (!isJsonContainer(node)) return undefined;
    node = readMember(node, token);
  }
  return node;
}

function isJsonContainer(value: unknown): value is JsonContainer {
  return typeof value === "object" && value !== null;
}

function readMember(node: JsonContainer, token: string): unknown {
  if (!Array.isArray(node)) return node[token];
  const index = arrayIndex(node, token);
  return index === null ? undefined : node[index];
}

function writeMember(node: JsonContainer, token: string, value: unknown): void {
  if (!Array.isArray(node)) {
    node[token] = value;
    return;
  }
  if (token === "-") {
    node.push(value);
    return;
  }
  const index = arrayIndex(node, token);
  if (index === null) {
    throw new Error(`JSON Pointer array member '${token}' is not an index`);
  }
  node[index] = value;
}

function arrayIndex(node: unknown[], token: string): number | null {
  if (token === "-") return node.length;
  return /^(0|[1-9][0-9]*)$/.test(token) ? Number(token) : null;
}
