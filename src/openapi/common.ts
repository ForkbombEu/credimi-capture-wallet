import type { JsonRecord } from "../types.js";

export const json = (schema: JsonRecord = { type: "object" }): JsonRecord => ({
  content: { "application/json": { schema } },
});

export const form = (schema: JsonRecord): JsonRecord => ({
  content: { "application/x-www-form-urlencoded": { schema } },
});

export const response = (description: string, schema?: JsonRecord): JsonRecord => ({
  description,
  ...(schema ? json(schema) : {}),
});

export const errorResponses: JsonRecord = {
  "400": response("The request is invalid for the current protocol state.", {
    $ref: "#/components/schemas/Error",
  }),
  "404": response("The requested session or protocol resource was not found.", {
    $ref: "#/components/schemas/Error",
  }),
};

export const sessionIdParameter: JsonRecord = {
  name: "sessionId",
  in: "path",
  required: true,
  description: "Capture session identifier returned when the session was created.",
  schema: { type: "string", format: "uuid" },
};

export function issuerConfigurationIdParameterFor(issuerIds: readonly string[]): JsonRecord {
  return {
    name: "issuerConfigurationId",
    in: "path",
    required: true,
    description: "Served issuer configuration identifier returned by GET /issuers.",
    schema: { type: "string", enum: [...issuerIds] },
  };
}
