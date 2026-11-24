import type { Express } from "express";
import request from "supertest";
import { expect } from "vitest";

export async function getJson<T>(app: Express, path: string): Promise<T> {
  const response = await request(app).get(path);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

export async function postJson<T>(app: Express, path: string, body: object): Promise<T> {
  const response = await request(app).post(path).send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}

export async function postForm<T>(
  app: Express,
  path: string,
  body: Record<string, string>,
): Promise<T> {
  const response = await request(app).post(path).type("form").send(body);
  expect(response.status).toBeLessThan(400);
  return response.body as T;
}
