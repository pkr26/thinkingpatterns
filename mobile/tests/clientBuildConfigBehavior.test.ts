import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

beforeEach(() => { vi.resetModules(); storage.__reset(); });
afterEach(() => { vi.unstubAllGlobals(); });

it.each([
  [undefined, undefined, "https://api.mindpattern.example"],
  [false, undefined, "https://api.mindpattern.example"],
  [true, undefined, "http://localhost:8000"],
  [false, "https://deployed.example.com", "https://deployed.example.com"],
  [true, "https://deployed.example.com", "http://localhost:8000"],
  [false, null, "https://api.mindpattern.example"],
] as const)("resolves build defaults for development=%s and injected origin=%s", async (development, injected, expected) => {
  vi.stubGlobal("__DEV__", development); vi.stubGlobal("__API_ORIGIN__", injected);
  const client = await import("../src/api/client");
  expect(client.DEFAULT_BASE_URL).toBe(expected);
  expect(client.PRODUCTION_BASE_URL).toBe(typeof injected === "string" ? injected : "https://api.mindpattern.example");
  expect(await client.getBaseUrl()).toBe(expected);
  const fetch = vi.fn(async () => new Response('{"version":"deployed"}')); vi.stubGlobal("fetch", fetch);
  expect(await client.api.meta()).toEqual({ version: "deployed" });
  expect(fetch.mock.calls[0]![0]).toBe(expected + "/api/v1/meta");
});
