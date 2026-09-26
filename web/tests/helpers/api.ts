/** Test helpers for API-driving view tests: a fetch stub and module-state
 *  reset. The window shim's storage persists across tests within a file,
 *  and the api client + vault are module singletons — both must be
 *  normalized between tests. */
import { vi } from "vitest";
import { clearSession, setSession } from "../../src/api/client";
import { setKvBackendForTests, type KvBackend } from "../../src/kvstore";
import { resetEntryVersionMirrors } from "../../src/entryVersions";
import { vault } from "../../src/vault";

export type FetchHandler = (url: string, init: RequestInit) => Response | Promise<Response>;

/** A fresh in-memory kv backend per test (isolated queue/mood/version
 *  stores; tests that need their own can re-inject after this). */
export function memoryKvBackend(): KvBackend {
  const map = new Map<string, string>();
  return {
    async getItem(key: string) {
      return map.get(key) ?? null;
    },
    async setItem(key: string, value: string) {
      map.set(key, value);
    },
    async removeItem(key: string) {
      map.delete(key);
    },
  };
}

/** Install a global fetch stub returning real Response objects. Returns the
 *  mock for call assertions. */
export function stubFetch(handler: FetchHandler): ReturnType<typeof vi.fn> {
  const mock = vi.fn(handler);
  vi.stubGlobal("fetch", mock);
  return mock;
}

export function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
}

/** Normalize module state: kill the session, lock the vault, wipe the shim
 *  storage, and give the kv seam a fresh in-memory backend. Call in
 *  beforeEach of every test that touches client, vault, or stores. */
export function resetTestState(): void {
  clearSession();
  vault.lock();
  setKvBackendForTests(memoryKvBackend());
  resetEntryVersionMirrors();
  const win = (globalThis as { window?: { localStorage?: Storage; sessionStorage?: Storage } }).window;
  win?.localStorage?.clear();
  win?.sessionStorage?.clear();
}

/** Install a signed-in session against the shim origin (loopback http is
 *  allowed in the test build), as a successful login would have. */
export function installSession(userId = "user-1", username = "tester"): void {
  setSession("token-123", userId, username);
}
