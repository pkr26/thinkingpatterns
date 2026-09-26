/** The ciphertext-only offline queue: scope partitioning, caps, backoff
 *  classification, the M-5 duplicate verification, the 401 keep-everything
 *  path, the generation fence, quarantine, and recovery. Uses the
 *  injectable kv backend + fetch stubs. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  abortInFlightFlush,
  flushQueueOnReconnect,
  clearQueue,
  enqueue,
  flushQueue,
  QueueAbandonedError,
  QueueFullError,
  queueLength,
  quarantinedQueueExists,
  rejectedEntries,
  requeueRejected,
  SessionExpiredError,
  MAX_QUEUE_LENGTH,
} from "../src/offlineQueue";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const ORIGIN = "http://localhost:5173";

function freshBackend(): { backend: KvBackend; dump: () => string[] } {
  const map = new Map<string, string>();
  const backend: KvBackend = {
    async getItem(key) {
      return map.get(key) ?? null;
    },
    async setItem(key, value) {
      map.set(key, value);
    },
    async removeItem(key) {
      map.delete(key);
    },
  };
  return { backend, dump: () => [...map.entries()].map(([k, v]) => `${k}=${v}`) };
}

const item = (n: number, overrides: Record<string, unknown> = {}): Parameters<typeof enqueue>[0] => ({
  userId: "user-1",
  clientEntryId: `e-2026-09-25-${n}`,
  blobB64: "AAECAwQFBgcICQoL",
  entryDate: "2026-09-25",
  ...overrides,
});

beforeEach(() => {
  resetTestState();
  installSession("user-1");
  const { backend } = freshBackend();
  setKvBackendForTests(backend);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("enqueue + scope", () => {
  it("queues ciphertext and reports length", async () => {
    await enqueue(item(1));
    await enqueue(item(2));
    expect(await queueLength("user-1")).toBe(2);
  });

  it("requires an account id", async () => {
    await expect(enqueue({ ...item(1), userId: "" })).rejects.toThrow("account id");
  });

  it("refuses to exceed the count cap", async () => {
    for (let n = 0; n < MAX_QUEUE_LENGTH; n += 1) await enqueue(item(n));
    await expect(enqueue(item(999))).rejects.toThrow(QueueFullError);
  });

  it("scopes storage by the caller's account id (one account cannot touch another's queue)", async () => {
    await enqueue({ ...item(1), userId: "attacker" });
    expect(await queueLength("user-1")).toBe(0);
    expect(await queueLength("attacker")).toBe(1);
    expect(await rejectedEntries("user-1")).toHaveLength(0);
  });
});

describe("flushQueue", () => {
  it("uploads due items as first-generation creates and removes them", async () => {
    await enqueue(item(1));
    await enqueue(item(2));
    const mock = stubFetch((url, init) => {
      expect(url).toBe(`${ORIGIN}/api/v1/entries`);
      const body = JSON.parse(String(init.body)) as { content_version?: number };
      expect(body.content_version).toBe(1);
      return jsonResponse({ id: "row" }, { status: 201 });
    });
    const sent = await flushQueue("user-1");
    expect(sent).toBe(2);
    expect(await queueLength("user-1")).toBe(0);
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it("honors notBefore (a rate-limited item does not re-fire immediately)", async () => {
    let calls = 0;
    stubFetch(() => {
      calls += 1;
      return jsonResponse({ detail: "slow", code: "rate_limited" }, { status: 429, headers: { "Retry-After": "60" } });
    });
    await enqueue(item(1));
    const sent = await flushQueue("user-1");
    expect(sent).toBe(0);
    expect(await queueLength("user-1")).toBe(1);
    const first = await flushQueue("user-1");
    expect(first).toBe(0); // still within the advisory window
    expect(calls).toBe(1);
  });

  it("a 409 with a real row (GET 200) is a verified duplicate — discarded", async () => {
    stubFetch((url) => {
      if (url.includes("/entries/") && url.split("/").pop() === "e-2026-09-25-1") {
        return jsonResponse({ id: "row", client_entry_id: "e-2026-09-25-1", blob: "AA", entry_date: "d", received_at: "r" });
      }
      return jsonResponse({ detail: "exists", code: "conflict" }, { status: 409 });
    });
    await enqueue(item(1));
    const sent = await flushQueue("user-1");
    expect(sent).toBe(0);
    expect(await queueLength("user-1")).toBe(0);
    expect(await rejectedEntries("user-1")).toHaveLength(0);
  });

  it("a lying 409 (GET 404) parks the item in the rejected store, never deletes it", async () => {
    stubFetch((url) => {
      if (url.includes("/entries/e-2026-09-25-1")) {
        return jsonResponse({ detail: "no", code: "not_found" }, { status: 404 });
      }
      return jsonResponse({ detail: "exists", code: "conflict" }, { status: 409 });
    });
    await enqueue(item(1));
    await flushQueue("user-1");
    expect(await queueLength("user-1")).toBe(0);
    const rejected = await rejectedEntries("user-1");
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.clientEntryId).toBe("e-2026-09-25-1");
    // Recovery moves it back.
    stubFetch(() => jsonResponse({ id: "row" }, { status: 201 }));
    const moved = await requeueRejected("user-1");
    expect(moved).toBe(1);
    expect(await queueLength("user-1")).toBe(1);
  });

  it("a 401 mid-flush preserves everything queued (SessionExpiredError)", async () => {
    stubFetch(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 }));
    await enqueue(item(1));
    await enqueue(item(2));
    await expect(flushQueue("user-1")).rejects.toThrow(SessionExpiredError);
    expect(await queueLength("user-1")).toBe(2);
    expect(await rejectedEntries("user-1")).toHaveLength(0);
  });

  it("a hard 413 parks as reject-and-stop", async () => {
    stubFetch(() => jsonResponse({ detail: "too big", code: "payload_too_large" }, { status: 413 }));
    await enqueue(item(1));
    await flushQueue("user-1");
    expect(await queueLength("user-1")).toBe(0);
    expect(await rejectedEntries("user-1")).toHaveLength(1);
  });

  it("corrupt queue bytes are quarantined, never wedged", async () => {
    const { backend } = freshBackend();
    // Pre-seed the scope's queue key with unparseable bytes.
    const bytes = new TextEncoder().encode(`${ORIGIN}\u0000user-1`);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    const scopeId = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    await backend.setItem(`mindpattern/queue.v1.items.${scopeId}`, "%%%not-json%%%");
    setKvBackendForTests(backend);
    expect(await queueLength("user-1")).toBe(0);
    expect(await quarantinedQueueExists("user-1")).toBe(true);
  });

  it("the generation fence abandons an enqueue racing a sign-out", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { backend } = freshBackend();
    let readStarted = false;
    setKvBackendForTests({
      getItem: async (key) => {
        readStarted = true; // the read is IN FLIGHT from here
        await gate; // hold it until the fence fires
        return backend.getItem(key);
      },
      setItem: backend.setItem,
      removeItem: backend.removeItem,
    });
    const pending = enqueue(item(1));
    // Let the microtask chain reach the gated read before fencing.
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(readStarted).toBe(true);
    abortInFlightFlush(); // sign-out lands while the read is in flight
    release();
    await expect(pending).rejects.toThrow(QueueAbandonedError);
  });

  it("clearQueue wipes the whole scope", async () => {
    await enqueue(item(1));
    await clearQueue("user-1");
    expect(await queueLength("user-1")).toBe(0);
  });

  it("flushQueueOnReconnect is throttled and flushes only a non-empty queue", async () => {
    stubFetch(() => jsonResponse({ id: "row" }, { status: 201 }));
    await enqueue(item(1));
    await flushQueueOnReconnect(); // flushes (network ok)
    expect(await queueLength("user-1")).toBe(0);
    // Immediately again: throttled — no flush happens (queue stays as-is).
    await enqueue(item(2));
    const before = Date.now();
    await flushQueueOnReconnect();
    expect(Date.now() - before).toBeLessThan(50); // returned without network work
    expect(await queueLength("user-1")).toBe(1);
  });

  it("storage-scrape: the persisted queue value contains ciphertext fields only", async () => {
    const { backend, dump } = freshBackend();
    setKvBackendForTests(backend);
    await enqueue({ ...item(1), blobB64: "T0hBSU9O" });
    const persisted = dump().join("\n");
    // Fields allowed in storage: the queue record's own shape. Forbidden:
    // any key/token/plaintext markers.
    expect(persisted).toContain("T0hBSU9O");
    expect(persisted).not.toMatch(/dataKey|authKey|token-123|Bearer/);
  });
});
