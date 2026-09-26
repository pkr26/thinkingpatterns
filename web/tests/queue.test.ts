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
  isFutureDateRejection,
  QueueAbandonedError,
  QueueFullError,
  queueLength,
  quarantinedQueueExists,
  rejectedEntries,
  requeueRejected,
  SessionExpiredError,
  MAX_QUEUE_LENGTH,
} from "../src/offlineQueue";
import { ApiError } from "../src/api/client";
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

describe("audit 2026-09-25 hardening", () => {
  it("a Retry-After: 0 advisory backs off at least one second — no re-POST storm", async () => {
    let posts = 0;
    stubFetch(() => {
      posts += 1;
      return jsonResponse({ detail: "back now", code: "service_unavailable" }, { status: 503, headers: { "Retry-After": "0" } });
    });
    await enqueue(item(1));
    // The drain loop must terminate: the item is re-parked with a real
    // delay, so the immediate re-flush below finds nothing due.
    expect(await flushQueue("user-1")).toBe(0);
    expect(await flushQueue("user-1")).toBe(0);
    expect(posts).toBe(1);
    expect(await queueLength("user-1")).toBe(1);
  });

  it("a past HTTP-date advisory (parsed as 0) gets the same floor", async () => {
    let posts = 0;
    stubFetch(() => {
      posts += 1;
      return jsonResponse({ detail: "x" }, { status: 503, headers: { "Retry-After": "Mon, 01 Jan 2001 00:00:00 GMT" } });
    });
    await enqueue(item(1));
    expect(await flushQueue("user-1")).toBe(0);
    expect(await flushQueue("user-1")).toBe(0);
    expect(posts).toBe(1);
  });

  it("enqueue is idempotent per client_entry_id (the id is the dedupe key)", async () => {
    await enqueue(item(1));
    await enqueue(item(1));
    await enqueue(item(1));
    expect(await queueLength("user-1")).toBe(1);
  });

  it("a wipe racing the enqueue commit is rolled back — nothing outlives sign-out", async () => {
    const map = new Map<string, string>();
    let bumped = false;
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
        // The commit lands, THEN the clearQueue generation bump fires —
        // the write-after-wipe interleave (audit TOCTOU).
        if (!bumped && k.includes(".items.")) {
          bumped = true;
          abortInFlightFlush();
        }
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    await expect(enqueue(item(1))).rejects.toThrow(QueueAbandonedError);
    expect([...map.keys()].filter((k) => k.includes(".items."))).toHaveLength(0);
  });

  it("corrupt member records inside a valid envelope are quarantined, not dropped", async () => {
    const map = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    await enqueue(item(1));
    const queueKey = [...map.keys()].find((k) => k.includes(".items."))!;
    const envelope = JSON.parse(map.get(queueKey)!) as { v: number; items: unknown[] };
    envelope.items.push({ garbage: "not-a-valid-record" });
    map.set(queueKey, JSON.stringify(envelope));
    expect(await queueLength("user-1")).toBe(1); // the valid record survives
    expect(await quarantinedQueueExists("user-1")).toBe(true); // the corrupt one is kept as evidence
    const quarantineKey = [...map.keys()].find((k) => k.includes(".quarantine."))!;
    const quarantine = JSON.parse(map.get(quarantineKey)!) as { records: string[] };
    expect(quarantine.records.some((record) => record.includes("not-a-valid-record"))).toBe(true);
  });

  it("the quarantine store is capped — a hostile store cannot grow it without bound", async () => {
    const map = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    const slots = Array.from({ length: 60 }, (_, n) => ({ corrupt: n }));
    await enqueue(item(1));
    const queueKey = [...map.keys()].find((k) => k.startsWith("mindpattern/queue.v1.items."))!;
    map.set(queueKey, JSON.stringify({ v: 1, items: [...slots, item(2)] }));
    await queueLength("user-1");
    const quarantineKey = [...map.keys()].find((k) => k.startsWith("mindpattern/queue.v1.quarantine."))!;
    const quarantine = JSON.parse(map.get(quarantineKey)!) as { records: string[] };
    expect(quarantine.records.length).toBeLessThanOrEqual(50);
    // The NEWEST records win when the cap evicts.
    expect(quarantine.records.at(-1)).toContain('"corrupt":59');
  });

  it("the future-date classifier: only genuine future-date 422s retry", () => {
    expect(isFutureDateRejection(new ApiError(422, "entry_date is in the future"))).toBe(true);
    expect(isFutureDateRejection(new ApiError(422, "date must not be in the FUTURE", "validation_error"))).toBe(true);
    expect(isFutureDateRejection(new ApiError(422, "blob is malformed", "validation_error"))).toBe(false);
    expect(isFutureDateRejection(new ApiError(422, "too many", "quota_exceeded"))).toBe(false);
  });

  it("a future-dated 422 stays queued for retry; any other 422 is rejected", async () => {
    stubFetch(() => jsonResponse({ detail: "entry_date is in the future", code: "validation_error" }, { status: 422 }));
    await enqueue(item(1));
    expect(await flushQueue("user-1")).toBe(0);
    expect(await queueLength("user-1")).toBe(1);
    expect(await rejectedEntries("user-1")).toHaveLength(0);

    // Fresh item for the non-future case (the first now carries a backoff).
    await clearQueue("user-1");
    await enqueue(item(2));
    stubFetch(() => jsonResponse({ detail: "blob is malformed", code: "validation_error" }, { status: 422 }));
    expect(await flushQueue("user-1")).toBe(0);
    expect(await queueLength("user-1")).toBe(0);
    expect(await rejectedEntries("user-1")).toHaveLength(1);
  });
});
