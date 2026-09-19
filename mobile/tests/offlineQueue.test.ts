/** Security and recovery tests for the origin/account-scoped offline queue. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

let baseUrl = "https://one.example.test";

vi.mock("../src/api/client", () => {
  class ApiError extends Error {
    constructor(public status: number, message: string, public code?: string, public retryAfterMs?: number) {
      super(message);
    }
  }
  class OriginPinnedError extends Error {
    constructor(public expected: string, public actual: string) {
      super(`refusing to send data pinned to ${expected} while ${actual} is selected`);
    }
  }
  return {
    ApiError,
    OriginPinnedError,
    getBaseUrl: vi.fn(async () => baseUrl),
    api: {
      createEntry: vi.fn(async () => ({})),
      createQueuedEntry: vi.fn(async () => ({})),
      getUserId: vi.fn(async () => "alice"),
    },
  };
});

const { api, ApiError, OriginPinnedError } = await import("../src/api/client") as any;
const {
  enqueue,
  flushQueue,
  clearQueue,
  queueLength,
  quarantinedQueueExists,
  rejectedEntries,
  rejectedEntryCount,
  requeueRejected,
  hasLegacyQueueRecovery,
  abortInFlightFlush,
  MAX_QUEUE_LENGTH,
  QueueFullError,
  SessionExpiredError,
} = await import("../src/offlineQueue");

const entry = (userId: string, id: string) => ({
  userId,
  clientEntryId: id,
  blobB64: Buffer.alloc(48, id.length).toString("base64"),
  entryDate: "2026-09-01",
});

const scopedKeys = async (kind: "items" | "rejected" | "quarantine") =>
  (await storage.getAllKeys()).filter((key: string) => key.startsWith(`@mindpattern/queue.v2.${kind}.`));

beforeEach(() => {
  storage.__reset();
  baseUrl = "https://one.example.test";
  vi.mocked(api.createQueuedEntry).mockReset();
  vi.mocked(api.createQueuedEntry).mockImplementation(async () => ({}));
  vi.mocked(api.getUserId).mockReset();
  vi.mocked(api.getUserId).mockResolvedValue("alice");
});

describe("offline queue scope", () => {
  it("uses physically separate origin/account stores and never uploads a foreign scope", async () => {
    await enqueue(entry("alice", "a-1"));
    await enqueue(entry("bob", "b-1"));

    expect(await scopedKeys("items")).toHaveLength(2);
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createQueuedEntry).toHaveBeenCalledWith("a-1", expect.any(String), "2026-09-01", "https://one.example.test");
    expect(await queueLength("alice")).toBe(0);
    expect(await queueLength("bob")).toBe(1);

    // Account deletion only deletes this account's selected-origin stores.
    await clearQueue("alice");
    expect(await queueLength("bob")).toBe(1);
  });

  it("does not expose or upload pending ciphertext after an origin change", async () => {
    await enqueue(entry("alice", "a-on-one"));
    baseUrl = "https://two.example.test";

    expect(await queueLength("alice")).toBe(0);
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).not.toHaveBeenCalled();

    baseUrl = "https://one.example.test";
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);
  });

  it("keeps rejected recovery scoped to the same account and origin", async () => {
    await enqueue(entry("alice", "a-rejected"));
    await enqueue(entry("bob", "b-live"));
    vi.mocked(api.createQueuedEntry).mockImplementation(async (id: string) => {
      if (id === "a-rejected") throw new ApiError(422, "invalid encrypted blob");
      return {};
    });

    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries("alice")).map((item: any) => item.clientEntryId)).toEqual(["a-rejected"]);
    expect(await rejectedEntryCount("bob")).toBe(0);
    expect(await queueLength("bob")).toBe(1);

    vi.mocked(api.createQueuedEntry).mockImplementation(async () => ({}));
    expect(await requeueRejected("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);
    expect(await rejectedEntryCount("alice")).toBe(0);
  });

  it("moves only the current scope to recovery after an authentic 401", async () => {
    await enqueue(entry("alice", "a-1"));
    await enqueue(entry("alice", "a-2"));
    await enqueue(entry("bob", "b-1"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(401, "expired"));

    await expect(flushQueue("alice")).rejects.toBeInstanceOf(SessionExpiredError);
    expect((await rejectedEntries("alice")).map((item: any) => item.clientEntryId)).toEqual(["a-1", "a-2"]);
    expect(await queueLength("bob")).toBe(1);
  });

  it("fences an in-flight flush on sign-out rather than rejecting its ciphertext", async () => {
    await enqueue(entry("alice", "a-1"));
    let release!: () => void;
    vi.mocked(api.createQueuedEntry).mockImplementationOnce(
      () => new Promise((resolve) => { release = () => resolve({}); }),
    );
    const flushing = flushQueue("alice");
    await new Promise((resolve) => setTimeout(resolve, 0));
    abortInFlightFlush();
    release();

    // The upload reached the server, but the local commit was fence-
    // abandoned and the entry is still queued — so the flush must NOT
    // report it as sent (the badge/UI count would overstate progress; a
    // later flush safely receives server-side 409 dedupe).
    expect(await flushing).toBe(0);
    expect(await queueLength("alice")).toBe(1);
    expect(await rejectedEntries("alice")).toEqual([]);
  });
});

describe("cross-origin upload containment (2026-09-18 audit)", () => {
  it("stops the flush when the selected origin moves between iterations", async () => {
    await enqueue(entry("alice", "a-first"));
    await enqueue(entry("alice", "a-second"));
    // The first upload succeeds and flips the server selection before the
    // loop's next iteration: exactly the origin-switch + re-login window.
    vi.mocked(api.createQueuedEntry).mockImplementationOnce(async () => {
      baseUrl = "https://two.example.test";
      return {};
    });

    expect(await flushQueue("alice")).toBe(1);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);
    expect(api.createQueuedEntry).toHaveBeenCalledWith("a-first", expect.any(String), "2026-09-01", "https://one.example.test");
    // Under the NEW origin the old scope is invisible — the containment
    // guarantee itself — and nothing was moved to any rejected store.
    expect(await queueLength("alice")).toBe(0);
    expect(await rejectedEntries("alice")).toEqual([]);

    // Back on the original origin, the un-uploaded item is still queued —
    // never sent to the new origin, never lost.
    baseUrl = "https://one.example.test";
    expect(await queueLength("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);
    expect(await queueLength("alice")).toBe(0);
  });

  it("aborts without touching the queue when the send-point origin pin refuses", async () => {
    await enqueue(entry("alice", "a-pinned"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(
      new OriginPinnedError("https://one.example.test", "https://two.example.test"),
    );

    expect(await flushQueue("alice")).toBe(0);
    expect(await queueLength("alice")).toBe(1);
    expect(await rejectedEntries("alice")).toEqual([]);
  });

  it("treats loopback spellings of one server as the same queue scope", async () => {
    baseUrl = "http://localhost:8000";
    await enqueue(entry("alice", "a-loop"));

    // Saving the alias (or a restore that persisted the other spelling)
    // must not strand the ciphertext behind a different storage key.
    baseUrl = "http://127.0.0.1:8000";
    expect(await queueLength("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createQueuedEntry).toHaveBeenCalledWith("a-loop", expect.any(String), "2026-09-01", "http://127.0.0.1:8000");

    baseUrl = "http://[::1]:8000";
    await enqueue(entry("alice", "a-v6"));
    baseUrl = "http://localhost:8000";
    expect(await queueLength("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);
  });
});

describe("offline queue durability", () => {
  it("quarantines corrupt data in the current scope without touching another scope", async () => {
    await enqueue(entry("alice", "a-corrupt"));
    await enqueue(entry("bob", "b-safe"));
    const [aliceKey] = await scopedKeys("items");
    await storage.setItem(aliceKey!, "{not json");

    expect(await queueLength("alice")).toBe(0);
    expect(await quarantinedQueueExists("alice")).toBe(true);
    expect(await queueLength("bob")).toBe(1);
    expect(await scopedKeys("quarantine")).toHaveLength(1);
  });

  it("preserves pre-v2 global bytes without assigning them to the current server", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify([entry("alice", "old-global")]));

    expect(await queueLength("alice")).toBe(0);
    expect(await hasLegacyQueueRecovery()).toBe(true);
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    const retained = await storage.getItem("@mindpattern/queue.legacy-unscoped.v1");
    expect(retained).toContain("old-global");
    expect(await flushQueue("alice")).toBe(0);
  });

  it("erases preserved legacy bytes with the deleting account (right to erasure)", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify([entry("alice", "old-global")]));
    await enqueue(entry("alice", "a-live"));
    await enqueue(entry("bob", "b-live"));
    expect(await hasLegacyQueueRecovery()).toBe(true);

    await clearQueue("alice");
    // Account deletion removed this account's scoped stores AND the
    // pre-upgrade bytes it owned; another account's queue survives.
    expect(await hasLegacyQueueRecovery()).toBe(false);
    expect(await queueLength("alice")).toBe(0);
    expect(await queueLength("bob")).toBe(1);
  });

  it("quarantines a parseable but unrecognized envelope instead of losing it on the next write", async () => {
    await enqueue(entry("alice", "a-shape"));
    const [aliceKey] = await scopedKeys("items");
    // A future/wrong envelope version parses as JSON but is not a v1 items
    // array: it must land in quarantine, not silently read as empty and be
    // overwritten by the next enqueue.
    await storage.setItem(aliceKey!, JSON.stringify({ v: 2, items: [] }));

    expect(await queueLength("alice")).toBe(0);
    expect(await quarantinedQueueExists("alice")).toBe(true);
    const [quarantineKey] = await scopedKeys("quarantine");
    const readQuarantine = async (): Promise<{ v: number; records: string[] }> =>
      JSON.parse((await storage.getItem(quarantineKey!))!);
    const first = await readQuarantine();
    expect(first.v).toBe(1);
    expect(first.records).toHaveLength(1);
    expect(first.records[0]).toContain('"v":2');

    await enqueue(entry("alice", "a-fresh"));
    expect(await queueLength("alice")).toBe(1);
    expect((await readQuarantine()).records[0]).toContain('"v":2');
  });
  it("enforces a per-scope capacity and preserves every existing ciphertext", async () => {
    for (let i = 0; i < MAX_QUEUE_LENGTH; i++) await enqueue(entry("alice", `a-${i}`));
    await expect(enqueue(entry("alice", "overflow"))).rejects.toBeInstanceOf(QueueFullError);
    expect(await queueLength("alice")).toBe(MAX_QUEUE_LENGTH);
    expect(await queueLength("bob")).toBe(0);
  });
});

describe("flush retry semantics (restored 2026-09-18)", () => {
  const queuedItem = async (): Promise<any> => {
    const [key] = await scopedKeys("items");
    const raw = await storage.getItem(key!);
    return JSON.parse(raw!).items[0];
  };

  it("defers a retryable failure with exponential backoff and jitter", async () => {
    const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
    try {
      await enqueue(entry("alice", "a-5xx"));
      vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(503, "unavailable"));

      expect(await flushQueue("alice")).toBe(0);
      const item = await queuedItem();
      expect(item.attempts).toBe(1);
      // attempts=0 -> base 30s, jitter floor half the window (random=0).
      expect(item.notBefore).toBeGreaterThan(Date.now() + 14_000);
      expect(item.notBefore).toBeLessThanOrEqual(Date.now() + 30_500);

      // The due-gate has its own test; force the item due again so this
      // test pins the SECOND retry's window growth, not the skip.
      const [key] = await scopedKeys("items");
      const stored = JSON.parse((await storage.getItem(key!))!);
      stored.items[0].notBefore = Date.now() - 1;
      await storage.setItem(key!, JSON.stringify(stored));
      vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(502, "bad gateway"));
      expect(await flushQueue("alice")).toBe(0);
      const again = await queuedItem();
      expect(again.attempts).toBe(2);
      // attempts=1 -> base 60s window.
      expect(again.notBefore).toBeGreaterThan(Date.now() + 29_000);
    } finally {
      randomSpy.mockRestore();
    }
  });

  it("honors Retry-After from a 429 instead of local backoff", async () => {
    await enqueue(entry("alice", "a-429"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(
      new ApiError(429, "slow down", undefined, 5_000),
    );

    expect(await flushQueue("alice")).toBe(0);
    const item = await queuedItem();
    expect(item.attempts).toBe(1);
    expect(item.notBefore).toBeLessThanOrEqual(Date.now() + 5_000);
    expect(item.notBefore).toBeGreaterThan(Date.now() + 3_000);
  });

  it("stops flushing on 429 and network failure but keeps the ciphertext queued", async () => {
    await enqueue(entry("alice", "a-ratelimit"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(429, "slow down"));

    expect(await flushQueue("alice")).toBe(0);
    expect(await queueLength("alice")).toBe(1);
    expect(await rejectedEntries("alice")).toEqual([]);

    // A fresh, due item so the status-0 path is actually exercised (the
    // 429'd item is now inside its backoff window and would be skipped).
    await enqueue(entry("alice", "a-offline"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(0, "network unreachable"));
    expect(await flushQueue("alice")).toBe(0);
    expect(await queueLength("alice")).toBe(2);
    expect(await rejectedEntries("alice")).toEqual([]);
  });

  it("moves the item to the rejected store on 413 (stop) and plain 4xx (terminal)", async () => {
    await enqueue(entry("alice", "a-too-big"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(413, "too large"));
    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries("alice")).map((i: any) => i.clientEntryId)).toEqual(["a-too-big"]);

    await enqueue(entry("alice", "a-bad"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(400, "bad request"));
    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries("alice")).map((i: any) => i.clientEntryId)).toEqual(["a-too-big", "a-bad"]);
  });

  it("drops the item on a 409 duplicate without recovery", async () => {
    await enqueue(entry("alice", "a-dup"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(409, "already exists"));

    expect(await flushQueue("alice")).toBe(0);
    expect(await queueLength("alice")).toBe(0);
    expect(await rejectedEntries("alice")).toEqual([]);
  });

  it("skips an item whose backoff window has not elapsed", async () => {
    await enqueue(entry("alice", "a-later"));
    await enqueue(entry("alice", "a-now"));
    const [key] = await scopedKeys("items");
    const raw = JSON.parse((await storage.getItem(key!))!);
    raw.items = raw.items.map((item: any, index: number) =>
      index === 0 ? { ...item, notBefore: Date.now() + 60_000 } : item,
    );
    await storage.setItem(key!, JSON.stringify(raw));
    vi.mocked(api.createQueuedEntry).mockImplementation(async (id: string) => {
      if (id !== "a-now") throw new Error(`unexpected upload of ${id}`);
      return {};
    });

    expect(await flushQueue("alice")).toBe(1);
    const remaining = await queuedItem();
    expect(remaining.clientEntryId).toBe("a-later");
  });

  it("normalizes hostile attempts/notBefore fields instead of poisoning retry math", async () => {
    await enqueue(entry("alice", "a-poison"));
    const [key] = await scopedKeys("items");
    const raw = JSON.parse((await storage.getItem(key!))!);
    raw.items[0].attempts = "many"; // string, must be dropped
    raw.items[0].notBefore = 1e999; // Infinity in JSON, must be dropped
    await storage.setItem(key!, JSON.stringify(raw));

    // With the hostile fields ignored, the item is due immediately.
    expect(await queueLength("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);

    await enqueue(entry("alice", "a-poison2"));
    const [key2] = await scopedKeys("items");
    const raw2 = JSON.parse((await storage.getItem(key2!))!);
    raw2.items[0].attempts = "many";
    await storage.setItem(key2!, JSON.stringify(raw2));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(503, "unavailable"));
    expect(await flushQueue("alice")).toBe(0);
    const item = await queuedItem();
    expect(item.attempts).toBe(1); // string attempts did not seed the counter
  });
});

describe("mutation hardening (2026-09-18)", () => {
  const itemsKey = async (): Promise<string> => (await scopedKeys("items"))[0]!;
  const stored = async (key: string): Promise<any> => JSON.parse((await storage.getItem(key))!);

  it("pins the public error surface (names and exact copy)", async () => {
    for (let i = 0; i < MAX_QUEUE_LENGTH; i++) await enqueue(entry("alice", `f-${i}`));
    await expect(enqueue(entry("alice", "one-more"))).rejects.toMatchObject({
      name: "QueueFullError",
      message: `offline queue is full (${MAX_QUEUE_LENGTH} entries) — sync before writing more`,
    });
    await clearQueue("alice");
    await expect(flushQueue("")).rejects.toMatchObject({
      name: "Error",
      message: "cannot access an offline queue without an account id",
    });
    vi.mocked(api.getUserId).mockResolvedValue(null as never);
    await expect((await import("../src/offlineQueue")).queueLength()).rejects.toThrow(
      "cannot access an offline queue without an account id",
    );
    await enqueue(entry("alice", "auth-expired"));
    vi.mocked(api.getUserId).mockResolvedValue("alice");
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(401, "expired"));
    const err = await flushQueue("alice").catch((e: unknown) => e);
    expect(err).toMatchObject({
      name: "SessionExpiredError",
      message: "session expired mid-flush — unsent entries were preserved for recovery",
    });
  });

  it("preserves ALL THREE legacy stores and chains repeated migrations", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify([entry("alice", "old-q")]));
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([entry("alice", "old-r")]));
    await storage.setItem("@mindpattern/queue_quarantine", "{not json");

    expect(await queueLength("alice")).toBe(0);
    const first = await storage.getItem("@mindpattern/queue.legacy-unscoped.v1");
    expect(first).toContain("old-q");
    expect(first).toContain("old-r");
    expect(first).toContain("queue_quarantine");

    // A restored backup can re-introduce global keys later; the second
    // migration must run again and preserve the first envelope via
    // `previous` instead of silently dropping it.
    await storage.setItem("@mindpattern/queue", JSON.stringify([entry("alice", "second-wave")]));
    expect(await queueLength("alice")).toBe(0);
    const second = JSON.parse((await storage.getItem("@mindpattern/queue.legacy-unscoped.v1"))!);
    expect(second.previous).toContain("old-q");
    expect(JSON.stringify(second.records)).toContain("second-wave");
  });

  it("canonicalizes a portless loopback origin too", async () => {
    baseUrl = "http://localhost";
    await enqueue(entry("alice", "a-portless"));
    baseUrl = "http://127.0.0.1";
    expect(await queueLength("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createQueuedEntry).toHaveBeenCalledWith(
      "a-portless", expect.any(String), "2026-09-01", "http://127.0.0.1",
    );
  });

  it("normalizes hostile per-field shapes instead of reading them as entries", async () => {
    await enqueue(entry("alice", "a-seed"));
    const key = await itemsKey();
    await storage.setItem(key, JSON.stringify([
      41,
      null,
      "not-an-object",
      { userId: 7, clientEntryId: "x", blobB64: "y", entryDate: "2026-09-01" },
      { clientEntryId: "no-user" },
      { userId: "alice" },
      // Wrong-typed fields ON a scope-matching entry: each must be dropped
      // on its own, or the per-field validation has a mutant-shaped hole.
      { userId: "alice", clientEntryId: 7, blobB64: "y", entryDate: "2026-09-01" },
      { userId: "alice", clientEntryId: "c", blobB64: false, entryDate: "2026-09-01" },
      { userId: "alice", clientEntryId: "d", blobB64: "y", entryDate: {} },
      entry("alice", "a-valid"),
    ]));
    // Only the one fully-typed, scope-matching entry survives; nothing 500s.
    expect(await queueLength("alice")).toBe(1);
    await storage.setItem(key, JSON.stringify([entry("alice", "a-bare-array")]));
    expect(await queueLength("alice")).toBe(1); // bare-array envelope shape
    await storage.setItem(key, JSON.stringify({ v: 1, items: { not: "an array" } }));
    expect(await queueLength("alice")).toBe(0);
    expect(await quarantinedQueueExists("alice")).toBe(true);
  });

  it("appends every quarantine record and tolerates a hostile quarantine store", async () => {
    await enqueue(entry("alice", "a-seed"));
    const key = await itemsKey();
    const quarantineKey = key.replace(".items.", ".quarantine.");
    const records = async (): Promise<unknown[]> => (await stored(quarantineKey)).records;

    // First corruption seeds the quarantine envelope.
    await storage.setItem(key, "{one");
    expect(await queueLength("alice")).toBe(0);
    expect(await records()).toEqual(["{one"]);

    // A corrupt (non-JSON) previous quarantine degrades to one raw record
    // (the hostile overwrite deliberately discarded the history).
    await storage.setItem(quarantineKey, "not json at all");
    await storage.setItem(key, "{two");
    expect(await queueLength("alice")).toBe(0);
    expect(await records()).toEqual(["not json at all", "{two"]);

    // A v1 envelope with non-string records filters them and keeps appending.
    await storage.setItem(quarantineKey, JSON.stringify({ v: 1, records: [7, null, "kept"] }));
    await storage.setItem(key, "{three");
    expect(await queueLength("alice")).toBe(0);
    expect(await records()).toEqual(["kept", "{three"]);

    // An unrecognized previous envelope keeps the raw bytes as one record.
    await storage.setItem(quarantineKey, JSON.stringify({ v: 9 }));
    await storage.setItem(key, "{four");
    expect(await queueLength("alice")).toBe(0);
    expect(await records()).toEqual(['{"v":9}', "{four"]);

    // The corrupt source key itself is removed after quarantine on every path.
    expect(await storage.getItem(key)).toBeNull();
  });

  it("writes rejections under the scope's rejected key", async () => {
    await enqueue(entry("alice", "a-reject-key"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(422, "invalid encrypted blob"));
    await flushQueue("alice");
    expect(await scopedKeys("rejected")).toHaveLength(1);
    expect((await stored((await scopedKeys("rejected"))[0]!)).items[0].clientEntryId).toBe("a-reject-key");
  });

  it("abandons an enqueue that crosses a wipe instead of persisting it", async () => {
    const { abortInFlightFlush } = await import("../src/offlineQueue");
    const original = storage.getItem.bind(storage);
    const spy = vi.spyOn(storage, "getItem").mockImplementation(async (key: string) => {
      abortInFlightFlush(); // generation moves AFTER enqueue captured it
      return original(key);
    });
    try {
      await expect(enqueue(entry("alice", "a-fenced"))).rejects.toMatchObject({
        name: "QueueAbandonedError",
        message: "the queue was cleared while saving — the entry was NOT queued",
      });
    } finally {
      spy.mockRestore();
    }
    expect(await queueLength("alice")).toBe(0);
  });

  it("keeps the queue when sign-out wins the 401 race (no rejected move, no throw)", async () => {
    await enqueue(entry("alice", "a-401-fence"));
    await enqueue(entry("alice", "a-401-fence-2"));
    const { abortInFlightFlush } = await import("../src/offlineQueue");
    const original = storage.getItem.bind(storage);
    const queueKey = await itemsKey();
    let itemReads = 0;
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(401, "expired"));
    const spy = vi.spyOn(storage, "getItem").mockImplementation(async (key: string) => {
      // The peek is this key's first read; bump before the session-expired
      // commit's read so the fence wins between them (legacy-migration reads
      // touch other keys and must not count).
      if (key === queueKey && ++itemReads === 2) abortInFlightFlush();
      return original(key);
    });
    try {
      await expect(flushQueue("alice")).resolves.toBe(0);
    } finally {
      spy.mockRestore();
    }
    expect(await queueLength("alice")).toBe(2);
    expect(await rejectedEntries("alice")).toEqual([]);
  });

  it("counts a remotely-won upload as sent when another flush already removed it", async () => {
    await enqueue(entry("alice", "a-resolved"));
    const original = storage.getItem.bind(storage);
    const queueKey = await itemsKey();
    let queueKeyReads = 0;
    const spy = vi.spyOn(storage, "getItem").mockImplementation(async (key: string) => {
      if (key !== queueKey) return original(key);
      queueKeyReads += 1;
      const raw = await original(key);
      if (!raw) return raw;
      if (queueKeyReads === 1) return raw; // the peek sees the real queue
      // From the commit read onward, every view of the stored queue no
      // longer contains the item — another flush resolved it first (and
      // its removal persists for later peeks).
      const parsed = JSON.parse(raw);
      const remaining = parsed.items.filter((x: any) => x.clientEntryId !== "a-resolved");
      return JSON.stringify({ v: 1, items: remaining });
    });
    try {
      expect(await flushQueue("alice")).toBe(1);
    } finally {
      spy.mockRestore();
    }
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);
    // The storage copy was never really removed — only this flush's view.
    expect(await queueLength("alice")).toBe(1);
  });

  it("stops after a 413/429/network failure but continues through 5xx and 409", async () => {
    const fresh = async () => {
      await clearQueue("alice");
      await enqueue(entry("alice", "a-multi-1"));
      await enqueue(entry("alice", "a-multi-2"));
      vi.mocked(api.createQueuedEntry).mockClear();
    };
    const attemptsById = async (): Promise<Record<string, number | undefined>> => {
      const raw = await stored(await itemsKey());
      const out: Record<string, number | undefined> = {};
      for (const item of raw.items) out[item.clientEntryId] = item.attempts;
      return out;
    };

    await fresh();
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(413, "too large"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1); // stopped, not drained
    expect((await attemptsById())["a-multi-2"]).toBeUndefined(); // never attempted
    expect((await rejectedEntries("alice")).map((i: any) => i.clientEntryId)).toEqual(["a-multi-1"]);

    await fresh();
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(429, "slow down"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);

    await fresh();
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new Error("network"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);

    await fresh();
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(0, "offline"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);

    await fresh();
    vi.mocked(api.createQueuedEntry)
      .mockRejectedValueOnce(new ApiError(503, "unavailable"))
      .mockRejectedValueOnce(new ApiError(503, "unavailable"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(2); // retried THROUGH
    const both = await attemptsById();
    expect(both["a-multi-1"]).toBe(1);
    expect(both["a-multi-2"]).toBe(1);

    await fresh();
    vi.mocked(api.createQueuedEntry)
      .mockRejectedValueOnce(new ApiError(409, "duplicate"))
      .mockResolvedValueOnce({});
    expect(await flushQueue("alice")).toBe(1); // only the true send counts
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(2);
    expect(await queueLength("alice")).toBe(0);
  });

  it("preserves a valid stored attempts counter through the retry math", async () => {
    await enqueue(entry("alice", "a-counted"));
    const key = await itemsKey();
    const raw = await stored(key);
    raw.items[0].attempts = 4;
    await storage.setItem(key, JSON.stringify(raw));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(503, "unavailable"));

    expect(await flushQueue("alice")).toBe(0);
    expect((await stored(key)).items[0].attempts).toBe(5);
  });

  it("merges the 401 recovery move without duplicating existing rejections", async () => {
    await enqueue(entry("alice", "a-merge-1"));
    await enqueue(entry("alice", "a-merge-2"));
    const rejectedKey = (await itemsKey()).replace(".items.", ".rejected.");
    await storage.setItem(rejectedKey, JSON.stringify({ v: 1, items: [entry("alice", "a-merge-1")] }));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(401, "expired"));

    await expect(flushQueue("alice")).rejects.toMatchObject({ name: "SessionExpiredError" });
    const merged = (await stored(rejectedKey)).items.map((i: any) => i.clientEntryId);
    expect(merged).toEqual(["a-merge-1", "a-merge-2"]);
  });

  it("keeps the queue when the wipe lands between the recovery append and the clear", async () => {
    await enqueue(entry("alice", "a-late-wipe"));
    const { abortInFlightFlush } = await import("../src/offlineQueue");
    const original = storage.setItem.bind(storage);
    const spy = vi.spyOn(storage, "setItem").mockImplementation(async (key: string, value: string) => {
      // appendRejected's write is the first setItem inside the 401 commit.
      abortInFlightFlush();
      return original(key, value);
    });
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(401, "expired"));
    try {
      await expect(flushQueue("alice")).resolves.toBe(0);
    } finally {
      spy.mockRestore();
    }
    expect(await queueLength("alice")).toBe(1); // the clear was fenced off
  });

  it("keeps a 422-rejected item queued when the wipe lands after its recovery append", async () => {
    await enqueue(entry("alice", "a-reject-wipe"));
    const { abortInFlightFlush } = await import("../src/offlineQueue");
    const original = storage.setItem.bind(storage);
    const spy = vi.spyOn(storage, "setItem").mockImplementation(async (key: string, value: string) => {
      abortInFlightFlush();
      return original(key, value);
    });
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(422, "invalid encrypted blob"));
    try {
      expect(await flushQueue("alice")).toBe(0);
    } finally {
      spy.mockRestore();
    }
    expect(await queueLength("alice")).toBe(1);
  });

  it("treats exactly-500 like any other 5xx: retryable without stopping", async () => {
    await enqueue(entry("alice", "a-500-1"));
    await enqueue(entry("alice", "a-500-2"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(500, "server error"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(2);
    const raw = await stored(await itemsKey());
    expect(raw.items.every((i: any) => i.attempts === 1)).toBe(true);
  });

  it("does not preserve an empty-string legacy store value", async () => {
    await storage.setItem("@mindpattern/queue", "");
    expect(await queueLength("alice")).toBe(0);
    expect(await hasLegacyQueueRecovery()).toBe(false);
  });

  it("treats an undefined-code 422 future-date rejection as retryable", async () => {
    await enqueue(entry("alice", "a-future-nc"));
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(422, "entry date is in the future"));
    await flushQueue("alice");
    expect(await queueLength("alice")).toBe(1);
    const raw = await stored(await itemsKey());
    expect(raw.items[0].attempts).toBe(1);
  });

  it("requeueRejected is a no-op for an empty store, skips queued ids, and respects capacity", async () => {
    expect(await requeueRejected("alice")).toBe(0);

    // A rejected id that is already back in the queue is skipped; a second
    // distinct id moves over, stripped of its retry bookkeeping.
    await enqueue(entry("alice", "a-in-queue"));
    const rejectedKey = (await itemsKey()).replace(".items.", ".rejected.");
    await storage.setItem(
      rejectedKey,
      JSON.stringify({ v: 1, items: [
        { ...entry("alice", "a-in-queue"), attempts: 3, notBefore: 99 },
        entry("alice", "a-waiting"),
      ] }),
    );
    expect(await requeueRejected("alice")).toBe(1);
    const queueRaw = await stored(await itemsKey());
    expect(queueRaw.items.map((i: any) => i.clientEntryId)).toEqual(["a-in-queue", "a-waiting"]);
    expect(queueRaw.items[1].attempts).toBeUndefined();
    expect(await storage.getItem(rejectedKey)).toBeNull(); // empty rejected store removed

    // Queue at capacity: nothing moves, the item stays in the rejected store.
    await clearQueue("alice");
    for (let i = 0; i < MAX_QUEUE_LENGTH; i++) await enqueue(entry("alice", `c-${i}`));
    await storage.setItem(rejectedKey, JSON.stringify({ v: 1, items: [entry("alice", "a-blocked")] }));
    expect(await requeueRejected("alice")).toBe(0);
    expect(await storage.getItem(rejectedKey)).toBeTruthy();
  });
});
