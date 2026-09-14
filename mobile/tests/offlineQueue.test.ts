/**
 * Offline queue security regressions (from the red-team audit):
 *  - one account's queued ciphertext can never be uploaded under another
 *    account's session,
 *  - a wipe during an in-flight flush is never resurrected by the flush's
 *    write-back,
 *  - capacity is a loud failure, never silent destruction of oldest items.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

vi.mock("../src/api/client", () => {
  class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
      public code?: string,
      public retryAfterMs?: number,
    ) {
      super(message);
    }
  }
  return {
    ApiError,
    api: {
      // Controlled per-test via the exposed mock functions.
      createEntry: vi.fn(async () => ({})),
    },
  };
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { api, ApiError } = await import("../src/api/client") as any;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { enqueue, flushQueue, clearQueue, queueLength, quarantinedQueueExists, rejectedEntries, rejectedEntryCount, requeueRejected, abortInFlightFlush, MAX_QUEUE_LENGTH, QueueFullError, QueueAbandonedError, SessionExpiredError } =
  await import("../src/offlineQueue");

const aliceEntry = (n: number) => ({
  userId: "alice",
  clientEntryId: `a-${n}`,
  blobB64: Buffer.alloc(40, n).toString("base64"),
  entryDate: "2026-09-01",
});

/** The persisted queue is a versioned envelope — { v: 1, items: [...] }. */
const storedQueueItems = async (): Promise<any[]> => {
  const raw = (await storage.getItem("@mindpattern/queue")) ?? '{"v":1,"items":[]}';
  return JSON.parse(raw).items;
};

beforeEach(() => {
  storage.__reset();
  vi.mocked(api.createEntry).mockClear();
  vi.mocked(api.createEntry).mockImplementation(async () => ({}));
});

describe("account isolation", () => {
  it("never uploads another account's queued entries", async () => {
    await enqueue(aliceEntry(1));
    await enqueue({ ...aliceEntry(2), userId: "bob" });

    const sent = await flushQueue("alice");

    expect(sent).toBe(1);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(api.createEntry).toHaveBeenCalledWith("a-1", aliceEntry(1).blobB64, "2026-09-01");

    // Bob's ciphertext stays queued for Bob — not uploaded, not dropped.
    expect(await queueLength()).toBe(1);
    const bobStillQueued = await flushQueue("bob");
    expect(bobStillQueued).toBe(1);
    expect(await queueLength()).toBe(0);
  });
});

describe("concurrency (C3: no lost updates)", () => {
  it("an enqueue racing an in-flight flush commits immediately and is never overwritten", async () => {
    await enqueue(aliceEntry(1));
    let resolveUpload!: (v: unknown) => void;
    // The FIRST upload parks (blackholed network); later calls succeed.
    vi.mocked(api.createEntry).mockImplementationOnce(
      () => new Promise((resolve) => (resolveUpload = resolve)),
    );
    const flushing = flushQueue("alice");
    // The flush is parked on its first upload; a save lands mid-flush.
    await new Promise((r) => setTimeout(r, 0));
    const enqueuing = enqueue(aliceEntry(2));
    // The mutex no longer covers network I/O: the enqueue resolves while
    // the flush is still parked — the old code blocked here for the rest
    // of the flush (up to 200 × 15s of timeouts).
    await enqueuing;
    resolveUpload({});
    await flushing;
    // Entry 1 was sent; entry 2 was neither lost (the old stale-snapshot
    // write-back destroyed it) nor left behind — the SAME flush picked it
    // up once the network recovered.
    expect(api.createEntry).toHaveBeenCalledTimes(2);
    expect(api.createEntry).toHaveBeenLastCalledWith("a-2", aliceEntry(2).blobB64, "2026-09-01");
    expect(await queueLength()).toBe(0);
  });

  it("two concurrent enqueues both survive", async () => {
    await Promise.all([enqueue(aliceEntry(1)), enqueue(aliceEntry(2)), enqueue(aliceEntry(3))]);
    expect(await queueLength()).toBe(3);
  });
});

describe("wipe races", () => {
  it("abandons the write-back when the queue is cleared mid-flush", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));

    let calls = 0;
    vi.mocked(api.createEntry).mockImplementation(async () => {
      calls += 1;
      if (calls === 1) {
        // Sign-out happens while the flush is between items.
        await clearQueue();
      }
      return {};
    });

    const sent = await flushQueue("alice");
    expect(sent).toBe(1); // first item went out before the wipe
    // The wipe must win: the flush may not re-persist its stale snapshot —
    // the key is GONE, not merely emptied.
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await queueLength()).toBe(0);
  });

  it("skips the final write-back when the wipe lands after the last upload", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      await clearQueue(); // wipes after the upload succeeded
      return {};
    });

    const sent = await flushQueue("alice");
    expect(sent).toBe(1);
    expect(await storage.getItem("@mindpattern/queue")).toBeNull(); // never resurrected
    expect(await queueLength()).toBe(0);
  });
});

describe("failure handling", () => {
  it("keeps items on network errors and drops them on permanent 4xx", async () => {
    await enqueue(aliceEntry(1)); // will 422 -> dropped
    await enqueue(aliceEntry(2)); // will 5xx -> kept for retry
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-1") throw new ApiError(422, "bad blob");
      throw new ApiError(0, "server unreachable");
    });

    const sent = await flushQueue("alice");
    expect(sent).toBe(0);
    const remaining = await storedQueueItems();
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-2"]);
    // M2: the 422'd ciphertext is NOT destroyed — it moves to the rejected
    // store so a hostile server cannot erase the user's only copy with an
    // error code.
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
  });

  it("on 401 does NOT re-queue the doomed entries: they move to the rejected store and the flush is loud", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      throw new ApiError(401, "invalid token");
    });

    // Session death surfaces as a dedicated error, not a silent re-queue.
    await expect(flushQueue("alice")).rejects.toBeInstanceOf(SessionExpiredError);
    // The doomed ciphertext is preserved for recovery — never destroyed,
    // never re-queued against the dead session...
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1", "a-2"]);
    expect(await queueLength()).toBe(0);
    // ...so a second flush does NOT retry them (no silent re-queue forever).
    vi.mocked(api.createEntry).mockClear();
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("on 401 mid-queue preserves every doomed item and keeps foreign accounts queued", async () => {
    await enqueue(aliceEntry(1)); // succeeds
    await enqueue(aliceEntry(2)); // 401
    await enqueue(aliceEntry(3)); // never attempted
    await enqueue({ ...aliceEntry(4), userId: "bob" }); // foreign: not doomed
    let calls = 0;
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      calls += 1;
      if (id === "a-2") throw new ApiError(401, "invalid token");
      return {};
    });

    await expect(flushQueue("alice")).rejects.toBeInstanceOf(SessionExpiredError);
    expect(calls).toBe(2); // item 3 was never attempted
    // Alice's doomed ciphertext is in the rejected store; Bob's item was
    // never attempted against this session and stays queued for Bob.
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-2", "a-3"]);
    const remaining = await storedQueueItems();
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-4"]);
  });

  it("fails LOUDLY at capacity instead of silently discarding old entries", async () => {
    for (let i = 0; i < MAX_QUEUE_LENGTH; i++) {
      await enqueue(aliceEntry(i));
    }
    await expect(enqueue(aliceEntry(999))).rejects.toBeInstanceOf(QueueFullError);
    await expect(enqueue(aliceEntry(999))).rejects.toThrow(
      `offline queue is full (${MAX_QUEUE_LENGTH} entries) — sync before writing more`,
    );
    const err = new QueueFullError();
    expect(err.name).toBe("QueueFullError");
    // And the existing entries are intact.
    expect(await queueLength()).toBe(MAX_QUEUE_LENGTH);
  });

  it("stops the flush on the FIRST network error instead of burning every later item's timeout", async () => {
    // BEHAVIOR CHANGE (data-loss audit): the old loop continued past a
    // status-0 failure, so a blackholed network turned a 200-item flush into
    // 200 × 15s of timeouts — with the queue mutex held the whole time. Now
    // an unreachable server fails the flush fast: later items are not even
    // attempted, and the failed one is marked for backed-off retry.
    await enqueue(aliceEntry(1)); // network error -> marked, flush stops
    await enqueue(aliceEntry(2)); // never attempted this flush
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-1") throw new TypeError("fetch failed");
      return {};
    });
    const sent = await flushQueue("alice");
    expect(sent).toBe(0);
    expect(api.createEntry).toHaveBeenCalledTimes(1); // item 2 was NOT attempted
    const remaining = await storedQueueItems();
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-1", "a-2"]);
  });

  it("drops entries the server already has (409 double-flush)", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      throw new ApiError(409, "entry already exists");
    });
    const sent = await flushQueue("alice");
    expect(sent).toBe(0);
    expect(await queueLength()).toBe(0);
  });

  it("keeps entries on non-ApiError failures (treated like network errors)", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      throw new TypeError("fetch failed");
    });
    await flushQueue("alice");
    expect(await queueLength()).toBe(1);
  });
});

describe("corrupted storage recovery", () => {
  it("quarantines unparseable queue data instead of destroying it (M3)", async () => {
    await storage.setItem("@mindpattern/queue", "{not json");
    expect(await queueLength()).toBe(0);
    // A fresh queue takes over...
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    // ...but the corrupt ciphertext is preserved under the quarantine key
    // for recovery, not silently wiped.
    expect(await storage.getItem("@mindpattern/queue_quarantine")).toBe("{not json");
    expect(await quarantinedQueueExists()).toBe(true);
  });

  it("reports no quarantine for healthy storage", async () => {
    await enqueue(aliceEntry(1));
    expect(await quarantinedQueueExists()).toBe(false);
  });

  it("appends (never overwrites) quarantine data on repeated corruption (L4)", async () => {
    await storage.setItem("@mindpattern/queue", "{first");
    await queueLength();
    await storage.setItem("@mindpattern/queue", "{second");
    await queueLength();
    const quarantined = await storage.getItem("@mindpattern/queue_quarantine");
    expect(quarantined).toContain("{first");
    expect(quarantined).toContain("{second");
  });

  it("clearQueue also wipes the quarantine and rejected stores", async () => {
    await storage.setItem("@mindpattern/queue_quarantine", "{first");
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(1)]));
    await clearQueue();
    expect(await storage.getItem("@mindpattern/queue_quarantine")).toBeNull();
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBeNull();
  });

  it("treats a corrupt rejected-store as empty instead of throwing", async () => {
    await storage.setItem("@mindpattern/queue_rejected", "{not json");
    expect(await rejectedEntries()).toEqual([]);
    // Valid JSON that is not an array degrades the same way.
    await storage.setItem("@mindpattern/queue_rejected", "42");
    expect(await rejectedEntries()).toEqual([]);
  });

  it("treats non-array queue data as empty (and keeps it for repair)", async () => {
    await storage.setItem("@mindpattern/queue", "42");
    expect(await queueLength()).toBe(0);
    expect(await storage.getItem("@mindpattern/queue")).toBe("42");
  });

  it("skips null slots instead of crashing the flush", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify([null, aliceEntry(1)]));
    const sent = await flushQueue("alice");
    expect(sent).toBe(1);
    const remaining = await storedQueueItems();
    expect(remaining).toHaveLength(0);
  });

  it("a wipe racing enqueue wins: the item never lands in the wiped queue, and the enqueue is LOUD (M4)", async () => {
    await enqueue(aliceEntry(1)); // will be wiped mid-enqueue below
    // Interleave: the queue is cleared between enqueue's read and its
    // commit (sign-out timing, reproduced deterministically).
    const originalGetItem = storage.getItem.bind(storage);
    let armed = true;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (armed && k === "@mindpattern/queue") {
        armed = false;
        const stale = await originalGetItem(k); // enqueue's snapshot: pre-wipe
        await clearQueue(); // the wipe lands inside the read-to-write window
        return stale;
      }
      return originalGetItem(k);
    };
    try {
      // The abandoned commit no longer returns normally: the caller must
      // not show "Saved offline" for an entry that was never queued.
      const rejection = await enqueue(aliceEntry(2)).catch((e: unknown) => e);
      expect(rejection).toBeInstanceOf(QueueAbandonedError);
      expect((rejection as Error).message).toContain("NOT queued");
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // The wipe BEGAN before the enqueue committed, so the enqueue must NOT
    // survive it: no resurrection of the old entries AND no write of the
    // racing item into the just-wiped queue — the key stays gone entirely.
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await queueLength()).toBe(0);
    const err = new QueueAbandonedError();
    expect(err.name).toBe("QueueAbandonedError");
    expect(new SessionExpiredError().name).toBe("SessionExpiredError");
  });

  it("an enqueue that STARTS after the wipe still lands (the queue is reusable)", async () => {
    await enqueue(aliceEntry(1));
    await clearQueue();
    await enqueue(aliceEntry(2));
    expect(await queueLength()).toBe(1);
    expect(await storage.getItem("@mindpattern/queue")).toContain("a-2");
    expect(await storage.getItem("@mindpattern/queue")).not.toContain("a-1");
  });

  it("a wipe racing a 422-flush wins: appendRejected cannot rewrite REJECTED_KEY after the wipe (M2-a)", async () => {
    await enqueue(aliceEntry(1)); // will 422 mid-flush
    vi.mocked(api.createEntry).mockImplementation(async () => {
      throw new ApiError(422, "bad blob");
    });
    // Interleave: account deletion lands between appendRejected's read of
    // the rejected store and its write-back.
    const originalGetItem = storage.getItem.bind(storage);
    let armed = true;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (armed && k === "@mindpattern/queue_rejected") {
        armed = false;
        const stale = await originalGetItem(k);
        await clearQueue(); // the wipe lands inside the read-to-write window
        return stale;
      }
      return originalGetItem(k);
    };
    let flushError: unknown = null;
    try {
      await flushQueue("alice").catch((e: unknown) => {
        flushError = e;
      });
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // The flush abandoned its write-back (wiped mid-flush) — and crucially
    // the rejected store was NOT rewritten after the wipe.
    expect(flushError).toBeNull();
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBeNull();
    expect(await rejectedEntries()).toEqual([]);
  });

  it("a wipe racing a corrupt-queue quarantine write wins: QUARANTINE_KEY stays wiped (M2-a)", async () => {
    await storage.setItem("@mindpattern/queue", "{not json");
    // Interleave: the wipe lands between the quarantine read and its write.
    const originalGetItem = storage.getItem.bind(storage);
    let armed = true;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (armed && k === "@mindpattern/queue_quarantine") {
        armed = false;
        const stale = await originalGetItem(k);
        await clearQueue();
        return stale;
      }
      return originalGetItem(k);
    };
    try {
      expect(await queueLength()).toBe(0);
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // The corrupt payload was NOT re-quarantined after the wipe.
    expect(await storage.getItem("@mindpattern/queue_quarantine")).toBeNull();
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
  });

  it("treats non-array queue data as empty (and keeps it for repair)", async () => {
    await storage.setItem("@mindpattern/queue", "42");
    expect(await queueLength()).toBe(0);
    expect(await storage.getItem("@mindpattern/queue")).toBe("42");
  });

  it("skips null slots instead of crashing the flush", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify([null, aliceEntry(1)]));
    const sent = await flushQueue("alice");
    expect(sent).toBe(1);
    const remaining = await storedQueueItems();
    expect(remaining).toHaveLength(0);
  });
});

describe("fail-fast, backoff and classification (flush redesign)", () => {
  it("marks retriable failures with persisted backoff and skips them until due", async () => {
    vi.useFakeTimers();
    try {
      await enqueue(aliceEntry(1));
      vi.mocked(api.createEntry).mockRejectedValue(new ApiError(500, "boom"));
      const t0 = Date.now();
      expect(await flushQueue("alice")).toBe(0);
      const [marked] = await storedQueueItems();
      expect(marked.attempts).toBe(1);
      // ~30s base, jittered into [15s, 30s).
      expect(marked.notBefore).toBeGreaterThanOrEqual(t0 + 15_000);
      expect(marked.notBefore).toBeLessThan(t0 + 30_000);

      // Not yet due: the next flush does not even attempt the upload.
      vi.mocked(api.createEntry).mockClear();
      expect(await flushQueue("alice")).toBe(0);
      expect(api.createEntry).not.toHaveBeenCalled();

      // Once due it is retried — and a success clears the item.
      vi.advanceTimersByTime(31_000);
      vi.mocked(api.createEntry).mockImplementation(async () => ({}));
      expect(await flushQueue("alice")).toBe(1);
      expect(await queueLength()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("doubles the backoff on the second failure", async () => {
    vi.useFakeTimers();
    try {
      await enqueue(aliceEntry(1));
      vi.mocked(api.createEntry).mockRejectedValue(new ApiError(500, "boom"));
      await flushQueue("alice");
      vi.advanceTimersByTime(31_000);
      const t1 = Date.now();
      await flushQueue("alice");
      const [marked] = await storedQueueItems();
      expect(marked.attempts).toBe(2);
      // Base 60s now, jittered into [30s, 60s).
      expect(marked.notBefore).toBeGreaterThanOrEqual(t1 + 30_000);
      expect(marked.notBefore).toBeLessThan(t1 + 60_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it("continues past a per-item 5xx (the failure may be specific to one blob)", async () => {
    await enqueue(aliceEntry(1)); // 500 -> backoff, loop continues
    await enqueue(aliceEntry(2)); // succeeds
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-1") throw new ApiError(500, "server exploded");
      return {};
    });
    expect(await flushQueue("alice")).toBe(1);
    const remaining = await storedQueueItems();
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-1"]);
  });

  it("honors Retry-After on 429 exactly and stops the flush", async () => {
    vi.useFakeTimers();
    try {
      await enqueue(aliceEntry(1)); // 429 -> throttled
      await enqueue(aliceEntry(2)); // not attempted: the throttle is server-wide
      vi.mocked(api.createEntry).mockRejectedValue(
        new ApiError(429, "rate limited", "rate_limited", 45_000),
      );
      const t0 = Date.now();
      expect(await flushQueue("alice")).toBe(0);
      expect(api.createEntry).toHaveBeenCalledTimes(1);
      const [marked] = await storedQueueItems();
      expect(marked.attempts).toBe(1);
      expect(marked.notBefore).toBe(t0 + 45_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it("falls back to exponential backoff when a 429 carries no Retry-After", async () => {
    vi.useFakeTimers();
    try {
      await enqueue(aliceEntry(1));
      vi.mocked(api.createEntry).mockRejectedValue(new ApiError(429, "rate limited", "rate_limited"));
      const t0 = Date.now();
      expect(await flushQueue("alice")).toBe(0);
      const [marked] = await storedQueueItems();
      expect(marked.notBefore).toBeGreaterThanOrEqual(t0 + 15_000);
      expect(marked.notBefore).toBeLessThan(t0 + 30_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it("treats 403 as terminal for the entry (rejected store) and continues the flush", async () => {
    await enqueue(aliceEntry(1)); // 403 -> rejected
    await enqueue(aliceEntry(2)); // still uploaded
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-1") throw new ApiError(403, "verification failed", "verification_failed");
      return {};
    });
    expect(await flushQueue("alice")).toBe(1);
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
    expect(await queueLength()).toBe(0);
  });

  it("treats 413 quota as terminal for the entry AND stops the flush (later items stay queued)", async () => {
    await enqueue(aliceEntry(1)); // 413 -> rejected, flush stops
    await enqueue(aliceEntry(2)); // not attempted: the cumulative quota dooms it too,
    // but it stays QUEUED — the user may free space before the next sync.
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(413, "quota", "blob_quota_exceeded"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
    expect((await storedQueueItems()).map((r: any) => r.clientEntryId)).toEqual(["a-2"]);
  });

  it("treats other 4xx (e.g. 400) as terminal per entry", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(400, "bad request"));
    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
    expect(await queueLength()).toBe(0);
  });

  it("keeps a future-dated 422 retryable (time heals it) instead of rejecting", async () => {
    vi.useFakeTimers();
    try {
      await enqueue(aliceEntry(1));
      // Legacy shape: no code, detail text only.
      vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "entry_date cannot be in the future"));
      expect(await flushQueue("alice")).toBe(0);
      expect(await rejectedEntries()).toEqual([]); // NOT rejected
      expect(await queueLength()).toBe(1); // backed off, still queued
      vi.advanceTimersByTime(31_000);
      vi.mocked(api.createEntry).mockImplementation(async () => ({}));
      expect(await flushQueue("alice")).toBe(1);
      expect(await queueLength()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("detects the future-date case through the v1 validation_error code too", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(
      new ApiError(422, "entry_date cannot be in the future", "validation_error"),
    );
    expect(await flushQueue("alice")).toBe(0);
    expect(await rejectedEntries()).toEqual([]);
    expect(await queueLength()).toBe(1);
  });

  it("a 422 with a non-validation code stays terminal", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "future dates!", "payload_too_large"));
    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
  });

  it("two concurrent flushes race safely: the server dedupes, the commit notices", async () => {
    await enqueue(aliceEntry(1));
    let calls = 0;
    vi.mocked(api.createEntry).mockImplementation(async () => {
      // Capture the ordinal synchronously: after the park, `calls` already
      // counts BOTH racing uploads.
      const ordinal = ++calls;
      await new Promise((r) => setTimeout(r, 0));
      if (ordinal > 1) throw new ApiError(409, "entry already exists", "conflict");
      return {};
    });
    const [a, b] = await Promise.all([flushQueue("alice"), flushQueue("alice")]);
    expect(a + b).toBe(1); // exactly one flush counted the send
    expect(await queueLength()).toBe(0);
    expect(await rejectedEntries()).toEqual([]); // no double-reject
  });
});

describe("sign-out coordination (the 401 race)", () => {
  it("requeues current-user items when a 401 follows abortInFlightFlush", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      // signOut landed while this upload was in flight: it bumped the
      // generation, then the revoked token produced this 401.
      abortInFlightFlush();
      throw new ApiError(401, "invalid token", "unauthorized");
    });
    // Resolves instead of throwing SessionExpiredError...
    const sent = await flushQueue("alice");
    expect(sent).toBe(0);
    // ...and BOTH items are requeued for the next login — none rejected.
    expect((await storedQueueItems()).map((r: any) => r.clientEntryId)).toEqual(["a-1", "a-2"]);
    expect(await rejectedEntries()).toEqual([]);
  });

  it("a mid-upload account deletion still wins over the 401 path (no resurrection)", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      await clearQueue();
      throw new ApiError(401, "invalid token");
    });
    const sent = await flushQueue("alice");
    expect(sent).toBe(0);
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await rejectedEntries()).toEqual([]);
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBeNull();
  });
});

describe("requeueRejected (recovery surface)", () => {
  it("moves rejected entries back to the live queue with backoff reset", async () => {
    await storage.setItem(
      "@mindpattern/queue_rejected",
      JSON.stringify([{ ...aliceEntry(1), attempts: 3, notBefore: Date.now() + 999_999 }]),
    );
    expect(await requeueRejected()).toBe(1);
    const [item] = await storedQueueItems();
    expect(item.clientEntryId).toBe("a-1");
    expect(item.attempts).toBeUndefined();
    expect(item.notBefore).toBeUndefined();
    expect(await rejectedEntries()).toEqual([]);
  });

  it("returns 0 when nothing is rejected", async () => {
    expect(await requeueRejected()).toBe(0);
  });

  it("drops rejected copies of entries that are already queued (dedupe)", async () => {
    await enqueue(aliceEntry(1));
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(1), aliceEntry(2)]));
    expect(await requeueRejected()).toBe(1); // only a-2 moved
    expect(await queueLength()).toBe(2);
    expect(await rejectedEntries()).toEqual([]);
  });

  it("respects the capacity bound: what does not fit stays rejected", async () => {
    for (let i = 0; i < MAX_QUEUE_LENGTH - 1; i++) {
      await enqueue(aliceEntry(i));
    }
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(300), aliceEntry(301)]));
    expect(await requeueRejected()).toBe(1); // one slot, two candidates
    expect(await queueLength()).toBe(MAX_QUEUE_LENGTH);
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-301"]);
  });

  it("rejectedEntryCount reflects the rejected store", async () => {
    expect(await rejectedEntryCount()).toBe(0);
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(1)]));
    expect(await rejectedEntryCount()).toBe(1);
  });
});

describe("persisted schema v1", () => {
  it("new writes carry the { v: 1, items } envelope", async () => {
    await enqueue(aliceEntry(1));
    const raw = JSON.parse((await storage.getItem("@mindpattern/queue")) as string);
    expect(raw.v).toBe(1);
    expect(raw.items.map((r: any) => r.clientEntryId)).toEqual(["a-1"]);
  });

  it("loads the legacy bare-array shape and migrates it on read", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify([aliceEntry(1)]));
    expect(await queueLength()).toBe(1);
    const raw = JSON.parse((await storage.getItem("@mindpattern/queue")) as string);
    expect(raw.v).toBe(1); // read-through migration refreshed the shape
    expect(raw.items[0].clientEntryId).toBe("a-1");
    // And the migrated queue flushes normally.
    expect(await flushQueue("alice")).toBe(1);
    expect(await queueLength()).toBe(0);
  });

  it("reads the legacy bare-array rejected store", async () => {
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(1)]));
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
    expect(await rejectedEntryCount()).toBe(1);
  });

  it("keeps parseable-but-unrecognized shapes untouched for repair", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify({ v: 2, items: [aliceEntry(1)] }));
    expect(await queueLength()).toBe(0);
    const raw = JSON.parse((await storage.getItem("@mindpattern/queue")) as string);
    expect(raw.v).toBe(2); // not overwritten, not quarantined
  });

  it("normalizes hostile backoff fields on read", async () => {
    await storage.setItem(
      "@mindpattern/queue",
      JSON.stringify({ v: 1, items: [{ ...aliceEntry(1), attempts: "many", notBefore: "soon" }] }),
    );
    // notBefore is not a finite number: the item is due immediately.
    expect(await flushQueue("alice")).toBe(1);
    expect(await queueLength()).toBe(0);
  });

  it("drops non-object slots on read instead of flushing them", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify({ v: 1, items: [null, "junk", 42, aliceEntry(1)] }));
    expect(await flushQueue("alice")).toBe(1);
    expect(await queueLength()).toBe(0);
  });

  it("an envelope whose items field is not an array reads as empty", async () => {
    await storage.setItem("@mindpattern/queue", JSON.stringify({ v: 1, items: "junk" }));
    expect(await queueLength()).toBe(0);
  });
});

describe("wipe guards on the recovery paths", () => {
  it("a wipe landing between two rejected-store appends wins: no partial resurrection", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    // The 401 path appends each doomed item separately; the wipe lands on
    // the SECOND append's read.
    const originalGetItem = storage.getItem.bind(storage);
    let rejectedReads = 0;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (k === "@mindpattern/queue_rejected") {
        rejectedReads += 1;
        if (rejectedReads === 2) {
          const stale = await originalGetItem(k);
          await clearQueue(); // account deletion mid-reject
          return stale;
        }
      }
      return originalGetItem(k);
    };
    let flushResult: unknown;
    try {
      flushResult = await flushQueue("alice").then((s) => s, (e: unknown) => e);
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // The abort wins: no throw (the wipe is not session expiry), and the
    // wipe's removals were NOT rewritten by the in-flight reject loop.
    expect(flushResult).toBe(0);
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBeNull();
  });

  it("a wipe racing requeueRejected's queue read abandons the whole move", async () => {
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(1)]));
    const originalGetItem = storage.getItem.bind(storage);
    let armed = true;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (armed && k === "@mindpattern/queue") {
        armed = false;
        const stale = await originalGetItem(k);
        await clearQueue();
        return stale;
      }
      return originalGetItem(k);
    };
    let moved = -1;
    try {
      moved = await requeueRejected();
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    expect(moved).toBe(0);
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBeNull();
  });

  it("a wipe landing after requeueRejected's queue write skips the rejected write-back", async () => {
    await storage.setItem("@mindpattern/queue_rejected", JSON.stringify([aliceEntry(1)]));
    const originalSetItem = storage.setItem.bind(storage);
    let armed = true;
    (storage as { setItem: typeof storage.setItem }).setItem = async (k: string, v: string) => {
      await originalSetItem(k, v);
      if (armed && k === "@mindpattern/queue") {
        armed = false;
        await clearQueue(); // the wipe lands between the two writes
      }
    };
    let moved = -1;
    try {
      moved = await requeueRejected();
    } finally {
      (storage as { setItem: typeof storage.setItem }).setItem = originalSetItem;
    }
    expect(moved).toBe(0);
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    // The rejected store was wiped by clearQueue and NOT resurrected.
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBeNull();
  });
});
