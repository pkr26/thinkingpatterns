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
    constructor(public status: number, message: string) {
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
const { enqueue, flushQueue, clearQueue, queueLength, quarantinedQueueExists, rejectedEntries, MAX_QUEUE_LENGTH, QueueFullError } =
  await import("../src/offlineQueue");

const aliceEntry = (n: number) => ({
  userId: "alice",
  clientEntryId: `a-${n}`,
  blobB64: Buffer.alloc(40, n).toString("base64"),
  entryDate: "2026-09-01",
});

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
  it("an enqueue racing an in-flight flush is never overwritten by it", async () => {
    await enqueue(aliceEntry(1));
    let resolveUpload!: (v: unknown) => void;
    vi.mocked(api.createEntry).mockImplementation(
      () => new Promise((resolve) => (resolveUpload = resolve)),
    );
    const flushing = flushQueue("alice");
    // The flush is parked on its first upload; a save lands mid-flush.
    await new Promise((r) => setTimeout(r, 0));
    const enqueuing = enqueue(aliceEntry(2));
    resolveUpload({});
    await Promise.all([flushing, enqueuing]);
    // Entry 1 was sent; entry 2 is STILL QUEUED — the old code's write-back
    // of the stale snapshot silently destroyed it.
    expect(await queueLength()).toBe(1);
    expect((await storage.getItem("@mindpattern/queue"))).toContain("a-2");
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
    const remaining = JSON.parse((await storage.getItem("@mindpattern/queue")) ?? "[]");
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-2"]);
    // M2: the 422'd ciphertext is NOT destroyed — it moves to the rejected
    // store so a hostile server cannot erase the user's only copy with an
    // error code.
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
  });

  it("stops uploading on 401 and keeps the rest for after re-unlock", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockImplementation(async () => {
      throw new ApiError(401, "invalid token");
    });

    await flushQueue("alice");
    const remaining = JSON.parse((await storage.getItem("@mindpattern/queue")) ?? "[]");
    expect(remaining).toHaveLength(2);
  });

  it("on 401 mid-queue keeps every unsent item and stops retrying", async () => {
    await enqueue(aliceEntry(1)); // succeeds
    await enqueue(aliceEntry(2)); // 401
    await enqueue(aliceEntry(3)); // never attempted
    let calls = 0;
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      calls += 1;
      if (id === "a-2") throw new ApiError(401, "invalid token");
      return {};
    });

    const sent = await flushQueue("alice");
    expect(sent).toBe(1);
    expect(calls).toBe(2); // item 3 was never attempted
    const remaining = JSON.parse((await storage.getItem("@mindpattern/queue")) ?? "[]");
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-2", "a-3"]);
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

  it("keeps uploading after a plain network error (unlike 401)", async () => {
    await enqueue(aliceEntry(1)); // network error -> retried later, loop continues
    await enqueue(aliceEntry(2)); // succeeds
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-1") throw new TypeError("fetch failed");
      return {};
    });
    const sent = await flushQueue("alice");
    expect(sent).toBe(1); // item 2 went out after item 1's network error
    const remaining = JSON.parse((await storage.getItem("@mindpattern/queue")) ?? "[]");
    expect(remaining.map((r: any) => r.clientEntryId)).toEqual(["a-1"]);
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
    const remaining = JSON.parse((await storage.getItem("@mindpattern/queue")) ?? "[]");
    expect(remaining).toHaveLength(0);
  });

  it("a wipe racing enqueue wins: the item never lands in the wiped queue (M4)", async () => {
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
      await enqueue(aliceEntry(2));
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // The wipe BEGAN before the enqueue committed, so the enqueue must NOT
    // survive it: no resurrection of the old entries AND no write of the
    // racing item into the just-wiped queue — the key stays gone entirely.
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
    expect(await queueLength()).toBe(0);
  });

  it("an enqueue that STARTS after the wipe still lands (the queue is reusable)", async () => {
    await enqueue(aliceEntry(1));
    await clearQueue();
    await enqueue(aliceEntry(2));
    expect(await queueLength()).toBe(1);
    expect(await storage.getItem("@mindpattern/queue")).toContain("a-2");
    expect(await storage.getItem("@mindpattern/queue")).not.toContain("a-1");
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
    const remaining = JSON.parse((await storage.getItem("@mindpattern/queue")) ?? "[]");
    expect(remaining).toHaveLength(0);
  });
});
