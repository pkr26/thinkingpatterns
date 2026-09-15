/**
 * Deep-mutation pins for offlineQueue (2026-09-15 Stryker campaign).
 *
 * Each block kills specific surviving mutant classes (the 47 timeout-kills
 * are covered elsewhere; these are the survivors proper):
 *  - the exact SessionExpiredError message,
 *  - hostile persisted backoff fields (string attempts, 1e999 numbers) that
 *    must be normalized before the flush loop trusts them,
 *  - parse-edge shapes: raw "null"/""/non-iterable items envelopes — kept
 *    for repair, never quarantined,
 *    the v1 envelope must not be rewritten by a phantom "legacy" flag,
 *  - classification boundaries: 409-dedupe leaves the rejected store empty,
 *    a non-422 "future" message is still terminal, the future-422 retry
 *    does NOT stop the flush, status 0 DOES stop it, notBefore === now is
 *    due, and the 401-path rejected store starts empty,
 *  - commit races: wipe-during-commit cannot drop a re-saved entry, the
 *    userId must match in the commit findIndex, and an already-resolved
 *    item (index -1) must not splice the queue's tail,
 *  - requeueRejected: empty-rejected leaves both keys untouched, the
 *    overflow remainder is written exactly, and duplicate ids dedupe,
 *  - flushQueueOnReconnect: throttle behavior incl. the exact 10s boundary
 *    and the signed-out early return.
 *
 * Provably-equivalent mutants are suppressed in the source (see the
 * `Stryker disable next-line` comments); the typeof/`raw === null` arm
 * equivalents sharing lines with killable mutants are documented in the
 * campaign report instead.
 */
// @ts-nocheck

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
      createEntry: vi.fn(async () => ({})),
      getUserId: vi.fn(async () => "alice"),
    },
  };
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { api, ApiError } = await import("../src/api/client") as any;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const {
  enqueue,
  flushQueue,
  flushQueueOnReconnect,
  clearQueue,
  queueLength,
  quarantinedQueueExists,
  rejectedEntries,
  requeueRejected,
  MAX_QUEUE_LENGTH,
  SessionExpiredError,
} = await import("../src/offlineQueue");

const QUEUE_KEY = "@mindpattern/queue";
const QUARANTINE_KEY = "@mindpattern/queue_quarantine";
const REJECTED_KEY = "@mindpattern/queue_rejected";

const aliceEntry = (n: number) => ({
  userId: "alice",
  clientEntryId: `a-${n}`,
  blobB64: Buffer.alloc(40, n).toString("base64"),
  entryDate: "2026-09-01",
});

/** A planted ITEM with a field JSON.stringify would mangle (1e999 → null):
 *  splice the raw literal into the item's own JSON by hand so the parsed
 *  record really holds Infinity. */
const plantWithRawField = (entry: Record<string, unknown>, rawField: string): void => {
  const itemJson = JSON.stringify(entry).replace(/\}$/, `,${rawField}}`);
  void storage.setItem(QUEUE_KEY, `{"v":1,"items":[${itemJson}]}`);
};

const storedQueueItems = async (): Promise<any[]> => {
  const raw = (await storage.getItem(QUEUE_KEY)) ?? '{"v":1,"items":[]}';
  return JSON.parse(raw).items;
};

const tick = async (times = 1): Promise<void> => {
  for (let i = 0; i < times; i++) await new Promise((r) => setTimeout(r, 0));
};

beforeEach(() => {
  storage.__reset();
  vi.mocked(api.createEntry).mockClear();
  vi.mocked(api.createEntry).mockImplementation(async () => ({}));
  vi.mocked(api.getUserId).mockClear();
  vi.mocked(api.getUserId).mockImplementation(async () => "alice");
});

describe("offlineQueue pins: error message", () => {
  it("SessionExpiredError carries the exact preservation message", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const err = await flushQueue("alice").then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(SessionExpiredError);
    expect((err as Error).message).toBe(
      "session expired mid-flush — unsent entries were preserved in the rejected store",
    );
  });
});

describe("offlineQueue pins: hostile persisted backoff fields are normalized", () => {
  it("a string attempts value is dropped, not concatenated into the stored counter", async () => {
    await storage.setItem(QUEUE_KEY, JSON.stringify({ v: 1, items: [{ ...aliceEntry(1), attempts: "many" }] }));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(500, "boom"));
    const t0 = Date.now();
    expect(await flushQueue("alice")).toBe(0);
    const [marked] = await storedQueueItems();
    // Guard→true copies "many": attempts becomes "many1" and notBefore NaN.
    expect(marked.attempts).toBe(1);
    expect(marked.notBefore).toBeGreaterThanOrEqual(t0 + 15_000);
    expect(marked.notBefore).toBeLessThan(t0 + 30_000);
  });

  it("a non-finite attempts number (1e999) is dropped — the counter restarts at 1", async () => {
    // JSON.stringify(Infinity) is null, so the Infinity must be planted as a
    // raw literal — the only reachable non-finite JSON number.
    plantWithRawField(aliceEntry(1), '"attempts":1e999');
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(500, "boom"));
    const t0 = Date.now();
    expect(await flushQueue("alice")).toBe(0);
    const [marked] = await storedQueueItems();
    expect(marked.attempts).toBe(1);
    expect(marked.notBefore).toBeGreaterThanOrEqual(t0 + 15_000);
    expect(marked.notBefore).toBeLessThan(t0 + 30_000);
  });

  it("a non-finite notBefore (1e999) is dropped — the entry is due immediately", async () => {
    plantWithRawField(aliceEntry(1), '"notBefore":1e999');
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(await queueLength()).toBe(0);
  });
});

describe("offlineQueue pins: parse edges are kept for repair, never quarantined", () => {
  it("an envelope whose items field is a non-iterable stays untouched (no quarantine)", async () => {
    await storage.setItem(QUEUE_KEY, '{"v":1,"items":42}');
    expect(await queueLength()).toBe(0);
    expect(await storage.getItem(QUEUE_KEY)).toBe('{"v":1,"items":42}');
    expect(await quarantinedQueueExists()).toBe(false);
  });

  it('raw "null" parses to an unrecognized shape: empty queue, bytes preserved', async () => {
    await storage.setItem(QUEUE_KEY, "null");
    expect(await queueLength()).toBe(0);
    expect(await storage.getItem(QUEUE_KEY)).toBe("null");
    expect(await storage.getItem(QUARANTINE_KEY)).toBeNull();
  });

  it('raw "" is absent: no quarantine record is created', async () => {
    await storage.setItem(QUEUE_KEY, "");
    expect(await queueLength()).toBe(0);
    expect(await quarantinedQueueExists()).toBe(false);
    expect(await storage.getItem(QUARANTINE_KEY)).toBeNull();
  });

  it("a v1 envelope is NOT rewritten as legacy migration (null slots survive reads)", async () => {
    await storage.setItem(QUEUE_KEY, JSON.stringify({ v: 1, items: [null, aliceEntry(1)] }));
    expect(await queueLength()).toBe(1);
    // legacy→true would rewrite the envelope and silently drop the null slot.
    expect(JSON.parse((await storage.getItem(QUEUE_KEY)) as string).items).toEqual([null, aliceEntry(1)]);
  });
});

describe("offlineQueue pins: retryDelayMs jitter", () => {
  it("the delay really jitters into [15s, 30s) — not a constant 15s", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(api.createEntry).mockRejectedValue(new ApiError(500, "boom"));
      const deltas: number[] = [];
      for (let i = 0; i < 12; i++) {
        await clearQueue();
        await enqueue(aliceEntry(i));
        const now = Date.now();
        expect(await flushQueue("alice")).toBe(0);
        const [marked] = await storedQueueItems();
        deltas.push(marked.notBefore - now);
      }
      for (const delta of deltas) {
        expect(delta).toBeGreaterThanOrEqual(15_000);
        expect(delta).toBeLessThan(30_000);
      }
      // division-instead-of-multiplication pins every sample at exactly 15s.
      expect(Math.max(...deltas)).toBeGreaterThan(15_000);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("offlineQueue pins: classification boundaries", () => {
  it("a 409 duplicate is removed but NEVER lands in the rejected store", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(409, "entry already exists"));
    expect(await flushQueue("alice")).toBe(0);
    expect(await queueLength()).toBe(0);
    expect(await rejectedEntries()).toEqual([]);
  });

  it('a 400 whose message says "future" is still terminal (only 422 can retry)', async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(400, "entry_date cannot be in the future"));
    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries()).map((r) => r.clientEntryId)).toEqual(["a-1"]);
    expect(await queueLength()).toBe(0);
  });

  it("the retryable future-422 does NOT stop the flush: later items are attempted", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "entry_date cannot be in the future"));
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createEntry).toHaveBeenCalledTimes(2);
    expect((await storedQueueItems()).map((r: any) => r.clientEntryId)).toEqual(["a-1", "a-2"]);
  });

  it("a status-0 ApiError stops the flush: later items are not attempted", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-1") throw new ApiError(0, "server unreachable");
      return {};
    });
    expect(await flushQueue("alice")).toBe(0);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect((await storedQueueItems()).map((r: any) => r.clientEntryId)).toEqual(["a-1", "a-2"]);
  });

  it("notBefore === now is DUE (the boundary is inclusive)", async () => {
    vi.useFakeTimers();
    try {
      const now = Date.now();
      await storage.setItem(QUEUE_KEY, JSON.stringify({ v: 1, items: [{ ...aliceEntry(1), notBefore: now }] }));
      expect(await flushQueue("alice")).toBe(1);
      expect(api.createEntry).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("the 401-path rejected store starts empty — the FIRST write is already exact", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    // Capture every REJECTED_KEY write: a phantom first slot (["Stryker was
    // here"]) is normalized away by the NEXT append's read, so only the
    // transient write exposes it.
    const originalSetItem = storage.setItem.bind(storage);
    const rejectedWrites: string[] = [];
    (storage as { setItem: typeof storage.setItem }).setItem = async (k: string, v: string) => {
      if (k === REJECTED_KEY) rejectedWrites.push(v);
      return originalSetItem(k, v);
    };
    try {
      await expect(flushQueue("alice")).rejects.toBeInstanceOf(SessionExpiredError);
    } finally {
      (storage as { setItem: typeof storage.setItem }).setItem = originalSetItem;
    }
    expect(rejectedWrites.length).toBeGreaterThanOrEqual(2); // one per doomed append
    // The very first append must write exactly [a-1] — a poisoned initial
    // array shows up here (later reads normalize the phantom slot away).
    expect(JSON.parse(rejectedWrites[0]).items).toEqual([aliceEntry(1)]);
    for (const write of rejectedWrites) {
      expect(write).not.toContain("Stryker was here");
    }
    expect(JSON.parse((await storage.getItem(REJECTED_KEY)) as string).items).toEqual([aliceEntry(1), aliceEntry(2)]);
  });
});

describe("offlineQueue pins: commit races", () => {
  it("a wipe during a parked upload cannot drop the re-saved entry (commit abandons)", async () => {
    await enqueue(aliceEntry(1));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.mocked(api.createEntry).mockImplementationOnce(() => gate.then(() => ({})));
    const flushing = flushQueue("alice");
    await tick(3); // the flush is parked on its first upload
    await clearQueue(); // sign-out wins mid-flight
    await enqueue(aliceEntry(1)); // the user saves the SAME entry again
    release();
    // The abandoned commit must neither splice the re-saved copy…
    expect(await flushing).toBe(1);
    expect(await queueLength()).toBe(1);
    // …nor re-upload it (returning true would loop and flush it again).
    expect(api.createEntry).toHaveBeenCalledTimes(1);
  });

  it("a wipe during the 422-reject append abandons the commit; the re-saved entry survives", async () => {
    await enqueue(aliceEntry(1));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "bad blob"));
    const originalGetItem = storage.getItem.bind(storage);
    const originalSetItem = storage.setItem.bind(storage);
    let armed = true;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (armed && k === REJECTED_KEY) {
        armed = false;
        const stale = await originalGetItem(k);
        await clearQueue(); // account deletion inside appendRejected's read
        // The user re-saves the entry post-wipe. Written DIRECTLY (not via
        // enqueue) because this runs inside the flush's mutex-held commit —
        // enqueue here would deadlock on the same mutex.
        await originalSetItem(QUEUE_KEY, JSON.stringify({ v: 1, items: [aliceEntry(1)] }));
        return stale;
      }
      return originalGetItem(k);
    };
    try {
      expect(await flushQueue("alice")).toBe(0);
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // committed=false must stop the loop here: one upload, entry still
    // queued, nothing resurrected into the rejected store.
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(await queueLength()).toBe(1);
    expect(await storage.getItem(REJECTED_KEY)).toBeNull();
  });

  it("the commit findIndex matches userId too — a foreign same-id entry is never spliced", async () => {
    const shared = (userId: string, filler: number) => ({
      userId,
      clientEntryId: "shared-1",
      blobB64: Buffer.alloc(40, filler).toString("base64"),
      entryDate: "2026-09-01",
    });
    await enqueue(shared("bob", 2)); // bob's copy is FIRST in the queue
    await enqueue(shared("alice", 1));
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(api.createEntry).toHaveBeenCalledWith("shared-1", shared("alice", 1).blobB64, "2026-09-01");
    expect(await storedQueueItems()).toEqual([shared("bob", 2)]);
  });

  it("a concurrently-resolved item (index -1) neither splices the tail nor ends the flush early", async () => {
    await enqueue(aliceEntry(1));
    await enqueue(aliceEntry(2));
    let releaseA!: () => void;
    let releaseB!: () => void;
    const gateA = new Promise<void>((r) => {
      releaseA = r;
    });
    const gateB = new Promise<void>((r) => {
      releaseB = r;
    });
    const seen: Record<string, number> = {};
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      seen[id] = (seen[id] ?? 0) + 1;
      if (id === "a-1" && seen["a-1"] === 1) await gateA; // flush A parks on a-1
      if (id === "a-2" && seen["a-2"] === 1) await gateB; // flush B parks on a-2
      return {};
    });
    const flushA = flushQueue("alice");
    await tick(5);
    const flushB = flushQueue("alice");
    await tick(5);
    releaseA(); // A's a-1 upload resolves AFTER B already resolved it
    const sentA = await flushA;
    releaseB();
    const sentB = await flushB;
    // A's commit sees index -1: it must return true WITHOUT splicing a-2
    // (splice(-1,1) would destroy it) — so A still uploads a-2 itself. B
    // counted its own successful a-1 upload before parking on a-2.
    expect(sentA).toBe(2);
    expect(sentB).toBe(2);
    expect(api.createEntry).toHaveBeenCalledTimes(4);
    expect(await queueLength()).toBe(0);
  });
});

describe("offlineQueue pins: requeueRejected", () => {
  it("an unparseable rejected store is left untouched when nothing can move", async () => {
    await storage.setItem(REJECTED_KEY, "{not json");
    expect(await requeueRejected()).toBe(0);
    expect(await storage.getItem(REJECTED_KEY)).toBe("{not json");
    expect(await storage.getItem(QUEUE_KEY)).toBeNull();
  });

  it("the capacity overflow remainder is written exactly — no phantom slot", async () => {
    // One slot short of full: a-300 takes it, a-301 stays rejected.
    for (let i = 0; i < MAX_QUEUE_LENGTH - 1; i++) {
      await enqueue(aliceEntry(i));
    }
    await storage.setItem(REJECTED_KEY, JSON.stringify([aliceEntry(300), aliceEntry(301)]));
    expect(await requeueRejected()).toBe(1);
    const raw = JSON.parse((await storage.getItem(REJECTED_KEY)) as string);
    expect(raw.v).toBe(1);
    expect(raw.items).toEqual([aliceEntry(301)]);
  });

  it("duplicate rejected copies of one entry move exactly once", async () => {
    await storage.setItem(REJECTED_KEY, JSON.stringify([aliceEntry(1), aliceEntry(1)]));
    expect(await requeueRejected()).toBe(1);
    expect(await queueLength()).toBe(1);
    expect(await storedQueueItems()).toEqual([aliceEntry(1)]);
    expect(await rejectedEntries()).toEqual([]);
  });
});

describe("offlineQueue pins: flushQueueOnReconnect throttle", () => {
  it("rapid flaps are throttled before getUserId; the exact 10s boundary reopens", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.parse("2026-09-15T00:00:00Z"));
      await flushQueueOnReconnect();
      await flushQueueOnReconnect(); // seconds later: throttled, no UserId read
      expect(api.getUserId).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(10_000); // EXACTLY the window: 10000 < 10000 is false
      await flushQueueOnReconnect();
      expect(api.getUserId).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("signed out: the flush never starts, even for a queue item whose userId is null", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.parse("2026-09-15T02:00:00Z")); // past the throttle above
      // A hostile/corrupt slot whose userId round-trips as null would match
      // flushQueue(null) — the signed-out early return must precede it.
      await storage.setItem(QUEUE_KEY, JSON.stringify({ v: 1, items: [{ ...aliceEntry(9), userId: null }] }));
      vi.mocked(api.getUserId).mockResolvedValue(null);
      await flushQueueOnReconnect();
      expect(api.createEntry).not.toHaveBeenCalled();
      expect(await queueLength()).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
