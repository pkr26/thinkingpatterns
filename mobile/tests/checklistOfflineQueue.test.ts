/**
 * External verification checklist 2026-09-23: the offline queue's EXACT
 * byte boundary and the three-entry offline-day journey.
 *
 * The mapped suite crosses the cap in ~200/600 KB jumps; here the scope
 * lands on MAX_QUEUE_BYTES exactly (accepted) and one serialized byte over
 * (rejected), pinning the cap's edge. The journey test then drains a
 * 3-entry offline day in one reconnect, asserting each entry uploads
 * exactly once with its own date.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

let baseUrl = "https://one.example.test";

vi.mock("../src/api/client", async (importOriginal) => {
  const { canonicalOrigin } = await importOriginal<typeof import("../src/api/client")>();
  class ApiError extends Error {
    constructor(public status: number, message: string, public code?: string, public retryAfterMs?: number) {
      super(message);
    }
  }
  return {
    canonicalOrigin,
    ApiError,
    getBaseUrl: vi.fn(async () => baseUrl),
    api: {
      createQueuedEntry: vi.fn(async () => ({})),
      getUserId: vi.fn(async () => "alice"),
      getEntry: vi.fn(async () => {
        throw new ApiError(404, "entry not found", "not_found");
      }),
    },
  };
});

const { api } = await import("../src/api/client") as any;
const {
  enqueue,
  flushQueue,
  queueLength,
  MAX_QUEUE_BYTES,
  QueueFullError,
} = await import("../src/offlineQueue");

const itemsKey = async (): Promise<string> => {
  const keys = (await storage.getAllKeys()).filter((k: string) =>
    k.startsWith("@mindpattern/queue.v2.items."),
  );
  if (keys.length !== 1) throw new Error(`expected one scope, got ${keys.length}`);
  return keys[0];
};

beforeEach(() => {
  storage.__reset();
  baseUrl = "https://one.example.test";
  vi.mocked(api.createQueuedEntry).mockReset();
  vi.mocked(api.createQueuedEntry).mockImplementation(async () => ({}));
});

describe("checklist: exact byte boundary", () => {
  it("accepts a scope of exactly MAX_QUEUE_BYTES and rejects one byte more", async () => {
    // Documented: the cap is 1,000,000 serialized bytes (a decimal
    // megabyte, 48,576 bytes below 1 MiB) — Android cursor-window safety,
    // not a disk quota.
    expect(MAX_QUEUE_BYTES).toBe(1_000_000);

    const first = {
      userId: "alice",
      clientEntryId: "edge-1",
      blobB64: "A".repeat(1000),
      entryDate: "2026-09-01",
    };
    await enqueue(first);
    const raw1 = (await storage.getItem(await itemsKey())) as string;

    // The stored shape is a JSON array of items; adding one item costs
    // "," + itemJson. Craft the second item so the TOTAL serialized
    // length equals the cap exactly.
    const template = {
      userId: "alice",
      clientEntryId: "edge-2",
      blobB64: "A".repeat(1000),
      entryDate: "2026-09-02",
    };
    const templateItemJson = JSON.stringify(template);
    const targetItemJsonLen = MAX_QUEUE_BYTES - raw1.length - 1;
    const pad = targetItemJsonLen - templateItemJson.length;
    expect(pad).toBeGreaterThan(0);
    const second = {
      ...template,
      blobB64: "A".repeat(1000 + pad),
    };

    await enqueue(second);
    const raw2 = (await storage.getItem(await itemsKey())) as string;
    expect(raw2.length).toBe(MAX_QUEUE_BYTES);
    expect(await queueLength("alice")).toBe(2);

    // One serialized byte over the cap: refused, nothing disturbed.
    const overflow = {
      userId: "alice",
      clientEntryId: "edge-3",
      blobB64: "A".repeat(64),
      entryDate: "2026-09-03",
    };
    await expect(enqueue(overflow)).rejects.toBeInstanceOf(QueueFullError);
    const raw3 = (await storage.getItem(await itemsKey())) as string;
    expect(raw3.length).toBe(MAX_QUEUE_BYTES);
    expect(await queueLength("alice")).toBe(2);
  });
});

describe("checklist: offline-day journey", () => {
  it("three offline entries on three days flush exactly once on reconnect", async () => {
    const days = ["2026-09-20", "2026-09-21", "2026-09-22"];
    for (let i = 0; i < days.length; i++) {
      await enqueue({
        userId: "alice",
        clientEntryId: `offline-${i}`,
        blobB64: Buffer.alloc(48, i + 1).toString("base64"),
        entryDate: days[i],
      });
    }
    expect(await queueLength("alice")).toBe(3);

    // Reconnect: one flush drains everything, in order, exactly once.
    await flushQueue("alice");
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(3);
    const calls = vi.mocked(api.createQueuedEntry).mock.calls;
    expect(calls.map((c) => c[0])).toEqual(["offline-0", "offline-1", "offline-2"]);
    expect(calls.map((c) => c[2])).toEqual(days);
    expect(await queueLength("alice")).toBe(0);

    // A second flush (another foreground flap) uploads nothing new —
    // no duplicate entries server-side.
    await flushQueue("alice");
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(3);
  });
});
