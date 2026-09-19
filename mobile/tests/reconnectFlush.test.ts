/**
 * flushQueueOnReconnect: the AppState-driven sync trigger. A foregrounding
 * with a live session and a non-empty queue flushes; throttled so a
 * foreground/background flap cannot stampede the server; failures leave
 * the queue intact for the next trigger.
 *
 * Module state (the throttle timestamp) is per-file here, so this suite
 * gets its own file — store.test.tsx asserts the AppState wiring against
 * the mocked module instead.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

vi.mock("../src/api/client", () => {
  class OriginPinnedError extends Error {
      constructor(public expected: string, public actual: string) {
        super(`refusing to send data pinned to ${expected} while ${actual} is selected`);
      }
    }
    class ApiError extends Error {
    constructor(public status: number, message: string) {
      super(message);
    }
  }
  return {
    ApiError,
    OriginPinnedError,
    api: {
      getUserId: vi.fn(async () => "alice"),
      createEntry: vi.fn(async () => ({})),
      createQueuedEntry: vi.fn(async () => ({})),
    },
    getBaseUrl: vi.fn(async () => "http://localhost:8000"),
  };
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { api } = await import("../src/api/client") as any;
const { enqueue, queueLength, clearQueue, flushQueueOnReconnect } = await import("../src/offlineQueue");

const entry = (n: number) => ({
  userId: "alice",
  clientEntryId: `r-${n}`,
  blobB64: Buffer.alloc(40, n).toString("base64"),
  entryDate: "2026-09-01",
});

// The throttle timestamp is module state: each test starts the fake clock
// one minute later than the previous one so suites never share a window.
let clock: number | undefined;

beforeEach(() => {
  storage.__reset();
  vi.mocked(api.getUserId).mockClear();
  vi.mocked(api.getUserId).mockImplementation(async () => "alice");
  vi.mocked(api.createQueuedEntry).mockClear();
  vi.mocked(api.createQueuedEntry).mockImplementation(async () => ({}));
  vi.useFakeTimers();
  clock = (clock ?? Date.parse("2026-09-07T00:00:00Z")) + 60_000;
  vi.setSystemTime(clock);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("flushQueueOnReconnect", () => {
  it("flushes a non-empty queue when a session exists", async () => {
    await enqueue(entry(1));
    await flushQueueOnReconnect();
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);
    expect(await queueLength()).toBe(0);
  });

  it("does nothing when signed out or when the queue is empty", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null as never);
    await enqueue(entry(1));
    await flushQueueOnReconnect();
    expect(api.createQueuedEntry).not.toHaveBeenCalled();
    expect(await queueLength("alice")).toBe(1); // the entry waits for its owner

    // Empty queue: no upload, and the flush itself is skipped cheaply.
    // (Advance past the throttle window — this test's first call consumed it.)
    vi.advanceTimersByTime(11_000);
    vi.mocked(api.getUserId).mockResolvedValue("alice" as never);
    await clearQueue("alice");
    vi.mocked(api.createQueuedEntry).mockClear();
    await flushQueueOnReconnect();
    expect(api.createQueuedEntry).not.toHaveBeenCalled();
  });

  it("throttles rapid foreground/background flaps", async () => {
    await enqueue(entry(1));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new Error("offline")); // stays queued
    await flushQueueOnReconnect();
    await flushQueueOnReconnect(); // seconds later: throttled, not a stampede
    await flushQueueOnReconnect();
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);
  });

  it("flushes again once the throttle window has passed", async () => {
    await enqueue(entry(1));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new Error("offline"));
    await flushQueueOnReconnect();
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(31_000); // past BOTH the 10s throttle and the item's ≤30s backoff
    await flushQueueOnReconnect();
    expect(api.createQueuedEntry).toHaveBeenCalledTimes(2);
  });

  it("a failed flush never throws and keeps the ciphertext queued", async () => {
    await enqueue(entry(1));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new Error("offline"));
    await expect(flushQueueOnReconnect()).resolves.toBeUndefined();
    expect(await queueLength()).toBe(1);
  });
});
