/** Focused regression pins for queue classification and isolation boundaries. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

let baseUrl = "https://queue.example.test";
vi.mock("../src/api/client", async (importOriginal) => {
  // canonicalOrigin stays the REAL shared helper (H-1) — queue scoping and
  // the client's origin pin must not drift between mock and production.
  const { canonicalOrigin } = await importOriginal<typeof import("../src/api/client")>();
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
    canonicalOrigin,
    ApiError,
    OriginPinnedError,
    getBaseUrl: vi.fn(async () => baseUrl),
    api: {
      createEntry: vi.fn(async () => ({})),
      createQueuedEntry: vi.fn(async () => ({})),
      getUserId: vi.fn(async () => "alice"),
      // M-5 (2026-09-20): default 404; the verified-duplicate pin overrides.
      getEntry: vi.fn(async () => {
        throw new ApiError(404, "entry not found", "not_found");
      }),
    },
  };
});

const { api, ApiError } = await import("../src/api/client") as any;
const { enqueue, flushQueue, queueLength, rejectedEntries, MAX_QUEUE_LENGTH } = await import("../src/offlineQueue");
const item = (id: string) => ({
  userId: "alice",
  clientEntryId: id,
  blobB64: Buffer.alloc(48, 1).toString("base64"),
  entryDate: "2026-09-01",
});

beforeEach(() => {
  storage.__reset();
  baseUrl = "https://queue.example.test";
  vi.mocked(api.createQueuedEntry).mockReset();
  vi.mocked(api.createQueuedEntry).mockImplementation(async () => ({}));
});

describe("queue regression pins", () => {
  it("does not make a VERIFIED 409 duplicate into a rejected recovery item (M-5)", async () => {
    await enqueue(item("duplicate"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(409, "already exists"));
    vi.mocked(api.getEntry).mockResolvedValue({ id: "x", client_entry_id: "duplicate", blob: "b", entry_date: "2026-09-20", received_at: "2026-09-20T00:00:00Z", content_version: 1 } as never);
    expect(await flushQueue("alice")).toBe(0);
    expect(await queueLength("alice")).toBe(0);
    expect(await rejectedEntries("alice")).toEqual([]);
  });

  it("keeps a non-validation 422 terminal even when its message says future", async () => {
    await enqueue(item("bad"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(422, "future date", "entry_blob_invalid"));
    await flushQueue("alice");
    expect((await rejectedEntries("alice")).map((x: any) => x.clientEntryId)).toEqual(["bad"]);
  });

  it("makes a validation future-date response retryable, without uploading it to another origin", async () => {
    await enqueue(item("future"));
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(422, "entry date is in the future", "validation_error"));
    await flushQueue("alice");
    expect(await queueLength("alice")).toBe(1);
    baseUrl = "https://other.example.test";
    expect(await queueLength("alice")).toBe(0);
  });

  it("has a hard per-scope bound rather than evicting the oldest entry", async () => {
    for (let i = 0; i < MAX_QUEUE_LENGTH; i++) await enqueue(item(`id-${i}`));
    await expect(enqueue(item("overflow"))).rejects.toThrow(/offline queue is full/);
    expect(await queueLength("alice")).toBe(MAX_QUEUE_LENGTH);
  });
});
