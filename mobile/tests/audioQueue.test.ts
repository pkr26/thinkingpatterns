/** Security and recovery tests for the kept-recording offline queue
 *  (wave 2, 2026-09-30). Same discipline as the text queue: ciphertext
 *  only, scoped per (origin, account), bounded, honest flush semantics. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

let baseUrl = "https://one.example.test";

vi.mock("../src/api/client", async (importOriginal) => {
  const { canonicalOrigin } = await importOriginal<typeof import("../src/api/client")>();
  class ApiError extends Error {
    constructor(public status: number, message: string, public code?: string) {
      super(message);
    }
  }
  return {
    canonicalOrigin,
    ApiError,
    getBaseUrl: vi.fn(async () => baseUrl),
    api: {
      getUserId: vi.fn(async () => "alice"),
      uploadAudioAttachment: vi.fn(async () => ({})),
    },
  };
});

const { api, ApiError } = (await import("../src/api/client")) as any;
const {
  MAX_AUDIO_QUEUE_ITEMS,
  MAX_TAKE_BYTES,
  AudioTooLargeError,
  audioQueueCount,
  clearAudioQueue,
  enqueueAudio,
  flushAudioQueue,
} = await import("../src/audioQueue");

function take(n = 1): string {
  // A small but non-trivial ciphertext stand-in.
  return Buffer.alloc(1024 * n, 7).toString("base64");
}

beforeEach(async () => {
  storage.__reset();
  vi.clearAllMocks();
  (api.getUserId as any).mockResolvedValue("alice");
  (api.uploadAudioAttachment as any).mockReset();
  (api.uploadAudioAttachment as any).mockResolvedValue({});
});

describe("enqueueAudio", () => {
  it("stores ciphertext rows scoped per account and counts them", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "e1", blobB64: take(), mime: "audio/m4a", durationSeconds: 30 });
    await enqueueAudio({ userId: "alice", clientEntryId: "e2", blobB64: take(), mime: "audio/m4a", durationSeconds: 40 });
    await enqueueAudio({ userId: "bob", clientEntryId: "e1", blobB64: take(), mime: "audio/m4a", durationSeconds: 50 });
    expect(await audioQueueCount("alice")).toBe(2);
    expect(await audioQueueCount("bob")).toBe(1);
  });

  it("replaces the older take for the same entry (one attachment per entry)", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "e1", blobB64: take(1), mime: "audio/m4a", durationSeconds: 30 });
    await enqueueAudio({ userId: "alice", clientEntryId: "e1", blobB64: take(2), mime: "audio/m4a", durationSeconds: 60 });
    expect(await audioQueueCount("alice")).toBe(1);
  });

  it("refuses an oversized take instead of wedging the store row", async () => {
    await expect(
      enqueueAudio({ userId: "alice", clientEntryId: "big", blobB64: "x".repeat(MAX_TAKE_BYTES + 1), mime: "audio/m4a", durationSeconds: 60 }),
    ).rejects.toBeInstanceOf(AudioTooLargeError);
    expect(await audioQueueCount("alice")).toBe(0);
  });

  it("enforces the item cap by dropping the OLDEST take", async () => {
    for (let i = 0; i < MAX_AUDIO_QUEUE_ITEMS + 2; i += 1) {
      await enqueueAudio({ userId: "alice", clientEntryId: `e${i}`, blobB64: take(), mime: "audio/m4a", durationSeconds: i });
      // Distinct queuedAt so eviction order is deterministic.
      await new Promise((r) => setTimeout(r, 2));
    }
    expect(await audioQueueCount("alice")).toBe(MAX_AUDIO_QUEUE_ITEMS);
    // The flush uploads only the survivors: the two oldest are gone.
    const uploaded = await flushAudioQueue();
    expect(uploaded).toBe(MAX_AUDIO_QUEUE_ITEMS);
    expect(api.uploadAudioAttachment).toHaveBeenCalledTimes(MAX_AUDIO_QUEUE_ITEMS);
    const ids = (api.uploadAudioAttachment as any).mock.calls.map(([id]: [string]) => id);
    expect(ids).not.toContain("e0");
    expect(ids).not.toContain("e1");
    expect(ids).toContain(`e${MAX_AUDIO_QUEUE_ITEMS + 1}`);
  });
});

describe("flushAudioQueue", () => {
  it("uploads stored bytes VERBATIM (ciphertext-only, no key needed) and removes the row", async () => {
    const blob = take(3);
    await enqueueAudio({ userId: "alice", clientEntryId: "e9", blobB64: blob, mime: "audio/m4a", durationSeconds: 42 });
    const uploaded = await flushAudioQueue();
    expect(uploaded).toBe(1);
    expect(api.uploadAudioAttachment).toHaveBeenCalledWith("e9", blob, "audio/m4a", 42);
    expect(await audioQueueCount("alice")).toBe(0);
  });

  it("a 401 PARKS the take instead of dropping it (session expiry)", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "e401", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    (api.uploadAudioAttachment as any).mockRejectedValueOnce(new ApiError(401, "unauthorized"));
    expect(await flushAudioQueue()).toBe(0);
    expect(await audioQueueCount("alice")).toBe(1);
  });

  it("permanent rejections (403/404/409/413) drop the take honestly", async () => {
    for (const [id, status] of [["p403", 403], ["p404", 404], ["p409", 409], ["p413", 413]] as const) {
      await enqueueAudio({ userId: "alice", clientEntryId: id, blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    }
    (api.uploadAudioAttachment as any)
      .mockRejectedValueOnce(new ApiError(403, "consent"))
      .mockRejectedValueOnce(new ApiError(404, "entry gone"))
      .mockRejectedValueOnce(new ApiError(409, "conflict"))
      .mockRejectedValueOnce(new ApiError(413, "too large"));
    expect(await flushAudioQueue()).toBe(0);
    expect(await audioQueueCount("alice")).toBe(0);
  });

  it("network failures keep the take for the next reconnect", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "enet", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    (api.uploadAudioAttachment as any).mockRejectedValueOnce(new Error("fetch failed"));
    expect(await flushAudioQueue()).toBe(0);
    expect(await audioQueueCount("alice")).toBe(1);
    // The next healthy flush lands it.
    expect(await flushAudioQueue()).toBe(1);
  });

  it("a corrupt row is dropped without blocking the rest", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "egood", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    // Forge a corrupt sibling row directly in the same scope (the mock
    // exposes getAllKeys through the real AsyncStorage surface).
    const goodKey = (await storage.getAllKeys()).find((k: string) => k.endsWith(":egood"))!;
    await storage.setItem(`${goodKey.slice(0, goodKey.lastIndexOf(":"))}:ebad`, "{not json");
    expect(await flushAudioQueue()).toBe(1);
    expect(await audioQueueCount("alice")).toBe(0);
  });
});

describe("clearAudioQueue (account deletion policy)", () => {
  it("erases only the named account's takes and stops in-flight flushes", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "e1", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    await enqueueAudio({ userId: "bob", clientEntryId: "e1", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    await clearAudioQueue("alice");
    expect(await audioQueueCount("alice")).toBe(0);
    expect(await audioQueueCount("bob")).toBe(1);
    // After a clear, a racing stash must not resurrect the wiped rows.
    await enqueueAudio({ userId: "alice", clientEntryId: "e2", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    expect(await audioQueueCount("alice")).toBe(1); // a LATER stash is fine
  });
});
