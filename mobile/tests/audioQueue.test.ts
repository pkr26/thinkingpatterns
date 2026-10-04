/** Security and recovery tests for the kept-recording offline queue
 *  (wave 2, 2026-09-30). Same discipline as the text queue: ciphertext
 *  only, scoped per (origin, account), bounded, honest flush semantics. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import * as fs from "./helpers/expoFsMock";

vi.mock("../src/offlineQueue", () => ({ flushQueue: vi.fn(async () => 0), pendingEntryIds: vi.fn(async () => []) }));

let baseUrl = "https://one.example.test";

vi.mock("../src/api/client", async (importOriginal) => {
  const { canonicalOrigin } = await importOriginal<typeof import("../src/api/client")>();
  class ApiError extends Error {
    constructor(public status: number, message: string, public code?: string) {
      super(message);
    }
  }
  class OriginPinnedError extends Error {
    constructor(expected: string, actual: string) {
      super(`refusing to send data pinned to ${expected} while ${actual} is selected`);
      this.name = "OriginPinnedError";
    }
  }
  return {
    canonicalOrigin,
    ApiError,
    OriginPinnedError,
    getBaseUrl: vi.fn(async () => baseUrl),
    api: {
      getUserId: vi.fn(async () => "alice"),
      uploadAudioAttachment: vi.fn(async () => ({})),
    },
  };
});

const { api, ApiError } = (await import("../src/api/client")) as any;
const parents = await import("../src/offlineQueue");
const {
  MAX_AUDIO_QUEUE_ITEMS,
  MAX_TAKE_BYTES,
  AudioTooLargeError,
  AudioQueueFullError,
  audioQueueStatus,
  retryAudioQueue,
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
  fs.__resetFiles();
  baseUrl = "https://one.example.test";
  vi.clearAllMocks();
  (api.getUserId as any).mockResolvedValue("alice");
  (api.uploadAudioAttachment as any).mockReset();
  (api.uploadAudioAttachment as any).mockResolvedValue({});
  vi.mocked(parents.flushQueue).mockResolvedValue(0);
  vi.mocked(parents.pendingEntryIds).mockResolvedValue([]);
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

  it("refuses overflow and preserves every earlier acknowledged recording", async () => {
    for (let i = 0; i < MAX_AUDIO_QUEUE_ITEMS; i++) {
      await enqueueAudio({ userId: "alice", clientEntryId: `e${i}`, blobB64: take(), mime: "audio/m4a", durationSeconds: i });
    }
    await expect(enqueueAudio({ userId: "alice", clientEntryId: "overflow", blobB64: take(), mime: "audio/m4a", durationSeconds: 1 })).rejects.toBeInstanceOf(AudioQueueFullError);
    expect(await audioQueueCount("alice")).toBe(MAX_AUDIO_QUEUE_ITEMS);
    expect(await flushAudioQueue()).toBe(MAX_AUDIO_QUEUE_ITEMS);
    const ids = api.uploadAudioAttachment.mock.calls.map(([id]: [string]) => id);
    expect(ids).toContain("e0");
    expect(ids).toContain(`e${MAX_AUDIO_QUEUE_ITEMS-1}`);
    expect(ids).not.toContain("overflow");
  });

  it("keeps a large encrypted take in a file with a small descriptor", async () => {
    const blob = take(2048);
    await enqueueAudio({ userId: "alice", clientEntryId: "large", blobB64: blob, mime: "audio/m4a", durationSeconds: 60 });
    const key = (await storage.getAllKeys()).find(k => k.endsWith(":large"))!;
    const raw = (await storage.getItem(key))!;
    expect(raw.length).toBeLessThan(1024);
    expect(JSON.parse(raw)).not.toHaveProperty("blobB64");
    expect(await fs.readAsStringAsync(JSON.parse(raw).uri)).toBe(blob);
  });

});

describe("flushAudioQueue", () => {
  it("preserves client ids containing colons", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "device:entry:1", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    expect(await flushAudioQueue()).toBe(1);
    expect(api.uploadAudioAttachment.mock.calls[0][0]).toBe("device:entry:1");
  });

  it("waits for the parent acknowledgement and retains rejected parents", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "parent", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    vi.mocked(parents.pendingEntryIds).mockResolvedValue(["parent"]);
    expect(await flushAudioQueue()).toBe(0);
    expect(parents.flushQueue).toHaveBeenCalledWith("alice");
    expect(api.uploadAudioAttachment).not.toHaveBeenCalled();
    expect(await audioQueueCount("alice")).toBe(1);
    vi.mocked(parents.pendingEntryIds).mockResolvedValue([]);
    expect(await flushAudioQueue()).toBe(1);
  });

  it("migrates a legacy blob without copying its large payload into the descriptor", async () => {
    const blob = take(2048);
    const key = `@mindpattern/audioqueue.v1:${baseUrl}:alice:legacy`;
    await storage.setItem(key, JSON.stringify({ blobB64: blob, mime: "audio/m4a", durationSeconds: 60, queuedAt: 123 }));
    api.uploadAudioAttachment.mockRejectedValueOnce(new Error("offline"));
    expect(await flushAudioQueue()).toBe(0);
    const raw = (await storage.getItem(key))!;
    expect(raw.length).toBeLessThan(1024);
    expect(JSON.parse(raw)).not.toHaveProperty("blobB64");
    expect(await fs.readAsStringAsync(JSON.parse(raw).uri)).toBe(blob);
  });

  it("an old upload acknowledgement cannot delete a replacement take", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "race", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    let acknowledge!: () => void;
    api.uploadAudioAttachment.mockImplementationOnce(() => new Promise<void>(resolve => { acknowledge = resolve; }));
    const pending = flushAudioQueue();
    await vi.waitFor(() => expect(api.uploadAudioAttachment).toHaveBeenCalledOnce());
    await enqueueAudio({ userId: "alice", clientEntryId: "race", blobB64: take(2), mime: "audio/m4a", durationSeconds: 20 });
    acknowledge();
    expect(await pending).toBe(0);
    expect(await audioQueueCount("alice")).toBe(1);
    expect(await flushAudioQueue()).toBe(1);
    expect(api.uploadAudioAttachment.mock.calls[1][1]).toBe(take(2));
  });

  it("coalesces concurrent flushes into one upload", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "single", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    let acknowledge!: () => void;
    api.uploadAudioAttachment.mockImplementationOnce(() => new Promise<void>(resolve => { acknowledge = resolve; }));
    const first = flushAudioQueue();
    await vi.waitFor(() => expect(api.uploadAudioAttachment).toHaveBeenCalledOnce());
    const second = flushAudioQueue();
    await vi.waitFor(() => expect(parents.flushQueue).toHaveBeenCalledOnce());
    acknowledge();
    expect(await Promise.all([first, second])).toEqual([1, 1]);
    expect(api.uploadAudioAttachment).toHaveBeenCalledOnce();
  });

  it("an in-flight 401 cannot resurrect an erased take", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "erase", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    let reject!: (err: Error) => void;
    api.uploadAudioAttachment.mockImplementationOnce(() => new Promise<void>((_, fail) => { reject = fail; }));
    const pending = flushAudioQueue();
    await vi.waitFor(() => expect(api.uploadAudioAttachment).toHaveBeenCalledOnce());
    await clearAudioQueue("alice");
    reject(new ApiError(401, "expired"));
    expect(await pending).toBe(0);
    expect(await audioQueueCount("alice")).toBe(0);
  });

  it("exposes missing ciphertext files for user recovery", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "missing", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    fs.__resetFiles();
    expect(await audioQueueStatus("alice")).toEqual({ total: 1, needsAttention: 1 });
    expect(await flushAudioQueue()).toBe(0);
    expect(await audioQueueCount("alice")).toBe(1);
  });
  it("uploads stored bytes VERBATIM (ciphertext-only, no key needed) and removes the row", async () => {
    const blob = take(3);
    await enqueueAudio({ userId: "alice", clientEntryId: "e9", blobB64: blob, mime: "audio/m4a", durationSeconds: 42 });
    const uploaded = await flushAudioQueue();
    expect(uploaded).toBe(1);
    // 2026-10-01 audit H1: every upload is pinned to the flush's origin.
    expect(api.uploadAudioAttachment).toHaveBeenCalledWith("e9", blob, "audio/m4a", 42, baseUrl, expect.objectContaining({ userId: "alice" }));
    expect(await audioQueueCount("alice")).toBe(0);
  });

  it("a 401 PARKS the take instead of dropping it (session expiry)", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "e401", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    (api.uploadAudioAttachment as any).mockRejectedValueOnce(new ApiError(401, "unauthorized"));
    expect(await flushAudioQueue()).toBe(0);
    expect(await audioQueueCount("alice")).toBe(1);
  });

  it("rejections (403/404/409/413) retain the only copy and expose recovery status", async () => {
    for (const [id, status] of [["p403", 403], ["p404", 404], ["p409", 409], ["p413", 413]] as const) {
      await enqueueAudio({ userId: "alice", clientEntryId: id, blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    }
    (api.uploadAudioAttachment as any)
      .mockRejectedValueOnce(new ApiError(403, "consent"))
      .mockRejectedValueOnce(new ApiError(404, "entry gone"))
      .mockRejectedValueOnce(new ApiError(409, "conflict"))
      .mockRejectedValueOnce(new ApiError(413, "too large"));
    expect(await flushAudioQueue()).toBe(0);
    expect(await audioQueueCount("alice")).toBe(4);
    expect(await audioQueueStatus("alice")).toEqual({ total: 4, needsAttention: 4 });
    await retryAudioQueue("alice");
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

  it("an origin-pin refusal KEEPS the row (server switched mid-flush, 2026-10-01 H1)", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "e-pin", blobB64: take(), mime: "audio/m4a", durationSeconds: 30 });
    const { OriginPinnedError } = await import("../src/api/client");
    (api.uploadAudioAttachment as any).mockRejectedValueOnce(
      new OriginPinnedError("https://one.example.test", "https://two.example.test"),
    );
    const uploaded = await flushAudioQueue();
    expect(uploaded).toBe(0);
    expect(await audioQueueCount("alice")).toBe(1); // NOT dropped — it stays queued
  });

  it("a corrupt row remains recoverable without blocking independent recordings", async () => {
    await enqueueAudio({ userId: "alice", clientEntryId: "egood", blobB64: take(), mime: "audio/m4a", durationSeconds: 10 });
    // Forge a corrupt sibling row directly in the same scope (the mock
    // exposes getAllKeys through the real AsyncStorage surface).
    const goodKey = (await storage.getAllKeys()).find((k: string) => k.endsWith(":egood"))!;
    await storage.setItem(`${goodKey.slice(0, goodKey.lastIndexOf(":"))}:ebad`, "{not json");
    expect(await flushAudioQueue()).toBe(1);
    expect(await audioQueueCount("alice")).toBe(1);
    expect(await audioQueueStatus("alice")).toEqual({ total: 1, needsAttention: 1 });
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
