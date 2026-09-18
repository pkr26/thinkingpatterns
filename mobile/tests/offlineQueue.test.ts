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
  return {
    ApiError,
    getBaseUrl: vi.fn(async () => baseUrl),
    api: {
      createEntry: vi.fn(async () => ({})),
      getUserId: vi.fn(async () => "alice"),
    },
  };
});

const { api, ApiError } = await import("../src/api/client") as any;
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
  vi.mocked(api.createEntry).mockReset();
  vi.mocked(api.createEntry).mockImplementation(async () => ({}));
  vi.mocked(api.getUserId).mockReset();
  vi.mocked(api.getUserId).mockResolvedValue("alice");
});

describe("offline queue scope", () => {
  it("uses physically separate origin/account stores and never uploads a foreign scope", async () => {
    await enqueue(entry("alice", "a-1"));
    await enqueue(entry("bob", "b-1"));

    expect(await scopedKeys("items")).toHaveLength(2);
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createEntry).toHaveBeenCalledWith("a-1", expect.any(String), "2026-09-01");
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
    expect(api.createEntry).not.toHaveBeenCalled();

    baseUrl = "https://one.example.test";
    expect(await flushQueue("alice")).toBe(1);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
  });

  it("keeps rejected recovery scoped to the same account and origin", async () => {
    await enqueue(entry("alice", "a-rejected"));
    await enqueue(entry("bob", "b-live"));
    vi.mocked(api.createEntry).mockImplementation(async (id: string) => {
      if (id === "a-rejected") throw new ApiError(422, "invalid encrypted blob");
      return {};
    });

    expect(await flushQueue("alice")).toBe(0);
    expect((await rejectedEntries("alice")).map((item: any) => item.clientEntryId)).toEqual(["a-rejected"]);
    expect(await rejectedEntryCount("bob")).toBe(0);
    expect(await queueLength("bob")).toBe(1);

    vi.mocked(api.createEntry).mockImplementation(async () => ({}));
    expect(await requeueRejected("alice")).toBe(1);
    expect(await flushQueue("alice")).toBe(1);
    expect(await rejectedEntryCount("alice")).toBe(0);
  });

  it("moves only the current scope to recovery after an authentic 401", async () => {
    await enqueue(entry("alice", "a-1"));
    await enqueue(entry("alice", "a-2"));
    await enqueue(entry("bob", "b-1"));
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "expired"));

    await expect(flushQueue("alice")).rejects.toBeInstanceOf(SessionExpiredError);
    expect((await rejectedEntries("alice")).map((item: any) => item.clientEntryId)).toEqual(["a-1", "a-2"]);
    expect(await queueLength("bob")).toBe(1);
  });

  it("fences an in-flight flush on sign-out rather than rejecting its ciphertext", async () => {
    await enqueue(entry("alice", "a-1"));
    let release!: () => void;
    vi.mocked(api.createEntry).mockImplementationOnce(
      () => new Promise((resolve) => { release = () => resolve({}); }),
    );
    const flushing = flushQueue("alice");
    await new Promise((resolve) => setTimeout(resolve, 0));
    abortInFlightFlush();
    release();

    expect(await flushing).toBe(1);
    // The success was remote, but the stale local commit is abandoned. A
    // later flush safely receives server-side 409 dedupe if needed.
    expect(await queueLength("alice")).toBe(1);
    expect(await rejectedEntries("alice")).toEqual([]);
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

  it("enforces a per-scope capacity and preserves every existing ciphertext", async () => {
    for (let i = 0; i < MAX_QUEUE_LENGTH; i++) await enqueue(entry("alice", `a-${i}`));
    await expect(enqueue(entry("alice", "overflow"))).rejects.toBeInstanceOf(QueueFullError);
    expect(await queueLength("alice")).toBe(MAX_QUEUE_LENGTH);
    expect(await queueLength("bob")).toBe(0);
  });
});
