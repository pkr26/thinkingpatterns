import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, ApiError } from "../src/api/client";
import { abortInFlightFlush, enqueue, flushQueue, queueLength, rejectedEntries } from "../src/offlineQueue";
const USER = "11111111111111111111111111111111";
const entry = (id: string, blobB64 = "opaque encrypted writing") => ({ userId: USER, clientEntryId: id, entryDate: "2026-10-05", blobB64 });
beforeEach(() => { storage.__reset(); abortInFlightFlush(); vi.spyOn(api, "getUserId").mockResolvedValue(USER); });
afterEach(() => { abortInFlightFlush(); vi.restoreAllMocks(); });
async function slots() {
  await enqueue(entry("newest"));
  const queue = (await storage.getAllKeys()).find(key => key.startsWith("@mindpattern/queue.v2.items."))!;
  expect(queue).toBeTruthy();
  return { queue, quarantine: queue.replace(".items.", ".quarantine."), rejected: queue.replace(".items.", ".rejected.") };
}
function finiteByteBudget() {
  const native = Buffer.byteLength;
  let measurements = 0;
  return vi.spyOn(Buffer, "byteLength").mockImplementation((...args: Parameters<typeof Buffer.byteLength>) => {
    if (++measurements > 16) throw new Error("finite recovery storage stopped making progress");
    return native(...args);
  });
}
it("recovers an unreadable queue as empty while retaining its corrupt evidence", async () => {
  const { queue, quarantine } = await slots();
  await storage.setItem(queue, "corrupt encrypted queue record");
  expect(await queueLength(USER)).toBe(0);
  expect(await storage.getItem(queue)).toBeNull();
  expect(JSON.parse((await storage.getItem(quarantine))!).records).toEqual(["corrupt encrypted queue record"]);
});
it("retains the newest fifty quarantine records when a full drawer receives another", async () => {
  const { queue, quarantine } = await slots();
  const before = Array.from({ length: 50 }, (_, index) => `older opaque record ${index}`);
  await storage.setItem(quarantine, JSON.stringify({ v: 1, records: before }));
  await storage.setItem(queue, "newest corrupt encrypted record");
  expect(await queueLength(USER)).toBe(0);
  expect(JSON.parse((await storage.getItem(quarantine))!).records).toEqual([...before.slice(1), "newest corrupt encrypted record"]);
});
it("shrinks oversized quarantine evidence within a finite serialization budget", async () => {
  const { queue, quarantine } = await slots();
  await storage.setItem(quarantine, JSON.stringify({ v: 1, records: ["A".repeat(1_000_001)] }));
  await storage.setItem(queue, "newest corrupt encrypted record");
  const observer = finiteByteBudget();
  try {
    expect(await queueLength(USER)).toBe(0);
    expect(JSON.parse((await storage.getItem(quarantine))!).records).toEqual(["newest corrupt encrypted record"]);
  } finally { observer.mockRestore(); }
});
it("retains the newest two hundred rejected entries when a full drawer receives another", async () => {
  const { rejected } = await slots();
  const before = Array.from({ length: 200 }, (_, index) => entry(`older-${index}`));
  await storage.setItem(rejected, JSON.stringify({ v: 1, items: before }));
  vi.spyOn(api, "createQueuedEntry").mockRejectedValue(new ApiError(400, "invalid retained writing"));
  expect(await flushQueue(USER)).toBe(0);
  expect(await rejectedEntries(USER)).toEqual([...before.slice(1), entry("newest")]);
});
it("shrinks oversized rejected storage within a finite serialization budget", async () => {
  const { rejected } = await slots();
  await storage.setItem(rejected, JSON.stringify({ v: 1, items: [entry("older", "A".repeat(1_000_001))] }));
  vi.spyOn(api, "createQueuedEntry").mockRejectedValue(new ApiError(400, "invalid retained writing"));
  const observer = finiteByteBudget();
  try {
    await expect(flushQueue(USER)).resolves.toBe(0);
    expect(await rejectedEntries(USER)).toEqual([entry("newest")]);
  } finally { observer.mockRestore(); }
});

it("reports a fresh owned queue and rejected drawer as empty", async () => {
  expect(await queueLength(USER)).toBe(0);
  expect(await rejectedEntries(USER)).toEqual([]);
});

it("reports an aborted full-queue admission as abandoned and preserves its exact bytes", async () => {
  const { QueueAbandonedError } = await import("../src/offlineQueue");
  const { queue } = await slots();
  const original = JSON.stringify({ v: 1, items: Array.from({ length: 200 }, (_, index) => entry(`retained-${index}`)) });
  await storage.setItem(queue, original);
  const read = storage.getItem.bind(storage);
  let interrupted = false;
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await read(key);
    if (key === queue && !interrupted) { interrupted = true; abortInFlightFlush(); }
    return value;
  });
  await expect(enqueue(entry("abandoned-newest"))).rejects.toBeInstanceOf(QueueAbandonedError);
  expect(interrupted).toBe(true);
  expect(await read(queue)).toBe(original);
});

it("an aborted recovery write preserves its rejected copy and reports no acknowledged move", async () => {
  const { requeueRejected } = await import("../src/offlineQueue");
  const { queue, rejected } = await slots();
  await storage.removeItem(queue);
  const original = JSON.stringify({ v: 1, items: [entry("retained-recovery")] });
  await storage.setItem(rejected, original);
  const write = storage.setItem.bind(storage);
  let release!: () => void, admitted!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === queue) { admitted(); await gate; }
    await write(key, value);
  });
  const recovering = requeueRejected(USER);
  try {
    await Promise.race([entered, recovering]);
    abortInFlightFlush(); release();
    expect(await recovering).toBe(0);
    expect(await storage.getItem(rejected)).toBe(original);
  } finally { release(); await recovering; }
});
