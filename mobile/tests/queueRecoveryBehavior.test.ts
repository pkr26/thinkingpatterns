import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, ApiError, OriginPinnedError } from "../src/api/client";
import { abortInFlightFlush, enqueue, flushQueue, queueLength, quarantinedQueueExists, rejectedEntries, SessionExpiredError, type QueuedEntry } from "../src/offlineQueue";
const owner = "11111111111111111111111111111111", other = "22222222222222222222222222222222";
const entry = (id = "queued", fields: Partial<QueuedEntry> = {}): QueuedEntry => ({ userId: owner, clientEntryId: id, blobB64: "opaque encrypted writing", entryDate: "2026-10-05", ...fields });
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); abortInFlightFlush(); vi.spyOn(api, "getUserId").mockResolvedValue(owner); });
afterEach(() => { abortInFlightFlush(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function slots() { await enqueue(entry()); const queue = (await storage.getAllKeys()).find(k => k.startsWith("@mindpattern/queue.v2.items."))!; return { queue, rejected: queue.replace(".items.", ".rejected."), quarantine: queue.replace(".items.", ".quarantine.") }; }
function twiceThenOriginRefusal(error: ApiError) {
  let requests = 0;
  return vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => {
    if (++requests > 2) throw new OriginPinnedError("https://queued.example", "https://replacement.example");
    throw error;
  });
}
it("retains valid queued writing after a transient native read failure and recovers on retry", async () => {
  const { queue, quarantine } = await slots(), before = await storage.getItem(queue), read = storage.getItem; let fail = true;
  const unavailable = new Error("Temporary native database read failure");
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === queue && fail) { fail = false; throw unavailable; } return read(slot); });
  await expect(queueLength(owner)).rejects.toBe(unavailable);
  expect(await storage.getItem(queue)).toBe(before); expect(await storage.getItem(quarantine)).toBeNull(); expect(await queueLength(owner)).toBe(1);
});
it.each([null, true, 42, "text", {}, { userId: 1 }, { clientEntryId: null }, { blobB64: [] }, { entryDate: {} }])("retains malformed recovery records as evidence while preserving valid queued writing: %#", async fields => {
  const { rejected, quarantine } = await slots();
  const malformed = fields !== null && typeof fields === "object" && Object.keys(fields).length > 0 ? { ...entry("invalid"), evidence: "original encrypted record", ...fields } : fields;
  const original = JSON.stringify({ v: 1, items: [malformed, entry("valid")] }); await storage.setItem(rejected, original);
  expect(await rejectedEntries(owner)).toEqual([entry("valid")]);
  expect(JSON.parse((await storage.getItem(quarantine))!).records).toContain(original);
  expect(await rejectedEntries(owner)).toEqual([entry("valid")]);
});
it("quarantines a foreign owner's ciphertext without exposing it in this account's recovery list", async () => {
  const { rejected, quarantine } = await slots(), foreign = entry("foreign", { userId: other, blobB64: "foreign encrypted writing" });
  await storage.setItem(rejected, JSON.stringify([foreign, entry("own")])); expect(await rejectedEntries(owner)).toEqual([entry("own")]);
  const records = JSON.parse((await storage.getItem(quarantine))!).records as string[]; expect(records.some(raw => raw.includes(foreign.blobB64))).toBe(true);
  expect(await rejectedEntries(other)).toEqual([]); expect(await quarantinedQueueExists(owner)).toBe(true); expect(await quarantinedQueueExists(other)).toBe(false);
});
it.each(["null", "42", "true", '"text"', "{}", '{"v":2,"items":[]}', '{"v":1,"items":{}}'])("parks an unrecognized native queue envelope verbatim: %s", async raw => {
  const { queue, quarantine } = await slots(); await storage.setItem(queue, raw);
  expect(await queueLength(owner)).toBe(0); expect(await storage.getItem(queue)).toBeNull(); expect(JSON.parse((await storage.getItem(quarantine))!).records).toContain(raw);
});
it("normalizes optional retry metadata without coercing strings or arrays", async () => {
  const { rejected } = await slots();
  await storage.setItem(rejected, JSON.stringify([entry("valid", { attempts: 2, notBefore: 123 }), entry("invalid", { attempts: "2" as never, notBefore: [123] as never })]));
  expect(await rejectedEntries(owner)).toEqual([entry("valid", { attempts: 2, notBefore: 123 }), entry("invalid")]);
});
it.each([[0, 15_000], [1, 30_000], [10, 900_000], [100, 900_000]])("waits for the bounded exponential pause after %s prior failures", async (attempts, delay) => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); vi.spyOn(Math, "random").mockReturnValue(0);
  await enqueue(entry("retry", { attempts })); const post = twiceThenOriginRefusal(new ApiError(503, "temporary"));
  await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1); vi.setSystemTime(1_000_000 + delay - 1); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1);
  vi.setSystemTime(1_000_000 + delay); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2);
});
it.each([[0, 1000], [120_000, 120_000], [7_200_000, 3_600_000]])("honors a server retry advisory within the stated floor and ceiling: %s", async (advisory, delay) => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); await enqueue(entry());
  const post = twiceThenOriginRefusal(new ApiError(429, "busy", "rate_limited", advisory));
  await flushQueue(owner); vi.setSystemTime(1_000_000 + delay - 1); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1);
  vi.setSystemTime(1_000_000 + delay); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2);
});
it("preserves an expired session's writing for fifteen minutes before a retry", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); await enqueue(entry("single"));
  const post = twiceThenOriginRefusal(new ApiError(401, "expired"));
  await expect(flushQueue(owner)).rejects.toBeInstanceOf(SessionExpiredError); expect(await queueLength(owner)).toBe(1);
  vi.setSystemTime(1_899_999); expect(await flushQueue(owner)).toBe(0); expect(post).toHaveBeenCalledTimes(1);
  vi.setSystemTime(1_900_000); await expect(flushQueue(owner)).rejects.toBeInstanceOf(SessionExpiredError); expect(post).toHaveBeenCalledTimes(2);
});
