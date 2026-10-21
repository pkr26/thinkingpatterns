import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api } from "../src/api/client";
import { buildAad, decrypt, encrypt } from "../src/crypto/envelope";
import { abortInFlightFlush, clearQueue, enqueue, rejectedEntryCount, type QueuedEntry } from "../src/offlineQueue";

const owner = "62626262626262626262626262626262";
const entryId = "malformed-rejected-erasure-custody";
const key = Buffer.alloc(32, 62);
const privateText = "owner writing inside genuine authenticated ciphertext";

beforeEach(async () => {
  vi.restoreAllMocks();
  storage.__reset();
  abortInFlightFlush();
  await api.setSession("rejected-recovery-owner-session", owner, "rejected-recovery-owner");
});
afterEach(() => { vi.restoreAllMocks(); abortInFlightFlush(); });

async function malformedRejected() {
  const item: QueuedEntry = {
    userId: owner,
    clientEntryId: entryId,
    entryDate: "2026-10-06",
    blobB64: encrypt(key, Buffer.from(privateText), buildAad("entry", owner, entryId, "1")).toString("base64"),
  };
  await enqueue(item);
  const queue = (await storage.getAllKeys()).find(slot => slot.startsWith("@mindpattern/queue.v2.items."));
  expect(queue).toBeDefined();
  await storage.removeItem(queue!);
  const rejected = queue!.replace(".items.", ".rejected.");
  const quarantine = queue!.replace(".items.", ".quarantine.");
  const raw = JSON.stringify({ v: 1, items: [item, null] });
  await storage.setItem(rejected, raw);
  return { queue: queue!, rejected, quarantine, raw, item };
}

it("keeps the healthy Settings rejected-count recovery ciphertext authenticated and recoverable", async () => {
  const { rejected, quarantine, raw, item } = await malformedRejected();
  expect(await rejectedEntryCount(owner)).toBe(1);
  expect(JSON.parse((await storage.getItem(rejected))!).items).toEqual([item]);
  expect(JSON.parse((await storage.getItem(quarantine))!).records).toEqual([raw]);
  expect(decrypt(key, Buffer.from(item.blobB64, "base64"), buildAad("entry", owner, entryId, "1")).toString()).toBe(privateText);
  await clearQueue(owner);
  expect(await storage.getItem(quarantine)).toBeNull();
});

it("a completed public queue erasure cannot be followed by the older Settings recovery ciphertext write", async () => {
  const { queue, rejected, quarantine, raw } = await malformedRejected();
  const write = storage.setItem;
  let entered!: () => void;
  let release!: () => void;
  const reached = new Promise<void>(resolve => { entered = resolve; });
  const held = new Promise<void>(resolve => { release = resolve; });
  const events: string[] = [];
  let admitted = 0;
  const observer = vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    if (slot === quarantine) {
      admitted += 1;
      expect(JSON.parse(value).records).toEqual([raw]);
      events.push("write admitted before physical completion");
      entered();
      await held;
      await write(slot, value);
      events.push("physical ciphertext write completed");
      return;
    }
    return write(slot, value);
  });
  let reading: Promise<number> | undefined;
  let wiping: Promise<void> | undefined;
  let fallback: ReturnType<typeof setTimeout> | undefined;
  try {
    reading = rejectedEntryCount(owner);
    await Promise.race([reached, reading.then(() => { throw new Error("Settings recovery did not admit its native quarantine write"); })]);
    expect(await storage.getItem(quarantine)).toBeNull();
    expect(admitted).toBe(1);
    wiping = clearQueue(owner);
    const erasureReceipt = wiping.then(() => {
      events.push("public erasure completed");
      release();
    });
    // The original erasure receipt releases the old write. A serialized
    // erasure correctly waits, so this finite native receipt gate releases
    // its earlier write without replacing the public erasure implementation.
    fallback = setTimeout(release, 100);
    const [count] = await Promise.all([reading, erasureReceipt]);
    expect(count).toBe(1);
    expect(events.filter(event => event === "physical ciphertext write completed")).toHaveLength(1);
    expect(await storage.getItem(queue)).toBeNull();
    expect(await storage.getItem(rejected)).toBeNull();
    const resurrected = await storage.getItem(quarantine) !== null;
    console.info("OFFLINE_QUEUE_ERASURE_CUSTODY", JSON.stringify({ events, admitted, resurrected }));
    expect(resurrected, "completed queue erasure must retain no older Settings recovery ciphertext").toBe(false);
  } finally {
    release();
    if (fallback !== undefined) clearTimeout(fallback);
    const settled = await Promise.allSettled([...(reading ? [reading] : []), ...(wiping ? [wiping] : [])]);
    observer.mockRestore();
    const failure = settled.find(result => result.status === "rejected");
    if (failure?.status === "rejected") throw failure.reason;
  }
});
