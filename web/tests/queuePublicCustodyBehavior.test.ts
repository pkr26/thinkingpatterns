import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError, clearSession } from "../src/api/client";
import { abortInFlightFlush, clearQueue, drainPendingQueueForRotation, enqueue, flushQueue, flushQueueOnReconnect, isFutureDateRejection, queueEvictionSummary, queueLength, rejectedEntries, requeueRejected, rewrapQueue, QueueAbandonedError, QueueFullError, type QueuedEntry } from "../src/offlineQueue";
import { setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { encryptEntry, decryptEntry } from "../src/crypto/patient";
import { displayError } from "../src/errors";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const owner = "queue-public-custody";
const item = (id: string, extra: Partial<QueuedEntry> = {}): QueuedEntry => ({ userId: owner, clientEntryId: id, blobB64: "opaque ciphertext", entryDate: "2026-10-07", ...extra });
let physical: Map<string, string>;
type DeviceEvent = (kind: "read" | "write" | "remove", key: string) => void | Promise<void>;
let onDeviceEvent: DeviceEvent | undefined;
beforeEach(() => {
  resetTestState(); installSession(owner); physical = new Map(); onDeviceEvent = undefined;
  // Public storage backend boundary. A device operation first takes custody
  // of its value, then returns the independently controlled JS receipt.
  setKvBackendForTests({
    async getItem(key) { const value = physical.get(key) ?? null; await onDeviceEvent?.("read", key); return value; },
    async setItem(key, value) { physical.set(key, value); await onDeviceEvent?.("write", key); },
    async removeItem(key) { physical.delete(key); await onDeviceEvent?.("remove", key); },
    async keys() { return [...physical.keys()]; },
  });
});
afterEach(() => { onDeviceEvent = undefined; abortInFlightFlush(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); setKvBackendForTests(null); });
async function slots() {
  await enqueue(item("seed"));
  const queue = [...physical.keys()].find(k => k.startsWith("mindpattern/queue.v1.items."))!;
  return { queue, rejected: queue.replace(".items.", ".rejected."), quarantine: queue.replace(".items.", ".quarantine."), evictions: queue.replace(".items.", ".evictions.") };
}

it("bounds an oversized rejection drawer by count and reports its lost oldest ciphertext", async () => {
  const { rejected } = await slots(), rows = Array.from({ length: 201 }, (_, i) => item(`old-${i}`));
  physical.set(rejected, JSON.stringify({ v: 1, items: rows }));
  expect(await rejectedEntries()).toEqual(rows.slice(1));
  expect(await queueEvictionSummary()).toEqual({ rejected: 1, quarantine: 0 });
});
it.each([false, true])("preserves both prior loss counters when an appended rejection exceeds byte capacity: exact=%s", async exact => {
  const { queue, rejected, evictions } = await slots();
  const old = item("old"), newest = item("new", { blobB64: "new ciphertext" });
  const overhead = new TextEncoder().encode(JSON.stringify({ v: 1, items: [old, newest] })).length;
  old.blobB64 += "A".repeat(1_000_000 - overhead + (exact ? 0 : 1));
  physical.set(queue, JSON.stringify({ v: 1, items: [newest] }));
  physical.set(rejected, JSON.stringify({ v: 1, items: [old] }));
  physical.set(evictions, JSON.stringify({ rejected: 2, quarantine: 3 }));
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "invalid entry"));
  await flushQueue(owner);
  expect(await rejectedEntries()).toEqual(exact ? [old, newest] : [newest]);
  expect(await queueEvictionSummary()).toEqual({ rejected: exact ? 2 : 3, quarantine: 3 });
});
it("moves an exact one-megabyte rejected record without inventing a new quarantine record", async () => {
  const { queue, rejected, quarantine } = await slots(); physical.delete(queue);
  const retained = item("maximum");
  const overhead = new TextEncoder().encode(JSON.stringify({ v: 1, items: [retained] })).length;
  retained.blobB64 += "A".repeat(1_000_000 - overhead);
  physical.set(rejected, JSON.stringify({ v: 1, items: [retained] }));
  expect(await requeueRejected()).toBe(1);
  expect(JSON.parse(physical.get(queue)!).items).toEqual([retained]);
  expect(physical.has(rejected)).toBe(false);
  expect(await rejectedEntries()).toEqual([]); expect(physical.has(quarantine)).toBe(false);
});
it("exposes the byte-capacity refusal while preserving the retained ciphertext", async () => {
  const { queue } = await slots(), before = physical.get(queue);
  try { await enqueue(item("too-large", { blobB64: "A".repeat(1_000_001) })); throw new Error("expected refusal"); }
  catch (error) { expect(error).toBeInstanceOf(QueueFullError); expect(displayError(error, "retry")).toBe("offline queue is full (over 1 MB of pending entries) — sync before writing more"); }
  expect(physical.get(queue)).toBe(before);
});
it.each([new ApiError(422, "entry_date is in the future", "validation_error"), new ApiError(409, "conflict")])
  ("backs off a retryable public rejection rather than immediately reposting the ciphertext: %#", async failure => {
    vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000);
    await enqueue(item("retry")); const post = vi.spyOn(api, "createEntry").mockRejectedValue(failure);
    vi.spyOn(api, "getEntry").mockRejectedValue(new ApiError(503, "verification unavailable"));
    expect(await flushQueue(owner)).toBe(0); expect(await flushQueue(owner)).toBe(0);
    expect(post).toHaveBeenCalledTimes(1); expect(await queueLength()).toBe(1);
  });
it("increments existing expiry attempts and retains the complete public recovery metadata", async () => {
  const { queue } = await slots(); physical.set(queue, JSON.stringify({ v: 1, items: [item("expired", { attempts: 4 })] }));
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000);
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(401, "expired"));
  await expect(flushQueue(owner)).rejects.toThrow("session expired mid-flush");
  expect(JSON.parse(physical.get(queue)!).items).toEqual([item("expired", { attempts: 5, notBefore: 1_900_000 })]);
});
it("classifies a future validation error only under the supported validation code", () => {
  expect(isFutureDateRejection(new ApiError(422, "future date", "different_code"))).toBe(false);
  expect(isFutureDateRejection(new ApiError(422, "future date"))).toBe(true);
});

it.each(["malformed", "foreign", "unparseable"])("retains the original queue after retirement at the physical quarantine write: %s", async shape => {
  const { queue, quarantine } = await slots();
  const raw = shape === "malformed" ? JSON.stringify({ v: 1, items: [item("kept"), { opaque: "corrupt but retained" }] })
    : shape === "foreign" ? JSON.stringify({ v: 1, items: [item("kept"), item("foreign", { userId: "another-owner" })] }) : "unparseable ciphertext";
  physical.set(queue, raw);
  onDeviceEvent = (event, key) => { if (event === "write" && key === quarantine) abortInFlightFlush(); };
  await queueLength(); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(raw); expect(physical.has(quarantine)).toBe(true);
});
it.each(["read", "write"] as const)("preserves the rejected ciphertext when requeue retires at its physical %s receipt", async phase => {
  const { queue, rejected } = await slots(); physical.delete(queue);
  const raw = JSON.stringify({ v: 1, items: [item("retained")] }); physical.set(rejected, raw);
  onDeviceEvent = (event, key) => { if (event === phase && key === (phase === "read" ? rejected : queue)) abortInFlightFlush(); };
  expect(await requeueRejected()).toBe(0); onDeviceEvent = undefined;
  expect(physical.get(rejected)).toBe(raw);
});
it("does not discard a newly rejected entry after retirement during the physical rejected-store read", async () => {
  const { queue, rejected } = await slots(), before = physical.get(queue);
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "refused"));
  onDeviceEvent = (event, key) => { if (event === "read" && key === rejected) clearSession(); };
  expect(await flushQueue(owner)).toBe(0); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(before); expect(physical.has(rejected)).toBe(false);
});
it("erases every physical AAD buffer after successful browser crypto rewrap", async () => {
  const oldKey = new Uint8Array(new ArrayBuffer(32)).fill(71), newKey = new Uint8Array(new ArrayBuffer(32)).fill(73);
  const payload = await encryptEntry(oldKey, owner, "private", "private writing", "2026-10-07", 0, undefined, 1);
  await enqueue(item("private", { blobB64: payload.blobB64 }));
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle), bindings: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const aad = (args[0] as AesGcmParams).additionalData!;
    bindings.push(ArrayBuffer.isView(aad) ? new Uint8Array(aad.buffer, aad.byteOffset, aad.byteLength) : new Uint8Array(aad));
    return decrypt(...args);
  });
  await rewrapQueue(owner, oldKey, newKey);
  expect(bindings.length).toBeGreaterThan(0);
  for (const retainedPhysicalBuffer of bindings) expect(retainedPhysicalBuffer).toEqual(new Uint8Array(retainedPhysicalBuffer.length));
  vi.restoreAllMocks(); const queue = [...physical.keys()].find(k => k.startsWith("mindpattern/queue.v1.items."))!;
  const retained = JSON.parse(physical.get(queue)!).items[0];
  expect((await decryptEntry(newKey, owner, "private", retained.blobB64, 1)).text).toBe("private writing");
});

async function settlesBeforeUnfinishedDeviceReceipt(work: Promise<unknown>, release: () => void) {
  // The oracle is completion of the exported operation with one independent
  // storage receipt still pending. The finite deadline is a witness, not a
  // storage/product SLA, and every pending device operation is released.
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const outcome = await Promise.race([
      work.then(() => "settled", () => "settled"),
      new Promise<string>(resolve => { timer = setTimeout(() => resolve("waiting for unrelated device IO"), 100); }),
    ]);
    expect(outcome).toBe("settled");
  } finally { if (timer !== undefined) clearTimeout(timer); release(); await work.catch(() => {}); }
}
it("returns a retired repair without acquiring an unfinished quarantine read", async () => {
  const { queue, quarantine } = await slots(), raw = "unparseable retained ciphertext"; physical.set(queue, raw);
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; });
  onDeviceEvent = (event, key) => {
    if (event === "read" && key === queue) abortInFlightFlush();
    if (event === "read" && key === quarantine) return receipt;
  };
  await settlesBeforeUnfinishedDeviceReceipt(queueLength(), release); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(raw); expect(physical.has(quarantine)).toBe(false);
});
it("does not acquire loss-counter storage when its evidence drawer lost no records", async () => {
  const { queue, quarantine, evictions } = await slots(); physical.set(queue, "corrupt ciphertext");
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; });
  onDeviceEvent = (event, key) => { if (event === "read" && key === evictions) return receipt; };
  await settlesBeforeUnfinishedDeviceReceipt(queueLength(), release); onDeviceEvent = undefined;
  expect(JSON.parse(physical.get(quarantine)!).records).toEqual(["corrupt ciphertext"]); expect(physical.has(evictions)).toBe(false);
});
it("does not acquire loss-counter storage after retirement at an oversized evidence write", async () => {
  const { queue, quarantine, evictions } = await slots(); const raw = "!".repeat(34_000); physical.set(queue, raw);
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; });
  onDeviceEvent = (event, key) => {
    if (event === "write" && key === quarantine) abortInFlightFlush();
    if (event === "read" && key === evictions) return receipt;
  };
  await settlesBeforeUnfinishedDeviceReceipt(queueLength(), release); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(raw); expect(physical.has(evictions)).toBe(false);
});
it("retains the evidence drawer after retirement at its device read", async () => {
  const { queue, quarantine } = await slots(), raw = "corrupt ciphertext"; physical.set(queue, raw);
  onDeviceEvent = (event, key) => { if (event === "read" && key === quarantine) abortInFlightFlush(); };
  await queueLength(); onDeviceEvent = undefined;
  expect(physical.has(quarantine)).toBe(false); expect(physical.get(queue)).toBe(raw);
});
it("retains prior loss counters after retirement at their device read", async () => {
  const { rejected, evictions } = await slots(), prior = JSON.stringify({ rejected: 2, quarantine: 3 });
  physical.set(evictions, prior); physical.set(rejected, JSON.stringify({ v: 1, items: Array.from({ length: 201 }, (_, i) => item(`old-${i}`)) }));
  onDeviceEvent = (event, key) => { if (event === "read" && key === evictions) abortInFlightFlush(); };
  await rejectedEntries(); onDeviceEvent = undefined;
  expect(physical.get(evictions)).toBe(prior);
});
it("keeps a refused upload out of the rejection drawer after retirement at the loss-counter receipt", async () => {
  const { queue, rejected, evictions } = await slots(), old = Array.from({ length: 200 }, (_, i) => item(`old-${i}`));
  physical.set(rejected, JSON.stringify({ v: 1, items: old })); const before = physical.get(rejected);
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "refused"));
  onDeviceEvent = (event, key) => { if (event === "write" && key === evictions) clearSession(); };
  expect(await flushQueue(owner)).toBe(0); onDeviceEvent = undefined;
  expect(physical.get(rejected)).toBe(before); expect(JSON.parse(physical.get(queue)!).items).toEqual([item("seed")]);
});
it("refuses a retired producer before it acquires an unfinished queue read", async () => {
  const { queue } = await slots(), before = physical.get(queue);
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; });
  onDeviceEvent = (event, key) => {
    if (event === "read" && key === writeGenerationKey(owner)) abortInFlightFlush();
    if (event === "read" && key === queue) return receipt;
  };
  const work = enqueue(item("retired"));
  await settlesBeforeUnfinishedDeviceReceipt(work, release); await expect(work).rejects.toThrow("queue was cleared"); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(before);
});
it.each(["crypto", "queue-commit"])("retains rejected ciphertext after rotation retirement at its %s receipt", async phase => {
  const { queue, rejected } = await slots(), oldKey = new Uint8Array(new ArrayBuffer(32)).fill(81), newKey = new Uint8Array(new ArrayBuffer(32)).fill(83);
  const payload = await encryptEntry(oldKey, owner, "rotating", "retained private writing", "2026-10-07", 0, undefined, 1);
  const raw = JSON.stringify({ v: 1, items: [item("rotating", { blobB64: payload.blobB64 })] }); physical.set(queue, raw); physical.set(rejected, raw);
  if (phase === "crypto") {
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const encrypted = await encrypt(...args); abortInFlightFlush(); return encrypted; });
  } else onDeviceEvent = (event, key) => { if (event === "write" && key === queue) abortInFlightFlush(); };
  await rewrapQueue(owner, oldKey, newKey); onDeviceEvent = undefined;
  expect(physical.get(rejected)).toBe(raw);
  if (phase === "crypto") expect(physical.get(queue)).toBe(raw);
});
it.each([null, { quarantine: -1 }, { quarantine: 1.5 }, { quarantine: "3" }, { quarantine: Number.MAX_SAFE_INTEGER + 1 }, { quarantine: 3 }])
  ("sanitizes earlier quarantine loss metadata when new evidence must be truncated: %j", async prior => {
    const { queue, evictions } = await slots(); physical.set(evictions, JSON.stringify(prior)); physical.set(queue, "!".repeat(34_000));
    await queueLength(); expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: prior?.quarantine === 3 ? 4 : 1 });
  });
it("parks a future-looking 400 rejection rather than applying the 422 clock repair policy", async () => {
  await enqueue(item("invalid")); vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "future invalid data", "validation_error"));
  expect(await flushQueue(owner)).toBe(0); expect(await queueLength()).toBe(0); expect(await rejectedEntries()).toEqual([item("invalid")]);
});
it("reports retirement before a stale producer's full-queue capacity refusal", async () => {
  const { queue } = await slots(); const full = Array.from({ length: 200 }, (_, i) => item(`full-${i}`)); physical.set(queue, JSON.stringify({ v: 1, items: full }));
  onDeviceEvent = (event, key) => { if (event === "read" && key === queue) abortInFlightFlush(); };
  await expect(enqueue(item("retired"))).rejects.toBeInstanceOf(QueueAbandonedError); onDeviceEvent = undefined;
  expect(JSON.parse(physical.get(queue)!).items).toEqual(full);
});
it("keeps an old exported drain retired after both public abort and clear transitions", async () => {
  await enqueue(item("old")); let received!: () => void, release!: () => void;
  const dispatched = new Promise<void>(resolve => { received = resolve; }), receipt = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(api, "createEntry").mockImplementation(async () => { received(); await receipt; return { id: "accepted-old" }; });
  const work = flushQueue(owner); await dispatched;
  abortInFlightFlush(); await clearQueue(owner); await enqueue(item("new")); release();
  expect(await work).toBe(0); const queue = [...physical.keys()].find(k => k.startsWith("mindpattern/queue.v1.items."))!;
  expect(JSON.parse(physical.get(queue)!).items).toEqual([item("new")]);
});
it("returns an empty recovery drawer without acquiring unfinished empty-queue deletion", async () => {
  const { queue } = await slots(); physical.delete(queue);
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; });
  onDeviceEvent = (event, key) => { if (event === "remove" && key === queue) return receipt; };
  await settlesBeforeUnfinishedDeviceReceipt(requeueRejected(), release); onDeviceEvent = undefined;
});
it.each(["before-scope", "after-scope"])("refuses a retired drain before new physical storage IO: %s", async phase => {
  const { queue } = await slots(); if (phase === "before-scope") clearSession();
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; });
  onDeviceEvent = (event, key) => {
    if (event !== "read") return;
    if (phase === "before-scope" && key === writeGenerationKey(owner)) return receipt;
    if (phase === "after-scope" && key === writeGenerationKey(owner)) clearSession();
    if (phase === "after-scope" && key === queue) return receipt;
  };
  const work = flushQueue(owner); await settlesBeforeUnfinishedDeviceReceipt(work, release); expect(await work).toBe(0); onDeviceEvent = undefined;
});
it("resolves a retired expired drain quietly after its physical commit reread", async () => {
  const { queue } = await slots(), before = physical.get(queue); let serverRefused = false;
  vi.spyOn(api, "createEntry").mockImplementation(async () => { serverRefused = true; throw new ApiError(401, "expired"); });
  onDeviceEvent = (event, key) => { if (event === "read" && key === queue && serverRefused) clearSession(); };
  expect(await flushQueue(owner)).toBe(0); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(before);
});
it("resolves a retired expired drain quietly when its commit was queued behind an independent storage reader", async () => {
  const { queue } = await slots(), before = physical.get(queue);
  let posted!: () => void, releaseServer!: () => void, read!: () => void, releaseRead!: () => void;
  const dispatched = new Promise<void>(resolve => { posted = resolve; }), serverReceipt = new Promise<void>(resolve => { releaseServer = resolve; });
  const reading = new Promise<void>(resolve => { read = resolve; }), readReceipt = new Promise<void>(resolve => { releaseRead = resolve; });
  vi.spyOn(api, "createEntry").mockImplementation(async () => { posted(); await serverReceipt; throw new ApiError(401, "expired"); });
  const work = flushQueue(owner); await dispatched;
  onDeviceEvent = (event, key) => { if (event === "read" && key === queue) { read(); return readReceipt; } };
  const reader = queueLength(); await reading; releaseServer();
  // A browser task arrives after the already-delivered HTTP courier's
  // microtask checkpoint. No mutation IDs or counted microtasks are used.
  await new Promise<void>(resolve => { setTimeout(() => { clearSession(); onDeviceEvent = undefined; releaseRead(); resolve(); }, 0); });
  await reader; expect(await work).toBe(0); expect(physical.get(queue)).toBe(before);
});
it("resolves a retired expired drain quietly after an earlier rejection's loss-counter receipt", async () => {
  const { queue, rejected, evictions } = await slots();
  const batch = [item("refused"), item("expired")]; physical.set(queue, JSON.stringify({ v: 1, items: batch }));
  physical.set(rejected, JSON.stringify({ v: 1, items: Array.from({ length: 200 }, (_, i) => item(`old-${i}`)) })); const before = physical.get(queue);
  vi.spyOn(api, "createEntry").mockImplementation(async id => { throw new ApiError(id === "refused" ? 400 : 401, "refused"); });
  onDeviceEvent = (event, key) => { if (event === "write" && key === evictions) clearSession(); };
  expect(await flushQueue(owner)).toBe(0); onDeviceEvent = undefined; expect(physical.get(queue)).toBe(before);
});
it("removes the oldest evidence from an overflowing count drawer in a finite repair", async () => {
  const { queue, quarantine } = await slots(), earlier = Array.from({ length: 50 }, (_, i) => `old evidence ${i}`);
  physical.set(quarantine, JSON.stringify({ v: 1, records: earlier })); physical.set(queue, "new corrupt ciphertext");
  await queueLength(); expect(JSON.parse(physical.get(quarantine)!).records).toEqual([...earlier.slice(1), "new corrupt ciphertext"]);
  expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 1 });
});
it("removes the oldest evidence from an overflowing byte drawer in a finite repair", async () => {
  const { queue, quarantine } = await slots(), earlier = Array.from({ length: 8 }, (_, i) => String(i).repeat(31_800));
  physical.set(quarantine, JSON.stringify({ v: 1, records: earlier })); physical.set(queue, "new corrupt ciphertext");
  await queueLength(); expect(JSON.parse(physical.get(quarantine)!).records).toEqual([...earlier.slice(1), "new corrupt ciphertext"]);
  expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 1 });
});
it("removes an overflowing rejected ciphertext value in a finite byte repair", async () => {
  const { rejected } = await slots(); physical.set(rejected, JSON.stringify({ v: 1, items: [item("too-large", { blobB64: "A".repeat(1_000_001) })] }));
  expect(await rejectedEntries()).toEqual([]); expect(physical.has(rejected)).toBe(false);
  expect(await queueEvictionSummary()).toEqual({ rejected: 1, quarantine: 0 });
});
it.each(["count", "bytes"])("reports actual eviction immediately after appending an overflowing rejection: %s", async kind => {
  const { queue, rejected } = await slots();
  const newest = item("new", { blobB64: "B".repeat(500) }), oldest = item("large");
  const overhead = new TextEncoder().encode(JSON.stringify({ v: 1, items: [oldest, newest] })).length;
  oldest.blobB64 += "A".repeat(1_000_001 - overhead);
  const rows = kind === "count" ? Array.from({ length: 200 }, (_, i) => item(`old-${i}`)) : [oldest];
  physical.set(rejected, JSON.stringify({ v: 1, items: rows })); physical.set(queue, JSON.stringify({ v: 1, items: [newest] }));
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "refused")); await flushQueue(owner);
  expect(await queueEvictionSummary()).toEqual({ rejected: 1, quarantine: 0 });
  expect(JSON.parse(physical.get(rejected)!).items).toHaveLength(kind === "count" ? 200 : 1);
});
it.each(["malformed", "foreign", "unparseable"])("physically repairs recovered ciphertext exactly once: %s", async shape => {
  const { queue, quarantine } = await slots(), retained = item("kept");
  const raw = shape === "malformed" ? JSON.stringify({ v: 1, items: [retained, { opaque: "broken" }] })
    : shape === "foreign" ? JSON.stringify({ v: 1, items: [retained, item("foreign", { userId: "another-owner" })] }) : "{ corrupt ciphertext";
  physical.set(queue, raw); expect(await queueLength()).toBe(shape === "unparseable" ? 0 : 1);
  if (shape === "unparseable") expect(physical.has(queue)).toBe(false);
  else expect(JSON.parse(physical.get(queue)!).items).toEqual([retained]);
  const evidence = physical.get(quarantine); await queueLength(); expect(physical.get(quarantine)).toBe(evidence);
});
it("retains an unrecognized envelope when its quarantine write finishes after retirement", async () => {
  const { queue, quarantine } = await slots(), raw = '{"v":2,"items":[]}'; physical.set(queue, raw);
  onDeviceEvent = (event, key) => { if (event === "write" && key === quarantine) abortInFlightFlush(); };
  expect(await queueLength()).toBe(0); onDeviceEvent = undefined; expect(physical.get(queue)).toBe(raw);
});
it("drains an accepted queued upload before reporting the rotation's remaining count", async () => {
  await enqueue(item("accepted")); stubFetch(() => jsonResponse({ id: "server-accepted" }));
  expect(await drainPendingQueueForRotation(owner)).toBe(0); expect(await queueLength()).toBe(0);
});
it("returns an empty reconnect without requesting a second lock held by a competing document", async () => {
  const { queue } = await slots(); physical.delete(queue); vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(7_000_000_000);
  let release!: () => void; const receipt = new Promise<void>(resolve => { release = resolve; }); let sibling: Promise<unknown> | undefined;
  onDeviceEvent = (event, key) => {
    if (event === "read" && key === queue && sibling === undefined) sibling = navigator.locks.request("queue-flush", async () => { await receipt; });
  };
  await settlesBeforeUnfinishedDeviceReceipt(flushQueueOnReconnect(), release); onDeviceEvent = undefined; await sibling;
});
it("propagates a reconnect preflight's real device-read failure", async () => {
  await slots(); vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(8_000_000_000);
  onDeviceEvent = event => { if (event === "read") throw new Error("device storage unavailable"); };
  await expect(flushQueueOnReconnect()).rejects.toThrow("Local encrypted records could not be read");
});
it("does not admit a needless commit after the storage device becomes unavailable at a completed batch read", async () => {
  const { queue } = await slots(); physical.set(queue, JSON.stringify({ v: 1, items: [item("waiting", { notBefore: Date.now() + 3_600_000 })] }));
  let storageUnavailable = false;
  onDeviceEvent = (event, key) => {
    if (event !== "read") return;
    if (storageUnavailable) throw new Error("the storage device is unavailable");
    // This read already captured its physical value. The availability
    // event refuses every subsequently issued read, regardless of key.
    if (key === queue) storageUnavailable = true;
  };
  expect(await flushQueue(owner)).toBe(0);
});
it("does not acquire new device IO when an old drain retires behind an already-completed reader", async () => {
  const { queue } = await slots();
  let posted!: () => void, releaseServer!: () => void, read!: () => void, releaseRead!: () => void;
  const dispatched = new Promise<void>(resolve => { posted = resolve; }), serverReceipt = new Promise<void>(resolve => { releaseServer = resolve; });
  const reading = new Promise<void>(resolve => { read = resolve; }), readReceipt = new Promise<void>(resolve => { releaseRead = resolve; });
  vi.spyOn(api, "createEntry").mockImplementation(async () => { posted(); await serverReceipt; throw new ApiError(401, "expired"); });
  const work = flushQueue(owner); await dispatched; let storageUnavailable = false;
  onDeviceEvent = async (event, key) => {
    if (event !== "read") return;
    if (storageUnavailable) throw new Error("the storage device is unavailable");
    if (key === queue) { read(); await readReceipt; }
  };
  const reader = queueLength(); await reading; releaseServer();
  await new Promise<void>(resolve => { setTimeout(() => { clearSession(); storageUnavailable = true; releaseRead(); resolve(); }, 0); });
  await reader; expect(await work).toBe(0);
});
it("does not report phantom rejected-ciphertext loss after owner retirement at the drawer read", async () => {
  const { queue, rejected } = await slots(), old = Array.from({ length: 200 }, (_, i) => item(`old-${i}`));
  physical.set(rejected, JSON.stringify({ v: 1, items: old })); const before = physical.get(queue);
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "refused"));
  onDeviceEvent = (event, key) => { if (event === "read" && key === rejected) clearSession(); };
  expect(await flushQueue(owner)).toBe(0); onDeviceEvent = undefined;
  expect(physical.get(queue)).toBe(before); expect(await rejectedEntries(owner)).toEqual(old);
  expect(await queueEvictionSummary(owner)).toEqual({ rejected: 0, quarantine: 0 });
});
