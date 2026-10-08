import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv, createDecipheriv } from "node:crypto";
import storage from "./helpers/storageMock";
import { engine } from "./helpers/nodeEngine";
import { api, ApiError, OriginPinnedError } from "../src/api/client";
import * as client from "../src/api/client";
import { changeLocalSessionOwner } from "../src/localWriteGuard";
import { abortInFlightFlush, enqueue, flushQueue, flushQueueOnReconnect, pendingEntryIds, prepareQueueRekey, queueLength, quarantinedQueueExists, rejectedEntries, requeueRejected, rewrapQueue, type QueuedEntry } from "../src/offlineQueue";
const owner = "11111111111111111111111111111111", oldKey = Buffer.alloc(32, 21), newKey = Buffer.alloc(32, 22), plaintext = "private writing retained for rotation";
function record(id: string, blobB64 = "opaque retained writing"): QueuedEntry { return { userId: owner, clientEntryId: id, blobB64, entryDate: "2026-10-05" }; }
function aad(id: string, versioned: boolean) { return Buffer.from(JSON.stringify(versioned ? ["entry", owner, id, "1"] : ["entry", owner, id])); }
function seal(id: string, versioned = true, key = oldKey) { const nonce = Buffer.alloc(12, 4), cipher = createCipheriv("aes-256-gcm", key, nonce); cipher.setAAD(aad(id, versioned)); return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]).toString("base64"); }
function open(blobB64: string, id: string, versioned = true) { const blob = Buffer.from(blobB64, "base64"), decipher = createDecipheriv("aes-256-gcm", newKey, blob.subarray(0, 12)); decipher.setAuthTag(blob.subarray(-16)); decipher.setAAD(aad(id, versioned)); return Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]).toString(); }
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); abortInFlightFlush(); vi.spyOn(api, "getUserId").mockResolvedValue(owner); });
afterEach(() => { vi.restoreAllMocks(); abortInFlightFlush(); vi.useRealTimers(); });
async function nativeSlots() { await enqueue(record("locator")); const queue = (await storage.getAllKeys()).find(k => k.startsWith("@mindpattern/queue.v2.items."))!; await storage.removeItem(queue); return { queue, rejected: queue.replace(".items.", ".rejected.") }; }

it.each([true, false])("prepares retained %s-bound writing without publishing until durable commit", async versioned => {
  const { queue, rejected } = await nativeSlots(), queued = record("queued", seal("queued", versioned)), parked = record("parked", seal("parked", versioned));
  const originals = new Map([[queue, JSON.stringify({ v: 1, items: [queued] })], [rejected, JSON.stringify({ v: 1, items: [parked] })]]);
  for (const [slot, raw] of originals) await storage.setItem(slot, raw);
  const changes = await prepareQueueRekey(owner, oldKey, newKey); expect(changes.length).toBe(2);
  for (const change of changes) { expect(change.before).toBe(originals.get(change.key)); expect(await storage.getItem(change.key)).toBe(change.before); await storage.setItem(change.key, change.after); }
  expect(await pendingEntryIds(owner)).toEqual(["queued", "parked"]);
  expect(await quarantinedQueueExists(owner)).toBe(false);
  const held = await rejectedEntries(owner); expect(held).toHaveLength(1); expect(open(held[0]!.blobB64, "parked", versioned)).toBe(plaintext);
  let uploaded: QueuedEntry | undefined;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async (id, blobB64, date) => { if (uploaded) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); uploaded = record(id, blobB64); uploaded.entryDate = date; return {} as never; });
  expect(await flushQueue(owner)).toBe(1); expect(uploaded).toMatchObject({ ...queued, blobB64: expect.any(String) }); expect(open(uploaded!.blobB64, "queued", versioned)).toBe(plaintext);
});
it.each(["null", "{}", '{"v":1,"items":{}}', '{"v":1,"items":[null]}'])("refuses rotation of malformed retained records and preserves native bytes: %s", async raw => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, raw);
  await expect(prepareQueueRekey(owner, oldKey, newKey)).rejects.toThrow("Retained entries require repair before rotation"); expect(await storage.getItem(queue)).toBe(raw);
});
it.each(["wrong-key", "corrupt"])("refuses unauthenticated %s retained writing before retiring its usable old key", async kind => {
  const { rejected } = await nativeSlots(), raw = JSON.stringify([record("parked", kind === "corrupt" ? "truncated ciphertext" : seal("parked", true, newKey))]); await storage.setItem(rejected, raw);
  await expect(prepareQueueRekey(owner, oldKey, newKey)).rejects.toThrow("A retained entry did not authenticate before rotation"); expect(await storage.getItem(rejected)).toBe(raw);
});
it("prepares an empty installation without fabricating retained changes", async () => { expect(await prepareQueueRekey(owner, oldKey, newKey)).toEqual([]); });
it("best-effort rewrap preserves unopenable ciphertext and re-seals both queue and rejected records", async () => {
  const { queue, rejected } = await nativeSlots(), bad = record("bad", "unopenable retained ciphertext");
  await storage.setItem(queue, JSON.stringify([record("queue", seal("queue")), bad])); await storage.setItem(rejected, JSON.stringify([record("legacy", seal("legacy", false))]));
  await rewrapQueue(owner, oldKey, newKey); const items = JSON.parse((await storage.getItem(queue))!).items as QueuedEntry[];
  expect(items).toHaveLength(2); expect(items[1]).toEqual(bad); expect(open(items[0]!.blobB64, "queue")).toBe(plaintext); const parked = await rejectedEntries(owner); expect(open(parked[0]!.blobB64, "legacy", false)).toBe(plaintext);
});
it.each([false, true])("erases actual provider-held rewrap plaintext and AAD after native write failure=%s", async fail => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([record("custody", seal("custody"))]));
  const held: Buffer[] = [], bindings: Buffer[] = [], create = engine.createCipheriv.bind(engine);
  vi.spyOn(engine, "createCipheriv").mockImplementation((algorithm, key, nonce) => {
    const cipher = create(algorithm, key, nonce), update = cipher.update.bind(cipher), set = cipher.setAAD.bind(cipher);
    vi.spyOn(cipher, "update").mockImplementation((value: Buffer) => { held.push(value); return update(value); });
    vi.spyOn(cipher, "setAAD").mockImplementation((value: Buffer) => { bindings.push(value); return set(value); }); return cipher;
  });
  if (fail) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native rewrap commit failed"));
  const operation = rewrapQueue(owner, oldKey, newKey); if (fail) await expect(operation).rejects.toThrow("Native rewrap commit failed"); else await operation;
  expect(held.length).toBeGreaterThan(0); expect(bindings.length).toBeGreaterThan(0); for (const value of [...held, ...bindings]) expect(value.every(byte => byte === 0)).toBe(true);
});
it("acknowledges one upload without repeating its accepted payload after native removal", async () => {
  await enqueue(record("accepted")); let sent = false;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (sent) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); sent = true; return {} as never; });
  await expect(flushQueue(owner)).resolves.toBe(1); expect(await queueLength(owner)).toBe(0);
});
it("flushes a reconnected account once per ten-second interval and only while writing exists", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(4_000_000_000_000); let requests = 0;
  const post = vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (++requests > 2) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); return {} as never; });
  await enqueue(record("first")); await flushQueueOnReconnect(); expect(await queueLength(owner)).toBe(0); expect(post).toHaveBeenCalledTimes(1);
  await enqueue(record("second")); vi.setSystemTime(4_000_000_009_999); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(1); expect(await queueLength(owner)).toBe(1);
  vi.setSystemTime(4_000_000_010_000); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(2); expect(await queueLength(owner)).toBe(0);
  vi.setSystemTime(4_000_000_020_000); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(2);
});
it("keeps no-account reconnect silent when native queue storage is unavailable", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(5_000_000_000_000); vi.spyOn(api, "getUserId").mockResolvedValue(null);
  vi.spyOn(storage, "getItem").mockRejectedValue(new Error("No account owns this native store")); await expect(flushQueueOnReconnect()).resolves.toBeUndefined();
});
it("reports an unavailable owned native queue before reconnect can upload retained writing", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(8_000_000_000_000);
  const { queue } = await nativeSlots(), read = storage.getItem;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === queue) throw new Error("Native retained queue is unavailable"); return read(slot); });
  const post = vi.spyOn(api, "createQueuedEntry");
  await expect(flushQueueOnReconnect()).rejects.toThrow("Native retained queue is unavailable");
  expect(post).not.toHaveBeenCalled();
});
it.each([true, false])("a failed duplicate verification stops this pass only for an origin refusal=%s", async pinned => {
  await enqueue(record("unverified")); await enqueue(record("later")); const posted: string[] = [];
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async id => { posted.push(id); if (posted.length > 3) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); if (id === "unverified") throw new ApiError(409, "conflict"); return {} as never; });
  vi.spyOn(api, "getEntry").mockRejectedValue(pinned ? new OriginPinnedError("https://queued.example", "https://replacement.example") : new Error("Native verification unavailable"));
  expect(await flushQueue(owner)).toBe(pinned ? 0 : 1); expect(posted).toEqual(pinned ? ["unverified"] : ["unverified", "later"]); expect(await queueLength(owner)).toBe(pinned ? 2 : 1);
});
it("uses the upper jitter half without retrying an accepted pause early", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); vi.spyOn(Math, "random").mockReturnValue(1); await enqueue(record("jitter"));
  let attempts = 0;
  const post = vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (++attempts > 2) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); throw new ApiError(503, "temporary"); }); await flushQueue(owner);
  vi.setSystemTime(1_029_999); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1); vi.setSystemTime(1_030_000); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2);
});
it("recovers from a failed legacy archive read on the next real queue operation", async () => {
  await storage.setItem("@mindpattern/queue", "historical opaque encrypted writing"); const read = storage.getItem; let failed = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === "@mindpattern/queue" && !failed) { failed = true; throw new Error("Temporary legacy backup read failure"); } return read(slot); });
  await expect(queueLength(owner)).rejects.toThrow("Temporary legacy backup read failure"); await expect(queueLength(owner)).resolves.toBe(0); expect(await storage.getItem("@mindpattern/queue")).toBeNull();
});
it("shares one pending legacy archive migration while native persistence becomes read-only after commit", async () => {
  await storage.setItem("@mindpattern/queue", "historical opaque encrypted writing"); const read = storage.getItem, write = storage.setItem; let entered!: () => void, release!: () => void, first = true, readOnly = false;
  const reached = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === "@mindpattern/queue" && first) { first = false; entered(); await gate; } return read(slot); });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (readOnly) throw new Error("Native backup archive became read-only"); await write(slot, value); if (slot === "@mindpattern/queue.legacy-unscoped.v1") readOnly = true; });
  const firstRead = queueLength(owner); await Promise.race([reached, firstRead.then(() => { throw Error("Legacy migration did not reach the installed backup"); })]); const secondRead = queueLength(owner); release();
  expect(await Promise.all([firstRead, secondRead])).toEqual([0, 0]); expect(await storage.getItem("@mindpattern/queue.legacy-unscoped.v1")).not.toBeNull();
});
it("resolves a transitional no-argument queue from the actual account and refuses absence", async () => {
  await enqueue(record("current-account")); expect(await queueLength()).toBe(1); expect(await rejectedEntries()).toEqual([]); vi.mocked(api.getUserId).mockResolvedValue(null); await expect(queueLength()).rejects.toThrow("without an account id");
});
it("parks a conflict whose single-entry verification proves the server has no writing", async () => {
  await enqueue(record("absent-conflict")); vi.spyOn(api, "createQueuedEntry").mockRejectedValue(new ApiError(409, "conflict")); vi.spyOn(api, "getEntry").mockRejectedValue(new ApiError(404, "no server writing"));
  expect(await flushQueue(owner)).toBe(0); expect(await queueLength(owner)).toBe(0); expect((await rejectedEntries(owner)).map(item => item.clientEntryId)).toEqual(["absent-conflict"]);
});
it("a duplicate-verification session expiry retains writing for reauthentication", async () => {
  await enqueue(record("expired-verification")); let requests = 0;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (++requests > 1) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); throw new ApiError(409, "verify conflict"); });
  vi.spyOn(api, "getEntry").mockRejectedValue(new ApiError(401, "verification needs login"));
  await expect(flushQueue(owner)).rejects.toMatchObject({ name: "SessionExpiredError" }); expect(await queueLength(owner)).toBe(1); expect(await rejectedEntries(owner)).toEqual([]);
});
it("accepts exactly one megabyte of serialized queued writing", async () => {
  const item = record("exact-byte-cap", ""), overhead = Buffer.byteLength(JSON.stringify({ v: 1, items: [item] })); item.blobB64 = "A".repeat(1_000_000 - overhead);
  await expect(enqueue(item)).resolves.toBeUndefined(); expect(await queueLength(owner)).toBe(1);
});
it.each([0, 1])("recovery honors the exact serialized one-megabyte boundary plus %s byte", async extra => {
  const { rejected } = await nativeSlots(), item = record("recovery-byte-cap", ""), overhead = Buffer.byteLength(JSON.stringify({ v: 1, items: [item] })); item.blobB64 = "A".repeat(1_000_000 - overhead + extra); await storage.setItem(rejected, JSON.stringify([item]));
  expect(await requeueRejected(owner)).toBe(extra === 0 ? 1 : 0); expect(await queueLength(owner)).toBe(extra === 0 ? 1 : 0); expect((await rejectedEntries(owner)).length).toBe(extra === 0 ? 0 : 1);
});
it("keeps both rejected records when their serialized drawer is exactly one megabyte", async () => {
  const { queue, rejected } = await nativeSlots(), existing = record("previous-rejection", ""), newest = record("new-rejection"), overhead = Buffer.byteLength(JSON.stringify({ v: 1, items: [existing, newest] })); existing.blobB64 = "A".repeat(1_000_000 - overhead);
  await storage.setItem(rejected, JSON.stringify([existing])); await storage.setItem(queue, JSON.stringify([newest])); vi.spyOn(api, "createQueuedEntry").mockRejectedValue(new ApiError(400, "invalid retained writing"));
  expect(await flushQueue(owner)).toBe(0); expect((await rejectedEntries(owner)).map(item => item.clientEntryId)).toEqual(["previous-rejection", "new-rejection"]);
});
it("keeps both quarantine records at the exact one-megabyte evidence boundary", async () => {
  const { queue } = await nativeSlots(), quarantine = queue.replace(".items.", ".quarantine."), newest = "new corrupt native record", overhead = Buffer.byteLength(JSON.stringify({ v: 1, records: ["", newest] })), prior = "A".repeat(1_000_000 - overhead);
  await storage.setItem(quarantine, JSON.stringify({ v: 1, records: [prior] })); await storage.setItem(queue, newest); expect(await queueLength(owner)).toBe(0); expect(JSON.parse((await storage.getItem(quarantine))!).records).toEqual([prior, newest]);
});
it.each(["attempts", "notBefore"])("drops non-finite native retry %s metadata without treating it as a usable delay", async field => {
  const { rejected } = await nativeSlots(), raw = JSON.stringify([record("overflow")]).replace('"entryDate":"2026-10-05"', `"entryDate":"2026-10-05","${field}":1e400`); await storage.setItem(rejected, raw);
  expect(await rejectedEntries(owner)).toEqual([record("overflow")]);
});
it("preserves a future-version quarantine envelope as opaque evidence instead of stripping its metadata", async () => {
  const { queue } = await nativeSlots(), quarantine = queue.replace(".items.", ".quarantine."), previous = JSON.stringify({ v: 2, records: ["opaque future ciphertext"], ownerEvidence: "retained future migration evidence" });
  await storage.setItem(quarantine, previous); await storage.setItem(queue, "new corrupt native record"); expect(await queueLength(owner)).toBe(0); expect(JSON.parse((await storage.getItem(quarantine))!).records).toEqual([previous, "new corrupt native record"]);
});
it("an aborted native quarantine read does not publish recovery evidence after sign-out", async () => {
  const { queue } = await nativeSlots(), quarantine = queue.replace(".items.", ".quarantine."), read = storage.getItem; await storage.setItem(queue, "corrupt native record"); let interrupted = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === quarantine && !interrupted) { interrupted = true; abortInFlightFlush(); } return value; });
  expect(await queueLength(owner)).toBe(0); expect(interrupted).toBe(true); expect(await quarantinedQueueExists(owner)).toBe(false); expect(await storage.getItem(queue)).toBe("corrupt native record");
});
it("an already aborted corrupt read settles before an unavailable evidence drawer", async () => {
  const { queue } = await nativeSlots(), quarantine = queue.replace(".items.", ".quarantine."), read = storage.getItem; await storage.setItem(queue, "corrupt native record"); let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === quarantine) await held; const value = await read(slot); if (slot === queue) abortInFlightFlush(); return value; });
  const result = queueLength(owner);
  try { expect(await Promise.race([result.then(value => ({ value })), new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ value: 0 }); }
  finally { release(); await result; }
});
it.each([401, 400, 201])("an aborted post-response native commit preserves writing and reports zero progress after status %s", async status => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([record("interrupted-commit")])); const read = storage.getItem; let postFinished = false, interrupted = false;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { postFinished = true; if (status !== 201) throw new ApiError(status, "native outcome"); return {} as never; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (postFinished && slot === queue && !interrupted) { interrupted = true; abortInFlightFlush(); } return value; });
  await expect(flushQueue(owner)).resolves.toBe(0); expect(interrupted).toBe(true); expect(await queueLength(owner)).toBe(1); expect(await rejectedEntries(owner)).toEqual([]);
});
it("a retired enqueue settles before reading an unavailable replacement native queue", async () => {
  const { queue } = await nativeSlots(), base = client.getBaseUrl, read = storage.getItem;
  let retiring = true, release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(client, "getBaseUrl").mockImplementation(async () => { const value = await base(); if (retiring) { retiring = false; changeLocalSessionOwner(owner); } return value; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === queue) await held; return read(slot); });
  const result = enqueue(record("retired-enqueue")).then(() => ({ written: true }), error => ({ message: (error as Error).message }));
  try { expect(await Promise.race([result, new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ message: "The local write belongs to a retired account or key generation" }); }
  finally { release(); await result; }
});
it("an interrupted rejection read preserves the existing native recovery drawer", async () => {
  const { queue, rejected } = await nativeSlots(), original = JSON.stringify([record("previous")]);
  await storage.setItem(queue, JSON.stringify([record("interrupted-rejection")])); await storage.setItem(rejected, original);
  const read = storage.getItem; let aborting = true;
  vi.spyOn(api, "createQueuedEntry").mockRejectedValue(new ApiError(400, "retained rejected writing"));
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === rejected && aborting) { aborting = false; abortInFlightFlush(); } return value; });
  expect(await flushQueue(owner)).toBe(0); expect(await storage.getItem(rejected)).toBe(original); expect(await queueLength(owner)).toBe(1);
});
it("an interrupted recovery read settles before publishing restored native queue writing", async () => {
  const { queue, rejected } = await nativeSlots(), original = JSON.stringify([record("recoverable")]); await storage.setItem(rejected, original);
  const read = storage.getItem; let aborting = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === rejected && aborting) { aborting = false; abortInFlightFlush(); } return value; });
  expect(await requeueRejected(owner)).toBe(0); expect(await storage.getItem(queue)).toBeNull(); expect(await storage.getItem(rejected)).toBe(original);
});
it("an interrupted physical recovery write retains the native rejection drawer", async () => {
  const { queue, rejected } = await nativeSlots(), original = JSON.stringify([record("recoverable")]); await storage.setItem(rejected, original);
  const write = storage.setItem; let aborting = true;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { await write(slot, value); if (slot === queue && aborting) { aborting = false; abortInFlightFlush(); } });
  expect(await requeueRejected(owner)).toBe(0); expect(await storage.getItem(rejected)).toBe(original); expect(await queueLength(owner)).toBe(1);
});
it("recovery restores only one native queue record for duplicate rejected ids", async () => {
  const { rejected } = await nativeSlots(); await storage.setItem(rejected, JSON.stringify([record("recovered-once"), record("recovered-once", "duplicate retained payload")]));
  expect(await requeueRejected(owner)).toBe(1); expect(await queueLength(owner)).toBe(1); expect(await rejectedEntries(owner)).toEqual([]);
});
it("a local origin refusal leaves writing ready for an immediate healthy retry", async () => {
  await enqueue(record("pinned-retry")); let calls = 0;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (++calls === 1) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); if (calls > 2) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); return {} as never; });
  expect(await flushQueue(owner)).toBe(0); expect(await flushQueue(owner)).toBe(1); expect(await queueLength(owner)).toBe(0);
});
it.each([503, 422])("a retryable %s writing does not block a later ready entry in the same pass", async status => {
  await enqueue(record("retry-first")); await enqueue(record("ready-second")); let calls = 0;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async id => { if (++calls > 2) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); if (id === "retry-first") throw new ApiError(status, status === 422 ? "entry date is in the future" : "maintenance", status === 422 ? "validation_error" : undefined); return {} as never; });
  expect(await flushQueue(owner)).toBe(1); expect(await pendingEntryIds(owner)).toEqual(["retry-first"]);
});
it("a non-date validation failure remains recoverable rather than being scheduled as a future date", async () => {
  await enqueue(record("invalid-fields")); let calls = 0;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (++calls > 1) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); throw new ApiError(422, "invalid encrypted record", "validation_error"); });
  expect(await flushQueue(owner)).toBe(0); expect(await queueLength(owner)).toBe(0); expect((await rejectedEntries(owner)).map(item => item.clientEntryId)).toEqual(["invalid-fields"]);
});
it("session expiry preserves an earlier paused entry while delaying only the attempted writing", async () => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([{ ...record("already-paused"), notBefore: Date.now() + 100_000 }, record("attempted-expired")]));
  vi.spyOn(api, "createQueuedEntry").mockRejectedValue(new ApiError(401, "login expired"));
  await expect(flushQueue(owner)).rejects.toMatchObject({ name: "SessionExpiredError" }); expect(await pendingEntryIds(owner)).toEqual(["already-paused", "attempted-expired"]);
});
it("an abandoned session-expiry commit reports no progress after the attempted record was removed", async () => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([record("expired-abandoned")])); const read = storage.getItem; let expired = false, intercepted = false;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { expired = true; throw new ApiError(401, "login expired"); });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (expired && slot === queue && !intercepted) { intercepted = true; await storage.removeItem(queue); const value = await read(slot); abortInFlightFlush(); return value; } return read(slot); });
  expect(await flushQueue(owner)).toBe(0); expect(await queueLength(owner)).toBe(0);
});
it("an acknowledged native queue read cannot report progress after its account permit retires", async () => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([record("accepted-retired")])); const read = storage.getItem; let accepted = false, intercepted = false;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { accepted = true; return {} as never; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (accepted && slot === queue && !intercepted) { intercepted = true; await storage.removeItem(queue); const value = await read(slot); changeLocalSessionOwner(owner); return value; } return read(slot); });
  await expect(flushQueue(owner)).rejects.toThrow("retired account or key generation"); expect(await queueLength(owner)).toBe(0);
});
it("a rejected native session commit cannot report session expiry after its account permit retires", async () => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([record("expired-retired")])); const read = storage.getItem; let expired = false, intercepted = false;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { expired = true; throw new ApiError(401, "login expired"); });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (expired && slot === queue && !intercepted) { intercepted = true; await storage.removeItem(queue); const value = await read(slot); changeLocalSessionOwner(owner); return value; } return read(slot); });
  await expect(flushQueue(owner)).rejects.toThrow("retired account or key generation"); expect(await queueLength(owner)).toBe(0);
});
it("an already removed expired record settles before an unavailable second native deletion", async () => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify([record("expired-removed")])); const read = storage.getItem, remove = storage.removeItem; let expired = false, intercepted = false, release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { expired = true; throw new ApiError(401, "login expired"); });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (expired && slot === queue && !intercepted) { intercepted = true; await remove(queue); } return read(slot); });
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => { if (intercepted && slot === queue) await gate; return remove(slot); });
  const result = flushQueue(owner).then(value => ({ value }), error => ({ name: (error as Error).name }));
  try { expect(await Promise.race([result, new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ name: "SessionExpiredError" }); }
  finally { release(); await result; }
});
it("an abandoned full native queue reports cancellation rather than a capacity failure", async () => {
  const { queue } = await nativeSlots(); await storage.setItem(queue, JSON.stringify(Array.from({ length: 200 }, (_, index) => record(`full-${index}`)))); const read = storage.getItem; let intercepted = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === queue && !intercepted) { intercepted = true; abortInFlightFlush(); } return value; });
  await expect(enqueue(record("cancelled-full"))).rejects.toMatchObject({ name: "QueueAbandonedError" }); expect(await queueLength(owner)).toBe(200);
});
it("a non-422 future-related validation message is retained as rejected writing", async () => {
  await enqueue(record("future-but-bad-request")); let calls = 0;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => { if (++calls > 1) throw new OriginPinnedError("https://queued.example", "https://replacement.example"); throw new ApiError(400, "future entry date is invalid", "validation_error"); });
  expect(await flushQueue(owner)).toBe(0); expect(await queueLength(owner)).toBe(0); expect((await rejectedEntries(owner)).map(item => item.clientEntryId)).toEqual(["future-but-bad-request"]);
});
it("an empty reconnect settles before an unavailable redundant native queue reread", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(7_000_000_000_000); const { queue } = await nativeSlots(); const read = storage.getItem; let reads = 0, release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === queue && ++reads > 1) await gate; return read(slot); });
  const result = flushQueueOnReconnect().then(() => ({ complete: true }));
  try { expect(await Promise.race([result, new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ complete: true }); }
  finally { release(); await result; }
});
it("an interrupted native rewrap provider preserves the original encrypted queue", async () => {
  const { queue } = await nativeSlots(), original = JSON.stringify([record("key-custody", seal("key-custody"))]); await storage.setItem(queue, original);
  const create = engine.createCipheriv.bind(engine); let aborting = true;
  vi.spyOn(engine, "createCipheriv").mockImplementation((algorithm, key, nonce) => { const cipher = create(algorithm, key, nonce), update = cipher.update.bind(cipher); vi.spyOn(cipher, "update").mockImplementation((value: Buffer) => { const encrypted = update(value); if (aborting) { aborting = false; abortInFlightFlush(); } return encrypted; }); return cipher; });
  await rewrapQueue(owner, oldKey, newKey); expect(await storage.getItem(queue)).toBe(original);
});
it("an interrupted native rewrap queue commit preserves the original encrypted recovery drawer", async () => {
  const { queue, rejected } = await nativeSlots(), original = JSON.stringify([record("recovery-key", seal("recovery-key"))]);
  await storage.setItem(queue, JSON.stringify([record("queue-key", seal("queue-key"))])); await storage.setItem(rejected, original);
  const write = storage.setItem; let aborting = true;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { await write(slot, value); if (slot === queue && aborting) { aborting = false; abortInFlightFlush(); } });
  await rewrapQueue(owner, oldKey, newKey); expect(await storage.getItem(rejected)).toBe(original);
});
