import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { api, ApiError, clearSession } from "../src/api/client";
import { abortInFlightFlush, clearQueue, drainPendingQueueForRotation, enqueue, flushQueue, flushQueueOnReconnect, rewrapQueue, QueueFullError, QueueAbandonedError, queueEvictionSummary, queueLength, quarantinedQueueExists, rejectedEntries, requeueRejected, SessionExpiredError, type QueuedEntry } from "../src/offlineQueue";
import { kv, newWriteGeneration, resetKvConnectionForTests, setKvBackendForTests, StorageCommitError, StorageReadError, writeGenerationKey } from "../src/kvstore";
import { decryptEntry, encryptEntry } from "../src/crypto/patient";
import { displayError } from "../src/errors";
import { installSession, resetTestState } from "./helpers/api";

const owner = "queue-recovery", other = "queue-other";
let records: Map<string, string>;
const entry = (id = "queued", fields: Partial<QueuedEntry> = {}): QueuedEntry => ({ userId: owner, clientEntryId: id, blobB64: "opaque encrypted writing", entryDate: "2026-10-05", ...fields });
beforeEach(() => {
  resetTestState(); installSession(owner); records = new Map();
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); }, keys: async () => [...records.keys()] });
});
afterEach(() => { abortInFlightFlush(); setKvBackendForTests(null); resetKvConnectionForTests(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });
async function slots() { await enqueue(entry()); const queue = (await kv.keys()).find(k => k.startsWith("mindpattern/queue.v1.items."))!; return { queue, rejected: queue.replace(".items.", ".rejected."), quarantine: queue.replace(".items.", ".quarantine."), evictions: queue.replace(".items.", ".evictions.") }; }

it.each([null, true, 42, "text", {}, { userId: 1 }, { clientEntryId: null }, { blobB64: [] }, { entryDate: {} }])
  ("keeps every malformed recovery record as evidence while retaining valid ciphertext: %#", async fields => {
    const { rejected, quarantine } = await slots();
    const malformed = fields !== null && typeof fields === "object" && Object.keys(fields).length > 0 ? { ...entry("invalid"), evidence: "original opaque record", ...fields } : fields;
    records.set(rejected, JSON.stringify({ v: 1, items: [malformed, entry("valid")] }));
    expect(await rejectedEntries()).toEqual([entry("valid")]);
    expect(JSON.parse(records.get(quarantine)!).records).toContain(JSON.stringify(malformed));
    expect(await rejectedEntries()).toEqual([entry("valid")]);
  });
it("quarantines a foreign owner's ciphertext instead of returning it under this account or silently dropping it", async () => {
  const { rejected, quarantine } = await slots(), foreign = entry("foreign", { userId: other, blobB64: "foreign opaque ciphertext" });
  records.set(rejected, JSON.stringify([foreign, entry("own")])); expect(await rejectedEntries()).toEqual([entry("own")]);
  const evidence = JSON.parse(records.get(quarantine)!).records as string[]; expect(evidence.some(raw => raw.includes(foreign.blobB64))).toBe(true);
  expect(await rejectedEntries(other)).toEqual([]); expect(await quarantinedQueueExists(owner)).toBe(true); expect(await quarantinedQueueExists(other)).toBe(false);
});
it("retains a valid queue during a transient storage read failure and recovers it on retry", async () => {
  const { queue, quarantine } = await slots(), before = records.get(queue); let fail = true;
  setKvBackendForTests({ getItem: async k => { if (k === queue && fail) { fail = false; throw new Error("temporary device read failure"); } return records.get(k) ?? null; }, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); }, keys: async () => [...records.keys()] });
  await expect(queueLength()).rejects.toBeInstanceOf(StorageReadError);
  expect(records.get(queue)).toBe(before); expect(records.has(quarantine)).toBe(false); expect(await queueLength()).toBe(1);
});
it.each(["null", "42", "true", '"text"', "{}", '{"v":2,"items":[]}', '{"v":1,"items":{}}', '{"v":1,"items":"opaque ciphertext"}'])
  ("parks an unrecognized queue envelope verbatim and repairs its old slot: %s", async raw => {
    const { queue, quarantine } = await slots(); records.set(queue, raw);
    expect(await queueLength()).toBe(0); expect(records.has(queue)).toBe(false); expect(JSON.parse(records.get(quarantine)!).records).toContain(raw);
  });
it.each([null, { rejected: 2, quarantine: 3 }, { rejected: "2", quarantine: "3" }, { rejected: -1, quarantine: -1 }, { rejected: 0.5, quarantine: 0.5 }])
  ("preserves valid prior evidence-loss counts and sanitizes invalid counters when another record is lost: %j", async prior => {
    const { rejected, evictions } = await slots(); records.set(evictions, JSON.stringify(prior));
    records.set(rejected, JSON.stringify({ v: 1, items: [entry("oversized", { blobB64: "A".repeat(1_000_001) })] }));
    expect(await rejectedEntries()).toEqual([]); expect(await queueEvictionSummary()).toEqual(prior?.rejected === 2 ? { rejected: 3, quarantine: 3 } : { rejected: 1, quarantine: 0 });
  });
it("keeps exactly fifty evidence records and accepts an exact 250KB evidence drawer", async () => {
  const { queue, quarantine } = await slots(); const prior = Array.from({ length: 49 }, (_, i) => `evidence-${i}`), newest = "new corrupt ciphertext";
  records.set(quarantine, JSON.stringify({ v: 1, records: prior })); records.set(queue, newest); await queueLength();
  expect(JSON.parse(records.get(quarantine)!).records).toEqual([...prior, newest]); expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 0 });
  const large = Array.from({ length: 8 }, (_, i) => `${i}`.repeat(31_000));
  const overhead = new TextEncoder().encode(JSON.stringify({ v: 1, records: [...large, "", newest] })).length;
  const padded = [...large, "p".repeat(250_000 - overhead)]; records.set(quarantine, JSON.stringify({ v: 1, records: padded })); records.set(queue, newest);
  await queueLength(); expect(new TextEncoder().encode(records.get(quarantine)!).length).toBe(250_000); expect(JSON.parse(records.get(quarantine)!).records).toEqual([...padded, newest]);
});
it("caps newly appended rejection records and deduplicates a tampered duplicate upload batch", async () => {
  const { queue, rejected } = await slots(); const held = Array.from({ length: 200 }, (_, i) => entry(`older-${i}`)); records.set(rejected, JSON.stringify({ v: 1, items: held }));
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "invalid")); await flushQueue(owner);
  expect(await rejectedEntries()).toEqual([...held.slice(1), entry()]); expect(await queueEvictionSummary()).toEqual({ rejected: 1, quarantine: 0 });
  await clearQueue(); records.set(queue, JSON.stringify({ v: 1, items: [entry("duplicate"), entry("duplicate")] }));
  await flushQueue(owner); expect(await rejectedEntries()).toEqual([entry("duplicate")]);
  records.set(queue, JSON.stringify({ v: 1, items: [entry("duplicate")] })); await flushQueue(owner); expect(await rejectedEntries()).toEqual([entry("duplicate")]);
});
it("leaves rejected writing parked when either count or byte capacity prevents requeue, and deduplicates existing queued ids", async () => {
  const { queue, rejected } = await slots(); const full = Array.from({ length: 200 }, (_, i) => entry(`full-${i}`)); records.set(queue, JSON.stringify({ v: 1, items: full })); records.set(rejected, JSON.stringify({ v: 1, items: [entry("retained")] }));
  expect(await requeueRejected()).toBe(0); expect(await rejectedEntries()).toEqual([entry("retained")]); expect(await queueLength()).toBe(200);
  const large = entry("large", { blobB64: "A".repeat(999_700) }); records.set(queue, JSON.stringify({ v: 1, items: [large] })); records.set(rejected, JSON.stringify({ v: 1, items: [entry("retained", { blobB64: "B".repeat(500) })] }));
  expect(await requeueRejected()).toBe(0); expect(await rejectedEntries()).toEqual([entry("retained", { blobB64: "B".repeat(500) })]);
  records.set(queue, JSON.stringify({ v: 1, items: [entry("existing")] })); records.set(rejected, JSON.stringify({ v: 1, items: [entry("existing"), entry("new"), entry("new")] }));
  expect(await requeueRejected()).toBe(1); expect(await queueLength()).toBe(2); expect(await rejectedEntries()).toEqual([]);
});
it.each([[new Error("unreachable network"), true, false], [new ApiError(0, "network"), true, false], [new ApiError(429, "busy"), true, false], [new ApiError(413, "too large"), true, true], [new ApiError(400, "invalid"), false, true], [new ApiError(500, "server"), false, false], [new ApiError(422, "entry_date is in the future", "validation_error"), false, false]])
  ("continues or stops a two-entry drain according to the public failure classification: %#", async (failure, stop, reject) => {
    await enqueue(entry("first")); await enqueue(entry("second")); const post = vi.spyOn(api, "createEntry").mockRejectedValue(failure);
    expect(await flushQueue(owner)).toBe(0); const count = stop ? 1 : 2; expect(post).toHaveBeenCalledTimes(count);
    expect(await rejectedEntries()).toHaveLength(reject ? count : 0); expect(await queueLength()).toBe(reject ? 2 - count : 2);
  });
it.each([new ApiError(404, "missing"), new ApiError(401, "expired"), new ApiError(503, "verification unavailable"), new Error("verification failed")])
  ("retains an unverified conflict instead of treating it as a proved duplicate: %#", async failure => {
    await enqueue(entry("first")); await enqueue(entry("second")); const post = vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(409, "conflict")); vi.spyOn(api, "getEntry").mockRejectedValue(failure);
    if (failure instanceof ApiError && failure.status === 401) await expect(flushQueue(owner)).rejects.toBeInstanceOf(SessionExpiredError); else expect(await flushQueue(owner)).toBe(0);
    const missing = failure instanceof ApiError && failure.status === 404;
    expect(post).toHaveBeenCalledTimes(failure instanceof ApiError && failure.status === 401 ? 1 : 2); expect(await rejectedEntries()).toHaveLength(missing ? 2 : 0); expect(await queueLength()).toBe(missing ? 0 : 2);
  });
it("applies a real jittered pause and increases it after another failed attempt", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); vi.spyOn(Math, "random").mockReturnValue(0.5); await enqueue(entry());
  const post = vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(503, "temporary")); await flushQueue(owner);
  vi.setSystemTime(1_022_499); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1); vi.setSystemTime(1_022_500); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2);
  vi.setSystemTime(1_067_499); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2); vi.setSystemTime(1_067_500); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(3);
});
it("does not begin a flush without a live session, and refuses queue access without an explicit account", async () => {
  clearSession(); expect(await flushQueue(owner)).toBe(0);
  for (const run of [queueLength, rejectedEntries, queueEvictionSummary, clearQueue]) await expect(run()).rejects.toThrow("account id");
});
it("reports remaining writing during rotation and retains it after a network failure", async () => {
  await enqueue(entry()); vi.spyOn(api, "createEntry").mockRejectedValue(new Error("offline")); expect(await drainPendingQueueForRotation(owner)).toBe(1); expect(await queueLength()).toBe(1);
});
it("normalizes retry metadata to finite numbers without coercing strings, objects or arrays", async () => {
  const { rejected } = await slots();
  records.set(rejected, '[{"userId":"queue-recovery","clientEntryId":"valid","blobB64":"opaque","entryDate":"2026-10-05","attempts":2,"notBefore":123},{"userId":"queue-recovery","clientEntryId":"invalid","blobB64":"opaque","entryDate":"2026-10-05","attempts":"2","notBefore":[123]},{"userId":"queue-recovery","clientEntryId":"infinite","blobB64":"opaque","entryDate":"2026-10-05","attempts":1e400,"notBefore":1e400}]');
  expect(await rejectedEntries()).toEqual([{ ...entry("valid"), blobB64: "opaque", attempts: 2, notBefore: 123 }, { ...entry("invalid"), blobB64: "opaque" }, { ...entry("infinite"), blobB64: "opaque" }]);
});
it.each([null, {}, { rejected: -1, quarantine: -1 }, { rejected: "2", quarantine: "3" }, { rejected: 0.5, quarantine: 0.5 }, { rejected: Number.MAX_SAFE_INTEGER + 1, quarantine: Number.MAX_SAFE_INTEGER + 1 }, { rejected: 2, quarantine: 3 }])
  ("reports only safe nonnegative evidence loss counters: %j", async row => {
    const { evictions } = await slots(); records.set(evictions, JSON.stringify(row));
    expect(await queueEvictionSummary()).toEqual(row?.rejected === 2 ? { rejected: 2, quarantine: 3 } : { rejected: 0, quarantine: 0 });
    records.set(evictions, "{"); expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 0 });
  });
it.each(["{", JSON.stringify({ v: 2, records: ["old"] }), JSON.stringify({ v: 1, records: ["old", 42, null] })])
  ("retains previous recoverable evidence when appending a new corrupt value: %#", async prior => {
    const { queue, quarantine } = await slots(); records.set(quarantine, prior); records.set(queue, "new corrupt ciphertext");
    expect(await queueLength()).toBe(0); const rows = JSON.parse(records.get(quarantine)!).records;
    expect(rows).toEqual(prior.startsWith('{"v":1,') ? ["old", "new corrupt ciphertext"] : [prior, "new corrupt ciphertext"]);
  });
it("keeps a maximum-size evidence record verbatim and bounds every oversized preview before storing it", async () => {
  const { queue, quarantine } = await slots(), exact = "!".repeat(32_000); records.set(queue, exact);
  await queueLength(); expect(JSON.parse(records.get(quarantine)!).records).toEqual([exact]); expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 0 });
  records.set(queue, "!".repeat(34_000)); await queueLength(); const evidence = JSON.parse(records.get(quarantine)!).records as string[];
  expect(evidence[0]).toBe(exact); expect(new TextEncoder().encode(evidence[1]!).length).toBeLessThanOrEqual(32_000);
  expect(JSON.parse(evidence[1]!)).toMatchObject({ truncated: true, original_bytes: 34_000 }); expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 1 });
});
it("preserves exact count and serialized byte boundaries while moving rejected writing back to the queue", async () => {
  const { queue, rejected } = await slots(); records.delete(queue);
  const rows = Array.from({ length: 200 }, (_, i) => entry(`retained-${i}`)); records.set(rejected, JSON.stringify({ v: 1, items: rows }));
  expect(await rejectedEntries()).toEqual(rows); expect(await queueEvictionSummary()).toEqual({ rejected: 0, quarantine: 0 });
  expect(await requeueRejected()).toBe(200); expect(await queueLength()).toBe(200); expect(await rejectedEntries()).toEqual([]);
  await clearQueue(); const maximum = entry("exact-byte-cap"); const overhead = new TextEncoder().encode(JSON.stringify({ v: 1, items: [maximum] })).length;
  maximum.blobB64 += "A".repeat(1_000_000 - overhead); await enqueue(maximum); expect(await queueLength()).toBe(1);
  records.set(rejected, JSON.stringify({ v: 1, items: [maximum] })); expect(await rejectedEntries()).toEqual([maximum]);
  await expect(enqueue(entry("over-cap"))).rejects.toThrow("offline queue is full"); expect(await queueLength()).toBe(1);
});
it.each([[0, 15_000], [1, 30_000], [10, 900_000], [100, 900_000]])
  ("does not retry before the bounded exponential pause for %s prior failures", async (attempts, delay) => {
    vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); vi.spyOn(Math, "random").mockReturnValue(0);
    await enqueue(entry("retry", { attempts })); const post = vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(503, "temporary"));
    await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1); vi.setSystemTime(1_000_000 + delay - 1); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1);
    vi.setSystemTime(1_000_000 + delay); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2);
  });
it.each([[0, 1000], [120_000, 120_000], [7_200_000, 3_600_000]])
  ("honors a server retry advisory within the stated floor and ceiling: %s", async (advisory, delay) => {
    vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); await enqueue(entry());
    const post = vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(429, "busy", "rate_limited", advisory));
    await flushQueue(owner); vi.setSystemTime(1_000_000 + delay - 1); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(1);
    vi.setSystemTime(1_000_000 + delay); await flushQueue(owner); expect(post).toHaveBeenCalledTimes(2);
  });
it("preserves an expired session's entire queue for fifteen minutes rather than hammering the dead bearer", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(1_000_000); await enqueue(entry("first")); await enqueue(entry("unattempted"));
  const post = vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(401, "expired"));
  await expect(flushQueue(owner)).rejects.toBeInstanceOf(SessionExpiredError); expect(post).toHaveBeenCalledTimes(1); expect(await queueLength()).toBe(2);
  await clearQueue(); await enqueue(entry("single")); post.mockClear(); await expect(flushQueue(owner)).rejects.toBeInstanceOf(SessionExpiredError);
  vi.setSystemTime(1_899_999); expect(await flushQueue(owner)).toBe(0); expect(post).toHaveBeenCalledTimes(1);
  vi.setSystemTime(1_900_000); await expect(flushQueue(owner)).rejects.toBeInstanceOf(SessionExpiredError); expect(post).toHaveBeenCalledTimes(2);
});
it("uses URL-safe scope keys which the durable owner policy can fence for Unicode account identities", async () => {
  setKvBackendForTests(null); resetKvConnectionForTests(); vi.stubGlobal("indexedDB", new IDBFactory()); const secret = new Uint8Array(32).fill(39);
  for (const user of ["user+plus/slash", "\u00ff\u00fe\u00fd", "\uffff\ufffe", "😄"]) {
    const permit = await kv.captureWritePermit(user, secret); await enqueue({ ...entry(user), userId: user }, permit);
    await kv.setItem(writeGenerationKey(user), await newWriteGeneration(user, secret));
    await expect(enqueue({ ...entry(`old-${user}`), userId: user }, permit)).rejects.toBeInstanceOf(StorageCommitError);
    expect(await queueLength(user)).toBe(1);
  }
});

it("returns a useful public capacity error without changing the two hundred retained entries", async () => {
  const { queue } = await slots(), full = Array.from({ length: 200 }, (_, i) => entry(`retained-${i}`)); records.set(queue, JSON.stringify({ v: 1, items: full }));
  try { await enqueue(entry("overflow")); throw new Error("expected full queue"); }
  catch (error) { expect(error).toBeInstanceOf(QueueFullError); expect((error as Error).name).toBe("QueueFullError"); expect(displayError(error, "Retry")).toBe("offline queue is full (200 entries) — sync before writing more"); }
  expect(await queueLength()).toBe(200); expect(JSON.parse(records.get(queue)!).items).toEqual(full);
});
it("reports an abandoned producer with a useful public error and preserves the old queue after sign-out lands during its read", async () => {
  const { queue } = await slots(), before = records.get(queue); let release!: () => void, observed!: () => void;
  const started = new Promise<void>(resolve => { observed = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const get = kv.getItem.bind(kv); vi.spyOn(kv, "getItem").mockImplementation(async k => { const result = await get(k); if (k === queue) { observed(); await gate; } return result; });
  const settled = enqueue(entry("retired")).then(value => ({ value, error: null }), error => ({ value: null, error }));
  await started; abortInFlightFlush(); release(); const result = await settled;
  expect(result.error).toBeInstanceOf(QueueAbandonedError); expect(result.error.name).toBe("QueueAbandonedError"); expect(displayError(result.error, "Retry")).toBe("the queue was cleared while saving — the entry was NOT queued"); expect(records.get(queue)).toBe(before);
});
it.each([false, true])("requires a key-bound permit for this owner and exposes its refusal explanation: wrongOwner=%s", async wrongOwner => {
  const permit = await kv.captureWritePermit(wrongOwner ? other : owner);
  if (wrongOwner) permit.keyBound = true;
  try { await enqueue(entry(), permit); throw new Error("expected producer refusal"); }
  catch (error) { expect(error).toBeInstanceOf(StorageCommitError); expect(displayError(error, "Retry")).toBe("A queued entry requires its producer's account-key generation permit."); }
  expect(await queueLength()).toBe(0);
});
it("retains an expired queue and exposes the public session recovery error", async () => {
  await enqueue(entry()); vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(401, "expired"));
  try { await flushQueue(owner); throw new Error("expected expired session"); }
  catch (error) { expect(error).toBeInstanceOf(SessionExpiredError); expect((error as Error).name).toBe("SessionExpiredError"); expect(displayError(error, "Retry")).toBe("session expired mid-flush — unsent entries were preserved for recovery"); }
  expect(await queueLength()).toBe(1);
});
it("throttles reconnects only before ten seconds, allowing the exact boundary and a backward clock correction", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); const start = 100_000_000; vi.setSystemTime(start);
  const post = vi.spyOn(api, "createEntry").mockResolvedValue({ id: "accepted" });
  await enqueue(entry("first")); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(1);
  await enqueue(entry("second")); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(1);
  vi.setSystemTime(start + 9999); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(1); expect(await queueLength()).toBe(1);
  vi.setSystemTime(start + 10000); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(2);
  await enqueue(entry("backward")); vi.setSystemTime(start - 1); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(3);
  clearSession(); vi.setSystemTime(start + 30000); await flushQueueOnReconnect(); expect(post).toHaveBeenCalledTimes(3);
});
it.each([false, true])("erases actual decrypted rotation plaintext after transferring or failing to reseal it: encryptFailure=%s", async fail => {
  const oldKey = new Uint8Array(new ArrayBuffer(32)).fill(41), newKey = new Uint8Array(new ArrayBuffer(32)).fill(43), oldBefore = oldKey.slice(), newBefore = newKey.slice();
  const id = "real-rotation-secret", payload = await encryptEntry(oldKey, owner, id, "private rotation writing", "2026-10-05", 0, undefined, 1);
  await enqueue(entry(id, { blobB64: payload.blobB64 }));
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle), secrets: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => { const result = await decrypt(...args); secrets.push(new Uint8Array(result)); return result; });
  if (fail) vi.spyOn(crypto.subtle, "encrypt").mockRejectedValue(new Error("device reseal failed"));
  await rewrapQueue(owner, oldKey, newKey);
  expect(secrets.length).toBeGreaterThan(0); for (const physical of secrets) expect(physical).toEqual(new Uint8Array(physical.length));
  expect(oldKey).toEqual(oldBefore); expect(newKey).toEqual(newBefore);
  vi.restoreAllMocks(); const queue = (await kv.keys()).find(k => k.startsWith("mindpattern/queue.v1.items."))!, stored = JSON.parse((await kv.getItem(queue))!).items[0] as QueuedEntry;
  if (fail) expect(stored.blobB64).toBe(payload.blobB64);
  else expect((await decryptEntry(newKey, owner, id, stored.blobB64, 1)).text).toBe("private rotation writing");
});
it("preserves the queue after a failed best-effort rotation drain and returns its remaining count", async () => {
  await enqueue(entry()); vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(401, "expired"));
  expect(await drainPendingQueueForRotation(owner)).toBe(1); expect(await queueLength()).toBe(1);
});

it("retains recoverable queue ciphertext when committing its rejection store fails", async () => {
  const { queue, rejected } = await slots(), before = records.get(queue);
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { if (k === rejected) throw new Error("device rejection store is full"); records.set(k, v); }, removeItem: async k => { records.delete(k); }, keys: async () => [...records.keys()] });
  vi.spyOn(api, "createEntry").mockRejectedValue(new ApiError(400, "invalid writing"));
  await expect(flushQueue(owner)).rejects.toBeInstanceOf(StorageCommitError);
  expect(records.get(queue)).toBe(before); expect(records.has(rejected)).toBe(false);
});
