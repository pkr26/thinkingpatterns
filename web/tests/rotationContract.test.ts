import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildAad } from "../src/crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { hasLocalRotation, resumeLocalRotation, rotationDataKey, rotationSalt, stageLocalRotation } from "../src/localRotation";
import { kv, newWriteGeneration, setKvBackendForTests } from "../src/kvstore";

vi.mock("../src/crypto/core", async (original) => {
  const actual = await original<typeof import("../src/crypto/core")>();
  return { ...actual, decrypt: vi.fn(actual.decrypt), encrypt: vi.fn(actual.encrypt) };
});
const owner = "rotation-contract-owner";
const oldKey = new Uint8Array(new ArrayBuffer(32)).fill(2);
const newKey = new Uint8Array(new ArrayBuffer(32)).fill(3);
const credential = { operation_id: "rotation-operation", new_salt: toBase64(new Uint8Array(new ArrayBuffer(16)).fill(4)), new_verifier: "new-verifier" };
const journalSlot = `mindpattern.localRotation.${owner}`;
let records: Map<string, string>;

beforeEach(() => {
  records = new Map();
  setKvBackendForTests({
    async getItem(key) { return records.get(key) ?? null; },
    async setItem(key, value) { records.set(key, value); },
    async removeItem(key) { records.delete(key); },
    async keys() { return [...records.keys()]; },
    async compareAndSet(key, expected, value) {
      if ((records.get(key) ?? null) !== expected) return false;
      records.set(key, value); return true;
    },
  });
  vi.mocked(decrypt).mockClear();
  vi.mocked(encrypt).mockClear();
});
afterEach(() => { setKvBackendForTests(null); vi.restoreAllMocks(); });

async function sealed(key: Uint8Array<ArrayBuffer>, domain: string, text: string, entryId?: string): Promise<string> {
  return toBase64(await encrypt(key, new TextEncoder().encode(text), buildAad(domain, owner, ...(entryId ? [entryId] : []))));
}

async function installJournal(fields: Record<string, unknown> = {}): Promise<string> {
  const journal = { v: 1, owner, credential, old_key: toBase64(oldKey), records: [], ...fields };
  const ciphertext = await sealed(newKey, "local-rotation", JSON.stringify(journal));
  records.set(journalSlot, ciphertext);
  return ciphertext;
}

describe("public rotation recovery contract", () => {
  it("opens the stored candidate key using the documented seed domain and rejects a short candidate", async () => {
    const candidate = new Uint8Array(new ArrayBuffer(32)).fill(31);
    records.set(`mindpattern.rotationSeed.${owner}`, toBase64(await encrypt(newKey, candidate, buildAad("local-rotation-seed", owner))));
    expect(await rotationDataKey(owner, newKey)).toEqual(candidate);
    records.set(`mindpattern.rotationSeed.${owner}`, toBase64(await encrypt(newKey, candidate.slice(0, 31), buildAad("local-rotation-seed", owner))));
    await expect(rotationDataKey(owner, newKey)).rejects.toThrow("invalid");
    const plaintext = await vi.mocked(decrypt).mock.results.at(-1)!.value as Uint8Array;
    expect(plaintext.every((byte) => byte === 0)).toBe(true);
  });

  it("uses an existing legacy salt and rejects an invalid salt without storing it", async () => {
    const legacy = new Uint8Array(new ArrayBuffer(16)).fill(19);
    expect(await rotationSalt(owner, toBase64(legacy))).toEqual(legacy);
    records.clear();
    await expect(rotationSalt(owner, toBase64(legacy.slice(0, 15)))).rejects.toThrow("invalid");
    expect(await kv.getItem(`mindpattern.rotationSalt.${owner}`)).toBeNull();
  });

  it.each([
    { v: 2 }, { owner: "another-owner" }, { credential: {} }, { credential: null },
    { records: {} }, { old_key: toBase64(new Uint8Array(new ArrayBuffer(31))) },
  ])("retains an authenticated malformed migration checkpoint: %j", async (fields) => {
    const checkpoint = await installJournal(fields);
    await expect(resumeLocalRotation(owner, newKey, credential.new_salt)).rejects.toThrow("Invalid migration journal");
    expect(records.get(journalSlot)).toBe(checkpoint);
    await expect(stageLocalRotation(owner, oldKey, newKey, credential)).rejects.toThrow("original new password");
    expect(records.get(journalSlot)).toBe(checkpoint);
  });

  it("clears the decrypt API's returned checkpoint plaintext after both success and validation failure", async () => {
    for (const fields of [{}, { v: 2 }]) {
      await installJournal(fields);
      try { await stageLocalRotation(owner, oldKey, newKey, credential); } catch { /* Failure is checked by the malformed-journal cases. */ }
      const plaintext = await vi.mocked(decrypt).mock.results.at(-1)!.value as Uint8Array;
      expect(plaintext.length).toBeGreaterThan(0);
      expect(plaintext.every((byte) => byte === 0)).toBe(true);
    }
  });

  it("rotates all account-owned storage domains and leaves unrelated data untouched", async () => {
    const stores = [
      [`mindpattern.draft.active.${owner}`, "draft"], [`mindpattern.safetyPlan.${owner}`, "safety-plan"],
      [`mindpattern.moodlog.${owner}`, "moodlog"], [`mindpattern.feedback.${owner}`, "feedback-local"],
      [`mindpattern.pendingMeasure.${owner}`, "pending-measure"], [`mindpattern.patternMutes.v1.${owner}`, "pattern-mutes"],
      [`mindpattern.entryVersions.${owner}`, "entry-versions"], [`mindpattern.entryV2Bound.${owner}`, "entry-v2-bound"],
    ];
    for (const [slot, domain] of stores) records.set(slot!, await sealed(oldKey, domain!, `private ${domain}`));
    records.set("unrelated", "leave this data alone");
    const before = new Map(records);
    vi.mocked(decrypt).mockClear(); vi.mocked(encrypt).mockClear();
    await stageLocalRotation(owner, oldKey, newKey, credential);
    for (const result of vi.mocked(decrypt).mock.results) expect((await result.value as Uint8Array).every(byte => byte === 0)).toBe(true);
    for (const [, plaintext] of vi.mocked(encrypt).mock.calls) expect(plaintext.every(byte => byte === 0)).toBe(true);
    for (const [slot] of stores) expect(records.get(slot!)).toBe(before.get(slot!));
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    for (const [slot, domain] of stores) {
      expect(new TextDecoder().decode(await decrypt(newKey, fromBase64(records.get(slot!)!), buildAad(domain!, owner)))).toBe(`private ${domain}`);
    }
    expect(records.get("unrelated")).toBe("leave this data alone");
    expect(await hasLocalRotation(owner)).toBe(false);
  });

  it("rotates an array queue containing both owners while retaining the other owner's item", async () => {
    const queueSlot = "mindpattern/queue.v1.items.mixed";
    const own = { userId: owner, clientEntryId: "own", blobB64: await sealed(oldKey, "entry", "owned writing", "own") };
    const other = { userId: "another-owner", clientEntryId: "other", blobB64: "opaque other ciphertext", attempts: 3 };
    records.set(queueSlot, JSON.stringify([own, other, null]));
    vi.mocked(decrypt).mockClear();
    await stageLocalRotation(owner, oldKey, newKey, credential);
    const opens = await Promise.allSettled(vi.mocked(decrypt).mock.results.map(result => result.value as Promise<Uint8Array>));
    expect(opens.some(result => result.status === "fulfilled")).toBe(true);
    for (const result of opens) if (result.status === "fulfilled") expect(result.value.every(byte => byte === 0)).toBe(true);
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    const queue = JSON.parse(records.get(queueSlot)!);
    expect(queue).toHaveLength(3);
    expect(queue[1]).toEqual(other);
    expect(queue[2]).toBeNull();
    expect(new TextDecoder().decode(await decrypt(newKey, fromBase64(queue[0].blobB64), buildAad("entry", owner, "own")))).toBe("owned writing");
  });

  it.each([
    ["unreadable", "unreadable"],
    [[{ userId: owner, clientEntryId: 42, blobB64: "cipher" }], "malformed"],
    [[{ userId: owner, clientEntryId: "own", blobB64: 42 }], "malformed"],
    [[{ userId: owner, clientEntryId: "own", blobB64: "invalid-ciphertext" }], "cannot be authenticated"],
  ])("retains the original queue when it cannot be safely rotated: %j", async (items, message) => {
    const queueSlot = "mindpattern/queue.v1.rejected.hostile";
    const before = JSON.stringify({ v: 1, items });
    records.set(queueSlot, before);
    await expect(stageLocalRotation(owner, oldKey, newKey, credential)).rejects.toThrow(message);
    expect(records.get(queueSlot)).toBe(before);
    expect(await hasLocalRotation(owner)).toBe(false);
  });

  it("keeps a queue with no item for the rotating account byte-identical", async () => {
    const queueSlot = "mindpattern/queue.v1.items.other";
    const before = JSON.stringify([{ userId: "another-owner", blobB64: "opaque" }, null]);
    records.set(queueSlot, before);
    await stageLocalRotation(owner, oldKey, newKey, credential);
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    expect(records.get(queueSlot)).toBe(before);
  });

  it("erases the candidate passed to encryption if its durable seed cannot be stored", async () => {
    vi.spyOn(kv, "setItem").mockRejectedValueOnce(new Error("seed storage unavailable"));
    await expect(rotationDataKey(owner, newKey)).rejects.toThrow("seed storage unavailable");
    const plaintext = vi.mocked(encrypt).mock.calls[0]![1];
    expect(plaintext.length).toBe(32); expect(plaintext.every(byte => byte === 0)).toBe(true);
  });

  it("ignores queue-like names outside the account queue namespace", async () => {
    const slot = "unrelated/mindpattern/queue.v1.items.somewhere";
    records.set(slot, "this is unrelated, non-JSON data");
    await stageLocalRotation(owner, oldKey, newKey, credential);
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    expect(records.get(slot)).toBe("this is unrelated, non-JSON data");
  });

  it("retains a legacy checkpoint if its durable upgrade loses a comparison race", async () => {
    const before = await installJournal();
    vi.spyOn(kv, "compareAndSetForMigration").mockResolvedValueOnce(false);
    vi.mocked(encrypt).mockClear();
    await expect(resumeLocalRotation(owner, newKey, credential.new_salt)).rejects.toThrow("checkpoint changed");
    expect(records.get(journalSlot)).toBe(before);
    for (const [, plaintext] of vi.mocked(encrypt).mock.calls) expect(plaintext.every(byte => byte === 0)).toBe(true);
  });

  it("retains migration records if another writer wins generation advancement", async () => {
    await stageLocalRotation(owner, oldKey, newKey, credential);
    const before = records.get(journalSlot);
    vi.spyOn(kv, "compareAndSetForMigration").mockResolvedValueOnce(false);
    await expect(resumeLocalRotation(owner, newKey, credential.new_salt)).rejects.toThrow("writing generation changed");
    expect(records.get(journalSlot)).toBe(before);
  });

  it("tolerates a queue removed between enumeration and its snapshot read", async () => {
    const slot = "mindpattern/queue.v1.items.removed";
    vi.spyOn(kv, "keys").mockResolvedValueOnce([slot]);
    await stageLocalRotation(owner, oldKey, newKey, credential);
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    expect(await hasLocalRotation(owner)).toBe(false);
  });

  it("does not block this account's migration when another account changes its own queue", async () => {
    const slot = "mindpattern/queue.v1.items.other";
    records.set(slot, JSON.stringify([{ userId: "another-owner", blobB64: "other ciphertext" }]));
    await stageLocalRotation(owner, oldKey, newKey, credential);
    records.set(slot, JSON.stringify([{ userId: "another-owner", blobB64: "new other ciphertext" }]));
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    expect(JSON.parse(records.get(slot)!)[0].blobB64).toBe("new other ciphertext");
    expect(await hasLocalRotation(owner)).toBe(false);
  });

  it("recovers a checkpoint with only the pre-migration generation field missing", async () => {
    await installJournal({ generationAfter: await newWriteGeneration(owner, newKey) });
    await resumeLocalRotation(owner, newKey, credential.new_salt);
    expect(await hasLocalRotation(owner)).toBe(false);
  });
});
