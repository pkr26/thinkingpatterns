import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildAad } from "../src/crypto/aad";
import { decrypt, encrypt, toBase64 } from "../src/crypto/core";
import { clearActiveDraft, loadActiveDraft, preserveActiveDraft, registerDraftSource, rewrapActiveDraft, saveActiveDraft, type EntryDraft } from "../src/entryDraft";
import { kv, setKvBackendForTests, StorageReadError } from "../src/kvstore";
import { vault } from "../src/vault";
import { observeSecretCopies } from "./helpers/secretCustody";
import { displayError } from "../src/errors";

vi.mock("../src/crypto/core", async (original) => {
  const actual = await original<typeof import("../src/crypto/core")>();
  return { ...actual, decrypt: vi.fn(actual.decrypt), encrypt: vi.fn(actual.encrypt) };
});

const owner = "draft-contract-owner";
let dataKey: Uint8Array<ArrayBuffer>;
const slot = `mindpattern.draft.active.${owner}`;
const valid: EntryDraft = { text: "private writing", mood: null, energy: null, sleep: null, tags: [] };
let store: Map<string, string>;
let removeSource: (() => void) | undefined;

beforeEach(() => {
  store = new Map();
  dataKey = new Uint8Array(new ArrayBuffer(32)).fill(17);
  setKvBackendForTests({
    async getItem(key) { return store.get(key) ?? null; },
    async setItem(key, value) { store.set(key, value); },
    async removeItem(key) { store.delete(key); },
    async keys() { return [...store.keys()]; },
  });
  vault.unlock({ authKey: dataKey, dataKey }, owner);
  removeSource = registerDraftSource(() => null);
  vi.mocked(decrypt).mockClear();
  vi.mocked(encrypt).mockClear();
});
afterEach(() => {
  removeSource?.();
  registerDraftSource(() => null)();
  vault.lock();
  setKvBackendForTests(null);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function installRecord(value: unknown): Promise<string> {
  const ciphertext = toBase64(await encrypt(dataKey, new TextEncoder().encode(JSON.stringify(value)), buildAad("draft", owner)));
  await kv.setItem(slot, ciphertext);
  return ciphertext;
}

describe("encrypted draft public storage contract", () => {
  it.each([
    { mood: 0 }, { energy: 0 }, { sleep: 0 }, { tags: ["work"] },
  ])("retains a structured check-in even when its text is blank: %j", async (fields) => {
    const draft = { ...valid, text: "  ", ...fields };
    await saveActiveDraft(dataKey, owner, draft);
    expect(await loadActiveDraft(dataKey, owner)).toEqual(draft);
  });

  it("accepts the documented text and tag boundaries", async () => {
    const draft = { ...valid, text: "a".repeat(100_000), tags: Array.from({ length: 200 }, () => "work"), mood: 0, energy: -1, sleep: 1 };
    await installRecord(draft);
    expect(await loadActiveDraft(dataKey, owner)).toEqual(draft);
  });

  it.each([
    null, true, 42, "text", [], {},
    { ...valid, text: 42 }, { ...valid, text: null }, { ...valid, text: "x".repeat(100_001) },
    { ...valid, mood: "happy" }, { ...valid, energy: false }, { ...valid, sleep: {} },
    { text: "writing", energy: null, sleep: null, tags: [] },
    { text: "writing", mood: null, sleep: null, tags: [] },
    { text: "writing", mood: null, energy: null, tags: [] },
    { ...valid, tags: "work" }, { ...valid, tags: null }, { ...valid, tags: [42] },
    { ...valid, tags: Array.from({ length: 201 }, () => "work") },
  ])("rejects authenticated invalid draft shape #%# without deleting recoverable ciphertext", async (record) => {
    const ciphertext = await installRecord(record);
    await expect(loadActiveDraft(dataKey, owner)).rejects.toBeInstanceOf(StorageReadError);
    expect(await kv.getItem(slot)).toBe(ciphertext);
  });

  it("clears the decrypt API's returned plaintext after successful restoration and validation failure", async () => {
    for (const record of [valid, { ...valid, mood: "invalid" }]) {
      await installRecord(record);
      try { await loadActiveDraft(dataKey, owner); } catch (error) { expect(error).toBeInstanceOf(StorageReadError); }
      const result = vi.mocked(decrypt).mock.results.at(-1)!;
      const plaintext = await result.value as Uint8Array;
      expect(plaintext.length).toBeGreaterThan(0);
      expect(plaintext.every((byte) => byte === 0)).toBe(true);
    }
  });

  it.each(["{", '{"text":"writing","mood":1e400,"energy":null,"sleep":null,"tags":[]}'])
    ("retains authenticated malformed JSON or an overflowing numeric check-in", async (raw) => {
      const ciphertext = toBase64(await encrypt(dataKey, new TextEncoder().encode(raw), buildAad("draft", owner)));
      await kv.setItem(slot, ciphertext);
      await expect(loadActiveDraft(dataKey, owner)).rejects.toBeInstanceOf(StorageReadError);
      expect(await kv.getItem(slot)).toBe(ciphertext);
    });

  it("exposes the underlying restoration failure as the public storage error cause", async () => {
    await installRecord({ ...valid, tags: [false] });
    try { await loadActiveDraft(dataKey, owner); throw new Error("expected unreadable draft"); }
    catch (error) {
      expect(error).toBeInstanceOf(StorageReadError);
      expect((error as StorageReadError).cause).toMatchObject({ message: "Stored draft shape is invalid." });
      expect(displayError(error, "Unable to restore writing")).toBe("A saved draft could not be authenticated or restored. Retry with the correct account key before changing stored writing.");
    }
  });

  it("unmounting an older editor does not unregister the current editor, and unmounting the current editor preserves the parked draft", async () => {
    const unmountOld = registerDraftSource(() => ({ ...valid, text: "older" }));
    let currentText = "current";
    const unmountCurrent = registerDraftSource(() => ({ ...valid, text: currentText }));
    unmountOld();
    await preserveActiveDraft();
    expect((await loadActiveDraft(dataKey, owner))?.text).toBe("current");
    unmountCurrent();
    currentText = "retired editor state";
    await preserveActiveDraft();
    expect((await loadActiveDraft(dataKey, owner))?.text).toBe("current");
  });

  it("clears the key and plaintext passed to the encryption API after storing a draft", async () => {
    await saveActiveDraft(dataKey, owner, valid);
    const [key, plaintext] = vi.mocked(encrypt).mock.calls[0]!;
    expect(key.every((byte) => byte === 0)).toBe(true);
    expect(plaintext.every((byte) => byte === 0)).toBe(true);
    expect(dataKey.some((byte) => byte !== 0)).toBe(true);
    expect(await loadActiveDraft(dataKey, owner)).toEqual(valid);
  });

  it("creates no durable metadata or encrypted record without a live editor or verified owner", async () => {
    await preserveActiveDraft();
    expect(await kv.keys()).toEqual([]);
    registerDraftSource(() => valid);
    vault.unlock({ authKey: dataKey, dataKey });
    await preserveActiveDraft();
    expect(await kv.keys()).toEqual([]);
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("does not touch a parked record when the editor returns undefined or the vault is locked", async () => {
    await saveActiveDraft(dataKey, owner, valid);
    const ciphertext = await kv.getItem(slot);
    registerDraftSource(() => undefined);
    await preserveActiveDraft();
    expect(await kv.getItem(slot)).toBe(ciphertext);
    registerDraftSource(() => ({ ...valid, text: "locked editor" }));
    vault.lock();
    await preserveActiveDraft();
    expect(await kv.getItem(slot)).toBe(ciphertext);
  });

  it("rotation of an absent draft leaves storage empty", async () => {
    await rewrapActiveDraft(dataKey, new Uint8Array(new ArrayBuffer(32)).fill(23), owner);
    expect(await loadActiveDraft(dataKey, owner)).toBeNull();
    expect(await kv.keys()).toEqual([]);
    await clearActiveDraft(owner);
  });
  it("clears parked writing when an empty or whitespace-only editor is deliberately saved", async () => {
    for (const text of ["", " \t\n "]) {
      await saveActiveDraft(dataKey, owner, valid);
      await saveActiveDraft(dataKey, owner, { text, mood: null, energy: null, sleep: null, tags: [] });
      expect(await loadActiveDraft(dataKey, owner)).toBeNull(); expect(store.has(slot)).toBe(false);
    }
  });
  it("clears a real parked record and re-seals nonempty writing under a replacement key", async () => {
    await saveActiveDraft(dataKey, owner, valid); await clearActiveDraft(owner); expect(await loadActiveDraft(dataKey, owner)).toBeNull();
    await saveActiveDraft(dataKey, owner, valid); const incoming = new Uint8Array(32).fill(23);
    await rewrapActiveDraft(dataKey, incoming, owner); expect(await loadActiveDraft(incoming, owner)).toEqual(valid);
    await expect(loadActiveDraft(dataKey, owner)).rejects.toBeInstanceOf(StorageReadError);
  });
  it("serializes a successful clear behind a suspended seal so a saved entry cannot reappear as a draft", async () => {
    let entered!: () => void, release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; }), blocked = new Promise<void>(resolve => { release = resolve; });
    const actualEncrypt = vi.mocked(encrypt).getMockImplementation()!;
    vi.mocked(encrypt).mockImplementationOnce(async (...args) => { entered(); await blocked; return actualEncrypt(...args); });
    const saving = saveActiveDraft(dataKey, owner, valid); await started; const clearing = clearActiveDraft(owner);
    // Suspend the real crypto operation, before its storage write is queued.
    // A clear must wait for that seal, including on an IndexedDB backend
    // which would independently serialize already-created transactions.
    let cleared = false; void clearing.then(() => { cleared = true; });
    await new Promise(resolve => setTimeout(resolve, 10));
    try { expect(cleared).toBe(false); } finally { release(); }
    await Promise.all([saving, clearing]); expect(store.has(slot)).toBe(false);
  });
  it.each([false, true])("releases every owned physical copy of the caller secret after live draft preservation settles: failure=%s", async fail => {
    const original = dataKey.slice(); await saveActiveDraft(dataKey, owner, valid); const previous = store.get(slot);
    registerDraftSource(() => ({ ...valid, text: "Writing when the session locks" }));
    if (fail) vi.spyOn(kv, "setItem").mockRejectedValue(new Error("quota"));
    const { copies } = await observeSecretCopies(dataKey, () => preserveActiveDraft());
    expect(copies.length).toBeGreaterThan(0); copies.forEach(secret => expect(secret).toEqual(new Uint8Array(secret.length)));
    expect(dataKey).toEqual(original);
    if (fail) expect(store.get(slot)).toBe(previous);
    else expect((await loadActiveDraft(dataKey, owner))?.text).toBe("Writing when the session locks");
  });
});
