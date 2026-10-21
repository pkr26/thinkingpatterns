import { setImmediate as nextTurn } from "node:timers";
import { afterEach, expect, it, vi } from "vitest";
import type { Bytes } from "../src/crypto/core";
import { clearActiveDraft, preserveActiveDraft, registerDraftSource, saveActiveDraft, type EntryDraft } from "../src/entryDraft";
import { kv, newWriteGeneration, setKvBackendForTests, StorageCommitError, writeGenerationKey } from "../src/kvstore";
import { vault } from "../src/vault";

const KEY = new Uint8Array(new ArrayBuffer(32)).fill(73);
const DRAFT: EntryDraft = { text: "synthetic writing awaiting local storage", mood: 0, energy: -1, sleep: null, tags: ["work"] };
let release: (() => void) | undefined;
let dispose: (() => void) | undefined;
let predecessor: Promise<void> | undefined;
let saving: Promise<void> | undefined;
let capture: Promise<unknown> | undefined;
const setup = (message: string, cause?: unknown): Error => new Error("SetupError: rejected draft permit: " + message, { cause });
async function completed<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(label + " did not finish")), 5000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
const turn = (): Promise<void> => new Promise(resolve => nextTurn(resolve));
afterEach(async () => {
  try {
    release?.();
    if (predecessor) await completed(predecessor, "owned predecessor cleanup");
    if (saving) await completed(Promise.allSettled([saving]), "owned public save cleanup");
    if (capture) await completed(Promise.allSettled([capture]), "owned original capture cleanup");
  } finally {
    dispose?.(); dispose = undefined; release = undefined; predecessor = undefined; saving = undefined; capture = undefined;
    vi.restoreAllMocks(); vault.lock(); setKvBackendForTests(null);
  }
});

it.each(["direct save", "live preservation"] as const)("retires %s owning bytes after a rejected permit while an earlier clear remains held", async mode => {
  const owner = "draft-early-refusal-" + (mode === "direct save" ? "save" : "preserve");
  const slot = "mindpattern.draft.active." + owner, generation = writeGenerationKey(owner);
  const records = new Map([[slot, "previous retained synthetic ciphertext"]]);
  let entered!: () => void, open!: () => void;
  const enteredPromise = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { open = resolve; });
  let held = true, slotWrites = 0, generationReads = 0;
  release = () => { held = false; open(); };
  setKvBackendForTests({
    async getItem(name) { if (name === generation) generationReads++; return records.get(name) ?? null; },
    async setItem(name, value) { if (name === slot) slotWrites++; records.set(name, value); },
    async removeItem(name) { if (name === slot) { entered(); await gate; } records.delete(name); },
    async keys() { return [...records.keys()]; },
  });
  records.set(generation, await newWriteGeneration(owner, KEY));
  const permit = await kv.captureWritePermit(owner, KEY);
  const vaultDataKey = KEY.slice();
  vault.unlock({ authKey: KEY.slice(), dataKey: vaultDataKey }, owner);
  predecessor = clearActiveDraft(owner, permit);
  await completed(enteredPromise, "earlier public clear backend admission");
  // A real deletion marker rejects the next native key-bound capture. The
  // already admitted predecessor stays held until unconditional cleanup.
  const deleted = JSON.parse(records.get(generation)!);
  records.set(generation, JSON.stringify({ ...deleted, deleted: true }));
  let copiedKey: Bytes | undefined, payload: Uint8Array | undefined;
  let preservationKey: Uint8Array | undefined;
  const originalCapture = kv.captureWritePermit;
  const captureSpy = vi.spyOn(kv, "captureWritePermit").mockImplementation((...args) => {
    copiedKey = args[1];
    const original = originalCapture(...args);
    capture = original;
    // Observe but return the exact original Promise unchanged.
    void original.catch(() => undefined);
    return original;
  });
  const encode = TextEncoder.prototype.encode;
  vi.spyOn(TextEncoder.prototype, "encode").mockImplementation(function (this: TextEncoder, text?: string) {
    const original = encode.call(this, text);
    if (text === JSON.stringify(DRAFT)) payload = original;
    return original;
  });
  const set = Uint8Array.prototype.set;
  vi.spyOn(Uint8Array.prototype, "set").mockImplementation(function (this: Uint8Array, bytes: ArrayLike<number>, offset?: number) {
    set.call(this, bytes, offset);
    if (bytes === vaultDataKey) preservationKey = this;
  });
  dispose = registerDraftSource(() => DRAFT);
  saving = mode === "direct save" ? saveActiveDraft(KEY, owner, DRAFT) : preserveActiveDraft();
  let state: "pending" | "fulfilled" | "rejected" = "pending", rejection: unknown;
  void saving.then(() => { state = "fulfilled"; }, cause => { state = "rejected"; rejection = cause; });
  // This synchronous assertion makes the 04433 baseline fail directly:
  // its capture is inside the held chain, rather than relying on a timeout.
  expect(captureSpy).toHaveBeenCalledTimes(1);
  const original = capture;
  if (!original || !copiedKey || !payload) throw setup("actual capture or owned buffers were not observed");
  const result = await completed(Promise.allSettled([original]), "actual refused capture");
  expect(result[0]?.status).toBe("rejected");
  if (result[0]?.status !== "rejected") throw setup("deleted marker did not reject the original capture");
  expect(result[0].reason).toBeInstanceOf(StorageCommitError);
  await turn(); await turn();
  expect(held).toBe(true);
  expect(state).toBe(mode === "direct save" ? "rejected" : "fulfilled");
  if (mode === "direct save") expect(rejection).toBe(result[0].reason);
  expect([...copiedKey]).toEqual(Array(32).fill(0));
  expect(payload.every(byte => byte === 0)).toBe(true);
  if (mode === "live preservation") {
    expect(preservationKey).toBeDefined();
    expect([...(preservationKey ?? [])]).toEqual(Array(32).fill(0));
    expect([...vaultDataKey]).toEqual(Array(32).fill(73));
  }
  expect(generationReads).toBeGreaterThanOrEqual(2);
  expect(slotWrites).toBe(0);
  expect(records.get(slot)).toBe("previous retained synthetic ciphertext");
  expect([...KEY]).toEqual(Array(32).fill(73));
  release();
  await completed(predecessor, "released original predecessor");
  await completed(Promise.allSettled([saving]), "refused public operation drainage");
  await completed(clearActiveDraft(owner, permit), "subsequent clear after rejected chain member");
  expect(records.has(slot)).toBe(false);
});
