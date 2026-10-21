import { createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import { setImmediate as nextTurn } from "node:timers";
import { afterEach, expect, it } from "vitest";
import { clearActiveDraft, loadActiveDraft, preserveActiveDraft, registerDraftSource, saveActiveDraft, type EntryDraft } from "../src/entryDraft";
import { kv, setKvBackendForTests, type KvBackend, type WritePermit } from "../src/kvstore";
import { vault } from "../src/vault";

const KEY = new Uint8Array(new ArrayBuffer(32)).fill(73);
const DRAFT: EntryDraft = { text: "new private synthetic writing", mood: 0, energy: -1, sleep: null, tags: ["work"] };
const EARLIER: EntryDraft = { text: "earlier private synthetic writing", mood: 1, energy: null, sleep: 0, tags: [] };
let disposeSource: (() => void) | undefined;
let active: { release: () => void; operations: Promise<unknown>[] } | undefined;

function setup(message: string, cause?: unknown): Error { return new Error("SetupError: draft queue witness: " + message, { cause }); }
async function completion<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(label + " did not complete")), 5000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function drainOriginal(operations: Promise<unknown>[], label: string): Promise<void> {
  const results = await completion(Promise.allSettled(operations), label);
  const rejected = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
  if (rejected) throw setup("owned original operation rejected during cleanup: " + label, rejected.reason);
}
async function turn(): Promise<void> { await new Promise<void>(resolve => nextTurn(resolve)); }
function aad(owner: string): Buffer { return Buffer.from(JSON.stringify(["draft", owner]), "utf8"); }
function independentSeal(owner: string, draft: EntryDraft): string {
  const nonce = Buffer.alloc(12, 19), cipher = createCipheriv("aes-256-gcm", Buffer.from(KEY), nonce);
  cipher.setAAD(aad(owner)); const ciphertext = Buffer.concat([cipher.update(JSON.stringify(draft), "utf8"), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString("base64");
}
function independentOpen(owner: string, blob: string): unknown {
  const bytes = Buffer.from(blob, "base64"), decipher = createDecipheriv("aes-256-gcm", Buffer.from(KEY), bytes.subarray(0, 12));
  decipher.setAAD(aad(owner)); decipher.setAuthTag(bytes.subarray(-16));
  return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]).toString("utf8"));
}
function install(owner: string) {
  const slot = "mindpattern.draft.active." + owner, generation = "mindpattern.writeGeneration." + owner;
  const initial = independentSeal(owner, EARLIER);
  const tag = Buffer.from(hkdfSync("sha256", Buffer.from(KEY), Buffer.alloc(32), Buffer.from("mindpattern/local-write-generation/v1/" + owner), 32)).toString("base64");
  const store = new Map([[slot, initial], [generation, JSON.stringify({ v: 1, nonce: "18".repeat(16), deleted: false, keyTag: tag })]]);
  let entered!: () => void, release!: () => void, hold = false, heldGenerationReads = 0, authenticatedWrites = 0;
  const enteredPromise = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const backend: KvBackend = {
    async getItem(key) { if (key === generation && hold) { heldGenerationReads++; entered(); await gate; } return store.get(key) ?? null; },
    async setItem(key, value) { if (key === slot) { try { const actual = independentOpen(owner, value); if (JSON.stringify(actual) !== JSON.stringify(DRAFT)) throw setup("unexpected authored draft ciphertext"); authenticatedWrites++; } catch (error) { throw setup("new ciphertext failed independent native authentication", error); } } store.set(key, value); },
    async removeItem(key) { store.delete(key); },
    async keys() { return [...store.keys()]; },
  };
  setKvBackendForTests(backend);
  vault.unlock({ authKey: KEY.slice(), dataKey: KEY.slice() }, owner);
  return { owner, slot, initial, hold: () => { hold = true; }, release, enteredPromise, counts: () => ({ heldGenerationReads, authenticatedWrites }) };
}
async function capturePermit(owner: string): Promise<WritePermit> {
  try { return await completion(kv.captureWritePermit(owner, KEY), "actual initial permit"); }
  catch (error) { throw setup("actual original permit refused independent valid generation", error); }
}
afterEach(async () => {
  try { active?.release(); if (active) await drainOriginal(active.operations, "owned original operation cleanup"); }
  finally { active = undefined; disposeSource?.(); disposeSource = undefined; registerDraftSource(() => null)(); vault.lock(); setKvBackendForTests(null); }
});

it.each(["direct save", "live preservation"])("admits %s before a later clear while the actual generation read is pending", async mode => {
  const witness = install("draft-queue-" + (mode === "direct save" ? "save" : "preserve"));
  const permit = await capturePermit(witness.owner);
  // Fixture validity comes from the independent native authenticated bytes,
  // while the actual public reader consumes them before the held producer.
  expect(independentOpen(witness.owner, witness.initial)).toEqual(EARLIER);
  expect(await loadActiveDraft(KEY, witness.owner)).toEqual(EARLIER);
  witness.hold(); disposeSource = registerDraftSource(() => DRAFT);
  const saving = mode === "direct save" ? saveActiveDraft(KEY, witness.owner, DRAFT) : preserveActiveDraft();
  active = { release: witness.release, operations: [saving] };
  let clearing: Promise<void> | undefined, clearCompleted = false, clearError: unknown;
  try {
    await completion(witness.enteredPromise, "actual held generation backend read");
    clearing = clearActiveDraft(witness.owner, permit); active.operations.push(clearing);
    // Annotation only: the real public Promise is retained and awaited intact.
    void clearing.then(() => { clearCompleted = true; }, error => { clearError = error; });
    // Once the actual generation read is held, only already-ready JS Promise
    // continuations could advance an incorrectly admitted clear. Native turns
    // drain them without a timing delay or a timeout failure as an oracle.
    await turn(); await turn();
    if (clearError !== undefined) throw setup("later clear unexpectedly refused", clearError);

    expect(clearCompleted).toBe(false);
    expect(await kv.getItem(witness.slot)).toBe(witness.initial);
    witness.release();
    try { await completion(Promise.all([saving, clearing]), "actual public save and clear"); }
    catch (error) { throw setup("public producer rejected after release", error); }
    expect(witness.counts().authenticatedWrites).toBe(1);
    expect(await loadActiveDraft(KEY, witness.owner)).toBeNull();
    expect(await kv.getItem(witness.slot)).toBeNull();

  } finally {
    witness.release(); await drainOriginal([saving, ...(clearing ? [clearing] : [])], "all original operations after assertion");
  }
});

it("an admitted empty draft removes the slot inside its own chain without nesting a queued clear", async () => {
  const witness = install("draft-queue-empty");
  const saving = saveActiveDraft(KEY, witness.owner, { text: " \t\n", mood: null, energy: null, sleep: null, tags: [] });
  active = { release: witness.release, operations: [saving] };
  try { await completion(saving, "empty public draft clear"); } catch (error) { throw setup("empty-draft chain did not settle normally", error); }
  expect(await loadActiveDraft(KEY, witness.owner)).toBeNull();
  expect(witness.counts().authenticatedWrites).toBe(0);
});

it("the admitted nonempty draft remains independently authenticated and publicly restorable", async () => {
  const witness = install("draft-queue-positive");
  const saving = saveActiveDraft(KEY, witness.owner, DRAFT);
  active = { release: witness.release, operations: [saving] };
  try { await completion(saving, "nonempty public draft save"); } catch (error) { throw setup("positive public producer refused", error); }
  const blob = await kv.getItem(witness.slot); if (blob === null) throw setup("completed positive write missing");
  expect(independentOpen(witness.owner, blob)).toEqual(DRAFT);
  expect(await loadActiveDraft(KEY, witness.owner)).toEqual(DRAFT);
  expect(witness.counts().authenticatedWrites).toBe(1);
});
