import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { setBaseUrl } from "../src/api/client";
import { JOURNAL_DRAFT_PREFIX, journalDraftScope, newJournalDraft, loadJournalDraft, saveJournalDraft, acknowledgeJournalDraft, clearJournalDraft, waitJournalDraftWrites, __resetJournalDraftRuntimeForTests, type JournalDraftScope } from "../src/journalDraft";
import { prepareLocalRekey, resumeLocalRekey, markLocalRekeyPhase, markAccountDeleted, __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { buildAad, encrypt } from "../src/crypto/envelope";
import { setSecureStoreBackend } from "../src/secureStore";
const user = "draft-owner", key = Buffer.alloc(32, 7), nextKey = Buffer.alloc(32, 9);
let scope: JournalDraftScope;
beforeEach(async () => {
  await waitJournalDraftWrites(); runTestControl(__resetJournalDraftRuntimeForTests); runTestControl(__resetLocalKeyLifecycleForTests);
  storage.__reset(); runTestControl(setSecureStoreBackend, null);
  await setBaseUrl("http://localhost:8000"); scope = await journalDraftScope(user);
});
afterEach(async () => { vi.restoreAllMocks(); await waitJournalDraftWrites(); });
const words = () => ({ ...newJournalDraft(), revision: 1, text: "Private unfinished journal", mood: -0.5, energy: 3, sleep: 4, tags: ["work", "friends"] });
describe("encrypted account/server-bound typed draft custody", () => {
  it("restores all editor fields after process restart, with neither plaintext nor key stored", async () => {
    const draft = words(); await saveJournalDraft(key, scope, draft);
    const raw = (await storage.getItem(scope.slot))!;
    expect(raw).not.toContain(draft.text); expect(raw).not.toContain(key.toString("base64"));
    runTestControl(__resetJournalDraftRuntimeForTests);
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(draft);
    expect(scope.slot.startsWith(JOURNAL_DRAFT_PREFIX)).toBe(true);
  });
  it("another account/server cannot authenticate a copied ciphertext", async () => {
    await saveJournalDraft(key, scope, words()); const raw = (await storage.getItem(scope.slot))!;
    const other = await journalDraftScope("other-owner");
    expect(await loadJournalDraft(key, other)).toBeNull();
    await storage.setItem(other.slot, raw);
    await expect(loadJournalDraft(key, other)).rejects.toThrow("retained");
    await setBaseUrl("http://localhost:9000"); const otherOrigin = await journalDraftScope(user);
    await storage.setItem(otherOrigin.slot, raw);
    await expect(loadJournalDraft(key, otherOrigin)).rejects.toThrow("retained");
    // Origin retirement removes every old-origin account family; the copied
    // ciphertext at the new origin remains retained for explicit recovery.
    expect(await storage.getItem(scope.slot)).toBeNull();
  });
  it("failed writes and reads retain the last recoverable ciphertext and support a real retry", async () => {
    const draft = words(); await saveJournalDraft(key, scope, draft); const before = await storage.getItem(scope.slot);
    const newer = { ...draft, revision: 2, text: "Newer unfinished journal" };
    const fail = vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("disk full"));
    await expect(saveJournalDraft(key, scope, newer)).rejects.toThrow("disk full"); fail.mockRestore();
    expect(await storage.getItem(scope.slot)).toBe(before);
    const read = vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("disk read failed"));
    await expect(loadJournalDraft(key, scope)).rejects.toThrow("disk read failed"); read.mockRestore();
    expect(await storage.getItem(scope.slot)).toBe(before);
    await saveJournalDraft(key, scope, newer);
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(newer);
  });
  it.each(["not an envelope", "", "e30="])("unreadable ciphertext %j cannot silently become or be overwritten by an empty draft", async raw => {
    await storage.setItem(scope.slot, raw);
    await expect(loadJournalDraft(key, scope)).rejects.toThrow("retained");
    await expect(saveJournalDraft(key, scope, words())).rejects.toThrow("retained");
    expect(await storage.getItem(scope.slot)).toBe(raw);
  });
  it("authenticated malformed JSON/schema remains recoverable rather than defaulting to blank", async () => {
    for (const data of ["not JSON", JSON.stringify({ ...words(), mood: 7 }), JSON.stringify({ ...words(), tags: [null] })]) {
      const raw = encrypt(key, Buffer.from(data), buildAad("journal-draft", user, scope.origin)).toString("base64");
      await storage.setItem(scope.slot, raw);
      await expect(loadJournalDraft(key, scope)).rejects.toThrow("retained");
      expect(await storage.getItem(scope.slot)).toBe(raw);
    }
  });
  it("old writes and late server ACKs preserve newer editor text and metadata", async () => {
    const saved = words(), newer = { ...saved, revision: 2, text: "New text while upload awaits", mood: 1, tags: ["family"] };
    await saveJournalDraft(key, scope, saved); await saveJournalDraft(key, scope, newer);
    expect(await saveJournalDraft(key, scope, saved)).toBe("superseded");
    expect(await acknowledgeJournalDraft(key, scope, saved.editorId, saved.revision)).toBe(false);
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(newer);
    expect(await acknowledgeJournalDraft(key, scope, newer.editorId, newer.revision)).toBe(true);
    expect(await loadJournalDraft(key, scope)).toBeNull();
    expect(await saveJournalDraft(key, scope, newer)).toBe("superseded");
    expect(await loadJournalDraft(key, scope)).toBeNull();
  });
  it("a pending stale write cannot resurrect an acknowledged editor", async () => {
    const draft = words();
    const queuedWrite = saveJournalDraft(key, scope, draft);
    const ack = acknowledgeJournalDraft(key, scope, draft.editorId, draft.revision);
    expect(await queuedWrite).toBe("superseded"); expect(await ack).toBe(true);
    expect(await loadJournalDraft(key, scope)).toBeNull();
  });
  it("equal revision retries are idempotent, while altered content at that revision fails closed", async () => {
    const draft = words(); await saveJournalDraft(key, scope, draft); const raw = await storage.getItem(scope.slot);
    expect(await saveJournalDraft(key, scope, draft)).toBe("saved"); expect(await storage.getItem(scope.slot)).toBe(raw);
    await expect(saveJournalDraft(key, scope, { ...draft, text: "changed without revision" })).rejects.toThrow("Another editor");
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(draft);
  });
  it("another editor needs explicit exact-ciphertext CAS; old ACK cannot remove its replacement", async () => {
    const older = words(); await saveJournalDraft(key, scope, older);
    const raw = (await storage.getItem(scope.slot))!, replacement = { ...words(), text: "Explicit current-editor choice" };
    await expect(saveJournalDraft(key, scope, replacement)).rejects.toThrow("Another editor");
    await expect(saveJournalDraft(key, scope, replacement, "different ciphertext")).rejects.toThrow("Another editor");
    await saveJournalDraft(key, scope, replacement, raw);
    expect(await acknowledgeJournalDraft(key, scope, older.editorId, older.revision)).toBe(false);
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(replacement);
    await clearJournalDraft(user);
    await expect(saveJournalDraft(key, scope, words(), raw)).rejects.toThrow("Another editor");
  });
  it("failed matching draft cleanup is surfaced and keeps its ciphertext", async () => {
    const draft = words(); await saveJournalDraft(key, scope, draft); const before = await storage.getItem(scope.slot);
    const fail = vi.spyOn(storage, "removeItem").mockRejectedValueOnce(new Error("cleanup unavailable"));
    await expect(acknowledgeJournalDraft(key, scope, draft.editorId, draft.revision)).rejects.toThrow("cleanup unavailable");
    fail.mockRestore(); expect(await storage.getItem(scope.slot)).toBe(before);
    expect(await acknowledgeJournalDraft(key, scope, draft.editorId, draft.revision)).toBe(true);
  });
  it("rejects invalid editor metadata, impossible scopes and malformed copied owners before storage", async () => {
    const draft = words();
    for (const patch of [{ v: 2 }, { editorId: "invalid" }, { revision: -1 }, { revision: NaN }, { text: "x".repeat(100001) }, { energy: Infinity }, { sleep: 0 }, { tags: Array(201).fill("tag") }]) {
      await expect(saveJournalDraft(key, scope, { ...draft, ...patch } as never)).rejects.toThrow("Invalid");
    }
    await expect(loadJournalDraft(key, { ...scope, userId: "other" })).rejects.toThrow("Invalid");
    expect(() => saveJournalDraft(key, { ...scope, origin: `${scope.origin}/` }, draft)).toThrow("Invalid");
    expect(await loadJournalDraft(key, scope)).toBeNull();
  });
  it("registered origin-bound draft rekeys only after confirmed credential commit, with its data intact", async () => {
    const draft = words(); await saveJournalDraft(key, scope, draft);
    await prepareLocalRekey(user, key, nextKey);
    await expect(resumeLocalRekey(user, nextKey)).rejects.toThrow("confirmed online");
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(draft);
    await markLocalRekeyPhase(user, "credential"); await resumeLocalRekey(user, nextKey);
    expect((await loadJournalDraft(nextKey, scope))?.draft).toEqual(draft);
    await expect(loadJournalDraft(key, scope)).rejects.toThrow("retained");
  });
  it("an erasure fence blocks late queued writes, then clears only that account/origin", async () => {
    const other = await journalDraftScope("another-account"); await saveJournalDraft(key, other, words());
    const draft = words(); await saveJournalDraft(key, scope, draft);
    const pending = saveJournalDraft(key, scope, { ...draft, revision: 2 });
    markAccountDeleted(user);
    await expect(pending).rejects.toThrow("deleted");
    await clearJournalDraft(user);
    expect(await loadJournalDraft(key, scope)).toBeNull(); expect(await loadJournalDraft(key, other)).not.toBeNull();
    expect(() => saveJournalDraft(key, scope, draft)).toThrow("deleted");
  });
  it("a late ACK racing rekey preparation cannot remove a staged draft or diverge its CAS", async () => {
    const draft = words(); await saveJournalDraft(key, scope, draft);
    const original = storage.getItem; let release: (() => void) | undefined;
    const gate = vi.spyOn(storage, "getItem").mockImplementation(async slot => {
      if (slot === scope.slot && !release) await new Promise<void>(resolve => { release = resolve; });
      return original(slot);
    });
    const ack = acknowledgeJournalDraft(key, scope, draft.editorId, draft.revision);
    const rejectedAck = expect(ack).rejects.toThrow("paused");
    await new Promise(resolve => setTimeout(resolve, 0));
    const rekey = prepareLocalRekey(user, key, nextKey);
    release?.(); await rejectedAck; await rekey; gate.mockRestore();
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(draft);
    expect(() => acknowledgeJournalDraft(key, scope, draft.editorId, draft.revision)).toThrow("paused");
    await markLocalRekeyPhase(user, "credential"); await resumeLocalRekey(user, nextKey);
    expect((await loadJournalDraft(nextKey, scope))?.draft).toEqual(draft);
    await acknowledgeJournalDraft(nextKey, scope, draft.editorId, draft.revision);
    expect(await loadJournalDraft(nextKey, scope)).toBeNull();
  });
});
