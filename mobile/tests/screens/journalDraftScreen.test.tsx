import { runTestControl } from "../helpers/testControl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { AppState, Alert } from "react-native";
vi.mock("../../src/api/client", async importOriginal => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ...actual, ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});
vi.mock("../../src/store", async importOriginal => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ activeDays: 0, unlockDays: 30, touchActivity: vi.fn(), refreshActiveDays: vi.fn() }) };
});
vi.mock("../../src/moodLog", async importOriginal => {
  const actual = await importOriginal<typeof import("../../src/moodLog")>();
  return { ...actual, recordMood: vi.fn(async () => {}), localStreak: vi.fn(async () => 0), recentMoods: vi.fn(async () => []) };
});
vi.mock("../../src/offlineQueue", () => ({
  prepareQueueRekey: vi.fn(async () => []), pendingEntryIds: vi.fn(async () => []), abortInFlightFlush: vi.fn(),
  enqueue: vi.fn(async () => {}), flushQueue: vi.fn(async () => 0), QueueFullError: class extends Error {}, QueueAbandonedError: class extends Error {},
}));
import { api } from "../../src/api/client";
import { resetApi } from "../helpers/apiMock";
import storage from "../helpers/storageMock";
import { EntryScreen } from "../../src/screens/EntryScreen";
import { vault } from "../../src/vault";
import { takeStashedDraft, stashDraft } from "../../src/store";
import { journalDraftScope, saveJournalDraft, newJournalDraft, loadJournalDraft, waitJournalDraftWrites, __resetJournalDraftRuntimeForTests, type JournalDraftScope } from "../../src/journalDraft";
import { __resetLocalKeyLifecycleForTests } from "../../src/localRekey";
import { changeLocalSessionOwner, freezeLocalKeyWrites, installLocalDataKey } from "../../src/localWriteGuard";
import { decryptEntry } from "../../src/crypto/journalCrypto";
import { render as renderRaw, flush, act, typeInto, pressLabel, firePress, inputByPlaceholder, touchableByLabel, textOf } from "../helpers/rtr";
const user = "user-1", nav = { navigate: vi.fn() }, placeholder = "What's going on today?";
let key: Buffer, scope: JournalDraftScope;
const roots: Awaited<ReturnType<typeof renderRaw>>[] = [];
async function render() { const root = await renderRaw(<EntryScreen navigation={nav} />); roots.push(root); await flush(); return root; }
async function close(root: Awaited<ReturnType<typeof render>>) { await act(async () => root.unmount()); await waitJournalDraftWrites(); }
async function background() {
  await act(async () => { for (const [, cb] of AppState.addEventListener.mock.calls) cb("background"); await waitJournalDraftWrites(); });
  await flush();
}
const value = (root: Awaited<ReturnType<typeof render>>) => inputByPlaceholder(root, placeholder).props.value;
beforeEach(async () => {
  vi.restoreAllMocks(); await waitJournalDraftWrites(); runTestControl(__resetJournalDraftRuntimeForTests); runTestControl(__resetLocalKeyLifecycleForTests);
  storage.__reset(); resetApi(api as never); AppState.addEventListener.mockClear(); Alert.alert.mockClear();
  takeStashedDraft(user); vault.lock(); key = Buffer.alloc(32, 7);
  vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: key }, user); scope = await journalDraftScope(user);
});
afterEach(async () => {
  vi.restoreAllMocks(); await act(async () => { for (const root of roots.splice(0)) root.unmount(); });
  await waitJournalDraftWrites(); takeStashedDraft(user);
});
describe("EntryScreen persistent typed journal draft", () => {
  it("does not adopt a replacement account while the submit's first owner lookup is suspended", async () => {
    const root = await render(); await typeInto(root, placeholder, "old account private words");
    let release!: () => void;
    vi.mocked(api.getUserId).mockImplementationOnce(async () => { await new Promise<void>(resolve => { release = resolve; }); return "user-2"; });
    await firePress(root, "Save entry"); await flush(); expect(release).toBeTypeOf("function");
    changeLocalSessionOwner("user-2");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 3), dataKey: Buffer.alloc(32, 8) }, "user-2");
    await act(async () => release()); await flush();
    expect(api.createEntry).not.toHaveBeenCalled(); expect(value(root)).toBe("old account private words");
  });
  it("refuses an old-key producer delayed in draft backup across a completed key-generation transition", async () => {
    installLocalDataKey(user, key);
    const root = await render(); await typeInto(root, placeholder, "preserve these unsent words");
    const original = storage.getItem; let release!: () => void; let blocked = false;
    const gate = vi.spyOn(storage, "getItem").mockImplementation(async slot => {
      if (slot === scope.slot && !blocked) { blocked = true; await new Promise<void>(resolve => { release = resolve; }); }
      return original(slot);
    });
    await firePress(root, "Save entry"); await flush(); expect(release).toBeTypeOf("function");
    freezeLocalKeyWrites(user); installLocalDataKey(user, Buffer.alloc(32, 8));
    await act(async () => release()); await flush(); gate.mockRestore();
    expect(api.createEntry).not.toHaveBeenCalled(); expect(value(root)).toBe("preserve these unsent words");
    expect(Alert.alert).toHaveBeenCalled();
  });
  it("restores encrypted text and every optional check-in after process restart, independent of the RAM stash", async () => {
    const root = await render(); await typeInto(root, placeholder, "Unfinished words before process death");
    await pressLabel(root, "Add details (optional)"); await pressLabel(root, "Light"); await pressLabel(root, "Energized");
    await pressLabel(root, "Rested"); await pressLabel(root, "work"); await background();
    expect(textOf(root)).toContain("Encrypted draft saved on this device");
    const draft = (await loadJournalDraft(key, scope))!.draft;
    expect(draft).toMatchObject({ text: value(root), mood: 1, energy: 1, sleep: 5, tags: ["work"] });
    await close(root); takeStashedDraft(user); runTestControl(__resetJournalDraftRuntimeForTests);
    const next = await render(); expect(value(next)).toBe(draft.text);
    await pressLabel(next, "Details added:");
    for (const label of ["Light", "Energized", "Rested"]) expect(touchableByLabel(next, label).props.accessibilityState.selected).toBe(true);
    expect(touchableByLabel(next, "work").props.accessibilityState.checked).toBe(true);
  });
  it("backs up the latest revision after debounce and does not claim saved while a write is pending", async () => {
    const root = await render();
    await typeInto(root, placeholder, "pending draft"); expect(textOf(root)).toContain("Backing up this draft");
    expect(textOf(root)).not.toContain("Encrypted draft saved on this device");
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 350)); });
    expect((await loadJournalDraft(key, scope))?.draft.text).toBe("pending draft");
    expect(textOf(root)).toContain("Encrypted draft saved on this device");
  });
  it("reports failed disk backup, retains the old cipher and retries the fresh editor rather than replacing it", async () => {
    const old = { ...newJournalDraft(), revision: 1, text: "old backup" }; await saveJournalDraft(key, scope, old);
    const before = await storage.getItem(scope.slot); const root = await render();
    await typeInto(root, placeholder, "new words not yet backed up");
    const original = storage.setItem;
    const fail = vi.spyOn(storage, "setItem").mockImplementation(async (slot, raw) => { if (slot === scope.slot) throw new Error("disk full"); return original(slot, raw); });
    await background(); expect(value(root)).toBe("new words not yet backed up");
    expect(textOf(root)).toContain("Draft backup failed"); expect(await storage.getItem(scope.slot)).toBe(before);
    fail.mockRestore(); await pressLabel(root, "Retry draft backup"); await flush();
    expect((await loadJournalDraft(key, scope))?.draft.text).toBe("new words not yet backed up");
    expect(textOf(root)).toContain("Encrypted draft saved on this device");
  });
  it("a late hydration cannot clobber fresh typing/picks; explicitly keeping the editor replaces the exact prior copy", async () => {
    const old = { ...newJournalDraft(), revision: 1, text: "recoverable older text", mood: -1 }; await saveJournalDraft(key, scope, old);
    const original = storage.getItem; let release: (() => void) | undefined;
    const gate = vi.spyOn(storage, "getItem").mockImplementation(async slot => {
      if (slot === scope.slot && !release) await new Promise<void>(resolve => { release = resolve; });
      return original(slot);
    });
    const root = await render(); await typeInto(root, placeholder, "fresh typing while disk read waits");
    await pressLabel(root, "Add details (optional)"); await pressLabel(root, "Light");
    await act(async () => release?.()); await flush(); gate.mockRestore();
    expect(value(root)).toBe("fresh typing while disk read waits"); expect(touchableByLabel(root, "Light").props.accessibilityState.selected).toBe(true);
    expect(textOf(root)).toContain("A saved draft was found");
    await pressLabel(root, "Back up current editor instead"); await flush();
    expect((await loadJournalDraft(key, scope))?.draft).toMatchObject({ text: value(root), mood: 1 });
  });
  it("an explicit restore choice restores the complete prior draft instead of mixing editor generations", async () => {
    const old = { ...newJournalDraft(), revision: 2, text: "restore these words", mood: -1, energy: -1, sleep: 5, tags: ["rest"] };
    await saveJournalDraft(key, scope, old); const original = storage.getItem; let release: (() => void) | undefined;
    const gate = vi.spyOn(storage, "getItem").mockImplementation(async slot => {
      if (slot === scope.slot && !release) await new Promise<void>(resolve => { release = resolve; }); return original(slot);
    });
    const root = await render(); await typeInto(root, placeholder, "replaceable fresh editor");
    await act(async () => release?.()); await flush(); gate.mockRestore();
    await pressLabel(root, "Restore saved draft"); expect(value(root)).toBe(old.text);
    await pressLabel(root, "Details added:"); expect(touchableByLabel(root, "Heavy").props.accessibilityState.selected).toBe(true);
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(old);
  });
  it("a read failure retains ciphertext and fresh edits; retry offers a choice rather than silently overwriting either", async () => {
    const old = { ...newJournalDraft(), revision: 1, text: "last known backup" }; await saveJournalDraft(key, scope, old);
    const before = await storage.getItem(scope.slot), original = storage.getItem;
    const fail = vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === scope.slot) throw new Error("read failure"); return original(slot); });
    const root = await render(); expect(textOf(root)).toContain("could not be read");
    await typeInto(root, placeholder, "fresh unbacked words"); await background();
    fail.mockRestore(); expect(await storage.getItem(scope.slot)).toBe(before);
    await pressLabel(root, "Retry draft backup"); await flush();
    expect(value(root)).toBe("fresh unbacked words"); expect(textOf(root)).toContain("A saved draft was found");
  });
  it("unreadable stored ciphertext is retained across edits and retry without a false backup claim", async () => {
    await storage.setItem(scope.slot, "damaged ciphertext"); const root = await render();
    await typeInto(root, placeholder, "fresh words with unreadable old draft"); await background();
    expect(await storage.getItem(scope.slot)).toBe("damaged ciphertext");
    await pressLabel(root, "Retry draft backup"); await flush();
    expect(textOf(root)).toContain("this editor is not backed up yet"); expect(value(root)).toContain("fresh words");
  });
  it("a late entry-save ACK retains newer typed text and structured picks both on screen and after restart", async () => {
    let release: (() => void) | undefined;
    vi.mocked(api.createEntry).mockImplementation(() => new Promise(resolve => { release = () => resolve({} as never); }));
    const root = await render(); await typeInto(root, placeholder, "the snapshot that is saved");
    await pressLabel(root, "Add details (optional)"); await pressLabel(root, "Heavy"); await firePress(root, "Save entry"); await flush();
    await typeInto(root, placeholder, "newer unfinished words during upload"); await pressLabel(root, "Light"); await pressLabel(root, "Energized"); await background();
    await act(async () => release?.()); await flush();
    expect(value(root)).toBe("newer unfinished words during upload");
    expect(touchableByLabel(root, "Light").props.accessibilityState.selected).toBe(true);
    const call = vi.mocked(api.createEntry).mock.calls[0];
    expect(decryptEntry({ dataKey: key }, user, call[0], call[1], 1)).toMatchObject({ text: "the snapshot that is saved", sentiment: -1 });
    expect((await loadJournalDraft(key, scope))?.draft).toMatchObject({ text: value(root), mood: 1, energy: 1 });
    await close(root); takeStashedDraft(user); runTestControl(__resetJournalDraftRuntimeForTests);
    expect(value(await render())).toBe("newer unfinished words during upload");
  });
  it("ACK clears only a matching revision after durable save, so restart does not offer a duplicate draft", async () => {
    const root = await render(); await typeInto(root, placeholder, "successfully acknowledged editor"); await background();
    expect(await loadJournalDraft(key, scope)).not.toBeNull(); await pressLabel(root, "Save entry"); await flush();
    expect(value(root)).toBe(""); expect(await loadJournalDraft(key, scope)).toBeNull();
    await close(root); takeStashedDraft(user); runTestControl(__resetJournalDraftRuntimeForTests);
    expect(value(await render())).toBe("");
  });
  it("an unchanged text value with a newer mood revision is not cleared by the older save", async () => {
    let release: (() => void) | undefined;
    vi.mocked(api.createEntry).mockImplementation(() => new Promise(resolve => { release = () => resolve({} as never); }));
    const root = await render(); await typeInto(root, placeholder, "same words with a later check-in");
    await pressLabel(root, "Add details (optional)"); await pressLabel(root, "Heavy"); await firePress(root, "Save entry"); await flush();
    await pressLabel(root, "Light"); await background(); await act(async () => release?.()); await flush();
    expect(value(root)).toBe("same words with a later check-in");
    expect((await loadJournalDraft(key, scope))?.draft.mood).toBe(1);
    expect(touchableByLabel(root, "Light").props.accessibilityState.selected).toBe(true);
  });
  it("backing up an older save snapshot cannot cancel a newer edit's debounce", async () => {
    const root = await render(); await typeInto(root, placeholder, "older submitted snapshot");
    let releaseOwner: (() => void) | undefined, releaseCreate: (() => void) | undefined;
    vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { releaseOwner = () => resolve(user); }));
    vi.mocked(api.createEntry).mockImplementation(() => new Promise(resolve => { releaseCreate = () => resolve({} as never); }));
    await firePress(root, "Save entry"); await typeInto(root, placeholder, "new edit before account lookup finished");
    await act(async () => releaseOwner?.()); await flush();
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 350)); });
    expect((await loadJournalDraft(key, scope))?.draft.text).toBe("new edit before account lookup finished");
    expect(textOf(root)).toContain("Encrypted draft saved on this device");
    await act(async () => releaseCreate?.()); await flush(); expect(value(root)).toBe("new edit before account lookup finished");
  });
  it("a hydration response captured before a completed save cannot restore a now-cleared editor", async () => {
    const original = storage.getItem; let release: (() => void) | undefined;
    const gate = vi.spyOn(storage, "getItem").mockImplementation(async slot => {
      if (slot === scope.slot && !release) {
        const captured = await original(slot);
        await new Promise<void>(resolve => { release = resolve; }); return captured;
      }
      return original(slot);
    });
    const root = await render(); await typeInto(root, placeholder, "saved before initial read resolves");
    await pressLabel(root, "Save entry"); expect(value(root)).toBe("");
    await act(async () => release?.()); await flush(); gate.mockRestore();
    expect(value(root)).toBe(""); expect(await loadJournalDraft(key, scope)).toBeNull();
    await typeInto(root, placeholder, "a fresh editor after save"); await background();
    expect((await loadJournalDraft(key, scope))?.draft.text).toBe("a fresh editor after save");
  });
  it("disk cleanup failure leaves the saved entry acknowledged but warns that its old draft may reappear", async () => {
    const root = await render(); await typeInto(root, placeholder, "entry that will save"); await background();
    const original = storage.removeItem;
    const fail = vi.spyOn(storage, "removeItem").mockImplementation(async slot => { if (slot === scope.slot) throw new Error("disk unavailable"); return original(slot); });
    await pressLabel(root, "Save entry"); await flush();
    expect(textOf(root)).toContain("Saved ✓"); expect(textOf(root)).toContain("old draft could not be removed");
    fail.mockRestore(); expect(await storage.getItem(scope.slot)).not.toBeNull();
  });
  it("unmount flush snapshots its private key before a lock zeroizes the vault", async () => {
    const root = await render(); await typeInto(root, placeholder, "words before an immediate lock");
    const originalKey = Buffer.from(key); await act(async () => { root.unmount(); vault.lock(); }); await waitJournalDraftWrites();
    expect((await loadJournalDraft(originalKey, scope))?.draft.text).toBe("words before an immediate lock");
  });
  it.each(["disk-first", "RAM-first"])("retains newer RAM text and every changed check-in after failed backup and lock, with %s hydration", async order => {
    const root = await render(); await typeInto(root, placeholder, "older recoverable disk draft");
    await pressLabel(root, "Add details (optional)"); await pressLabel(root, "Heavy"); await pressLabel(root, "Drained");
    await pressLabel(root, "Rough"); await pressLabel(root, "work"); await background();
    const oldRaw = await storage.getItem(scope.slot);
    await typeInto(root, placeholder, "newer RAM words after failed backup");
    await pressLabel(root, "Light"); await pressLabel(root, "Energized"); await pressLabel(root, "Rested");
    await pressLabel(root, "work"); await pressLabel(root, "family");
    const originalWrite = storage.setItem;
    const fail = vi.spyOn(storage, "setItem").mockImplementation(async (slot, raw) => { if (slot === scope.slot) throw new Error("backup failed"); return originalWrite(slot, raw); });
    await background(); expect(textOf(root)).toContain("Draft backup failed"); await close(root); fail.mockRestore();
    expect(await storage.getItem(scope.slot)).toBe(oldRaw);
    const originalKey = Buffer.from(key); vault.lock(); key = originalKey;
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32), dataKey: key }, user);
    let release!: () => void;
    if (order === "disk-first") {
      let owners = 0;
      vi.mocked(api.getUserId).mockImplementation(async () => {
        if (++owners === 2) await new Promise<void>(resolve => { release = resolve; }); return user;
      });
    } else {
      const originalRead = storage.getItem; let blocked = false;
      vi.spyOn(storage, "getItem").mockImplementation(async slot => {
        if (slot === scope.slot && !blocked) { blocked = true; await new Promise<void>(resolve => { release = resolve; }); }
        return originalRead(slot);
      });
    }
    const next = await render();
    expect(value(next)).toBe(order === "disk-first" ? "older recoverable disk draft" : "newer RAM words after failed backup");
    await act(async () => release()); await flush();
    expect(value(next)).toBe("newer RAM words after failed backup"); expect(textOf(next)).toContain("A saved draft was found");
    await pressLabel(next, "Details added:");
    for (const label of ["Light", "Energized", "Rested"]) expect(touchableByLabel(next, label).props.accessibilityState.selected).toBe(true);
    expect(touchableByLabel(next, "family").props.accessibilityState.checked).toBe(true);
    expect(touchableByLabel(next, "work").props.accessibilityState.checked).toBe(false);
    expect(await storage.getItem(scope.slot)).toBe(oldRaw);
    await pressLabel(next, "Back up current editor instead"); await flush();
    expect((await loadJournalDraft(key, scope))?.draft).toMatchObject({ text: "newer RAM words after failed backup", mood: 1, energy: 1, sleep: 5, tags: ["family"] });
  });
  it.each(["restore", "keep"])("offers an explicit %s choice when an earlier complete RAM editor arrives after new typing", async choice => {
    const previous = { ...newJournalDraft(), revision: 4, text: "earlier RAM editor", mood: -1, energy: -1, sleep: 5, tags: ["rest"] };
    stashDraft(user, previous.text, previous, scope.origin);
    let owners = 0, release!: () => void;
    vi.mocked(api.getUserId).mockImplementation(async () => {
      if (++owners === 2) await new Promise<void>(resolve => { release = resolve; }); return user;
    });
    const next = await render(); await typeInto(next, placeholder, "new live editing");
    await pressLabel(next, "Add details (optional)"); await pressLabel(next, "Light");
    await act(async () => release()); await flush();
    expect(value(next)).toBe("new live editing"); expect(textOf(next)).toContain("Your earlier editor is also available");
    await pressLabel(next, choice === "restore" ? "Restore earlier editor" : "Keep these new edits"); await background();
    expect(value(next)).toBe(choice === "restore" ? previous.text : "new live editing");
    expect((await loadJournalDraft(key, scope))?.draft.mood).toBe(choice === "restore" ? -1 : 1);
  });
});
