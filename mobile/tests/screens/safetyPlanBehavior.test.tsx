import React from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Alert, AppState, BackHandler, TextInput, TouchableOpacity, emitAppState, emitBackPress } from "../helpers/rnMock";
import storage from "../helpers/storageMock";
import { render, act, flush, pressLabel, firePress, textOf, pressAlertButton } from "../helpers/rtr";
import { runTestControl } from "../helpers/testControl";
import { __resetLocalKeyLifecycleForTests, waitLocalWriteCommits } from "../../src/localWriteGuard";
vi.mock("../../src/api/client", async original => {
  const actual = await original<typeof import("../../src/api/client")>(); const { makeApiMock } = await import("../helpers/apiMock"); return { ...actual, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});
const touchActivity = vi.hoisted(() => vi.fn());
vi.mock("../../src/store", async original => ({ ...await original<typeof import("../../src/store")>(), useSession: () => ({ touchActivity }) }));
import { api } from "../../src/api/client";
import { SafetyPlanScreen } from "../../src/screens/SafetyPlanScreen";
import { vault } from "../../src/vault";
import { emptySafetyPlan, loadSafetyPlan, loadSafetyPlanDraft, saveSafetyPlanDraft } from "../../src/safetyPlan";
const owner = "user-1", key = Buffer.alloc(32, 7), labels = ["My warning signs", "Things I can do to cope", "People and places that help", "Who I can ask for help", "Professionals and services", "Making my environment safer"];
const nav = { goBack: vi.fn(), navigate: vi.fn(), dispatch: vi.fn(), addListener: vi.fn((_event: string, _handler: (event: any) => void) => vi.fn()) };
const roots: Awaited<ReturnType<typeof render>>[] = [];
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); runTestControl(__resetLocalKeyLifecycleForTests); Alert.alert.mockClear(); AppState.addEventListener.mockClear(); BackHandler.addEventListener.mockClear(); nav.goBack.mockClear(); nav.navigate.mockClear(); nav.dispatch.mockClear(); nav.addListener.mockClear(); vault.lock(); key.fill(7); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: key }, owner); vi.mocked(api.getUserId).mockResolvedValue(owner); });
afterEach(async () => { await act(async () => { for (const root of roots.splice(0)) root.unmount(); }); await waitLocalWriteCommits(); vi.useRealTimers(); vi.restoreAllMocks(); });
async function open() { const root = await render(<SafetyPlanScreen navigation={nav} />); roots.push(root); await flush(); return root; }
function input(root: Awaited<ReturnType<typeof open>>, label: string) { const node = root.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === label); if (!node) throw Error(`Missing plan field ${label}`); return node; }
async function edit(root: Awaited<ReturnType<typeof open>>, label: string, value: string) { await act(async () => { input(root, label).props.onChangeText(value); }); }

it("edits and saves each personal field without changing another field", async () => {
  const root = await open(); for (const [index, label] of labels.entries()) await edit(root, label, `Personal safety note ${index}`);
  await pressLabel(root, "Save my safety plan"); const plan = await loadSafetyPlan(key, owner);
  expect(plan).toEqual({ warningSigns: "Personal safety note 0", copingStrategies: "Personal safety note 1", peoplePlaces: "Personal safety note 2", askForHelp: "Personal safety note 3", professionals: "Personal safety note 4", environmentSafer: "Personal safety note 5" });
});
it("starts autosave at three hundred milliseconds and preserves the last edit", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "First unfinished note"); await act(async () => { await vi.advanceTimersByTimeAsync(299); });
  expect(await loadSafetyPlanDraft(key, owner)).toBeNull(); await edit(root, labels[0]!, "Second unfinished note"); await act(async () => { await vi.advanceTimersByTimeAsync(299); }); expect(await loadSafetyPlanDraft(key, owner)).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(1); }); await waitLocalWriteCommits(); expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("Second unfinished note"); expect(await loadSafetyPlan(key, owner)).toBeNull();
});
it.each(["active", "inactive", "background"])("flushes interruption drafts for native %s events according to visibility", async state => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Native interruption draft"); await act(async () => { emitAppState(state); }); await waitLocalWriteCommits();
  expect((await loadSafetyPlanDraft(key, owner))?.warningSigns ?? null).toBe(state === "active" ? null : "Native interruption draft");
});
it("Android back consumes a dirty editor, asks to discard, then removes the encrypted draft", async () => {
  const root = await open(); await edit(root, labels[0]!, "Unsaved back note"); await act(async () => { emitAppState("background"); }); await waitLocalWriteCommits();
  expect(await loadSafetyPlanDraft(key, owner)).not.toBeNull(); expect(emitBackPress()).toBe(true); expect(nav.goBack).not.toHaveBeenCalled();
  const buttons = Alert.alert.mock.calls.at(-1)![2] as Array<{text:string;style?:string;onPress?:()=>unknown}>; expect(buttons.map(b => b.style)).toEqual(["cancel", "destructive"]);
  await pressAlertButton(buttons[1]!.text); expect(await loadSafetyPlanDraft(key, owner)).toBeNull(); expect(nav.goBack).toHaveBeenCalledTimes(1); expect(emitBackPress()).toBe(false);
});
it("native header dismissal preserves its requested navigation action after confirmed discard", async () => {
  const root = await open(); await edit(root, labels[1]!, "Unsaved gesture note"); const event = { preventDefault: vi.fn(), data: { action: { type: "GO_BACK", source: "safety-editor" } } };
  const listener = nav.addListener.mock.calls.find(([name]) => name === "beforeRemove")?.[1]; if (!listener) throw Error("Native dismissal listener missing"); await act(async () => { listener(event); });
  expect(event.preventDefault).toHaveBeenCalledTimes(1); expect(nav.dispatch).not.toHaveBeenCalled(); const buttons = Alert.alert.mock.calls.at(-1)![2] as Array<{text:string}>; await pressAlertButton(buttons[1]!.text); expect(nav.dispatch).toHaveBeenCalledWith(event.data.action);
});
it("a failed discard keeps the editor and its draft rather than navigating away", async () => {
  const root = await open(); await edit(root, labels[2]!, "Draft must survive failure"); await act(async () => { emitAppState("background"); }); await waitLocalWriteCommits(); const remove = storage.removeItem;
  vi.spyOn(storage, "removeItem").mockImplementation(slot => slot.startsWith("@mindpattern/safety_plan_draft_") ? Promise.reject(new Error("Native draft deletion failed")) : remove(slot));
  await pressLabel(root, "Back"); const buttons = Alert.alert.mock.calls.at(-1)![2] as Array<{text:string}>; await pressAlertButton(buttons[1]!.text); expect(nav.goBack).not.toHaveBeenCalled(); expect((await loadSafetyPlanDraft(key, owner))?.peoplePlaces).toBe("Draft must survive failure"); expect(Alert.alert.mock.calls.at(-1)?.slice(0, 2)).toEqual(["Could not save", "Your plan is still on screen exactly as you typed it — try again."]);
});
it("unmounted editor releases its native event subscriptions", async () => {
  const root = await open(); await edit(root, labels[0]!, "Leaving this editor"); await act(async () => { root.unmount(); }); await waitLocalWriteCommits(); Alert.alert.mockClear(); expect(emitBackPress()).toBe(false); emitAppState("background"); expect(Alert.alert).not.toHaveBeenCalled();
});
it("restores an unsaved draft and expires its visible status at the exact display boundary", async () => {
  await saveSafetyPlanDraft(key, owner, { ...emptySafetyPlan(), warningSigns: "Recovered unfinished plan" }); const root = await open(); expect(input(root, labels[0]!).props.value).toBe("Recovered unfinished plan");
  expect(textOf(root)).toContain("Your unsaved encrypted draft was restored");
});
it("retains readable fields and shows their over-limit count when an older plan exceeds the new edit bound", async () => {
  await saveSafetyPlanDraft(key, owner, { ...emptySafetyPlan(), warningSigns: "x".repeat(4001) }); const root = await open(); expect(input(root, labels[0]!).props.value).toHaveLength(4001); expect(textOf(root)).toContain("4001/4000"); await pressLabel(root, "Save my safety plan"); expect(Alert.alert.mock.calls.at(-1)?.[0]).toBe("Could not save"); expect(await loadSafetyPlan(key, owner)).toBeNull();
});
it("keeps spelling private and displays the offered field limit without an error at the boundary", async () => {
  const root = await open(); const field = input(root, labels[0]!); expect(field.props.autoCorrect).toBe(false); expect(field.props.spellCheck).toBe(false); expect(field.props.textContentType).toBe("none"); expect(field.props.maxLength).toBe(4000);
  await edit(root, labels[0]!, "x".repeat(4000)); await flush(); expect(textOf(root)).toContain("4000/4000"); await pressLabel(root, "Save my safety plan"); expect((await loadSafetyPlan(key, owner))?.warningSigns).toHaveLength(4000);
});
it("keeps the save control busy while a native commit is pending, then restores it", async () => {
  const root = await open(); await edit(root, labels[0]!, "Pending explicit save"); const write = storage.setItem; let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === `@mindpattern/safety_plan_${owner}`) await held; await write(slot, value); });
  try {
    await firePress(root, "Save my safety plan"); const button = root.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Save my safety plan")!;
    expect(button.props.disabled).toBe(true); expect(button.props.accessibilityState).toEqual({ disabled: true, busy: true });
  } finally { await act(async () => { release(); }); await flush(); }
  const button = root.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Save my safety plan")!; expect(button.props.disabled).toBe(false); expect(button.props.accessibilityState.busy).toBe(false);
});
it.each(["identity", "saved", "draft"])("refuses a replacement vault after the pending native %s hydration boundary", async stage => {
  const saved = { ...emptySafetyPlan(), warningSigns: "Original owner's private safety note" };
  const planStore = await import("../../src/safetyPlan"); await planStore.saveSafetyPlan(key, owner, saved); await saveSafetyPlanDraft(key, owner, { ...saved, warningSigns: "Original owner's unfinished private note" });
  let release!: () => void, releaseLater!: () => void; const held = new Promise<void>(resolve => { release = resolve; }), later = new Promise<void>(resolve => { releaseLater = resolve; });
  if (stage === "identity") vi.mocked(api.getUserId).mockImplementationOnce(async () => { await held; return owner; });
  else {
    const read = storage.getItem, target = stage === "saved" ? `@mindpattern/safety_plan_${owner}` : `@mindpattern/safety_plan_draft_${owner}`;
    vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === target) await held; if (stage === "saved" && slot === `@mindpattern/safety_plan_draft_${owner}`) await later; return value; });
  }
  const root = await render(<SafetyPlanScreen navigation={nav} />); roots.push(root); await flush();
  const replacement = stage === "identity" ? key : Buffer.alloc(32, 9);
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: replacement }, stage === "identity" ? "replacement-account" : owner);
  try { await act(async () => { release(); }); await flush(); expect(textOf(root)).toContain("unlock to read or edit it"); expect(textOf(root)).not.toContain("1. My warning signs"); }
  finally { release(); releaseLater(); await flush(); }
});
it("retains static crisis exits on an unreadable stored plan", async () => {
  await storage.setItem(`@mindpattern/safety_plan_${owner}`, "unreadable saved ciphertext"); const root = await open(); expect(textOf(root)).toContain("will not replace it"); await pressLabel(root, "Back"); expect(nav.goBack).toHaveBeenCalledTimes(1); await pressLabel(root, "Need help now? Crisis resources"); expect(nav.navigate).toHaveBeenCalledWith("Crisis");
});
it("the editor's crisis action remains reachable after editing", async () => { const root = await open(); await edit(root, labels[0]!, "Keep the plan"); await pressLabel(root, "Need help now? Crisis resources"); expect(nav.navigate).toHaveBeenCalledWith("Crisis"); });
it("uses the complete reviewed discard dialog before removing any personal draft", async () => {
  const root = await open(); await edit(root, labels[0]!, "Unsaved personal note"); await pressLabel(root, "Back"); const call = Alert.alert.mock.calls.at(-1)!;
  expect(call.slice(0, 2)).toEqual(["Discard your changes?", "Your safety plan changes have not been saved."]); expect((call[2] as Array<{text:string}>).map(button => button.text)).toEqual(["Keep editing", "Discard changes"]);
});
it("preserves an encrypted draft on unmount before its autosave timer fires", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Unmounted unfinished note"); await act(async () => { root.unmount(); }); await waitLocalWriteCommits();
  expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("Unmounted unfinished note"); expect(await loadSafetyPlan(key, owner)).toBeNull();
});
it("erases actual safety-draft consumer key references after background commit and loader teardown", async () => {
  const store = await import("../../src/safetyPlan"), save = store.saveSafetyPlanDraft, load = store.loadSafetyPlan, writes: Buffer[] = [], reads: Buffer[] = [];
  vi.spyOn(store, "saveSafetyPlanDraft").mockImplementation(async (dataKey, userId, plan) => { writes.push(dataKey); return save(dataKey, userId, plan); });
  vi.spyOn(store, "loadSafetyPlan").mockImplementation(async (dataKey, userId) => { reads.push(dataKey); return load(dataKey, userId); });
  const root = await open(); await edit(root, labels[0]!, "Background key custody"); await act(async () => { emitAppState("background"); }); await waitLocalWriteCommits();
  expect(writes.length).toBeGreaterThan(0); for (const held of writes) expect(held.every(byte => byte === 0)).toBe(true);
  await act(async () => { root.unmount(); }); expect(reads.length).toBeGreaterThan(0); for (const held of reads) expect(held.every(byte => byte === 0)).toBe(true);
});
it("does not let a queued old draft adopt a new same-account authentication epoch", async () => {
  const root = await open(); const write = storage.setItem; let release!: () => void, entered!: () => void, first = true;
  const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (first && slot === `@mindpattern/safety_plan_draft_${owner}`) { first = false; entered(); await gate; } return write(slot, value); });
  await edit(root, labels[0]!, "First admitted draft"); await act(async () => { emitAppState("background"); }); await reached;
  await edit(root, labels[0]!, "Queued retired draft"); await act(async () => { emitAppState("background"); }); const { changeLocalSessionOwner } = await import("../../src/localWriteGuard"); changeLocalSessionOwner(owner);
  await act(async () => { release(); }); await waitLocalWriteCommits(); expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("First admitted draft");
});
it("does not publish an old editor's draft after same-account authentication retires its scope", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Old editor scope"); const { changeLocalSessionOwner } = await import("../../src/localWriteGuard"); changeLocalSessionOwner(owner);
  await act(async () => { emitAppState("background"); }); await waitLocalWriteCommits(); expect(await loadSafetyPlanDraft(key, owner)).toBeNull();
});
it("a later saved status receives its own complete display interval", async () => {
  const root = await open(); vi.useFakeTimers(); await pressLabel(root, "Save my safety plan"); await act(async () => { await vi.advanceTimersByTimeAsync(2000); }); await pressLabel(root, "Save my safety plan");
  await act(async () => { await vi.advanceTimersByTimeAsync(600); }); expect(textOf(root)).toContain("Saved — encrypted, as always."); await act(async () => { await vi.advanceTimersByTimeAsync(2000); }); expect(textOf(root)).not.toContain("Saved — encrypted, as always.");
});
it("a save action refreshes the actual session's idle lease", async () => {
  const root = await open(); vi.useFakeTimers(); let lease: ReturnType<typeof setTimeout> | undefined;
  touchActivity.mockImplementation(() => { if (lease) clearTimeout(lease); lease = setTimeout(() => vault.lock(), 1000); });
  try { await edit(root, labels[0]!, "Keep the editor active"); await act(async () => { await vi.advanceTimersByTimeAsync(900); }); await pressLabel(root, "Save my safety plan"); await act(async () => { await vi.advanceTimersByTimeAsync(100); }); expect(vault.isUnlocked()).toBe(true); }
  finally { if (lease) clearTimeout(lease); touchActivity.mockReset(); }
});
it("unmount removes the actual native subscription handles and scheduled status callback", async () => {
  const root = await open(); vi.useFakeTimers(); await pressLabel(root, "Save my safety plan");
  const appStateHandle = AppState.addEventListener.mock.results.at(-1)?.value, backHandle = BackHandler.addEventListener.mock.results.at(-1)?.value;
  expect(appStateHandle?.remove).toBeTypeOf("function"); expect(backHandle?.remove).toBeTypeOf("function");
  await act(async () => { root.unmount(); }); await waitLocalWriteCommits();
  expect(appStateHandle.remove).toHaveBeenCalledOnce(); expect(backHandle.remove).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
});
it("finishing an older save preserves a newer edit immediately as a separate encrypted draft", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Explicitly saved snapshot");
  const write = storage.setItem; let release!: () => void, entered!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === `@mindpattern/safety_plan_${owner}`) { entered(); await gate; } await write(slot, value); });
  const saving = firePress(root, "Save my safety plan"); await saving; await reached;
  try { await edit(root, labels[0]!, "Newer unfinished edit"); await act(async () => { release(); }); await saving; await waitLocalWriteCommits(); await act(async () => {}); expect((await loadSafetyPlan(key, owner))?.warningSigns).toBe("Explicitly saved snapshot"); expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("Newer unfinished edit"); }
  finally { release(); await saving; }
});
it.each(["identity", "saved", "draft"])("unmounting during the pending %s native hydration erases every provider-held screen key", async stage => {
  const store = await import("../../src/safetyPlan"), originalLoad = store.loadSafetyPlan, originalDraft = store.loadSafetyPlanDraft, heldKeys: Buffer[] = [];
  vi.spyOn(store, "loadSafetyPlan").mockImplementation(async (dataKey, userId) => { heldKeys.push(dataKey); return originalLoad(dataKey, userId); });
  vi.spyOn(store, "loadSafetyPlanDraft").mockImplementation(async (dataKey, userId) => { heldKeys.push(dataKey); return originalDraft(dataKey, userId); });
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  if (stage === "identity") vi.mocked(api.getUserId).mockImplementationOnce(async () => { await gate; return owner; });
  else { const read = storage.getItem, target = stage === "saved" ? `@mindpattern/safety_plan_${owner}` : `@mindpattern/safety_plan_draft_${owner}`; vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === target) await gate; return value; }); }
  const root = await render(<SafetyPlanScreen navigation={nav} />); roots.push(root); await flush();
  try { await act(async () => { root.unmount(); }); release(); await flush(); for (const dataKey of heldKeys) expect(dataKey.every(byte => byte === 0)).toBe(true); expect(await loadSafetyPlanDraft(key, owner)).toBeNull(); }
  finally { release(); }
});
it("background draft persistence releases the pending native autosave timer", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "One interruption draft"); expect(vi.getTimerCount()).toBe(1);
  await act(async () => { emitAppState("background"); }); await waitLocalWriteCommits(); expect(vi.getTimerCount()).toBe(0); expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("One interruption draft");
});
it("confirming discard releases the pending native autosave timer before navigation", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Discard this pending edit"); await pressLabel(root, "Back"); await pressAlertButton("Discard changes");
  expect(nav.goBack).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0); expect(await loadSafetyPlanDraft(key, owner)).toBeNull();
});
it("backgrounding an unchanged editor does not manufacture an unsaved recovery draft", async () => {
  const root = await open(); await act(async () => { emitAppState("background"); }); await waitLocalWriteCommits(); expect(await loadSafetyPlanDraft(key, owner)).toBeNull(); expect(input(root, labels[0]!).props.value).toBe("");
});
it("a same-account authentication change during native hydration cannot adopt the earlier editor epoch", async () => {
  const store = await import("../../src/safetyPlan"), saved = { ...emptySafetyPlan(), warningSigns: "Earlier authentication's private plan" }; await store.saveSafetyPlan(key, owner, saved);
  const read = storage.getItem; let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === `@mindpattern/safety_plan_${owner}`) await gate; return value; });
  const root = await render(<SafetyPlanScreen navigation={nav} />); roots.push(root); await flush(); const { changeLocalSessionOwner } = await import("../../src/localWriteGuard"); changeLocalSessionOwner(owner);
  try { await act(async () => { release(); }); await flush(); expect(textOf(root)).toContain("unlock to read or edit it"); expect(textOf(root)).not.toContain(saved.warningSigns); }
  finally { release(); }
});
it("a same-account authentication change during the save's identity read cannot publish the captured plan", async () => {
  const root = await open(); await edit(root, labels[0]!, "Retired save snapshot"); let release!: () => void, entered!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; });
  vi.mocked(api.getUserId).mockImplementationOnce(async () => { entered(); await gate; return owner; }); const saving = firePress(root, "Save my safety plan"); await saving; await reached;
  const { changeLocalSessionOwner } = await import("../../src/localWriteGuard"); changeLocalSessionOwner(owner);
  try { await act(async () => { release(); }); await saving; await flush(); expect(Alert.alert.mock.calls.at(-1)?.slice(0, 2)).toEqual(["Could not save", "Your plan is still on screen exactly as you typed it — try again."]); expect(await loadSafetyPlan(key, owner)).toBeNull(); }
  finally { release(); await saving; }
});
it("an old editor cannot save into a later same-account authentication scope", async () => {
  const root = await open(); await edit(root, labels[0]!, "Old editor must remain unsaved"); const { changeLocalSessionOwner } = await import("../../src/localWriteGuard"); changeLocalSessionOwner(owner);
  await pressLabel(root, "Save my safety plan"); expect(Alert.alert.mock.calls.at(-1)?.[0]).toBe("Could not save"); expect(await loadSafetyPlan(key, owner)).toBeNull();
});
it("a mismatched vault owner cannot save the editor even when two accounts use equal key bytes", async () => {
  const root = await open(); await edit(root, labels[0]!, "This account's private plan"); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.from(key) }, "other-account");
  await pressLabel(root, "Save my safety plan"); expect(Alert.alert.mock.calls.at(-1)?.[0]).toBe("Could not save"); expect(await loadSafetyPlan(key, owner)).toBeNull();
});
it("native hardware back remains available from a locked view with an earlier dirty editor", async () => {
  const root = await open(); await edit(root, labels[0]!, "Earlier dirty edit"); vault.lock(); await pressLabel(root, "Save my safety plan"); Alert.alert.mockClear();
  expect(emitBackPress()).toBe(false); expect(Alert.alert).not.toHaveBeenCalled();
});
it("a clean native header transition proceeds without interception or redispatch", async () => {
  await open(); const listener = nav.addListener.mock.calls.find(([name]) => name === "beforeRemove")?.[1]; if (!listener) throw Error("Native header listener missing");
  const event = { preventDefault: vi.fn(), data: { action: { type: "GO_BACK" } } }; await act(async () => { listener(event); }); expect(event.preventDefault).not.toHaveBeenCalled(); expect(nav.dispatch).not.toHaveBeenCalled(); expect(Alert.alert).not.toHaveBeenCalled();
});
it("an account id mismatch in native identity hydration locks the earlier owner's editor", async () => {
  vi.mocked(api.getUserId).mockResolvedValue("other-account"); const root = await open(); expect(textOf(root)).toContain("unlock to read or edit it"); expect(root.root.findAllByType(TextInput)).toHaveLength(0);
});
it("acknowledging the current saved snapshot releases its pending native autosave timer", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Save this current snapshot"); await pressLabel(root, "Save my safety plan");
  expect(vi.getTimerCount()).toBe(1); expect(textOf(root)).toContain("Saved — encrypted, as always."); expect(await loadSafetyPlanDraft(key, owner)).toBeNull();
});
it("a later dirty draft does not require a native deletion when its earlier explicit save finishes", async () => {
  const root = await open(); vi.useFakeTimers(); await edit(root, labels[0]!, "Earlier explicit snapshot"); const write = storage.setItem, remove = storage.removeItem;
  let release!: () => void, entered!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === `@mindpattern/safety_plan_${owner}`) { entered(); await gate; } return write(slot, value); });
  await firePress(root, "Save my safety plan"); await reached;
  try { await edit(root, labels[0]!, "Later recoverable draft"); await act(async () => { await vi.advanceTimersByTimeAsync(300); }); expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("Later recoverable draft"); }
  catch (error) { release(); throw error; }
  // The already-admitted explicit write remains held. Observe the draft
  // through its reader without draining that separate pending write.
  vi.spyOn(storage, "removeItem").mockImplementation(slot => slot === `@mindpattern/safety_plan_draft_${owner}` ? Promise.reject(new Error("The newer recovery drawer is read-only for deletion")) : remove(slot));
  try { await act(async () => { release(); }); await waitLocalWriteCommits(); await act(async () => {}); expect(Alert.alert).not.toHaveBeenCalled(); expect(textOf(root)).toContain("Saved — encrypted, as always."); expect((await loadSafetyPlanDraft(key, owner))?.warningSigns).toBe("Later recoverable draft"); }
  finally { release(); }
});
it("a replacement native navigation handle receives dirty-editor confirmation and its own action", async () => {
  const root = await open(); await edit(root, labels[0]!, "Keep editor ownership through the navigation provider");
  const replacement = { ...nav, dispatch: vi.fn(), addListener: vi.fn((_name: string, _handler: (event: any) => void) => vi.fn()) };
  await act(async () => { root.update(<SafetyPlanScreen navigation={replacement} />); }); await flush();
  const handler = replacement.addListener.mock.calls.find(([name]) => name === "beforeRemove")?.[1]; if (!handler) throw Error("Replacement native navigation listener missing");
  const event = { preventDefault: vi.fn(), data: { action: { type: "GO_BACK", source: "replacement-native-stack" } } }; await act(async () => { handler(event); }); await pressAlertButton("Discard changes");
  expect(replacement.dispatch).toHaveBeenCalledWith(event.data.action); expect(nav.dispatch).not.toHaveBeenCalled();
});
it("a native tap queued during a pending save cannot release the original busy control", async () => {
  const root = await open(); await edit(root, labels[0]!, "Pending native tap ownership"); const write = storage.setItem; let release!: () => void, entered!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === `@mindpattern/safety_plan_${owner}`) { entered(); await gate; } return write(slot, value); });
  await firePress(root, "Save my safety plan"); await reached; vi.mocked(api.getUserId).mockRejectedValueOnce(new Error("Native identity read became unavailable after admission"));
  try { const queuedControl = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save my safety plan")!; await act(async () => { void queuedControl.props.onPress({ nativeEvent: { timestamp: Date.now() }, currentTarget: 1, target: 1 }); }); const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save my safety plan")!; expect(button.props.accessibilityState).toEqual({ disabled: true, busy: true }); expect(Alert.alert).not.toHaveBeenCalled(); }
  finally { vi.mocked(api.getUserId).mockReset().mockResolvedValue(owner); await act(async () => { release(); }); await waitLocalWriteCommits(); }
});
