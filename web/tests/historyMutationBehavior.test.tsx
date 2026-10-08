import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as client from "../src/api/client";
import { api, ApiError, clearSession, type ListedEntry } from "../src/api/client";
import { HistoryView } from "../src/views/History";
import { decryptEntry, encryptAudio, encryptEntry, type VoiceFields } from "../src/crypto/patient";
import * as patient from "../src/crypto/patient";
import * as versions from "../src/entryVersions";
import * as moods from "../src/moodLog";
import { observeEntryVersions, resetEntryVersionMirrors } from "../src/entryVersions";
import { recordMood } from "../src/moodLog";
import { setKvBackendForTests } from "../src/kvstore";
import { vault } from "../src/vault";
import { __setLocaleForTests, t } from "../src/strings";
import { resetTestState, installSession } from "./helpers/api";
import { isDisabled, press, pressAria, render, textOf, textOfNode, typeArea, typeInto } from "./helpers/rtr";
import { publicSurface } from "./helpers/publicSurface";
import * as crisis from "../src/crisisDialog";
import { applyThemePref } from "../src/theme";

const owner = "history-behavior-owner";
const reference = new Uint8Array(new ArrayBuffer(32)).fill(71);
type Root = Awaited<ReturnType<typeof render>>;
const flush = async () => { for (let i = 0; i < 12; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); };
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { resolve, promise }; }
const attachment = (blob: string): Awaited<ReturnType<typeof api.fetchAudioAttachment>> => ({ id: "audio-recorded", client_entry_id: "recorded", blob, mime_type: "audio/webm", duration_seconds: 2, size_bytes: 32, created_at: "2026-10-05", expires_at: "2026-11-01" });
async function row(id = "entry-current", text = "A truthful journal entry", version = 1, voice?: VoiceFields, expiry?: string): Promise<ListedEntry> {
  const { blobB64 } = await encryptEntry(reference, owner, id, text, "2026-10-05T11:22:33.000Z", 0.8, { energy: 3, sleep: 4, tags: ["walk", "family"], tod: "morning" }, version, voice);
  return { id: `server-${id}`, client_entry_id: id, blob: blobB64, entry_date: "2026-10-05", received_at: "2026-10-05T11:23:00.000Z", content_version: version, ...(expiry ? { audio: { attachment_id: `audio-${id}`, expires_at: expiry } } : {}) };
}
async function mount(rows: ListedEntry[]) { vi.mocked(client.listEntriesWalk).mockResolvedValue(rows); const root = await render(<HistoryView />); await flush(); for (let i = 0; i < 1_000 && textOf(root).includes(t("common.loading")); i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); expect(textOf(root)).not.toContain(t("common.loading")); return root; }
async function beginEdit(root: Root, text: string) { await press(root, t("history.edit")); await typeArea(root, t("history.yourEntry"), text); }
beforeEach(() => {
  resetTestState(); __setLocaleForTests("en"); vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
  const records = new Map<string, string>(); setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); }, keys: async () => [...records.keys()], compareAndSet: async (key, expected, value, _permit, current) => { if (current && !current()) return false; if ((records.get(key) ?? null) !== expected) return false; records.set(key, value); return true; } }); resetEntryVersionMirrors();
  installSession(owner); vault.unlock({ authKey: reference.slice(), dataKey: reference.slice() }, owner); vi.spyOn(client, "listEntriesWalk").mockResolvedValue([]);
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:decrypted-history-recording"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); setKvBackendForTests(null); __setLocaleForTests("en"); });

it.each([["en", 1], ["en", 2], ["es", 1], ["es", 2]] as const)("names the exact rollback count while retaining other decryptable writing in %s: %i", async (locale, count) => {
  __setLocaleForTests(locale);
  const old = await Promise.all(Array.from({ length: count }, (_, index) => row(`rollback-${index}`, "Never display the reverted writing", 2)));
  await observeEntryVersions(owner, reference, old.map(entry => ({ clientEntryId: entry.client_entry_id, contentVersion: 5 })));
  const root = await mount([...old, await row("current", "Retained current writing")]);
  expect(textOf(root)).not.toContain("Never display the reverted writing"); expect(textOf(root)).toContain("Retained current writing");
  expect(textOf(root)).toContain(t(count === 1 ? "history.rollbackOne" : "history.rollbackMany", { count }));
});
it.each([0, 0.49, 0.5, -0.5])("uses the public calendar's non-color mood underline at the exact boundary %s", async value => {
  await recordMood(reference, owner, "2026-10-06", value); const root = await mount([]), day = root.root.findAllByType("button").find(node => String(node.props["aria-label"]).startsWith("2026-10-06"))!;
  expect(day.props["aria-label"]).toContain("2026-10-06");
  if (Math.abs(value) < 0.5) expect(day.props.style.borderBottom).toBeUndefined(); else expect(day.props.style.borderBottom).toMatch(/^1px solid /);
});
it.each(["new", "shown today", "read failure", "write failure", "retired during stamp"] as const)("provides calm crisis support after committing an edited entry: %s", async state => {
  if (state === "shown today") await crisis.recordCrisisDialogShown(owner, "2026-10-05");
  if (state === "read failure") vi.spyOn(crisis, "crisisDialogShownOn").mockRejectedValue(new Error("local stamp unavailable"));
  if (state === "write failure") vi.spyOn(crisis, "recordCrisisDialogShown").mockRejectedValue(new Error("local stamp unavailable"));
  if (state === "retired during stamp") { const actual = crisis.recordCrisisDialogShown; vi.spyOn(crisis, "recordCrisisDialogShown").mockImplementation(async (...args) => { await actual(...args); clearSession(); vault.lock(); }); }
  const update = vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "committed-crisis-edit" }), root = await mount([await row()]);
  await beginEdit(root, "I want to kill myself"); await press(root, t("history.saveEdit")); await flush();
  expect(update).toHaveBeenCalledTimes(1); const wire = update.mock.calls[0]!; expect((await decryptEntry(reference, owner, wire[0], wire[1], wire[3])).text).toBe("I want to kill myself");
  if (state === "shown today" || state === "retired during stamp") expect(textOf(root)).not.toContain(t("entry.crisisPromptTitle"));
  else { expect(textOf(root)).toContain(t("entry.crisisPromptTitle")); expect(textOf(root)).toContain(t("entry.crisisPromptProceed")); }
});
it.each([false, true])("retains the saved voice translation when an edit changes only its outer spacing: trim=%s", async trim => {
  const entry = await row("voice-spaces", trim ? " Saved voice text " : "Saved voice text", 2, { inputMode: "voice", transcriptLang: "en", englishText: "Retained translated channel" }), translate = vi.spyOn(api, "translateText").mockResolvedValue({ english_text: "A different translation", transcript_lang: "en" } as Awaited<ReturnType<typeof api.translateText>>), update = vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "updated" });
  const changed = trim ? "Saved voice text" : " Saved voice text ", root = await mount([entry]); await beginEdit(root, changed); await press(root, t("history.saveEdit")); await flush();
  expect(translate).not.toHaveBeenCalled(); const wire = update.mock.calls[0]!; const payload = await decryptEntry(reference, owner, wire[0], wire[1], wire[3]);
  expect(payload.text).toBe(changed); expect(payload.english_text).toBe("Retained translated channel");
});

it.each(["en", "es"] as const)("renders real populated calendar, long writing, mood intensity, recording and edit metadata in %s", async locale => {
  __setLocaleForTests(locale); await recordMood(reference, owner, "2026-10-06", -3); const first = await row("first", "Saved long writing ".repeat(20), 4, { inputMode: "voice", transcriptLang: "es", englishText: "Saved translation" }, "2026-10-06T12:00:01Z"); const second = await row("second", "Other entry"); second.entry_date = "2026-10-04";
  const root = await mount([first, second]); expect(publicSurface(root.toJSON())).toMatchSnapshot(); const day = root.root.findAllByType("button").find(n => String(n.props["aria-label"]).startsWith("2026-10-05"))!;
  await act(async () => { day.props.onClick(); }); expect(textOf(root)).not.toContain("Other entry"); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t("history.showingDay", { date: "2026-10-05" })); expect(textOf(root)).toContain("Other entry");
  await pressAria(root, t("history.prevMonth")); expect(textOf(root)).not.toContain(t("history.monthEntriesMany", { count: 2 })); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await pressAria(root, t("history.nextMonth")); expect(textOf(root)).toContain(t("history.monthEntriesMany", { count: 2 }));
});
it.each([1, 2])( "honestly renders combined rollback and tamper warnings for %i hidden entries", async count => {
  await observeEntryVersions(owner, reference, [{ clientEntryId: "old", contentVersion: 5 }]); const old = await row("old", "Never present rolled back content", 3), damaged = { ...await row("damaged"), blob: "malformed ciphertext" };
  const root = await mount(count === 1 ? [old] : [old, damaged]); expect(textOf(root)).not.toContain("Never present rolled back content"); expect(textOf(root)).toContain(t(count === 1 ? "history.hiddenOne" : "history.hiddenMany", { count })); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["not-a-date", "2026-10-04T12:00:00Z", "2026-10-05T12:00:01Z"])("shows a nonnegative rounded recording retention for %s", async expiry => {
  const root = await mount([await row("recorded", "Kept recording", 1, undefined, expiry)]); expect(textOf(root)).toContain(t("history.recordingExpires", { days: expiry.endsWith("01Z") ? 1 : 0 }));
});
const playbackFailures = [
  [new ApiError(410, "expired", "audio_expired"), "history.playbackExpired"],
  [new ApiError(503, "storage not configured", "audio_storage_unconfigured"), "history.playbackUnavailable"],
  [new ApiError(503, "storage failed", "audio_storage_failed"), "history.playbackUnavailable"],
  [new ApiError(503, "unavailable", "service_unavailable"), "history.playbackUnavailable"],
  [new ApiError(0, "offline"), "history.loadOffline"],
  [Object.assign(new Error("authentication failed"), { name: "TamperError" }), "history.playbackTampered"],
  [new Error("untrusted decoder failure"), "history.playbackFailed"],
  [new ApiError(500, "unrecognized upstream failure"), "history.playbackFailed"],
] as const;
it.each(playbackFailures)("localizes the actual failed recording without retaining a busy player: %#", async (failure, key) => {
  vi.spyOn(api, "fetchAudioAttachment").mockRejectedValue(failure); const root = await mount([await row("recorded", "Kept recording", 1, undefined, "2026-11-01")]); await press(root, t("history.playRecording")); await flush(); expect(textOf(root)).toContain(t(key)); expect(isDisabled(root, t("history.playRecording"))).toBe(false); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["ended", "error"] as const)("releases real decrypted playback after the audio element reports %s", async outcome => {
  const encrypted = await encryptAudio(reference, owner, "recorded", new Uint8Array([1, 3, 5, 7])); vi.spyOn(api, "fetchAudioAttachment").mockResolvedValue(attachment(encrypted.blobB64));
  const root = await mount([await row("recorded", "Kept recording", 1, undefined, "2026-11-01")]); await press(root, t("history.playRecording")); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(1); expect(publicSurface(root.toJSON())).toMatchSnapshot(); const audio = root.root.findAllByType("audio")[0]!; await act(async () => { outcome === "ended" ? audio.props.onEnded() : audio.props.onError(); }); expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-history-recording"); expect(root.root.findAllByType("audio")).toHaveLength(0); if (outcome === "error") expect(textOf(root)).toContain(t("history.playbackFailed"));
  expect(isDisabled(root, t("history.playRecording"))).toBe(false); await press(root, t("history.playRecording")); await flush(); expect(api.fetchAudioAttachment).toHaveBeenCalledTimes(2); expect(root.root.findAllByType("audio")).toHaveLength(1);
});
it.each([new ApiError(0, "offline"), new ApiError(503, "delete server refused"), new Error("delete service failed")])("retains a recording and honest error after deletion fails: %#", async failure => {
  vi.spyOn(api, "deleteAudioAttachment").mockRejectedValue(failure); const root = await mount([await row("recorded", "Kept recording", 1, undefined, "2026-11-01")]); await press(root, t("history.deleteRecording")); await flush(); expect(textOf(root)).toContain(t(failure instanceof ApiError && failure.status === 0 ? "history.loadOffline" : "history.deleteRecordingFailed")); expect(isDisabled(root, t("history.deleteRecording"))).toBe(false);
});
it("releases a real recording that finishes loading after its session retires", async () => {
  const encrypted = await encryptAudio(reference, owner, "recorded", new Uint8Array([2, 4, 6])), fetched = deferred<Awaited<ReturnType<typeof api.fetchAudioAttachment>>>(); vi.spyOn(api, "fetchAudioAttachment").mockReturnValue(fetched.promise); const root = await mount([await row("recorded", "Kept recording", 1, undefined, "2026-11-01")]); await press(root, t("history.playRecording")); clearSession(); await act(async () => { fetched.resolve(attachment(encrypted.blobB64)); }); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-history-recording");
});
it("refuses to publish retired recording-deletion state after session replacement", async () => {
  const removed = deferred<null>(); vi.spyOn(api, "deleteAudioAttachment").mockReturnValue(removed.promise); const root = await mount([await row("recorded", "Kept recording", 1, undefined, "2026-11-01")]); await press(root, t("history.deleteRecording")); clearSession(); installSession("replacement-owner"); await act(async () => { removed.resolve(null); }); await flush(); expect(root.root.findAllByType("button").some(n => n.children.includes(t("history.playRecording")))).toBe(true);
});
it.each(["translated", "translation-failed", "unchanged", "untranslated"] as const)("preserves actual voice metadata through its edit commit: %s", async state => {
  const oldText = "Texto original", initial = await row("voice", oldText, 3, { inputMode: "voice", transcriptLang: "es", englishText: state === "untranslated" ? null : "Original English" }); const translated = vi.spyOn(api, "translateText"); state === "translation-failed" ? translated.mockRejectedValue(new Error("translation unavailable")) : translated.mockResolvedValue({ english_text: "New English" }); let saved: string | undefined;
  const updated = vi.spyOn(api, "updateEntry").mockImplementation(async (_id, blob) => { saved = blob; return { id: "saved" }; }); const root = await mount([initial]); const newText = state === "unchanged" ? oldText : "Texto editado"; await beginEdit(root, newText); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t("history.saveEdit")); await flush(); expect(updated).toHaveBeenCalledWith("voice", expect.any(String), "2026-10-05", 4);
  const actual = await decryptEntry(reference, owner, "voice", saved!, 4); expect(actual).toMatchObject({ v: 3, text: newText, created_at: "2026-10-05T11:22:33.000Z", energy: 3, sleep: 4, tags: ["walk", "family"], tod: "morning", input_mode: "voice", transcript_lang: "es", english_text: state === "translated" ? "New English" : state === "unchanged" ? "Original English" : null }); if (state === "unchanged" || state === "untranslated") expect(translated).not.toHaveBeenCalled(); else expect(translated).toHaveBeenCalledWith(newText, "es");
});
it.each(["keep", "replace", "reload-failed", "deleted"] as const)("presents an explicit competing edit and honors its public resolution: %s", async mode => {
  const initial = await row("conflicted", "Originally saved", 1), fresh = await row("conflicted", "Their changed writing", 4); const updates = vi.spyOn(api, "updateEntry").mockRejectedValueOnce(new ApiError(mode === "deleted" ? 404 : 409, "changed elsewhere", mode === "deleted" ? undefined : "version_conflict")).mockResolvedValue({ id: "replacement" }), get = vi.spyOn(api, "getEntry"); mode === "reload-failed" ? get.mockRejectedValue(new Error("reload unavailable")) : get.mockResolvedValue(fresh);
  const root = await mount([initial]); await beginEdit(root, "My preserved writing"); await press(root, t("history.saveEdit")); await flush(); expect(publicSurface(root.toJSON())).toMatchSnapshot(); if (mode === "reload-failed") { expect(textOf(root)).toContain(t("history.conflictReloadFailed")); return; } expect(textOf(root)).toContain("My preserved writing"); expect(textOf(root)).toContain(mode === "deleted" ? t("history.deletedElsewhere") : "Their changed writing"); expect(updates).toHaveBeenCalledTimes(1);
  if (mode === "keep") { await press(root, t("history.keepTheirs")); await flush(); expect(updates).toHaveBeenCalledTimes(1); expect(textOf(root)).not.toContain(t("history.conflictTitle")); }
  if (mode === "replace") { await press(root, t("history.applyMine")); await flush(); expect(updates).toHaveBeenLastCalledWith("conflicted", expect.any(String), "2026-10-05", 5); const saved = updates.mock.calls.at(-1)![1]; expect((await decryptEntry(reference, owner, "conflicted", saved, 5)).text).toBe("My preserved writing"); expect(textOf(root)).not.toContain(t("history.conflictTitle")); }
});
it("shows honest initial progress before any encrypted listing has arrived", async () => {
  const listing = deferred<ListedEntry[]>(); vi.mocked(client.listEntriesWalk).mockReturnValue(listing.promise); const root = await render(<HistoryView />); expect(textOf(root)).toContain(t("common.loading")); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await act(async () => { listing.resolve([]); }); await flush(); expect(textOf(root)).not.toContain(t("common.loading"));
});
it.each([new ApiError(0, "offline"), new Error("temporary journal service failure")])("ends loading with honest public fetch failure: %#", async failure => {
  vi.mocked(client.listEntriesWalk).mockRejectedValue(failure); const root = await render(<HistoryView />); await flush(); expect(textOf(root)).toContain(failure instanceof ApiError ? t("history.loadOffline") : failure.message); expect(textOf(root)).not.toContain(t("common.loading"));
});
it("deletes a playing recording and updates only that entry's attachment", async () => {
  const encrypted = await encryptAudio(reference, owner, "recorded", new Uint8Array([2, 4, 6])); vi.spyOn(api, "fetchAudioAttachment").mockResolvedValue(attachment(encrypted.blobB64)); vi.spyOn(api, "deleteAudioAttachment").mockResolvedValue(null);
  const root = await mount([await row("recorded", "Recording to remove", 1, undefined, "2026-11-01"), await row("other", "Other recording stays", 1, undefined, "2026-11-01")]); const play = root.root.findAllByType("button").find(node => node.children.includes(t("history.playRecording")))!; await act(async () => { play.props.onClick(); }); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(1);
  const remove = root.root.findAllByType("button").find(node => node.children.includes(t("history.deleteRecording")))!; await act(async () => { remove.props.onClick(); }); await flush(); expect(api.deleteAudioAttachment).toHaveBeenCalledWith("audio-recorded"); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-history-recording"); expect(root.root.findAllByType("button").filter(node => node.children.includes(t("history.playRecording")))).toHaveLength(1); expect(textOf(root)).toContain("Recording to remove"); expect(textOf(root)).toContain("Other recording stays");
});
it("releases a real playing recording when its view unmounts", async () => {
  const encrypted = await encryptAudio(reference, owner, "recorded", new Uint8Array([2, 4, 6])); vi.spyOn(api, "fetchAudioAttachment").mockResolvedValue(attachment(encrypted.blobB64)); const root = await mount([await row("recorded", "Recording", 1, undefined, "2026-11-01")]); await press(root, t("history.playRecording")); await flush(); await act(async () => { root.unmount(); }); expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-history-recording");
});
it("renders exactly240 characters without an expansion and presents unscored writing honestly", async () => {
  const saved = await patient.encryptEntry(reference, owner, "unscored", "x".repeat(240), "2026-10-05T11:22:33Z", null); const root = await mount([{ id: "server-unscored", client_entry_id: "unscored", blob: saved.blobB64, entry_date: "2026-10-05", content_version: 1, received_at: "2026-10-05" }]); expect(textOf(root)).toContain(t("history.noRead")); expect(textOf(root)).toContain("x".repeat(240)); expect(textOf(root)).not.toContain("x".repeat(240) + "…"); expect(root.root.findAllByType("details")).toHaveLength(0); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each([100_000, 100_001])("honors the encrypted editor boundary at%i characters", async size => {
  const updated = vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "edited" }); const root = await mount([await row()]); await beginEdit(root, "x".repeat(size)); await press(root, t("history.saveEdit")); await flush();
  if (size === 100_001) { expect(updated).not.toHaveBeenCalled(); expect(textOf(root)).toContain(t("entry.tooLongBody", { max: "100,000" })); } else { expect(updated).toHaveBeenCalledTimes(1); expect((await decryptEntry(reference, owner, "entry-current", updated.mock.calls[0]![1], 2)).text).toBe("x".repeat(size)); }
});
it("rejects boundary writing whose preserved outer spaces exceed the encrypted payload limit", async () => {
  vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "too-large" }); const root = await mount([await row()]); await beginEdit(root, " " + "x".repeat(100_000) + " "); await press(root, t("history.saveEdit")); await flush(); expect(api.updateEntry).not.toHaveBeenCalled(); expect(textOf(root)).toContain(t("entry.tooLongBody", { max: "100,000" }));
});
it("preserves actual cryptographic key custody after an edit and displays a failed edit honestly", async () => {
  const initial = await row(), real = patient.encryptEntry, temporary: Uint8Array[] = [], caller = vault.get().dataKey; vi.spyOn(patient, "encryptEntry").mockImplementation(async (...args) => { temporary.push(args[0]); return real(...args); }); vi.spyOn(api, "updateEntry").mockRejectedValue(new Error("journal commit unavailable")); const root = await mount([initial]); await beginEdit(root, "Changed writing"); await press(root, t("history.saveEdit")); await flush(); expect(textOf(root)).toContain("journal commit unavailable"); expect(isDisabled(root, t("history.saveEdit"))).toBe(false); expect(temporary.length).toBeGreaterThan(0); temporary.forEach(key => expect(key).toEqual(new Uint8Array(key.length))); expect(caller).toEqual(reference);
});
it("clears real encrypted version and mood metadata after a confirmed deletion and erases its transferred key", async () => {
  const initial = await row(), real = versions.forgetEntryVersion, temporary: Uint8Array[] = [], caller = vault.get().dataKey; await recordMood(reference, owner, "2026-10-05", 2); const root = await mount([initial]); expect(await versions.knownEntryVersion(owner, reference, initial.client_entry_id)).toBe(1); vi.spyOn(versions, "forgetEntryVersion").mockImplementation(async (...args) => { temporary.push(args[1]); return real(...args); }); vi.spyOn(api, "deleteEntry").mockResolvedValue(null); vi.mocked(client.listEntriesWalk).mockResolvedValue([]);
  await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); await flush(); expect(api.deleteEntry).toHaveBeenCalledWith(initial.client_entry_id); expect(await versions.knownEntryVersion(owner, reference, initial.client_entry_id)).toBeNull(); expect(await moods.recentMoods(reference, owner, 400)).toEqual([]); expect(temporary.length).toBeGreaterThan(0); temporary.forEach(key => expect(key).toEqual(new Uint8Array(key.length))); expect(caller).toEqual(reference); expect(textOf(root)).toContain(t("history.empty"));
});
it("retains the entry and enables recovery when deletion fails", async () => {
  vi.spyOn(api, "deleteEntry").mockRejectedValue(new Error("journal deletion unavailable")); const root = await mount([await row()]); await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); await flush(); expect(textOf(root)).toContain("journal deletion unavailable"); expect(textOf(root)).toContain("A truthful journal entry"); expect(isDisabled(root, t("common.deletePermanently"))).toBe(false); await press(root, t("common.cancel")); expect(root.root.findAllByType("button").some(node => node.children.includes(t("common.deletePermanently")))).toBe(false);
});
it("cancels an edit without saving and restores the next editor's original text", async () => {
  vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "unexpected" }); const root = await mount([await row()]); await beginEdit(root, "Abandoned writing"); await press(root, t("common.cancel")); expect(root.root.findAllByType("textarea")).toHaveLength(0); expect(api.updateEntry).not.toHaveBeenCalled(); await press(root, t("history.edit")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("A truthful journal entry");
});
it("grows the window by30 entries and resets it when the reader searches", async () => {
  const rows = await Promise.all(Array.from({ length: 61 }, (_, index) => row(`window-${index}`, `Window writing ${index}`))); const root = await mount(rows); expect(root.root.findAllByType("article")).toHaveLength(30); await press(root, t("settings.showMore")); expect(root.root.findAllByType("article")).toHaveLength(60); await typeInto(root, t("history.search"), "Window"); expect(root.root.findAllByType("article")).toHaveLength(30); await press(root, t("settings.showMore")); await press(root, t("settings.showMore")); expect(root.root.findAllByType("article")).toHaveLength(61); expect(root.root.findAllByType("button").some(node => node.children.includes(t("settings.showMore")))).toBe(false);
});
it("leaves exactly30 visible entries without an extra sentinel", async () => {
  const rows = await Promise.all(Array.from({ length: 30 }, (_, index) => row(`boundary-${index}`, `Boundary writing ${index}`))); const root = await mount(rows); expect(root.root.findAllByType("article")).toHaveLength(30); expect(root.root.findAllByType("button").some(node => node.children.includes(t("settings.showMore")))).toBe(false);
});
it.each(["success", "failure"] as const)("does not publish a retired listing or listing error: %s", async outcome => {
  let resolve!: (rows: ListedEntry[]) => void, reject!: (failure: Error) => void; const pending = new Promise<ListedEntry[]>((yes, no) => { resolve = yes; reject = no; }); vi.mocked(client.listEntriesWalk).mockReturnValue(pending); const root = await render(<HistoryView />), initial = publicSurface(root.toJSON()); clearSession();
  await act(async () => { outcome === "success" ? resolve([await row("retired", "Retired account writing")]) : reject(new Error("retired account fetch error")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(initial);
});
it("does not publish decrypted rows after the actual local mood read finishes for a retired owner", async () => {
  const initial = await row("retired", "Retired account writing"), gate = deferred<void>(), began = deferred<void>(), real = moods.recentMoods; vi.spyOn(moods, "recentMoods").mockImplementation(async (...args) => { const result = await real(...args); began.resolve(); await gate.promise; return result; }); vi.mocked(client.listEntriesWalk).mockResolvedValue([initial]); const root = await render(<HistoryView />); await began.promise; const surface = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(surface);
});
it.each(["encrypt", "upload"] as const)("does not continue an edit after its actual%s boundary finishes for a retired session", async boundary => {
  const initial = await row(), gate = deferred<void>(), began = deferred<void>(), real = patient.encryptEntry; const updated = vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "edited" });
  if (boundary === "encrypt") vi.spyOn(patient, "encryptEntry").mockImplementation(async (...args) => { const result = await real(...args); began.resolve(); await gate.promise; return result; });
  else updated.mockImplementation(async () => { began.resolve(); await gate.promise; return { id: "edited" }; });
  const root = await mount([initial]); await beginEdit(root, "Late edit writing"); await press(root, t("history.saveEdit")); await began.promise; const surface = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(surface); expect(client.listEntriesWalk).toHaveBeenCalledTimes(1); if (boundary === "encrypt") expect(updated).not.toHaveBeenCalled();
});
it.each(["fetch", "decrypt"] as const)("does not display a competing edit after its actual%s boundary retires", async boundary => {
  const initial = await row("conflicted", "Originally saved", 1), fresh = await row("conflicted", "Other account late writing", 4), gate = deferred<void>(), began = deferred<void>(), real = patient.decryptEntry; vi.spyOn(api, "updateEntry").mockRejectedValue(new ApiError(409, "changed elsewhere", "version_conflict")); const get = vi.spyOn(api, "getEntry").mockResolvedValue(fresh);
  const root = await mount([initial]);
  if (boundary === "fetch") get.mockImplementation(async () => { began.resolve(); await gate.promise; return fresh; });
  else vi.spyOn(patient, "decryptEntry").mockImplementation(async (...args) => { const result = await real(...args); began.resolve(); await gate.promise; return result; });
  await beginEdit(root, "My writing"); await press(root, t("history.saveEdit")); await began.promise; const surface = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(surface); expect(textOf(root)).not.toContain("Other account late writing");
});
it.each(["delete", "forget-version", "remove-mood"] as const)("does not refresh a deleted account after its actual%s boundary retires", async boundary => {
  const initial = await row(), gate = deferred<void>(), began = deferred<void>(); const removed = vi.spyOn(api, "deleteEntry").mockResolvedValue(null), realForget = versions.forgetEntryVersion, realMood = moods.removeMoodDay; const root = await mount([initial]);
  if (boundary === "delete") removed.mockImplementation(async () => { began.resolve(); await gate.promise; return null; });
  else if (boundary === "forget-version") vi.spyOn(versions, "forgetEntryVersion").mockImplementation(async (...args) => { await realForget(...args); began.resolve(); await gate.promise; });
  else vi.spyOn(moods, "removeMoodDay").mockImplementation(async (...args) => { await realMood(...args); began.resolve(); await gate.promise; });
  await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); await began.promise; const surface = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(surface); expect(client.listEntriesWalk).toHaveBeenCalledTimes(1);
});
it.each(["timer", "native idle callback"] as const)("lets a queued native navigation retire a large malformed tail during decryption: %s", async host => {
  const valid = await Promise.all(Array.from({ length: 25 }, (_, index) => row(`host-${index}`, `Host event writing ${index}`))), broken = Array.from({ length: 80 }, (_, index) => ({ ...valid[0]!, id: `broken-server-${index}`, client_entry_id: `broken-${index}`, blob: "!" }));
  if (host === "native idle callback") vi.stubGlobal("requestIdleCallback", (callback: () => void) => setTimeout(callback, 0)); else vi.stubGlobal("requestIdleCallback", undefined);
  const real = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const plaintext = await real(...args);
    // Identify the known last entry at the actual decrypt boundary. Other
    // encrypted metadata can decrypt during a walk, so counting all native
    // decrypt calls would retire the session before the intended row.
    try { if (JSON.parse(new TextDecoder().decode(plaintext)).text === "Host event writing 24") setTimeout(() => { clearSession(); }, 0); } catch { /* non-entry binary output */ }
    return plaintext;
  });
  vi.mocked(client.listEntriesWalk).mockResolvedValue([...valid, ...broken]); const root = await render(<HistoryView />); await flush(); expect(textOf(root)).not.toContain("Host event writing"); expect(root.root.findAllByType("article")).toHaveLength(0); expect(await versions.entryV2Bindings(owner, reference)).toEqual(new Set()); expect(await (await import("../src/kvstore")).kv.getItem(`mindpattern.entryV2Bound.${owner}`)).toBeNull(); for (const entry of valid) expect(await versions.knownEntryVersion(owner, reference, entry.client_entry_id)).toBeNull(); vi.unstubAllGlobals();
});
it("completes a normal large history walk when the browser grants its native idle callback", async () => {
  vi.stubGlobal("requestIdleCallback", (callback: () => void) => setTimeout(callback, 0));
  const rows = await Promise.all(Array.from({ length: 26 }, (_, index) => row(`native-idle-${index}`, `Readable idle entry${index}`))), root = await mount(rows);
  expect(root.root.findAllByType("article")).toHaveLength(26); expect(textOf(root)).toContain("Readable idle entry25"); expect(textOf(root)).not.toContain(t("common.loading"));
});
it.each(["old failure", "delete another recording"] as const)("keeps the current real audio player and its controls when handling%s", async outcome => {
  const first = await row("first-audio", "First recorded writing", 1, undefined, "2026-11-01"), second = await row("second-audio", "Second recorded writing", 1, undefined, "2026-11-01"), firstAudio = await encryptAudio(reference, owner, first.client_entry_id, new Uint8Array([1, 2, 3])), secondAudio = await encryptAudio(reference, owner, second.client_entry_id, new Uint8Array([4, 5, 6]));
  let rejectFirst!: (error: Error) => void;
  vi.spyOn(api, "fetchAudioAttachment").mockImplementation(id => {
    if (id === first.audio!.attachment_id && outcome === "old failure") return new Promise((_resolve, reject) => { rejectFirst = reject; });
    const entry = id === first.audio!.attachment_id ? first : second, encrypted = entry === first ? firstAudio : secondAudio;
    return Promise.resolve({ ...attachment(encrypted.blobB64), id, client_entry_id: entry.client_entry_id });
  });
  const remove = vi.spyOn(api, "deleteAudioAttachment").mockResolvedValue(null), root = await mount([first, second]);
  const article = (writing: string) => root.root.findAllByType("article").find(node => textOfNode(node).includes(writing))!;
  const click = async (writing: string, label: string) => { const button = article(writing).findAllByType("button").find(node => textOfNode(node) === label)!; expect(button.props.disabled).not.toBe(true); await act(async () => { button.props.onClick(); }); };
  if (outcome === "old failure") { await click("First recorded writing", t("history.playRecording")); const busy = article("First recorded writing").findAllByType("button").filter(node => [t("history.playRecording"), t("history.deleteRecording")].includes(textOfNode(node))); expect(busy.every(node => node.props.disabled === true)).toBe(true); }
  await click("Second recorded writing", t("history.playRecording")); await flush(); expect(article("Second recorded writing").findAllByType("audio")).toHaveLength(1);
  if (outcome === "old failure") { await act(async () => { rejectFirst(new Error("retired first recording failure")); }); await flush(); expect(textOf(root)).not.toContain(t("history.playbackFailed")); }
  else { await click("First recorded writing", t("history.deleteRecording")); await flush(); expect(remove).toHaveBeenCalledWith(first.audio!.attachment_id); expect(article("First recorded writing").findAllByType("button").some(node => textOfNode(node) === t("history.playRecording"))).toBe(false); }
  expect(article("Second recorded writing").findAllByType("audio")).toHaveLength(1); await click("Second recorded writing", t("history.stopRecording")); expect(root.root.findAllByType("audio")).toHaveLength(0);
});
it("redraws its actual calendar mood and legend after a public theme change", async () => {
  vi.stubGlobal("document", { documentElement: { dataset: { theme: "light" } } });
  const root = await mount([await row()]); const day = () => root.root.findAllByType("button").find(node => String(node.props["aria-label"]).startsWith("2026-10-05"))!;
  const light = day().props.style.backgroundColor; await act(async () => { applyThemePref("dark"); }); const dark = day().props.style.backgroundColor;
  expect(dark).not.toBe(light); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await act(async () => { applyThemePref("light"); }); expect(day().props.style.backgroundColor).toBe(light);
});
it("counts only the current single-digit month when another month also contains writing", async () => {
  vi.setSystemTime(new Date("2026-01-05T12:00:00Z")); const january = await row("january", "January writing"), secondJanuary = await row("january-second", "Another January day"), october = await row("october", "October writing"); january.entry_date = "2026-01-05"; secondJanuary.entry_date = "2026-01-06";
  const root = await mount([january, secondJanuary, october]); expect(textOf(root)).toContain(t("history.monthEntriesMany", { count: 2 })); expect(textOf(root)).not.toContain(t("history.monthEntriesOne", { count: 1 }));
});
it("does not accept a legacy replay after this view previously authenticated the same entry's version binding", async () => {
  const bound = await row("bound-once", "Version-bound current writing", 1), first = await mount([bound]); expect(textOf(first)).toContain("Version-bound current writing"); await act(async () => { first.unmount(); });
  const legacy = await encryptEntry(reference, owner, bound.client_entry_id, "Never display the old version-free replay", "2026-10-05T11:22:33Z", 0.8), root = await mount([{ ...bound, blob: legacy.blobB64 }]);
  expect(textOf(root)).not.toContain("Never display the old version-free replay"); expect(textOf(root)).toContain(t("history.hiddenOne", { count: 1 }));
});
it("keeps decrypted writing available when the disposable local mood read rejects", async () => {
  vi.spyOn(moods, "recentMoods").mockRejectedValue(new Error("local metadata read unavailable")); const root = await mount([await row()]); expect(textOf(root)).toContain("A truthful journal entry"); expect(textOf(root)).not.toContain("local metadata read unavailable"); expect(textOf(root)).not.toContain(t("common.loading"));
});
it.each(["held refresh", "retired owner"] as const)("shows an honest state when keeping the competing edit starts a %s", async outcome => {
  const initial = await row("conflicted", "Originally saved", 1), fresh = await row("conflicted", "Competing writing", 3); vi.spyOn(api, "updateEntry").mockRejectedValue(new ApiError(409, "changed elsewhere", "version_conflict")); vi.spyOn(api, "getEntry").mockResolvedValue(fresh);
  const root = await mount([initial]); await beginEdit(root, "My retained writing"); await press(root, t("history.saveEdit")); await flush(); expect(textOf(root)).toContain(t("history.conflictTitle"));
  const held = deferred<ListedEntry[]>(); vi.mocked(client.listEntriesWalk).mockReturnValue(held.promise);
  if (outcome === "retired owner") clearSession(); await press(root, t("history.keepTheirs")); await flush();
  if (outcome === "retired owner") { expect(textOf(root)).toContain(t("common.sessionLocked")); expect(client.listEntriesWalk).toHaveBeenCalledTimes(1); }
  else { expect(textOf(root)).toContain(t("common.loading")); expect(root.root.findAllByType("article")).toHaveLength(0); await act(async () => { held.resolve([fresh]); }); await flush(); expect(textOf(root)).toContain("Competing writing"); }
});
it.each(["edit", "delete"] as const)("refuses the still-enabled public %s button after its vault locks without a native rejected event", async action => {
  const failures: unknown[] = [], observe = (reason: unknown) => { failures.push(reason); }; process.on("unhandledRejection", observe);
  try { vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "unexpected" }); vi.spyOn(api, "deleteEntry").mockResolvedValue(null); const root = await mount([await row()]); if (action === "edit") await beginEdit(root, "Before locking"); else await press(root, t("common.delete")); vault.lock(); await press(root, t(action === "edit" ? "history.saveEdit" : "common.deletePermanently")); await flush(); expect(failures).toEqual([]); expect(api.updateEntry).not.toHaveBeenCalled(); expect(api.deleteEntry).not.toHaveBeenCalled(); }
  finally { process.removeListener("unhandledRejection", observe); }
});
it.each(["recording", "entry"] as const)("does not publish a retired public %s deletion failure", async kind => {
  let reject!: (reason: Error) => void; const pending = new Promise<null>((_resolve, no) => { reject = no; });
  if (kind === "recording") vi.spyOn(api, "deleteAudioAttachment").mockReturnValue(pending); else vi.spyOn(api, "deleteEntry").mockReturnValue(pending);
  const root = await mount([await row("recorded", "Keep this writing", 1, undefined, "2026-11-01")]);
  if (kind === "recording") await press(root, t("history.deleteRecording")); else { await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); }
  const before = publicSurface(root.toJSON()); clearSession(); await act(async () => { reject(new Error("retired deletion failure")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before);
});
it("keeps the actual edit field read-only while its accepted ciphertext commit would otherwise discard later typing", async () => {
  const held = deferred<void>(), began = deferred<void>(), update = vi.spyOn(api, "updateEntry").mockImplementation(async () => { began.resolve(); await held.promise; return { id: "committed-edit" }; });
  const root = await mount([await row()]); await beginEdit(root, "The writing actually submitted"); await press(root, t("history.saveEdit")); await began.promise;
  try { expect(root.root.findAllByType("textarea")[0]!.props.disabled).toBe(true); expect(isDisabled(root, t("entry.saving"))).toBe(true); }
  finally { await act(async () => { held.resolve(); }); await flush(); }
  const wire = update.mock.calls[0]!; expect((await decryptEntry(reference, owner, wire[0], wire[1], wire[3])).text).toBe("The writing actually submitted"); expect(root.root.findAllByType("textarea")).toHaveLength(0);
});

it.each(["play", "delete"] as const)("refuses a still-rendered recording %s after native vault retirement", async action => {
  const errors: unknown[] = [], observe = (reason: unknown) => { errors.push(reason); }; process.on("unhandledRejection", observe);
  try {
    const root = await mount([await row("recorded", "Retained recorded writing", 1, undefined, "2026-11-01")]), fetched = vi.spyOn(api, "fetchAudioAttachment"), removed = vi.spyOn(api, "deleteAudioAttachment"); vault.lock();
    await press(root, t(action === "play" ? "history.playRecording" : "history.deleteRecording")); await flush(); expect(errors).toEqual([]); expect(fetched).not.toHaveBeenCalled(); expect(removed).not.toHaveBeenCalled(); expect(root.root.findAllByType("audio")).toHaveLength(0);
  } finally { process.removeListener("unhandledRejection", observe); }
});
it.each(["failure", "success"] as const)("keeps a replacement recording visibly busy while a retired %s settles", async outcome => {
  const first = await row("first-audio", "First pending take", 1, undefined, "2026-11-01"), second = await row("second-audio", "Second pending take", 1, undefined, "2026-11-01"), firstBytes = await encryptAudio(reference, owner, first.client_entry_id, new Uint8Array([1, 2])), secondBytes = await encryptAudio(reference, owner, second.client_entry_id, new Uint8Array([3, 4]));
  let resolveFirst!: (value: Awaited<ReturnType<typeof api.fetchAudioAttachment>>) => void, rejectFirst!: (reason: Error) => void;
  const one = new Promise<Awaited<ReturnType<typeof api.fetchAudioAttachment>>>((yes, no) => { resolveFirst = yes; rejectFirst = no; }), two = deferred<Awaited<ReturnType<typeof api.fetchAudioAttachment>>>(); vi.spyOn(api, "fetchAudioAttachment").mockImplementation(id => id === first.audio!.attachment_id ? one : two.promise);
  const root = await mount([first, second]), article = (writing: string) => root.root.findAllByType("article").find(node => textOfNode(node).includes(writing))!;
  const click = async (writing: string) => { const button = article(writing).findAllByType("button").find(node => textOfNode(node) === t("history.playRecording"))!; expect(button.props.disabled).not.toBe(true); await act(async () => { button.props.onClick(); }); };
  await click("First pending take"); await click("Second pending take"); await act(async () => { if (outcome === "failure") rejectFirst(new Error("Old recording refused")); else resolveFirst({ ...attachment(firstBytes.blobB64), id: first.audio!.attachment_id, client_entry_id: first.client_entry_id }); }); await flush();
  try { expect(article("Second pending take").findAllByType("button").filter(n => [t("history.playRecording"), t("history.deleteRecording")].includes(textOfNode(n))).every(n => n.props.disabled === true)).toBe(true); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(textOf(root)).not.toContain(t("history.playbackFailed")); }
  finally { await act(async () => { two.resolve({ ...attachment(secondBytes.blobB64), id: second.audio!.attachment_id, client_entry_id: second.client_entry_id }); }); await flush(); }
  expect(article("Second pending take").findAllByType("audio")).toHaveLength(1);
});
it("shows recording deletion as busy and clears a preceding playback error only after its accepted public action", async () => {
  const root = await mount([await row("recorded", "Retained recording", 1, undefined, "2026-11-01")]); vi.spyOn(api, "fetchAudioAttachment").mockRejectedValue(new ApiError(0, "Offline recording")); await press(root, t("history.playRecording")); await flush(); expect(textOf(root)).toContain(t("history.loadOffline"));
  const removed = deferred<null>(); vi.spyOn(api, "deleteAudioAttachment").mockReturnValue(removed.promise); await press(root, t("history.deleteRecording"));
  try { expect(isDisabled(root, t("history.deleteRecording"))).toBe(true); expect(isDisabled(root, t("history.playRecording"))).toBe(true); expect(textOf(root)).not.toContain(t("history.loadOffline")); expect(root.root.findAllByType("div").filter(n => n.props.role === "alert")).toHaveLength(0); }
  finally { await act(async () => { removed.resolve(null); }); await flush(); }
  expect(root.root.findAllByType("button").some(n => textOfNode(n) === t("history.playRecording"))).toBe(false);
});
it.each(["edit", "delete", "load"] as const)("uses honest localized generic copy for a non-Error %s failure", async action => {
  if (action === "load") { vi.mocked(client.listEntriesWalk).mockRejectedValue(null); const root = await render(<HistoryView />); await flush(); expect(textOf(root)).toContain(t("history.loadFailed")); return; }
  const root = await mount([await row()]); if (action === "edit") { vi.spyOn(api, "updateEntry").mockRejectedValue(null); await beginEdit(root, "Retain this edited writing"); await press(root, t("history.saveEdit")); }
  else { vi.spyOn(api, "deleteEntry").mockRejectedValue(null); await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); }
  await flush(); expect(textOf(root)).toContain(t(action === "edit" ? "history.editFailed" : "history.deleteFailed"));
});

it("does not author a new authenticated binding after the native last-row decrypt retires its account epoch", async () => {
  const initial = await row("late-native-bound", "Native last-row plaintext"), real = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const plaintext = await real(...args); try { if (JSON.parse(new TextDecoder().decode(plaintext)).text === "Native last-row plaintext") clearSession(); } catch { /* encrypted non-entry metadata */ } return plaintext;
  });
  vi.mocked(client.listEntriesWalk).mockResolvedValue([initial]); const root = await render(<HistoryView />); await flush();
  expect(textOf(root)).not.toContain("Native last-row plaintext"); expect(await versions.entryV2Bindings(owner, reference)).toEqual(new Set()); expect(await versions.knownEntryVersion(owner, reference, initial.client_entry_id)).toBeNull();
});
it("does not advance the authenticated version mirror after a binding commit retires its native account epoch", async () => {
  const initial = await row("late-native-version", "Native version candidate"), real = crypto.subtle.encrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => {
    const encrypted = await real(...args), params = args[0] as AesGcmParams;
    try { if (JSON.parse(new TextDecoder().decode(params.additionalData!))[0] === "entry-v2-bound") clearSession(); } catch { /* non-binding encrypted channel */ }
    return encrypted;
  });
  vi.mocked(client.listEntriesWalk).mockResolvedValue([initial]); const root = await render(<HistoryView />); await flush();
  expect(await versions.entryV2Bindings(owner, reference)).toEqual(new Set([initial.client_entry_id])); expect(await versions.knownEntryVersion(owner, reference, initial.client_entry_id)).toBeNull(); expect(textOf(root)).not.toContain("Native version candidate");
});
it("retains a replacement epoch's actual mood receipt when an old accepted deletion finishes its native version cleanup", async () => {
  const records = new Map<string, string>(); let replaceAtCleanup = false;
  setKvBackendForTests({ getItem: async slot => records.get(slot) ?? null, setItem: async (slot, value) => { records.set(slot, value); }, removeItem: async slot => {
    records.delete(slot);
    if (replaceAtCleanup && slot === `mindpattern.entryVersions.${owner}`) { replaceAtCleanup = false; clearSession(); installSession(owner); vault.unlock({ authKey: reference.slice(), dataKey: reference.slice() }, owner); await recordMood(reference, owner, "2026-10-05", -0.5); }
  }, keys: async () => [...records.keys()] });
  const root = await mount([await row("delete-old-epoch", "Delete original writing")]); await recordMood(reference, owner, "2026-10-05", 0.8); replaceAtCleanup = true;
  vi.spyOn(api, "deleteEntry").mockResolvedValue(null); await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); await flush();
  expect(await moods.recentMoods(reference, owner)).toEqual([{ date: "2026-10-05", value: -0.5 }]);
});

it("does not treat a known upstream edit refusal as a competing deletion", async () => {
  const root = await mount([await row()]); vi.spyOn(api, "updateEntry").mockRejectedValue(new ApiError(503, "Keep the authenticated edit open")); await beginEdit(root, "Retained edited writing"); await press(root, t("history.saveEdit")); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Retained edited writing"); expect(textOf(root)).toContain(t("errors.serverError")); expect(textOf(root)).not.toContain(t("history.deletedElsewhere"));
});
it("requires a new delete confirmation when an independently authored entry legitimately reuses an erased identifier", async () => {
  const old = await row("recreated", "Original erased writing", 3), recreated = await row("recreated", "Newly authored writing with reused identifier", 1), root = await mount([old]);
  vi.spyOn(api, "deleteEntry").mockResolvedValue(null); vi.mocked(client.listEntriesWalk).mockResolvedValue([recreated]); await press(root, t("common.delete")); await press(root, t("common.deletePermanently")); await flush(); expect(textOf(root)).toContain("Newly authored writing with reused identifier");
  expect(root.root.findAllByType("button").some(n => textOfNode(n) === t("common.deletePermanently"))).toBe(false); await press(root, t("common.delete")); expect(root.root.findAllByType("button").some(n => textOfNode(n) === t("common.deletePermanently"))).toBe(true);
});
it("preserves a pending refresh's honest empty loading state when a concurrent kept-recording deletion settles", async () => {
  const initial = await row("refresh-recorded", "Refresh recorded writing", 1, undefined, "2026-11-01"), removed = deferred<null>(), refresh = deferred<ListedEntry[]>(); vi.spyOn(api, "deleteAudioAttachment").mockReturnValue(removed.promise); vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "accepted refreshed edit" });
  vi.mocked(client.listEntriesWalk).mockResolvedValue([initial]); const { ViewBoundary } = await import("../src/ErrorBoundary"), root = await render(<ViewBoundary resetKey="history"><HistoryView /></ViewBoundary>); await flush(); await press(root, t("history.deleteRecording")); await beginEdit(root, "Updated recorded writing"); vi.mocked(client.listEntriesWalk).mockReturnValue(refresh.promise); await press(root, t("history.saveEdit")); await flush(); expect(textOf(root)).toContain(t("common.loading"));
  await act(async () => { removed.resolve(null); }); await flush(); expect(textOf(root)).not.toContain(t("app.crashTitle")); expect(root.root.findAllByType("article")).toHaveLength(0); await act(async () => { refresh.resolve([]); }); await flush(); expect(textOf(root)).toContain(t("history.empty"));
});

it("does not consume the session crisis throttle when the actual read completes after its edit owner retires", async () => {
  const real = crisis.crisisDialogShownOn; vi.spyOn(crisis, "crisisDialogShownOn").mockImplementation(async (...args) => { const receipt = await real(...args); clearSession(); return receipt; });
  vi.spyOn(api, "updateEntry").mockResolvedValue({ id: "accepted-crisis-edit" }); const root = await mount([await row()]); await beginEdit(root, "I want to kill myself"); await press(root, t("history.saveEdit")); await flush();
  expect(textOf(root)).not.toContain(t("entry.crisisPromptTitle")); expect(await real(owner, "2026-10-05")).toBe(false);
});
it.each(["commit", "conflict reload"] as const)("does not publish an old account's late %s failure over the still-mounted public editor", async boundary => {
  let reject!: (reason: Error) => void; const pending = new Promise<never>((_yes, no) => { reject = no; });
  if (boundary === "commit") vi.spyOn(api, "updateEntry").mockReturnValue(pending);
  else { vi.spyOn(api, "updateEntry").mockRejectedValue(new ApiError(409, "competing edit", "version_conflict")); vi.spyOn(api, "getEntry").mockReturnValue(pending); }
  const root = await mount([await row()]); await beginEdit(root, "Retained old-account revision"); await press(root, t("history.saveEdit")); await flush(); const before = publicSurface(root.toJSON()); clearSession();
  await act(async () => { reject(new Error("Late old-account failure")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(textOf(root)).not.toContain("Late old-account failure"); expect(textOf(root)).not.toContain(t("history.conflictReloadFailed"));
});
it("disables the accepted permanent deletion and independent edit controls until the actual endpoint completes", async () => {
  const pending = deferred<null>(); vi.spyOn(api, "deleteEntry").mockReturnValue(pending.promise); const root = await mount([await row("busy-delete", "Delete accepted writing"), await row("busy-other", "Retain separate writing")]);
  const first = root.root.findAllByType("article").find(node => textOfNode(node).includes("Delete accepted writing"))!, button = first.findAllByType("button").find(node => textOfNode(node) === t("common.delete"))!; await act(async () => { button.props.onClick(); }); await press(root, t("common.deletePermanently"));
  try { expect(isDisabled(root, t("common.deletePermanently"))).toBe(true); expect(root.root.findAllByType("button").filter(node => textOfNode(node) === t("history.edit")).every(node => node.props.disabled === true)).toBe(true); }
  finally { vi.mocked(client.listEntriesWalk).mockResolvedValue([]); await act(async () => { pending.resolve(null); }); await flush(); }
});

it("services queued browser navigation at the native idle opportunity following a full decrypted batch", async () => {
  let queuedNavigation = false;
  vi.stubGlobal("requestIdleCallback", (callback: () => void) => setTimeout(() => { if (queuedNavigation) clearSession(); callback(); }, 0));
  const rows = await Promise.all(Array.from({ length: 25 }, (_, index) => row(`idle-batch-${index}`, `Idle batch writing ${index}`))), broken = Array.from({ length: 80 }, (_, index) => ({ ...rows[0]!, id: `idle-broken-server-${index}`, client_entry_id: `idle-broken-${index}`, blob: "!" })), real = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => { const plaintext = await real(...args); try { if (JSON.parse(new TextDecoder().decode(plaintext)).text === "Idle batch writing 24") queuedNavigation = true; } catch { /* authenticated non-entry metadata */ } return plaintext; });
  vi.mocked(client.listEntriesWalk).mockResolvedValue([...rows, ...broken]); const root = await render(<HistoryView />); await flush(); expect(textOf(root)).not.toContain("Idle batch writing"); expect(await versions.entryV2Bindings(owner, reference)).toEqual(new Set()); expect(await (await import("../src/kvstore")).kv.getItem(`mindpattern.entryV2Bound.${owner}`)).toBeNull();
});

it.each(["valid rows", "malformed prefix"] as const)("finishes a real history walk with %s while the browser has no idle time by using its native deadline", async shape => {
  const pending: Array<() => void> = []; vi.stubGlobal("requestIdleCallback", (callback: () => void, options?: { timeout?: number }) => { pending.push(callback); if (options?.timeout !== undefined) return setTimeout(callback, options.timeout); return 1; });
  const rows = await Promise.all(Array.from({ length: 26 }, (_, index) => row(`busy-browser-${index}`, `Readable busy-browser entry${index}`)));
  const malformed = shape === "malformed prefix" ? Array.from({ length: 40 }, (_, index) => ({ ...rows[0]!, id: `busy-prefix-server-${index}`, client_entry_id: `busy-prefix-${index}`, blob: "!" })) : [];
  vi.mocked(client.listEntriesWalk).mockResolvedValue([...malformed, ...rows]); const root = await render(<HistoryView />);
  try { await act(async () => { await new Promise(resolve => setTimeout(resolve, 150)); }); expect(root.root.findAllByType("article")).toHaveLength(26); expect(textOf(root)).not.toContain(t("common.loading")); }
  finally { await act(async () => { for (const callback of pending) callback(); }); await flush(); }
});

it("does not block a replacement account's actual mood reader behind an obsolete native history read after the version receipt retires its scope", async () => {
  const replacement = "history-mood-replacement", records = new Map<string, string>(), pending = deferred<string | null>(), committed = deferred<void>(); let retired = false;
  setKvBackendForTests({ getItem: async slot => slot === `mindpattern.moodlog.${owner}` && retired ? pending.promise : records.get(slot) ?? null, setItem: async (slot, value) => { records.set(slot, value); if (slot === `mindpattern.entryVersions.${owner}` && !retired) { retired = true; clearSession(); installSession(replacement); vault.unlock({ authKey: reference.slice(), dataKey: reference.slice() }, replacement); committed.resolve(); } }, removeItem: async slot => { records.delete(slot); }, keys: async () => [...records.keys()] });
  vi.mocked(client.listEntriesWalk).mockResolvedValue([await row("old-mood-read", "Obsolete authenticated writing")]); const root = await render(<HistoryView />);
  try {
    let timer!: ReturnType<typeof setTimeout>; const reached = await Promise.race([committed.promise.then(() => true), new Promise<boolean>(yes => { timer = setTimeout(() => yes(false), 300); })]); clearTimeout(timer); expect(reached).toBe(true); await flush();
    const result = await Promise.race([moods.recentMoods(reference, replacement), new Promise<string>(yes => { timer = setTimeout(() => yes("blocked behind retired account"), 50); })]); clearTimeout(timer); expect(result).toEqual([]); expect(textOf(root)).not.toContain("Obsolete authenticated writing");
  } finally { await act(async () => { pending.resolve(null); }); await flush(); }
});
it("does not restore an independently erased binding into the actual global mirror through a retired listing's delayed native read", async () => {
  const records = new Map<string, string>(), pending = deferred<void>(), removedId = "erased-bound-id", slot = `mindpattern.entryV2Bound.${owner}`; let retiredListing = false, eraseStarted = false;
  setKvBackendForTests({ getItem: async key => { const value = records.get(key) ?? null; if (key === slot && retiredListing && !eraseStarted) await pending.promise; return value; }, setItem: async (key, value) => { records.set(key, value); }, removeItem: async key => { records.delete(key); }, keys: async () => [...records.keys()] });
  await versions.noteV2BoundBatch(owner, reference, new Set([removedId])); resetEntryVersionMirrors(); vi.mocked(client.listEntriesWalk).mockImplementation(async () => { clearSession(); retiredListing = true; return []; }); const root = await render(<HistoryView />); await flush();
  try { eraseStarted = true; await versions.forgetEntryVersion(owner, reference, removedId); }
  finally { await act(async () => { pending.resolve(); }); await flush(); }
  expect(await versions.entryV2Bindings(owner, reference)).toEqual(new Set()); expect(textOf(root)).not.toContain(removedId);
});
it("releases its real edit key immediately after a retired translation failure without admitting a fresh unavailable native encryption", async () => {
  const initial = await row("retired-translation-key", "Saved voice writing", 2, { inputMode: "voice", transcriptLang: "en", englishText: "Saved translated writing" }), gate = deferred<void>(), real = crypto.subtle.encrypt.bind(crypto.subtle);
  const root = await mount([initial]); vi.spyOn(api, "translateText").mockImplementation(async () => { clearSession(); throw new ApiError(503, "retired translation unavailable"); });
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const result = await real(...args); await gate.promise; return result; }); const { observeSecretCopies } = await import("./helpers/secretCustody"); await beginEdit(root, "Edited private writing whose translation retired");
  try { const held = await observeSecretCopies(reference, async () => { await press(root, t("history.saveEdit")); await flush(); }); expect(held.copies.length).toBeGreaterThan(0); for (const copy of held.copies) expect(copy.every(byte => byte === 0)).toBe(true); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});
it.each(["next history row", "competing edit"] as const)("does not retain newly decrypted native plaintext after its owner retires before the %s boundary", async boundary => {
  const secret = "New native plaintext that must not be admitted after retirement", initial = await row("first-native-retire", "First native retiring row"), next = await row("next-native-retire", secret, 4), gate = deferred<void>(), observed: Uint8Array[] = [], real = crypto.subtle.decrypt.bind(crypto.subtle);
  let root: Root;
  if (boundary === "competing edit") { root = await mount([initial]); vi.spyOn(api, "updateEntry").mockRejectedValue(new ApiError(409, "competing entry", "version_conflict")); vi.spyOn(api, "getEntry").mockImplementation(async () => { clearSession(); return next; }); }
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => { const result = await real(...args); try { const text = JSON.parse(new TextDecoder().decode(result)).text; if (text === "First native retiring row" && boundary === "next history row") clearSession(); if (text === secret) { observed.push(new Uint8Array(result)); await gate.promise; } } catch { /* authenticated non-entry metadata */ } return result; });
  if (boundary === "next history row") { vi.mocked(client.listEntriesWalk).mockResolvedValue([initial, next]); root = await render(<HistoryView />); } else { await beginEdit(root!, "Competing private edit"); await press(root!, t("history.saveEdit")); }
  try { await flush(); for (const plaintext of observed) expect(plaintext.every(byte => byte === 0)).toBe(true); expect(textOf(root!)).not.toContain(secret); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("stops its native recording on the explicit public stop button without acquiring a new playback", async () => {
  const encrypted = await encryptAudio(reference, owner, "recorded", new Uint8Array([1, 3, 5, 7])), fetched = deferred<Awaited<ReturnType<typeof api.fetchAudioAttachment>>>();
  vi.spyOn(api, "fetchAudioAttachment").mockResolvedValueOnce(attachment(encrypted.blobB64)).mockReturnValue(fetched.promise);
  const root = await mount([await row("recorded", "Actual currently played writing", 1, undefined, "2026-11-01")]); await press(root, t("history.playRecording")); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(1);
  try { await press(root, t("history.stopRecording")); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(isDisabled(root, t("history.playRecording"))).toBe(false); expect(api.fetchAudioAttachment).toHaveBeenCalledTimes(1); }
  finally { await act(async () => { fetched.resolve(attachment(encrypted.blobB64)); }); await flush(); }
});
it("keeps both public conflict choices disabled while an actual accepted apply-mine update remains unresolved", async () => {
  const initial = await row("conflict-admission", "Original authentic writing", 1), fresh = await row("conflict-admission", "Their competing authentic writing", 4), pending = deferred<Awaited<ReturnType<typeof api.updateEntry>>>(), began = deferred<void>();
  vi.spyOn(api, "getEntry").mockResolvedValue(fresh);
  vi.spyOn(api, "updateEntry").mockRejectedValueOnce(new ApiError(409, "Competing native update", "version_conflict")).mockImplementation(async () => { began.resolve(); return pending.promise; });
  const root = await mount([initial]); await beginEdit(root, "My authentic preserved writing"); await press(root, t("history.saveEdit")); await flush(); await press(root, t("history.applyMine"));
  try { let timer!: ReturnType<typeof setTimeout>; const started = await Promise.race([began.promise.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), 300); })]); clearTimeout(timer); expect(started).toBe(true); expect(isDisabled(root, t("history.applyMine"))).toBe(true); expect(isDisabled(root, t("history.keepTheirs"))).toBe(true); }
  finally { await act(async () => { pending.resolve({ id: "accepted-my-writing" }); }); await flush(); }
});
