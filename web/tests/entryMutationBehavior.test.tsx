import { act, Profiler } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { EntryView } from "../src/views/Entry";
import { api, ApiError, clearSession } from "../src/api/client";
import { decryptAudio, decryptEntry } from "../src/crypto/patient";
import * as drafts from "../src/entryDraft";
import { recordMood } from "../src/moodLog";
import { enqueue, queueLength } from "../src/offlineQueue";
import { kv, StorageReadError, StorageCommitError } from "../src/kvstore";
import { vault } from "../src/vault";
import { __setLocaleForTests, t } from "../src/strings";
import { resetTestState, installSession } from "./helpers/api";
import { isDisabled, press, pressAria, pressSwitch, render, textOf, textOfNode, typeArea } from "./helpers/rtr";
import { publicSurface } from "./helpers/publicSurface";
import { promptChipsFor } from "../src/promptChips";
import * as crisis from "../src/crisisDialog";

const owner = "entry-behavior-owner", key = new Uint8Array(new ArrayBuffer(32)).fill(79);
const audioBytes = new Uint8Array([1, 3, 5, 7, 9, 11]);
type Root = Awaited<ReturnType<typeof render>>;
const flush = async () => { for (let i = 0; i < 10; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); };
function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { resolve, reject, promise }; }
const transcript: Awaited<ReturnType<typeof api.transcribeAudio>> = { original_text: "Una entrada hablada", language: "es", language_raw: "Spanish", english_text: "A spoken entry", provider_name: "Approved audio provider", policy_version: "v2" };
class NativeRecorder {
  static isTypeSupported(mime: string): boolean { return mime === "audio/webm"; }
  mimeType = "audio/webm"; state = "inactive";
  ondataavailable: ((event: { data: Blob }) => void) | null = null;
  onstop: (() => void) | null = null; onerror: (() => void) | null = null;
  constructor(_stream: MediaStream, _options: MediaRecorderOptions) {}
  start() { this.state = "recording"; }
  stop() { if (this.state === "inactive") return; this.state = "inactive"; this.ondataavailable?.({ data: new Blob([audioBytes], { type: this.mimeType }) }); this.onstop?.(); }
}
let media: ReturnType<typeof vi.fn>;
async function mount(saved = vi.fn(), support = vi.fn()) { const root = await render(<EntryView onSaved={saved} onCrisis={support} />); await flush(); return root; }
async function take(root: Root) { await press(root, t("entry.micRecord")); await flush(); expect(isDisabled(root, t("entry.save"))).toBe(true); await press(root, t("entry.micStop")); await flush(); }
beforeEach(() => {
  resetTestState(); __setLocaleForTests("en"); vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date(2026, 9, 5, 10, 11, 12)); installSession(owner); vault.unlock({ authKey: key.slice(), dataKey: key.slice() }, owner);
  const track = { stop: vi.fn(), readyState: "live", addEventListener: vi.fn(), removeEventListener: vi.fn() }, stream = { getTracks: () => [track] }; media = vi.fn(async () => stream);
  vi.stubGlobal("MediaRecorder", NativeRecorder); vi.stubGlobal("navigator", { onLine: true, locks: navigator.locks, mediaDevices: { getUserMedia: media } });
  vi.stubGlobal("window", { ...window, setInterval: () => 1, clearInterval: () => undefined, requestAnimationFrame: () => 1, cancelAnimationFrame: () => undefined });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:actual-recorded-take"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
  vi.spyOn(api, "meta").mockResolvedValue({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, llm_provider_name: null, llm_data_retention: null, sharing_available: true, sharing_disclosure_version: "v3", audio_available: true });
  vi.spyOn(api, "getVoiceConsent").mockResolvedValue({ enabled: true, active_for_current_policy: true, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null });
  vi.spyOn(api, "transcribeAudio").mockResolvedValue(transcript); vi.spyOn(api, "createEntry").mockResolvedValue({ id: "saved" }); vi.spyOn(api, "uploadAudioAttachment").mockResolvedValue({ attachment_id: "audio-saved", expires_at: "2026-11-04", size_bytes: audioBytes.length }); vi.spyOn(api, "translateText").mockResolvedValue({ english_text: "New translation" });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); __setLocaleForTests("en"); });

it("keeps an exact-cap editor draft intact when a public writing starter would exceed its raw encrypted bound", async () => {
  const text = "x" + " ".repeat(99_999), root = await mount(); await typeArea(root, t("entry.question"), text); const chip = promptChipsFor(new Date(), 3, "en")[0]!; await press(root, chip);
  expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(text); expect(textOf(root)).toContain(t("entry.tooLongBody", { max: "100,000" }));
  await press(root, t("entry.save")); await flush(); const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).text).toBe(text);
});
it("refuses an oversized actual transcription without installing an unpersistable draft or a voice payload", async () => {
  vi.mocked(api.transcribeAudio).mockResolvedValue({ ...transcript, original_text: "x" + " ".repeat(100_000) }); const root = await mount(); await take(root);
  expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(""); expect(textOf(root)).toContain(t("entry.tooLongBody", { max: "100,000" })); expect(textOf(root)).not.toContain(t("entry.voiceReviewTitle")); expect(api.createEntry).not.toHaveBeenCalled();
});

it.each([10, 12, 14, 18, 21])("renders its actual greeting and populated local streak and queue at hour %i", async hour => {
  vi.setSystemTime(new Date(2026, 9, 5, hour, 11, 12)); await recordMood(key, owner, "2026-10-04", 0.4); await recordMood(key, owner, "2026-10-03", -0.2); await enqueue({ userId: owner, clientEntryId: "held-1", blobB64: "retained encrypted writing", entryDate: "2026-10-04" }); const root = await mount(); expect(textOf(root)).toContain(t(hour < 12 ? "entry.greetingMorning" : hour < 18 ? "entry.greetingAfternoon" : "entry.greetingEvening")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["en", "es"] as const)("restores all actual sealed check-in fields and persists only explicit selections through a real encrypted save in %s", async locale => {
  __setLocaleForTests(locale); const draft = { text: "Recovered writing", mood: 0.5, energy: 3, sleep: 4, tags: ["work", "family"] }; await drafts.saveActiveDraft(key, owner, draft); const root = await mount(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(draft.text); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t("entry.save")); await flush(); const [id, blob, date, version] = vi.mocked(api.createEntry).mock.calls[0]!; const actual = await decryptEntry(key, owner, id, blob, version); expect(actual).toMatchObject({ text: draft.text, sentiment: 0.5, energy: 3, sleep: 4, tags: ["work", "family"], tod: "morning" }); expect(date).toBe("2026-10-05"); expect(await drafts.loadActiveDraft(key, owner)).toBeNull();
  expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(""); await press(root, t("entry.save")); await flush(); expect(api.createEntry).toHaveBeenCalledTimes(1); expect(textOf(root)).toContain(t("entry.empty"));
  await typeArea(root, t("entry.question"), "A new independent writing session"); expect(textOf(root)).not.toContain(t("entry.draftRestoredNote")); await press(root, t("entry.save")); await flush(); const next = vi.mocked(api.createEntry).mock.calls[1]!, fresh = await decryptEntry(key, owner, next[0], next[1], next[3]); expect(fresh.text).toBe("A new independent writing session"); expect(fresh.sentiment).toBeNull(); expect(fresh.energy).toBeUndefined(); expect(fresh.sleep).toBeUndefined(); expect(fresh.tags).toBeUndefined();
});
it("reports a failed draft restoration, retains the sealed record, and retries before enabling save", async () => {
  const real = drafts.loadActiveDraft, original = { text: "Retained readable writing", mood: null, energy: null, sleep: null, tags: [] }; await drafts.saveActiveDraft(key, owner, original); const read = vi.spyOn(drafts, "loadActiveDraft").mockRejectedValueOnce(new StorageReadError("Draft storage temporarily unavailable")).mockImplementation(real); const root = await mount(); expect(isDisabled(root, t("entry.save"))).toBe(true); expect(textOf(root)).toContain("Draft storage temporarily unavailable"); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t("entry.retryDraft")); await flush(); expect(read).toHaveBeenCalledTimes(2); expect(isDisabled(root, t("entry.save"))).toBe(false); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(original.text);
});
it("discards all edited check-in fields and the actual sealed draft, and revokes recorded playback", async () => {
  await drafts.saveActiveDraft(key, owner, { text: "Discard this", mood: -0.5, energy: 2, sleep: 2, tags: ["work"] }); const root = await mount(); await take(root); await press(root, t("entry.discard")); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(""); expect(await drafts.loadActiveDraft(key, owner)).toBeNull(); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:actual-recorded-take"); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["retained", "failed"] as const)("honestly reports the outcome of actual automatic draft persistence: %s", async state => {
  const root = await mount(); if (state === "failed") vi.spyOn(kv, "setItem").mockRejectedValue(new StorageCommitError("Keep this draft open; storage commit failed")); await typeArea(root, t("entry.question"), "New unsaved writing"); await act(async () => { await new Promise(resolve => setTimeout(resolve, 350)); }); await flush(); if (state === "retained") { expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("New unsaved writing"); expect(textOf(root)).toContain(t("entry.draftSaved")); } else expect(textOf(root)).toContain("Keep this draft open; storage commit failed");
});
it.each(["unavailable", "no-consent", "stale-consent", "metadata-error", "consent-error", "permission-denied"] as const)("honestly refuses microphone acquisition before the relevant privacy prerequisite: %s", async state => {
  if (state === "unavailable") vi.mocked(api.meta).mockResolvedValue({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, llm_provider_name: null, llm_data_retention: null, sharing_available: true, sharing_disclosure_version: "v3", audio_available: false });
  if (state === "no-consent" || state === "stale-consent") vi.mocked(api.getVoiceConsent).mockResolvedValue({ enabled: state !== "no-consent", active_for_current_policy: false, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null });
  if (state === "metadata-error") vi.mocked(api.meta).mockRejectedValueOnce(new Error("transient metadata failure")); if (state === "consent-error") vi.mocked(api.getVoiceConsent).mockRejectedValueOnce(new Error("transient consent failure")); if (state === "permission-denied") media.mockRejectedValue(new Error("permission denied"));
  const root = await mount(); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t(state === "unavailable" ? "entry.voiceUnavailable" : state === "no-consent" || state === "stale-consent" ? "entry.voiceConsentNeeded" : state === "permission-denied" ? "entry.voiceMicDenied" : "entry.voiceCheckFailed")); if (state !== "permission-denied") expect(media).not.toHaveBeenCalled(); expect(publicSurface(root.toJSON())).toMatchSnapshot();
  if (state === "metadata-error" || state === "consent-error") { await press(root, t("entry.micRecord")); await flush(); expect(media).toHaveBeenCalledTimes(1); expect(textOf(root)).toContain(t("entry.micRecording")); await press(root, t("entry.micStop")); await flush(); }
});
it.each([[new ApiError(413, "too large", "audio_too_large"), "entry.voiceTooLarge"], [new ApiError(403, "consent required", "voice_consent_required"), "entry.voiceConsentNeeded"], [new ApiError(503, "audio unavailable", "stt_unconfigured"), "entry.voiceUnavailable"], [new Error("transcription unavailable"), "entry.voiceTranscribeFailed"], [new ApiError(500, "transcription upstream unavailable", "unexpected_audio_failure"), "entry.voiceTranscribeFailed"]] as const)("shows a failed actual recording transcription while preserving editable writing: %#", async (failure, message) => {
  vi.mocked(api.transcribeAudio).mockRejectedValue(failure); const root = await mount(); await typeArea(root, t("entry.question"), "Keep my writing"); await take(root); expect(textOf(root)).toContain(t(message)); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Keep my writing"); expect(isDisabled(root, t("entry.save"))).toBe(false); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["add", "replace", "keep"] as const)("retains typing that raced actual transcription and honors the user's explicit %s choice", async choice => {
  const pending = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValue(pending.promise); const root = await mount(); await take(root); await typeArea(root, t("entry.question"), "Concurrent handwritten draft"); await act(async () => { pending.resolve(transcript); }); await flush(); expect(isDisabled(root, t("entry.save"))).toBe(true); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Concurrent handwritten draft"); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t(choice === "add" ? "entry.transcriptAdd" : choice === "replace" ? "entry.transcriptReplace" : "entry.transcriptKeep")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(choice === "add" ? `Concurrent handwritten draft\n\n${transcript.original_text}` : choice === "replace" ? transcript.original_text : "Concurrent handwritten draft"); expect(isDisabled(root, t("entry.save"))).toBe(false);
});
it("refuses an over-cap transcript append without losing either writing channel", async () => {
  const pending = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValue(pending.promise); const root = await mount(); await take(root); const typed = "a".repeat(100_000); await typeArea(root, t("entry.question"), typed); await act(async () => { pending.resolve(transcript); }); await flush(); await press(root, t("entry.transcriptAdd")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(typed); expect(textOf(root)).toContain(t("entry.tooLongBody", { max: (100_000).toLocaleString("en-US") })); expect(isDisabled(root, t("entry.save"))).toBe(true);
});
it.each([false, true])("saves an actual voice ciphertext with opt-in recording retention: keep=%s", async keep => {
  const saved = vi.fn(), root = await mount(saved); await take(root); expect(publicSurface(root.toJSON())).toMatchSnapshot(); expect(api.transcribeAudio).toHaveBeenCalledWith(Buffer.from(audioBytes).toString("base64"), "audio/webm", 1); if (keep) await pressSwitch(root); await press(root, t("entry.save")); await flush(); const [id, blob, date, version] = vi.mocked(api.createEntry).mock.calls[0]!; expect(await decryptEntry(key, owner, id, blob, version)).toMatchObject({ v: 3, input_mode: "voice", transcript_lang: "es", english_text: "A spoken entry", text: transcript.original_text, sentiment: null }); expect(saved).toHaveBeenCalledWith("sent", date);
  if (keep) { const [audioId, encrypted, mime, seconds] = vi.mocked(api.uploadAudioAttachment).mock.calls[0]!; expect(audioId).toBe(id); expect(await decryptAudio(key, owner, id, encrypted)).toEqual(audioBytes); expect(mime).toBe("audio/webm"); expect(seconds).toBe(1); } else expect(api.uploadAudioAttachment).not.toHaveBeenCalled();
});
it.each(["translated", "failed"] as const)("retranslates an edited voice transcript before actual encryption: %s", async state => {
  if (state === "failed") vi.mocked(api.translateText).mockRejectedValue(new Error("translation unavailable")); const root = await mount(); await take(root); await typeArea(root, t("entry.question"), "Nuevo texto editado"); await press(root, t("entry.save")); await flush(); const [id, blob, _date, version] = vi.mocked(api.createEntry).mock.calls[0]!; expect(await decryptEntry(key, owner, id, blob, version)).toMatchObject({ text: "Nuevo texto editado", english_text: state === "translated" ? "New translation" : null, input_mode: "voice" }); expect(api.translateText).toHaveBeenCalledWith("Nuevo texto editado", "es");
});
it.each([403, 404, 413])("warns once after a terminal kept-recording refusal %i while retaining the successfully saved entry", async status => {
  vi.mocked(api.uploadAudioAttachment).mockRejectedValue(new ApiError(status, "terminal recording refusal")); const saved = vi.fn(), root = await mount(saved); await take(root); await pressSwitch(root); await press(root, t("entry.save")); await flush(); expect(api.uploadAudioAttachment).toHaveBeenCalledTimes(1); expect(saved).toHaveBeenCalledWith("sent", "2026-10-05"); expect(textOf(root)).toContain(t("entry.voiceAudioNotKept"));
});
it.each(["recovers", "exhausted"] as const)("finishes the actual kept-recording retry ladder without duplicating the saved entry: %s", async outcome => {
  const upload = vi.mocked(api.uploadAudioAttachment); upload.mockRejectedValueOnce(new ApiError(503, "temporary audio failure"));
  if (outcome === "exhausted") upload.mockRejectedValue(new Error("audio connection unavailable"));
  const saved = vi.fn(), root = await mount(saved); await take(root); await pressSwitch(root); await press(root, t("entry.save"));
  for (let i = 0; i < 150 && saved.mock.calls.length === 0; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
  expect(saved).toHaveBeenCalledWith("sent", "2026-10-05"); expect(api.createEntry).toHaveBeenCalledTimes(1); expect(upload).toHaveBeenCalledTimes(outcome === "recovers" ? 2 : 3);
  for (const wire of upload.mock.calls) expect(await decryptAudio(key, owner, wire[0], wire[1])).toEqual(audioBytes);
  expect(textOf(root).includes(t("entry.voiceAudioNotKept"))).toBe(outcome === "exhausted"); expect(isDisabled(root, t("entry.save"))).toBe(false);
});
it.each(["success", "failure", "retired"] as const)("erases the actual Blob-read transcription plaintext after %s while retaining the caller's playable take", async outcome => {
  const actualRead = Blob.prototype.arrayBuffer, observed: ArrayBuffer[] = [], callerTakes: Blob[] = [];
  vi.spyOn(Blob.prototype, "arrayBuffer").mockImplementation(async function (this: Blob) { const bytes = await actualRead.call(this); observed.push(bytes); callerTakes.push(this); return bytes; });
  const pending = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValue(pending.promise);
  const root = await mount(); await take(root); expect(observed.length).toBeGreaterThan(0); expect(Array.from(new Uint8Array(observed[0]!))).toEqual(Array.from(audioBytes));
  if (outcome === "retired") clearSession();
  // The in-flight public endpoint owns the recorded bytes until its promise settles.
  await act(async () => { if (outcome === "failure") pending.reject(new Error("actual transcription failure")); else pending.resolve(transcript); }); await flush();
  for (const bytes of observed) expect(Array.from(new Uint8Array(bytes))).toEqual(Array(bytes.byteLength).fill(0));
  expect(new Uint8Array(await actualRead.call(callerTakes[0]!))).toEqual(audioBytes);
  const recording = root.root.findAllByType("audio")[0];
  if (outcome === "success") expect(recording?.props.src).toBe("blob:actual-recorded-take");
});
it("saves a kept voice entry offline as real text ciphertext and reports the recording's unqueued custody", async () => {
  const saved = vi.fn(), root = await mount(saved); await take(root); await pressSwitch(root); vi.stubGlobal("navigator", { onLine: false, locks: navigator.locks }); await press(root, t("entry.save")); await flush(); expect(saved).toHaveBeenCalledWith("queued", "2026-10-05"); expect(await queueLength(owner)).toBe(1); expect(api.createEntry).not.toHaveBeenCalled(); expect(api.uploadAudioAttachment).not.toHaveBeenCalled(); expect(textOf(root)).toContain(t("entry.voiceAudioQueuedNote")); expect(textOf(root)).toContain(t("entry.offlineQueueNote")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["session", "discard"] as const)("does not publish a completed transcription after its ownership is retired by %s", async retired => {
  const pending = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValue(pending.promise); const root = await mount(); await typeArea(root, t("entry.question"), "Keep this writing"); await take(root); if (retired === "session") clearSession(); else await press(root, t("entry.discard")); await act(async () => { pending.resolve(transcript); }); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(retired === "session" ? "Keep this writing" : ""); expect(textOf(root)).not.toContain(t("entry.voiceReviewTitle"));
});

it.each(["mood", "energy", "sleep", "activity"] as const)("saves an otherwise empty entry containing only the explicit%s check-in", async channel => {
  const root = await mount();
  if (channel === "mood") await pressAria(root, t("mood.option.low"));
  if (channel === "energy") await pressAria(root, t("energy.option.steady"));
  if (channel === "sleep") await pressAria(root, `1 — ${t("sleep.option.1")}`);
  if (channel === "activity") await press(root, t("activityTag.work"));
  expect(isDisabled(root, t("entry.discard"))).toBe(false);
  await press(root, t("entry.save")); await flush(); expect(api.createEntry).toHaveBeenCalledTimes(1); const wire = vi.mocked(api.createEntry).mock.calls[0]!, payload = await decryptEntry(key, owner, wire[0], wire[1], wire[3]);
  expect(payload.text).toBe(""); expect(payload.sentiment).toBe(channel === "mood" ? -0.5 : null);
  expect(payload.energy).toBe(channel === "energy" ? 0 : undefined); expect(payload.sleep).toBe(channel === "sleep" ? 1 : undefined); expect(payload.tags).toEqual(channel === "activity" ? ["work"] : undefined);
});
it("removes only a deselected activity while preserving the other explicit activity in actual ciphertext", async () => {
  const root = await mount(); await press(root, t("activityTag.work")); await press(root, t("activityTag.family")); await press(root, t("activityTag.work")); await press(root, t("entry.save")); await flush();
  const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).tags).toEqual(["family"]);
});
it.each(["", "existing text", "existing text "])("appends the displayed writing starter with one separating space to%s", async initial => {
  const root = await mount(); await typeArea(root, t("entry.question"), initial); const chip = promptChipsFor(new Date(), 3, "en")[0]!; await press(root, chip);
  const expected = `${initial}${initial && !initial.endsWith(" ") ? " " : ""}${chip} `; expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(expected);
  await press(root, t("entry.save")); await flush(); const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).text).toBe(expected);
});
it.each(["new", "already shown", "read failure", "write failure"] as const)("keeps support available while saving actual crisis writing: %s", async state => {
  if (state === "already shown") await crisis.recordCrisisDialogShown(owner, "2026-10-05");
  if (state === "read failure") vi.spyOn(crisis, "crisisDialogShownOn").mockRejectedValue(new Error("sensitive stamp unreadable"));
  if (state === "write failure") vi.spyOn(crisis, "recordCrisisDialogShown").mockRejectedValue(new Error("sensitive stamp cannot commit"));
  const support = vi.fn(), root = await mount(vi.fn(), support); await typeArea(root, t("entry.question"), "I want to kill myself"); await press(root, t("entry.save")); await flush();
  const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).text).toBe("I want to kill myself");
  if (state === "already shown") expect(textOf(root)).not.toContain(t("entry.crisisPromptTitle")); else { expect(textOf(root)).toContain(t("entry.crisisPromptTitle")); expect(textOf(root)).toContain(t("entry.crisisPromptProceed")); await press(root, t("measures.getSupport")); expect(support).toHaveBeenCalledTimes(1); await press(root, t("common.notNow")); expect(textOf(root)).not.toContain(t("entry.crisisPromptTitle")); }
});
it("refuses a retired stale draft when an ordinary retry has already observed the cleared slot", async () => {
  await drafts.saveActiveDraft(key, owner, { text: "Old held writing", mood: null, energy: null, sleep: null, tags: [] }); const real = drafts.loadActiveDraft, hold = deferred<Awaited<ReturnType<typeof drafts.loadActiveDraft>>>(), started = deferred<void>();
  vi.spyOn(drafts, "loadActiveDraft").mockImplementationOnce(async (...args) => { const captured = await real(...args); started.resolve(); await hold.promise; return captured; }).mockImplementation(real);
  const root = await render(<EntryView onSaved={() => undefined} />); await started.promise; await drafts.clearActiveDraft(owner); await press(root, t("entry.retryDraft")); await flush(); expect(isDisabled(root, t("entry.save"))).toBe(false);
  await act(async () => { hold.resolve(null); }); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(""); expect(textOf(root)).not.toContain(t("entry.draftRestoredNote"));
});

it("exposes live native recording time, meter and recording guidance, then restores the exact editor affordances", async () => {
  let clock!: () => void, frame!: () => void;
  class MeterContext {
    createMediaStreamSource() { return { connect: () => undefined }; }
    createAnalyser() { return { fftSize: 512, frequencyBinCount: 4, getByteTimeDomainData: (bytes: Uint8Array) => { bytes.fill(176); } }; }
    close() { return Promise.resolve(); }
  }
  vi.stubGlobal("window", { ...window, AudioContext: MeterContext, setInterval: (callback: () => void) => { clock = callback; return 1; }, clearInterval: () => undefined, requestAnimationFrame: (callback: () => void) => { frame = callback; return 1; }, cancelAnimationFrame: () => undefined });
  const root = await mount(); await press(root, t("entry.micRecord")); await flush();
  await act(async () => { vi.setSystemTime(new Date(2026, 9, 5, 10, 12, 17)); clock(); frame(); });
  expect(root.root.findAllByType("span").find(n => n.props.role === "timer")!.children.join("")).toBe("01:05");
  const meter = root.root.findAllByType("span").find(n => n.props.style?.width === 12)!; expect(meter.props.style).toEqual({ display: "inline-block", width: 12, height: 12, borderRadius: "50%", background: "var(--danger, #c0392b)", opacity: 0.675 });
  expect(textOf(root)).toContain(t("entry.micRecordingNote")); expect(root.root.findAllByType("button").some(node => node.children.includes(t("entry.micRecord")))).toBe(false); await press(root, t("entry.micStop")); await flush(); expect(textOf(root)).toContain(t("entry.voiceReviewTitle")); await press(root, t("entry.voiceDiscardTake")); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(isDisabled(root, t("entry.micRecord"))).toBe(false);
});
it("honestly disables native microphone preflight and shows transcription progress while each public operation is unresolved", async () => {
  const metadata = deferred<Awaited<ReturnType<typeof api.meta>>>(), nativeMeta = vi.mocked(api.meta).getMockImplementation()!, answer = await nativeMeta(), speech = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.meta).mockReturnValueOnce(metadata.promise); vi.mocked(api.transcribeAudio).mockReturnValueOnce(speech.promise);
  const root = await mount(); await press(root, t("entry.micRecord")); expect(isDisabled(root, t("entry.micRecord"))).toBe(true);
  await act(async () => { metadata.resolve(answer); }); await flush(); await press(root, t("entry.micStop")); await flush();
  try { expect(textOf(root)).toContain(t("entry.voiceTranscribing")); expect(isDisabled(root, t("entry.save"))).toBe(true); expect(isDisabled(root, t("entry.micRecord"))).toBe(true); }
  finally { await act(async () => { speech.resolve(transcript); }); await flush(); }
  expect(textOf(root)).not.toContain(t("entry.voiceTranscribing")); expect(isDisabled(root, t("entry.micRerecord"))).toBe(false);
});
it("reports a native audio preview failure and lets an explicit re-record retire and revoke the earlier take", async () => {
  const root = await mount(); await take(root); const audio = root.root.findAllByType("audio")[0]!; await act(async () => { audio.props.onError(); }); expect(textOf(root)).toContain(t("entry.voicePlaybackFailed"));
  await press(root, t("entry.micRerecord")); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:actual-recorded-take"); expect(textOf(root)).toContain(t("entry.micRecording")); expect(media).toHaveBeenCalledTimes(2); await press(root, t("entry.micStop")); await flush(); expect(root.root.findAllByType("audio")).toHaveLength(1); expect(textOf(root)).not.toContain(t("entry.voicePlaybackFailed"));
});
it.each(["unsupported", "native start failure"] as const)("reports an honest native recorder %s beside retained writing", async state => {
  class RefusedRecorder extends NativeRecorder { static isTypeSupported(mime: string): boolean { return state !== "unsupported" && super.isTypeSupported(mime); } start() { throw new Error("Native recorder unavailable"); } }
  vi.stubGlobal("MediaRecorder", RefusedRecorder); const root = await mount(); await typeArea(root, t("entry.question"), "Keep this writing"); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t(state === "unsupported" ? "entry.voiceMicUnsupported" : "entry.voiceRecordFailed")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Keep this writing"); expect(isDisabled(root, t("entry.save"))).toBe(false);
});
it.each(["en", "es"] as const)("reports the actual singular local streak and plural encrypted queue count in %s", async locale => {
  __setLocaleForTests(locale);
  await recordMood(key, owner, "2026-10-05", 0); await enqueue({ userId: owner, clientEntryId: "queued-first", blobB64: "encrypted first", entryDate: "2026-10-05" }); await enqueue({ userId: owner, clientEntryId: "queued-second", blobB64: "encrypted second", entryDate: "2026-10-05" });
  const root = await mount(), receipts = root.root.findAllByType("span").filter(node => node.props.role === "status").map(textOfNode); expect(receipts).toContain(t("common.streakOne", { count: 1 })); expect(receipts).not.toContain(t("common.streakMany", { count: 1 })); expect(textOf(root)).toContain(t("entry.queuedMany", { count: 2 }));
});
it("retains newer typing and structured check-ins while an accepted encrypted entry is visibly saving", async () => {
  const accepted = deferred<Awaited<ReturnType<typeof api.createEntry>>>(), began = deferred<void>(); vi.mocked(api.createEntry).mockImplementation(async () => { began.resolve(); return accepted.promise; });
  const root = await mount(); await typeArea(root, t("entry.question"), "The writing submitted"); await pressAria(root, t("mood.option.low")); await pressAria(root, t("energy.option.steady")); await pressAria(root, `1 — ${t("sleep.option.1")}`); await press(root, t("activityTag.work")); await press(root, t("entry.save")); await began.promise;
  try { expect(isDisabled(root, t("entry.saving"))).toBe(true); expect(isDisabled(root, t("entry.micRecord"))).toBe(true); expect(isDisabled(root, t("entry.discard"))).toBe(true); await typeArea(root, t("entry.question"), "Newer writing retained"); }
  finally { await act(async () => { accepted.resolve({ id: "actual accepted entry" }); }); await flush(); }
  expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Newer writing retained"); expect(isDisabled(root, t("entry.discard"))).toBe(false);
  await drafts.preserveActiveDraft(); expect(await drafts.loadActiveDraft(key, owner)).toMatchObject({ text: "Newer writing retained", mood: -0.5, energy: 0, sleep: 1, tags: ["work"] });
});
it.each(["mood", "energy", "sleep", "activity", "starter"] as const)("does not replace the live public %s selection when an older native sealed draft finishes reading", async channel => {
  await drafts.saveActiveDraft(key, owner, { text: "Old recovered writing", mood: 1, energy: 1, sleep: 5, tags: ["family"] }); const actual = drafts.loadActiveDraft, held = deferred<void>(), began = deferred<void>();
  vi.spyOn(drafts, "loadActiveDraft").mockImplementationOnce(async (...args) => { const captured = await actual(...args); began.resolve(); await held.promise; return captured; }).mockImplementation(actual);
  const root = await render(<EntryView onSaved={() => {}} />); await began.promise;
  if (channel === "mood") await pressAria(root, t("mood.option.low")); if (channel === "energy") await pressAria(root, t("energy.option.steady")); if (channel === "sleep") await pressAria(root, `1 — ${t("sleep.option.1")}`); if (channel === "activity") await press(root, t("activityTag.work")); if (channel === "starter") await press(root, promptChipsFor(new Date(), 3, "en")[0]!);
  await act(async () => { held.resolve(); }); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).not.toBe("Old recovered writing"); expect(textOf(root)).not.toContain(t("entry.draftRestoredNote"));
  await press(root, t("entry.save")); await flush(); const wire = vi.mocked(api.createEntry).mock.calls[0]!, payload = await decryptEntry(key, owner, wire[0], wire[1], wire[3]); expect(payload.sentiment).toBe(channel === "mood" ? -0.5 : null); expect(payload.energy).toBe(channel === "energy" ? 0 : undefined); expect(payload.sleep).toBe(channel === "sleep" ? 1 : undefined); expect(payload.tags).toEqual(channel === "activity" ? ["work"] : undefined);
});
it("accepts an actual exactly capped transcript append without truncating either writing channel", async () => {
  const pending = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValue(pending.promise); const root = await mount(); await take(root); const typed = "a".repeat(100_000 - 2 - transcript.original_text.length); await typeArea(root, t("entry.question"), typed);
  await act(async () => { pending.resolve(transcript); }); await flush(); await press(root, t("entry.transcriptAdd")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(`${typed}\n\n${transcript.original_text}`); expect(isDisabled(root, t("entry.save"))).toBe(false);
});
it("honestly surfaces a non-Error native encryption failure and releases its actual transferred data-key copy", async () => {
  const real = crypto.subtle.encrypt.bind(crypto.subtle); vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const params = args[0] as AesGcmParams; let domain: unknown; try { domain = JSON.parse(new TextDecoder().decode(params.additionalData!))[0]; } catch { /* other encryption */ } if (domain === "entry") throw null; return real(...args); });
  const { observeSecretCopies } = await import("./helpers/secretCustody"), root = await mount(); await typeArea(root, t("entry.question"), "Native failure writing retained"); const held = await observeSecretCopies(key, async () => { await press(root, t("entry.save")); await flush(); });
  expect(textOf(root)).toContain(t("entry.couldNotSave")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Native failure writing retained"); expect(isDisabled(root, t("entry.save"))).toBe(false); expect(api.createEntry).not.toHaveBeenCalled(); expect(held.copies.length).toBeGreaterThan(0); for (const copy of held.copies) expect(copy.every(byte => byte === 0)).toBe(true);
});

it("does not install or reseal an old account's native decrypted draft after vault/session replacement", async () => {
  await drafts.saveActiveDraft(key, owner, { text: "Old account private writing", mood: -0.5, energy: 0, sleep: 1, tags: ["work"] });
  const actual = crypto.subtle.decrypt.bind(crypto.subtle), ready = deferred<void>(), held = deferred<void>(), replacement = "native-new-draft-owner", replacementKey = new Uint8Array(32).fill(97);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const plaintext = await actual(...args), params = args[0] as AesGcmParams; let domain: unknown;
    try { domain = JSON.parse(new TextDecoder().decode(params.additionalData!))[0]; } catch { /* another encrypted channel */ }
    if (domain === "draft") { ready.resolve(); await held.promise; }
    return plaintext;
  });
  const root = await render(<EntryView onSaved={() => {}} />); await ready.promise;
  clearSession(); installSession(replacement); vault.unlock({ authKey: replacementKey.slice(), dataKey: replacementKey.slice() }, replacement);
  await act(async () => { held.resolve(); }); await flush(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 350)); }); await flush();
  expect(root.root.findAllByType("textarea")[0]!.props.value).not.toBe("Old account private writing"); expect(await kv.getItem(`mindpattern.draft.active.${replacement}`)).toBeNull();
  expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("Old account private writing");
});

it("does not autosave or erase the existing authenticated draft while the native restoration result remains unresolved", async () => {
  const saved = { text: "Retained restoration writing", mood: 0.5, energy: 3, sleep: 4, tags: ["family"] }, gate = deferred<void>(), began = deferred<void>(), real = drafts.loadActiveDraft; await drafts.saveActiveDraft(key, owner, saved);
  vi.spyOn(drafts, "loadActiveDraft").mockImplementation(async (...args) => { const result = await real(...args); began.resolve(); await gate.promise; return result; }); const root = await render(<EntryView onSaved={() => {}} />); await began.promise; await typeArea(root, t("entry.question"), "Live unhydrated writing");
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 360)); }); expect(await real(key, owner)).toEqual(saved); expect(isDisabled(root, t("entry.save"))).toBe(true); await act(async () => { gate.resolve(); }); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Live unhydrated writing");
});
it.each(["success", "failure"] as const)("keeps a second native transcription busy and private when a discarded first %s settles late", async outcome => {
  const first = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(), second = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  const root = await mount(); await typeArea(root, t("entry.question"), "Before the abandoned first take"); await take(root); await press(root, t("entry.discard")); await take(root); expect(api.transcribeAudio).toHaveBeenCalledTimes(2);
  await act(async () => { outcome === "success" ? first.resolve({ ...transcript, original_text: "Discarded first private transcript" }) : first.reject(new Error("Discarded first transcript error")); }); await flush();
  try { expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(""); expect(textOf(root)).not.toContain("Discarded first private transcript"); expect(textOf(root)).not.toContain(t("entry.voiceTranscribeFailed")); expect(textOf(root)).toContain(t("entry.voiceTranscribing")); expect(isDisabled(root, t("entry.save"))).toBe(true); }
  finally { await act(async () => { second.resolve({ ...transcript, original_text: "Legitimate second private transcript" }); }); await flush(); }
  expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Legitimate second private transcript");
});
it("releases every real kept-audio Blob-read plaintext after the encrypted upload while retaining independently decryptable server bytes", async () => {
  const real = Blob.prototype.arrayBuffer, observed: ArrayBuffer[] = []; vi.spyOn(Blob.prototype, "arrayBuffer").mockImplementation(async function (this: Blob) { const bytes = await real.call(this); observed.push(bytes); return bytes; });
  const root = await mount(); await take(root); await pressSwitch(root); await press(root, t("entry.save")); await flush(); expect(api.uploadAudioAttachment).toHaveBeenCalledTimes(1); const wire = vi.mocked(api.uploadAudioAttachment).mock.calls[0]!; expect(await decryptAudio(key, owner, wire[0], wire[1])).toEqual(audioBytes);
  expect(observed.length).toBeGreaterThan(1); for (const bytes of observed) expect(new Uint8Array(bytes).every(byte => byte === 0)).toBe(true); expect(root.root.findAllByType("audio")).toHaveLength(0); expect(textOf(root)).not.toContain(t("entry.voiceReviewTitle")); expect(isDisabled(root, t("entry.micRecord"))).toBe(false);
});
it("reports cached unavailable voice support on a second accepted microphone press without consulting consent or recording", async () => {
  const metadata = await vi.mocked(api.meta).getMockImplementation()!(); vi.mocked(api.meta).mockResolvedValue({ ...metadata, audio_available: false }); const root = await mount(); await press(root, t("entry.micRecord")); await flush(); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t("entry.voiceUnavailable")); expect(media).not.toHaveBeenCalled(); expect(api.getVoiceConsent).not.toHaveBeenCalled(); expect(api.meta).toHaveBeenCalledTimes(1);
});
it("retains known voice availability through a later unrelated metadata outage for another native recording", async () => {
  const root = await mount(); await take(root); await press(root, t("entry.voiceDiscardTake")); vi.mocked(api.meta).mockRejectedValue(new Error("Later metadata outage")); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t("entry.micRecordingNote")); expect(textOf(root)).not.toContain(t("entry.voiceCheckFailed")); expect(media).toHaveBeenCalledTimes(2); expect(api.meta).toHaveBeenCalledTimes(1); await press(root, t("entry.micStop")); await flush();
});
it("appends the deferred public transcript directly when the reader emptied their racing editor", async () => {
  const pending = deferred<Awaited<ReturnType<typeof api.transcribeAudio>>>(); vi.mocked(api.transcribeAudio).mockReturnValue(pending.promise); const root = await mount(); await take(root); await typeArea(root, t("entry.question"), "Racing writing"); await typeArea(root, t("entry.question"), ""); await act(async () => { pending.resolve(transcript); }); await flush(); await press(root, t("entry.transcriptAdd")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(transcript.original_text);
});
it.each([["affronted", "entry.leanEven"], ["amorphous", "entry.leanEven"], ["happy", "entry.leanLighter"], ["sad", "entry.leanHeavier"]] as const)("names the actual on-device sentiment around its exact boundary for %s", async (writing, key) => {
  const root = await mount(); await typeArea(root, t("entry.question"), writing); expect(textOf(root)).toContain(t("entry.onDeviceRead", { leaning: t(key) }));
});

it("does not replace the still-mounted editor with an old account's native draft-read failure after its session retires", async () => {
  const pending = deferred<drafts.EntryDraft | null>(); vi.spyOn(drafts, "loadActiveDraft").mockReturnValue(pending.promise); const root = await render(<EntryView onSaved={() => {}} />); await flush(); const before = publicSurface(root.toJSON()); clearSession(); await act(async () => { pending.reject(new StorageReadError("Old-account draft storage unavailable")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(textOf(root)).not.toContain("Old-account draft storage unavailable");
});
it("releases the real autosave operation's owned key copies after its authenticated idle draft commit", async () => {
  const { observeSecretCopies } = await import("./helpers/secretCustody"), root = await mount(), caller = vault.get().dataKey;
  const held = await observeSecretCopies(key, async () => { await typeArea(root, t("entry.question"), "Autosaved private writing"); await act(async () => { await new Promise(resolve => setTimeout(resolve, 370)); }); await flush(); });
  expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("Autosaved private writing"); expect(held.copies.length).toBeGreaterThan(0); for (const copy of held.copies) expect(copy.every(byte => byte === 0)).toBe(true); expect(caller).toEqual(key);
});
it("seals current writing when the real editor unmounts before its idle autosave is due", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "Writing retained across actual navigation"); await act(async () => { root.unmount(); }); await flush(); expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("Writing retained across actual navigation");
});
it.each(["discard", "saved"] as const)("reports an actual durable draft-clear refusal after the public %s action while retaining the original authenticated record", async action => {
  const saved = { text: "Retained authenticated draft-clear original", mood: 0.5, energy: 3, sleep: 4, tags: ["family"] }; await drafts.saveActiveDraft(key, owner, saved); const root = await mount(), actual = kv.removeItem;
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { if (args[0] === `mindpattern.draft.active.${owner}`) throw new StorageCommitError("This draft could not be removed; its encrypted original is retained."); return actual(...args); });
  await press(root, t(action === "discard" ? "entry.discard" : "entry.save")); await flush(); expect(textOf(root)).toContain("This draft could not be removed; its encrypted original is retained."); expect(await drafts.loadActiveDraft(key, owner)).toEqual(saved); if (action === "saved") expect(api.createEntry).toHaveBeenCalledTimes(1);
});
it("does not label a zero-day local history as a saved streak", async () => {
  const root = await mount(); expect(textOf(root)).not.toContain(t("common.streakMany", { count: 0 })); expect(textOf(root)).not.toContain(t("common.streakOne", { count: 0 }));
});

it("accepts a writing starter that makes the public raw draft exactly the inclusive encrypted character limit", async () => {
  const root = await mount(), chip = promptChipsFor(new Date(), 3, "en")[0]!, writing = "a".repeat(100_000 - chip.length - 2); await typeArea(root, t("entry.question"), writing); await press(root, chip); const expected = `${writing} ${chip} `; expect(expected.length).toBe(100_000); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(expected); expect(textOf(root)).not.toContain(t("entry.tooLongBody", { max: "100,000" }));
});
it("accepts a native transcription exactly at the inclusive encrypted character bound", async () => {
  const writing = "a".repeat(100_000); vi.mocked(api.transcribeAudio).mockResolvedValue({ ...transcript, original_text: writing }); const root = await mount(); await take(root); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(writing); expect(textOf(root)).toContain(t("entry.voiceReviewTitle")); expect(textOf(root)).not.toContain(t("entry.tooLongBody", { max: "100,000" }));
});
it("keeps a whitespace-only editor empty for discard, private sentiment display and encrypted-save admission", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "   \n\t "); expect(isDisabled(root, t("entry.discard"))).toBe(true); expect(textOf(root)).not.toContain(t("entry.onDeviceRead", { leaning: t("entry.leanEven") })); await press(root, t("entry.save")); await flush(); expect(textOf(root)).toContain(t("entry.empty")); expect(api.createEntry).not.toHaveBeenCalled();
});
it("retries actual draft restoration repeatedly before the third native read returns the preserved authenticated writing", async () => {
  const saved = { text: "Preserved through repeated native read failures", mood: 0.5, energy: 3, sleep: 4, tags: ["family"] }; await drafts.saveActiveDraft(key, owner, saved); const actual = drafts.loadActiveDraft; vi.spyOn(drafts, "loadActiveDraft").mockRejectedValueOnce(new StorageReadError("First local read refused")).mockRejectedValueOnce(new StorageReadError("Second local read refused")).mockImplementation(actual);
  const root = await mount(); expect(textOf(root)).toContain("First local read refused"); await press(root, t("entry.retryDraft")); await flush(); expect(textOf(root)).toContain("Second local read refused"); await press(root, t("entry.retryDraft")); await flush(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe(saved.text); expect(isDisabled(root, t("entry.save"))).toBe(false);
});
it("does not let an unmounted account's source overwrite another account's authentic parked draft during a later native lock", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "Old account private navigation writing"); await act(async () => { root.unmount(); }); await flush(); const nextOwner = "parked-draft-replacement", nextKey = new Uint8Array(32).fill(93), parked = { text: "Replacement account preserved private writing", mood: -0.5, energy: 2, sleep: 3, tags: ["work"] };
  clearSession(); installSession(nextOwner); vault.unlock({ dataKey: nextKey.slice(), authKey: nextKey.slice() }, nextOwner); await drafts.saveActiveDraft(nextKey, nextOwner, parked); await drafts.preserveActiveDraft(); expect(await drafts.loadActiveDraft(nextKey, nextOwner)).toEqual(parked);
});
it("does not invent a translated preview when the actual native voice result has no English channel", async () => {
  vi.mocked(api.transcribeAudio).mockResolvedValue({ ...transcript, english_text: null }); const root = await mount(); await take(root); expect(textOf(root)).toContain(t("entry.voiceReviewTitle")); expect(textOf(root)).not.toContain(t("entry.voiceEnglishPreview")); await press(root, t("entry.save")); await flush(); const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).english_text).toBeNull();
});
it("keeps the original translated voice channel when the user changes only their outer whitespace", async () => {
  const root = await mount(); await take(root); await typeArea(root, t("entry.question"), ` ${transcript.original_text} `); await press(root, t("entry.save")); await flush(); const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).english_text).toBe(transcript.english_text); expect(api.translateText).not.toHaveBeenCalled();
});
it("keeps the actual microphone replacement and take-discard controls disabled while the accepted kept audio upload remains unresolved", async () => {
  const pending = deferred<Awaited<ReturnType<typeof api.uploadAudioAttachment>>>(), began = deferred<void>(); vi.mocked(api.uploadAudioAttachment).mockImplementation(async () => { began.resolve(); return pending.promise; }); const root = await mount(); await take(root); await pressSwitch(root); await press(root, t("entry.save")); await began.promise;
  try { expect(isDisabled(root, t("entry.micRerecord"))).toBe(true); expect(isDisabled(root, t("entry.voiceDiscardTake"))).toBe(true); }
  finally { await act(async () => { pending.resolve({ attachment_id: "accepted-kept-recording", expires_at: "2026-11-04", size_bytes: audioBytes.length }); }); await flush(); }
});
it("gives a fresh privacy-preflight error priority over an earlier actual microphone acquisition refusal", async () => {
  media.mockRejectedValue(new Error("Native permission denied")); const root = await mount(); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t("entry.voiceMicDenied")); vi.mocked(api.getVoiceConsent).mockRejectedValue(new ApiError(503, "Current privacy status unavailable")); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t("entry.voiceCheckFailed")); expect(textOf(root)).not.toContain(t("entry.voiceMicDenied"));
});
it.each(["metadata failure", "metadata unavailable", "consent failure", "consent success"] as const)("does not publish or start capture for an obsolete microphone %s after native session retirement", async boundary => {
  const metadata = await vi.mocked(api.meta).getMockImplementation()!(), consent = await vi.mocked(api.getVoiceConsent).getMockImplementation()!(), pending = deferred<unknown>(); if (boundary.startsWith("metadata")) vi.mocked(api.meta).mockReturnValue(pending.promise as ReturnType<typeof api.meta>); else vi.mocked(api.getVoiceConsent).mockReturnValue(pending.promise as ReturnType<typeof api.getVoiceConsent>);
  const root = await mount(); await press(root, t("entry.micRecord")); await flush(); const before = publicSurface(root.toJSON()); clearSession(); await act(async () => { if (boundary.endsWith("failure")) pending.reject(new ApiError(503, "Retired privacy preflight error")); else pending.resolve(boundary === "metadata unavailable" ? { ...metadata, audio_available: false } : consent); });
  try { await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(media).not.toHaveBeenCalled(); }
  finally { await act(async () => { root.unmount(); }); }
});
it.each(["success", "failure"] as const)("does not reset old writing or author a queue receipt when an accepted native entry request settles with a retired %s", async outcome => {
  const pending = deferred<Awaited<ReturnType<typeof api.createEntry>>>(), began = deferred<void>(); vi.mocked(api.createEntry).mockImplementation(async () => { began.resolve(); return pending.promise; }); const root = await mount(); await typeArea(root, t("entry.question"), "Writing kept after the accepted old request retired"); await press(root, t("entry.save")); await began.promise; const before = publicSurface(root.toJSON()); clearSession();
  await act(async () => { outcome === "success" ? pending.resolve({ id: "accepted-old-owner-entry" }) : pending.reject(new ApiError(0, "Retired request offline")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(await queueLength(owner)).toBe(0);
});
it("does not record a new old-account mood receipt when the real encrypted entry result retires its save owner", async () => {
  await recordMood(key, owner, "2026-10-05", -0.5); const root = await mount(), real = crypto.subtle.encrypt.bind(crypto.subtle); vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const result = await real(...args), params = args[0] as AesGcmParams; try { if (JSON.parse(new TextDecoder().decode(params.additionalData!))[0] === "entry") clearSession(); } catch { /* encrypted account metadata */ } return result; });
  await typeArea(root, t("entry.question"), "A changed mood cannot be admitted after retirement"); await pressAria(root, t("mood.option.light")); await press(root, t("entry.save")); await flush(); const { recentMoods } = await import("../src/moodLog"); expect(await recentMoods(key, owner)).toEqual([{ date: "2026-10-05", value: -0.5 }]);
});

it("releases its actual save key after a retired voice translation failure without admitting an unavailable native encryption", async () => {
  const root = await mount(); await take(root); await typeArea(root, t("entry.question"), "Edited private voice writing whose translation retired");
  const gate = deferred<void>(), real = crypto.subtle.encrypt.bind(crypto.subtle);
  vi.mocked(api.translateText).mockImplementation(async () => { clearSession(); throw new ApiError(503, "Retired translation unavailable"); });
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const result = await real(...args); await gate.promise; return result; });
  const { observeSecretCopies } = await import("./helpers/secretCustody");
  try { const held = await observeSecretCopies(key, async () => { await press(root, t("entry.save")); await flush(); }); expect(held.copies.length).toBeGreaterThan(0); for (const copy of held.copies) expect(copy.every(byte => byte === 0)).toBe(true); expect(api.createEntry).not.toHaveBeenCalled(); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("does not seal old live writing into a replacement owner's authentic parked draft when the native root unmounts late", async () => {
  const replacement = "late-unmount-draft-owner", replacementKey = new Uint8Array(32).fill(91), root = await mount(); await typeArea(root, t("entry.question"), "Old account live writing must remain private");
  clearSession(); installSession(replacement); vault.unlock({ authKey: replacementKey.slice(), dataKey: replacementKey.slice() }, replacement);
  await drafts.saveActiveDraft(replacementKey, replacement, { text: "Authentic replacement parked writing", mood: null, energy: null, sleep: null, tags: [] });
  await act(async () => { root.unmount(); }); await flush(); expect((await drafts.loadActiveDraft(replacementKey, replacement))?.text).toBe("Authentic replacement parked writing");
});
it("does not publish an old actual autosave completion after its native durable commit retires the account", async () => {
  const real = kv.setItem.bind(kv), began = deferred<void>(), gate = deferred<void>(), root = await mount();
  vi.spyOn(kv, "setItem").mockImplementation(async (...args) => { await real(...args); if (args[0] === `mindpattern.draft.active.${owner}`) { began.resolve(); await gate.promise; } });
  await typeArea(root, t("entry.question"), "Actual old-account autosave writing");
  try { let timer!: ReturnType<typeof setTimeout>; const started = await Promise.race([began.promise.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), 700); })]); clearTimeout(timer); expect(started).toBe(true); const before = publicSurface(root.toJSON()); clearSession(); installSession("autosave-replacement"); vault.unlock({ authKey: key.slice(), dataKey: key.slice() }, "autosave-replacement"); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});
it("does not publish an old writing streak when a held actual native mood read returns after account replacement", async () => {
  const { setKvBackendForTests } = await import("../src/kvstore"), records = new Map<string, string>(), gate = deferred<void>(), began = deferred<void>(); let hold = false;
  setKvBackendForTests({ getItem: async slot => { const value = records.get(slot) ?? null; if (hold && slot === `mindpattern.moodlog.${owner}`) { began.resolve(); await gate.promise; } return value; }, setItem: async (slot, value) => { records.set(slot, value); }, removeItem: async slot => { records.delete(slot); }, keys: async () => [...records.keys()] });
  await recordMood(key, owner, "2026-10-05", 0.5);
  const moods = await import("../src/moodLog"), realStreak = moods.localStreak;
  vi.spyOn(moods, "localStreak").mockImplementationOnce(async (...args) => { const result = await realStreak(...args); expect(result).toBe(1); began.resolve(); await gate.promise; return result; });
  let retired = false, root!: Root; const committed: string[] = [];
  root = await render(<Profiler id="old-streak" onRender={() => { if (retired) committed.push(publicSurface(root.toJSON())); }}><EntryView onSaved={() => {}} /></Profiler>);
  try { let timer!: ReturnType<typeof setTimeout>; const started = await Promise.race([began.promise.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), 300); })]); clearTimeout(timer); expect(started).toBe(true); await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("streak-replacement"); vault.unlock({ authKey: key.slice(), dataKey: key.slice() }, "streak-replacement"); retired = true; await act(async () => { gate.resolve(); }); await flush(); expect(committed.every(surface => !surface.includes(t("common.streakOne", { count: 1 })))).toBe(true); expect(publicSurface(root.toJSON())).toBe(before); }
  finally { await act(async () => { gate.resolve(); }); await flush(); setKvBackendForTests(null); }
});

it.each(["disabled", "stale", "contradictory-policy-echo"] as const)("refuses real capture when the public voice consent is %s", async state => {
  const consent = await vi.mocked(api.getVoiceConsent).getMockImplementation()!(); vi.mocked(api.getVoiceConsent).mockResolvedValue({ ...consent, enabled: state === "stale", active_for_current_policy: state === "contradictory-policy-echo" });
  const root = await mount(); await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).toContain(t("entry.voiceConsentNeeded")); expect(media).not.toHaveBeenCalled(); expect(api.transcribeAudio).not.toHaveBeenCalled();
});

it("labels both actual recording retention choices before an independently decryptable save", async () => {
  const root = await mount(); await take(root); const control = () => root.root.findAllByType("button").find(node => node.props.role === "switch")!;
  expect(control().props["aria-label"]).toBe(t("entry.voiceKeepOff")); expect(textOf(root)).toContain(t("entry.voiceKeepOff")); await pressSwitch(root); expect(control().props["aria-label"]).toBe(t("entry.voiceKeepOn")); await pressSwitch(root); expect(control().props["aria-label"]).toBe(t("entry.voiceKeepOff"));
  await press(root, t("entry.save")); await flush(); expect(api.uploadAudioAttachment).not.toHaveBeenCalled();
});

it("does not admit a microphone privacy request from an already retired public editor", async () => {
  const root = await mount(); clearSession(); await press(root, t("entry.micRecord")); await flush(); expect(api.meta).not.toHaveBeenCalled(); expect(api.getVoiceConsent).not.toHaveBeenCalled(); expect(media).not.toHaveBeenCalled();
});

it("does not read or submit a take that finishes natively after its authenticated recording view retires", async () => {
  const root = await mount(); await press(root, t("entry.micRecord")); await flush(); const read = vi.spyOn(Blob.prototype, "arrayBuffer"); clearSession(); await press(root, t("entry.micStop")); await flush(); expect(read).not.toHaveBeenCalled(); expect(api.transcribeAudio).not.toHaveBeenCalled(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("");
});

it("erases a real transcription Blob result without dispatching it after native account retirement", async () => {
  const actual = Blob.prototype.arrayBuffer, physical: ArrayBuffer[] = []; vi.spyOn(Blob.prototype, "arrayBuffer").mockImplementation(async function (this: Blob) { const result = await actual.call(this); physical.push(result); clearSession(); return result; });
  const root = await mount(); await take(root); expect(physical.length).toBeGreaterThan(0); physical.forEach(bytes => expect(new Uint8Array(bytes)).toEqual(new Uint8Array(bytes.byteLength))); expect(api.transcribeAudio).not.toHaveBeenCalled(); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("");
});

it.each(["Blob", "WebCrypto"] as const)("retires kept recording work at its accepted native %s result and releases owned plaintext and keys", async boundary => {
  const root = await mount(); await take(root); await pressSwitch(root); const read = Blob.prototype.arrayBuffer, encrypt = crypto.subtle.encrypt.bind(crypto.subtle), physical: ArrayBuffer[] = []; let retired = false, audioCalls = 0;
  vi.spyOn(Blob.prototype, "arrayBuffer").mockImplementation(async function (this: Blob) { const result = await read.call(this); physical.push(result); if (boundary === "Blob") { retired = true; clearSession(); } return result; });
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const algorithm = args[0] as AesGcmParams; const aad = algorithm.additionalData ? JSON.parse(new TextDecoder().decode(algorithm.additionalData)) as string[] : []; const audio = aad[0] === "audio"; if (audio) audioCalls += 1; const result = await encrypt(...args); if (audio && boundary === "WebCrypto") { retired = true; clearSession(); } return result; });
  const { observeSecretCopies } = await import("./helpers/secretCustody"), custody = await observeSecretCopies(key, async () => { await press(root, t("entry.save")); await flush(); });
  expect(retired).toBe(true); expect(audioCalls).toBe(boundary === "Blob" ? 0 : 1); expect(api.uploadAudioAttachment).not.toHaveBeenCalled(); physical.forEach(bytes => expect(new Uint8Array(bytes)).toEqual(new Uint8Array(bytes.byteLength))); expect(custody.copies.length).toBeGreaterThan(0); custody.copies.forEach(bytes => expect(bytes).toEqual(new Uint8Array(bytes.length)));
});

it("preserves the authentic parked draft when its native root unmounts before restoration has admitted a live editor", async () => {
  const saved = { text: "Authentic writing awaiting restoration", mood: 0.5, energy: 3, sleep: 4, tags: ["family"] }; await drafts.saveActiveDraft(key, owner, saved);
  const read = drafts.loadActiveDraft, began = deferred<void>(), gate = deferred<void>(); vi.spyOn(drafts, "loadActiveDraft").mockImplementationOnce(async (...args) => { const result = await read(...args); began.resolve(); await gate.promise; return result; }).mockImplementation(read);
  const root = await render(<EntryView onSaved={() => {}} />); await began.promise;
  try { await act(async () => { root.unmount(); }); await flush(); expect(await read(key, owner)).toEqual(saved); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("keeps a fresh same-account unlocked key's authentic parked draft when an older editor unmounts late", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "Old-key live private writing"); const nextKey = new Uint8Array(32).fill(89), saved = { text: "Fresh-key private parked writing", mood: 0.5, energy: 3, sleep: 4, tags: ["work"] };
  clearSession(); installSession(owner); vault.unlock({ authKey: nextKey.slice(), dataKey: nextKey.slice() }, owner); await drafts.saveActiveDraft(nextKey, owner, saved); await act(async () => { root.unmount(); }); await flush(); expect(await drafts.loadActiveDraft(nextKey, owner)).toEqual(saved);
});

it("never parks invented writing when the real native draft clear overlaps the root's lock preservation", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "Accepted writing whose draft is complete"); const remove = kv.removeItem.bind(kv); let preserved: Promise<void> | undefined;
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { await remove(...args); if (args[0] === `mindpattern.draft.active.${owner}` && !preserved) preserved = drafts.preserveActiveDraft(); });
  await press(root, t("entry.save")); await flush(); expect(api.createEntry).toHaveBeenCalledTimes(1); expect(preserved).toBeDefined(); await preserved; expect(await drafts.loadActiveDraft(key, owner)).toBeNull();
});

it("does not disclose edited voice text after its accepted native writing permit retires the account", async () => {
  const root = await mount(); await take(root); await typeArea(root, t("entry.question"), "Private edited voice writing"); const read = kv.getItem.bind(kv); let retired = false;
  vi.spyOn(kv, "getItem").mockImplementation(async (...args) => { const result = await read(...args); if (args[0] === `mindpattern.writeGeneration.${owner}`) { retired = true; clearSession(); } return result; });
  await press(root, t("entry.save")); await flush(); expect(retired).toBe(true); expect(api.translateText).not.toHaveBeenCalled(); expect(api.createEntry).not.toHaveBeenCalled();
});

it("does not dispatch saved writing after an accepted native mood commit retires its account", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "Private writing awaiting native mood receipt"); const write = kv.setItem.bind(kv); let retired = false;
  vi.spyOn(kv, "setItem").mockImplementation(async (...args) => { await write(...args); if (args[0] === `mindpattern.moodlog.${owner}`) { retired = true; clearSession(); } });
  await press(root, t("entry.save")); await flush(); expect(retired).toBe(true); expect(api.createEntry).not.toHaveBeenCalled(); expect(await queueLength(owner)).toBe(0);
});

it("does not read a kept recording after accepted native draft removal retires the save", async () => {
  const root = await mount(); await take(root); await pressSwitch(root); const remove = kv.removeItem.bind(kv), read = vi.spyOn(Blob.prototype, "arrayBuffer"); let retired = false;
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { await remove(...args); if (args[0] === `mindpattern.draft.active.${owner}`) { retired = true; clearSession(); } });
  await press(root, t("entry.save")); await flush(); expect(retired).toBe(true); expect(read).not.toHaveBeenCalled(); expect(api.uploadAudioAttachment).not.toHaveBeenCalled();
});

it("does not dismiss an obsolete playable take after its accepted kept-recording receipt retires the session", async () => {
  const root = await mount(), gate = deferred<Awaited<ReturnType<typeof api.uploadAudioAttachment>>>(), began = deferred<void>(); await take(root); await pressSwitch(root);
  vi.mocked(api.uploadAudioAttachment).mockImplementation(async () => { began.resolve(); return gate.promise; }); await press(root, t("entry.save")); await began.promise; await flush(); const before = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve({ attachment_id: "actual-accepted-old-recording", expires_at: "2026-11-04", size_bytes: audioBytes.length }); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(root.root.findAllByType("audio")).toHaveLength(1);
});

it("keeps a late actual autosave failure out of the retired editor's public receipts", async () => {
  const root = await mount(), write = kv.setItem.bind(kv), began = deferred<void>(), gate = deferred<void>();
  vi.spyOn(kv, "setItem").mockImplementation(async (...args) => { await write(...args); if (args[0] === `mindpattern.draft.active.${owner}`) { began.resolve(); await gate.promise; throw new StorageCommitError("Old native autosave acknowledgement failed"); } }); await typeArea(root, t("entry.question"), "Retained native autosave writing");
  try { await began.promise; await flush(); const before = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(textOf(root)).not.toContain("Old native autosave acknowledgement failed"); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("erases its owned save key without publishing a late native writing-permit read failure", async () => {
  const root = await mount(), read = kv.getItem.bind(kv), began = deferred<void>(), gate = deferred<void>(); await typeArea(root, t("entry.question"), "Private writing awaiting permit storage");
  vi.spyOn(kv, "getItem").mockImplementation(async (...args) => { const result = await read(...args); if (args[0] === `mindpattern.writeGeneration.${owner}`) { began.resolve(); await gate.promise; throw new StorageReadError("Retired native writing permit unavailable"); } return result; });
  const { observeSecretCopies } = await import("./helpers/secretCustody");
  try { const custody = await observeSecretCopies(key, async () => { await press(root, t("entry.save")); await began.promise; await flush(); const before = publicSurface(root.toJSON()); clearSession(); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); }); expect(custody.copies.length).toBeGreaterThan(0); custody.copies.forEach(bytes => expect(bytes).toEqual(new Uint8Array(bytes.length))); expect(api.createEntry).not.toHaveBeenCalled(); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("keeps a new writing session free of a discarded draft's restoration receipt", async () => {
  await drafts.saveActiveDraft(key, owner, { text: "Authentic restored writing", mood: null, energy: null, sleep: null, tags: [] }); const root = await mount(); await press(root, t("entry.discard")); await typeArea(root, t("entry.question"), "A newly written entry after discard"); expect(textOf(root)).not.toContain(t("entry.draftRestoredNote"));
});

it("does not fetch a locked key when an earlier editor's actual enabled discard is pressed", async () => {
  const saved = { text: "Actual encrypted draft retained while locked", mood: null, energy: null, sleep: null, tags: [] }; await drafts.saveActiveDraft(key, owner, saved); const root = await mount(); vault.lock(); await press(root, t("entry.discard")); await flush(); expect(await drafts.loadActiveDraft(key, owner)).toEqual(saved);
});

it("keeps a same-account sibling writer's authentic parked draft after the earlier native editor has unmounted", async () => {
  const root = await mount(); await typeArea(root, t("entry.question"), "Old navigation writing"); await act(async () => { root.unmount(); }); await flush(); const parked = { text: "Latest authentic same-account sibling writing", mood: 0.5, energy: 3, sleep: 4, tags: ["family"] }; await drafts.saveActiveDraft(key, owner, parked); await drafts.preserveActiveDraft(); expect(await drafts.loadActiveDraft(key, owner)).toEqual(parked);
});

it("never attaches a revoked prior native Blob URL to a newly accepted recording's public frame", async () => {
  vi.mocked(URL.createObjectURL).mockRestore(); vi.mocked(URL.revokeObjectURL).mockRestore(); const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL), created: string[] = [], revoked: string[] = [];
  vi.spyOn(URL, "createObjectURL").mockImplementation(blob => { const url = create(blob); created.push(url); return url; }); vi.spyOn(URL, "revokeObjectURL").mockImplementation(url => { revoked.push(url); revoke(url); });
  let second = false, root!: Root; const frames: string[] = []; root = await render(<Profiler id="native-take-url" onRender={() => { if (second) root.root.findAllByType("audio").forEach(node => frames.push(node.props.src as string)); }}><EntryView onSaved={() => {}} /></Profiler>); await flush(); await take(root); expect(created).toHaveLength(1); await press(root, t("entry.voiceDiscardTake")); await flush(); expect(revoked).toContain(created[0]); second = true; await take(root); expect(created).toHaveLength(2); expect(frames).not.toContain(created[0]); expect(root.root.findAllByType("audio")[0]!.props.src).toBe(created[1]);
});

it("reports honest localized autosave failure when native encryption provides no error detail", async () => {
  const root = await mount(); vi.spyOn(crypto.subtle, "encrypt").mockRejectedValue(new DOMException("", "OperationError")); await typeArea(root, t("entry.question"), "Private writing retained after native encryption refusal"); await act(async () => { await new Promise(resolve => setTimeout(resolve, 350)); }); await flush(); expect(textOf(root)).toContain(t("entry.draftFailed")); expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("Private writing retained after native encryption refusal");
});

it("keeps newer actual autosaved writing after an older accepted entry request completes", async () => {
  const gate = deferred<Awaited<ReturnType<typeof api.createEntry>>>(), began = deferred<void>(); vi.mocked(api.createEntry).mockImplementation(async () => { began.resolve(); return gate.promise; }); const root = await mount(); await typeArea(root, t("entry.question"), "Original submitted writing"); await press(root, t("entry.save")); await began.promise;
  try { await typeArea(root, t("entry.question"), "New authentic autosaved writing"); await act(async () => { await new Promise(resolve => setTimeout(resolve, 360)); }); await flush(); expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("New authentic autosaved writing"); await act(async () => { gate.resolve({ id: "accepted-original-writing" }); }); await flush(); expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("New authentic autosaved writing"); }
  finally { await act(async () => { gate.resolve({ id: "accepted-original-writing" }); }); await flush(); }
});

it("keeps the old authentic parked draft when its pending native autosave loses session ownership", async () => {
  const parked = { text: "Old authenticated parked writing", mood: null, energy: null, sleep: null, tags: [] }; await drafts.saveActiveDraft(key, owner, parked); const root = await mount(); await typeArea(root, t("entry.question"), "Retired pending autosave writing"); clearSession(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 360)); }); await flush(); expect(await drafts.loadActiveDraft(key, owner)).toEqual(parked);
});

it("does not strand the final lock-time draft behind an obsolete native idle seal while typing continues", async () => {
  const root = await mount(), encrypt = crypto.subtle.encrypt.bind(crypto.subtle), gate = deferred<void>();
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const result = await encrypt(...args), algorithm = args[0] as AesGcmParams; const aad = algorithm.additionalData ? JSON.parse(new TextDecoder().decode(algorithm.additionalData)) as string[] : []; if (aad[0] === "draft" && JSON.parse(new TextDecoder().decode(args[2])).text === "Intermediate continuously typed writing") await gate.promise; return result; });
  try { await typeArea(root, t("entry.question"), "First continuously typed writing"); await act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); }); await typeArea(root, t("entry.question"), "Intermediate continuously typed writing"); await act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); }); await typeArea(root, t("entry.question"), "Final lock-time writing"); await act(async () => { root.unmount(); }); await flush(); expect((await drafts.loadActiveDraft(key, owner))?.text).toBe("Final lock-time writing"); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("retains the real recording through a bounded native audio-service outage before its final retry", async () => {
  let available = false, availability: ReturnType<typeof setTimeout> | undefined; vi.mocked(api.uploadAudioAttachment).mockImplementation(async () => { if (!availability) availability = setTimeout(() => { available = true; }, 900); if (!available) throw new ApiError(503, "Native audio service briefly unavailable"); return { attachment_id: "accepted-recording-after-service-recovery", expires_at: "2026-11-04", size_bytes: audioBytes.length }; });
  const saved = vi.fn(), root = await mount(saved); await take(root); await pressSwitch(root); await press(root, t("entry.save"));
  try { for (let i = 0; i < 180 && saved.mock.calls.length === 0; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); }); expect(saved).toHaveBeenCalledWith("sent", "2026-10-05"); expect(textOf(root)).not.toContain(t("entry.voiceAudioNotKept")); const accepted = vi.mocked(api.uploadAudioAttachment).mock.calls.at(-1)!; expect(await decryptAudio(key, owner, accepted[0], accepted[1])).toEqual(audioBytes); }
  finally { clearTimeout(availability); }
});

it("preserves the original English channel of an unedited native transcript carrying an upstream Unicode BOM", async () => {
  // The actual STT producer uses Python str.strip, which retains FEFF;
  // the browser editor's trim removes it on both comparison operands.
  vi.mocked(api.transcribeAudio).mockResolvedValue({ ...transcript, original_text: `\uFEFF${transcript.original_text}` }); const root = await mount(); await take(root); await press(root, t("entry.save")); await flush(); expect(api.translateText).not.toHaveBeenCalled(); const wire = vi.mocked(api.createEntry).mock.calls[0]!; expect((await decryptEntry(key, owner, wire[0], wire[1], wire[3])).english_text).toBe(transcript.english_text);
});

it("does not resurrect completed writing when lock preservation can recover a transient native draft-clear refusal", async () => {
  await drafts.saveActiveDraft(key, owner, { text: "Authenticated writing about to complete", mood: null, energy: null, sleep: null, tags: [] }); const root = await mount(), remove = kv.removeItem.bind(kv); let preserved: Promise<void> | undefined;
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { if (args[0] === `mindpattern.draft.active.${owner}` && !preserved) { preserved = drafts.preserveActiveDraft(); throw new StorageCommitError("Native draft clear briefly refused"); } await remove(...args); });
  await press(root, t("entry.save")); await flush(); expect(api.createEntry).toHaveBeenCalledTimes(1); expect(preserved).toBeDefined(); await preserved; expect(await drafts.loadActiveDraft(key, owner)).toBeNull();
});

it("does not commit an old encrypted queue receipt after the native helper returns into a replacement account", async () => {
  await enqueue({ userId: owner, clientEntryId: "old-owner-queued-writing", blobB64: "authentic parked encrypted writing", entryDate: "2026-10-05" });
  const queue = await import("../src/offlineQueue"), nativeCount = queue.queueLength, gate = deferred<void>(), began = deferred<void>();
  vi.spyOn(queue, "queueLength").mockImplementationOnce(async (...args) => { const count = await nativeCount(...args); expect(count).toBe(1); began.resolve(); await gate.promise; return count; });
  let retired = false, root!: Root; const frames: string[] = [];
  root = await render(<Profiler id="native-queue-receipt" onRender={() => { if (retired) frames.push(publicSurface(root.toJSON())); }}><EntryView onSaved={() => {}} /></Profiler>);
  try { await began.promise; await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("queue-receipt-replacement"); vault.unlock({ authKey: key.slice(), dataKey: key.slice() }, "queue-receipt-replacement"); retired = true; await act(async () => { gate.resolve(); }); await flush(); expect(frames.every(frame => !frame.includes(t("entry.queuedOne", { count: 1 })))).toBe(true); expect(publicSurface(root.toJSON())).toBe(before); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it.each(["discard", "save", "oversized retry"] as const)("clears the actual stopped recorder fault after its public %s decision", async decision => {
  let recorder!: NativeRecorder; class FaultedNativeRecorder extends NativeRecorder { constructor(stream: MediaStream, options: MediaRecorderOptions) { super(stream, options); recorder = this; } }
  vi.stubGlobal("MediaRecorder", FaultedNativeRecorder);
  if (decision === "oversized retry") vi.mocked(api.transcribeAudio).mockResolvedValue({ ...transcript, original_text: "x".repeat(100_001) });
  const root = await mount(); await press(root, t("entry.micRecord")); await flush(); await act(async () => { recorder.onerror?.(); }); await flush();
  if (decision !== "oversized retry") { expect(textOf(root)).toContain(t("entry.voiceRecordFailed")); await press(root, t(decision === "discard" ? "entry.voiceDiscardTake" : "entry.save")); await flush(); expect(textOf(root)).not.toContain(t("entry.voiceRecordFailed")); }
  else {
    expect(textOf(root)).toContain(t("entry.tooLongBody", { max: "100,000" }));
    const consent = deferred<Awaited<ReturnType<typeof api.getVoiceConsent>>>(); vi.mocked(api.getVoiceConsent).mockReturnValueOnce(consent.promise);
    try { await press(root, t("entry.micRecord")); await flush(); expect(textOf(root)).not.toContain(t("entry.voiceRecordFailed")); }
    finally { await act(async () => { consent.resolve({ enabled: false, active_for_current_policy: false, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null }); }); await flush(); }
  }
});

it("honestly retains an unkept recording receipt when the bounded retry budget ends before native service recovery", async () => {
  let refused = 0; vi.mocked(api.uploadAudioAttachment).mockImplementation(async () => { if (refused < 3) { refused += 1; throw new ApiError(503, "Native attachment service is still recovering"); } return { attachment_id: "available-only-after-the-accepted-retry-budget", expires_at: "2026-11-04", size_bytes: audioBytes.length }; });
  const saved = vi.fn(), root = await mount(saved); await take(root); await pressSwitch(root); await press(root, t("entry.save"));
  for (let i = 0; i < 180 && saved.mock.calls.length === 0; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
  expect(saved).toHaveBeenCalledWith("sent", "2026-10-05"); expect(textOf(root)).toContain(t("entry.voiceAudioNotKept")); expect(api.uploadAudioAttachment).toHaveBeenCalledTimes(3); expect(api.createEntry).toHaveBeenCalledTimes(1);
});
