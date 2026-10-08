import { act } from "react";
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SettingsView } from "../src/views/Settings";
import { api, auth, ApiError, clearSession, setSession, type LlmConsentState, type VoiceConsentState } from "../src/api/client";
import * as reauth from "../src/reauth";
import * as queue from "../src/offlineQueue";
import * as platform from "../src/platform";
import { kv, setKvBackendForTests, StorageCommitError } from "../src/kvstore";
import { vault } from "../src/vault";
import { __setLocaleForTests, applyLanguagePref, getLanguagePref, t } from "../src/strings";
import { readMeasureCadence, writeMeasureCadence } from "../src/measureCadence";
import { readThemePref } from "../src/theme";
import { installSession, resetTestState, stubFetch, jsonResponse } from "./helpers/api";
import { isDisabled, press, pressSwitch, render, textOf, textOfNode, typeInto } from "./helpers/rtr";
import { publicSurface } from "./helpers/publicSurface";
import { pendingLocalErasures } from "../src/localErasure";

const owner = "settings-behavior-owner";
type Root = Awaited<ReturnType<typeof render>>;
const flush = async () => { for (let i = 0; i < 6; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); };
const llm = (enabled = false, active = true): LlmConsentState => ({ enabled, active_for_current_policy: active, llm_consent_at: null, llm_consent_disclosure: null, llm_consent_policy: null });
const voice = (enabled = false, active = true): VoiceConsentState => ({ enabled, active_for_current_policy: active, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null });
const meta = { version: "1", api_version: "v1", unlock_days: 30, llm_available: true, llm_provider_name: "Approved translation provider", llm_data_retention: "Transient processing", llm_policy_fingerprint: "translation-policy-3", sharing_available: true, sharing_disclosure_version: "v3", audio_available: true, stt_provider_name: "Approved audio provider", stt_data_retention: "Transient transcription", stt_policy_fingerprint: "audio-policy-3" };
const row = (action: string, actor = "self") => ({ at: "2026-10-05T01:02:03.000Z", action, actor });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { resolve, reject, promise }; }
async function mount(open?: () => void) { const root = await render(<SettingsView onLockdown={() => undefined} onOpenSafetyPlan={open} />); await flush(); return root; }
async function confirm(root: Root) { await typeInto(root, t("settings.reauthPasswordField"), "fresh typed password"); await press(root, t("settings.reauthConfirm")); await flush(); }
beforeEach(() => {
  resetTestState(); applyLanguagePref("auto"); __setLocaleForTests("en"); installSession(owner, "settings-user");
  vi.stubGlobal("localStorage", window.localStorage);
  vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)).fill(59), dataKey: new Uint8Array(new ArrayBuffer(32)).fill(61) }, owner);
  vi.spyOn(api, "meta").mockResolvedValue(meta); vi.spyOn(api, "getLlmConsent").mockResolvedValue(llm()); vi.spyOn(api, "getVoiceConsent").mockResolvedValue(voice());
  vi.spyOn(api, "keyEnvelope").mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null });
  vi.spyOn(api, "accessLogPage").mockResolvedValue({ rows: [], nextCursor: null });
  vi.spyOn(reauth, "freshStepUp").mockResolvedValue({ ok: true, proof: "sensitive-proof" });
});
afterEach(() => { vi.restoreAllMocks(); applyLanguagePref("auto"); vi.unstubAllGlobals(); __setLocaleForTests("en"); });

it("retires its public patient loaders after a vault lock without a native rejected UI continuation", async () => {
  const failures: unknown[] = [], observe = (reason: unknown) => { failures.push(reason); }; process.on("unhandledRejection", observe);
  try { vault.lock(); await mount(); await flush(); expect(failures).toEqual([]); expect(api.meta).not.toHaveBeenCalled(); expect(api.accessLogPage).not.toHaveBeenCalled(); }
  finally { process.removeListener("unhandledRejection", observe); }
});

it.each(["export", "recovery", "llm", "voice", "delete", "cadence"] as const)("refuses the still-mounted public %s control after the native vault locks", async kind => {
  const failures: unknown[] = [], observe = (reason: unknown) => { failures.push(reason); }; process.on("unhandledRejection", observe);
  const exportTicket = vi.spyOn(api, "exportAccountTicket").mockResolvedValue({ ticket: "unrequested-native-export", expires_in: 60 }), recover = vi.spyOn(queue, "requeueRejected").mockResolvedValue(0);
  if (kind === "recovery") vi.spyOn(queue, "rejectedEntries").mockResolvedValue([{ userId: owner, clientEntryId: "retained-native-lock", blobB64: "retained ciphertext", entryDate: "2026-10-05" }]);
  const root = await mount(); if (kind === "delete") await typeInto(root, t("settings.deleteConfirmLabel"), "DELETE"); const before = publicSurface(root.toJSON()); vault.lock();
  try {
    if (kind === "llm" || kind === "voice") await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff")); else if (kind === "cadence") await pressSwitch(root, t("settings.remindMeasures")); else await press(root, t(kind === "export" ? "settings.export" : kind === "recovery" ? "settings.requeue" : "settings.deleteButton"));
    await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(exportTicket).not.toHaveBeenCalled(); expect(recover).not.toHaveBeenCalled(); expect(failures).toEqual([]);
  } finally { process.removeListener("unhandledRejection", observe); }
});

it.each(["en", "es"] as const)("renders populated privacy, cadence, access history and key-scheme settings in %s", async locale => {
  __setLocaleForTests(locale); vi.mocked(api.getLlmConsent).mockResolvedValue(llm(true)); vi.mocked(api.getVoiceConsent).mockResolvedValue(voice(true));
  vi.mocked(api.accessLogPage).mockResolvedValue({ rows: [row("patient read"), row("therapist read", "Dr. External"), row("recording playback", "")], nextCursor: "next-page" });
  await writeMeasureCadence(owner, { enabled: true, intervalWeeks: 8, snoozedUntil: "2026-11-01" }); const root = await mount(() => undefined);
  expect(publicSurface(root.toJSON())).toMatchSnapshot(); expect(textOf(root)).toContain("Dr. External"); expect(textOf(root)).toContain("2026-10-05 01:02:03");
});
it.each(["unavailable", "stale", "missing-details", "unknown", "missing-voice-consent"] as const)("renders honest processing policy states: %s", async state => {
  if (state === "unavailable") vi.mocked(api.meta).mockResolvedValue({ ...meta, llm_available: false, audio_available: false });
  if (state === "stale") { vi.mocked(api.getLlmConsent).mockResolvedValue(llm(true, false)); vi.mocked(api.getVoiceConsent).mockResolvedValue(voice(true, false)); }
  if (state === "missing-details") vi.mocked(api.meta).mockResolvedValue({ ...meta, llm_provider_name: null, llm_data_retention: null, llm_policy_fingerprint: null, stt_provider_name: null, stt_data_retention: null, stt_policy_fingerprint: null });
  if (state === "unknown") vi.mocked(api.meta).mockRejectedValue(new Error("metadata unavailable"));
  if (state === "missing-voice-consent") vi.mocked(api.getVoiceConsent).mockRejectedValue(new ApiError(404, "older account"));
  const root = await mount(); expect(publicSurface(root.toJSON())).toMatchSnapshot();
  if (state === "stale") { expect(textOf(root)).toContain(t("settings.llmStaleNote")); expect(textOf(root)).toContain(t("settings.voiceStaleNote")); }
  if (state === "unknown") { vi.mocked(api.meta).mockResolvedValue(meta); await press(root, t("settings.llmRetry")); await flush(); expect(textOf(root)).not.toContain(t("settings.llmUnknown")); }
});
it.each(["v2", "legacy-v1", "unknown"] as const)("honestly routes key protection and its retry state: %s", async scheme => {
  if (scheme === "v2") vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: "public-salt", kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 800_000 }, wrapped_data_key: "opaque envelope" });
  if (scheme === "legacy-v1") vi.mocked(api.keyEnvelope).mockRejectedValue(new ApiError(404, "older server"));
  if (scheme === "unknown") vi.mocked(api.keyEnvelope).mockRejectedValue(new ApiError(503, "unavailable"));
  const root = await mount(); expect(publicSurface(root.toJSON())).toMatchSnapshot();
  if (scheme === "unknown") { expect(root.root.findAllByType("button").some(n => n.children.includes(t("settings.changePasswordButton")))).toBe(false); }
});
it.each(["v1", "v2"] as const)("migrates the retained legacy rekey hint through durable storage and sweeps or dismisses it for %s", async scheme => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: scheme, salt: "", kdf_params: null, wrapped_data_key: null }); const key = `mindpattern.rekeyHint.${owner}`; platform.localStore.set(key, "1");
  const root = await mount(); expect(platform.localStore.get(key)).toBeNull();
  if (scheme === "v1") { expect(await kv.getItem(key)).toBeNull(); expect(textOf(root)).not.toContain(t("settings.rekeyHintNote")); }
  else { expect(await kv.getItem(key)).toBe("1"); expect(textOf(root)).toContain(t("settings.rekeyHintNote")); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t("settings.rekeyHintDismiss")); await flush(); expect(await kv.getItem(key)).toBeNull(); expect(textOf(root)).not.toContain(t("settings.rekeyHintNote")); }
});

it("keeps the existing durable native hint distinct from a duplicate legacy receipt until a later public mount", async () => {
  const key = `mindpattern.rekeyHint.${owner}`; await kv.setItem(key, "1"); platform.localStore.set(key, "1"); vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: "", kdf_params: null, wrapped_data_key: null });
  const first = await mount(); expect(textOf(first)).toContain(t("settings.rekeyHintNote")); expect(platform.localStore.get(key)).toBe("1"); await press(first, t("settings.rekeyHintDismiss")); await flush(); expect(await kv.getItem(key)).toBeNull(); await act(async () => { first.unmount(); });
  const later = await mount(); expect(textOf(later)).toContain(t("settings.rekeyHintNote")); expect(await kv.getItem(key)).toBe("1"); expect(platform.localStore.get(key)).toBeNull();
});
it("preserves fetched access rows after a page failure and retries the same continuation before appending the next page", async () => {
  vi.mocked(api.accessLogPage).mockResolvedValueOnce({ rows: [row("first truthful row")], nextCursor: "cursor-1" }).mockRejectedValueOnce(new Error("temporary page outage")).mockResolvedValueOnce({ rows: [row("second truthful row", "Dr. Next")], nextCursor: null });
  const root = await mount(); await press(root, t("settings.showMore")); await flush(); expect(textOf(root)).toContain("first truthful row"); expect(textOf(root)).toContain(t("settings.accessLoadFailedWeb")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
  await press(root, t("settings.showMore")); await flush(); expect(api.accessLogPage).toHaveBeenLastCalledWith("cursor-1"); expect(textOf(root)).toContain("second truthful row"); expect(textOf(root)).not.toContain(t("settings.accessLoadFailedWeb")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it("applies actual theme, language and cadence choices, and opens the safety-plan destination", async () => {
  const open = vi.fn(), root = await mount(open); await press(root, t("settings.themeDark")); expect(readThemePref()).toBe("dark"); await press(root, t("settings.themeLight")); expect(readThemePref()).toBe("light"); await press(root, t("settings.themeSystem")); expect(readThemePref()).toBe("auto");
  await press(root, t("settings.languageEs")); expect(getLanguagePref()).toBe("es"); await press(root, t("settings.languageEn")); expect(getLanguagePref()).toBe("en");
  await pressSwitch(root, t("settings.remindMeasures")); await flush(); expect((await readMeasureCadence(owner)).enabled).toBe(true);
  await press(root, t("measures.cadence.2")); await flush(); expect((await readMeasureCadence(owner)).intervalWeeks).toBe(2); await press(root, t("measures.cadence.8")); await flush(); expect((await readMeasureCadence(owner)).intervalWeeks).toBe(8);
  await press(root, t("settings.openSafetyPlan")); expect(open).toHaveBeenCalledTimes(1);
});
it.each([false, true])("reports the actual browser result for its one-time export ticket: allowed=%s", async allowed => {
  vi.spyOn(api, "exportAccountTicket").mockResolvedValue({ ticket: "single-use-export-ticket", expires_in: 60 }); const download = vi.spyOn(platform, "requestAccountDownload").mockReturnValue(allowed); const root = await mount(); await press(root, t("settings.export")); await flush();
  expect(download).toHaveBeenCalledWith("single-use-export-ticket"); expect(textOf(root)).toContain(t(allowed ? "settings.exportOk" : "settings.exportBlocked")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it("retains an export error and refuses a retired asynchronous export ticket", async () => {
  const ticket = deferred<Awaited<ReturnType<typeof api.exportAccountTicket>>>(); const request = vi.spyOn(api, "exportAccountTicket").mockRejectedValueOnce(new Error("export service unavailable")).mockReturnValueOnce(ticket.promise), download = vi.spyOn(platform, "requestAccountDownload").mockReturnValue(true);
  const root = await mount(); await press(root, t("settings.export")); await flush(); expect(textOf(root)).toContain("export service unavailable"); await press(root, t("settings.export")); clearSession(); vault.lock(); await act(async () => { ticket.resolve({ ticket: "retired ticket", expires_in: 60 }); }); await flush(); expect(request).toHaveBeenCalledTimes(2); expect(download).not.toHaveBeenCalled();
});
it.each([0, 1, 3])("reports the public recovery result without inventing recovered writing: moved=%s", async moved => {
  vi.spyOn(queue, "queueLength").mockResolvedValueOnce(2).mockResolvedValue(2 + moved); vi.spyOn(queue, "rejectedEntries").mockResolvedValueOnce([{ userId: owner, clientEntryId: "held", blobB64: "ciphertext", entryDate: "2026-10-05" }]).mockResolvedValue([]); vi.spyOn(queue, "queueEvictionSummary").mockResolvedValue({ rejected: 2, quarantine: 3 }); const recovery = vi.spyOn(queue, "requeueRejected").mockResolvedValue(moved);
  const root = await mount(); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, t("settings.requeue")); await flush(); expect(recovery).toHaveBeenCalledWith(owner); expect(textOf(root)).toContain(t(moved === 0 ? "settings.recoveredNone" : moved === 1 ? "settings.recoveredOne" : "settings.recoveredMany", { count: moved })); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["llm", "voice"] as const)("requires fresh authentication for processing consent and displays the returned policy currency: %s", async kind => {
  const change = kind === "llm" ? vi.spyOn(api, "setLlmConsent").mockResolvedValue(llm(true)) : vi.spyOn(api, "setVoiceConsent").mockResolvedValue(voice(true)); const root = await mount(); await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff")); expect(publicSurface(root.toJSON())).toMatchSnapshot(); expect(change).not.toHaveBeenCalled(); expect(isDisabled(root, t("settings.reauthConfirm"))).toBe(true); await confirm(root);
  expect(reauth.freshStepUp).toHaveBeenCalledWith("fresh typed password", kind === "llm" ? "llm_consent" : "voice_consent"); expect(change).toHaveBeenCalledWith(true, "sensitive-proof"); expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmEnabledNote" : "settings.voiceEnabledNote")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it.each(["llm", "voice", "delete"] as const)("does not dispatch a new %s commit after its authenticated view has been retired", async kind => {
  vi.mocked(reauth.freshStepUp).mockRestore();
  const password = "fresh long retirement passphrase", salt = Buffer.alloc(16, 37), master = pbkdf2Sync(password, salt, 100_000, 32, "sha256"), authKey = new Uint8Array(hkdfSync("sha256", master, new Uint8Array(32), Buffer.from("mindpattern/auth/v1"), 32));
  vault.unlock({ authKey, dataKey: new Uint8Array(32).fill(61) }, owner);
  vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: salt.toString("base64") });
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: salt.toString("base64"), kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 100_000 }, wrapped_data_key: "existing encrypted envelope" });
  const granted = deferred<Awaited<ReturnType<typeof api.stepUp>>>(), stepUp = vi.spyOn(api, "stepUp").mockReturnValue(granted.promise);
  const commit = kind === "llm" ? vi.spyOn(api, "setLlmConsent").mockResolvedValue(llm(true)) : kind === "voice" ? vi.spyOn(api, "setVoiceConsent").mockResolvedValue(voice(true)) : vi.spyOn(api, "deleteAccount").mockResolvedValue(null);
  const root = await mount();
  if (kind === "delete") { await typeInto(root, t("settings.deleteConfirmLabel"), "DELETE"); await press(root, t("settings.deleteButton")); }
  else await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff"));
  await typeInto(root, t("settings.reauthPasswordField"), password); await press(root, t("settings.reauthConfirm"));
  for (let i = 0; i < 1_000 && stepUp.mock.calls.length === 0; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); });
  expect(stepUp).toHaveBeenCalledExactlyOnceWith(Buffer.from(authKey).toString("base64"), kind === "llm" ? "llm_consent" : kind === "voice" ? "voice_consent" : "account_delete");
  await act(async () => { root.unmount(); }); await act(async () => { granted.resolve({ proof: "authorized original-account proof", expires_in: 300, action: kind === "llm" ? "llm_consent" : kind === "voice" ? "voice_consent" : "account_delete" }); }); await flush();
  expect(commit).not.toHaveBeenCalled(); expect(await pendingLocalErasures()).toEqual([]);
});

it("shows the sensitive action as working and disables its confirm/cancel controls until authentication settles", async () => {
  const answer = deferred<Awaited<ReturnType<typeof reauth.freshStepUp>>>(); vi.mocked(reauth.freshStepUp).mockReturnValue(answer.promise);
  const change = vi.spyOn(api, "setVoiceConsent").mockResolvedValue(voice(true)), root = await mount(); await pressSwitch(root, t("settings.voiceStatusOff")); await typeInto(root, t("settings.reauthPasswordField"), "fresh typed password"); await press(root, t("settings.reauthConfirm")); await flush();
  const prompt = root.root.findAllByType("section").find(section => section.findAllByType("h2").some(title => textOfNode(title) === t("settings.reauthVoiceTitle")))!; expect(prompt.findAllByType("button").map(textOfNode)).toEqual([t("settings.working"), t("common.cancel")]);
  expect(isDisabled(root, t("settings.working"))).toBe(true); expect(isDisabled(root, t("common.cancel"))).toBe(true); expect(isDisabled(root, t("settings.export"))).toBe(true); expect(change).not.toHaveBeenCalled();
  await act(async () => { answer.resolve({ ok: true, proof: "settled sensitive proof" }); }); await flush(); expect(change).toHaveBeenCalledWith(true, "settled sensitive proof"); expect(textOf(root)).not.toContain(t("settings.working"));
});
it.each(["locked", "no-account", "wrong-password", "offline"] as const)("shows fresh authentication refusal while retaining its explicit consent prompt: %s", async reason => {
  vi.mocked(reauth.freshStepUp).mockResolvedValue({ ok: false, reason }); const change = vi.spyOn(api, "setVoiceConsent").mockResolvedValue(voice(true)), root = await mount(); await pressSwitch(root, t("settings.voiceStatusOff")); await confirm(root); const keys = { locked: "common.reauthLocked", "no-account": "common.reauthNoAccount", "wrong-password": "common.wrongPassword", offline: "common.reauthOffline" }; expect(textOf(root)).toContain(t(keys[reason])); expect(change).not.toHaveBeenCalled(); expect(root.root.findAllByType("input").find(n => n.props.autoComplete === "current-password" && n.props.type === "password" && n.props.value === "")).toBeDefined(); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it.each(["llm-unavailable", "llm-error", "voice-unavailable", "voice-error"] as const)("shows an honest consent commit error without claiming an enabled policy: %s", async kind => {
  const isLlm = kind.startsWith("llm"), unavailable = kind.endsWith("unavailable"), error = new ApiError(503, "scope unavailable", unavailable ? isLlm ? "llm_unavailable" : "stt_unavailable" : undefined);
  if (isLlm) vi.spyOn(api, "setLlmConsent").mockRejectedValue(error); else vi.spyOn(api, "setVoiceConsent").mockRejectedValue(error);
  const root = await mount(); await pressSwitch(root, t(isLlm ? "settings.llmStatusOff" : "settings.voiceStatusOff")); await confirm(root);
  expect(textOf(root)).toContain(t(isLlm ? unavailable ? "settings.llmNotOfferedToggle" : "settings.llmToggleFailed" : unavailable ? "settings.voiceNotOffered" : "settings.voiceToggleFailed")); expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it("requires explicit DELETE confirmation and allows a cancelled destructive prompt to retain all records", async () => {
  const remove = vi.spyOn(api, "deleteAccount").mockResolvedValue(null), root = await mount(); expect(isDisabled(root, t("settings.deleteButton"))).toBe(true); await typeInto(root, t("settings.deleteConfirmLabel"), "DELETE something else"); expect(isDisabled(root, t("settings.deleteButton"))).toBe(true); await typeInto(root, t("settings.deleteConfirmLabel"), " delete "); expect(isDisabled(root, t("settings.deleteButton"))).toBe(false); await press(root, t("settings.deleteButton")); expect(publicSurface(root.toJSON())).toMatchSnapshot(); await typeInto(root, t("settings.reauthPasswordField"), "discard this password"); await press(root, t("common.cancel")); expect(remove).not.toHaveBeenCalled(); expect(reauth.freshStepUp).not.toHaveBeenCalled();
});
it("displays a failed queue recovery as an actionable error and releases the busy state", async () => {
  vi.spyOn(queue, "rejectedEntries").mockResolvedValue([{ userId: owner, clientEntryId: "held", blobB64: "retained ciphertext", entryDate: "2026-10-05" }]); const recover = vi.spyOn(queue, "requeueRejected").mockRejectedValue(new StorageCommitError("Recovery was not saved; retry without deleting your writing.")); const root = await mount(); await press(root, t("settings.requeue")); await flush(); expect(textOf(root)).toContain("Recovery was not saved; retry without deleting your writing."); expect(isDisabled(root, t("settings.requeue"))).toBe(false);
  recover.mockResolvedValueOnce(1); await press(root, t("settings.requeue")); await flush(); expect(textOf(root)).not.toContain("Recovery was not saved; retry without deleting your writing."); expect(textOf(root)).toContain(t("settings.recoveredOne", { count: 1 }));
});
it.each(["v1 rotation", "v2 password", "v1 upgrade"] as const)("never submits the original account's data key after an owner replacement during%s", async flow => {
  const envelope = { key_scheme: flow === "v2 password" ? "v2" as const : "v1" as const, salt: "", kdf_params: null, wrapped_data_key: null }; vi.mocked(api.keyEnvelope).mockResolvedValue(envelope); const root = await mount(), response = deferred<Awaited<ReturnType<typeof api.keyEnvelope>>>(); const processing = vi.spyOn(api, "openProcessingSession").mockRejectedValue(new Error("boundary transport deliberately unavailable"));
  if (flow === "v1 upgrade") {
    let answer!: (value: { salt: string }) => void; vi.spyOn(auth, "saltFor").mockImplementation(() => new Promise(resolve => { answer = resolve; })); await typeInto(root, t("settings.upgradePasswordField"), "a-fresh-long-passphrase-7"); await press(root, t("settings.upgradeButton")); clearSession(); installSession("replacement-account", "replacement-user"); vault.unlock({ authKey: new Uint8Array(32).fill(91), dataKey: new Uint8Array(32).fill(93) }, "replacement-account"); await act(async () => { answer({ salt: Buffer.from(new Uint8Array(16).fill(17)).toString("base64") }); });
  } else {
    vi.spyOn(queue, "drainPendingQueueForRotation").mockResolvedValue(0); vi.mocked(api.keyEnvelope).mockReturnValue(response.promise); await typeInto(root, t("settings.newPasswordField"), "a-fresh-long-passphrase-7"); await typeInto(root, t("settings.confirmPasswordField"), "a-fresh-long-passphrase-7"); await press(root, t("settings.changePasswordButton"));
    // Wait for the rotation to fetch its own press-time envelope before retiring ownership.
    for (let i = 0; i < 100 && vi.mocked(api.keyEnvelope).mock.calls.length < 2; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); expect(api.keyEnvelope).toHaveBeenCalledTimes(2); clearSession(); installSession("replacement-account", "replacement-user"); vault.unlock({ authKey: new Uint8Array(32).fill(91), dataKey: new Uint8Array(32).fill(93) }, "replacement-account"); await act(async () => { response.resolve(envelope); });
  }
  const busy = () => root.root.findAllByType("button").some(node => node.children.includes(t("settings.working")));
  for (let i = 0; i < 1_000 && busy(); i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); expect(busy()).toBe(false); expect(processing).not.toHaveBeenCalled();
});

it.each(["llm", "voice"] as const)("turns off an active consent and reflects the server's returned disabled policy: %s", async kind => {
  vi.mocked(api.getLlmConsent).mockResolvedValue(llm(true)); vi.mocked(api.getVoiceConsent).mockResolvedValue(voice(true));
  const change = kind === "llm" ? vi.spyOn(api, "setLlmConsent").mockResolvedValue(llm(false)) : vi.spyOn(api, "setVoiceConsent").mockResolvedValue(voice(false));
  const root = await mount(); await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusEnabled" : "settings.voiceStatusEnabled")); await confirm(root);
  expect(change).toHaveBeenCalledWith(false, "sensitive-proof"); expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmDisabledNote" : "settings.voiceDisabledNote"));
  expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff"));
});
it.each(["llm", "voice"] as const)("preserves a returned inactive policy even after the server accepts the opt-in: %s", async kind => {
  if (kind === "llm") vi.spyOn(api, "setLlmConsent").mockResolvedValue(llm(true, false)); else vi.spyOn(api, "setVoiceConsent").mockResolvedValue(voice(true, false));
  const root = await mount(); await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff")); await confirm(root);
  expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmStaleNote" : "settings.voiceStaleNote"));
  expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff"));
});
it.each(["llm", "voice"] as const)("handles a native consent transport failure without inventing availability: %s", async kind => {
  if (kind === "llm") vi.spyOn(api, "setLlmConsent").mockRejectedValue(new Error("native transport disconnected")); else vi.spyOn(api, "setVoiceConsent").mockRejectedValue(new Error("native transport disconnected"));
  const root = await mount(); await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff")); await confirm(root);
  expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmToggleFailed" : "settings.voiceToggleFailed"));
});
it("cancels the displayed authentication prompt and clears its password before a new consent request", async () => {
  const root = await mount(); await pressSwitch(root, t("settings.voiceStatusOff")); await typeInto(root, t("settings.reauthPasswordField"), "retired secret"); await press(root, t("common.cancel"));
  expect(textOf(root)).not.toContain(t("settings.reauthVoiceTitle")); await pressSwitch(root, t("settings.llmStatusOff"));
  const input = root.root.findAllByType("input").find(node => node.props.autoComplete === "current-password" && node.props.type === "password");
  expect(input?.props.value).toBe(""); expect(reauth.freshStepUp).not.toHaveBeenCalled();
});
it.each(["success", "remote refusal", "already deleted", "local cleanup failure", "checkpoint failure"] as const)("finishes account deletion honestly and retains retry evidence on%s", async outcome => {
  await kv.setItem(`mindpattern.moodlog.${owner}`, "owned ciphertext"); await kv.setItem("mindpattern.moodlog.other-account", "other ciphertext");
  const actualRemove = kv.removeItem.bind(kv), actualSet = kv.setItem.bind(kv);
  if (outcome === "local cleanup failure") vi.spyOn(kv, "removeItem").mockImplementation(async key => { if (key === `mindpattern.moodlog.${owner}`) throw new Error("disk cleanup failed"); await actualRemove(key); });
  if (outcome === "checkpoint failure") vi.spyOn(kv, "setItem").mockImplementation(async (key, value) => { if (key === `mindpattern.erase.${owner}`) throw new Error("checkpoint unavailable"); await actualSet(key, value); });
  const remove = vi.spyOn(api, "deleteAccount");
  if (outcome === "remote refusal") remove.mockRejectedValue(new ApiError(503, "delete refused")); else if (outcome === "already deleted") remove.mockRejectedValue(new ApiError(410, "already deleted")); else remove.mockResolvedValue(null);
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); await typeInto(root, t("settings.deleteConfirmLabel"), " delete "); await press(root, t("settings.deleteButton")); await confirm(root);
  for (let i = 0; i < 100 && root.root.findAllByType("button").some(node => textOfNode(node) === t("settings.working")); i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); });
  expect(reauth.freshStepUp).toHaveBeenCalledWith("fresh typed password", "account_delete"); expect(await kv.getItem("mindpattern.moodlog.other-account")).toBe("other ciphertext");
  if (outcome === "success") { expect(remove).toHaveBeenCalledWith("sensitive-proof"); expect(await kv.getItem(`mindpattern.moodlog.${owner}`)).toBeNull(); expect(await pendingLocalErasures()).toEqual([]); expect(lockdown).toHaveBeenCalledWith(t("settings.deleteDoneNotice")); }
  else if (outcome === "already deleted" || outcome === "local cleanup failure") { expect(lockdown).toHaveBeenCalledWith(t("app.erasureIncomplete")); expect((await pendingLocalErasures()).map(row => [row.owner, row.remoteConfirmed])).toEqual([[owner, outcome === "local cleanup failure"]]); }
  else { expect(lockdown).not.toHaveBeenCalled(); expect(textOf(root)).toContain(t("settings.deleteFailed")); expect(await kv.getItem(`mindpattern.moodlog.${owner}`)).toBe("owned ciphertext"); if (outcome === "checkpoint failure") expect(remove).not.toHaveBeenCalled(); }
});
it("reflects each browser theme in the rendered selection and document, and returns language to automatic", async () => {
  const documentElement = { dataset: {} as Record<string, string> }; vi.stubGlobal("document", { documentElement }); const root = await mount();
  for (const theme of ["dark", "light", "auto"] as const) {
    const label = t(theme === "dark" ? "settings.themeDark" : theme === "light" ? "settings.themeLight" : "settings.themeSystem"); await press(root, label);
    expect(documentElement.dataset.theme).toBe(theme === "auto" ? "light" : theme);
    expect(root.root.findAllByType("button").find(node => textOfNode(node) === label)?.props["aria-checked"]).toBe(true);
  }
  await press(root, t("settings.languageEs")); await press(root, t("settings.languageAuto")); expect(getLanguagePref()).toBe("auto");
});
it("reports singular queued writing and multiple rejected records without changing the recovery counts", async () => {
  vi.spyOn(queue, "queueLength").mockResolvedValue(1); vi.spyOn(queue, "rejectedEntries").mockResolvedValue([0, 1].map(index => ({ userId: owner, clientEntryId: `rejected-${index}`, blobB64: "kept ciphertext", entryDate: "2026-10-05" })));
  const root = await mount(); expect(textOf(root)).toContain(t("settings.queuedOne", { count: 1 })); expect(textOf(root)).toContain(t("settings.rejectedMany", { count: 2 }));
});
it("starts with empty access history after its first page fails and retries from the first page", async () => {
  const pages = vi.mocked(api.accessLogPage).mockRejectedValueOnce(new Error("first page unavailable")).mockResolvedValue({ rows: [row("recovered audit row")], nextCursor: null });
  const root = await mount(); expect(textOf(root)).toContain(t("settings.accessEmpty")); expect(textOf(root)).not.toContain(t("settings.showMore"));
  vi.mocked(api.keyEnvelope).mockRejectedValue(new ApiError(503, "scheme unavailable")); vi.mocked(api.meta).mockRejectedValue(new Error("metadata unavailable"));
  // A fresh mount presents the ordinary retry for unavailable account data.
  await act(async () => { root.unmount(); }); const retry = await mount(); vi.mocked(api.meta).mockResolvedValue(meta); await press(retry, t("settings.llmRetry")); await flush();
  expect(pages).toHaveBeenLastCalledWith(undefined); expect(textOf(retry)).toContain("recovered audit row");
});
it("does not sweep the replacement account's rekey warning from an abandoned partial settings load", async () => {
  let rejectVoice!: (error: Error) => void; vi.mocked(api.getVoiceConsent).mockImplementation(() => new Promise((_resolve, reject) => { rejectVoice = reject; }));
  const root = await render(<SettingsView onLockdown={() => undefined} />); await flush(); expect(api.keyEnvelope).toHaveBeenCalledTimes(1);
  // The old v1 envelope has already arrived, while the remaining request is
  // aborted during an ordinary account replacement and view unmount.
  await kv.setItem("mindpattern.rekeyHint.replacement-owner", "1"); await act(async () => { root.unmount(); }); clearSession(); installSession("replacement-owner", "replacement-user"); vault.unlock({ authKey: new Uint8Array(32).fill(91), dataKey: new Uint8Array(32).fill(93) }, "replacement-owner");
  await act(async () => { rejectVoice(new ApiError(0, "previous account request aborted")); }); await flush();
  expect(await kv.getItem("mindpattern.rekeyHint.replacement-owner")).toBe("1");
});

it.each(["llm", "voice"] as const)("keeps honest localized copy when a native %s consent commit returns a non-Error failure", async kind => {
  if (kind === "llm") vi.spyOn(api, "setLlmConsent").mockRejectedValue(null); else vi.spyOn(api, "setVoiceConsent").mockRejectedValue(null);
  const root = await mount(); await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff")); await confirm(root); expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmToggleFailed" : "settings.voiceToggleFailed"));
});
it.each(["rejected", "losses"] as const)("honestly retains the queue section when its native %s inventory cannot be read", async kind => {
  if (kind === "rejected") vi.spyOn(queue, "rejectedEntries").mockRejectedValue(new Error("Rejected storage unavailable")); else vi.spyOn(queue, "queueEvictionSummary").mockRejectedValue(new Error("Loss inventory unavailable"));
  const errors: unknown[] = [], observe = (reason: unknown) => { errors.push(reason); }; process.on("unhandledRejection", observe);
  try { const root = await mount(); await flush(); expect(errors).toEqual([]); expect(textOf(root)).toContain(t("settings.export")); expect(textOf(root)).not.toContain(t("settings.rejectedOne", { count: 1 })); expect(root.root.findAllByType("button").some(n => textOfNode(n) === t("settings.requeue"))).toBe(false); }
  finally { process.removeListener("unhandledRejection", observe); }
});
it("retains known metadata controls while a public retry honestly returns to its loading state", async () => {
  vi.mocked(api.meta).mockRejectedValueOnce(new Error("First metadata unavailable")); const root = await mount(); expect(textOf(root)).toContain(t("settings.llmUnknown")); const answer = deferred<Awaited<ReturnType<typeof api.meta>>>(); vi.mocked(api.meta).mockReturnValueOnce(answer.promise); await press(root, t("settings.llmRetry"));
  try { expect(textOf(root)).not.toContain(t("settings.llmUnknown")); expect(textOf(root)).not.toContain(t("settings.llmRetry")); }
  finally { await act(async () => { answer.resolve(meta); }); await flush(); }
  expect(textOf(root)).toContain(t("settings.llmStatusOff"));
});

it("does not publish an old account's policy or rekey hint after its accepted native legacy migration finishes for a replacement session", async () => {
  const slot = `mindpattern.rekeyHint.${owner}`, records = new Map<string, string>(), pending = deferred<void>(), began = deferred<void>(); platform.localStore.set(slot, "1");
  setKvBackendForTests({ getItem: async key => records.get(key) ?? null, setItem: async (key, value) => { records.set(key, value); if (key === slot) { began.resolve(); await pending.promise; } }, removeItem: async key => { records.delete(key); }, keys: async () => [...records.keys()] });
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: "public-salt", kdf_params: null, wrapped_data_key: "authenticated envelope" }); const root = await render(<SettingsView onLockdown={() => {}} />); await began.promise; const before = publicSurface(root.toJSON());
  clearSession(); installSession("replacement-settings-owner", "replacement-settings-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-settings-owner"); await act(async () => { pending.resolve(); }); await flush();
  expect(publicSurface(root.toJSON())).toBe(before); expect(textOf(root)).not.toContain(t("settings.rekeyHintNote")); expect(vault.ownerUserId()).toBe("replacement-settings-owner");
});

it("does not publish old account queue inventory after a held actual native read completes for a replacement session", async () => {
  const records = new Map<string, string>(), gate = deferred<void>(), began = deferred<void>(); let hold = false;
  setKvBackendForTests({ getItem: async slot => { const value = records.get(slot) ?? null; if (hold && slot.startsWith("mindpattern/queue.v1.items.")) { began.resolve(); await gate.promise; } return value; }, setItem: async (slot, value) => { records.set(slot, value); }, removeItem: async slot => { records.delete(slot); }, keys: async () => [...records.keys()] });
  await queue.enqueue({ userId: owner, clientEntryId: "old-device-entry", blobB64: "actual retained old encrypted writing", entryDate: "2026-10-05" }); hold = true; const root = await render(<SettingsView onLockdown={() => {}} />);
  try { let timer!: ReturnType<typeof setTimeout>; const started = await Promise.race([began.promise.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), 300); })]); clearTimeout(timer); expect(started).toBe(true); await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-queue-owner", "replacement-queue-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-queue-owner"); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(textOf(root)).not.toContain(t("settings.queuedOne", { count: 1 })); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("keeps a retired actual recovery receipt out of a replacement session's settings surface", async () => {
  const records = new Map<string, string>(), gate = deferred<void>(), wrote = deferred<void>(); let hold = false;
  setKvBackendForTests({ getItem: async slot => records.get(slot) ?? null, setItem: async (slot, value) => { records.set(slot, value); if (hold && slot.startsWith("mindpattern/queue.v1.rejected.")) { wrote.resolve(); await gate.promise; } }, removeItem: async slot => { records.delete(slot); if (hold && slot.startsWith("mindpattern/queue.v1.rejected.")) { wrote.resolve(); await gate.promise; } }, keys: async () => [...records.keys()] });
  await queue.enqueue({ userId: owner, clientEntryId: "old-rejected-device-entry", blobB64: "actual retained rejected encrypted writing", entryDate: "2026-10-05" });
  const itemSlot = [...records.keys()].find(slot => slot.startsWith("mindpattern/queue.v1.items."))!, rejectedSlot = itemSlot.replace(".items.", ".rejected."); await kv.setItem(rejectedSlot, records.get(itemSlot)!); await kv.removeItem(itemSlot);
  const root = await mount(); expect(textOf(root)).toContain(t("settings.rejectedOne", { count: 1 })); hold = true; await press(root, t("settings.requeue"));
  try { let timer!: ReturnType<typeof setTimeout>; const started = await Promise.race([wrote.promise.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), 300); })]); clearTimeout(timer); expect(started).toBe(true); await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-recovery-owner", "replacement-recovery-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-recovery-owner"); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); expect(textOf(root)).not.toContain(t("settings.recoveredOne", { count: 1 })); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("hides the old LLM controls while a native public retry is loading and removes unavailable voice policy after its answer", async () => {
  vi.mocked(api.keyEnvelope).mockRejectedValueOnce(new ApiError(503, "Envelope briefly unavailable")); const root = await mount(); expect(root.root.findAllByType("button").some(node => node.props.role === "switch" && node.props["aria-label"] === t("settings.voiceStatusOff"))).toBe(true);
  const gate = deferred<Awaited<ReturnType<typeof api.meta>>>(); vi.mocked(api.meta).mockReturnValueOnce(gate.promise); await press(root, t("settings.llmRetry"));
  try { expect(root.root.findAllByType("button").some(node => node.props.role === "switch" && node.props["aria-label"] === t("settings.llmStatusOff"))).toBe(false); }
  finally { await act(async () => { gate.reject(new ApiError(503, "Current native policy unavailable")); }); await flush(); }
  expect(textOf(root)).toContain(t("settings.llmUnknown")); expect(root.root.findAllByType("button").some(node => node.props.role === "switch" && node.props["aria-label"] === t("settings.voiceStatusOff"))).toBe(false);
});

it.each(["v1", "v2"] as const)("removes the previously known %s credential actions when a public retry cannot establish its native key scheme", async scheme => {
  vi.mocked(api.meta).mockRejectedValueOnce(new ApiError(503, "Metadata briefly unavailable")); vi.mocked(api.keyEnvelope).mockResolvedValueOnce({ key_scheme: scheme, salt: "", kdf_params: null, wrapped_data_key: null }).mockRejectedValue(new ApiError(503, "Fresh envelope unavailable")); const root = await mount(); expect(root.root.findAllByType("button").some(node => textOfNode(node) === t("settings.changePasswordButton"))).toBe(true); await press(root, t("settings.llmRetry")); await flush(); expect(textOf(root)).toContain(t("settings.schemeUnknownNote")); expect(root.root.findAllByType("button").some(node => textOfNode(node) === t("settings.changePasswordButton"))).toBe(false); expect(root.root.findAllByType("input").some(node => node.props.autoComplete === "new-password")).toBe(false);
});

it.each(["fresh", "failed"] as const)("refreshes access history from its first native page after a public scheme retry: %s", async outcome => {
  vi.mocked(api.keyEnvelope).mockRejectedValueOnce(new ApiError(503, "Envelope briefly unavailable")); vi.mocked(api.accessLogPage).mockResolvedValueOnce({ rows: [row("old-completed-access")], nextCursor: "old-continuation" }); const root = await mount(); expect(textOf(root)).toContain("old-completed-access");
  if (outcome === "fresh") vi.mocked(api.accessLogPage).mockResolvedValueOnce({ rows: [row("fresh-completed-access")], nextCursor: null }); else vi.mocked(api.accessLogPage).mockRejectedValueOnce(new ApiError(503, "First access page unavailable")); await press(root, t("settings.llmRetry")); await flush(); expect(textOf(root)).not.toContain("old-completed-access"); expect(root.root.findAllByType("button").some(node => textOfNode(node) === t("settings.showMore"))).toBe(false); if (outcome === "fresh") expect(textOf(root)).toContain("fresh-completed-access");
});

it("consumes the old export receipt while the user's accepted native upgrade proof is still being obtained", async () => {
  vi.spyOn(api, "exportAccountTicket").mockResolvedValue({ ticket: "actual-one-time-export", expires_in: 60 }); vi.spyOn(platform, "requestAccountDownload").mockReturnValue(true); const root = await mount(); await press(root, t("settings.export")); await flush(); expect(textOf(root)).toContain(t("settings.exportOk")); const gate = deferred<{ salt: string }>(); vi.spyOn(auth, "saltFor").mockReturnValue(gate.promise); vi.spyOn(api, "openProcessingSession").mockResolvedValue({ session_token: "native-upgrade-proof", expires_in: 300 }); vi.spyOn(api, "upgradeKeyEnvelope").mockResolvedValue(null); await typeInto(root, t("settings.upgradePasswordField"), "a-fresh-long-passphrase-7"); await press(root, t("settings.upgradeButton"));
  try { expect(textOf(root)).not.toContain(t("settings.exportOk")); }
  finally { await act(async () => { gate.resolve({ salt: Buffer.alloc(16, 23).toString("base64") }); }); for (let i = 0; i < 300 && root.root.findAllByType("button").some(node => textOfNode(node) === t("settings.working")); i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); await flush(); }
  expect(api.upgradeKeyEnvelope).toHaveBeenCalledTimes(1);
});

it("keeps the newer public retry's cadence when an earlier native preference read returns late in the same account", async () => {
  await writeMeasureCadence(owner, { enabled: false, intervalWeeks: 2, snoozedUntil: null });
  const realRead = kv.getItem.bind(kv), gate = deferred<void>(), began = deferred<void>(); let first = true;
  vi.spyOn(kv, "getItem").mockImplementation(async (...args) => { const value = await realRead(...args); if (first && args[0] === `mindpattern.measureCadence.${owner}`) { first = false; began.resolve(); await gate.promise; } return value; });
  vi.mocked(api.meta).mockRejectedValueOnce(new ApiError(503, "First metadata read temporarily unavailable"));
  const root = await render(<SettingsView onLockdown={() => {}} />);
  try {
    await began.promise; await flush(); expect(textOf(root)).toContain(t("settings.llmRetry"));
    await writeMeasureCadence(owner, { enabled: true, intervalWeeks: 8, snoozedUntil: null });
    await press(root, t("settings.llmRetry")); await flush();
    const remind = () => root.root.findAllByType("button").find(button => button.props.role === "switch" && String(button.props["aria-label"] ?? "").includes(t("settings.remindMeasures")))!;
    expect(remind().props["aria-checked"]).toBe(true); expect(textOf(root)).toContain(t("measures.cadence.8"));
    await act(async () => { gate.resolve(); }); await flush(); expect(remind().props["aria-checked"]).toBe(true); expect(await readMeasureCadence(owner)).toMatchObject({ enabled: true, intervalWeeks: 8 });
  } finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("keeps the newer native access history when the first public load answers after a same-account Retry", async () => {
  const gate = deferred<Awaited<ReturnType<typeof api.accessLogPage>>>(), began = deferred<void>();
  vi.mocked(api.meta).mockRejectedValueOnce(new ApiError(503, "First metadata request temporarily unavailable"));
  vi.mocked(api.accessLogPage).mockImplementationOnce(async () => { began.resolve(); return gate.promise; }).mockResolvedValue({ rows: [row("Newest verified native access history")], nextCursor: null });
  const root = await render(<SettingsView onLockdown={() => {}} />);
  try { await began.promise; await flush(); await press(root, t("settings.llmRetry")); await flush(); expect(textOf(root)).toContain("Newest verified native access history"); await act(async () => { gate.resolve({ rows: [row("Obsolete earlier native access history")], nextCursor: "old-page-cursor" }); }); await flush(); expect(textOf(root)).toContain("Newest verified native access history"); expect(textOf(root)).not.toContain("Obsolete earlier native access history"); expect(root.root.findAllByType("button").some(button => textOfNode(button) === t("settings.showMore"))).toBe(false); }
  finally { await act(async () => { gate.resolve({ rows: [], nextCursor: null }); }); await flush(); }
});

it("keeps the newest same-generation native access continuation after two public Show more admissions", async () => {
  const gate = deferred<Awaited<ReturnType<typeof api.accessLogPage>>>(), began = deferred<void>(); vi.mocked(api.accessLogPage).mockResolvedValueOnce({ rows: [row("Verified first page")], nextCursor: "verified-cursor-one" }).mockImplementationOnce(async () => { began.resolve(); return gate.promise; }).mockResolvedValueOnce({ rows: [row("Newest accepted continuation")], nextCursor: "verified-cursor-two" }).mockResolvedValue({ rows: [], nextCursor: null });
  const root = await mount();
  try { await press(root, t("settings.showMore")); await began.promise; await press(root, t("settings.showMore")); await flush(); expect(textOf(root)).toContain("Newest accepted continuation"); await act(async () => { gate.resolve({ rows: [row("Obsolete held continuation")], nextCursor: "obsolete-native-cursor" }); }); await flush(); expect(textOf(root)).not.toContain("Obsolete held continuation"); await press(root, t("settings.showMore")); await flush(); expect(api.accessLogPage).toHaveBeenLastCalledWith("verified-cursor-two"); }
  finally { await act(async () => { gate.resolve({ rows: [], nextCursor: null }); }); await flush(); }
});

it("refuses an older native access receipt as soon as a public retry begins before its new metadata is available", async () => {
  const pageGate = deferred<Awaited<ReturnType<typeof api.accessLogPage>>>(), pageBegan = deferred<void>(), metadataGate = deferred<typeof meta>(); vi.mocked(api.meta).mockRejectedValueOnce(new ApiError(503, "Earlier metadata unavailable")).mockReturnValueOnce(metadataGate.promise).mockResolvedValue(meta); vi.mocked(api.accessLogPage).mockImplementationOnce(async () => { pageBegan.resolve(); return pageGate.promise; }).mockResolvedValue({ rows: [row("Current accepted native page")], nextCursor: null });
  const root = await render(<SettingsView onLockdown={() => {}} />);
  try { await pageBegan.promise; await flush(); await press(root, t("settings.llmRetry")); await flush(); await act(async () => { pageGate.resolve({ rows: [row("Retired old native page during new loading")], nextCursor: "obsolete-cursor" }); }); await flush(); expect(textOf(root)).not.toContain("Retired old native page during new loading"); await act(async () => { metadataGate.resolve(meta); }); await flush(); expect(textOf(root)).toContain("Current accepted native page"); }
  finally { await act(async () => { pageGate.resolve({ rows: [], nextCursor: null }); metadataGate.resolve(meta); }); await flush(); }
});

it("keeps an accepted native initial envelope receipt from opening retired account credential controls", async () => {
  vi.mocked(api.keyEnvelope).mockRestore(); const nativeEnvelope = api.keyEnvelope, gate = deferred<void>(), began = deferred<void>(); stubFetch(() => jsonResponse({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null })); vi.spyOn(api, "keyEnvelope").mockImplementationOnce(async () => { const body = await nativeEnvelope(); began.resolve(); await gate.promise; return body; }); const root = await render(<SettingsView onLockdown={() => {}} />);
  try { await began.promise; await flush(); expect(root.root.findAllByType("button").some(button => textOfNode(button) === t("settings.llmRetry"))).toBe(false); const privacy = root.root.findAllByType("section").find(section => section.findAllByType("h2").some(node => textOfNode(node) === t("settings.privacyDataTitle")))!; expect(textOfNode(privacy)).toContain(t("common.loading")); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-native-envelope-owner", "replacement-native-envelope-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-envelope-owner"); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("refuses a public fresh-authentication confirmation after its native vault lock", async () => {
  const root = await mount(); await pressSwitch(root, t("settings.llmStatusOff")); await typeInto(root, t("settings.reauthPasswordField"), "fresh typed native password"); const before = publicSurface(root.toJSON()); vault.lock(); await press(root, t("settings.reauthConfirm")); await flush(); expect(reauth.freshStepUp).not.toHaveBeenCalled(); expect(publicSurface(root.toJSON())).toBe(before);
});

it("refuses the public access continuation after the native vault lock", async () => {
  vi.mocked(api.accessLogPage).mockResolvedValue({ rows: [row("Already admitted access history")], nextCursor: "unrequested-native-cursor" }); const root = await mount(); vi.mocked(api.accessLogPage).mockClear(); const before = publicSurface(root.toJSON()); vault.lock(); await press(root, t("settings.showMore")); await flush(); expect(api.accessLogPage).not.toHaveBeenCalled(); expect(publicSurface(root.toJSON())).toBe(before);
});

it("keeps the fresh native access failure quiet after it has replaced the retained history", async () => {
  vi.mocked(api.accessLogPage).mockRejectedValue(new ApiError(503, "Native access page unavailable")); const root = await mount(), card = root.root.findAllByType("section").find(section => section.findAllByType("h2").some(node => textOfNode(node) === t("settings.accessTitle")))!; expect(textOfNode(card)).toBe(t("settings.accessTitle") + t("settings.accessEmpty"));
});

it("dismisses an old visible hint after a native vault lock without dispatching unavailable storage", async () => {
  await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1"); vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: "", kdf_params: null, wrapped_data_key: null }); const root = await mount(), failures: unknown[] = [], observe = (reason: unknown) => { failures.push(reason); }; process.on("unhandledRejection", observe); vault.lock(); setKvBackendForTests({ getItem: async () => null, keys: async () => [], setItem: async () => { throw new Error("Native device storage unavailable"); }, removeItem: async () => { throw new Error("Native device deletion unavailable"); } });
  try { await press(root, t("settings.rekeyHintDismiss")); await flush(); expect(textOf(root)).not.toContain(t("settings.rekeyHintNote")); expect(failures).toEqual([]); }
  finally { process.removeListener("unhandledRejection", observe); }
});

it("keeps retired native joined recovery counts from replacing the account's admitted pending controls", async () => {
  await queue.enqueue({ userId: owner, clientEntryId: "joined-native-recovery", blobB64: "retained encrypted original", entryDate: "2026-10-05" }); const itemSlot = (await kv.keys()).find(slot => slot.startsWith("mindpattern/queue.v1.items."))!, wire = await kv.getItem(itemSlot); await kv.setItem(itemSlot.replace(".items.", ".rejected."), wire!); await kv.removeItem(itemSlot); const recovery = queue.requeueRejected, length = queue.queueLength, began = deferred<void>(), gate = deferred<void>(); let recovered = false;
  vi.spyOn(queue, "requeueRejected").mockImplementation(async (...args) => { const count = await recovery(...args); recovered = true; return count; }); vi.spyOn(queue, "queueLength").mockImplementation(async (...args) => { const count = await length(...args); if (recovered) { began.resolve(); await gate.promise; } return count; }); const root = await mount();
  try { await press(root, t("settings.requeue")); await began.promise; await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-native-joined-recovery-owner", "replacement-native-joined-recovery-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-joined-recovery-owner"); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it.each(["accepted", "failed"] as const)("keeps a retired native export %s receipt out of the replacement account", async outcome => {
  const gate = deferred<Awaited<ReturnType<typeof api.exportAccountTicket>>>(); vi.spyOn(api, "exportAccountTicket").mockReturnValue(gate.promise); const download = vi.spyOn(platform, "requestAccountDownload").mockReturnValue(true), root = await mount();
  await press(root, t("settings.export")); await flush(); expect(isDisabled(root, t("settings.export"))).toBe(true); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-native-export-owner", "replacement-native-export-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-export-owner");
  await act(async () => { outcome === "accepted" ? gate.resolve({ ticket: "obsolete-native-export-ticket", expires_in: 60 }) : gate.reject(new ApiError(503, "Original native export unavailable")); }); await flush(); expect(download).not.toHaveBeenCalled(); expect(publicSurface(root.toJSON())).toBe(before);
});

it.each(["accepted", "failed"] as const)("keeps a retired native access page %s receipt out of replacement settings", async outcome => {
  vi.mocked(api.accessLogPage).mockResolvedValueOnce({ rows: [row("Already verified native history")], nextCursor: "held-native-page" }); const root = await mount(), gate = deferred<Awaited<ReturnType<typeof api.accessLogPage>>>(); vi.mocked(api.accessLogPage).mockReturnValueOnce(gate.promise); await press(root, t("settings.showMore")); await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-native-access-owner", "replacement-native-access-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-access-owner");
  await act(async () => { outcome === "accepted" ? gate.resolve({ rows: [row("Old private native access row")], nextCursor: null }) : gate.reject(new ApiError(503, "Old private native access error")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before);
});

it("keeps a retired native recovery failure and its pending controls out of replacement settings", async () => {
  vi.spyOn(queue, "rejectedEntries").mockResolvedValue([{ userId: owner, clientEntryId: "held-native-recovery", blobB64: "retained ciphertext", entryDate: "2026-10-05" }]); const gate = deferred<number>(); vi.spyOn(queue, "requeueRejected").mockReturnValue(gate.promise);
  const root = await mount(); await press(root, t("settings.requeue")); await flush(); expect(isDisabled(root, t("settings.requeue"))).toBe(true); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-native-recovery-error-owner", "replacement-native-recovery-error-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-recovery-error-owner");
  await act(async () => { gate.reject(new StorageCommitError("Original recovered writing was not committed")); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before);
});

it.each(["llm", "voice", "delete"] as const)("keeps native HTTP refusal guidance scoped to the requested %s action", async kind => {
  const code = kind === "llm" ? "stt_unavailable" : kind === "voice" ? "llm_unavailable" : "stt_unavailable", fetch = stubFetch(() => jsonResponse({ detail: "Native processing service refused this request", code }, { status: 422 })), root = await mount();
  if (kind === "delete") { await typeInto(root, t("settings.deleteConfirmLabel"), "DELETE"); await press(root, t("settings.deleteButton")); } else await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff"));
  await confirm(root); expect(fetch).toHaveBeenCalledTimes(1); expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmToggleFailed" : kind === "voice" ? "settings.voiceToggleFailed" : "settings.deleteFailed")); expect(vault.ownerUserId()).toBe(owner);
});

it.each(["llm", "voice"] as const)("keeps a native HTTP410 %s refusal from claiming an account erasure", async kind => {
  const fetch = stubFetch(() => jsonResponse({ detail: "The processing receipt has expired", code: "processing_receipt_expired" }, { status: 410 })), lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); await pressSwitch(root, t(kind === "llm" ? "settings.llmStatusOff" : "settings.voiceStatusOff")); await confirm(root); expect(fetch).toHaveBeenCalledTimes(1); expect(lockdown).not.toHaveBeenCalled(); expect(textOf(root)).toContain(t(kind === "llm" ? "settings.llmToggleFailed" : "settings.voiceToggleFailed")); expect(vault.ownerUserId()).toBe(owner);
});

it.each(["llm accepted", "voice accepted", "llm failed", "voice failed"] as const)("refuses old native sensitive commit publication after retirement: %s", async boundary => {
  const gate = deferred<LlmConsentState | VoiceConsentState>(), llmAction = boundary.startsWith("llm"); if (llmAction) vi.spyOn(api, "setLlmConsent").mockReturnValue(gate.promise as Promise<LlmConsentState>); else vi.spyOn(api, "setVoiceConsent").mockReturnValue(gate.promise as Promise<VoiceConsentState>); const root = await mount(); await pressSwitch(root, t(llmAction ? "settings.llmStatusOff" : "settings.voiceStatusOff")); await confirm(root); clearSession(); installSession("replacement-native-sensitive-owner", "replacement-native-sensitive-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-sensitive-owner");
  await act(async () => { boundary.endsWith("accepted") ? gate.resolve(llmAction ? llm(true) : voice(true)) : gate.reject(new ApiError(503, "Retired native consent failure")); }); await flush(); expect(textOf(root)).not.toContain(t(llmAction ? "settings.llmEnabledNote" : "settings.voiceEnabledNote")); expect(textOf(root)).not.toContain(t(llmAction ? "settings.llmToggleFailed" : "settings.voiceToggleFailed")); expect(root.root.findAllByType("button").find(button => button.props.role === "switch" && String(button.props["aria-label"] ?? "").includes(t(llmAction ? "settings.llmStatusOff" : "settings.voiceStatusOff")))?.props["aria-checked"]).toBe(false);
});

it.each(["v2 read", "v1 sweep"] as const)("keeps old native policy loading after a retired durable hint %s receipt", async boundary => {
  const hintKey = `mindpattern.rekeyHint.${owner}`; await kv.setItem(hintKey, "1"); vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: boundary === "v2 read" ? "v2" : "v1", salt: "", kdf_params: null, wrapped_data_key: null });
  const gate = deferred<void>(), began = deferred<void>(), actualRead = kv.getItem.bind(kv), actualRemove = kv.removeItem.bind(kv); let paused = false;
  if (boundary === "v2 read") vi.spyOn(kv, "getItem").mockImplementation(async (...args) => { const value = await actualRead(...args); if (!paused && args[0] === hintKey) { paused = true; began.resolve(); await gate.promise; } return value; });
  else vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { await actualRemove(...args); if (!paused && args[0] === hintKey) { paused = true; began.resolve(); await gate.promise; } });
  const root = await render(<SettingsView onLockdown={() => {}} />);
  try { await began.promise; await flush(); const before = publicSurface(root.toJSON()); clearSession(); installSession("replacement-native-hint-owner", "replacement-native-hint-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-hint-owner"); await act(async () => { gate.resolve(); }); await flush(); expect(publicSurface(root.toJSON())).toBe(before); }
  finally { await act(async () => { gate.resolve(); }); await flush(); }
});

it("continues the live v1 policy load after actually sweeping its durable stale rekey hint", async () => {
  await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1"); const root = await mount(); expect(await kv.getItem(`mindpattern.rekeyHint.${owner}`)).toBeNull(); expect(textOf(root)).toContain(t("settings.llmStatusOff")); expect(textOf(root)).toContain(t("settings.voiceStatusOff")); expect(textOf(root)).not.toContain(t("common.loading"));
});

it("removes the v2-only hint controls when a native public Retry establishes the older v1 endpoint", async () => {
  await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1"); vi.mocked(api.meta).mockRejectedValueOnce(new ApiError(503, "First current metadata unavailable")); vi.mocked(api.keyEnvelope).mockResolvedValueOnce({ key_scheme: "v2", salt: "", kdf_params: null, wrapped_data_key: null }).mockRejectedValue(new ApiError(404, "Backend key envelope endpoint unavailable")); const root = await mount(); expect(textOf(root)).toContain(t("settings.rekeyHintNote")); await press(root, t("settings.llmRetry")); await flush(); expect(textOf(root)).toContain(t("settings.upgradeTitle")); expect(textOf(root)).not.toContain(t("settings.rekeyHintNote")); expect(root.root.findAllByType("button").some(button => textOfNode(button) === t("settings.rekeyHintButton") || textOfNode(button) === t("settings.rekeyHintDismiss"))).toBe(false);
});

it("gives localized guidance for an unclassified native one-time export refusal", async () => {
  vi.spyOn(api, "exportAccountTicket").mockRejectedValue(new ApiError(422, "Unclassified Native export refusal", "export_validation_failed")); const root = await mount(); await press(root, t("settings.export")); await flush(); expect(textOf(root)).toContain(t("settings.exportFailed")); expect(textOf(root)).not.toContain("Unclassified Native");
});

it("preserves encrypted recoverable writing when the actual native WebLock rejects without an error detail", async () => {
  vi.spyOn(queue, "rejectedEntries").mockResolvedValue([{ userId: owner, clientEntryId: "native-recoverable-writing", blobB64: "retained-original-ciphertext", entryDate: "2026-10-05" }]); const root = await mount(); const lock = navigator.locks; expect(lock).toBeDefined(); vi.spyOn(lock, "request").mockRejectedValueOnce(new DOMException("", "UnknownError")); await press(root, t("settings.requeue")); await flush(); expect(textOf(root)).toContain(t("errors.generic")); expect(textOf(root)).toContain(t("settings.rejectedOne", { count: 1 })); expect(isDisabled(root, t("settings.requeue"))).toBe(false);
});

it("never transmits an old account's deletion proof after its accepted native erasure staging retires the account", async () => {
  const real = kv.setItem.bind(kv); let retired = false;
  vi.spyOn(kv, "setItem").mockImplementation(async (...args) => { await real(...args); if (!retired && args[0] === `mindpattern.erase.${owner}`) { retired = true; clearSession(); setSession("replacement-native-delete-token", "replacement-native-delete-owner", "replacement-native-delete-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-delete-owner"); } });
  const fetch = stubFetch(() => jsonResponse({ detail: "Old proof does not authorize this account", code: "step_up_required" }, { status: 403 })), root = await mount(); await typeInto(root, t("settings.deleteConfirmLabel"), "DELETE"); await press(root, t("settings.deleteButton")); await confirm(root);
  expect(retired).toBe(true); expect(fetch).not.toHaveBeenCalled(); expect(await pendingLocalErasures()).toMatchObject([{ owner, remoteConfirmed: false }]); expect(vault.ownerUserId()).toBe("replacement-native-delete-owner");
});

it.each(["accepted", "failed"] as const)("does not lock a replacement account when the old native local erasure finally %s", async outcome => {
  vi.spyOn(api, "deleteAccount").mockResolvedValue(null); const lockdown = vi.fn(), realRemove = kv.removeItem.bind(kv), realMark = kv.markOwnerErased.bind(kv); let retired = false;
  const retire = () => { retired = true; clearSession(); installSession("replacement-native-erasure-owner", "replacement-native-erasure-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-erasure-owner"); };
  if (outcome === "accepted") vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { await realRemove(...args); if (args[0] === `mindpattern.erase.${owner}`) retire(); });
  else vi.spyOn(kv, "markOwnerErased").mockImplementationOnce(async (...args) => { const result = await realMark(...args); retire(); throw new StorageCommitError("Original native erasure destination is temporarily unavailable"); return result; });
  const root = await render(<SettingsView onLockdown={lockdown} />); await flush(); await typeInto(root, t("settings.deleteConfirmLabel"), "DELETE"); await press(root, t("settings.deleteButton")); await confirm(root);
  expect(retired).toBe(true); expect(api.deleteAccount).toHaveBeenCalledExactlyOnceWith("sensitive-proof"); expect(lockdown).not.toHaveBeenCalled(); expect(vault.ownerUserId()).toBe("replacement-native-erasure-owner"); expect(vault.get().dataKey).toEqual(new Uint8Array(32).fill(75));
});

it("does not hold a new account's native queue read behind retired recovery inventory", async () => {
  const records = new Map<string,string>(); setKvBackendForTests({ getItem: async slot => records.get(slot) ?? null, setItem: async (slot,value) => { records.set(slot,value); }, removeItem: async slot => { records.delete(slot); }, keys: async () => [...records.keys()] });
  await queue.enqueue({ userId: owner, clientEntryId: "native-recovery-transfer", blobB64: "actual retained recovery ciphertext", entryDate: "2026-10-05" });
  const itemSlot = [...records.keys()].find(slot => slot.startsWith("mindpattern/queue.v1.items."))!, rejectedSlot = itemSlot.replace(".items.", ".rejected."); await kv.setItem(rejectedSlot, records.get(itemSlot)!); await kv.removeItem(itemSlot);
  const root = await mount(), nativeRecovery = queue.requeueRejected, gate = deferred<void>(), began = deferred<void>(), nativeGate = deferred<void>(), read = kv.getItem.bind(kv); let retired = false, oldReads = 0;
  vi.spyOn(queue,"requeueRejected").mockImplementationOnce(async (...args) => { const moved = await nativeRecovery(...args); began.resolve(); await gate.promise; return moved; });
  vi.spyOn(kv,"getItem").mockImplementation(async (...args) => { const value = await read(...args); if (retired && args[0] === itemSlot) { oldReads += 1; await nativeGate.promise; } return value; });
  try { await press(root,t("settings.requeue")); await began.promise; clearSession(); installSession("replacement-native-recovery-reader", "replacement-native-recovery-reader-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-recovery-reader"); retired = true; await act(async () => { gate.resolve(); }); await flush(); expect(oldReads).toBe(0);
    let timer!: ReturnType<typeof setTimeout>; const readable = await Promise.race([queue.queueLength("replacement-native-recovery-reader").then(count => count === 0), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), 120); })]); clearTimeout(timer); expect(readable).toBe(true);
  } finally { await act(async () => { gate.resolve(); nativeGate.resolve(); }); await flush(); }
});
