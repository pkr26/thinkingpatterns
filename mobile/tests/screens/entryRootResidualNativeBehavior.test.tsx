/** Public editor outcomes with real HTTP, encrypted drafts, mood receipts
 * and offline custody. No encrypted payload or storage helper is mocked. */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { Alert, Keyboard, Text, TextInput, TouchableOpacity } from "react-native";
import { api,getBaseUrl,setBaseUrl } from "../../src/api/client";
import { EntryScreen } from "../../src/screens/EntryScreen";
import { ThemeProvider } from "../../src/theme";
import { vault } from "../../src/vault";
import { decryptEntry, decryptAudio } from "../../src/crypto/journalCrypto";
import {encrypt,buildAad} from "../../src/crypto/envelope";
import { abortInFlightAudioFlush,flushAudioQueue } from "../../src/audioQueue";
import { fakeRecorderStatus,__resetAudioMock,AudioModule,recorderControls } from "../helpers/expoAudioMock";
import { journalDraftScope, loadJournalDraft, saveJournalDraft, newJournalDraft, __resetJournalDraftRuntimeForTests, waitJournalDraftWrites } from "../../src/journalDraft";
import { queueLength, abortInFlightFlush } from "../../src/offlineQueue";
import { accountStorageKey, ACCOUNT_STORAGE_PREFIX } from "../../src/accountStorage";
import { recentMoods, localDateISO } from "../../src/moodLog";
import { installLocalDataKey, __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { secureStore, setSecureStoreBackend } from "../../src/secureStore";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
import * as files from "../helpers/expoFsMock";
import { setLocale, t as tr } from "../../src/strings";
import { emitAppState } from "../helpers/rnMock";
import {takeStashedDraft,stashDraft} from "../../src/store";
import {publicSurface} from "../helpers/publicSurface";
import {assertPublicSurface} from "../helpers/publicSurfaceOracle";
import {installedNativeKeyboard} from "../helpers/nativeKeyboard";
import {nativeGrantedPress} from "../helpers/nativePressability";
import { StackRouter, CommonActions } from "@react-navigation/routers";
import { Platform, Vibration } from "react-native";
import { audioQueueStatus, listSavedAudio } from "../../src/audioQueue";
import { setHapticsEnabled } from "../../src/haptics";
import { installedNativeTiming } from "../helpers/nativeTiming";
const router = StackRouter({ initialRouteName: "Entry" });
const routeOptions = { routeNames: ["Entry", "SafetyPlan", "Crisis"], routeParamList: {}, routeGetIdList: {} };
let nativeRoute = router.getInitialState(routeOptions);
const USER = "a".repeat(32), KEY = Buffer.alloc(32, 41), ORIGINAL = "My native encrypted journal words";
const session = { activeDays: 3, activeDaysKnown: true, activeDaysLoading: false, unlockDays: 30, touchActivity: () => {}, refreshActiveDays: async () => {} };
vi.mock("../../src/store", async original => ({ ...await original<typeof import("../../src/store")>(), useSession: () => session }));
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let entryDispatchBoundary:(()=>Promise<void>)|undefined,requireAudioParent:boolean;
let status: number, boundary: (() => Promise<void>) | undefined;
let transcriptionBoundary:(()=>Promise<void>)|undefined,transcriptionLanguage:string|null,transcriptionEnglish:string|null,transcriptionOriginal:string;
let stored: Map<string, Record<string, any>>, submitted: Record<string, any> | undefined;
let attachments:Map<string,Record<string,any>>,audioStatus:number,translationStatus:number,transcribedBytes:string|undefined,transcribeCode:string|undefined;
const SPOKEN="Mis palabras habladas siguen siendo mías",ENGLISH="My spoken words are still mine",SENSOR_BYTES=Buffer.from("Native microphone encoded AAC bytes");
const releases: Array<() => void> = [];
const physicalDraftRead=storage.getItem.bind(storage),physicalFileDelete=files.deleteAsync.getMockImplementation()!;
const deliverNativeReadReceipt = setImmediate;
const flush = async () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
function words() { const flat = (v: unknown): string => Array.isArray(v) ? v.map(flat).join("") : typeof v === "string" || typeof v === "number" ? String(v) : ""; return root!.root.findAllByType(Text).map(node => flat(node.props.children)).join(" "); }
function editor() { return root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Journal entry")!; }
async function type(value: string) { await act(async () => editor().props.onChangeText(value)); }
async function press(label: string, wait = true) { const node = root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === label); expect(node, label).toBeDefined(); await act(async () => { const result = node!.props.onPress(); if (wait) await result; }); }
async function mount() { await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><EntryScreen navigation={{ navigate: name => { nativeRoute = router.getStateForAction(nativeRoute, CommonActions.navigate(name), routeOptions)!; }, addListener: () => () => {} }}/></ThemeProvider>); }); await flush(); await vi.waitFor(() => expect(words()).not.toContain("Loading device draft")); }
function hold() { let entered = false, release!: () => void; const wait = new Promise<void>(resolve => { release = resolve; }); releases.push(release); return { run: async () => { entered = true; await wait; }, entered: () => entered, release }; }
async function queued() { const receipts = await Promise.all((await storage.getAllKeys()).filter(key => key.startsWith(`${ACCOUNT_STORAGE_PREFIX.queue}.items.`)).map(async key => JSON.parse((await storage.getItem(key))!))); return receipts.flatMap(receipt => receipt.items); }
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks();files.deleteAsync.mockImplementation(physicalFileDelete); setLocale("en"); storage.__reset(); files.__resetFiles(); __resetAudioMock(); keychain.__reset(); runTestControl(setSecureStoreBackend, null); runTestControl(__resetJournalDraftRuntimeForTests); runTestControl(__resetLocalKeyLifecycleForTests); abortInFlightFlush();abortInFlightAudioFlush(); vault.lock();
  await api.setSession("native entry bearer", USER, "alice"); vault.unlock({ masterKey: Buffer.alloc(32, 42), authKey: Buffer.alloc(32, 43), dataKey: Buffer.from(KEY) }, USER); installLocalDataKey(USER, vault.get().dataKey);
  nativeRoute = router.getInitialState(routeOptions); status = 200; boundary = undefined;entryDispatchBoundary=undefined;requireAudioParent=false;transcriptionBoundary=undefined;transcriptionLanguage="es";transcriptionEnglish=ENGLISH;transcriptionOriginal=SPOKEN; stored = new Map(); submitted = undefined;attachments=new Map();audioStatus=200;translationStatus=200;transcribedBytes=undefined;transcribeCode=undefined; vi.mocked(Alert.alert).mockClear();
  takeStashedDraft(USER);
  // A Native storage read returns through its asynchronous bridge receipt.
  // Completed reads release their resources; there is no lifetime read cap.
  storage.getItem=async slot=>{if(slot.startsWith(ACCOUNT_STORAGE_PREFIX.journalDraft))await new Promise<void>(resolve=>deliverNativeReadReceipt(resolve));return physicalDraftRead(slot);};
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname, method = init.method ?? "GET";
    if(path.endsWith("/audio/transcriptions")||path.endsWith("/audio/translations")||path.endsWith("/audio/attachments")){
      const body=JSON.parse(String(init.body));let value:unknown={},nativeStatus=200;
      if(path.endsWith("/audio/transcriptions")){transcribedBytes=body.audio_b64;nativeStatus=transcribeCode?400:200;value=transcribeCode?{code:transcribeCode,detail:"The Native transcription provider refused this take"}:{language:transcriptionLanguage,language_raw:"Spanish as reported by the provider",original_text:transcriptionOriginal,english_text:transcriptionEnglish};}
      else if(path.endsWith("/audio/translations")){nativeStatus=translationStatus;value=nativeStatus===200?{english_text:"An independently translated edit"}:{code:"stt_upstream",detail:"The Native translation provider is temporarily unavailable"};}
      else{nativeStatus=requireAudioParent&&!stored.has(body.client_entry_id)?404:audioStatus;if(nativeStatus===200)attachments.set(body.client_entry_id,body);value=nativeStatus===200?{stored:true}:nativeStatus===404?{code:"unknown_entry",detail:"no entry with that client_entry_id"}:{code:"service_unavailable",detail:"The Native attachment store is temporarily unavailable"};}
      const response=new Response(JSON.stringify(value),{status:nativeStatus});Object.defineProperty(response,"url",{value:url});if(path.endsWith("/audio/transcriptions")){const json=response.json.bind(response);response.json=async()=>{const result=await json();await transcriptionBoundary?.();return result;};}return response;
    }
    if(path.endsWith("/meta")||path.endsWith("/insights")){const value=path.endsWith("/meta")?{unlock_days:30}:{phase:"baseline",active_days:3,days_remaining:27};const response=new Response(JSON.stringify(value));Object.defineProperty(response,"url",{value:url});return response;}
    if (!path.endsWith("/entries") || method !== "POST") throw new Error("Unexpected Native entry route " + path);
    await entryDispatchBoundary?.();submitted = JSON.parse(String(init.body)); const admitted = submitted!;
    if (status === 200) stored.set(admitted.client_entry_id, admitted);
    const response = new Response(JSON.stringify(status === 200 ? { id: "server-native-entry", ...admitted } : { error: { code: status === 422 ? "validation_error" : "server_error", message: "Native server refusal" } }), { status }); Object.defineProperty(response, "url", { value: url });
    const json = response.json.bind(response); response.json = async () => { const result = await json(); await boundary?.(); return result; }; return response;
  });
});
afterEach(async () => { vi.useRealTimers(); for (const release of releases.splice(0)) release(); await flush(); if (root) { await act(async () => root!.unmount()); root = undefined; } await waitJournalDraftWrites(); vi.restoreAllMocks(); storage.getItem=physicalDraftRead; vault.lock(); await api.clearSession(); vi.unstubAllGlobals(); vi.useRealTimers(); });

// These are exported EntryScreen + real installed API/vault/crypto/Native
// module contracts. The static session metadata is not an end-to-end Root
// account-publication producer; no such production regression is claimed.
async function recordVoice() {
  await press("Record instead"); await flush();
  await vi.waitFor(() => expect(words()).toContain("Recording…"));
  const uri = files.cacheDirectory + "root-native-entry-take.m4a";
  fakeRecorderStatus.url = uri; fakeRecorderStatus.durationMillis = 4000;
  files.__seedFile(uri, SENSOR_BYTES.toString("base64"));
  await press("Stop recording"); await flush();
  await vi.waitFor(() => expect(editor().props.value).toBe(SPOKEN));
  return uri;
}

it.each([200, 401])("a Native %s save while device draft initialization is pending has the correct public result", async nativeStatus => {
  const receipt = hold(), read = secureStore.getItem.bind(secureStore); let first = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const value = await read(slot); if (first && slot === "@mindpattern/user_id") { first = false; await receipt.run(); } return value; });
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><EntryScreen navigation={{ navigate: () => {}, addListener: () => () => {} }} /></ThemeProvider>); });
  await vi.waitFor(() => expect(receipt.entered()).toBe(true));
  status = nativeStatus; await type(ORIGINAL); await press("Save entry"); await flush();
  if (nativeStatus === 200) { expect(words()).toContain(tr("entry.saved")); expect(words()).not.toContain(tr("entry.deviceDraft.cleanup-error")); expect(editor().props.value).toBe(""); const row = [...stored.values()][0]!; expect(decryptEntry({ dataKey: KEY }, USER, row.client_entry_id, row.blob, 1).text).toBe(ORIGINAL); }
  else { expect(vi.mocked(Alert.alert).mock.calls.map(row => row[0])).toEqual([tr("common.sessionExpiredTitle")]); expect(vault.isUnlocked()).toBe(false); }
  receipt.release(); await flush();
});

it("restoring a physical device draft accepts a subsequently delivered initial RAM fallback without an authored conflict", async () => {
  const scope = await journalDraftScope(USER), device = { ...newJournalDraft(), revision: 1, text: "The actual device draft" }, ram = { ...newJournalDraft(), revision: 1, text: "The interrupted RAM draft" };
  await saveJournalDraft(KEY, scope, device);
  const deviceReceipt = hold(), ramIdentity = hold(), read = secureStore.getItem.bind(secureStore), storedRead = storage.getItem.bind(storage); let uid = 0, deviceRead = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === "@mindpattern/user_id" && ++uid === 2) await ramIdentity.run(); return value; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await storedRead(slot); if (deviceRead && slot === scope.slot) { deviceRead = false; await deviceReceipt.run(); } return value; });
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><EntryScreen navigation={{ navigate: () => {}, addListener: () => () => {} }} /></ThemeProvider>); });
  await vi.waitFor(() => expect(deviceReceipt.entered()).toBe(true)); await vi.waitFor(() => expect(ramIdentity.entered()).toBe(true));
  await type("The temporary authored edit"); deviceReceipt.release(); await flush();
  expect(words()).toContain(tr("entry.deviceDraftConflict")); await press(tr("entry.restoreDeviceDraft"));
  stashDraft(USER, ram.text, ram, scope.origin); ramIdentity.release(); await flush();
  expect(editor().props.value).toBe(ram.text); expect(words()).not.toContain(tr("entry.ramDraftConflict"));
});

it("an acknowledged editor restored during a held Native upload disposes its pending Native backup timer", async () => {
  const scope = await journalDraftScope(USER), saved = { ...newJournalDraft(), revision: 1, text: "The acknowledged RAM and device editor" };
  await saveJournalDraft(KEY, scope, saved); stashDraft(USER, saved.text, saved, scope.origin);
  const deviceReceipt = hold(), upload = hold(), read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (first && slot === scope.slot) { first = false; await deviceReceipt.run(); } return value; });
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><EntryScreen navigation={{ navigate: () => {}, addListener: () => () => {} }} /></ThemeProvider>); });
  await vi.waitFor(() => expect(deviceReceipt.entered()).toBe(true)); await vi.waitFor(() => expect(editor().props.value).toBe(saved.text));
  boundary = upload.run; await press("Save entry", false); await vi.waitFor(() => expect(upload.entered()).toBe(true));
  const device = installedNativeTiming(); vi.stubGlobal("setTimeout", device.setTimeout); vi.stubGlobal("clearTimeout", device.clearTimeout);
  try {
    await type("A temporary edit whose device conflict is restored before the upload receipt");
    expect(device.hasActiveTimersInRange(400)).toBe(true);
    await act(async () => { deviceReceipt.release(); for (let i = 0; i < 4; i++) await new Promise<void>(setImmediate); });
    expect(words()).toContain(tr("entry.deviceDraftConflict")); await press(tr("entry.restoreDeviceDraft"));
    expect(editor().props.value).toBe(saved.text); expect(device.hasActiveTimersInRange(400)).toBe(true);
    await act(async () => { upload.release(); for (let i = 0; i < 8; i++) await new Promise<void>(setImmediate); });
    expect(editor().props.value).toBe(""); expect(words()).toContain(tr("entry.saved"));
    expect(device.hasActiveTimersInRange(400)).toBe(false);
    const row = [...stored.values()][0]!; expect(decryptEntry({ dataKey: KEY }, USER, row.client_entry_id, row.blob, 1).text).toBe(saved.text);
    expect(await loadJournalDraft(KEY, scope)).toBeNull();
  } finally { deviceReceipt.release(); upload.release(); vi.unstubAllGlobals(); }
});

it("restoring the device editor clears the RAM marker before a newer authenticated same-text hydration arrives", async () => {
  const scope = await journalDraftScope(USER), device = { ...newJournalDraft(), revision: 1, text: "The original physical device text" };
  await saveJournalDraft(KEY, scope, device);
  const restore = hold(), read = secureStore.getItem.bind(secureStore); let accounts = 0;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === "@mindpattern/user_id" && ++accounts === 2) await restore.run(); return value; });
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><EntryScreen navigation={{ navigate: () => {}, addListener: () => () => {} }} /></ThemeProvider>); });
  await vi.waitFor(() => expect(restore.entered()).toBe(true)); await vi.waitFor(() => expect(editor().props.value).toBe(device.text));
  const failure = hold(), write = storage.setItem.bind(storage); let refuse = true;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === scope.slot && refuse) { await failure.run(); throw new Error("The admitted Native draft write failed"); } return write(slot, value); });
  await type("The temporary authored editor"); await act(async () => emitAppState("background")); await vi.waitFor(() => expect(failure.entered()).toBe(true));
  const ram = { ...newJournalDraft(), revision: 1, text: "The explicitly chosen RAM editor" }; stashDraft(USER, ram.text, ram, scope.origin);
  restore.release(); await flush(); expect(words()).toContain(tr("entry.ramDraftConflict")); await press(tr("entry.restoreRamDraft"));
  expect(words()).toContain(tr("entry.deviceDraftConflict")); failure.release(); await waitJournalDraftWrites(); await flush();
  expect(words()).toContain(tr("entry.deviceDraft.error")); refuse = false;
  const priorWire = (await storage.getItem(scope.slot))!, newer = { ...device, revision: 2, mood: .5 };
  expect(await saveJournalDraft(KEY, scope, newer, priorWire)).toBe("saved");
  const latest = hold(), storedRead = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await storedRead(slot); if (first && slot === scope.slot) { first = false; await latest.run(); } return value; });
  await press(tr("entry.retryDeviceDraft")); await vi.waitFor(() => expect(latest.entered()).toBe(true));
  await press(tr("entry.restoreDeviceDraft")); expect(editor().props.value).toBe(device.text);
  latest.release(); await act(async () => { for (let i = 0; i < 6; i++) await new Promise<void>(setImmediate); });
  expect(words()).not.toContain(tr("entry.deviceDraftConflict")); expect(editor().props.value).toBe(device.text);
  await press("Add details (optional)"); expect(buttonState("Mood: Good").selected).toBe(true);
  expect((await loadJournalDraft(KEY, scope))!.draft).toEqual(newer);
});
function buttonState(label: string) { return root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label)!.props.accessibilityState; }

it("a granted module Save admitted during a locked interval can finish after the same account is genuinely unlocked", async () => {
  await mount(); await type(ORIGINAL);
  const receipt = hold(), read = secureStore.getItem.bind(secureStore); let first = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    if (first && slot === "@mindpattern/user_id") { first = false; await receipt.run(); }
    return value;
  });
  const currentButton = () => root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Save entry")!.props;
  const native = nativeGrantedPress(currentButton());
  try {
    // Exported Scene/module integration: the caller retains this mounted
    // Scene across the genuine vault interval. No Root/Login stack producer
    // or Native callback preemption of a JS continuation is claimed.
    await act(async () => { vault.lock(); native.configure(currentButton()); native.release(); });
    await vi.waitFor(() => expect(receipt.entered()).toBe(true));
    await act(async () => {
      vault.unlock({ masterKey: Buffer.alloc(32, 42), authKey: Buffer.alloc(32, 43), dataKey: Buffer.from(KEY) }, USER);
      installLocalDataKey(USER, vault.get().dataKey);
      receipt.release();
    });
    await vi.waitFor(() => expect(words()).toContain(tr("entry.saved")));
    expect(editor().props.value).toBe("");
    const row = [...stored.values()][0]!;
    expect(decryptEntry({ dataKey: KEY }, USER, row.client_entry_id, row.blob, 1).text).toBe(ORIGINAL);
  } finally { native.dispose(); receipt.release(); }
});

it("a mounted module Scene retains its editor when its vault owner changes before an old account upload receipt", async () => {
  await mount(); await type(ORIGINAL);
  const upload = hold(); boundary = upload.run;
  await press("Save entry", false);
  await vi.waitFor(() => expect(upload.entered()).toBe(true));
  const otherOwner = "b".repeat(32), otherKey = Buffer.alloc(32, 83);
  // The exported vault and key registry may be adopted independently by
  // this Scene's caller. This is a module owner-domain integration, not a
  // claim that Root/Login can publish mismatched credentials and vault.
  await act(async () => {
    vault.unlock({ masterKey: Buffer.alloc(32, 81), authKey: Buffer.alloc(32, 82), dataKey: otherKey }, otherOwner);
    installLocalDataKey(otherOwner, vault.get().dataKey);
    upload.release();
  });
  await vi.waitFor(() => expect(root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Save entry")!.props.disabled).toBe(false));
  expect(editor().props.value).toBe(ORIGINAL);
  expect(words()).not.toContain(tr("entry.saved"));
  expect(vault.ownerUserId()).toBe(otherOwner);
  const row = [...stored.values()][0]!;
  expect(decryptEntry({ dataKey: KEY }, USER, row.client_entry_id, row.blob, 1).text).toBe(ORIGINAL);
});

it("a failed disposed Save hands newer Native typing to the exported text-only RAM bridge", async () => {
  await mount(); await type(ORIGINAL);
  const upload = hold(); boundary = upload.run; status = 500;
  await press("Save entry", false); await vi.waitFor(() => expect(upload.entered()).toBe(true));
  const newer = "Newer words typed while the old upload awaits its Native receipt";
  await type(newer);
  await act(async () => { root!.unmount(); root = undefined; });
  await act(async () => { upload.release(); for (let i = 0; i < 8; i++) await new Promise<void>(setImmediate); });
  // This exported return is consumed by Entry's real focus bridge without
  // the complete journal record. It observes the module's handoff itself;
  // no private ref, synthetic Root transition or frozen callback is used.
  expect(takeStashedDraft(USER)).toBe(newer);
});
