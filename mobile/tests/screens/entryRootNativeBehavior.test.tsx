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

it("an accepted Native journal save emits enabled tactile feedback", async () => {
  const deviceOS = Object.getOwnPropertyDescriptor(Platform, "OS")!;
  Object.defineProperty(Platform, "OS", { value: "android", configurable: true });
  releases.push(() => Object.defineProperty(Platform, "OS", deviceOS));
  await setHapticsEnabled(true); await mount(); await type(ORIGINAL);
  vi.mocked(Vibration.vibrate).mockClear();
  await press("Save entry"); await flush();
  await vi.waitFor(() => expect(words()).toContain(tr("entry.saved")));
  await vi.waitFor(() => expect(vi.mocked(Vibration.vibrate).mock.calls).toContainEqual([10]));
  const receipt = [...stored.values()][0]!;
  expect(decryptEntry({ dataKey: KEY }, USER, receipt.client_entry_id, receipt.blob, 1).text).toBe(ORIGINAL);
  assertPublicSurface(publicSurface(root!), 0);
});

it("the current Native support dialog opens the installed Safety Plan route from its displayed choice", async () => {
  await mount(); await type("I want to kill myself"); await press("Save entry"); await flush();
  await vi.waitFor(() => expect(vi.mocked(Alert.alert).mock.calls.some(c => c[0] === tr("entry.crisisAlertTitle"))).toBe(true));
  const dialog = vi.mocked(Alert.alert).mock.calls.find(c => c[0] === tr("entry.crisisAlertTitle"))!;
  expect(dialog[2]?.map(b => b.text)).toEqual([tr("entry.crisisViewResources"), tr("common.makeSafetyPlan"), tr("common.notNow")]);
  const choice = dialog[2]!.find(b => b.text === tr("common.makeSafetyPlan"))!;
  await act(async () => choice.onPress?.());
  expect(nativeRoute.routes[nativeRoute.index]!.name).toBe("SafetyPlan");
  assertPublicSurface(publicSurface(root!), 0);
});

for (const nativeStatus of [401, 422]) {
  it(`a noncrisis Native ${nativeStatus} refusal keeps its displayed OK choice free of a support modal`, async () => {
    status = nativeStatus; await mount(); await type(ORIGINAL); await press("Save entry"); await flush();
    const title = tr(nativeStatus === 401 ? "common.sessionExpiredTitle" : "entry.notAcceptedTitle");
    await vi.waitFor(() => expect(vi.mocked(Alert.alert).mock.calls.some(c => c[0] === title)).toBe(true));
    const dialog = vi.mocked(Alert.alert).mock.calls.find(c => c[0] === title)!;
    await act(async () => dialog[2]!.find(b => b.text === tr("common.ok"))!.onPress?.()); await flush();
    expect(vi.mocked(Alert.alert).mock.calls.some(c => c[0] === tr("entry.crisisAlertTitle"))).toBe(false);
  });
}

it("a noncrisis Native audio persistence refusal leaves its displayed OK choice free of a support modal", async () => {
  await mount(); await recordVoice();
  const write = storage.setItem.bind(storage);
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key.startsWith(ACCOUNT_STORAGE_PREFIX.audioQueue)) throw new Error("The Native recording disk is unavailable");
    return write(key, value);
  });
  await press("Save entry"); await flush();
  await vi.waitFor(() => expect(vi.mocked(Alert.alert).mock.calls.some(c => c[0] === tr("entry.couldNotSaveTitle"))).toBe(true));
  const dialog = vi.mocked(Alert.alert).mock.calls.find(c => c[0] === tr("entry.couldNotSaveTitle"))!;
  await act(async () => dialog[2]!.find(b => b.text === tr("common.ok"))!.onPress?.()); await flush();
  expect(vi.mocked(Alert.alert).mock.calls.some(c => c[0] === tr("entry.crisisAlertTitle"))).toBe(false);
  expect(editor().props.value).toBe(SPOKEN);
});

it("retrying one physically retained Native take preserves its original parent identity and leaves no orphan recording", async () => {
  await mount(); const uri = await recordVoice(); status = 422;
  await press("Save entry"); await flush();
  await vi.waitFor(async () => expect((await listSavedAudio(USER)).length).toBe(1));
  const originalParent = (await listSavedAudio(USER))[0]!.id;
  expect(files.__hasFile(uri)).toBe(true); status = 200;
  await press("Save entry"); await flush();
  await vi.waitFor(() => expect(words()).toContain(tr("entry.saved")));
  expect([...stored.values()][0]!.client_entry_id).toBe(originalParent);
  const journal = [...stored.values()][0]!;
  expect(decryptEntry({ dataKey: KEY }, USER, originalParent, journal.blob, 1)).toMatchObject({ text: SPOKEN, input_mode: "voice", transcript_lang: "es", english_text: ENGLISH });
  await vi.waitFor(async () => expect(await audioQueueStatus(USER)).toEqual({ total: 0, needsAttention: 0 }));
  expect(decryptAudio({ dataKey: KEY }, USER, originalParent, attachments.get(originalParent)!.blob)).toEqual(SENSOR_BYTES);
  expect(files.__hasFile(uri)).toBe(false);
  assertPublicSurface(publicSurface(root!), 0);
});

for (const outcome of ["saved", "discarded"] as const) {
  it(`a ${outcome} Native take completes its queued recorder cleanup before a replacement recording begins`, async () => {
    await mount(); await recordVoice();
    const nativeStopReceipt = hold();
    recorderControls.stop.mockImplementation(async () => { fakeRecorderStatus.isRecording = false; await nativeStopReceipt.run(); });
    if (outcome === "saved") {
      await press("Save entry"); await flush();
      await vi.waitFor(() => expect(words()).toContain(tr("entry.saved")));
    } else {
      await press(tr("entry.voiceDiscardTake")); await flush();
      expect(words()).not.toContain(tr("entry.voiceReviewTitle"));
    }
    await press("Record instead"); await flush();
    if (outcome === "discarded") {
      const dialog = vi.mocked(Alert.alert).mock.calls.find(c => c[0] === tr("entry.voiceReplaceTitle"))!;
      await act(async () => dialog[2]!.find(b => b.text === tr("entry.voiceReplaceConfirm"))!.onPress?.());
    }
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 40)); });
    expect(words()).not.toContain(tr("entry.micRecording"));
    nativeStopReceipt.release();
    await flush();
    await vi.waitFor(() => expect(words()).toContain(tr("entry.micRecording")));
    assertPublicSurface(publicSurface(root!), 0);
  });
}
