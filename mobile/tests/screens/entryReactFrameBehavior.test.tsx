/** Public editor outcomes with real HTTP, encrypted drafts, mood receipts
 * and offline custody. No encrypted payload or storage helper is mocked. */
import React from "react";
import {act} from "react";
import {nativeFrameRenderer as ReactTestRenderer,nativeFrameScheduler} from "../helpers/nativeReactFrames";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { Alert, AppState, Keyboard, Text, TextInput, TouchableOpacity } from "react-native";
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
import {nativeInputChange,useNativeNavigationEvents} from "../helpers/nativeEntryEvents";
import {installedNativeTiming} from "../helpers/nativeTiming";
import {installedNativeAppState} from "../helpers/nativeAppState";
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
const physicalDraftRead=storage.getItem.bind(storage),physicalFileDelete=files.deleteAsync.getMockImplementation()!,physicalAppStateSubscribe=vi.mocked(AppState.addEventListener).getMockImplementation()!;
const deliverNativeReadReceipt = setImmediate;
const flush = async () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
function words() { const flat = (v: unknown): string => Array.isArray(v) ? v.map(flat).join("") : typeof v === "string" || typeof v === "number" ? String(v) : ""; return root!.root.findAllByType(Text).map(node => flat(node.props.children)).join(" "); }
function editor() { return root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Journal entry")!; }
async function type(value: string) { await act(async () => editor().props.onChangeText(value)); }
async function press(label: string, wait = true) { const node = root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === label); expect(node, label).toBeDefined(); await act(async () => { const result = node!.props.onPress(); if (wait) await result; }); }
async function mount() { await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><EntryScreen navigation={{ navigate: () => {}, addListener: () => () => {} }}/></ThemeProvider>); }); await flush(); await vi.waitFor(() => expect(words()).not.toContain("Loading device draft")); }
function hold() { let entered = false, release!: () => void; const wait = new Promise<void>(resolve => { release = resolve; }); releases.push(release); return { run: async () => { entered = true; await wait; }, entered: () => entered, release }; }
async function queued() { const receipts = await Promise.all((await storage.getAllKeys()).filter(key => key.startsWith(`${ACCOUNT_STORAGE_PREFIX.queue}.items.`)).map(async key => JSON.parse((await storage.getItem(key))!))); return receipts.flatMap(receipt => receipt.items); }
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks();vi.mocked(AppState.addEventListener).mockImplementation(physicalAppStateSubscribe);files.deleteAsync.mockImplementation(physicalFileDelete); setLocale("en"); storage.__reset(); files.__resetFiles(); __resetAudioMock(); keychain.__reset(); runTestControl(setSecureStoreBackend, null); runTestControl(__resetJournalDraftRuntimeForTests); runTestControl(__resetLocalKeyLifecycleForTests); abortInFlightFlush();abortInFlightAudioFlush(); vault.lock();
  await api.setSession("native entry bearer", USER, "alice"); vault.unlock({ masterKey: Buffer.alloc(32, 42), authKey: Buffer.alloc(32, 43), dataKey: Buffer.from(KEY) }, USER); installLocalDataKey(USER, vault.get().dataKey);
  status = 200; boundary = undefined;entryDispatchBoundary=undefined;requireAudioParent=false;transcriptionBoundary=undefined;transcriptionLanguage="es";transcriptionEnglish=ENGLISH;transcriptionOriginal=SPOKEN; stored = new Map(); submitted = undefined;attachments=new Map();audioStatus=200;translationStatus=200;transcribedBytes=undefined;transcribeCode=undefined; vi.mocked(Alert.alert).mockClear();
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
it("a Native focus bridge after an earlier passive effect preserves the latest committed input and its encrypted backup",async()=>{
 let navigation!:ReturnType<typeof useNativeNavigationEvents>;function NativeEditor(){navigation=useNativeNavigationEvents();return <ThemeProvider><EntryScreen navigation={{navigate:()=>{},...navigation.create("entry")}}/></ThemeProvider>;}await act(async()=>{root=ReactTestRenderer.create(<NativeEditor/>);});await flush();await vi.waitFor(()=>expect(words()).not.toContain(tr("entry.deviceDraft.loading")));await flush();const schedule=nativeFrameScheduler;const first="The prior Native text has committed but its passive mirror is pending",latest="The latest Native input must survive a delayed prior passive mirror",question="The actual question bridge words";nativeInputChange(editor().props,first);for(let i=0;i<20;i++)await Promise.resolve();schedule.unstable_flushUntilNextPaint();expect(editor().props.value).toBe(first);nativeInputChange(editor().props,latest);for(let i=0;i<20;i++)await Promise.resolve();schedule.unstable_flushUntilNextPaint();expect(editor().props.value).toBe(latest);stashDraft(USER,question);navigation.emit({type:"focus",target:"entry"});for(let i=0;i<20;i++)await Promise.resolve();schedule.unstable_flushAllWithoutAsserting();await act(async()=>{});expect(editor().props.value).toBe(latest+"\n\n"+question);await act(async()=>emitAppState("background"));await waitJournalDraftWrites();expect((await loadJournalDraft(KEY,await journalDraftScope(USER)))!.draft.text).toBe(latest+"\n\n"+question);
});
