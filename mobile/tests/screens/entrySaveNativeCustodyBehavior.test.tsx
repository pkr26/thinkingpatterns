/** Exported EntryScreen + real HTTP/encrypted Native custody contracts.
 * Static session metadata is not an end-to-end Root account publisher. */
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
import { recentMoods,recordMood, localDateISO } from "../../src/moodLog";
import { installLocalDataKey,freezeLocalKeyWrites, __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { secureStore, setSecureStoreBackend } from "../../src/secureStore";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
import * as files from "../helpers/expoFsMock";
import { setLocale, t as tr } from "../../src/strings";
import { emitAppState } from "../helpers/rnMock";
import {takeStashedDraft,stashDraft,hasDraft} from "../../src/store";
import {publicSurface} from "../helpers/publicSurface";
import {assertPublicSurface} from "../helpers/publicSurfaceOracle";
import {installedNativeAlert} from "../helpers/nativeAlert";
import {engine} from "../../src/crypto/engine";
import {nativeGrantedPress} from "../helpers/nativePressability";
import {nativeInputChange} from "../helpers/nativeEntryEvents";
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
let status: number, boundary: (() => Promise<void>) | undefined,headersBoundary:(()=>void)|undefined;
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
  nativeRoute = router.getInitialState(routeOptions); status = 200; boundary = undefined;headersBoundary=undefined;entryDispatchBoundary=undefined;requireAudioParent=false;transcriptionBoundary=undefined;transcriptionLanguage="es";transcriptionEnglish=ENGLISH;transcriptionOriginal=SPOKEN; stored = new Map(); submitted = undefined;attachments=new Map();audioStatus=200;translationStatus=200;transcribedBytes=undefined;transcribeCode=undefined; vi.mocked(Alert.alert).mockClear();
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
    if (status >= 200&&status<300) stored.set(admitted.client_entry_id, admitted);headersBoundary?.();
    const response = new Response(status===204?null:JSON.stringify(status === 200 ? { id: "server-native-entry", ...admitted } : { error: { code: status === 422 ? "validation_error" : "server_error", message: "Native server refusal" } }), { status }); Object.defineProperty(response, "url", { value: url });
    const json = response.json.bind(response); response.json = async () => { const result = await json(); await boundary?.(); return result; }; return response;
  });
});
afterEach(async () => { vi.useRealTimers(); for (const release of releases.splice(0)) release(); await flush(); if (root) { await act(async () => root!.unmount()); root = undefined; } await waitJournalDraftWrites(); vi.restoreAllMocks(); storage.getItem=physicalDraftRead; vault.lock(); await api.clearSession(); vi.unstubAllGlobals(); vi.useRealTimers(); });

// These are exported EntryScreen + real installed API/vault/crypto/Native
// module contracts. The static session metadata is not an end-to-end Root
// account-publication producer; no such production regression is claimed.
async function recordVoice(uri = files.cacheDirectory + "root-native-entry-take.m4a") {
  await press("Record instead"); await flush();
  await vi.waitFor(() => expect(words()).toContain("Recording…"));
  fakeRecorderStatus.url = uri; fakeRecorderStatus.durationMillis = 4000;
  files.__seedFile(uri, SENSOR_BYTES.toString("base64"));
  await press("Stop recording"); await flush();
  await vi.waitFor(() => expect(editor().props.value).toBe(SPOKEN));
  return uri;
}


it("a save's Native owner receipt cannot dispatch journal ciphertext after its public editor retires",async()=>{
 await mount();await type(ORIGINAL);const held=hold(),get=secureStore.getItem.bind(secureStore);let first=true;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(first&&slot==="@mindpattern/user_id"){first=false;await held.run();}return value;});
 await press("Save entry",false);await vi.waitFor(()=>expect(held.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;held.release();await flush();
 expect([...stored.values()]).toEqual([]);await mount();expect(editor().props.value).toBe(ORIGINAL);
 assertPublicSurface(publicSurface(root!),0);
});

it("a retired native queue admission cannot display an abandoned-save system window after public queue disposal",async()=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);status=500;const read=storage.getItem.bind(storage),receipt=hold();let first=true;
 vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const value=await read(slot);if(first&&submitted&&slot.startsWith(ACCOUNT_STORAGE_PREFIX.queue+".items.")){first=false;await receipt.run();}return value;});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;abortInFlightFlush();receipt.release();await flush();
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.toJSON()).toBeNull();await act(async()=>window!.unmount());
});

it("a retired audio-parent receipt cannot start its successor credential's pending recording uploads",async()=>{
 await mount();audioStatus=503;await recordVoice(files.cacheDirectory+"independent-backlog-first.m4a");await press("Save entry");await flush();expect(await audioQueueStatus(USER)).toEqual({total:1,needsAttention:0});
 await recordVoice(files.cacheDirectory+"independent-retired-parent-second.m4a");const read=storage.getItem.bind(storage),receipt=hold(),physicalKey=vault.get().dataKey;let first=true;
 vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const value=await read(slot);if(first&&stored.size===2&&submitted&&slot.startsWith(ACCOUNT_STORAGE_PREFIX.audioQueue)&&slot.endsWith(submitted.client_entry_id)){first=false;await receipt.run();}return value;});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await api.setSession("new same-key Native recording credential",USER,"alice");expect(vault.get().dataKey).toBe(physicalKey);audioStatus=200;receipt.release();await flush();
 expect(await audioQueueStatus(USER)).toEqual({total:2,needsAttention:1});expect(attachments.size).toBe(0);assertPublicSurface(publicSurface(root!),0);
});

it("a replaced Native credential keeps its reviewed take after an older save's delayed deletion receipt",async()=>{
 await mount();const priorUri=await recordVoice(),receipt=hold(),remove=files.deleteAsync.getMockImplementation()!,physicalKey=vault.get().dataKey;let first=true;
 files.deleteAsync.mockImplementation(async(uri,options)=>{await remove(uri,options);if(first&&uri===priorUri&&stored.size>0){first=false;await receipt.run();}});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await api.setSession("new same-key Native reviewed-take credential",USER,"alice");expect(vault.get().dataKey).toBe(physicalKey);receipt.release();await flush();
 expect(root!.root.findAllByType(TouchableOpacity).some(node=>node.props.accessibilityLabel===tr("entry.voiceDiscardTake"))).toBe(true);expect(words()).toContain(tr("entry.voiceReviewTitle"));assertPublicSurface(publicSurface(root!),0);
});

it("an explicitly disposed Entry view cannot publish a delayed Native crisis system window",async()=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type("I want to kill myself");const receipt=hold(),write=storage.setItem.bind(storage),slot=accountStorageKey.crisisJournal(USER);let first=true;
 vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{await write(key,value);if(first&&key===slot){first=false;await receipt.run();}});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await press(tr("nav.getHelpA11y"));expect(nativeRoute.routes[nativeRoute.index]!.name).toBe("Crisis");
 // Route selection is real; explicit exported-view disposal is this module
 // boundary. NativeStack push alone does not promise an Entry unmount.
 await act(async()=>root!.unmount());root=undefined;receipt.release();await flush();
 expect(await secureStore.getItem(slot)).toBe(localDateISO());let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.toJSON()).toBeNull();await act(async()=>window!.unmount());
});

it("a departed crisis view cannot stamp an undisplayed dialog and suppress its successor's support window",async()=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type("I want to kill myself");const receipt=hold(),read=storage.getItem.bind(storage),slot=accountStorageKey.crisisJournal(USER);let first=true;
 vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(first&&key===slot){first=false;await receipt.run();}return value;});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await press(tr("nav.getHelpA11y"));expect(nativeRoute.routes[nativeRoute.index]!.name).toBe("Crisis");
 // Route selection is real; explicit exported-view disposal is this module
 // boundary. NativeStack push alone does not promise an Entry unmount.
 await act(async()=>root!.unmount());root=undefined;receipt.release();await flush();
 expect(await secureStore.getItem(slot)).toBeNull();await mount();await type("I want to kill myself. These are new words for the current support moment.");await press("Save entry");await flush();
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.root.findAllByType(Text).map(node=>node.props.children).join(" ")).toContain(tr("entry.crisisAlertTitle"));await act(async()=>window!.unmount());
});

it.each([422,401])("a retired Native journal HTTP%s receipt cannot display a system window over its successor",async nativeStatus=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);status=nativeStatus;const held=hold();boundary=held.run;
 await press("Save entry",false);await vi.waitFor(()=>expect(held.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;held.release();await flush();
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.toJSON()).toBeNull();await act(async()=>window!.unmount());
});

it("a same-key Native credential replacement keeps its retired transcription out of the current editor",async()=>{
 await mount();const physicalKey=vault.get().dataKey,held=hold();transcriptionBoundary=held.run;
 await press("Record instead");await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));const uri=files.cacheDirectory+"independent-native-owned-transcription.m4a";fakeRecorderStatus.url=uri;fakeRecorderStatus.durationMillis=4000;files.__seedFile(uri,SENSOR_BYTES.toString("base64"));await press("Stop recording");await vi.waitFor(()=>expect(held.entered()).toBe(true));await type(ORIGINAL);
 await api.setSession("new same-owner Native credential bearer",USER,"alice");expect(vault.get().dataKey).toBe(physicalKey);held.release();await flush();expect(editor().props.value).toBe(ORIGINAL);expect(words()).not.toContain(tr("entry.voiceTranscribeFailed"));assertPublicSurface(publicSurface(root!),0);
});

it("a saved Native draft does not reappear when the new-editor random provider refuses after its server receipt",async()=>{
 await mount();await type(ORIGINAL);const nativeRandom=engine.randomBytes.bind(engine);let refused=false;
 vi.spyOn(engine,"randomBytes").mockImplementation(size=>{if(size===16&&stored.size>0&&!refused){refused=true;throw new Error("Native secure random allocation refused");}return nativeRandom(size);});
 await press("Save entry");await flush();expect(refused).toBe(true);const journal=[...stored.values()][0]!;expect(decryptEntry({dataKey:KEY},USER,journal.client_entry_id,journal.blob,1).text).toBe(ORIGINAL);
 await act(async()=>root!.unmount());root=undefined;await mount();expect(editor().props.value).toBe("");assertPublicSurface(publicSurface(root!),0);
});


it("an accepted Native offline save cannot resurrect its already queued words after a held physical queue commit",async()=>{
 await mount();await type(ORIGINAL);status=500;const held=hold(),write=storage.setItem.bind(storage);let first=true;
 vi.spyOn(storage,"setItem").mockImplementation(async(slot,value)=>{if(first&&slot.startsWith(ACCOUNT_STORAGE_PREFIX.queue+".items.")){first=false;await held.run();}return write(slot,value);});
 await press("Save entry",false);await vi.waitFor(()=>expect(held.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;held.release();await flush();await waitJournalDraftWrites();
 const entries=await queued();expect(entries).toHaveLength(1);expect(decryptEntry({dataKey:KEY},USER,entries[0].clientEntryId,entries[0].blobB64,1).text).toBe(ORIGINAL);
 await mount();expect(editor().props.value).toBe("");assertPublicSurface(publicSurface(root!),0);
});

it("a current Native journal refusal displays the installed system alert's actual title and acknowledgement",async()=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);status=422;await press("Save entry");await flush();
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});const text=window!.root.findAllByType(Text).map(n=>n.props.children).join(" ");expect(text).toContain(tr("entry.notAcceptedTitle"));expect(text).toContain(tr("common.ok"));await act(async()=>window!.unmount());expect(editor().props.value).toBe(ORIGINAL);
});

it("a Native encryption-provider refusal after editor retirement cannot display a save-refusal system window",async()=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);const held=hold(),write=storage.setItem.bind(storage),nativeRandom=engine.randomBytes.bind(engine);let first=true,retired=false;
 vi.spyOn(storage,"setItem").mockImplementation(async(slot,value)=>{if(first&&slot.startsWith(ACCOUNT_STORAGE_PREFIX.journalDraft)){first=false;await held.run();}return write(slot,value);});
 vi.spyOn(engine,"randomBytes").mockImplementation(size=>{if(retired&&size===12)throw new Error("Native AES nonce provider refused");return nativeRandom(size);});
 await press("Save entry",false);await vi.waitFor(()=>expect(held.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;retired=true;held.release();await flush();
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.toJSON()).toBeNull();await act(async()=>window!.unmount());expect([...stored.values()]).toEqual([]);
});

it("a same-key Native credential replacement keeps its retired save from displaying a damaged-session system window",async()=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);const held=hold(),get=secureStore.getItem.bind(secureStore),physicalKey=vault.get().dataKey;let first=true;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(first&&slot==="@mindpattern/user_id"){first=false;await held.run();}return value;});
 await press("Save entry",false);await vi.waitFor(()=>expect(held.entered()).toBe(true));await api.setSession("replaced same-owner Native save bearer",USER,"alice");expect(vault.get().dataKey).toBe(physicalKey);held.release();await flush();
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.toJSON()).toBeNull();await act(async()=>window!.unmount());expect([...stored.values()]).toEqual([]);expect(editor().props.value).toBe(ORIGINAL);assertPublicSurface(publicSurface(root!),0);
});


it("Native typing delivered before an old granted save gesture commits retains its durable current draft",async()=>{
 await mount();await type(ORIGINAL);const oldInput=editor().props,save=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Save entry")!,gesture=nativeGrantedPress(save.props),latest="Fresh Native words delivered before the old save frame commits";
 try{await act(async()=>{nativeInputChange(oldInput,latest);gesture.release();});await flush();expect(editor().props.value).toBe(latest);await act(async()=>{await new Promise<void>(resolve=>setTimeout(resolve,350));});await waitJournalDraftWrites();const backup=await loadJournalDraft(KEY,await journalDraftScope(USER));expect(backup?.draft.text).toBe(latest);assertPublicSurface(publicSurface(root!),0);}finally{gesture.dispose();}
});

it("an accepted old save keeps a restored same-text RAM editor's distinct check-in",async()=>{
 const scope=await journalDraftScope(USER),device={...newJournalDraft(),revision:1,text:ORIGINAL};await saveJournalDraft(KEY,scope,device);
 const restore=hold(),receipt=hold(),get=secureStore.getItem.bind(secureStore);let users=0;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(slot==="@mindpattern/user_id"&&++users===2)await restore.run();return value;});
 await mount();expect(editor().props.value).toBe(ORIGINAL);boundary=receipt.run;await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));
 const ram={...newJournalDraft(),revision:1,text:ORIGINAL,mood:.5,tags:["family"]};stashDraft(USER,ram.text,ram,scope.origin);restore.release();await flush();await vi.waitFor(()=>expect(words()).toContain(tr("entry.deviceDraftConflict")));
 receipt.release();await flush();await press("Add details (optional)");expect(editor().props.value).toBe(ORIGINAL);expect(root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Mood: Good")!.props.accessibilityState.selected).toBe(true);expect(root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Tag: family")!.props.accessibilityState.checked).toBe(true);
 assertPublicSurface(publicSurface(root!),0);
});

it("a same-key Native credential replacement keeps an old receipt cleanup failure out of the current editor",async()=>{
 await mount();await type(ORIGINAL);const receipt=hold(),read=storage.getItem.bind(storage),physicalKey=vault.get().dataKey;let first=true;
 vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const value=await read(slot);if(first&&stored.size>0&&slot.startsWith(ACCOUNT_STORAGE_PREFIX.journalDraft)){first=false;await receipt.run();}return value;});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await api.setSession("new same-owner Native post-save receipt credential",USER,"alice");expect(vault.get().dataKey).toBe(physicalKey);receipt.release();await flush();
 expect(words()).not.toContain(tr("entry.deviceDraft.cleanup-error"));expect(editor().props.value).toBe(ORIGINAL);const saved=[...stored.values()][0]!;expect(decryptEntry({dataKey:KEY},USER,saved.client_entry_id,saved.blob,1).text).toBe(ORIGINAL);assertPublicSurface(publicSurface(root!),0);
});

it("an offline Native voice save stays queued until its later explicit reconnect",async()=>{
 requireAudioParent=true;await mount();await recordVoice();status=500;const write=storage.setItem.bind(storage);let recovered=false;
 vi.spyOn(storage,"setItem").mockImplementation(async(slot,value)=>{await write(slot,value);if(slot.startsWith(ACCOUNT_STORAGE_PREFIX.audioQueue)&&JSON.parse(value).parentPending===undefined){recovered=true;status=200;}});
 await press("Save entry");await flush();expect(recovered).toBe(true);expect(await queueLength(USER)).toBe(1);expect(stored.size).toBe(0);expect(attachments.size).toBe(0);expect(await audioQueueStatus(USER)).toEqual({total:1,needsAttention:0});
 await flushAudioQueue();expect(await queueLength(USER)).toBe(0);const parent=[...stored.values()][0]!;expect(decryptEntry({dataKey:KEY},USER,parent.client_entry_id,parent.blob,1).text).toBe(SPOKEN);expect(decryptAudio({dataKey:KEY},USER,parent.client_entry_id,attachments.get(parent.client_entry_id)!.blob)).toEqual(SENSOR_BYTES);
 assertPublicSurface(publicSurface(root!),0);
});

it("a retained Native replace confirmation cannot let an earlier transcription hide the current pending take",async()=>{
 // The input/record deliveries were already queued before the Native alert
 // presentation. Its later visible confirmation remains a real system action;
 // no gesture from an unmounted Record host is delivered.
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);const record=root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Record instead")!,input=editor().props;
 await act(async()=>{record.props.onPress();nativeInputChange(input,"");record.props.onPress();});await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));
 const old=hold(),current=hold();let responses=0;transcriptionBoundary=()=>++responses===1?old.run():current.run();const uri=files.cacheDirectory+"independent-confirmation-first.m4a";fakeRecorderStatus.url=uri;fakeRecorderStatus.durationMillis=4000;files.__seedFile(uri,SENSOR_BYTES.toString("base64"));await press("Stop recording");await vi.waitFor(()=>expect(old.entered()).toBe(true));
 let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});try{
  const confirm=window!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===tr("entry.voiceReplaceConfirm"));expect(confirm).toBeDefined();await act(async()=>confirm!.props.onPress());await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));
  const nextUri=files.cacheDirectory+"independent-confirmation-second.m4a";fakeRecorderStatus.url=nextUri;fakeRecorderStatus.durationMillis=4000;files.__seedFile(nextUri,SENSOR_BYTES.toString("base64"));await press("Stop recording");await vi.waitFor(()=>expect(current.entered()).toBe(true));old.release();await flush();expect(words()).toContain(tr("entry.voiceTranscribing"));expect(editor().props.value).toBe("");
  current.release();await flush();await vi.waitFor(()=>expect(editor().props.value).toBe(SPOKEN));expect(words()).not.toContain(tr("entry.voiceTranscribing"));assertPublicSurface(publicSurface(root!),0);
 }finally{await act(async()=>window!.unmount());}
});

it("a late saved-take Native deletion receipt preserves a fresh public recording",async()=>{
 await mount();const priorUri=await recordVoice(),receipt=hold(),remove=files.deleteAsync.getMockImplementation()!;let first=true;
 files.deleteAsync.mockImplementation(async(uri,options)=>{await remove(uri,options);if(first&&uri===priorUri&&stored.size>0){first=false;await receipt.run();}});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await press(tr("entry.voiceDiscardTake"));await flush();await press("Record instead");await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));
 const freshUri=files.cacheDirectory+"independent-new-take-before-old-cleanup.m4a";fakeRecorderStatus.url=freshUri;files.__seedFile(freshUri,SENSOR_BYTES.toString("base64"));receipt.release();await flush();
 expect(words()).toContain("Recording…");expect(files.__hasFile(freshUri)).toBe(true);assertPublicSurface(publicSurface(root!),0);
});

it.each([[false,false],[true,false],[true,true]])("a retained Native replace confirmation protects its capture from an earlier save's cleanup (same Native beat %s, discard before confirm %s)",async(sameBeat,discardFirst)=>{
 const device=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type(ORIGINAL);const record=root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Record instead")!,input=editor().props;
 await act(async()=>{record.props.onPress();nativeInputChange(input,"");record.props.onPress();});await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));
 const priorUri=files.cacheDirectory+"independent-replace-saved-first.m4a";fakeRecorderStatus.url=priorUri;fakeRecorderStatus.durationMillis=4000;files.__seedFile(priorUri,SENSOR_BYTES.toString("base64"));await press("Stop recording");await vi.waitFor(()=>expect(editor().props.value).toBe(SPOKEN));
 const receipt=hold(),remove=files.deleteAsync.getMockImplementation()!;let first=true;files.deleteAsync.mockImplementation(async(uri,options)=>{await remove(uri,options);if(first&&uri===priorUri&&stored.size>0){first=false;await receipt.run();}});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});try{
  const confirm=window!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===tr("entry.voiceReplaceConfirm"));expect(confirm).toBeDefined();const discard=root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===tr("entry.voiceDiscardTake"));
  if(discardFirst){
   // Native deliveries share one live JS beat. The microtask checkpoint
   // runs before the next host task commits concurrent React updates.
   // The confirmation belongs to the still-visible system window.
   await new Promise<void>(resolve=>setImmediate(()=>{discard!.props.onPress();confirm!.props.onPress();receipt.release();queueMicrotask(resolve);}));
  }else await act(async()=>{confirm!.props.onPress();if(sameBeat)receipt.release();});await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));
  const freshUri=files.cacheDirectory+"independent-replace-next-capture.m4a";fakeRecorderStatus.url=freshUri;files.__seedFile(freshUri,SENSOR_BYTES.toString("base64"));if(!sameBeat)receipt.release();await flush();expect(words()).toContain("Recording…");expect(files.__hasFile(freshUri)).toBe(true);assertPublicSurface(publicSurface(root!),0);
 }finally{await act(async()=>window!.unmount());}
});


it("an accepted old save preserves a restored same-revision RAM fork's new words",async()=>{
 const scope=await journalDraftScope(USER),device={...newJournalDraft(),revision:1,text:ORIGINAL};await saveJournalDraft(KEY,scope,device);
 const restore=hold(),receipt=hold(),get=secureStore.getItem.bind(secureStore);let users=0;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(slot==="@mindpattern/user_id"&&++users===2)await restore.run();return value;});
 await mount();expect(editor().props.value).toBe(ORIGINAL);boundary=receipt.run;await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));
 const nextWords="New RAM fork words with the same authenticated editor revision",ram={...device,text:nextWords};stashDraft(USER,ram.text,ram,scope.origin);restore.release();await flush();await vi.waitFor(()=>expect(words()).toContain(tr("entry.deviceDraftConflict")));expect(editor().props.value).toBe(nextWords);
 receipt.release();await flush();expect(editor().props.value).toBe(nextWords);assertPublicSurface(publicSurface(root!),0);
});


it("an acknowledged save removes its matching RAM fallback before delayed Native restore",async()=>{
 const scope=await journalDraftScope(USER),device={...newJournalDraft(),revision:1,text:ORIGINAL};await saveJournalDraft(KEY,scope,device);
 const restore=hold(),receipt=hold(),get=secureStore.getItem.bind(secureStore);let users=0;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(slot==="@mindpattern/user_id"&&++users===2)await restore.run();return value;});
 await mount();boundary=receipt.run;await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));stashDraft(USER,device.text,device,scope.origin);receipt.release();await flush();await vi.waitFor(()=>expect(editor().props.value).toBe(""));restore.release();await flush();expect(editor().props.value).toBe("");assertPublicSurface(publicSurface(root!),0);
});

it("a retired key generation leaves the public matching RAM fallback available",async()=>{
 const scope=await journalDraftScope(USER),device={...newJournalDraft(),revision:1,text:ORIGINAL};await saveJournalDraft(KEY,scope,device);
 const restore=hold(),receipt=hold(),get=secureStore.getItem.bind(secureStore);let users=0;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(slot==="@mindpattern/user_id"&&++users===2)await restore.run();return value;});
 await mount();boundary=receipt.run;await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));stashDraft(USER,device.text,device,scope.origin);freezeLocalKeyWrites(USER);receipt.release();await flush();await vi.waitFor(()=>expect(words()).not.toContain("Saving…"));
 // hasDraft is the exported process-fallback availability contract consumed
 // by unlock/session flows. No private RAM object or hook is inspected.
 expect(hasDraft(USER)).toBe(true);expect(editor().props.value).toBe(ORIGINAL);assertPublicSurface(publicSurface(root!),0);
});


it("saving typed words during Native transcription preserves the finished take for review",async()=>{
 await mount();const receipt=hold();transcriptionBoundary=receipt.run;await press("Record instead");await flush();await vi.waitFor(()=>expect(words()).toContain("Recording…"));await type(ORIGINAL);
 const uri=files.cacheDirectory+"independent-typing-during-transcription.m4a";fakeRecorderStatus.url=uri;fakeRecorderStatus.durationMillis=4000;files.__seedFile(uri,SENSOR_BYTES.toString("base64"));await press("Stop recording");await vi.waitFor(()=>expect(receipt.entered()).toBe(true));expect(words()).toContain(tr("entry.voiceTranscribing"));await press("Save entry");await flush();expect(files.__hasFile(uri)).toBe(true);receipt.release();await flush();
 await vi.waitFor(()=>expect(words()).toContain(tr("entry.voiceReviewTitle")));expect(files.__hasFile(uri)).toBe(true);assertPublicSurface(publicSurface(root!),0);
});


it("a held Native streak receipt cannot replace the current credential view's streak",async()=>{
 const prior=new Date();prior.setDate(prior.getDate()-1);const older=new Date(prior);older.setDate(older.getDate()-1);await recordMood(KEY,USER,localDateISO(older),0);await recordMood(KEY,USER,localDateISO(prior),0);
 await mount();await vi.waitFor(()=>expect(words()).toContain(tr("common.streakMany",{count:2})));const receipt=hold(),read=storage.getItem.bind(storage),slot=accountStorageKey.moodLog(USER);let reads=0;
 vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(key===slot&&++reads===2)await receipt.run();return value;});await type(ORIGINAL);await press("Save entry");await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await api.setSession("new Native credential owns current streak",USER,"alice");receipt.release();await flush();
 expect(words()).toContain(tr("common.streakMany",{count:2}));expect(words()).not.toContain(tr("common.streakMany",{count:3}));assertPublicSurface(publicSurface(root!),0);
});


it("a disposed Entry's retained Android system-window action leaves the physical credential worker available",async()=>{
 const device=installedNativeAlert("android");vi.spyOn(Alert,"alert").mockImplementation(device.alert);await mount();await type("I want to kill myself");status=422;await press("Save entry");let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<device.Window/>);});expect(window!.root.findAllByType(Text).map(node=>node.props.children).join(" ")).toContain(tr("entry.notAcceptedTitle"));await act(async()=>root!.unmount());root=undefined;
 const read=storage.getItem.bind(storage),write=storage.setItem.bind(storage),remove=storage.removeItem.bind(storage),list=storage.getAllKeys.bind(storage),held=hold(),slot=accountStorageKey.crisisJournal(USER);let worker:Promise<unknown>=Promise.resolve(),replacement:Promise<void>|undefined,timer:ReturnType<typeof setTimeout>|undefined,finished=false;
 const nativeJob=<T,>(operation:()=>Promise<T>):Promise<T>=>{const job=worker.then(operation,operation);worker=job.catch(()=>{});return job;};
 // This is the installed Android AsyncStorage SerialExecutor boundary,
 // which holds its FIFO worker until the Native body exits. Its physical
 // read is unavailable; a delivered JS receipt would already free it.
 vi.spyOn(storage,"getItem").mockImplementation(key=>nativeJob(async()=>{if(key===slot){timer??=setTimeout(held.release,800);await held.run();}return read(key);}));vi.spyOn(storage,"setItem").mockImplementation((key,value)=>nativeJob(()=>write(key,value)));vi.spyOn(storage,"removeItem").mockImplementation(key=>nativeJob(()=>remove(key)));vi.spyOn(storage,"getAllKeys").mockImplementation(()=>nativeJob(list));
 try{const okay=window!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===tr("common.ok"));expect(okay).toBeDefined();await act(async()=>{okay!.props.onPress();replacement=api.setSession("new Android Native credential worker bearer",USER,"alice");void replacement.then(()=>{finished=true;});});await vi.waitFor(()=>expect(finished).toBe(true),{timeout:250,interval:5});expect(await secureStore.getItem("@mindpattern/token")).toBe("new Android Native credential worker bearer");}
 finally{held.release();if(timer)clearTimeout(timer);await replacement;await worker;await act(async()=>window!.unmount());}
});


it.each(["api","head-store","body-pin"] as const)("a paired Native %s credential-metadata receipt preserves retired-generation RAM custody",async courier=>{
 const alerts=installedNativeAlert();vi.spyOn(Alert,"alert").mockImplementation(alerts.alert);const scope=await journalDraftScope(USER),device={...newJournalDraft(),revision:1,text:ORIGINAL};await saveJournalDraft(KEY,scope,device);
 const restore=hold(),get=secureStore.getItem.bind(secureStore),read=storage.getItem.bind(storage);let users=0,firstUsername=true,usernameReady=false,deliverUsername:(()=>void)|undefined;const nativeSlot=courier.includes("pin")?"@mindpattern/pinned_origin":"@mindpattern/username";
 vi.spyOn(secureStore,"getItem").mockImplementation(slot=>{const pending=get(slot);if(slot==="@mindpattern/user_id"&&++users===2)return pending.then(async value=>{await restore.run();return value;});return pending;});await mount();
 vi.spyOn(storage,"getItem").mockImplementation(slot=>{const pending=read(slot);if(slot===nativeSlot&&firstUsername){firstUsername=false;return new Promise<string|null>(resolve=>{void pending.then(value=>{deliverUsername=()=>resolve(value);releases.push(deliverUsername);usernameReady=true;});});}return pending;});
 // Public encrypted credential-metadata read and verified key installation
 // deliver through their real Promise couriers beside the HTTP receipt.
 // This is a Native module contract, not a Root login producer claim.
 const installing=(courier.includes("pin")?api.pinnedOrigin():courier.endsWith("store")?secureStore.getItem("@mindpattern/username"):api.getUsername()).then(()=>{freezeLocalKeyWrites(USER);installLocalDataKey(USER,vault.get().dataKey);});await vi.waitFor(()=>expect(usernameReady).toBe(true));stashDraft(USER,device.text,device,scope.origin);if(courier.startsWith("head")){status=204;headersBoundary=()=>{deliverUsername!();};}else boundary=async()=>{deliverUsername!();};await press("Save entry");await installing;await flush();
 expect(hasDraft(USER)).toBe(true);let window:ReturnType<typeof ReactTestRenderer.create>;await act(async()=>{window=ReactTestRenderer.create(<alerts.Window/>);});expect(window!.toJSON()).toBeNull();await act(async()=>window!.unmount());assertPublicSurface(publicSurface(root!),0);
});


it("a changed public keep-recording pick remains in review after an older save's deletion receipt",async()=>{
 await mount();const uri=await recordVoice(),receipt=hold(),remove=files.deleteAsync.getMockImplementation()!;let first=true;files.deleteAsync.mockImplementation(async(path,options)=>{await remove(path,options);if(first&&path===uri&&stored.size>0){first=false;await receipt.run();}});
 await press("Save entry",false);await vi.waitFor(()=>expect(receipt.entered()).toBe(true));await press(tr("entry.voiceKeepOn"));receipt.release();await flush();expect(words()).toContain(tr("entry.voiceReviewTitle"));expect(root!.root.findAllByType(TouchableOpacity).some(node=>node.props.accessibilityLabel===tr("entry.voiceKeepOff"))).toBe(true);assertPublicSurface(publicSurface(root!),0);
});
