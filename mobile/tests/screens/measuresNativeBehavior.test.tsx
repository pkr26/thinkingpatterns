/** Actual credential storage, paged HTTP, AES and persisted questionnaires. */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ActivityIndicator, Alert, Text, TouchableOpacity } from "react-native";
import { api } from "../../src/api/client";
import { MeasuresScreen } from "../../src/screens/MeasuresScreen";
import { ThemeProvider } from "../../src/theme";
import { vault } from "../../src/vault";
import * as envelope from "../../src/crypto/envelope";
import { accountStorageKey } from "../../src/accountStorage";
import { savePendingMeasure, type PendingMeasure } from "../../src/pendingMeasure";
import * as pendingMeasure from "../../src/pendingMeasure";
import { installLocalDataKey, freezeLocalKeyWrites, __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import { secureStore } from "../../src/secureStore";
import { lastMeasureCompletedOn } from "../../src/measureReminders";
import { publicSurface } from "../helpers/publicSurface";
import { assertPublicSurface } from "../helpers/publicSurfaceOracle";
import * as completion from "../../src/measureReminders";
import * as reminderSync from "../../src/reminderSync";
import { recordCrisisDialogShown, clearCrisisDialogStamp } from "../../src/crisisDialog";
import { localDateISO } from "../../src/moodLog";
import { nativeGrantedPress } from "../helpers/nativePressability";

const USER = "a".repeat(32), OTHER = "b".repeat(32), KEY = Buffer.alloc(32, 21);
const touchActivity = vi.fn();
vi.mock("../../src/store", async original => ({ ...await original<typeof import("../../src/store")>(), useSession: () => ({ touchActivity }) }));
let root: ReactTestRenderer.ReactTestRenderer | undefined;
let serverRows: unknown[];
let serverStatus: number;
let sent: Array<{ client_measure_id: string; blob: string; measure_date: string }>;
let gets: number;
let releases: Array<() => void>;
let stage: number;
const navigation = { navigate: vi.fn(), goBack: vi.fn() };
const flush = async () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
function words(): string {
  const flat = (value: unknown): string => Array.isArray(value) ? value.map(flat).join("") : typeof value === "string" || typeof value === "number" ? String(value) : "";
  return root!.root.findAllByType(Text).map(node => flat(node.props.children)).join(" ");
}
function button(label: string) {
  const found = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  if (!found) throw new Error("Missing Native control " + label);
  return found;
}
function inspect() { if (root) assertPublicSurface(publicSurface(root), ++stage); }
async function press(label: string) { const node = button(label); expect(node.props.disabled).not.toBe(true); await act(async () => node.props.onPress()); inspect(); }
async function mount(wait = true) {
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><MeasuresScreen navigation={navigation} /></ThemeProvider>); });
  await flush();
  if (wait) await vi.waitFor(() => expect(words()).toContain("Nothing recorded yet."));
  inspect();
}
async function complete(kind = "phq2", score = 0) {
  if (kind === "phq2") await press("PHQ-2 (brief, 2 items)");
  const count = kind === "phq2" ? 2 : 9;
  for (let index = 0; index < count; index++) await press(`Question ${index + 1}: ${index === count - 1 && score ? "Several days" : "Not at all"}`);
}
function row(id: string, raw: string, date = "2026-09-20") {
  return { id, client_measure_id: id, measure_date: date, blob: envelope.encrypt(KEY, Buffer.from(raw), envelope.buildAad("measure", USER, id)).toString("base64") };
}
function gate() { let entered = false, release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); releases.push(release); return { promise, release, enter: () => { entered = true; }, entered: () => entered }; }
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  await api.setSession("native measures bearer", USER, "alice");
  await clearCrisisDialogStamp(USER);
  vault.unlock({ masterKey: Buffer.alloc(32, 3), authKey: Buffer.alloc(32, 4), dataKey: Buffer.from(KEY) }, USER); installLocalDataKey(USER, vault.get().dataKey);
  serverRows = []; serverStatus = 201; sent = []; gets = 0; releases = []; stage = 0; touchActivity.mockClear(); navigation.navigate.mockClear(); navigation.goBack.mockClear(); Alert.alert.mockClear();
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    if (!path.endsWith("/measures")) throw new Error("Unexpected Native measures path " + path);
    const post = init?.method === "POST";
    if (post) sent.push(JSON.parse(String(init.body)));
    else gets++;
    const response = new Response(JSON.stringify(post ? serverStatus >= 400 ? { detail: { code: "conflict", message: "Native refusal" } } : {} : serverRows), { status: post ? serverStatus : 200 });
    Object.defineProperty(response, "url", { value: url }); return response;
  });
});
afterEach(async () => {
  vi.useRealTimers(); releases.forEach(release => release()); await flush();
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vault.lock(); await api.clearSession();
});
it("Native JSON scores clamp to each accepted instrument and skip unknown or nonfinite shapes", async () => {
  serverRows = [row("low", '{"measure":"phq2","score":-2.8}'), row("high", '{"measure":"phq2","score":9.7}'), row("rounded", '{"measure":"gad7","score":4.6}'), row("string", '{"measure":"phq9","score":"8"}'), row("overflow", '{"measure":"phq9","score":1e999}'), row("future", '{"measure":"future","score":7}')];
  await mount(false); await vi.waitFor(() => expect(words()).toContain("Your recorded scores"));
  expect(words()).toContain("September 20, 2026: 0"); expect(words()).toContain("September 20, 2026: 6"); expect(words()).toContain("September 20, 2026: 5");
  expect(words()).not.toContain(": 8"); expect(words()).not.toContain(": 27"); expect(words()).not.toContain("future");
});
it("a Native PHQ-2 tap sends the completed instrument, date and decryptable stable identifier", async () => {
  await mount(); await complete(); await press("Record this check-in"); await vi.waitFor(() => expect(sent).toHaveLength(1));
  const wire = sent[0]!; expect(wire.client_measure_id).toMatch(/^m-\d{4}-\d{2}-\d{2}-[\w-]{12}$/);
  expect(JSON.parse(envelope.decrypt(KEY, Buffer.from(wire.blob, "base64"), envelope.buildAad("measure", USER, wire.client_measure_id)).toString())).toEqual({ v: 1, measure: "phq2", score: 0, completed_at: wire.measure_date });
  await vi.waitFor(() => expect(words()).toContain("Recorded")); expect(await storage.getItem(accountStorageKey.pendingMeasure(USER))).toBeNull();
});
it("an older accepted Native history load cannot replace the history refreshed after a new save", async () => {
  serverRows = [row("older", '{"measure":"phq2","score":1}')];
  const hold = gate(), original = api.listMeasures; let first = true;
  vi.spyOn(api, "listMeasures").mockImplementation(async () => { const result = await original(); if (first) { first = false; hold.enter(); await hold.promise; } return result; });
  await mount(false); await vi.waitFor(() => expect(hold.entered()).toBe(true));
  await complete(); serverRows = [row("newer", '{"measure":"phq2","score":5}')]; await press("Record this check-in");
  await vi.waitFor(() => expect(words()).toContain("September 20, 2026: 5")); hold.release(); await flush();
  expect(words()).toContain("September 20, 2026: 5"); expect(words()).not.toContain("September 20, 2026: 1");
});
it("an unmounted Native pending retry cannot dispatch the restored questionnaire", async () => {
  const pending: PendingMeasure = { kind: "phq2", clientMeasureId: "m-native-pending", picks: [0, 1], date: "2026-09-20" };
  await savePendingMeasure(KEY, USER, pending); const hold = gate(), read = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async name => { const value = await read(name); if (name === accountStorageKey.pendingMeasure(USER)) { hold.enter(); await hold.promise; } return value; });
  await mount(); await vi.waitFor(() => expect(hold.entered()).toBe(true)); await act(async () => root!.unmount()); root = undefined;
  hold.release(); await flush(); await flush(); expect(sent).toHaveLength(0); expect(await read(accountStorageKey.pendingMeasure(USER))).toBeTruthy();
});
it("a saved Native response released after unmount cannot load or alert into a replacement session", async () => {
  await mount(); await complete("phq9", 1); const hold = gate(), original = api.createMeasure;
  vi.spyOn(api, "createMeasure").mockImplementation(async (...args) => { const result = await original(...args); hold.enter(); await hold.promise; return result; });
  await press("Record this check-in"); await vi.waitFor(() => expect(hold.entered()).toBe(true));
  await act(async () => root!.unmount()); root = undefined; await api.setSession("replacement native bearer", OTHER, "bob"); vault.unlock({ masterKey: Buffer.alloc(32, 8), authKey: Buffer.alloc(32, 9), dataKey: Buffer.alloc(32, 10) }, OTHER); installLocalDataKey(OTHER, vault.get().dataKey);
  const before = gets; hold.release(); await flush(); await flush(); expect(gets).toBe(before); expect(Alert.alert).not.toHaveBeenCalled();
});
it("Native history plaintext copies are retired after parsing both valid and skipped rows", async () => {
  serverRows = [row("valid", '{"measure":"phq2","score":1}'), row("skipped", '{"measure":"future","score":1}')]; const physical: Buffer[] = [], original = envelope.decrypt;
  vi.spyOn(envelope, "decrypt").mockImplementation((...args) => { const plain = original(...args); if(args[2]?.toString().startsWith('["measure",')) physical.push(plain); return plain; });
  await mount(false); await vi.waitFor(() => expect(words()).toContain("Your recorded scores")); expect(physical).toHaveLength(2); expect(physical.every(bytes => bytes.every(byte => byte === 0))).toBe(true);
});
it("Native instrument changes clear prior answers and all real questionnaire taps count as activity", async () => {
  await mount(); await press("Question 1: Several days"); expect(touchActivity).toHaveBeenCalledTimes(1);
  await press("GAD-7 (anxiety, 7 items)"); expect(button("Record this check-in").props.disabled).toBe(true);
  expect(button("GAD-7 (anxiety, 7 items)").props.accessibilityState.selected).toBe(true);
  await press("Question 1: Nearly every day"); await press("PHQ-9 (depression, 9 items)");
  expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(false); expect(touchActivity).toHaveBeenCalledTimes(4);
});
it("Native settings and help controls navigate through the shipped destinations", async () => {
  await mount(); await press("Back to settings"); expect(navigation.goBack).toHaveBeenCalledOnce();
  const help = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel?.includes("Need help"))!;
  expect(help).toBeDefined(); await act(async () => help.props.onPress()); expect(navigation.navigate).toHaveBeenCalledWith("Crisis");
});
it("a completed persisted Native GAD-7 is restored and retried under its exact id and instrument", async () => {
  const pending: PendingMeasure = { kind: "gad7", clientMeasureId: "m-native-seven", picks: [0, 1, 2, 3, 0, 1, 2], date: "2026-09-20" };
  await savePendingMeasure(KEY, USER, pending); await mount(); await vi.waitFor(() => expect(sent).toHaveLength(1));
  expect(sent[0]!.client_measure_id).toBe(pending.clientMeasureId); expect(sent[0]!.measure_date).toBe(pending.date);
  expect(JSON.parse(envelope.decrypt(KEY, Buffer.from(sent[0]!.blob, "base64"), envelope.buildAad("measure", USER, pending.clientMeasureId)).toString())).toEqual({ v: 1, measure: "gad7", score: 9, completed_at: pending.date });
  await vi.waitFor(() => expect(words()).toContain("Recorded")); expect(button("GAD-7 (anxiety, 7 items)").props.accessibilityState.selected).toBe(true); expect(button("Record this check-in").props.disabled).toBe(true); inspect();
});
it("changed Native picks survive an accepted save and the next completed response gets a new id", async () => {
  await mount(); await complete(); const hold = gate(), original = api.createMeasure;
  vi.spyOn(api, "createMeasure").mockImplementationOnce(async (...args) => { const result = await original(...args); hold.enter(); await hold.promise; return result; });
  await press("Record this check-in"); await vi.waitFor(() => expect(hold.entered()).toBe(true)); await press("Question 1: Several days");
  hold.release(); await vi.waitFor(() => expect(words()).toContain("Recorded")); expect(button("Record this check-in").props.disabled).toBe(false); expect(button("Question 1: Several days").props.accessibilityState.selected).toBe(true);
  await press("Record this check-in"); await vi.waitFor(() => expect(sent).toHaveLength(2)); expect(sent[1]!.client_measure_id).not.toBe(sent[0]!.client_measure_id);
});
it("an offline Native send preserves encrypted picks and reuses the same id on retry", async () => {
  await mount(); await complete(); const fetchNative = globalThis.fetch; let failed = true;
  vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => { if (args[1]?.method === "POST" && failed) { failed = false; sent.push(JSON.parse(String(args[1].body))); throw new TypeError("Native network unavailable"); } return fetchNative(...args); });
  await press("Record this check-in"); await vi.waitFor(() => expect(words()).toContain("Your picks are still on screen.")); expect(button("Record this check-in").props.disabled).toBe(false); inspect();
  const raw = await storage.getItem(accountStorageKey.pendingMeasure(USER)); expect(raw).toBeTruthy(); expect(raw).not.toContain("picks");
  await press("Record this check-in"); await vi.waitFor(() => expect(sent).toHaveLength(2)); expect(sent[1]!.client_measure_id).toBe(sent[0]!.client_measure_id); await vi.waitFor(() => expect(words()).toContain("Recorded")); inspect();
});
it.each([201, 409, 0])("Native item-9 support follows safely persisted answers for response %s and exposes every reviewed action", async status => {
  serverStatus = status || 201; if (!status) { const fetchNative = globalThis.fetch; vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => { if (args[1]?.method === "POST") throw new TypeError("Native offline"); return fetchNative(...args); }); }
  await mount(); await complete("phq9", 1); await press("Record this check-in");
  if (status === 409) { await vi.waitFor(() => expect(words()).toContain("Already recorded")); expect(Alert.alert).not.toHaveBeenCalled(); return; }
  await vi.waitFor(() => expect(Alert.alert).toHaveBeenCalled());
  const call = Alert.alert.mock.calls.at(-1)!; expect(call[0]).toBe("Support is available"); expect(call[1]).toContain("does not monitor this response or alert anyone");
  expect(call[2]?.map((value: {text: string; style?: string}) => ({text: value.text, style: value.style}))).toEqual([{text: "View support resources", style: undefined}, {text: "Make a safety plan", style: undefined}, {text: "Not now", style: "cancel"}]);
  await act(async () => call[2]![0]!.onPress!()); expect(navigation.navigate).toHaveBeenLastCalledWith("Crisis"); await act(async () => call[2]![1]!.onPress!()); expect(navigation.navigate).toHaveBeenLastCalledWith("SafetyPlan");
  if (status === 201) expect(await lastMeasureCompletedOn(USER)).toBe(sent[0]!.measure_date);
  else { await press("Record this check-in"); await flush(); expect(Alert.alert).toHaveBeenCalledTimes(1); }
  inspect();
});
it("a Native server refusal keeps the questionnaire and reports the shipped failure dialog", async () => {
  await mount(); await complete(); serverStatus = 500; await press("Record this check-in"); await vi.waitFor(() => expect(Alert.alert).toHaveBeenCalled());
  expect(Alert.alert.mock.calls.at(-1)?.slice(0,2)).toEqual(["Not recorded", "Could not record just now. Your picks are still on screen."]);
  expect(button("Record this check-in").props.disabled).toBe(false); inspect();
});
it.each(["offline", "native-storage", "server"])("Native %s history failure displays its honest public state", async mode => {
  if (mode === "native-storage") { const original = storage.getItem.bind(storage); vi.spyOn(storage, "getItem").mockImplementation(async name => { if (name === "@mindpattern/user_id") throw new Error("Native storage refused"); return original(name); }); }
  else vi.stubGlobal("fetch", async (url: string) => { if (mode === "offline") throw new TypeError("Native offline"); const response = new Response(JSON.stringify({detail:"Unavailable"}), {status:500}); Object.defineProperty(response,"url",{value:url}); return response; });
  await mount(false); await vi.waitFor(() => expect(root!.root.findAllByType(ActivityIndicator)).toHaveLength(0)); inspect();
  expect(words()).toContain(mode === "offline" ? "Your recorded history needs a connection" : mode === "native-storage" ? "Could not load your measures." : "server");
});
it("a still-mounted locked Native view admits no load, pending read or send", async () => {
  vault.lock(); const read = storage.getItem.bind(storage);
  vi.spyOn(storage,"getItem").mockImplementation(name => name === "@mindpattern/user_id" ? new Promise<string|null>(()=>{}) : read(name));
  await mount(false); expect(gets).toBe(0); expect(words()).toContain("Your keys are locked"); await complete(); await press("Record this check-in"); expect(sent).toHaveLength(0); expect(Alert.alert).not.toHaveBeenCalled(); expect(button("Record this check-in").props.accessibilityState.busy).toBe(false); inspect();
});
it("a Native response confirmation expires on the shared finite status timer", async () => {
  await mount(); await complete(); await press("Record this check-in"); await vi.waitFor(() => expect(words()).toContain("Recorded")); await flush();
  await new Promise(resolve => setTimeout(resolve, 2650)); await flush(); expect(words()).not.toContain("Recorded — encrypted, as always."); inspect();
});
it.each(["scope", "key", "lock"])("a still-mounted Native history receipt retired by %s cannot decrypt or publish", async retirement => {
  serverRows = [row("private", '{"measure":"phq2","score":3}')]; const hold = gate(), original = api.listMeasures;
  vi.spyOn(api, "listMeasures").mockImplementationOnce(async () => { const result = await original(); hold.enter(); await hold.promise; return result; });
  await mount(false); await vi.waitFor(() => expect(hold.entered()).toBe(true)); const before = publicSurface(root!);
  if (retirement === "scope") await api.setSession("refreshed native bearer", USER, "alice");
  else if (retirement === "key") { vault.unlock({masterKey:Buffer.alloc(32,4),authKey:Buffer.alloc(32,5),dataKey:Buffer.from(KEY)},USER); installLocalDataKey(USER,vault.get().dataKey); }
  else vault.lock();
  hold.release(); await flush(); expect(publicSurface(root!)).toEqual(before); expect(words()).not.toContain("September 20, 2026: 3");
});
it("a Native first owner receipt released after unmount cannot admit an unavailable history provider", async () => {
  const hold = gate(), original = api.getUserId; let first = true;
  vi.spyOn(api, "getUserId").mockImplementation(async () => { const owner = await original(); if(first){first=false;hold.enter();await hold.promise;} return owner; });
  await mount(false); await vi.waitFor(() => expect(hold.entered()).toBe(true)); await act(async () => root!.unmount()); root=undefined;
  hold.release(); await flush(); expect(gets).toBe(0);
});
it("a Native pending receipt cannot restore old-account answers into the still-mounted replacement session", async () => {
  await savePendingMeasure(KEY,USER,{kind:"gad7",clientMeasureId:"m-native-old-owner",picks:[1,1,1,1,1,1,1],date:"2026-09-20"}); const hold=gate(),read=storage.getItem.bind(storage);
  vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.pendingMeasure(USER)){hold.enter();await hold.promise;}return value;});
  await mount(); await vi.waitFor(()=>expect(hold.entered()).toBe(true));const before=publicSurface(root!);
  await api.setSession("replacement native bearer",OTHER,"bob");vault.unlock({masterKey:Buffer.alloc(32,7),authKey:Buffer.alloc(32,8),dataKey:Buffer.alloc(32,9)},OTHER);installLocalDataKey(OTHER,vault.get().dataKey);
  hold.release();await flush();await flush();expect(publicSurface(root!)).toEqual(before);expect(sent).toHaveLength(0);expect(await read(accountStorageKey.pendingMeasure(OTHER))).toBeNull();
});
it.each(["success", "duplicate", "refusal"])("an accepted Native %s continuation retired by same-account credential refresh cannot mutate pending answers",async outcome=>{
  await mount();await complete();serverStatus=outcome==="success"?201:outcome==="duplicate"?409:500;const hold=gate(),original=api.createMeasure;
  vi.spyOn(api,"createMeasure").mockImplementationOnce(async(...args)=>{try{const result=await original(...args);hold.enter();await hold.promise;return result;}catch(error){hold.enter();await hold.promise;throw error;}});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));const read=storage.getItem.bind(storage),before=await read(accountStorageKey.pendingMeasure(USER)),beforeGets=gets;
  await api.setSession("same account refreshed bearer",USER,"alice");hold.release();await flush();await flush();expect(await read(accountStorageKey.pendingMeasure(USER))).toBe(before);expect(gets).toBe(beforeGets);expect(words()).not.toContain("Recorded —");expect(words()).not.toContain("Already recorded");expect(Alert.alert).not.toHaveBeenCalled();expect(button("Record this check-in").props.disabled).toBe(false);
});
it.each([201,409])("a Native pending-clear receipt released after unmount cannot restart cadence or history for status %s",async status=>{
  await mount();await complete();serverStatus=status;const hold=gate(),remove=storage.removeItem.bind(storage);
  vi.spyOn(storage,"removeItem").mockImplementation(async name=>{await remove(name);if(name===accountStorageKey.pendingMeasure(USER)){hold.enter();await hold.promise;}});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));const timers=vi.spyOn(globalThis,"setTimeout");await act(async()=>root!.unmount());root=undefined;const before=gets;hold.release();await flush();await flush();expect(gets).toBe(before);expect(await lastMeasureCompletedOn(USER)).toBeNull();expect(Alert.alert).not.toHaveBeenCalled();expect(timers.mock.calls.filter(call=>call[1]===2600)).toHaveLength(0);
});
it("a Native cadence receipt released after unmount cannot start reminder reconciliation or history",async()=>{
  await mount();await complete();const hold=gate(),original=completion.recordMeasureCompleted, sync=vi.spyOn(reminderSync,"syncMeasureReminderSchedule");
  vi.spyOn(completion,"recordMeasureCompleted").mockImplementationOnce(async(...args)=>{await original(...args);hold.enter();await hold.promise;});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;const before=gets;hold.release();await flush();expect(gets).toBe(before);expect(sync).not.toHaveBeenCalled();
});
it.each(["online-read","online-write","offline-read","offline-write"])("Native %s support-stamp completion retired with its view cannot show a late dialog",async phase=>{
  await mount();await complete("phq9",1);if(phase.startsWith("offline")){const fetchNative=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method==="POST")throw new TypeError("Native offline");return fetchNative(...args);});}
  const hold=gate(),read=storage.getItem.bind(storage),write=storage.setItem.bind(storage),slot=accountStorageKey.crisisItem9(USER);
  if(phase.endsWith("read"))vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===slot){hold.enter();await hold.promise;}return value;});
  else vi.spyOn(storage,"setItem").mockImplementation(async(name,value)=>{await write(name,value);if(name===slot){hold.enter();await hold.promise;}});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;hold.release();await flush();expect(Alert.alert).not.toHaveBeenCalled();if(phase.endsWith("read"))expect(await read(slot)).toBeNull();
});
it.each(["success","offline","native-cipher-refusal"])("Native %s submission retires physical data-key and plaintext copies",async outcome=>{
  await mount();await complete();const keys:Buffer[]=[],plains:Buffer[]=[],original=envelope.encrypt;
  vi.spyOn(envelope,"encrypt").mockImplementation((...args)=>{if(args[2]?.toString().startsWith('["measure",')){keys.push(args[0]);plains.push(args[1]);if(outcome==="native-cipher-refusal")throw new Error("Native cipher unavailable");}return original(...args);});
  if(outcome==="offline"){const fetchNative=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method==="POST")throw new TypeError("Native offline");return fetchNative(...args);});}
  await press("Record this check-in");await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));
  expect(keys).toHaveLength(1);expect(keys[0]!.every(value=>value===0)).toBe(true);expect(plains[0]!.every(value=>value===0)).toBe(true);expect(vault.get().dataKey).toEqual(KEY);
});
it("a mismatched Native credential receipt cannot read history or send the visible old-vault answers",async()=>{
  await api.setSession("mismatched Native bearer",OTHER,"bob");await mount(false);await vi.waitFor(()=>expect(words()).toContain("Could not load your measures."));expect(gets).toBe(0);
  await complete();await press("Record this check-in");await vi.waitFor(()=>expect(Alert.alert).toHaveBeenCalled());expect(sent).toHaveLength(0);expect(Alert.alert.mock.calls.at(-1)?.slice(0,2)).toEqual(["Not recorded","Could not record just now. Your picks are still on screen."]);inspect();
});
it("a Native missing credential id reports damaged submit without starting history or a send",async()=>{
  await secureStore.removeItem("@mindpattern/user_id");await mount(false);await vi.waitFor(()=>expect(words()).toContain("Could not load your measures."));expect(gets).toBe(0);
  await complete();await press("Record this check-in");await vi.waitFor(()=>expect(Alert.alert).toHaveBeenCalled());expect(Alert.alert.mock.calls.at(-1)?.slice(0,2)).toEqual(["Session damaged","Account id missing — please sign in again."]);expect(sent).toHaveLength(0);inspect();
});
it("a Native legacy vault with no verified owner admits no load or submission",async()=>{
  vault.unlock({masterKey:Buffer.alloc(32,4),authKey:Buffer.alloc(32,5),dataKey:Buffer.from(KEY)});await mount(false);expect(words()).toContain("Your keys are locked");await complete();await press("Record this check-in");expect(gets).toBe(0);expect(sent).toHaveLength(0);expect(Alert.alert).not.toHaveBeenCalled();inspect();
});
it("a same-account Native scope refresh before the first lookup receipt declines new history admission",async()=>{
  const hold=gate(),original=api.getUserId;let first=true;vi.spyOn(api,"getUserId").mockImplementation(async()=>{const value=await original();if(first){first=false;hold.enter();await hold.promise;}return value;});
  await mount(false);await vi.waitFor(()=>expect(hold.entered()).toBe(true));await api.setSession("refreshed Native bearer",USER,"alice");hold.release();await flush();expect(gets).toBe(0);
});
it("a Native status replacement remains visible until its own expiration",async()=>{
  await mount();await complete();vi.useFakeTimers();await press("Record this check-in");await vi.waitFor(()=>expect(words()).toContain("Recorded —"));await act(async()=>vi.advanceTimersByTimeAsync(1500));
  await complete();serverStatus=409;await press("Record this check-in");await vi.waitFor(()=>expect(words()).toContain("Already recorded"));await act(async()=>vi.advanceTimersByTimeAsync(1101));expect(words()).toContain("Already recorded");
  await act(async()=>vi.advanceTimersByTimeAsync(1500));expect(words()).not.toContain("Already recorded");inspect();vi.useRealTimers();
});
it("a Native view unmount cancels its finite status timer",async()=>{
  await mount();await complete();vi.useFakeTimers();await press("Record this check-in");await vi.waitFor(()=>expect(words()).toContain("Recorded —"));expect(vi.getTimerCount()).toBe(1);
  await act(async()=>root!.unmount());root=undefined;expect(vi.getTimerCount()).toBe(0);vi.useRealTimers();
});
it("two already queued Native Record taps admit one completed questionnaire",async()=>{
  await mount();await complete();const accepted=button("Record this check-in").props.onPress;
  await act(async()=>{accepted();accepted();});await vi.waitFor(()=>expect(words()).toContain("Recorded —"));expect(sent).toHaveLength(1);
});
it("a delayed Native pending restore retries its saved record while preserving newly edited visible answers",async()=>{
  await savePendingMeasure(KEY,USER,{kind:"gad7",clientMeasureId:"m-native-older-questionnaire",picks:[1,1,1,1,1,1,1],date:"2026-09-20"});const hold=gate(),read=storage.getItem.bind(storage);
  vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.pendingMeasure(USER)){hold.enter();await hold.promise;}return value;});
  await mount();await vi.waitFor(()=>expect(hold.entered()).toBe(true));await complete();hold.release();await vi.waitFor(()=>expect(words()).toContain("Recorded —"));
  expect(sent[0]!.client_measure_id).toBe("m-native-older-questionnaire");expect(button("PHQ-2 (brief, 2 items)").props.accessibilityState.selected).toBe(true);expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(true);expect(button("Record this check-in").props.disabled).toBe(false);
});
it.each(["complete","partial"])("a delayed Native PHQ-2 restore preserves %s new answers even when the saved picks match",async editing=>{
  await savePendingMeasure(KEY,USER,{kind:"phq2",clientMeasureId:"m-native-identical-prior-picks",picks:[0,0],date:"2026-09-20"});const hold=gate(),read=storage.getItem.bind(storage);
  vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.pendingMeasure(USER)){hold.enter();await hold.promise;}return value;});
  await mount();await vi.waitFor(()=>expect(hold.entered()).toBe(true));await press("PHQ-2 (brief, 2 items)");await press("Question 1: Not at all");if(editing==="complete")await press("Question 2: Not at all");expect(button("Record this check-in").props.disabled).toBe(true);
  hold.release();await vi.waitFor(()=>expect(words()).toContain("Recorded —"));expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(true);expect(button("PHQ-2 (brief, 2 items)").props.accessibilityState.selected).toBe(true);expect(button("Record this check-in").props.disabled).toBe(editing==="partial");inspect();
});
it("the first Native committed history frame honestly shows its pending load",async()=>{
  let initialSpinners:number|undefined;
  function InitialCommit(){React.useLayoutEffect(()=>{initialSpinners=root!.root.findAllByType(ActivityIndicator).length;},[]);return <MeasuresScreen navigation={navigation}/>;}
  await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><InitialCommit/></ThemeProvider>);});
  expect(initialSpinners).toBe(1);await vi.waitFor(()=>expect(words()).toContain("Nothing recorded yet."));inspect();
});
it.each(['{"measure":"future","score":2}','{"score":2}'])("Native history refuses a finite score without an accepted instrument: %s",async raw=>{
  serverRows=[row("unrecognized",raw)];await mount();expect(words()).not.toContain("Your recorded scores");expect(words()).not.toContain("September 20, 2026");inspect();
});
it("a later successful Native refresh clears an earlier history error",async()=>{
  const nativeFetch=globalThis.fetch;let refuse=true;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(refuse&&args[1]?.method!=="POST"){const response=new Response('{}',{status:500});Object.defineProperty(response,"url",{value:args[0]});return response;}return nativeFetch(...args);});
  await mount(false);await vi.waitFor(()=>expect(words()).toContain("server"));await complete();refuse=false;await press("Record this check-in");await vi.waitFor(()=>expect(words()).toContain("Nothing recorded yet."));expect(words()).not.toContain("server");inspect();
});
it("an unavailable Native refresh replaces previously loaded scores with the connection message",async()=>{
  serverRows=[row("prior",'{"measure":"phq2","score":3}')];await mount(false);await vi.waitFor(()=>expect(words()).toContain("September 20, 2026: 3"));await complete();const nativeFetch=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method!=="POST")throw new TypeError("Native history offline");return nativeFetch(...args);});
  await press("Record this check-in");await vi.waitFor(()=>expect(words()).toContain("Your recorded history needs a connection"));expect(words()).not.toContain("September 20, 2026: 3");inspect();
});
it.each(["offline","server"])("an earlier Native %s rejection cannot publish over a later accepted history",async outcome=>{
  const hold=gate(),original=api.listMeasures;vi.spyOn(api,"listMeasures").mockImplementationOnce(async()=>{hold.enter();await hold.promise;throw new (await import("../../src/api/client")).ApiError(outcome==="offline"?0:500,"old Native refusal");});
  await mount(false);await vi.waitFor(()=>expect(hold.entered()).toBe(true));await complete();serverRows=[row("new",'{"measure":"phq2","score":5}')];await press("Record this check-in");await vi.waitFor(()=>expect(words()).toContain("September 20, 2026: 5"));const before=publicSurface(root!);hold.release();await flush();expect(publicSurface(root!)).toEqual(before);expect(words()).not.toContain("connection");expect(original).toBeTypeOf("function");
});
it("an accepted Native pending-save receipt released after unmount cannot dispatch the old questionnaire",async()=>{
  await mount();await complete();const hold=gate(),write=storage.setItem.bind(storage);vi.spyOn(storage,"setItem").mockImplementation(async(name,value)=>{await write(name,value);if(name===accountStorageKey.pendingMeasure(USER)){hold.enter();await hold.promise;}});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;hold.release();await flush();await flush();expect(sent).toHaveLength(0);expect(await storage.getItem(accountStorageKey.pendingMeasure(USER))).toBeTruthy();
});
it("an accepted Native send released after same-account unmount preserves the pending receipt and retires its key",async()=>{
  await mount();await complete();const hold=gate(),create=api.createMeasure,encrypt=envelope.encrypt,keys:Buffer[]=[];vi.spyOn(envelope,"encrypt").mockImplementation((...args)=>{if(args[2]?.toString().startsWith('["measure",'))keys.push(args[0]);return encrypt(...args);});vi.spyOn(api,"createMeasure").mockImplementationOnce(async(...args)=>{const value=await create(...args);hold.enter();await hold.promise;return value;});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));const before=await storage.getItem(accountStorageKey.pendingMeasure(USER));expect(before).toBeTruthy();await act(async()=>root!.unmount());root=undefined;hold.release();await flush();await flush();expect(await storage.getItem(accountStorageKey.pendingMeasure(USER))).toBe(before);expect(keys).toHaveLength(1);expect(keys[0]!.every(value=>value===0)).toBe(true);
});
it("editing an offline Native questionnaire creates a fresh receipt for the new picks",async()=>{
  await mount();await complete();const nativeFetch=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method==="POST"){sent.push(JSON.parse(String(args[1].body)));throw new TypeError("Native offline after commit");}return nativeFetch(...args);});
  await press("Record this check-in");await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));expect(sent).toHaveLength(1);await press("Question 1: Several days");await press("Record this check-in");await vi.waitFor(()=>expect(sent).toHaveLength(2));expect(sent[0]!.client_measure_id).not.toBe(sent[1]!.client_measure_id);expect(JSON.parse(envelope.decrypt(KEY,Buffer.from(sent[1]!.blob,"base64"),envelope.buildAad("measure",USER,sent[1]!.client_measure_id)).toString()).score).toBe(1);expect(Alert.alert).not.toHaveBeenCalled();inspect();
});
it.each(["phq2","phq9"])("an unendorsed offline Native %s keeps its picks without offering the item-nine dialog",async kind=>{
  await mount();await complete(kind);const nativeFetch=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method==="POST")throw new TypeError("Native offline");return nativeFetch(...args);});await press("Record this check-in");await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));expect(Alert.alert).not.toHaveBeenCalled();expect(await storage.getItem(accountStorageKey.pendingMeasure(USER))).toBeTruthy();inspect();
});
it.each(["online","offline"])("Native %s storage refusal preserves the separate in-memory item-nine throttle",async mode=>{
  await mount();await complete("phq9",1);const nativeFetch=globalThis.fetch;if(mode==="offline")vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method==="POST")throw new TypeError("Native offline");return nativeFetch(...args);});const read=storage.getItem.bind(storage),write=storage.setItem.bind(storage),slot=accountStorageKey.crisisItem9(USER);
  vi.spyOn(storage,"getItem").mockImplementation(name=>name===slot?Promise.reject(new Error("Native stamp read unavailable")):read(name));vi.spyOn(storage,"setItem").mockImplementation((name,value)=>name===slot?Promise.reject(new Error("Native stamp write unavailable")):write(name,value));
  await press("Record this check-in");await vi.waitFor(()=>expect(Alert.alert).toHaveBeenCalledTimes(1));await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));if(mode==="online")await complete("phq9",1);await press("Record this check-in");await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));expect(Alert.alert).toHaveBeenCalledTimes(1);inspect();
});
it("Native key retirement after pending persistence prevents admitting the retired key to the measure cipher",async()=>{
  await mount();await complete();const hold=gate(),write=storage.setItem.bind(storage);vi.spyOn(storage,"setItem").mockImplementation(async(name,value)=>{await write(name,value);if(name===accountStorageKey.pendingMeasure(USER)){hold.enter();await hold.promise;}});
  await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));const cipher=envelope.encrypt,admitted:Buffer[]=[];vi.spyOn(envelope,"encrypt").mockImplementation((...args)=>{if(args[2]?.toString().startsWith('["measure",'))admitted.push(args[0]);return cipher(...args);});freezeLocalKeyWrites(USER);hold.release();await flush();await flush();expect(admitted).toHaveLength(0);expect(sent).toHaveLength(0);
});
it("a Native post-save history receipt cannot hold its retired submit key behind an unavailable support read",async()=>{
  await mount();await complete("phq9",1);const history=gate(),stamp=gate(),list=api.listMeasures,read=storage.getItem.bind(storage),cipher=envelope.encrypt,keys:Buffer[]=[];vi.spyOn(envelope,"encrypt").mockImplementation((...args)=>{if(args[2]?.toString().startsWith('["measure",'))keys.push(args[0]);return cipher(...args);});vi.spyOn(api,"listMeasures").mockImplementationOnce(async()=>{const rows=await list();history.enter();await history.promise;return rows;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{if(name===accountStorageKey.crisisItem9(USER)){stamp.enter();await stamp.promise;}return read(name);});
  await press("Record this check-in");await vi.waitFor(()=>expect(history.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;history.release();try{await flush();await flush();expect(keys).toHaveLength(1);expect(keys[0]!.every(value=>value===0)).toBe(true);expect(stamp.entered()).toBe(false);}finally{stamp.release();await flush();}
});
it("a decoded Native pending receipt delivered after same-account reauthentication cannot restore or send old answers",async()=>{
  const pending:PendingMeasure={kind:"gad7",clientMeasureId:"m-native-held-decoded",picks:[1,1,1,1,1,1,1],date:"2026-09-20"};await savePendingMeasure(KEY,USER,pending);const hold=gate(),load=pendingMeasure.loadPendingMeasure;
  vi.spyOn(pendingMeasure,"loadPendingMeasure").mockImplementationOnce(async(...args)=>{const decoded=await load(...args);expect(decoded).toEqual(pending);hold.enter();await hold.promise;return decoded;});await mount();await vi.waitFor(()=>expect(hold.entered()).toBe(true));const before=publicSurface(root!);await api.setSession("refreshed Native credential",USER,"alice");hold.release();await flush();await flush();expect(sent).toHaveLength(0);expect(publicSurface(root!)).toEqual(before);
});
it("a mismatched Native pending owner cannot admit the old-vault key to another account's unavailable encrypted queue",async()=>{
  await api.setSession("other Native account",OTHER,"bob");const read=storage.getItem.bind(storage),hold=gate(),clones:Buffer[]=[],from=Buffer.from,physicalKey=vault.get().dataKey;vi.spyOn(Buffer,"from").mockImplementation(((...args:Parameters<typeof Buffer.from>)=>{const value=from(...args);if(args[0]===physicalKey)clones.push(value);return value;})as typeof Buffer.from);vi.spyOn(storage,"getItem").mockImplementation(async name=>{if(name===accountStorageKey.pendingMeasure(OTHER)){hold.enter();await hold.promise;}return read(name);});
  await mount(false);await vi.waitFor(()=>expect(words()).toContain("Could not load your measures."));try{await flush();expect(hold.entered()).toBe(false);expect(clones.every(value=>value.every(byte=>byte===0))).toBe(true);}finally{hold.release();await flush();}
});
it("a retired Native mount-owner receipt cannot allocate a key copy behind an unavailable pending read",async()=>{
  const owner=gate(),pending=gate(),lookup=api.getUserId;let calls=0;vi.spyOn(api,"getUserId").mockImplementation(async()=>{const value=await lookup();if(++calls===2){owner.enter();await owner.promise;}return value;});await mount();await vi.waitFor(()=>expect(owner.entered()).toBe(true));const read=storage.getItem.bind(storage),clones:Buffer[]=[],from=Buffer.from,physicalKey=vault.get().dataKey;vi.spyOn(Buffer,"from").mockImplementation(((...args:Parameters<typeof Buffer.from>)=>{const value=from(...args);if(args[0]===physicalKey)clones.push(value);return value;})as typeof Buffer.from);vi.spyOn(storage,"getItem").mockImplementation(async name=>{if(name===accountStorageKey.pendingMeasure(USER)){pending.enter();await pending.promise;}return read(name);});
  await api.setSession("refreshed Native owner lookup",USER,"alice");owner.release();try{await flush();await flush();expect(pending.entered()).toBe(false);expect(clones.every(value=>value.every(byte=>byte===0))).toBe(true);}finally{pending.release();await flush();}
});
it("an installed Native responder granted before an instrument switch cannot submit its newly incomplete questionnaire",async()=>{
  await mount();await complete();const gesture=nativeGrantedPress(button("Record this check-in").props);try{await press("GAD-7 (anxiety, 7 items)");expect(button("Record this check-in").props.disabled).toBe(true);gesture.configure(button("Record this check-in").props);await act(async()=>gesture.release());await flush();expect(sent).toHaveLength(0);expect(await storage.getItem(accountStorageKey.pendingMeasure(USER))).toBeNull();expect(button("Record this check-in").props.accessibilityState.busy).toBe(false);inspect();}finally{gesture.dispose();}
});
it("a Native submit-owner receipt delivered after unmount cannot persist or send the retired questionnaire",async()=>{
  await mount();await complete();const hold=gate(),lookup=api.getUserId;vi.spyOn(api,"getUserId").mockImplementationOnce(async()=>{const owner=await lookup();hold.enter();await hold.promise;return owner;});await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));await act(async()=>root!.unmount());root=undefined;hold.release();await flush();await flush();expect(sent).toHaveLength(0);expect(await storage.getItem(accountStorageKey.pendingMeasure(USER))).toBeNull();
});
it("a successfully retried Native pending PHQ-2 can immediately accept the next completed questionnaire",async()=>{
  await savePendingMeasure(KEY,USER,{kind:"phq2",clientMeasureId:"m-native-restored-editor",picks:[0,1],date:"2026-09-20"});await mount(false);await vi.waitFor(()=>expect(words()).toContain("Recorded —"));expect(sent).toHaveLength(1);expect(button("PHQ-2 (brief, 2 items)").props.accessibilityState.selected).toBe(true);await press("Question 1: Not at all");await press("Question 2: Not at all");expect(button("Record this check-in").props.disabled).toBe(false);await press("Record this check-in");await vi.waitFor(()=>expect(sent).toHaveLength(2));expect(sent[1]!.client_measure_id).not.toBe(sent[0]!.client_measure_id);inspect();
});
it("a Native in-flight PHQ-9 save cannot reset a newly completed shorter instrument",async()=>{
  await mount();await complete("phq9");const hold=gate(),create=api.createMeasure;vi.spyOn(api,"createMeasure").mockImplementationOnce(async(...args)=>{const result=await create(...args);hold.enter();await hold.promise;return result;});await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));await complete();hold.release();await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));expect(button("PHQ-2 (brief, 2 items)").props.accessibilityState.selected).toBe(true);expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(true);expect(button("Question 2: Not at all").props.accessibilityState.selected).toBe(true);expect(button("Record this check-in").props.disabled).toBe(false);inspect();
});
it("a last-item Native tap after resetting an in-flight PHQ-9 remains selected when that older save completes",async()=>{
  await mount();await complete("phq9");const hold=gate(),create=api.createMeasure;vi.spyOn(api,"createMeasure").mockImplementationOnce(async(...args)=>{const result=await create(...args);hold.enter();await hold.promise;return result;});await press("Record this check-in");await vi.waitFor(()=>expect(hold.entered()).toBe(true));await press("PHQ-9 (depression, 9 items)");await press("Question 9: Not at all");hold.release();await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));expect(button("Question 9: Not at all").props.accessibilityState.selected).toBe(true);expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(false);expect(button("Record this check-in").props.disabled).toBe(true);inspect();
});
it("an installed Native last-item responder delivered before the restore commit preserves its pick through the mount retry",async()=>{
  await savePendingMeasure(KEY,USER,{kind:"phq9",clientMeasureId:"m-native-pending-partial-last",picks:[0,0,0,0,0,0,0,0,0],date:"2026-09-20"});const restore=gate(),send=gate(),read=storage.getItem.bind(storage),create=api.createMeasure,lookup=api.getUserId;let lookups=0,gesture:ReturnType<typeof nativeGrantedPress>|undefined,delivery:Promise<void>|undefined;
  vi.spyOn(api,"getUserId").mockImplementation(async()=>{if(++lookups===3){delivery=Promise.resolve().then(()=>{expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(false);gesture!.configure(button("Question 9: Not at all").props);gesture!.release();});}return lookup();});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.pendingMeasure(USER)){restore.enter();await restore.promise;}return value;});vi.spyOn(api,"createMeasure").mockImplementationOnce(async(...args)=>{const result=await create(...args);send.enter();await send.promise;return result;});await mount();await vi.waitFor(()=>expect(restore.entered()).toBe(true));gesture=nativeGrantedPress(button("Question 9: Not at all").props);try{restore.release();await vi.waitFor(()=>expect(send.entered()).toBe(true));await delivery;send.release();await vi.waitFor(()=>expect(button("Record this check-in").props.accessibilityState.busy).toBe(false));expect(button("Question 9: Not at all").props.accessibilityState.selected).toBe(true);expect(button("Question 1: Not at all").props.accessibilityState.selected).toBe(false);expect(button("Record this check-in").props.disabled).toBe(true);inspect();}finally{gesture.dispose();}
});
it.each(["online","offline"])("Native %s item-nine support uses its separate stamp despite an earlier journal prompt",async mode=>{
  await recordCrisisDialogShown(USER,localDateISO(),"journal");await mount();await complete("phq9",1);if(mode==="offline"){const nativeFetch=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(args[1]?.method==="POST")throw new TypeError("Native offline");return nativeFetch(...args);});}
  await press("Record this check-in");await vi.waitFor(()=>expect(Alert.alert).toHaveBeenCalled());expect(await secureStore.getItem(accountStorageKey.crisisItem9(USER))).toBe(localDateISO());expect(await secureStore.getItem(accountStorageKey.crisisJournal(USER))).toBe(localDateISO());inspect();
});
