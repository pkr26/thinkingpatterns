import { drainPortalDraftWritesForTests, runTestControl } from "./helpers/testControl";
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { encrypt, toBase64 } from "../src/crypto";
import { setKvBackendForTests } from "../src/kvstore";
import {  loadPortalDraft, savePortalDraft, usePortalDrafts, type DraftState } from "../src/noteDrafts";
import { flush, render, textOf } from "./helpers/rtr";

const key = new Uint8Array(32).fill(7);
const empty = (): DraftState => ({ text: {}, editing: null, pending: {} });
const saved: DraftState = { text: { general: "Saved earlier", pattern: "Earlier pattern note" }, editing: { id: "saved-note", text: "Saved edit" }, pending: { general: { client_note_id: "saved-request", blob: "sealed", text: "Saved pending text", pattern_pid: null } } };
let current!: ReturnType<typeof usePortalDrafts>;
let stored: Map<string, string>;
function Harness() {
  current = usePortalDrafts("therapist-1", "patient-1", key, []);
  return <p>{current.status}|{current.state.text.general ?? ""}</p>;
}
async function encoded(state: DraftState): Promise<string> {
  return toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify({ v: 1, state })), new TextEncoder().encode('["portal-draft","therapist-1","patient-1"]')));
}
beforeEach(() => {
  stored = new Map();
  runTestControl(setKvBackendForTests, { getItem: async id => stored.get(id) ?? null, setItem: async (id, value) => { stored.set(id, value); }, removeItem: async id => { stored.delete(id); } });
});
afterEach(() => vi.useRealTimers());

it("keeps an already-started replacement write authoritative when an earlier write completes",async()=>{
 const releases:Array<()=>void>=[];runTestControl(setKvBackendForTests, {getItem:async id=>stored.get(id)??null,setItem:(id,value)=>new Promise<void>(resolve=>{releases.push(()=>{stored.set(id,value);resolve();});}),removeItem:async()=>{}});
 const first=savePortalDraft("therapist-1","patient-1",key,{...empty(),text:{general:"first acknowledged snapshot"}});await vi.waitFor(()=>expect(releases).toHaveLength(1));const second=savePortalDraft("therapist-1","patient-1",key,{...empty(),text:{general:"replacement snapshot"}});releases[0]!();await first;await vi.waitFor(()=>expect(releases).toHaveLength(2));const reading=loadPortalDraft("therapist-1","patient-1",[key]);try{await flush(12);}finally{releases[1]!();await second;}await expect(reading).resolves.toMatchObject({text:{general:"replacement snapshot"}});
});

it.each(["restoring", "restored"])("retires host-held raw draft custody when leaving a %s view while preserving the caller's borrowed key",async stage=>{
 stored.set("portal.draft.therapist-1.patient-1",await encoded(saved));const native=crypto.subtle,importKey=native.importKey.bind(native),decrypt=native.decrypt.bind(native);const imported:Uint8Array[]=[];
 const importSpy=vi.spyOn(native,"importKey").mockImplementation(((...args:Parameters<SubtleCrypto["importKey"]>)=>{const [,material,algorithm]=args;if(algorithm==="AES-GCM"&&material instanceof Uint8Array)imported.push(material);return importKey(...args);}) as SubtleCrypto["importKey"]);
 let release:()=>void=()=>{};const decryptSpy=stage==="restoring"?vi.spyOn(native,"decrypt").mockImplementationOnce((...args)=>new Promise((resolve,reject)=>{release=()=>{void decrypt(...args).then(resolve,reject);};})):null;
 try{const root=await render(<Harness/>);await vi.waitFor(()=>expect(imported.length).toBeGreaterThan(0));if(stage==="restored")await vi.waitFor(()=>expect(current.restored).toBe(true));await act(async()=>root.unmount());if(stage==="restored")await drainPortalDraftWritesForTests();expect(imported.every(bytes=>bytes.every(byte=>byte===0))).toBe(true);expect(key.every(byte=>byte===7)).toBe(true);}finally{release();await flush(8);decryptSpy?.mockRestore();importSpy.mockRestore();}
});

it("merges writing made while a saved draft is restoring without losing pending requests", async () => {
  const encrypted = await encoded(saved);
  let resolveRead!: (value: string | null) => void;
  runTestControl(setKvBackendForTests, { getItem: () => new Promise(resolve => { resolveRead = resolve; }), setItem: async (id, value) => { stored.set(id, value); }, removeItem: async () => {} });
  const root = await render(<Harness />);
  expect(current.restored).toBe(false);
  expect(textOf(root)).toContain("Loading encrypted local draft…");
  await expect(current.persist()).rejects.toThrow("Existing local drafts have not been restored");
  const local: DraftState = { text: { general: "Typing now" }, editing: { id: "new-note", text: "Typing an edit" }, pending: { general: { client_note_id: "new-request", blob: "new-sealed", text: "New pending text", pattern_pid: null } } };
  await act(async () => { current.setState(local); resolveRead(encrypted); });
  await flush();
  expect(current.restored).toBe(true);
  expect(current.state).toEqual({ ...local, text: { ...saved.text, ...local.text } });
  expect(textOf(root)).toContain("Restored encrypted local draft.");
});

it("restores the unchanged draft, supports functional edits, and persists an explicit snapshot", async () => {
  stored.set("portal.draft.therapist-1.patient-1", await encoded(saved));
  const root = await render(<Harness />);
  await vi.waitFor(() => expect(current.state).toEqual(saved));
  expect(current.state).toEqual(saved);
  await act(async () => { current.setState(previous => ({ ...previous, text: { ...previous.text, general: "Changed writing" } })); });
  expect(current.state.text.general).toBe("Changed writing");
  await act(async () => { await current.persist(); });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(current.state);
  expect(textOf(root)).toContain("Draft saved encrypted on this device.");
  const explicit = { ...current.state, text: { general: "Explicit save" } };
  await act(async () => { await current.persist(explicit); });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(explicit);
});

it("publishes a functional draft update immediately for a caller's same-action durable save", async () => {
  await render(<Harness />);await flush();
  await act(async()=>{
    current.setState(previous=>({...previous,text:{...previous.text,general:"Immediate functional snapshot"}}));
    await current.persist();
  });
  await expect(loadPortalDraft("therapist-1","patient-1",[key])).resolves.toMatchObject({text:{general:"Immediate functional snapshot"}});
});

it("uses the latest restore request if two reads resolve out of order", async () => {
  const oldRow = await encoded(saved);
  const newest = { ...empty(), text: { general: "Newest stored version" } };
  const newRow = await encoded(newest);
  const reads: Array<(value: string | null) => void> = [];
  runTestControl(setKvBackendForTests, { getItem: () => new Promise(resolve => { reads.push(resolve); }), setItem: async () => {}, removeItem: async () => {} });
  await render(<Harness />);
  let retry!: Promise<void>;
  await act(async () => { retry = current.restore(); });
  expect(reads).toHaveLength(2);
  await act(async () => { reads[1]!(newRow); await retry; });
  expect(current.state).toEqual(newest);
  await act(async () => { reads[0]!(oldRow); });
  await flush();
  expect(current.state).toEqual(newest);
});

it("ignores an older restore failure after a newer restore has completed",async()=>{
  const reads:Array<{resolve:(value:string|null)=>void,reject:(error:unknown)=>void}>=[];
  runTestControl(setKvBackendForTests, {getItem:()=>new Promise((resolve,reject)=>{reads.push({resolve,reject});}),setItem:async()=>{},removeItem:async()=>{}});
  const root=await render(<Harness/>);let newest!:Promise<void>;
  await act(async()=>{newest=current.restore();});
  await act(async()=>{reads[1]!.resolve(null);await newest;});
  await act(async()=>{reads[0]!.reject(new Error("obsolete read failed"));});await flush();
  expect(current.restored).toBe(true);expect(textOf(root)).toContain("Drafts are encrypted on this device.");expect(textOf(root)).not.toContain("Local encrypted records could not be read");
});

it("does not restore data or allow new saves after its view is unmounted", async () => {
  const row = await encoded(saved);
  let resolveRead!: (value: string | null) => void;
  runTestControl(setKvBackendForTests, { getItem: () => new Promise(resolve => { resolveRead = resolve; }), setItem: async () => {}, removeItem: async () => {} });
  const root = await render(<Harness />);
  const abandoned = current;
  await act(async () => { root.unmount(); resolveRead(row); });
  await flush();
  expect(abandoned.state).toEqual(empty());
  await expect(abandoned.persist()).rejects.toThrow("This draft view is no longer active");
});

it("preserves an acknowledged earlier draft if its replacement view leaves before restoration completes",async()=>{
 const original=await encoded(saved);stored.set("portal.draft.therapist-1.patient-1",original);let release!:(value:string)=>void;let first=true;
 runTestControl(setKvBackendForTests, {getItem:async id=>{if(first){first=false;return new Promise<string>(resolve=>{release=resolve;});}return stored.get(id)??null;},setItem:async(id,value)=>{stored.set(id,value);},removeItem:async()=>{}});
 const root=await render(<Harness/>);await act(async()=>root.unmount());try{await expect(loadPortalDraft("therapist-1","patient-1",[key])).resolves.toEqual(saved);}finally{release(original);await flush();}
});

it("restores acknowledged writing without reporting a failed autosave while the clinician only reads it",async()=>{
 stored.set("portal.draft.therapist-1.patient-1",await encoded(saved));runTestControl(setKvBackendForTests, {getItem:async id=>stored.get(id)??null,setItem:async()=>{throw new Error("new writes denied");},removeItem:async()=>{}});vi.useFakeTimers();const root=await render(<Harness/>);await flush();expect(current.restored).toBe(true);expect(textOf(root)).toContain("Restored encrypted local draft.");await act(async()=>{vi.advanceTimersByTime(250);});await flush();expect(textOf(root)).toContain("Restored encrypted local draft.");expect(textOf(root)).not.toContain("Writing was not saved");
});

it("retains visible writing and reports a failed durable save so it can be retried", async () => {
  const root = await render(<Harness />);
  await flush();
  await act(async () => { current.setState({ ...empty(), text: { general: "Keep this writing" } }); });
  runTestControl(setKvBackendForTests, { getItem: async () => null, setItem: async () => { throw new Error("quota denied"); }, removeItem: async () => {} });
  await act(async () => { await expect(current.persist()).rejects.toThrow("Writing was not saved on this device"); });
  expect(textOf(root)).toContain("Writing was not saved on this device");
  expect(current.state.text.general).toBe("Keep this writing");
});

it("autosaves after the full debounce and flushes its last snapshot when leaving", async () => {
  const root = await render(<Harness />);
  await flush();
  vi.useFakeTimers();
  const before = stored.size;
  await act(async () => { vi.advanceTimersByTime(250); });
  expect(stored.size).toBe(before);
  await act(async () => { current.setState({ ...empty(), text: { general: "Debounced writing" } }); });
  await act(async () => { vi.advanceTimersByTime(100); current.setState({ ...empty(), text: { general: "Debounced latest writing" } }); });
  await act(async () => { vi.advanceTimersByTime(249); });
  expect(stored.size).toBe(before);
  await act(async () => { vi.advanceTimersByTime(1); await drainPortalDraftWritesForTests(); });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toMatchObject({ text: { general: "Debounced latest writing" } });
  await act(async () => { current.setState({ ...empty(), text: { general: "Last writing before leaving" } }); });
  await act(async () => { root.unmount(); await drainPortalDraftWritesForTests(); });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toMatchObject({ text: { general: "Last writing before leaving" } });
});

it("retires a pending autosave timer when the clinician leaves before its debounce",async()=>{
 const root=await render(<Harness/>);await flush();vi.useFakeTimers();await act(async()=>current.setState({...empty(),text:{general:"Writing before leaving"}}));expect(vi.getTimerCount()).toBe(1);await act(async()=>root.unmount());expect(vi.getTimerCount()).toBe(0);await expect(loadPortalDraft("therapist-1","patient-1",[key])).resolves.toMatchObject({text:{general:"Writing before leaving"}});
});

it("keeps the draft locked after a restore failure and recovers through an explicit retry", async () => {
  runTestControl(setKvBackendForTests, { getItem: async () => { throw new Error("storage denied"); }, setItem: async () => {}, removeItem: async () => {} });
  const root = await render(<Harness />);
  await flush();
  expect(current.restored).toBe(false);
  expect(textOf(root)).toContain("Local encrypted records could not be read");
  await expect(current.persist()).rejects.toThrow("Existing local drafts have not been restored");
  runTestControl(setKvBackendForTests, { getItem: async () => null, setItem: async (id, value) => { stored.set(id, value); }, removeItem: async () => {} });
  await act(async () => { await current.restore(); });
  expect(current.restored).toBe(true);
  expect(textOf(root)).toContain("Drafts are encrypted on this device.");
});
