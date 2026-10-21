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

it("keeps an already-started replacement write authoritative when an earlier write completes", async () => {
  const releases: Array<() => void> = [];
  const operations: Promise<unknown>[] = [];
  let finishing = false;
  const own = <T,>(operation: Promise<T>): Promise<T> => {
    operations.push(operation);
    void operation.catch(() => undefined);
    return operation;
  };
  try {
    runTestControl(setKvBackendForTests, {
      getItem: async id => stored.get(id) ?? null,
      setItem: (id, value) => new Promise<void>(resolve => {
        let released = false;
        const release = () => {
          if (released) return;
          released = true;
          stored.set(id, value);
          resolve();
        };
        releases.push(release);
        if (finishing) release();
      }),
      removeItem: async () => {},
    });
    const first = own(savePortalDraft("therapist-1", "patient-1", key, { ...empty(), text: { general: "first acknowledged snapshot" } }));
    await vi.waitFor(() => expect(releases).toHaveLength(1));
    const second = own(savePortalDraft("therapist-1", "patient-1", key, { ...empty(), text: { general: "replacement snapshot" } }));
    releases[0]!();
    await first;
    await vi.waitFor(() => expect(releases).toHaveLength(2));
    const reading = own(loadPortalDraft("therapist-1", "patient-1", [key]));
    await flush(12);
    releases[1]!();
    await second;
    await expect(reading).resolves.toMatchObject({ text: { general: "replacement snapshot" } });
  } finally {
    finishing = true;
    for (const release of releases) release();
    // Every operation is awaited on success; drain without masking an earlier assertion.
    await Promise.allSettled(operations);
  }
});

it.each(["restoring", "restored"])("retires host-held raw draft custody when leaving a %s view while preserving the caller's borrowed key",async stage=>{
 stored.set("portal.draft.therapist-1.patient-1",await encoded(saved));const native=crypto.subtle,importKey=native.importKey.bind(native),decrypt=native.decrypt.bind(native);const imported:Uint8Array[]=[];
 const importSpy=vi.spyOn(native,"importKey").mockImplementation(((...args:Parameters<SubtleCrypto["importKey"]>)=>{const [,material,algorithm]=args;if(algorithm==="AES-GCM"&&material instanceof Uint8Array)imported.push(material);return importKey(...args);}) as SubtleCrypto["importKey"]);
 let release:()=>void=()=>{};const decryptSpy=stage==="restoring"?vi.spyOn(native,"decrypt").mockImplementationOnce((...args)=>new Promise((resolve,reject)=>{release=()=>{void decrypt(...args).then(resolve,reject);};})):null;
 try{const root=await render(<Harness/>);await vi.waitFor(()=>expect(imported.length).toBeGreaterThan(0));if(stage==="restored")await vi.waitFor(()=>expect(current.restored).toBe(true));await act(async()=>root.unmount());if(stage==="restored")await drainPortalDraftWritesForTests();expect(imported.every(bytes=>bytes.every(byte=>byte===0))).toBe(true);expect(key.every(byte=>byte===7)).toBe(true);}finally{release();await flush(8);decryptSpy?.mockRestore();importSpy.mockRestore();}
});

it("merges writing made while a saved draft is restoring without losing pending requests", async () => {
  const encrypted = await encoded(saved);
  let resolveRead: ((value: string | null) => void) | undefined;
  runTestControl(setKvBackendForTests, { getItem: () => new Promise(resolve => { resolveRead = resolve; }), setItem: async (id, value) => { stored.set(id, value); }, removeItem: async () => {} });
  const native = crypto.subtle, importKey = native.importKey.bind(native), decrypt = native.decrypt.bind(native);
  const nativeOperations = new Set<Promise<unknown>>();
  const observe = <T,>(operation: Promise<T>): Promise<T> => {
    nativeOperations.add(operation);
    void operation.then(() => nativeOperations.delete(operation), () => nativeOperations.delete(operation));
    return operation;
  };
  const importSpy = vi.spyOn(native, "importKey").mockImplementation(((...args: Parameters<SubtleCrypto["importKey"]>) => observe(importKey(...args))) as SubtleCrypto["importKey"]);
  const decryptSpy = vi.spyOn(native, "decrypt").mockImplementation((...args) => observe(decrypt(...args)));
  let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    root = await render(<Harness />);
    expect(current.restored).toBe(false);
    expect(textOf(root)).toContain("Loading encrypted local draft…");
    await expect(current.persist()).rejects.toThrow("Existing local drafts have not been restored");
    const local: DraftState = { text: { general: "Typing now" }, editing: { id: "new-note", text: "Typing an edit" }, pending: { general: { client_note_id: "new-request", blob: "new-sealed", text: "New pending text", pattern_pid: null } } };
    await act(async () => { current.setState(local); resolveRead!(encrypted); });
    // The native decrypt is asynchronous; wait for the hook's public restored
    // publication rather than assuming three microtask-only acts complete it.
    await vi.waitFor(() => expect(current.restored).toBe(true));
    expect(current.restored).toBe(true);
    expect(current.state).toEqual({ ...local, text: { ...saved.text, ...local.text } });
    expect(textOf(root)).toContain("Restored encrypted local draft.");
  } finally {
    try {
      await act(async () => { resolveRead?.(encrypted); });
      while (nativeOperations.size > 0) {
        await act(async () => { await Promise.allSettled([...nativeOperations]); });
      }
    } finally {
      try { if (root) await act(async () => { root!.unmount(); }); }
      finally {
        try { await drainPortalDraftWritesForTests(); }
        finally { decryptSpy.mockRestore(); importSpy.mockRestore(); }
      }
    }
  }
});

it("restores the unchanged draft, supports functional edits, and persists an explicit snapshot", async () => {
  stored.set("portal.draft.therapist-1.patient-1", await encoded(saved));
  const root = await render(<Harness />);
  await vi.waitFor(() => expect(current.state).toEqual(saved));
  expect(current.state).toEqual(saved);
  vi.useFakeTimers();
  await act(async () => { current.setState(previous => ({ ...previous, text: { ...previous.text, general: "Changed writing" } })); });
  expect(current.state.text.general).toBe("Changed writing");
  await act(async () => { await current.persist(); });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(current.state);
  expect(textOf(root)).toContain("Draft saved encrypted on this device.");
  const explicit = { ...current.state, text: { general: "Explicit save" } };
  await act(async () => { await current.persist(explicit); });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(explicit);

  // Finish the already-scheduled debounce under the controlled clock before
  // another acknowledged writer updates the same encrypted storage slot.
  await act(async () => { await vi.advanceTimersByTimeAsync(250); await drainPortalDraftWritesForTests(); });
  const newer: DraftState = {
    text: { general: "Newer acknowledged writing", pattern: "Newer pattern writing" },
    editing: { id: "newer-note", text: "Newer acknowledged edit" },
    pending: { general: { client_note_id: "newer-request", blob: "newer-sealed-request", text: "Newer pending writing", pattern_pid: null } },
  };
  const native = crypto.subtle, originalEncrypt = native.encrypt, originalDecrypt = native.decrypt;
  const originals: Promise<ArrayBuffer>[] = [], nativeCensus: Array<Record<string, unknown>> = [];
  let refresh = true;
  const observe = (method: "encrypt" | "decrypt", args: Parameters<SubtleCrypto["encrypt"]>, original: Promise<ArrayBuffer>) => {
    originals.push(original);
    if (refresh) {
      const parameters = args[0] as AesGcmParams;
      nativeCensus.push({ method, aad: new TextDecoder().decode(parameters.additionalData), algorithm: args[1].algorithm.name,
        length: (args[1].algorithm as AesKeyAlgorithm).length, type: args[1].type, extractable: args[1].extractable, usages: [...args[1].usages],
        ivBytes: parameters.iv.byteLength, plaintext: method === "encrypt" ? new TextDecoder().decode(args[2]) : null });
    }
    return original;
  };
  const encryptObserver = vi.spyOn(native, "encrypt").mockImplementation((...args) => observe("encrypt", args, originalEncrypt.apply(native, args)));
  const decryptObserver = vi.spyOn(native, "decrypt").mockImplementation((...args) => observe("decrypt", args, originalDecrypt.apply(native, args)));
  try {
    await savePortalDraft("therapist-1", "patient-1", key, newer);
    const encrypted = stored.get("portal.draft.therapist-1.patient-1");
    // No setState occurs during this explicit, same-context restore.
    await act(async () => { await current.restore(); });
    await Promise.all(originals);
    const nativeKey = { aad: '["portal-draft","therapist-1","patient-1"]', algorithm: "AES-GCM", length: 256,
      type: "secret", extractable: false, usages: ["encrypt", "decrypt"], ivBytes: 12 };
    expect(nativeCensus).toEqual([{ method: "encrypt", ...nativeKey, plaintext: JSON.stringify({ v: 1, state: newer }) }, { method: "decrypt", ...nativeKey, plaintext: null }]);
    expect(encrypted).not.toContain(newer.text.general);
    expect(current.state, "an unchanged public restore must replace all documented fields with the newer acknowledged encrypted snapshot").toEqual(newer);
    expect(textOf(root)).toContain(newer.text.general);
    expect([...key]).toEqual(Array(32).fill(7));
  } finally {
    refresh = false;
    const cleanupFaults: unknown[] = [];
    try { await act(async () => root.unmount()); } catch (error) { cleanupFaults.push(error); }
    try { await drainPortalDraftWritesForTests(); } catch (error) { cleanupFaults.push(error); }
    for (;;) {
      const snapshot = [...originals], settled = await Promise.allSettled(snapshot);
      for (const result of settled) if (result.status === "rejected") cleanupFaults.push(result.reason);
      if (snapshot.length === originals.length) break;
    }
    encryptObserver.mockRestore(); decryptObserver.mockRestore();
    if (cleanupFaults.length) throw cleanupFaults[0];
  }
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
 vi.useRealTimers();
 stored.set("portal.draft.therapist-1.patient-1",await encoded(saved));
 runTestControl(setKvBackendForTests, {getItem:async id=>stored.get(id)??null,setItem:async()=>{throw new Error("new writes denied");},removeItem:async()=>{}});
 const native=crypto.subtle,importKey=native.importKey.bind(native),decrypt=native.decrypt.bind(native),encrypt=native.encrypt.bind(native);
 const nativeOperations=new Set<Promise<unknown>>();
 const observe=<T,>(operation:Promise<T>):Promise<T>=>{
   nativeOperations.add(operation);
   void operation.then(()=>nativeOperations.delete(operation),()=>nativeOperations.delete(operation));
   return operation;
 };
 const importSpy=vi.spyOn(native,"importKey").mockImplementation(((...args:Parameters<SubtleCrypto["importKey"]>)=>observe(importKey(...args))) as SubtleCrypto["importKey"]);
 const decryptSpy=vi.spyOn(native,"decrypt").mockImplementation((...args)=>observe(decrypt(...args)));
 const encryptSpy=vi.spyOn(native,"encrypt").mockImplementation((...args)=>observe(encrypt(...args)));
 let root:Awaited<ReturnType<typeof render>>|undefined;
 try{
   vi.useFakeTimers({shouldAdvanceTime:false});
   root=await render(<Harness/>);
   await vi.waitFor(()=>expect(current.restored).toBe(true),{timeout:10000,interval:0});
   await flush();
   expect(current.restored).toBe(true);
   expect(textOf(root)).toContain("Restored encrypted local draft.");
   await act(async()=>{vi.advanceTimersByTime(250);});
   await flush();
   expect(textOf(root)).toContain("Restored encrypted local draft.");
   expect(textOf(root)).not.toContain("Writing was not saved");
 }finally{
   vi.useRealTimers();
   try{
     while(nativeOperations.size>0){await act(async()=>{await Promise.allSettled([...nativeOperations]);});}
   }finally{
     try{if(root)await act(async()=>root!.unmount());}
     finally{
       try{
         await drainPortalDraftWritesForTests();
         while(nativeOperations.size>0){await act(async()=>{await Promise.allSettled([...nativeOperations]);});}
       }finally{encryptSpy.mockRestore();decryptSpy.mockRestore();importSpy.mockRestore();}
     }
   }
 }
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
