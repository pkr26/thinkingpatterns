import { drainPortalDraftWritesForTests, runTestControl } from "./helpers/testControl";
import { beforeEach, expect, it, vi } from "vitest";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto";
import { setKvBackendForTests } from "../src/kvstore";
import {  loadPortalDraft, savePortalDraft, type DraftState } from "../src/noteDrafts";

const key = new Uint8Array(32).fill(7);
const otherKey = new Uint8Array(32).fill(9);
let stored: Map<string, string>;
const state: DraftState = {
  text: { general: "A clinician's unsent observation" },
  editing: { id: "note-1", text: "Amended note" },
  pending: { general: { client_note_id: "request-1", blob: "encrypted-request", text: "Exact pending text", pattern_pid: null } },
};
const aad = (owner = "therapist-1", patient = "patient-1") => new TextEncoder().encode(JSON.stringify(["portal-draft", owner, patient]));
async function seed(row: unknown) {
  const body = new TextEncoder().encode(JSON.stringify(row));
  stored.set("portal.draft.therapist-1.patient-1", toBase64(await encrypt(key, body, aad())));
}
beforeEach(() => {
  stored = new Map();
  runTestControl(setKvBackendForTests, {
    getItem: async id => stored.get(id) ?? null,
    setItem: async (id, value) => { stored.set(id, value); },
    removeItem: async id => { stored.delete(id); },
    keys: async () => [...stored.keys()],
  });
});

it("encrypts and restores the complete draft and exact pending request", async () => {
  await savePortalDraft("therapist-1", "patient-1", key, state);
  const raw = stored.get("portal.draft.therapist-1.patient-1")!;
  expect(raw).not.toContain("clinician");
  const plain = await decrypt(key, fromBase64(raw), aad());
  expect(JSON.parse(new TextDecoder().decode(plain))).toEqual({ v: 1, state });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(state);
  expect(key).toEqual(new Uint8Array(32).fill(7));
});

it("returns null for an absent draft and authenticates historical custody in order", async () => {
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toBeNull();
  await seed({ v: 1, state });
  await expect(loadPortalDraft("therapist-1", "patient-1", [otherKey, key])).resolves.toEqual(state);
  await expect(loadPortalDraft("therapist-1", "patient-1", [otherKey])).rejects.toThrow("could not be authenticated");
  await expect(loadPortalDraft("therapist-1", "patient-1", [])).rejects.toThrow("could not be authenticated");
});

it("scrubs the host-returned decrypted draft buffer after validation and restoration",async()=>{
  await seed({v:1,state});
  const native=crypto.subtle.decrypt.bind(crypto.subtle);const held:ArrayBuffer[]=[];
  const spy=vi.spyOn(crypto.subtle,"decrypt").mockImplementation(async(...args)=>{const plain=await native(...args);held.push(plain);return plain;});
  try{await expect(loadPortalDraft("therapist-1","patient-1",[key])).resolves.toEqual(state);expect(held).toHaveLength(1);expect(new Uint8Array(held[0]!).every(byte=>byte===0)).toBe(true);}finally{spy.mockRestore();}
});

it("serializes a third draft save behind a second save that is still committing",async()=>{
  const releases:Array<()=>void>=[];const entered:Array<string>=[];
  runTestControl(setKvBackendForTests, {getItem:async id=>stored.get(id)??null,setItem:async(id,value)=>{entered.push(value);await new Promise<void>(resolve=>{releases.push(resolve);});stored.set(id,value);},removeItem:async()=>{}});
  const first=savePortalDraft("therapist-1","patient-1",key,state);
  const second=savePortalDraft("therapist-1","patient-1",key,{...state,text:{general:"Second writing"}});
  await vi.waitFor(()=>expect(releases).toHaveLength(1));releases[0]!();await first;
  await vi.waitFor(()=>expect(releases).toHaveLength(2));
  const third=savePortalDraft("therapist-1","patient-1",key,{...state,text:{general:"Third writing"}});
  try{for(let step=0;step<10;step++)await Promise.resolve();expect(entered).toHaveLength(2);}finally{
    releases[1]!();await second;await vi.waitFor(()=>expect(releases).toHaveLength(3));releases[2]!();await third;
  }
  await expect(loadPortalDraft("therapist-1","patient-1",[key])).resolves.toMatchObject({text:{general:"Third writing"}});
});

it("binds encrypted drafts to the therapist and patient even if storage is copied", async () => {
  await seed({ v: 1, state });
  const raw = stored.values().next().value!;
  stored.set("portal.draft.therapist-2.patient-1", raw);
  stored.set("portal.draft.therapist-1.patient-2", raw);
  await expect(loadPortalDraft("therapist-2", "patient-1", [key])).rejects.toThrow("could not be authenticated");
  await expect(loadPortalDraft("therapist-1", "patient-2", [key])).rejects.toThrow("could not be authenticated");
});

it("preserves newer serialized saves when multiple writes overlap", async () => {
  const first = savePortalDraft("therapist-1", "patient-1", key, state);
  const latest = { ...state, text: { general: "Latest writing" } };
  const second = savePortalDraft("therapist-1", "patient-1", key, latest);
  await Promise.all([first, second]);
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(latest);
});

it.each([false, true])("scrubs provider-held encryption inputs after a draft commit (failure=%s)", async failure => {
  const subtle = crypto.subtle;
  const importKey = subtle.importKey.bind(subtle);
  const encryptNative = subtle.encrypt.bind(subtle);
  const heldKeys: Uint8Array[] = [];
  const heldPlain: Uint8Array[] = [];
  const keySpy = vi.spyOn(subtle, "importKey").mockImplementation((...args: Parameters<SubtleCrypto["importKey"]>) => {
    if (args[0] === "raw" && args[2] === "AES-GCM") heldKeys.push(args[1] as Uint8Array);
    return importKey(...args);
  });
  const plainSpy = vi.spyOn(subtle, "encrypt").mockImplementation((...args) => {
    heldPlain.push(args[2] as Uint8Array);
    return encryptNative(...args);
  });
  try {
    if (failure) runTestControl(setKvBackendForTests, { getItem: async () => null, setItem: async () => { throw new Error("quota"); }, removeItem: async () => {} });
    const operation = savePortalDraft("therapist-1", "patient-1", key, state);
    if (failure) await expect(operation).rejects.toThrow("Writing was not saved"); else await operation;
    expect(heldKeys).toHaveLength(1);
    expect(heldPlain).toHaveLength(1);
    expect(heldKeys[0]!.every(byte => byte === 0)).toBe(true);
    expect(heldPlain[0]!.every(byte => byte === 0)).toBe(true);
    expect(key).toEqual(new Uint8Array(32).fill(7));
  } finally { keySpy.mockRestore(); plainSpy.mockRestore(); }
});

it("keeps the lifecycle drain pending until all committed writes finish", async () => {
  let release!: () => void;
  let entered!: () => void;
  const entry = new Promise<void>(resolve => { entered = resolve; });
  runTestControl(setKvBackendForTests, { getItem: async () => null, setItem: async () => { entered(); await new Promise<void>(resolve => { release = resolve; }); }, removeItem: async () => {} });
  const write = savePortalDraft("therapist-1", "patient-1", key, state);
  await entry;
  let drained = false;
  const drain = drainPortalDraftWritesForTests().then(() => { drained = true; });
  try {
    for (let step = 0; step < 5; step++) await Promise.resolve();
    expect(drained).toBe(false);
  } finally { release(); await write; await drain; }
  expect(drained).toBe(true);
});

it("accepts the documented size boundaries and a pattern-scoped operation", async () => {
  const boundary: DraftState = {
    text: { ["s".repeat(1200)]: "t".repeat(100000) },
    editing: { id: "note-boundary", text: "e".repeat(100000) },
    pending: { pattern: { client_note_id: "operation-boundary", blob: "b".repeat(300000), text: "p".repeat(100000), pattern_pid: "pattern-1" } },
  };
  await seed({ v: 1, state: boundary });
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).resolves.toEqual(boundary);
});

const invalidStates = [
  { v: 2, state }, { v: 1 }, { v: 1, state: null },
  { v: 1, state: { ...state, text: 42 } },
  { v: 1, state: { ...state, text: { invalid: 42 } } },
  { v: 1, state: { ...state, text: { ["s".repeat(1201)]: "text" } } },
  { v: 1, state: { ...state, text: { scope: "t".repeat(100001) } } },
  { v: 1, state: { ...state, editing: {} } },
  { v: 1, state: { ...state, editing: { id: 12, text: "text" } } },
  { v: 1, state: { ...state, editing: { id: "note-1", text: 12 } } },
  { v: 1, state: { ...state, editing: { id: "note-1", text: "t".repeat(100001) } } },
  { v: 1, state: { ...state, pending: null } },
  { v: 1, state: { ...state, pending: 42 } },
  ...[null, {}, { ...state.pending.general, client_note_id: 12 }, { ...state.pending.general, blob: 12 }, { ...state.pending.general, blob: "b".repeat(300001) }, { ...state.pending.general, text: 12 }, { ...state.pending.general, text: "t".repeat(100001) }, { ...state.pending.general, pattern_pid: 12 }].map(pending => ({ v: 1, state: { ...state, pending: { general: pending } } })),
];
it.each(invalidStates.map((row, index) => ({ row, index })))("rejects authenticated malformed draft $index without exposing it", async ({ row }) => {
  await seed(row);
  await expect(loadPortalDraft("therapist-1", "patient-1", [key])).rejects.toThrow("could not be authenticated");
});
