/** Encrypted local clinician drafts, including exact idempotent note requests. */
import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { buildAad } from "./aad";
import { decrypt, encrypt, fromBase64, toBase64, type Bytes } from "./crypto";
import { kv } from "./kvstore";

export interface DraftState {
  text: Record<string, string>;
  editing: {
    id: string;
    text: string;
  } | null;
  pending: Record<string, {
    client_note_id: string;
    blob: string;
    text: string;
    pattern_pid: string | null;
  }>;
}
const emptyDraftState = (): DraftState => ({ text: {}, editing: null, pending: {} });
const pendingDraftWrites = new Map<string, Promise<unknown>>();
const draftStorageKey = (owner: string, patient: string) => `portal.draft.${owner}.${patient}`;

/** Test lifecycle seam: callers must drain encrypted writes before replacing
 * the injected storage backend. Production never swaps its IndexedDB backend. */

export async function drainPortalDraftWritesForTests(): Promise<void> {
  while (pendingDraftWrites.size > 0)
    await Promise.allSettled([...pendingDraftWrites.values()]);
}

export async function savePortalDraft(owner: string, patient: string, key: Bytes, state: DraftState): Promise<void> {
  const id = draftStorageKey(owner, patient);
  const keyCopy = new Uint8Array(key);
  const plain = new TextEncoder().encode(JSON.stringify({ v: 1, state }));
  const run = async () => {
    try {
      await kv.setItem(id, toBase64(await encrypt(keyCopy, plain, buildAad("portal-draft", owner, patient))));
    } finally {
      keyCopy.fill(0);
      plain.fill(0);
    }
  };
  const result = (pendingDraftWrites.get(id) ?? Promise.resolve()).then(run, run);
  const tail = result.catch(() => undefined);
  pendingDraftWrites.set(id, tail);
  void tail.then(() => {
    if (pendingDraftWrites.get(id) === tail)
      pendingDraftWrites.delete(id);
  });
  await result;
}

export async function loadPortalDraft(owner: string, patient: string, keys: Bytes[]): Promise<DraftState | null> {
  await pendingDraftWrites.get(draftStorageKey(owner, patient));
  const raw = await kv.getItem(draftStorageKey(owner, patient));
  if (!raw)
    return null;
  for (const key of keys) {
    let plain: Bytes | null = null;
    try {
      plain = await decrypt(key, fromBase64(raw), buildAad("portal-draft", owner, patient));
      const row = JSON.parse(new TextDecoder().decode(plain));
      if (row?.v !== 1 || !row.state || typeof row.state.text !== "object" || !row.state.pending || typeof row.state.pending !== "object")
        throw new Error("Invalid draft.");
      for (const [scope, text] of Object.entries(row.state.text))
        if (scope.length > 1200 || typeof text !== "string" || text.length > 100000)
          throw new Error("Invalid draft text.");
      const edit = row.state.editing;
      if (edit !== null && (!edit || typeof edit.id !== "string" || typeof edit.text !== "string" || edit.text.length > 100000))
        throw new Error("Invalid draft edit.");
      for (const pending of Object.values(row.state.pending) as Array<Record<string, unknown>>)
        if (!pending || typeof pending.client_note_id !== "string" || typeof pending.blob !== "string" || pending.blob.length > 300000 || typeof pending.text !== "string" || pending.text.length > 100000 || (pending.pattern_pid !== null && typeof pending.pattern_pid !== "string"))
          throw new Error("Invalid draft operation.");
      return row.state as DraftState;
    } catch { /* authenticated historical custody can unlock an older draft */ } finally {
      plain?.fill(0);
    }
  }
  throw new Error("A saved local draft could not be authenticated. Keep this view open and check account custody before clearing site data.");
}

export function usePortalDrafts(owner: string, patient: string, active: Bytes, historical: Bytes[]) {
  const [state, rawSetState] = useState<DraftState>(emptyDraftState);
  const latest = useRef(state);
  latest.current = state;
  const revision = useRef(0);
  const alive = useRef(true);
  const ready = useRef(false);
  const key = useRef(new Uint8Array(active));
  const [restored, setRestored] = useState(false);
  const restoreGeneration = useRef(0);
  const [status, setStatus] = useState("Loading encrypted local draft…");
  const setState: Dispatch<SetStateAction<DraftState>> = (value) => {
    revision.current += 1;
    const next = typeof value === "function" ? value(latest.current) : value;
    latest.current = next;
    rawSetState(next);
  };
  const persist = async (snapshot: DraftState = latest.current) => {
    if (!alive.current)
      throw new Error("This draft view is no longer active. Its last encrypted snapshot is preserved.");
    if (!ready.current)
      throw new Error("Existing local drafts have not been restored. Retry restoring them before saving; your current writing is still on screen.");
    try {
      await savePortalDraft(owner, patient, key.current, snapshot);
      if (alive.current)
        setStatus("Draft saved encrypted on this device.");
    } catch (err) {
      if (alive.current)
        setStatus(err instanceof Error ? err.message : "Draft was not saved. Keep this view open and retry.");
      throw err;
    }
  };
  const restore = async (): Promise<void> => {
    const operation = ++restoreGeneration.current;
    const initialRevision = revision.current;
    try {
      const saved = await loadPortalDraft(owner, patient, [key.current, ...historical]);
      if (!alive.current || operation !== restoreGeneration.current)
        return;
      if (saved) {
        const next = revision.current === initialRevision ? saved : { text: { ...saved.text, ...latest.current.text }, editing: latest.current.editing ?? saved.editing, pending: { ...saved.pending, ...latest.current.pending } };
        latest.current = next;
        rawSetState(next);
      }
      ready.current = true;
      setRestored(true);
      setStatus(saved ? "Restored encrypted local draft." : "Drafts are encrypted on this device.");
    } catch (err) {
      if (alive.current && operation === restoreGeneration.current)
        setStatus(err instanceof Error ? err.message : "Draft could not be restored.");
    }
  };
  useEffect(() => {
    alive.current = true;
    void restore();
    return () => {
      alive.current = false;
      restoreGeneration.current += 1;
      if (ready.current)
        void savePortalDraft(owner, patient, key.current, latest.current).finally(() => key.current.fill(0)).catch(() => undefined);
      else
        key.current.fill(0);
    };
  }, [owner, patient]);
  useEffect(() => {
    if (!ready.current || revision.current === 0)
      return;
    const timer = setTimeout(() => { void persist(latest.current).catch(() => undefined); }, 250);
    return () => clearTimeout(timer);
  }, [state]);
  return { state, setState, latest, persist, status, restored, restore };
}
