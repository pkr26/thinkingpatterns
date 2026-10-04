/**
 * The active journal draft's lock-time preservation (audit 2026-09-26,
 * MEDIUM — the worst user-data-loss path). The hidden-tab/idle/bfcache
 * locks unmount the editor while the draft lives only in component state,
 * destroying a half-written entry outright. This module seals whatever the
 * editor holds AT LOCK TIME under the account's data key — exactly the
 * entryVersions/moodLog idiom (AES-GCM, AAD binds the user; unreadable records throw typed errors) — into ONE dedicated kvstore slot, and
 * the editor restores it on its next mount.
 *
 * Custody: the draft is ciphertext at rest, never plaintext; the slot
 * clears on a successful save (sent OR parked in the offline queue), on an
 * explicit discard, and whenever a lock lands with an EMPTY editor (the
 * user started over). A password rotation re-seals it under the new key
 * (the B-7 rewrap family); account deletion clears it with the rest of
 * the per-account stores.
 */
// @ts-nocheck

import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv, StorageReadError, type WritePermit } from "./kvstore";
import { vault } from "./vault";

/** The editor's whole in-progress state, modeled exactly as EntryView
 *  holds it: the free text plus every structured check-in pick. */
export interface EntryDraft {
  text: string;
  mood: number | null;
  energy: number | null;
  sleep: number | null;
  tags: string[];
}

const key = (userId: string): string => `mindpattern.draft.active.${userId}`;

/** independent audit 2026-09-27 (P2): a lock-time seal and a save/discard
 *  clear can be in flight for the SAME account at the same instant (the
 *  lock fires mid-save; the save's clear commits once the entry is safe).
 *  With bare kv writes the clear's removeItem could commit BEFORE the
 *  seal's setItem landed — the sealed slot then survived a successful save
 *  and resurrected the entry as a draft. Every slot mutation therefore
 *  runs through ONE per-account chain: a clear queued behind a seal waits
 *  for that seal to land first, so the clear is always the last write and
 *  the slot is genuinely empty when it resolves. */
const slotChains = new Map<string, Promise<unknown>>();

function chained<T>(userId: string, operation: () => Promise<T>): Promise<T> {
  const run = (slotChains.get(userId) ?? Promise.resolve()).then(operation, operation);
  slotChains.set(userId, run.catch(() => {}));
  return run;
}

/** An empty draft is "no entry in progress" — nothing to seal (and a
 *  reason to clear a stale slot: the user emptied the editor on purpose). */
function draftIsEmpty(draft: EntryDraft): boolean {
  return (
    draft.text.trim() === ""
    && draft.mood === null
    && draft.energy === null
    && draft.sleep === null
    && draft.tags.length === 0
  );
}

/** Full validation of anything read back from storage, the moodLog
 *  discipline: a hostile or half-written record is null, never
 *  wrong-typed state reaching the editor. */
function parseDraft(raw: string | null): EntryDraft | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const draft = parsed as Record<string, unknown>;
    if (typeof draft.text !== "string" || draft.text.length > 100_000) return null;
    const numberOrNull = (value: unknown): number | null | undefined => {
      if (value === null) return null;
      if (typeof value === "number" && Number.isFinite(value)) return value;
      return undefined;
    };
    const mood = numberOrNull(draft.mood);
    const energy = numberOrNull(draft.energy);
    const sleep = numberOrNull(draft.sleep);
    if (mood === undefined || energy === undefined || sleep === undefined) return null;
    if (!Array.isArray(draft.tags) || draft.tags.length > 200 || draft.tags.some((tag) => typeof tag !== "string")) return null;
    return { text: draft.text, mood, energy, sleep, tags: draft.tags as string[] };
  } catch {
    return null;
  }
}

/** Seal the draft under the data key. An empty draft clears the slot (the
 *  caller never wants a stale draft resurrected over an emptied editor). */
export async function saveActiveDraft(dataKey: Bytes, userId: string, draft: EntryDraft): Promise<void> {
  const keyCopy=new Uint8Array(dataKey);
  const payload = new TextEncoder().encode(JSON.stringify(draft));
  try {
    const permit=await kv.captureWritePermit(userId,keyCopy);
    if(draftIsEmpty(draft)){await clearActiveDraft(userId,permit);return;}
    await chained(userId, async () => {
      const blob = await encrypt(keyCopy, payload, buildAad("draft", userId));
      await kv.setItem(key(userId), toBase64(blob),permit);
    });
  } finally {
    zeroize(payload,keyCopy);
  }
}

/** Return null only for an absent record. Unreadable ciphertext is retained
 *  and raises StorageReadError so hydration cannot replace it as empty. */
export async function loadActiveDraft(dataKey: Bytes, userId: string): Promise<EntryDraft | null> {
  const raw = await kv.getItem(key(userId));
  if (!raw) return null;
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(raw), buildAad("draft", userId));
    const draft = parseDraft(new TextDecoder().decode(plaintext));
    if (!draft) throw new Error("Stored draft shape is invalid.");
    return draft;
  } catch (cause) {
    throw new StorageReadError("A saved draft could not be authenticated or restored. Retry with the correct account key before changing stored writing.", { cause });
  } finally {
    zeroize(plaintext);
  }
}

/** The draft's custody ended: saved (sent or parked), discarded, or the
 *  account is gone. The clear is COMBINED (audit 2026-09-27): it removes
 *  the stored record AND any seal still in flight — it runs after that
 *  seal's write lands, so a lock racing a save can never leave a sealed
 *  slot behind to resurrect an already-saved entry. */
export async function clearActiveDraft(userId: string,permit?:WritePermit): Promise<void> {
  await chained(userId, () => kv.removeItem(key(userId),permit));
}

/** Rotation parity with the B-7 rewrap family: re-seal an existing draft
 *  under the incoming key so an in-progress entry survives a password
 *  change. A failure propagates without clearing the recoverable original. */
export async function rewrapActiveDraft(oldKey: Bytes, newKey: Bytes, userId: string): Promise<void> {
  const draft = await loadActiveDraft(oldKey, userId);
  if (draft === null) return;
  await saveActiveDraft(newKey, userId, draft);
}

/** The live-editor registry: EntryView publishes a getter for its current
 *  multi-field state; App's lockDown seals whatever it returns BEFORE the
 *  vault zeroizes. The getter reads a ref, so it always sees the latest
 *  keystroke, and un-registering on unmount keeps a stale editor from
 *  ever being asked. */
let draftSource: (() => EntryDraft | null | undefined) | null = null;

export function registerDraftSource(source: () => EntryDraft | null | undefined): () => void {
  draftSource = source;
  return () => {
    if (draftSource === source) draftSource = null;
  };
}

/** Seal the live editor's draft for the lock that is happening RIGHT NOW.
 *  Called as the FIRST step of lockDown, while the vault still holds the
 *  key: the data-key bytes are snapshotted synchronously (the moodLog
 *  idiom — the caller zeroizes the shared buffer the moment this returns)
 *  and the async seal runs on the private copy. Best-effort by contract: a
 *  failed seal never blocks the lock itself. An empty editor clears any
 *  stale slot; no mounted editor (draftSource null) touches the slot at
 *  all — a draft parked by an earlier lock must survive unrelated locks. */
export function preserveActiveDraft(): Promise<void> {
  const draft = draftSource?.() ?? null;
  const owner = vault.ownerUserId();
  if (!draft || !owner || !vault.isUnlocked()) return Promise.resolve();
  // Empty clears carry the same old-key proof as non-empty lock-time seals.
  const current = vault.get();
  const keyCopy = new Uint8Array(new ArrayBuffer(current.dataKey.length));
  keyCopy.set(current.dataKey);
  return (async () => {
    try {
      await saveActiveDraft(keyCopy, owner, draft);
    } finally {
      zeroize(keyCopy);
    }
  })().catch(() => undefined);
}
