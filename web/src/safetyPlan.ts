/**
 * The local safety plan (clinical review 2026-09-27) — a minimal,
 * Stanley-Brown-inspired set of structured fields the PATIENT writes and
 * keeps: warning signs, what helps, people/places, who to ask, who to
 * contact, making the environment safer. It is deliberately NOT a
 * clinical instrument: no scoring, no interpretation, no template text
 * beyond the field prompts.
 *
 * CUSTODY (the entryDraft/pendingMeasure idiom, exactly): the plan is
 * sealed under the account's data key — AES-GCM, AAD binds the user; a
 * wrong key or tampered record reads as absent — in ONE dedicated
 * kvstore slot per account. It is therefore ciphertext at rest, unreadable
 * pre-unlock (the crisis dialog's plan link renders only while the vault
 * is unlocked, and the static crisis resources always stay first and
 * complete), it survives idle/hidden-tab locks, and a v1 password
 * rotation re-seals it under the new key (the B-7 rewrap family in
 * Settings). LOCAL-ONLY BY DESIGN: never synced, never exported, never
 * shared with a therapist — the copy says so where the plan is edited.
 */
// @ts-nocheck

import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv, StorageReadError, type WritePermit } from "./kvstore";
import { vault } from "./vault";

/** The six Stanley-Brown-inspired fields, in display order. All free
 *  text; all optional (an empty plan is "nothing written yet"). */
export interface SafetyPlan {
  warningSigns: string;
  coping: string;
  peoplePlaces: string;
  helpers: string;
  professionals: string;
  saferEnvironment: string;
}

/** Generous but bounded: a plan is a set of short lists in prose, not a
 *  second journal. */
export const FIELD_MAX = 4_000;

export const EMPTY_SAFETY_PLAN: SafetyPlan = {
  warningSigns: "",
  coping: "",
  peoplePlaces: "",
  helpers: "",
  professionals: "",
  saferEnvironment: "",
};

const key = (userId: string): string => `mindpattern.safetyPlan.${userId}`;

/** An all-empty plan is "nothing written yet" — nothing to seal, and a
 *  reason to clear a stale slot (the user erased the plan on purpose). */
export function safetyPlanIsEmpty(plan: SafetyPlan): boolean {
  return Object.values(plan).every((field) => field.trim() === "");
}

/** Full validation of anything read back from storage, the entryDraft
 *  discipline: a hostile or half-written record is null, never
 *  wrong-typed state reaching the editor. */
function parsePlan(raw: string | null): SafetyPlan | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const plan: Partial<SafetyPlan> = {};
    for (const field of Object.keys(EMPTY_SAFETY_PLAN) as (keyof SafetyPlan)[]) {
      const value = (parsed as Record<string, unknown>)[field];
      if (typeof value !== "string" || value.length > FIELD_MAX) return null;
      plan[field] = value;
    }
    return plan as SafetyPlan;
  } catch {
    return null;
  }
}

/** Seal the plan under the data key. An all-empty plan clears the slot
 *  (the caller never wants a erased plan resurrected over a blank
 *  editor). Throws on a storage failure — the view surfaces it, the plan
 *  also stays on screen. */
export async function saveSafetyPlan(dataKey: Bytes, userId: string, plan: SafetyPlan): Promise<void> {
  if (parsePlan(JSON.stringify(plan)) === null) throw new Error(`Each safety-plan field must be text of at most ${FIELD_MAX} characters.`);
  const keyCopy=new Uint8Array(dataKey);
  const payload = new TextEncoder().encode(JSON.stringify(plan));
  try {
    const permit=await kv.captureWritePermit(userId,keyCopy);
    if (safetyPlanIsEmpty(plan)) {await clearSafetyPlan(userId,permit);return;}
    const blob = await encrypt(keyCopy, payload, buildAad("safety-plan", userId));
    await kv.setItem(key(userId), toBase64(blob),permit);
  } finally {
    zeroize(payload,keyCopy);
  }
}

/** Return null only for an absent record. Unreadable ciphertext is retained
 *  and raises StorageReadError so hydration cannot replace it as empty. */
export async function loadSafetyPlan(dataKey: Bytes, userId: string): Promise<SafetyPlan | null> {
  const raw = await kv.getItem(key(userId));
  if (!raw) return null;
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(raw), buildAad("safety-plan", userId));
    const plan = parsePlan(new TextDecoder().decode(plaintext));
    if (!plan) throw new Error("Stored safety-plan shape is invalid.");
    return plan;
  } catch (cause) {
    throw new StorageReadError("A saved safety plan could not be authenticated or restored. Retry with the correct account key before changing stored writing.", { cause });
  } finally {
    zeroize(plaintext);
  }
}

/** The plan's custody ended: erased field-by-field, or the account is
 *  gone (deletion's per-account sweep). */
export async function clearSafetyPlan(userId: string,permit?:WritePermit): Promise<void> {
  await kv.removeItem(key(userId),permit);
}

/** Rotation parity with the B-7 rewrap family: re-seal an existing plan
 *  under the incoming key so it survives a v1 password change. A failure
 *  propagates without clearing the recoverable original. */
/** Rotation parity with the B-7 rewrap family: re-seal an existing plan
 *  under the incoming key so it survives a v1 password change. A failure
 *  propagates without clearing the recoverable original. */
export async function rewrapSafetyPlan(oldKey: Bytes, newKey: Bytes, userId: string): Promise<void> {
  const plan = await loadSafetyPlan(oldKey, userId);
  if (plan === null) return;
  await saveSafetyPlan(newKey, userId, plan);
}

// --- 2026-10-01 audit M11: live-plan custody ----------------------------------
//
// The entry draft got a seal-on-lock/crash registry (2026-09-26 MEDIUM);
// the safety plan shipped without the equivalent: half-written
// Stanley-Brown text was destroyed by every idle/hidden-tab lock, bfcache
// restore, or render crash — clinically significant writing, lost in
// exactly the states the locks fire in. Same shape as entryDraft's
// registry: the view publishes a getter, App's lockDown seals it FIRST.

/** The live plan, or null when the mounted editor has no unsaved edits
 *  (a clean editor must never resurrect over itself). */
let planSource: (() => SafetyPlan | null | undefined) | null = null;

export function registerSafetyPlanSource(
  source: () => SafetyPlan | null | undefined,
): () => void {
  planSource = source;
  return () => {
    if (planSource === source) planSource = null;
  };
}

/** Seal the live plan for the lock/crash/navigation happening RIGHT NOW —
 *  the entryDraft.preserveActiveDraft idiom (key snapshotted
 *  synchronously; async seal on the private copy; best-effort). */
export function preserveSafetyPlan(): Promise<void> {
  const plan = planSource?.() ?? null;
  const owner = vault.ownerUserId();
  if (!plan || !owner || !vault.isUnlocked()) return Promise.resolve();
  const current = vault.get();
  const keyCopy = new Uint8Array(new ArrayBuffer(current.dataKey.length));
  keyCopy.set(current.dataKey);
  return (async () => {
    try {
      await saveSafetyPlan(keyCopy, owner, plan);
    } finally {
      zeroize(keyCopy);
    }
  })().catch(() => undefined);
}
