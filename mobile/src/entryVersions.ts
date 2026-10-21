/**
 * Per-entry rollback protection for version-bound ciphertext.
 * AES-GCM verifies the entry's declared version, but a server could replay
 * both an older valid blob and its matching version. Remembering the highest
 * observed version detects that rollback before HistoryScreen renders it.
 *
 * The map is encrypted under the account data key. An in-memory mirror
 * preserves the current process's observations if storage disappears.
 * Deleting an entry removes its mark so a legitimate recreation can start
 * at version 1. A separate set records entries that have authenticated with
 * v2 AAD and must never fall back to unversioned legacy decryption.
 */
import { captureLocalWritePermit, assertLocalWritePermit, commitLocalWrite, type LocalWritePermit } from "./localRekey";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt } from "./crypto/envelope";
import { accountStorageKey } from "./accountStorage";
import { commitLocalErasureWrite, localWriteScopeEpoch } from "./localWriteGuard";


// A completed account reset wins work admitted before it. Reads already waiting
// on native storage may finish against detached mirrors, but cannot republish
// those mirrors or write their bytes after the reset's ordered deletion.
const resetGenerations = new Map<string, number>();
const entryWrites = new Map<string, Promise<void>>();
const entryResets = new Map<string, Promise<void>>();
const resetGeneration = (userId: string) => resetGenerations.get(userId) ?? 0;

function queueEntryWrite(userId: string, write: () => Promise<void>): Promise<void> {
  const pending = (entryWrites.get(userId) ?? Promise.resolve()).catch(() => {}).then(write);
  entryWrites.set(userId, pending);
  const clear = () => { if (entryWrites.get(userId) === pending) entryWrites.delete(userId); };
  void pending.then(clear, clear);
  return pending;
}

function commitEntryWrite(userId: string, permit: LocalWritePermit, mirror: Map<string, number> | Set<string>, write: () => Promise<void>): Promise<void> {
  const generation = resetGeneration(userId);
  return commitLocalWrite(permit, () => queueEntryWrite(userId, async () => {
    if (generation !== resetGeneration(userId) ||
        (memoryMirror.get(userId) !== mirror && v2BoundMirror.get(userId) !== mirror)) return;
    assertLocalWritePermit(permit);
    await write();
  }));
}

// IDs authenticated with v2 AAD cannot use the legacy unversioned fallback.
// The encrypted persisted set and process mirror enforce the same rule.
const v2BoundMirror = new Map<string, Set<string>>();

function v2BoundKey(userId: string): string {
  return accountStorageKey.entryV2Bound(userId);
}

async function loadV2Bound(userId: string, dataKey: Buffer): Promise<Set<string>> {
  while (entryResets.has(userId)) await entryResets.get(userId);
  let bound = v2BoundMirror.get(userId);
  if (!bound) {
    bound = new Set();
    v2BoundMirror.set(userId, bound);
  }
  let raw: string | null = null;
  try {
    raw = await AsyncStorage.getItem(v2BoundKey(userId));
  } catch {
    return bound;
  }
  if (!raw) return bound;
  let plaintext: Buffer | null = null;
  try {
    plaintext = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("entry-v2-bound", userId));
    const parsed = JSON.parse(plaintext.toString("utf8")) as unknown;
    if (Array.isArray(parsed)) {
      for (const id of parsed) if (typeof id === "string") bound.add(id);
    }
  } catch {
    // Corrupt/foreign ciphertext: treat as absent.
  } finally { plaintext?.fill(0); }
  return bound;
}

async function persistV2Bound(userId: string, dataKey: Buffer, bound: Set<string>, permit: LocalWritePermit): Promise<void> {
  const payload = Buffer.from(JSON.stringify([...bound]), "utf8");
  try {
    const blob = encrypt(dataKey, payload, buildAad("entry-v2-bound", userId));
    await commitEntryWrite(userId, permit, bound, () => AsyncStorage.setItem(v2BoundKey(userId), blob.toString("base64")));
  } finally {
    payload.fill(0);
  }
}

/** Record that this id authenticated under the v2 binding — the legacy
 *  fallback is refused for the id from now on. */
export async function noteV2Bound(userId: string, dataKey: Buffer, clientEntryId: string): Promise<void> {
  const permit = captureLocalWritePermit(userId, dataKey);
  const generation = resetGeneration(userId);
  const keyCopy = Buffer.from(dataKey);
  try {
    const bound = await loadV2Bound(userId, keyCopy);
    assertLocalWritePermit(permit);
    if (generation !== resetGeneration(userId)) return;
    if (bound.has(clientEntryId)) return;
    bound.add(clientEntryId);
    await persistV2Bound(userId, keyCopy, bound, permit);
  } finally {
    keyCopy.fill(0);
  }
}

/** Whether this id has EVER authenticated under the v2 binding. */
export async function isV2Bound(userId: string, dataKey: Buffer, clientEntryId: string): Promise<boolean> {
  const bound = await loadV2Bound(userId, dataKey);
  return bound.has(clientEntryId);
}

/** Process-lifetime mirror: user -> (clientEntryId -> max version). */
const memoryMirror = new Map<string, Map<string, number>>();

function storageKey(userId: string): string {
  return accountStorageKey.entryVersions(userId);
}

function loadMirror(userId: string): Map<string, number> {
  let mirror = memoryMirror.get(userId);
  if (!mirror) {
    mirror = new Map();
    memoryMirror.set(userId, mirror);
  }
  return mirror;
}

/** Decrypt the persisted map; absent/corrupt yields an empty map (the
 *  in-memory mirror remains authoritative for this session). */
async function loadStored(userId: string, dataKey: Buffer): Promise<Map<string, number>> {
  while (entryResets.has(userId)) await entryResets.get(userId);
  const mirror = loadMirror(userId);
  let raw: string | null = null;
  try {
    raw = await AsyncStorage.getItem(storageKey(userId));
  } catch {
    return mirror;
  }
  if (!raw) return mirror;
  let plaintext: Buffer | null = null;
  try {
    plaintext = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("entry-versions", userId));
    const parsed = JSON.parse(plaintext.toString("utf8")) as Record<string, unknown>;
    for (const [id, value] of Object.entries(parsed)) {
      if (typeof value === "number" && Number.isSafeInteger(value) && value >= 1) {
        const known = mirror.get(id) ?? 0;
        if (value > known) mirror.set(id, value);
      }
    }
  } catch {
    // Corrupt/foreign ciphertext: treat as absent. The mirror stands.
  } finally { plaintext?.fill(0); }
  return mirror;
}

async function persist(userId: string, dataKey: Buffer, mirror: Map<string, number>, permit: LocalWritePermit): Promise<void> {
  if (mirror.size === 0) {
    try {
      await commitEntryWrite(userId, permit, mirror, () => AsyncStorage.removeItem(storageKey(userId)));
    } catch {
      /* best effort */
    }
    return;
  }
  const record: Record<string, number> = {};
  for (const [id, version] of mirror) record[id] = version;
  const plaintext = Buffer.from(JSON.stringify(record), "utf8");
  try {
    const blob = encrypt(dataKey, plaintext, buildAad("entry-versions", userId));
    try {
      await commitEntryWrite(userId, permit, mirror, () => AsyncStorage.setItem(storageKey(userId), blob.toString("base64")));
    } catch {
      // best effort: the mirror holds for this session; next change retries.
    }
  } finally { plaintext.fill(0); }
}

export interface VersionObservation {
  /** Ids whose declared version moved BACKWARDS vs the remembered mark. */
  rolledBack: string[];
  /** Ids whose mark advanced (the caller may persist once per batch). */
  advanced: boolean;
}

/** Observe a batch of (id, declared version) rows — one HistoryScreen page.
 * Returns the rollback set; persists the updated map once when needed. */
export async function observeEntryVersions(
  userId: string,
  dataKey: Buffer,
  rows: ReadonlyArray<{ clientEntryId: string; contentVersion: number }>,
): Promise<VersionObservation> {
  const permit = captureLocalWritePermit(userId, dataKey);
  const generation = resetGeneration(userId);
  const keyCopy = Buffer.from(dataKey);
  try {
    const mirror = await loadStored(userId, keyCopy);
    assertLocalWritePermit(permit);
    if (generation !== resetGeneration(userId)) return { rolledBack: [], advanced: false };
    const rolledBack: string[] = [];
    let advanced = false;
    for (const row of rows) {
      if (!Number.isSafeInteger(row.contentVersion) || row.contentVersion < 1) continue;
      const known = mirror.get(row.clientEntryId) ?? 0;
      if (row.contentVersion < known) {
        rolledBack.push(row.clientEntryId);
        continue;
      }
      if (row.contentVersion > known) {
        mirror.set(row.clientEntryId, row.contentVersion);
        advanced = true;
      }
    }
    if (advanced) await persist(userId, keyCopy, mirror, permit);
    return { rolledBack, advanced };
  } finally {
    keyCopy.fill(0);
  }
}

/** The highest version remembered for one entry (null when never seen). */
export async function knownEntryVersion(
  userId: string,
  dataKey: Buffer,
  clientEntryId: string,
): Promise<number | null> {
  const mirror = await loadStored(userId, dataKey);
  const known = mirror.get(clientEntryId);
  return known === undefined ? null : known;
}

/** Forget one entry's mark (its row was deleted; a later recreate of the
 * same id legitimately restarts at version 1). */
export async function forgetEntryVersion(userId: string, dataKey: Buffer, clientEntryId: string): Promise<void> {
  const permit = captureLocalWritePermit(userId, dataKey);
  const generation = resetGeneration(userId);
  const keyCopy = Buffer.from(dataKey);
  try {
    const mirror = await loadStored(userId, keyCopy);
    assertLocalWritePermit(permit);
    if (generation !== resetGeneration(userId)) return;
    if (mirror.delete(clientEntryId)) await persist(userId, keyCopy, mirror, permit);
    if (generation !== resetGeneration(userId)) return;
    // Deleting the entry also removes its required-AAD-version marker.
    const bound = await loadV2Bound(userId, keyCopy);
    assertLocalWritePermit(permit);
    if (generation !== resetGeneration(userId)) return;
    if (bound.delete(clientEntryId)) await persistV2Bound(userId, keyCopy, bound, permit);
  } finally {
    keyCopy.fill(0);
  }
}

/** Forget everything for a user (sign-out / account deletion / origin
 * switch / data-key rotation re-keys the store anyway). */
export async function forgetAllEntryVersions(userId: string): Promise<void> {
  resetGenerations.set(userId, resetGeneration(userId) + 1);
  memoryMirror.delete(userId);
  v2BoundMirror.delete(userId);
  const pending = commitLocalErasureWrite(userId, localWriteScopeEpoch(), () => queueEntryWrite(userId, async () => {
    try {
      await AsyncStorage.removeItem(storageKey(userId));
      await AsyncStorage.removeItem(v2BoundKey(userId));
    } catch {
      /* nothing to forget */
    }
  }));
  entryResets.set(userId, pending);
  try { await pending; }
  finally { if (entryResets.get(userId) === pending) entryResets.delete(userId); }
}

/** Re-key the persisted map after a data-key rotation (rotation.ts): load
 *  with the OLD key, persist under the NEW one. On any failure the marks
 *  are forgotten rather than left as undecryptable bytes (a fresh map
 *  re-learns from the next history load; strictness degrades, never
 *  correctness). */
export async function rebindEntryVersions(userId: string, oldDataKey: Buffer, newDataKey: Buffer): Promise<void> {
  const permit = captureLocalWritePermit(userId, newDataKey);
  const generation = resetGeneration(userId);
  const mirror = await loadStored(userId, oldDataKey);
  assertLocalWritePermit(permit);
  if (generation !== resetGeneration(userId) || memoryMirror.get(userId) !== mirror) return;
  await persist(userId, newDataKey, mirror, permit);
  if (generation !== resetGeneration(userId)) return;
  const bound = await loadV2Bound(userId, oldDataKey);
  if (generation !== resetGeneration(userId)) return;
  await persistV2Bound(userId, newDataKey, bound, permit);
}

/** Test helper: drop every in-memory mirror (storage untouched). */
export function resetEntryVersionMirrors(): void {
  memoryMirror.clear();
  v2BoundMirror.clear();
}
