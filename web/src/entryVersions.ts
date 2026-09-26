/**
 * Per-entry content-version high-water marks — ported from mobile's
 * entryVersions.ts (audit fix M-2) with async WebCrypto and the kvstore
 * seam. The v2 entry AAD binds ("entry", userId, id, content_version) into
 * the ciphertext; what AES-GCM still cannot see is a both-copies rollback
 * (a compromised server replaying an older VALID blob with its own
 * truthful, older version echo). This module pins the highest version ever
 * observed per entry in local storage — the same standing the insights
 * stateSeqGuard gives the analysis generation — and makes any backwards
 * move loud: History treats a rolled-back entry exactly like a tampered
 * blob (skipped and counted, never rendered as today's truth).
 *
 * Storage is AES-GCM under the DATA KEY (AAD binds the user): unreadable
 * and unwritable by the server; an attacker who zeroes it degrades to "no
 * memory", never a forged lower mark. A process-lifetime in-memory mirror
 * keeps the guard alive within a session even if storage is wiped mid-run.
 * Deleting an entry forgets its mark so a later recreate of the same id
 * (legitimately version 1 again) does not false-alarm.
 */
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv } from "./kvstore";

const STORAGE_PREFIX = "mindpattern.entryVersions.";

/** Process-lifetime mirror: user -> (clientEntryId -> max version). */
const memoryMirror = new Map<string, Map<string, number>>();

function storageKey(userId: string): string {
  return `${STORAGE_PREFIX}${userId}`;
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
async function loadStored(userId: string, dataKey: Bytes): Promise<Map<string, number>> {
  const mirror = loadMirror(userId);
  const raw = await kv.getItem(storageKey(userId));
  if (!raw) return mirror;
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(raw), buildAad("entry-versions", userId));
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    for (const [id, value] of Object.entries(parsed)) {
      if (typeof value === "number" && Number.isSafeInteger(value) && value >= 1) {
        const known = mirror.get(id) ?? 0;
        if (value > known) mirror.set(id, value);
      }
    }
  } catch {
    // Corrupt/foreign ciphertext: treat as absent. The mirror stands.
  } finally {
    zeroize(plaintext);
  }
  return mirror;
}

async function persist(userId: string, dataKey: Bytes, mirror: Map<string, number>): Promise<void> {
  if (mirror.size === 0) {
    await kv.removeItem(storageKey(userId));
    return;
  }
  const record: Record<string, number> = {};
  for (const [id, version] of mirror) record[id] = version;
  const payload = new TextEncoder().encode(JSON.stringify(record));
  try {
    const blob = await encrypt(dataKey, payload, buildAad("entry-versions", userId));
    await kv.setItem(storageKey(userId), toBase64(blob));
  } finally {
    zeroize(payload);
  }
}

export interface VersionObservation {
  /** Ids whose declared version moved BACKWARDS vs the remembered mark. */
  rolledBack: string[];
  /** Ids whose mark advanced (the caller persists once per batch). */
  advanced: boolean;
}

/** Observe a batch of (id, declared version) rows — one History page.
 * Returns the rollback set; persists the updated map once when needed. */
export async function observeEntryVersions(
  userId: string,
  dataKey: Bytes,
  rows: ReadonlyArray<{ clientEntryId: string; contentVersion: number }>,
): Promise<VersionObservation> {
  const mirror = await loadStored(userId, dataKey);
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
  if (advanced) await persist(userId, dataKey, mirror);
  return { rolledBack, advanced };
}

/** The highest version remembered for one entry (null when never seen). */
export async function knownEntryVersion(
  userId: string,
  dataKey: Bytes,
  clientEntryId: string,
): Promise<number | null> {
  const mirror = await loadStored(userId, dataKey);
  const known = mirror.get(clientEntryId);
  return known === undefined ? null : known;
}

/** Forget one entry's mark (its row was deleted; a later recreate of the
 * same id legitimately restarts at version 1). */
export async function forgetEntryVersion(userId: string, dataKey: Bytes, clientEntryId: string): Promise<void> {
  const mirror = await loadStored(userId, dataKey);
  if (mirror.delete(clientEntryId)) await persist(userId, dataKey, mirror);
}

/** Forget everything for a user (sign-out / account deletion; a data-key
 *  rotation re-keys the store via rebind instead). */
export async function forgetAllEntryVersions(userId: string): Promise<void> {
  memoryMirror.delete(userId);
  await kv.removeItem(storageKey(userId));
}

/** Re-key the persisted map after a data-key rotation: load with the OLD
 *  key, persist under the NEW one. On any failure the marks are forgotten
 *  rather than left as undecryptable bytes (a fresh map re-learns from the
 *  next history load; strictness degrades, never correctness). */
export async function rebindEntryVersions(userId: string, oldDataKey: Bytes, newDataKey: Bytes): Promise<void> {
  const mirror = await loadStored(userId, oldDataKey);
  memoryMirror.set(userId, mirror);
  await persist(userId, newDataKey, mirror);
}

/** Test helper: drop every in-memory mirror (storage untouched). */
export function resetEntryVersionMirrors(): void {
  memoryMirror.clear();
}
