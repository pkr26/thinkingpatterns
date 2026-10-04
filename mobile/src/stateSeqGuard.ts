/**
 * Reject replayed analysis generations before rendering decrypted results.
 * The encrypted state_seq must match the response and cannot move below the
 * highest generation observed on this device. Once a mark exists, missing
 * generation fields also fail closed; legacy responses are accepted only
 * when there is no previous mark.
 *
 * Marks use secureStore's per-install key so they survive account data-key
 * rotation. An in-memory mirror preserves the current process's high-water
 * mark if storage is removed or corrupted; later writes repair the record.
 * Legacy plaintext marks migrate on read. Deleting storage and restarting
 * can remove this history, a limitation of device-local rollback detection.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { secureStore } from "./secureStore";
import { accountStorageKey } from "./accountStorage";
import { commitActiveAccountWrite } from "./localWriteGuard";

export const FRESHNESS_ERROR = "your pattern data failed its freshness check";

/** Process-lifetime mirror of the persisted high-water marks. */
const memoryMirror = new Map<string, number>();

function storageKey(userId: string): string {
  return accountStorageKey.stateSequence(userId);
}

/** Read the persisted mark (sealed lane first, one-time v1 plaintext
 *  migration second). See the module header for the tamper-evidence
 *  design; `readable` is false only when the secure-store seam itself is
 *  unavailable (Keychain dead), in which case the mirror stands alone. */
async function readPersistedMark(userId: string): Promise<{ stored: number; readable: boolean }> {
  try {
    const sealed = await secureStore.getItem(storageKey(userId));
    if (sealed !== null && /^\d+$/.test(sealed)) {
      return { stored: Number(sealed), readable: true };
    }
  } catch {
    return { stored: 0, readable: false };
  }
  // v1 plaintext migration: adopt the old mark and rewrite it sealed. The
  // sealed write lands in the SAME storage slot, so the plaintext copy is
  // gone by construction (an extra remove would delete the new envelope);
  // a failed sealed write leaves the plaintext in place for a later retry.
  // The lane only opens when NO sealed record exists; an attacker forcing
  // it open (delete + plant a plaintext mark) reaches exactly the deletion
  // residual, never a forged-valid record.
  try {
    const raw = await AsyncStorage.getItem(storageKey(userId));
    if (raw !== null && /^\d+$/.test(raw)) {
      const value = Number(raw);
      // A failed sealed write leaves the plaintext for a later retry; the
      // value is still adopted for this check either way.
      await commitActiveAccountWrite(userId, () => secureStore.setItem(storageKey(userId), raw)).catch(() => {});
      return { stored: value, readable: true };
    }
  } catch {
    // Unreadable legacy slot: nothing to migrate; the mirror stands.
  }
  return { stored: 0, readable: true };
}

async function persistMark(userId: string, mark: number): Promise<void> {
  try {
    await commitActiveAccountWrite(userId, () => secureStore.setItem(storageKey(userId), String(mark)));
  } catch {
    // best effort; the in-memory mirror holds for this session and the
    // next load re-attempts the persist.
  }
}

async function loadHighWater(userId: string): Promise<number> {
  const mirrored = memoryMirror.get(userId);
  const { stored, readable } = await readPersistedMark(userId);
  const highWater = Math.max(mirrored ?? 0, stored);
  if (highWater > 0) {
    memoryMirror.set(userId, highWater);
    // Self-heal (M-1): a persisted mark that reads BELOW the session's
    // mirror was tampered with or restored from a stale backup — rewrite
    // it so the defense survives the next process start too.
    if (readable && stored < highWater) {
      await persistMark(userId, highWater);
    }
  }
  return highWater;
}

export async function checkAnalysisGeneration(
  userId: string,
  payloadSeq: number | undefined,
  echoedSeq: number | undefined,
): Promise<void> {
  const highWater = await loadHighWater(userId);
  if (!Number.isFinite(payloadSeq) || !Number.isFinite(echoedSeq)) {
    // Fail closed once ANY mark exists (M-1): a server that previously
    // served numbered generations cannot legitimately go back to unnumbered
    // ones. No mark yet — old server, baseline account, fresh install —
    // still passes: there is nothing to compare against.
    if (highWater > 0) {
      throw new Error(FRESHNESS_ERROR);
    }
    return;
  }
  const payload = payloadSeq as number;
  const echoed = echoedSeq as number;
  if (payload !== echoed) {
    throw new Error(FRESHNESS_ERROR);
  }
  if (payload < highWater) {
    throw new Error(FRESHNESS_ERROR);
  }
  if (payload > highWater) {
    memoryMirror.set(userId, payload);
    await persistMark(userId, payload);
  }
}

/** Test/rotation helper: forget the pinned high-water mark for a user. */
export async function forgetAnalysisGeneration(userId: string): Promise<void> {
  memoryMirror.delete(userId);
  try {
    // secureStore.removeItem drops the sealed envelope AND any legacy
    // plaintext copy: both live in AsyncStorage under the same key.
    await secureStore.removeItem(storageKey(userId));
  } catch {
    // nothing to forget
  }
}

/** Test helper: drop every in-memory mirror (storage untouched) — the
 *  entryVersions.ts idiom for simulating a fresh process. */
export function resetAnalysisGenerationMirrors(): void {
  memoryMirror.clear();
}
