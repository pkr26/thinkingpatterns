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
import { assertLocalWritePermit, captureLocalWritePermit, commitLocalWrite, localWriteOriginEpoch, type LocalWritePermit } from "./localWriteGuard";

export const FRESHNESS_ERROR = "your pattern data failed its freshness check";

/** Process-lifetime mirror of the persisted high-water marks. */
const memoryMirror = new Map<string, number>();
const checks = new Map<string, Promise<void>>();
let mirrorOrigin = localWriteOriginEpoch();
function adoptOrigin(): void {
  const origin = localWriteOriginEpoch();
  if (origin === mirrorOrigin) return;
  mirrorOrigin = origin;
  memoryMirror.clear();
  checks.clear();
}

function storageKey(userId: string): string {
  return accountStorageKey.stateSequence(userId);
}

/** Read the persisted mark (sealed lane first, one-time v1 plaintext
 *  migration second). See the module header for the tamper-evidence
 *  design; `readable` is false only when the secure-store seam itself is
 *  unavailable (Keychain dead), in which case the mirror stands alone. */
async function readPersistedMark(userId: string, permit: LocalWritePermit, assertCurrent: () => void): Promise<{ stored: number; readable: boolean }> {
  assertCurrent();
  try {
    const sealed = await secureStore.getItem(storageKey(userId));
    assertCurrent();
    if (sealed !== null && /^\d+$/.test(sealed)) {
      return { stored: Number(sealed), readable: true };
    }
  } catch {
    assertCurrent();
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
    assertCurrent();
    const raw = await AsyncStorage.getItem(storageKey(userId));
    assertCurrent();
    if (raw !== null && /^\d+$/.test(raw)) {
      const value = Number(raw);
      // A failed sealed write leaves the plaintext for a later retry; the
      // value is still adopted for this check either way.
      await commitLocalWrite(permit, () => {
        assertCurrent();
        return secureStore.setItem(storageKey(userId), raw);
      }).catch(() => { assertCurrent(); });
      assertCurrent();
      return { stored: value, readable: true };
    }
  } catch {
    assertCurrent();
    // Unreadable legacy slot: nothing to migrate; the mirror stands.
  }
  return { stored: 0, readable: true };
}

async function persistMark(userId: string, mark: number, permit: LocalWritePermit, assertCurrent: () => void): Promise<void> {
  assertCurrent();
  try {
    await commitLocalWrite(permit, () => {
      assertCurrent();
      return secureStore.setItem(storageKey(userId), String(mark));
    });
  } catch {
    assertCurrent();
    // best effort; the in-memory mirror holds for this session and the
    // next load re-attempts the persist.
  }
  assertCurrent();
}

async function loadHighWater(userId: string, permit: LocalWritePermit, assertCurrent: () => void): Promise<number> {
  assertCurrent();
  const mirrored = memoryMirror.get(userId);
  const { stored, readable } = await readPersistedMark(userId, permit, assertCurrent);
  assertCurrent();
  const highWater = Math.max(mirrored ?? 0, stored);
  if (highWater > 0) {
    memoryMirror.set(userId, highWater);
    // Self-heal (M-1): a persisted mark that reads BELOW the session's
    // mirror was tampered with or restored from a stale backup — rewrite
    // it so the defense survives the next process start too.
    if (readable && stored < highWater) {
      await persistMark(userId, highWater, permit, assertCurrent);
      assertCurrent();
    }
  }
  return highWater;
}

export async function checkAnalysisGeneration(
  userId: string,
  payloadSeq: number | undefined,
  echoedSeq: number | undefined,
  stillCurrent?: () => boolean,
): Promise<void> {
  const assertView = () => {
    if (stillCurrent && !stillCurrent()) throw new Error("The pattern view has retired");
  };
  assertView();
  adoptOrigin();
  // Both the mirror read and the physical write belong to one ordered
  // check. A late Native read/write must not lower a newer load's receipt.
  // Capture admission before waiting so a queued old check cannot adopt a
  // replacement account or key generation when its turn eventually starts.
  const permit = captureLocalWritePermit(userId);
  const assertCurrent = () => { assertView(); assertLocalWritePermit(permit); };
  const previous = checks.get(userId) ?? Promise.resolve();
  const current = previous.then(async () => {
    assertCurrent();
    await checkGeneration(userId, payloadSeq, echoedSeq, permit, assertCurrent);
    assertCurrent();
  });
  const tail = current.catch(() => {});
  checks.set(userId, tail);
  void tail.finally(() => { if (checks.get(userId) === tail) checks.delete(userId); });
  await current;
  assertCurrent();
}

async function checkGeneration(userId: string, payloadSeq: number | undefined, echoedSeq: number | undefined, permit: LocalWritePermit, assertCurrent: () => void): Promise<void> {
  const highWater = await loadHighWater(userId, permit, assertCurrent);
  assertCurrent();
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
    await persistMark(userId, payload, permit, assertCurrent);
    assertCurrent();
  }
}

/** Test/rotation helper: forget the pinned high-water mark for a user. */
export async function forgetAnalysisGeneration(userId: string): Promise<void> {
  adoptOrigin();
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
