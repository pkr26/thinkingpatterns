/**
 * Analysis-generation rollback guard (2026-09-19 contract).
 *
 * AES-GCM authenticates WHO and WHAT a ciphertext belongs to, never WHICH
 * VERSION it is: without this check a compromised server could replay an
 * earlier, cryptographically valid patterns blob and the app would render
 * it as today's truth. The server now (a) embeds a monotonic
 * ``state_seq`` inside the encrypted payload and (b) echoes the same value
 * in the plaintext response. Two device-local checks make every rollback
 * loud:
 *
 *   1. payload.state_seq === response.state_seq  — a replayed-older blob
 *      disagrees with the row's echoed generation.
 *   2. payload.state_seq >= device high-water mark — even a both-copies
 *      rollback (column AND blob rewound together) moves the value
 *      backwards. The high-water mark lives in device-local storage the
 *      server cannot reach, which is exactly what makes it trustworthy
 *      against a server-side attacker.
 *
 * 2026-09-20 (audit fix M-1): absent values now FAIL CLOSED once a
 * high-water mark exists for the user. The old "absent passes silently"
 * rule was a protocol downgrade a compromised server controlled: replay a
 * pre-2026-09-19 blob and omit the echoed field, and both sides read
 * undefined while week-old analysis rendered as today's truth. Only a
 * user with NO mark yet (genuinely old server, fresh install) still
 * passes — there is nothing to compare against. A process-lifetime
 * in-memory mirror of the mark additionally survives on-device tampering
 * with the stored copy for the duration of the session (the same idiom
 * crisisDialog.ts uses); wiping the persisted mark and killing the app
 * before the next launch remains the documented residual.
 *
 * 2026-09-26 (audit LOW): the persisted mark is no longer plaintext in
 * AsyncStorage. It lives in secureStore — AES-256-GCM under the per-install
 * Keychain/Keystore device key (secureStore.ts) — so a local attacker who
 * LOWERS the stored bytes cannot forge a valid record: the GCM tag check
 * (the envelope primitive's own constant-time verification; no
 * attacker-controlled bytes are compared in the clear here) fails and the
 * tampered record reads as ABSENT, with the in-memory mirror remaining the
 * in-session authority and the self-heal rewrite re-pinning the true
 * value. A v1 plaintext decimal mark migrates sealed read-through, once.
 * Deleting the record outright is still possible and still the documented
 * residual: the next process degrades to "no memory" until the next
 * honest generation re-pins (M-1 then re-arms from there). The data-key
 * lane entryVersions.ts uses was NOT chosen here: this guard's callers
 * (InsightsScreen) hold the data key, but the mark must also survive a
 * data-key rotation without a rebind step and stay readable by the same
 * origin-bound key wipe in api/client.ts — the per-install device key
 * gives both for free.
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
