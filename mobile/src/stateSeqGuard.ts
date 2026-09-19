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
 * Absent values (older server, pre-threshold account) pass silently: the
 * guard must not break clients talking to a pre-2026-09-19 backend.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

const STORAGE_PREFIX = "mindpattern.stateSeq.";

export const FRESHNESS_ERROR = "your pattern data failed its freshness check";

function storageKey(userId: string): string {
  return `${STORAGE_PREFIX}${userId}`;
}

export async function checkAnalysisGeneration(
  userId: string,
  payloadSeq: number | undefined,
  echoedSeq: number | undefined,
): Promise<void> {
  if (!Number.isFinite(payloadSeq) || !Number.isFinite(echoedSeq)) {
    return; // old server or baseline phase: nothing to verify
  }
  const payload = payloadSeq as number;
  const echoed = echoedSeq as number;
  if (payload !== echoed) {
    throw new Error(FRESHNESS_ERROR);
  }
  let highWater = 0;
  try {
    const raw = await AsyncStorage.getItem(storageKey(userId));
    const parsed = raw == null ? NaN : Number(raw);
    if (Number.isFinite(parsed)) {
      highWater = parsed;
    }
  } catch {
    // Device storage unavailable: the cross-check above still ran; skip
    // the device pin rather than failing the whole screen.
    return;
  }
  if (payload < highWater) {
    throw new Error(FRESHNESS_ERROR);
  }
  if (payload > highWater) {
    try {
      await AsyncStorage.setItem(storageKey(userId), String(payload));
    } catch {
      // best-effort pin; next load re-attempts
    }
  }
}

/** Test/rotation helper: forget the pinned high-water mark for a user. */
export async function forgetAnalysisGeneration(userId: string): Promise<void> {
  try {
    await AsyncStorage.removeItem(storageKey(userId));
  } catch {
    // nothing to forget
  }
}
