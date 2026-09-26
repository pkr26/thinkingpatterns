/**
 * Analysis-generation rollback guard — ported from mobile's
 * stateSeqGuard.ts (2026-09-19 contract, audit fix M-1) onto the kvstore
 * seam. AES-GCM authenticates WHO and WHAT a ciphertext belongs to, never
 * WHICH VERSION it is: without this check a compromised server could
 * replay an earlier, cryptographically valid patterns blob and the app
 * would render it as today's truth. The server (a) embeds a monotonic
 * `state_seq` inside the encrypted payload and (b) echoes the same value
 * in the plaintext response. Two device-local checks make every rollback
 * loud:
 *
 *   1. payload.state_seq === response.state_seq — a replayed-older blob
 *      disagrees with the row's echoed generation.
 *   2. payload.state_seq >= device high-water mark — even a both-copies
 *      rollback moves the value backwards; the mark lives in device-local
 *      storage the server cannot reach, which is what makes it
 *      trustworthy against a server-side attacker.
 *
 * Absent values FAIL CLOSED once a high-water mark exists for the user;
 * only a user with NO mark yet (genuinely old server, fresh install)
 * passes. A process-lifetime in-memory mirror survives on-device tampering
 * with the stored copy for the session's duration.
 */
import { kv } from "./kvstore";

const STORAGE_PREFIX = "mindpattern.stateSeq.";

export const FRESHNESS_ERROR = "your pattern data failed its freshness check";

/** Process-lifetime mirror of the persisted high-water marks. */
const memoryMirror = new Map<string, number>();

function storageKey(userId: string): string {
  return `${STORAGE_PREFIX}${userId}`;
}

async function loadHighWater(userId: string): Promise<number> {
  const mirrored = memoryMirror.get(userId);
  let stored = 0;
  let storageReadable = true;
  try {
    const raw = await kv.getItem(storageKey(userId));
    const parsed = raw == null ? NaN : Number(raw);
    if (Number.isFinite(parsed)) {
      stored = parsed;
    }
  } catch {
    // Device storage unavailable: the in-memory mirror is the fallback
    // authority; 0 means "no mark this session".
    storageReadable = false;
  }
  const highWater = Math.max(mirrored ?? 0, stored);
  if (highWater > 0) {
    memoryMirror.set(userId, highWater);
    // Self-heal (M-1): a persisted mark that reads BELOW the session's
    // mirror was tampered with or restored from a stale backup — rewrite
    // it so the defense survives the next process start too.
    if (storageReadable && stored < highWater) {
      await kv.setItem(storageKey(userId), String(highWater));
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
    await kv.setItem(storageKey(userId), String(payload));
  }
}

/** Test/rotation helper: forget the pinned high-water mark for a user. */
export async function forgetAnalysisGeneration(userId: string): Promise<void> {
  memoryMirror.delete(userId);
  await kv.removeItem(storageKey(userId));
}
