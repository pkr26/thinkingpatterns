/**
 * Persistent exponential backoff for failed offline-unlock attempts.
 * The per-account counter uses the encrypted secure store, doubles the delay
 * up to a cap, and resets after a successful unlock.
 *
 * This limits guesses through the UI. It cannot constrain an attacker who
 * bypasses the app; offline cryptographic protection comes from the password
 * policy and the key-derivation cost.
 */

import { secureStore } from "./secureStore";
import { accountStorageKey } from "./accountStorage";
import { commitActiveAccountWrite } from "./localWriteGuard";

/** Per-account key under the encrypted secure-store envelope. */
const key = accountStorageKey.unlockFailure;

/** Base pause after the FIRST failure — identical to the old constant, so
 *  an honest first typo feels exactly as calm as before. */
export const BASE_UNLOCK_FAIL_DELAY_MS = 500;

/** Doubling stops here: 500ms → 1s → 2s → 4s → 8s → 16s → 30s (cap). */
export const MAX_UNLOCK_FAIL_DELAY_MS = 30_000;

/** Consecutive failures kept before the counter saturates — beyond this
 *  the delay simply stays at the cap; no unbounded growth, no overflow. */
export const MAX_TRACKED_UNLOCK_FAILURES = 12;

/** The pause owed after the n-th CONSECUTIVE failure (n ≥ 1). */
export function unlockFailureDelayMs(consecutiveFailures: number): number {
  const n = Math.max(1, Math.min(consecutiveFailures, MAX_TRACKED_UNLOCK_FAILURES));
  return Math.min(BASE_UNLOCK_FAIL_DELAY_MS * 2 ** (n - 1), MAX_UNLOCK_FAIL_DELAY_MS);
}

/** Read the current consecutive-failure count (0 when absent/corrupt —
 *  the store's corruption contract reads as absent, never bricks unlock). */
export async function unlockFailureCount(username: string): Promise<number> {
  const raw = await secureStore.getItem(key(username));
  if (raw === null) return 0;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, MAX_TRACKED_UNLOCK_FAILURES) : 0;
}

/** Record one more failure; returns the NEW consecutive count. */
export async function recordUnlockFailure(username: string, userId: string): Promise<number> {
  const next = Math.min((await unlockFailureCount(username)) + 1, MAX_TRACKED_UNLOCK_FAILURES);
  await commitActiveAccountWrite(userId, () => secureStore.setItem(key(username), String(next)));
  return next;
}

/** A successful unlock forgives everything. */
export async function clearUnlockFailures(username: string, userId: string): Promise<void> {
  await commitActiveAccountWrite(userId, () => secureStore.removeItem(key(username)));
}

/** Administrative-erasure primitive. The caller owns the tombstoned-user
 * commit lane, so no active-session permit is required here. */
export async function eraseUnlockFailures(username: string): Promise<void> {
  await secureStore.removeItem(key(username));
}
