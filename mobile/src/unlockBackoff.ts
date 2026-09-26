/**
 * Escalating offline-unlock failure throttle (2026-09-26 pentest S-5).
 *
 * The unlock flow's failure feedback used to pause a CONSTANT 500 ms — a
 * thief holding a locked device could grind password guesses through the
 * app at the PBKDF2-600k rate forever, throttled by nothing but that flat
 * pad. This module persists a per-account consecutive-failure counter in
 * the encrypted secure store and doubles the pause per failure, capped.
 *
 * Honest scope, same as the old constant's: an attacker script that
 * bypasses this UI does not honor any client-side sleep — the real
 * protection of the offline oracle is PBKDF2-600k plus the 12-character
 * registration policy. What the escalating pad buys is that the on-device
 * UI path (the only path a casual attacker has without tooling) gets
 * expensive fast, and stays expensive across app restarts (the counter is
 * durable, not in-memory). The counter resets on any successful unlock.
 */

import { secureStore } from "./secureStore";

/** Per-account key under the encrypted secure-store envelope. */
const key = (username: string): string => `mindpattern.unlockFail.${username}`;

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
export async function recordUnlockFailure(username: string): Promise<number> {
  const next = Math.min((await unlockFailureCount(username)) + 1, MAX_TRACKED_UNLOCK_FAILURES);
  await secureStore.setItem(key(username), String(next));
  return next;
}

/** A successful unlock forgives everything. */
export async function clearUnlockFailures(username: string): Promise<void> {
  await secureStore.removeItem(key(username));
}
