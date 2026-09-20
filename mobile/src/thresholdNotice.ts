/**
 * Threshold-crossing notice: shown at most ONCE per account.
 *
 * Thirty days of writing is the app's own ask; the day it completes was
 * historically invisible (the Entry header simply flipped wording). This
 * stamp backs the one-time calm "your patterns are ready" card — one
 * appearance, ever, then never again. The stamp is recorded when the card
 * is SHOWN (not when dismissed): a notice that could nag across restarts
 * is worse than no notice.
 *
 * Persisted per account at @mindpattern/threshold_notice_<userId> via the
 * encrypted secure store; account deletion must wipe it (the
 * SettingsScreen deletion flow, the same idiom as crisisDialog.ts).
 *
 * Failure direction is toward SHOWING once more: when storage is
 * unreadable a process-lifetime memory mirror is the only record, so a
 * broken store can repeat the card after a restart at worst — a benign,
 * celebratory message, never a gate on anything.
 */
import { secureStore } from "./secureStore";

const key = (userId: string): string => `@mindpattern/threshold_notice_${userId}`;

/** Process-lifetime mirror, consulted ONLY when storage throws. */
const memoryShown = new Set<string>();

/** True when the one-time threshold card already ran for this account. */
export async function thresholdNoticeShown(userId: string): Promise<boolean> {
  try {
    return (await secureStore.getItem(key(userId))) !== null;
  } catch {
    // Storage unreadable: the memory mirror is the only record left.
    return memoryShown.has(userId);
  }
}

/** Stamp the notice as shown. The mirror is always written, so a storage
 *  failure still suppresses repeats within this session. */
export async function recordThresholdNotice(userId: string): Promise<void> {
  memoryShown.add(userId);
  try {
    await secureStore.setItem(key(userId), "1");
  } catch {
    // The mirror holds it; a restart simply re-shows the card (fail-open).
  }
}

/** Account-deletion hygiene: the stamp must not outlive its account. */
export async function clearThresholdNotice(userId: string): Promise<void> {
  memoryShown.delete(userId);
  await secureStore.removeItem(key(userId));
}
