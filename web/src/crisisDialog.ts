/**
 * Crisis-prompt throttle (audit 2026-09-26, LOW c): at most once per
 * LOCAL calendar day per account — ported from mobile's crisisDialog.ts
 * onto the web localStore seam.
 *
 * The Entry prompt used to fire on EVERY crisis-flagged draft — dialog
 * fatigue trains dismissal, and the person who needs the resources most
 * stops reading them. The stamp is an ISO LOCAL calendar date (the same
 * day the entry belongs to, never a UTC guess) persisted per account at
 * mindpattern.crisisDialog.v1.<userId>, the same non-content standing as
 * the onboarding and threshold stamps (WEB_PLAN D-4): a date names no
 * health data. The W-6 prefix wipe (sign-out / account deletion) removes
 * it with every other mindpattern.* flag.
 *
 * The failure direction is deliberately TOWARD SHOWING: when storage is
 * unusable a process-lifetime memory mirror is the only record, so a
 * broken store can suppress a repeat prompt WITHIN one session at most —
 * a restart re-shows it. The stamp is a fatigue guard, never a gate that
 * can permanently silence support.
 */
import { localStore } from "./platform";

const key = (userId: string): string => `mindpattern.crisisDialog.v1.${userId}`;

/** Process-lifetime mirror, consulted ONLY when storage is unusable. */
const memoryStamps = new Map<string, string>();

/** True when the support prompt already ran for this account on `todayISO`. */
export async function crisisDialogShownOn(userId: string, todayISO: string): Promise<boolean> {
  try {
    return localStore.get(key(userId)) === todayISO;
  } catch {
    // Storage unreadable: the memory mirror is the only record left.
    return memoryStamps.get(userId) === todayISO;
  }
}

/** Stamp the prompt as shown today. The mirror is always written, so a
 *  storage failure still throttles repeats within this session. The stamp
 *  records BEFORE the prompt shows — sequential saves cannot double-fire. */
export async function recordCrisisDialogShown(userId: string, todayISO: string): Promise<void> {
  memoryStamps.set(userId, todayISO);
  try {
    localStore.set(key(userId), todayISO);
  } catch {
    // The mirror holds it; a restart simply re-shows the prompt (fail-open).
  }
}

/** Test/deletion hygiene: the stamp must not outlive its account. (The
 *  W-6 prefix wipe already covers this; the explicit drop keeps the module
 *  self-contained like mobile's clearCrisisDialogStamp.) */
export async function clearCrisisDialogStamp(userId: string): Promise<void> {
  memoryStamps.delete(userId);
  try {
    localStore.removePrefix(key(userId));
  } catch {
    // Storage is optional; never fail a hygiene path on it.
  }
}
