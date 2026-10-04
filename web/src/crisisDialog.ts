/**
 * Crisis-prompt throttle (audit 2026-09-26, LOW c): at most once per
 * LOCAL calendar day per account — ported from mobile's crisisDialog.ts.
 *
 * The Entry prompt used to fire on EVERY crisis-flagged draft — dialog
 * fatigue trains dismissal, and the person who needs the resources most
 * stops reading them.
 *
 * independent audit 2026-09-27 (P2): the stamp used to persist a
 * PLAINTEXT DATE of a crisis-flagged interaction at
 * mindpattern.crisisDialog.v1.<userId> in localStorage. A date paired
 * with the account id is interaction metadata this app has no business
 * leaving on disk — the zero-knowledge posture keeps even device-local
 * content encrypted. The record is now SESSION-SCOPED, in memory only:
 * the once-per-day UX is unchanged within a session, and a page reload
 * can re-show the prompt the same day (fail toward showing — the stamp
 * is a fatigue guard, never a gate that can permanently silence
 * support). The legacy localStorage key is opportunistically removed
 * the first time this module is consulted.
 */
// @ts-nocheck

import { localStore } from "./platform";

/** The pre-fix localStorage prefix (the one-time cleanup target). */
const LEGACY_PREFIX = "mindpattern.crisisDialog.v1.";

/** Session-scoped record: account id → the ISO LOCAL date the prompt last
 *  ran on. Module-level by design — it dies with the page. */
const sessionStamps = new Map<string, string>();

/** Remove every legacy stamp this browser still carries, once per load. */
let legacySwept = false;
function sweepLegacyStampOnce(): void {
  if (legacySwept) return;
  legacySwept = true;
  localStore.removePrefix(LEGACY_PREFIX);
}

/** L-8 (2026-09-28 audit): run the legacy-plaintext sweep at App mount.
 *  The module-scoped trigger only fired when a crisis-flagged save first
 *  consulted it — a user who never triggered one kept the pre-fix
 *  plaintext date on disk indefinitely (locks deliberately preserve
 *  mindpattern.* keys). Called once from the App shell so the sweep runs
 *  for EVERY visitor, crisis-flagged or not. */
export function sweepLegacyCrisisStamps(): void {
  sweepLegacyStampOnce();
}

/** True when the support prompt already ran for this account on `todayISO`. */
export async function crisisDialogShownOn(userId: string, todayISO: string): Promise<boolean> {
  sweepLegacyStampOnce();
  return sessionStamps.get(userId) === todayISO;
}

/** Stamp the prompt as shown today. The stamp records BEFORE the prompt
 *  shows — sequential saves cannot double-fire. */
export async function recordCrisisDialogShown(userId: string, todayISO: string): Promise<void> {
  sweepLegacyStampOnce();
  sessionStamps.set(userId, todayISO);
}

/** Test/deletion hygiene: the stamp must not outlive its account. */
export async function clearCrisisDialogStamp(userId: string): Promise<void> {
  sessionStamps.delete(userId);
  localStore.remove(`${LEGACY_PREFIX}${userId}`);
}

/** Test seam: the stamps are a module singleton, so tests reset them the
 *  way entryVersions' mirrors reset (tests/helpers/api.ts) — the throttle
 *  must not leak between cases now that it left wipeable localStorage. */
export function resetCrisisDialogStampsForTests(): void {
  sessionStamps.clear();
  legacySwept = false;
}
