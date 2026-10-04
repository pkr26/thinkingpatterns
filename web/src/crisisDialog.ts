/**
 * Limit the support prompt to once per local calendar day per account.
 *
 * Stamps stay in session memory because a crisis-interaction date is sensitive
 * metadata. Reloading may show the prompt again: throttling must never
 * permanently suppress support. Legacy localStorage stamps are removed when
 * this module is first consulted.
 */
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

/** Test seam: the stamps are a module singleton, so tests reset them the
 *  way entryVersions' mirrors reset (tests/helpers/api.ts) — the throttle
 *  must not leak between cases now that it left wipeable localStorage. */
export function resetCrisisDialogStampsForTests(): void {
  sessionStamps.clear();
  legacySwept = false;
}
