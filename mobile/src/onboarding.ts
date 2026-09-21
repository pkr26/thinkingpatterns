/**
 * First-run onboarding state: shown ONCE after a registration, never after
 * a plain login or an unlock.
 *
 * Three pieces of state:
 *  - a MEMORY-ONLY "pending" flag: LoginScreen sets it the moment a
 *    registration succeeds; the navigator consumes it (exactly once) when
 *    the main flow first renders. Login and unlock never set it, so those
 *    paths never see onboarding through this flag.
 *  - a PERSISTED per-account "seen" flag (the components/keyConsent.ts
 *    idiom): written when onboarding completes, wiped on account deletion.
 *    It is the belt-and-braces guard — landing on the onboarding screen
 *    with the flag already set routes straight to the journal instead of
 *    lecturing twice.
 *  - an in-memory MIRROR of the persisted flag (audit M-18, 2026-09-20):
 *    the navigator re-derives its gate on every entry into the main flow,
 *    and the render-time half of that needs a synchronous answer. The
 *    mirror is written by hasSeenOnboarding (on a successful storage read)
 *    and kept live by recordOnboardingSeen/clearOnboardingSeen; storage
 *    remains the source of truth for every async read.
 *
 * M-18 behavior change: backgrounding mid-onboarding locks the vault and
 * consumes the one-shot pending flag; re-deriving from the persisted flag
 * on re-entry restores the remaining panels instead of silently skipping
 * them. A full restart before completion also resumes now (the flag is on
 * disk, not only in memory) — the old "restart lands on the journal" note
 * is superseded; losing the WRITE to a storage error still only costs
 * showing the three short panels once more (fail-safe direction).
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

const key = (userId: string): string => `@mindpattern/onboarding_seen_${userId}`;

// E-10 (2026-09-21): M-18's re-entry restored the SCREEN but the panel
// index still restarted at 1 — a backgrounded user re-read everything
// they had already dismissed. The index persists beside the seen flag
// (single global key: only one onboarding runs at a time, and completion
// or account deletion wipes it).
const PANEL_INDEX_KEY = "@mindpattern/onboarding_panel";

let pending = false;

export async function saveOnboardingPanel(index: number): Promise<void> {
  try {
    await AsyncStorage.setItem(PANEL_INDEX_KEY, String(index));
  } catch {
    // Storage pressure: the resume position is a nicety, never a crash —
    // the fail-safe direction is showing a dismissed panel once more.
  }
}

export async function loadOnboardingPanel(panelCount: number): Promise<number> {
  try {
    const raw = await AsyncStorage.getItem(PANEL_INDEX_KEY);
    const parsed = Number.parseInt(raw ?? "0", 10);
    return Number.isInteger(parsed) && parsed > 0 && parsed < panelCount ? parsed : 0;
  } catch {
    return 0;
  }
}

/** Mirror of the persisted flag for the LAST account it was resolved for
 *  (null = not resolved yet in this process). */
let seenMemo: { userId: string; seen: boolean } | null = null;

/** Mark that THIS session just created its account — the navigator routes
 *  the first render of the main flow through onboarding. */
export function queueOnboarding(): void {
  pending = true;
}

/** One-shot read: true exactly once per queueOnboarding() call, so a later
 *  login inside the same session can never trigger onboarding. */
export function takePendingOnboarding(): boolean {
  const wasPending = pending;
  pending = false;
  return wasPending;
}

/** Reads STORAGE as the source of truth and refreshes the mirror on
 *  success. The mirror is deliberately NOT consulted here: a memo-first
 *  read would go stale against external storage changes and would defeat
 *  the failure semantics callers rely on (a broken store must REJECT, not
 *  silently answer from memory — OnboardingScreen fails toward showing,
 *  the navigator fails toward seen, both from the rejection). */
export async function hasSeenOnboarding(userId: string): Promise<boolean> {
  const seen = (await AsyncStorage.getItem(key(userId))) !== null;
  seenMemo = { userId, seen };
  return seen;
}

/** Synchronous read of the in-memory mirror: the persisted answer for THIS
 *  account when it has been resolved this process, else null. This is the
 *  navigator's render-time gate input (M-18) — null means "not known yet",
 *  which the navigator treats as seen rather than guessing. */
export function onboardingSeenCached(userId: string): boolean | null {
  return seenMemo?.userId === userId ? seenMemo.seen : null;
}

/** Completion keeps the mirror live so a lock/unlock cycle in the SAME
 *  session cannot re-derive "unseen" and lecture twice. */
export async function recordOnboardingSeen(userId: string): Promise<void> {
  await AsyncStorage.setItem(key(userId), "1");
  seenMemo = { userId, seen: true };
  // E-10 (2026-09-21): the resume position is meaningless once completed.
  await AsyncStorage.removeItem(PANEL_INDEX_KEY).catch(() => {});
}

/** Account-deletion hygiene: the flag must not outlive its account. */
export async function clearOnboardingSeen(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
  await AsyncStorage.removeItem(PANEL_INDEX_KEY).catch(() => {});
  if (seenMemo?.userId === userId) seenMemo = null; // next read hits storage
}
