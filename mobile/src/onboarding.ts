/**
 * First-run onboarding state: shown ONCE after a registration, never after
 * a plain login or an unlock.
 *
 * Two pieces of state:
 *  - a MEMORY-ONLY "pending" flag: LoginScreen sets it the moment a
 *    registration succeeds; the navigator consumes it (exactly once) when
 *    the main flow first renders. Login and unlock never set it, so those
 *    paths never see onboarding. Memory-only also means it cannot outlive
 *    the session it was registered in — a restart before onboarding simply
 *    lands on the journal.
 *  - a PERSISTED per-account "seen" flag (the components/keyConsent.ts
 *    idiom): written when onboarding completes, wiped on account deletion.
 *    It is the belt-and-braces guard — landing on the onboarding screen
 *    with the flag already set routes straight to the journal instead of
 *    lecturing twice.
 *
 * Losing the flag to a storage error is fail-safe in the honest direction:
 * worst case, three short calm panels show once more.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

const key = (userId: string): string => `@mindpattern/onboarding_seen_${userId}`;

let pending = false;

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

export async function hasSeenOnboarding(userId: string): Promise<boolean> {
  return (await AsyncStorage.getItem(key(userId))) !== null;
}

export async function recordOnboardingSeen(userId: string): Promise<void> {
  await AsyncStorage.setItem(key(userId), "1");
}

/** Account-deletion hygiene: the flag must not outlive its account. */
export async function clearOnboardingSeen(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
