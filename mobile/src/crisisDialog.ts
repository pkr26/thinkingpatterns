/**
 * Crisis-dialog throttle: at most once per calendar day per account.
 *
 * The support dialog used to fire on EVERY crisis-flagged save — dialog
 * fatigue trains dismissal, and the user who needs it most stops reading
 * it. The stamp is an ISO LOCAL calendar date (the same day the entry
 * belongs to, never a UTC guess) persisted per account at
 * @mindpattern/crisis_dialog_<userId> via AsyncStorage. Account deletion
 * must wipe it — clearCrisisDialogStamp rides the SettingsScreen deletion
 * flow, the same idiom as components/keyConsent.ts.
 *
 * The failure direction is deliberately TOWARD SHOWING: when storage is
 * unusable a process-lifetime memory mirror is the only record, so a
 * broken store can suppress a repeat dialog WITHIN one session at most —
 * a restart re-shows it. The stamp is a fatigue guard, never a gate that
 * can permanently silence support.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

const key = (userId: string): string => `@mindpattern/crisis_dialog_${userId}`;

/** Process-lifetime mirror, consulted ONLY when storage throws. */
const memoryStamps = new Map<string, string>();

/** True when the support dialog already ran for this account on `todayISO`. */
export async function crisisDialogShownOn(userId: string, todayISO: string): Promise<boolean> {
  try {
    return (await AsyncStorage.getItem(key(userId))) === todayISO;
  } catch {
    // Storage unreadable: the memory mirror is the only record left.
    return memoryStamps.get(userId) === todayISO;
  }
}

/** Stamp the dialog as shown today. The mirror is always written, so a
 *  storage failure still throttles repeats within this session. */
export async function recordCrisisDialogShown(userId: string, todayISO: string): Promise<void> {
  memoryStamps.set(userId, todayISO);
  try {
    await AsyncStorage.setItem(key(userId), todayISO);
  } catch {
    // The mirror holds it; a restart simply re-shows the dialog (fail-open).
  }
}

/** Account-deletion hygiene: the stamp must not outlive its account. */
export async function clearCrisisDialogStamp(userId: string): Promise<void> {
  memoryStamps.delete(userId);
  await AsyncStorage.removeItem(key(userId));
}
