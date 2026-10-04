/**
 * Crisis-dialog throttle: at most once per calendar day, account, and
 * trigger. Journal-language detection and an endorsed PHQ-9 item 9 are
 * deliberately independent: seeing a general journal prompt must never
 * suppress the first item-9 safety response for a later questionnaire.
 *
 * The support dialog used to fire on EVERY crisis-flagged save — dialog
 * fatigue trains dismissal, and the user who needs it most stops reading
 * it. The stamp is an ISO LOCAL calendar date (the same day the entry
 * belongs to, never a UTC guess) persisted per account at
 * @mindpattern/crisis_dialog_<userId> via the encrypted secure store. Account deletion
 * must wipe it — clearCrisisDialogStamp rides the SettingsScreen deletion
 * flow, the same idiom as components/keyConsent.ts.
 *
 * The failure direction is deliberately TOWARD SHOWING: when storage is
 * unusable a process-lifetime memory mirror is the only record, so a
 * broken store can suppress a repeat dialog WITHIN one session at most —
 * a restart re-shows it. The stamp is a fatigue guard, never a gate that
 * can permanently silence support.
 */
import { secureStore } from "./secureStore";
import { accountStorageKey } from "./accountStorage";
import { commitActiveAccountWrite } from "./localWriteGuard";

export type CrisisDialogTrigger = "journal" | "phq9-item9";

const key = (userId: string, trigger: CrisisDialogTrigger): string =>
  trigger === "journal"
    ? accountStorageKey.crisisJournal(userId)
    : accountStorageKey.crisisItem9(userId);

const memoryKey = (userId: string, trigger: CrisisDialogTrigger): string => `${trigger}:${userId}`;

/** Process-lifetime mirror, consulted ONLY when storage throws. */
const memoryStamps = new Map<string, string>();

/** True when the support dialog already ran for this account on `todayISO`. */
export async function crisisDialogShownOn(
  userId: string,
  todayISO: string,
  trigger: CrisisDialogTrigger = "journal",
): Promise<boolean> {
  try {
    return (await secureStore.getItem(key(userId, trigger))) === todayISO;
  } catch {
    // Storage unreadable: the memory mirror is the only record left.
    return memoryStamps.get(memoryKey(userId, trigger)) === todayISO;
  }
}

/** Stamp the dialog as shown today. The mirror is always written, so a
 *  storage failure still throttles repeats within this session. */
export async function recordCrisisDialogShown(
  userId: string,
  todayISO: string,
  trigger: CrisisDialogTrigger = "journal",
): Promise<void> {
  try {
    await commitActiveAccountWrite(userId, async () => {
      // Admission already proved this owner/generation is active. Update the
      // process mirror before the fallible native write so disk pressure
      // still prevents same-session dialog fatigue; erasure waits this
      // tracked commit and clears the mirror afterwards.
      memoryStamps.set(memoryKey(userId, trigger), todayISO);
      await secureStore.setItem(key(userId, trigger), todayISO);
    });
  } catch {
    // A pre-admission retired write fails open. Once admitted, the mirror is
    // intentionally retained even if native persistence fails so this process
    // does not fatigue the user with a repeat dialog.
  }
}

/** Account-deletion hygiene: the stamp must not outlive its account. */
export async function clearCrisisDialogStamp(userId: string): Promise<void> {
  memoryStamps.delete(memoryKey(userId, "journal"));
  memoryStamps.delete(memoryKey(userId, "phq9-item9"));
  await Promise.all([
    secureStore.removeItem(key(userId, "journal")),
    secureStore.removeItem(key(userId, "phq9-item9")),
  ]);
}
