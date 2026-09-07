/**
 * Mini-brain refresh: account-deletion hygiene for the daily-recompute stamp.
 *
 * The daily auto-refresh (maybeDailyRecompute) was REMOVED after the
 * red-team audit: shipping the data key to the server is only ever an
 * EXPLICIT, user-initiated act — the Question screen's button, which opens
 * the processing session itself (src/screens/QuestionScreen.tsx). No other
 * screen has a recompute affordance, so nothing may invoke a key-shipping
 * refresh automatically or on a casual gesture.
 *
 * What remains here is the stamp cleanup: installs that ran the old daily
 * job can still carry a `@mindpattern/last_recompute_<userId>` marker, and
 * the Settings screen's account-deletion flow wipes it per account.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

/** Per-account stamp: a shared key let one account's refresh satisfy (and
 *  skip) another account's — and the upload ships the DATA KEY, so the
 *  "once per day" cap held per account. */
const stampKey = (userId: string): string => `@mindpattern/last_recompute_${userId}`;

/** Account-deletion hygiene: remove this account's recompute stamp. */
export async function clearRecomputeStamp(userId: string): Promise<void> {
  await AsyncStorage.removeItem(stampKey(userId));
}
