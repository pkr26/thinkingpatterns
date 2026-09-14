/**
 * Informed consent for key shipment (QuestionScreen).
 *
 * Showing a question can open a single-use processing session — the ONE
 * moment the data key travels to the server (memory-only, destroyed within
 * minutes). The user was never told; now the first tap explains it and the
 * acknowledgment is recorded per account (a different account on the same
 * device gets asked again; account deletion wipes it — SettingsScreen).
 *
 * Losing the flag to a storage error is fail-safe in the honest direction:
 * the user is simply shown the explainer again.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

const key = (userId: string): string => `@mindpattern/keyship_consent_${userId}`;

export async function hasKeyShipConsent(userId: string): Promise<boolean> {
  return (await AsyncStorage.getItem(key(userId))) !== null;
}

export async function recordKeyShipConsent(userId: string): Promise<void> {
  await AsyncStorage.setItem(key(userId), "1");
}

/** Account-deletion hygiene: the consent flag must not outlive its account. */
export async function clearKeyShipConsent(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
