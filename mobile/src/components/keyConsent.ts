/**
 * Per-account consent for sending a data key to a processing session.
 * QuestionScreen explains the temporary, memory-only processing before the
 * first request. Account erasure removes the acknowledgment; a missing
 * flag requires the explanation again.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { accountStorageKey } from "../accountStorage";
import { commitActiveAccountWrite } from "../localWriteGuard";

const key = accountStorageKey.keyShipmentConsent;

export async function hasKeyShipConsent(userId: string): Promise<boolean> {
  return (await AsyncStorage.getItem(key(userId))) !== null;
}

export async function recordKeyShipConsent(userId: string): Promise<void> {
  await commitActiveAccountWrite(userId, () => AsyncStorage.setItem(key(userId), "1"));
}

/** Account-deletion hygiene: the consent flag must not outlive its account. */
export async function clearKeyShipConsent(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
