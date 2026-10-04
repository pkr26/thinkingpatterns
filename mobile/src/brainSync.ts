/**
 * Cleanup for recompute stamps left by older app versions.
 * Processing sessions require an explicit action in QuestionScreen;
 * this module never starts analysis or sends a data key.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { accountStorageKey } from "./accountStorage";

/** Storage key retained for deleting legacy per-account recompute stamps. */
const stampKey = accountStorageKey.recompute;

/** Account-deletion hygiene: remove this account's recompute stamp. */
export async function clearRecomputeStamp(userId: string): Promise<void> {
  await AsyncStorage.removeItem(stampKey(userId));
}
