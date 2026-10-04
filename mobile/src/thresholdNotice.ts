/**
 * Per-account stamp for the one-time analysis-threshold notice.
 * Record the stamp when the notice appears, not when it is dismissed.
 * secureStore encrypts the record; account erasure removes it.
 *
 * If persistence fails, an in-memory mirror prevents repeats in the current
 * process. A restart may show the notice again rather than suppressing it.
 */
import { secureStore } from "./secureStore";
import { accountStorageKey } from "./accountStorage";
import { commitActiveAccountWrite } from "./localWriteGuard";

const key = accountStorageKey.thresholdNotice;

/** Process-lifetime mirror, consulted ONLY when storage throws. */
const memoryShown = new Set<string>();

/** True when the one-time threshold card already ran for this account. */
export async function thresholdNoticeShown(userId: string): Promise<boolean> {
  try {
    return (await secureStore.getItem(key(userId))) !== null;
  } catch {
    // Storage unreadable: the memory mirror is the only record left.
    return memoryShown.has(userId);
  }
}

/** Stamp the notice as shown. The mirror is always written, so a storage
 *  failure still suppresses repeats within this session. */
export async function recordThresholdNotice(userId: string): Promise<void> {
  try {
    await commitActiveAccountWrite(userId, async () => {
      await secureStore.setItem(key(userId), "1");
      memoryShown.add(userId);
    });
  } catch {
    // A failed/retired write simply re-shows the card (fail-open).
  }
}

/** Account-deletion hygiene: the stamp must not outlive its account. */
export async function clearThresholdNotice(userId: string): Promise<void> {
  memoryShown.delete(userId);
  await secureStore.removeItem(key(userId));
}
