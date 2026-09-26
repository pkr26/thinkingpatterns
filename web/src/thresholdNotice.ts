/**
 * One-time threshold-crossing notice (ported from mobile's
 * thresholdNotice.ts; the flag is a non-content date stamp — the same
 * standing as the onboarding flag, WEB_PLAN P6.5).
 */
import { localStore } from "./platform";

const PREFIX = "mindpattern.thresholdNotice.v1.";

export async function thresholdNoticeShown(userId: string): Promise<boolean> {
  return localStore.get(`${PREFIX}${userId}`) !== null;
}

export async function recordThresholdNotice(userId: string): Promise<void> {
  localStore.set(`${PREFIX}${userId}`, new Date().toISOString().slice(0, 10));
}

export async function clearThresholdNotice(userId: string): Promise<void> {
  localStore.removePrefix(`${PREFIX}${userId}`);
}
