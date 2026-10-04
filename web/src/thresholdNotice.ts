/**
 * One-time notice that an account has crossed the pattern threshold.
 * The per-account date stamp lives in IndexedDB and participates in account
 * cleanup. It contains no journal content.
 */
import { kv } from "./kvstore";

const KEY = "mindpattern.thresholdNotice.v1";

export async function thresholdNoticeShown(userId: string): Promise<boolean> {
  return (await kv.getItem(`${KEY}.${userId}`)) !== null;
}

export async function recordThresholdNotice(userId: string): Promise<void> {
  await kv.setItem(`${KEY}.${userId}`, new Date().toISOString().slice(0, 10));
}

export async function clearThresholdNotice(userId: string): Promise<void> {
  await kv.removeItem(`${KEY}.${userId}`);
}
