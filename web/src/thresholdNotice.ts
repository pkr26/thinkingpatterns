/**
 * One-time threshold-crossing notice (ported from mobile's
 * thresholdNotice.ts; the flag is a non-content date stamp).
 *
 * 2026-10-01 audit L: the stamp used to live in PLAINTEXT localStorage
 * keyed by account id — the exact "date paired with the account id is
 * interaction metadata" class the 2026-09-27 audit removed the crisis
 * dialog's stamp for. It now rides the kv seam (IndexedDB, not
 * localStorage) under the same non-content disclosure as the cadence
 * snooze dates, and sign-out clears it with the other per-account keys.
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
