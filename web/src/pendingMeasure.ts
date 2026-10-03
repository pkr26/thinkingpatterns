/**
 * Pending measure persistence (audit 2026-09-26 LOW) — the web port of
 * mobile/src/pendingMeasure.ts onto the kvstore seam + async WebCrypto.
 *
 * A COMPLETED questionnaire used to live only in MeasuresView state: a
 * submit that failed offline (status 0) surfaced an error banner and every
 * answer died with the view. The completed record now survives here —
 * {kind, clientMeasureId, picks, date}, encrypted under the data key
 * exactly like the mood log (AES-GCM, AAD binds the user; a wrong key or
 * tampered record reads as absent) — and MeasuresView restores + retries
 * it on its next mount.
 *
 * WHY A PENDING RECORD, NOT AN OFFLINE-QUEUE ENTRY (mobile's deliberate
 * call, kept): offlineQueue.ts is entry-shaped — content_version
 * semantics, per-row origin pinning, reject/requeue machinery — and wiring
 * a second payload type into it for one row buys nothing: the retry needs
 * exactly one property, IDEMPOTENCY, and the server provides it natively.
 * POST /measures is idempotent by client_measure_id (backend
 * app/api/measures.py: a retry of a send that landed-but-was-never-acked
 * answers 409 conflict, which the view already treats as "recorded"). That
 * is also why the client id is persisted BEFORE the first send and reused
 * by every retry: a status-0 failure can be a timeout AFTER the server
 * committed, and a fresh id per attempt would record the same answers
 * twice. The record clears on the first 201 or 409.
 *
 * Item 6 (same audit): the picks are option VALUES, never option array
 * indexes — validated as membership in the instrument's option scale.
 */
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv,type WritePermit } from "./kvstore";
import { INSTRUMENTS, type MeasureId } from "./measures";

/** One completed-but-unsent questionnaire. */
export interface PendingMeasure {
  kind: MeasureId;
  /** Stable across retries: the idempotency key (see module header). */
  clientMeasureId: string;
  /** The per-item picks, in item order — option VALUES (item 6). */
  picks: number[];
  /** LOCAL calendar day the questionnaire was completed (date-granular,
   *  like every measure date). */
  date: string;
}

const key = (userId: string): string => `mindpattern.pendingMeasure.${userId}`;

/** Full validation of anything read back from storage, the mobile
 *  discipline: a hostile or half-written record is null, never
 *  hour-99-style nonsense reaching the send path. */
function parseRecord(raw: string | null): PendingMeasure | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const { kind, clientMeasureId, picks, date } = parsed as Record<string, unknown>;
    if (typeof kind !== "string" || !Object.prototype.hasOwnProperty.call(INSTRUMENTS, kind)) return null;
    const instrument = INSTRUMENTS[kind as MeasureId];
    if (typeof clientMeasureId !== "string" || clientMeasureId.length === 0 || clientMeasureId.length > 128) {
      return null;
    }
    if (!Array.isArray(picks) || picks.length !== instrument.items) return null;
    for (const pick of picks) {
      if (typeof pick !== "number" || !Number.isInteger(pick) || !instrument.options.includes(pick)) return null;
    }
    if (typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
    return { kind: kind as MeasureId, clientMeasureId, picks: picks as number[], date };
  } catch {
    return null;
  }
}

/** Persist the record BEFORE its send (see module header). Throws on a
 *  storage failure — the caller treats persistence as best-effort relative
 *  to the send, never as a reason to drop the answers. */
export async function savePendingMeasure(dataKey: Bytes, userId: string, record: PendingMeasure): Promise<void> {
  const keyCopy=new Uint8Array(dataKey);
  const payload = new TextEncoder().encode(JSON.stringify(record));
  try {
    const permit=await kv.captureWritePermit(userId,keyCopy);
    const blob = await encrypt(keyCopy, payload, buildAad("pending-measure", userId));
    await kv.setItem(key(userId), toBase64(blob),permit);
  } finally {
    zeroize(payload,keyCopy);
  }
}

/** The pending record for this account, or null when absent, corrupt, or
 *  under the wrong key (account switch / rotation): disposable metadata
 *  around one questionnaire, never worth an error surface. Never throws. */
export async function loadPendingMeasure(dataKey: Bytes, userId: string): Promise<PendingMeasure | null> {
  const raw = await kv.getItem(key(userId));
  if (!raw) return null;
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(raw), buildAad("pending-measure", userId));
    return parseRecord(new TextDecoder().decode(plaintext));
  } catch {
    return null;
  } finally {
    zeroize(plaintext);
  }
}

/** The send landed (201) or was already recorded (409): the record must
 *  not outlive its questionnaire. */
export async function clearPendingMeasure(userId: string,permit?:WritePermit): Promise<void> {
  await kv.removeItem(key(userId),permit);
}

/** Rotation parity with the B-7 rewrap family: re-seal an in-flight
 *  questionnaire under the incoming key so it survives a v1 password
 *  change. A failure propagates so the rotation falls back to clearing
 *  (the record is disposable metadata around one form, never worth an
 *  error that blocks the rotation). */
export async function rewrapPendingMeasure(oldKey: Bytes, newKey: Bytes, userId: string): Promise<void> {
  const record = await loadPendingMeasure(oldKey, userId);
  if (record === null) return;
  await savePendingMeasure(newKey, userId, record);
}
