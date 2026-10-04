/**
 * Pending measure persistence (2026-09-26 audit LOW).
 *
 * A COMPLETED questionnaire used to live only in MeasuresScreen state: a
 * submit that failed offline (status 0) or an app backgrounding mid-flow
 * (the vault lock unmounts the screen) silently destroyed every answer.
 * The completed record now survives here — {kind, clientMeasureId, picks,
 * date}, encrypted under the data key exactly like the mood log (AES-GCM,
 * AAD binds the user; a wrong key or tampered record reads as absent) —
 * and MeasuresScreen restores + retries it on its next mount.
 *
 * WHY A PENDING RECORD, NOT AN OFFLINE-QUEUE ENTRY (a deliberate call):
 * offlineQueue.ts is entry-shaped — content_version semantics, per-row
 * origin pinning, reject/requeue machinery — and wiring a second payload
 * type into it for one row buys nothing: the retry needs exactly one
 * property, IDEMPOTENCY, and the server provides it natively. POST
 * /measures is idempotent by client_measure_id (backend/app/api/measures.py:
 * a retry of a send that landed-but-was-never-acked answers 409 conflict,
 * which the screen already treats as "recorded"). That is also why the
 * client id is persisted BEFORE the first send and reused by every retry:
 * a status-0 failure can be a timeout AFTER the server committed, and a
 * fresh id per attempt would record the same answers twice. The record
 * clears on the first 201 or 409.
 */
import { captureLocalWritePermit, captureOpaqueLocalWritePermit, commitLocalWrite, type LocalWritePermit } from "./localRekey";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";
import { INSTRUMENTS, type MeasureId } from "./measures";
import { accountStorageKey } from "./accountStorage";

/** One completed-but-unsent questionnaire. */
export interface PendingMeasure {
  kind: MeasureId;
  /** Stable across retries: the idempotency key (see module header). */
  clientMeasureId: string;
  /** The per-item picks, in item order (the record is only saved once
   *  every item has one — MeasuresScreen's completion gate). */
  picks: number[];
  /** LOCAL calendar day the questionnaire was completed (date-granular,
   *  like every measure date). */
  date: string;
}

const key = accountStorageKey.pendingMeasure;

/** Full validation of anything read back from storage, the reminders.ts
 *  discipline: a hostile or half-written record is null, never hour-99
 *  style nonsense reaching the send path. */
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
    const maxOption = Math.max(...instrument.options);
    for (const pick of picks) {
      if (typeof pick !== "number" || !Number.isInteger(pick) || pick < 0 || pick > maxOption) return null;
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
export async function savePendingMeasure(dataKey: Buffer, userId: string, record: PendingMeasure): Promise<void> {
  const permit = captureLocalWritePermit(userId, dataKey);
  const keyCopy = Buffer.from(dataKey), plain = Buffer.from(JSON.stringify(record), "utf8");
  try {
    const blob = encrypt(keyCopy, plain, buildAad("pending-measure", userId));
    await commitLocalWrite(permit, () => AsyncStorage.setItem(key(userId), blob.toString("base64")));
  } finally { keyCopy.fill(0); plain.fill(0); }
}

/** The pending record for this account, or null when absent, corrupt, or
 *  under the wrong key (account switch / rotation): disposable metadata
 *  around one questionnaire, never worth an error surface. Never throws. */
export async function loadPendingMeasure(dataKey: Buffer, userId: string): Promise<PendingMeasure | null> {
  const keyCopy = Buffer.from(dataKey); let plain: Buffer | null = null;
  try {
    const raw = await AsyncStorage.getItem(key(userId));
    if (!raw) return null;
    plain = decrypt(keyCopy, Buffer.from(raw, "base64"), buildAad("pending-measure", userId));
    return parseRecord(plain.toString("utf8"));
  } catch { return null; }
  finally { keyCopy.fill(0); plain?.fill(0); }
}

/** The send landed (201) or was already recorded (409): the record must
 *  not outlive its questionnaire. Throws on storage failure — the caller
 *  catches; a surviving record only costs one idempotent retry next mount. */
export async function clearPendingMeasure(userId: string, source?: LocalWritePermit): Promise<void> {
  const permit = captureOpaqueLocalWritePermit(userId, source);
  await commitLocalWrite(permit, () => AsyncStorage.removeItem(key(userId)));
}
/** Explicit authorized account-erasure cleanup; the lifecycle is retired first. */
export async function erasePendingMeasure(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
