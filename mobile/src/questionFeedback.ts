/**
 * Encrypted question feedback and pattern-mute events.
 * Events are scoped to the account and queued locally under its data key.
 * The next explicit recompute sends an opaque blob through the existing
 * single-use processing session; a successful recompute clears the queue.
 *
 * Until recompute succeeds, a pattern mute is optimistic local state.
 * Losing the queue can make that pattern visible again.
 */
import { captureLocalWritePermit, captureOpaqueLocalWritePermit, assertLocalWritePermit, commitLocalWrite, type LocalWritePermit } from "./localRekey";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, encrypt, decrypt } from "./crypto/envelope";
import { zeroize } from "./crypto/kdf";
import { accountStorageKey } from "./accountStorage";
import { engine } from "./crypto/engine";

const key = accountStorageKey.feedback;
const MAX_PENDING = 100;

export interface FeedbackTap {
  pid: string;
  resonated: boolean;
}

/** A pattern mute/unmute request queued for the next recompute. */
export interface MuteEvent {
  pid: string;
  mute: boolean;
}

export type FeedbackEvent = FeedbackTap | MuteEvent;
type PendingEvent = FeedbackEvent & { event_id?: string };
export interface FeedbackReceipt { events: ReadonlyArray<PendingEvent>; }

function isTap(event: FeedbackEvent): event is FeedbackTap {
  return typeof (event as FeedbackTap).resonated === "boolean";
}

/** Serialize read-modify-write cycles so concurrent taps/mutes cannot
 * overwrite each other when appending to the same pending queue. */
let feedbackMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = feedbackMutex.then(operation, operation);
  feedbackMutex = run.catch(() => {});
  return run;
}

async function readPending(dataKey: Buffer, userId: string, assertCurrent?: () => void): Promise<PendingEvent[]> {
  const raw = await AsyncStorage.getItem(key(userId));
  assertCurrent?.();
  if (!raw) return [];
  let plain: Buffer | null = null;
  try {
    plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", userId));
    const parsed = JSON.parse(plain.toString("utf8")) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is FeedbackEvent =>
        typeof e === "object" && e !== null && typeof (e as FeedbackEvent).pid === "string" &&
        (typeof (e as FeedbackTap).resonated === "boolean" ||
          typeof (e as MuteEvent).mute === "boolean"),
    );
  } catch {
    return []; // wrong key / corruption: disposable
  } finally {
    zeroize(plain);
  }
}

/** Record one tap or mute event (fire-and-forget friendly). */
export async function recordFeedbackTap(
  dataKey: Buffer, userId: string, pid: string, resonated: boolean, stillCurrent?: () => boolean,
): Promise<void> {
  await appendEvent(dataKey, userId, { pid, resonated }, stillCurrent);
}

/** Queue a pattern mute (or unmute) for the next recompute. */
export async function recordPatternMute(
  dataKey: Buffer, userId: string, pid: string, mute: boolean, stillCurrent?: () => boolean,
): Promise<void> {
  await appendEvent(dataKey, userId, { pid, mute }, stillCurrent);
}

async function appendEvent(dataKey: Buffer, userId: string, event: FeedbackEvent, stillCurrent?: () => boolean): Promise<void> {
  const assertCurrent = () => {
    if (stillCurrent && !stillCurrent()) throw new Error("The feedback view has retired");
  };
  assertCurrent();
  const permit = captureLocalWritePermit(userId, dataKey);
  const keyCopy = Buffer.from(dataKey);
  try {
    // Serialize appends to prevent lost feedback during concurrent taps.
    await serialized(async () => {
      assertCurrent();
      assertLocalWritePermit(permit);
      const pending = await readPending(keyCopy, userId, assertCurrent);
      assertCurrent();
      pending.push({ ...event, event_id: engine.randomBytes(16).toString("base64") });
      const plain = Buffer.from(JSON.stringify(pending.slice(-MAX_PENDING)), "utf8");
      try {
        const blob = encrypt(keyCopy, plain, buildAad("feedback-local", userId));
        await commitLocalWrite(permit, () => {
          assertCurrent();
          return AsyncStorage.setItem(key(userId), blob.toString("base64"));
        });
      } finally { zeroize(plain); }
    });
  } finally {
    zeroize(keyCopy);
  }
}

/** The opaque blob for the recompute body, or null when nothing is pending.
 *  Encrypts under the DATA key with the server's feedback AAD. The shipped
 *  shape partitions taps from mutes: {"feedback": [...], "muted": [pids],
 *  "unmuted": [pids]} — the server applies each list separately. */
export async function buildFeedbackBlob(
  dataKey: Buffer, userId: string, prepared?: (receipt: FeedbackReceipt) => void, stillCurrent?: () => boolean,
): Promise<string | null> {
  const assertCurrent = () => { if (stillCurrent && !stillCurrent()) throw new Error("The feedback view has retired"); };
  assertCurrent();
  const keyCopy = Buffer.from(dataKey);
  let plain: Buffer | null = null;
  try {
    const pending = await readPending(keyCopy, userId, assertCurrent);
    assertCurrent();
    if (pending.length === 0) return null;
    const taps = pending.filter(isTap).map(({ pid, resonated }) => ({ pid, resonated }));
    // Last write wins per pid: an unmute queued after a mute (or the
    // reverse) is the user's final word, and the server applies lists in
    // muted-then-unmuted order anyway.
    const mutes = new Map<string, boolean>();
    for (const event of pending) {
      if (!isTap(event)) mutes.set(event.pid, event.mute);
    }
    plain = Buffer.from(
        JSON.stringify({
          feedback: taps,
          muted: [...mutes.entries()].filter(([, m]) => m).map(([pid]) => pid),
          unmuted: [...mutes.entries()].filter(([, m]) => !m).map(([pid]) => pid),
        }),
        "utf8",
      );
    const blob = encrypt(
      keyCopy,
      plain,
      // Bind feedback to its UTC seal date to limit replay across recomputes.
      // The server accepts today or yesterday to tolerate midnight crossings.
      buildAad("feedback", userId, new Date().toISOString().slice(0, 10)),
    );
    prepared?.({ events: pending.map(event => ({ ...event })) });
    return blob.toString("base64");
  } finally {
    zeroize(keyCopy, plain);
  }
}

/** Clear after a successful recompute (the server consumed the taps). */
export async function clearFeedback(userId: string, source?: LocalWritePermit, acknowledged?: { dataKey: Buffer; receipt: FeedbackReceipt }, stillCurrent?: () => boolean): Promise<void> {
  const assertCurrent = () => { if (stillCurrent && !stillCurrent()) throw new Error("The feedback view has retired"); };
  assertCurrent();
  const permit = captureOpaqueLocalWritePermit(userId, source);
  if (!acknowledged) {
    await serialized(() => {
      assertCurrent();
      return commitLocalWrite(permit, () => {
        assertCurrent();
        return AsyncStorage.removeItem(key(userId));
      });
    });
    return;
  }
  const keyCopy = Buffer.from(acknowledged.dataKey);
  try {
    await serialized(async () => {
      assertCurrent();
      assertLocalWritePermit(permit);
      const pending = await readPending(keyCopy, userId, assertCurrent);
      assertCurrent();
      const consumed = [...acknowledged.receipt.events];
      const retained = pending.filter(event => {
        const index = consumed.findIndex(sent => typeof event.event_id === "string"
          ? event.event_id === sent.event_id
          : typeof sent.event_id !== "string" && event.pid === sent.pid && isTap(event) === isTap(sent)
            && (isTap(event) ? event.resonated === (sent as FeedbackTap).resonated : event.mute === (sent as MuteEvent).mute));
        if (index < 0) return true;
        consumed.splice(index, 1);
        return false;
      });
      if (retained.length === 0) {
        await commitLocalWrite(permit, () => {
          assertCurrent();
          return AsyncStorage.removeItem(key(userId));
        });
        return;
      }
      const plain = Buffer.from(JSON.stringify(retained), "utf8");
      try {
        const blob = encrypt(keyCopy, plain, buildAad("feedback-local", userId));
        await commitLocalWrite(permit, () => {
          assertCurrent();
          return AsyncStorage.setItem(key(userId), blob.toString("base64"));
        });
      } finally { zeroize(plain); }
    });
  } finally { zeroize(keyCopy); }
}
export async function eraseFeedback(userId: string): Promise<void> { await AsyncStorage.removeItem(key(userId)); }
