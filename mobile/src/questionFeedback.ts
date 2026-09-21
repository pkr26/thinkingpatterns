/**
 * Question feedback (2026-09-17): "did this land?" taps.
 *
 * One tap per question ("This resonated" / "Not me"), stored ENCRYPTED on
 * this device under the session data key (AAD-bound to the account), and
 * shipped as an opaque blob WITH THE NEXT RECOMPUTE — the same
 * single-use-session moment that already carries the data key, so the
 * server never sees plaintext pids and never learns what was answered
 * except inside the secure processing context. The brain's question
 * ranking reads the taps; after a successful recompute the queue clears.
 *
 * Pattern mutes (2026-09-19) ride the exact same channel: "stop showing me
 * this" / unmute events queue locally, travel encrypted with the next
 * recompute, and land in the brain's per-pattern muted set. Until that
 * recompute runs, a mute is optimistic client state only — the pattern
 * reappears if the queue is lost, which is the honest failure direction.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, encrypt, decrypt } from "./crypto/envelope";
import { zeroize } from "./crypto/kdf";

const key = (userId: string): string => `@mindpattern/question_feedback.${userId}`;
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

function isTap(event: FeedbackEvent): event is FeedbackTap {
  return typeof (event as FeedbackTap).resonated === "boolean";
}

/** Serializes the queue's read-modify-write cycles (audit M-35,
 *  2026-09-20): two taps landing in the same frame (or a tap racing a
 *  mute) used to read the same pending list, each append its own event,
 *  and the last write to storage silently dropped the other — a lost
 *  answer the user believed was recorded. The moodLog.ts idiom: chain the
 *  operation onto the tail of the previous one. */
let feedbackMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = feedbackMutex.then(operation, operation);
  feedbackMutex = run.catch(() => {});
  return run;
}

async function readPending(dataKey: Buffer, userId: string): Promise<FeedbackEvent[]> {
  const raw = await AsyncStorage.getItem(key(userId));
  if (!raw) return [];
  try {
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", userId));
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
  }
}

/** Record one tap or mute event (fire-and-forget friendly). */
export async function recordFeedbackTap(
  dataKey: Buffer, userId: string, pid: string, resonated: boolean,
): Promise<void> {
  await appendEvent(dataKey, userId, { pid, resonated });
}

/** Queue a pattern mute (or unmute) for the next recompute. */
export async function recordPatternMute(
  dataKey: Buffer, userId: string, pid: string, mute: boolean,
): Promise<void> {
  await appendEvent(dataKey, userId, { pid, mute });
}

async function appendEvent(dataKey: Buffer, userId: string, event: FeedbackEvent): Promise<void> {
  const keyCopy = Buffer.from(dataKey);
  try {
    // Serialized (M-35): same-frame taps must not read the same pending
    // list and overwrite each other's event.
    await serialized(async () => {
      const pending = await readPending(keyCopy, userId);
      pending.push(event);
      const blob = encrypt(
        keyCopy,
        Buffer.from(JSON.stringify(pending.slice(-MAX_PENDING)), "utf8"),
        buildAad("feedback-local", userId),
      );
      await AsyncStorage.setItem(key(userId), blob.toString("base64"));
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
  dataKey: Buffer, userId: string,
): Promise<string | null> {
  const keyCopy = Buffer.from(dataKey);
  try {
    const pending = await readPending(keyCopy, userId);
    if (pending.length === 0) return null;
    const taps = pending.filter(isTap) as FeedbackTap[];
    // Last write wins per pid: an unmute queued after a mute (or the
    // reverse) is the user's final word, and the server applies lists in
    // muted-then-unmuted order anyway.
    const mutes = new Map<string, boolean>();
    for (const event of pending) {
      if (!isTap(event)) mutes.set(event.pid, event.mute);
    }
    const blob = encrypt(
      keyCopy,
      Buffer.from(
        JSON.stringify({
          feedback: taps,
          muted: [...mutes.entries()].filter(([, m]) => m).map(([pid]) => pid),
          unmuted: [...mutes.entries()].filter(([, m]) => !m).map(([pid]) => pid),
        }),
        "utf8",
      ),
      // C-5 (2026-09-21): the AAD carries the seal DATE (UTC), so a blob
      // captured by a hostile server cannot be replayed across recomputes.
      // The server accepts today or yesterday to tolerate clocks that
      // straddle UTC midnight between seal and verify.
      buildAad("feedback", userId, new Date().toISOString().slice(0, 10)),
    );
    return blob.toString("base64");
  } finally {
    zeroize(keyCopy);
  }
}

/** Clear after a successful recompute (the server consumed the taps). */
export async function clearFeedback(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
