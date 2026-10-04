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
  const permit = captureLocalWritePermit(userId, dataKey);
  const keyCopy = Buffer.from(dataKey);
  try {
    // Serialize appends to prevent lost feedback during concurrent taps.
    await serialized(async () => {
      assertLocalWritePermit(permit);
      const pending = await readPending(keyCopy, userId);
      pending.push(event);
      const blob = encrypt(
        keyCopy,
        Buffer.from(JSON.stringify(pending.slice(-MAX_PENDING)), "utf8"),
        buildAad("feedback-local", userId),
      );
      await commitLocalWrite(permit, () => AsyncStorage.setItem(key(userId), blob.toString("base64")));
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
      // Bind feedback to its UTC seal date to limit replay across recomputes.
      // The server accepts today or yesterday to tolerate midnight crossings.
      buildAad("feedback", userId, new Date().toISOString().slice(0, 10)),
    );
    return blob.toString("base64");
  } finally {
    zeroize(keyCopy);
  }
}

/** Clear after a successful recompute (the server consumed the taps). */
export async function clearFeedback(userId: string, source?: LocalWritePermit): Promise<void> {
  const permit = captureOpaqueLocalWritePermit(userId, source);
  await commitLocalWrite(permit, () => AsyncStorage.removeItem(key(userId)));
}
export async function eraseFeedback(userId: string): Promise<void> { await AsyncStorage.removeItem(key(userId)); }
