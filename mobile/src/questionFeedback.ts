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

async function readPending(dataKey: Buffer, userId: string): Promise<FeedbackTap[]> {
  const raw = await AsyncStorage.getItem(key(userId));
  if (!raw) return [];
  try {
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", userId));
    const parsed = JSON.parse(plain.toString("utf8")) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (t): t is FeedbackTap =>
        typeof t === "object" && t !== null &&
        typeof (t as FeedbackTap).pid === "string" && typeof (t as FeedbackTap).resonated === "boolean",
    );
  } catch {
    return []; // wrong key / corruption: disposable
  }
}

/** Record one tap (fire-and-forget friendly). */
export async function recordFeedbackTap(
  dataKey: Buffer, userId: string, pid: string, resonated: boolean,
): Promise<void> {
  const keyCopy = Buffer.from(dataKey);
  try {
    const pending = await readPending(keyCopy, userId);
    pending.push({ pid, resonated });
    const blob = encrypt(
      keyCopy,
      Buffer.from(JSON.stringify(pending.slice(-MAX_PENDING)), "utf8"),
      buildAad("feedback-local", userId),
    );
    await AsyncStorage.setItem(key(userId), blob.toString("base64"));
  } finally {
    zeroize(keyCopy);
  }
}

/** The opaque blob for the recompute body, or null when nothing is pending.
 *  Encrypts under the DATA key with the server's feedback AAD. */
export async function buildFeedbackBlob(
  dataKey: Buffer, userId: string,
): Promise<string | null> {
  const keyCopy = Buffer.from(dataKey);
  try {
    const pending = await readPending(keyCopy, userId);
    if (pending.length === 0) return null;
    const blob = encrypt(
      keyCopy,
      Buffer.from(JSON.stringify({ feedback: pending }), "utf8"),
      buildAad("feedback", userId),
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
