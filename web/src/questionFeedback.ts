/**
 * Question/pattern feedback queue — ported from mobile's
 * questionFeedback.ts onto the kvstore seam + async WebCrypto. Taps
 * ("this resonated / not me") and pattern mutes are encrypted under the
 * DATA key locally (AAD "feedback-local", bound to the user) and ride the
 * NEXT recompute as one opaque blob (AAD "feedback", bound to the user and
 * the seal DATE — C-5: a blob captured by a hostile server cannot be
 * replayed across recomputes). The shipped shape partitions taps from
 * mutes: {"feedback": [...], "muted": [pids], "unmuted": [pids]}.
 */
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv } from "./kvstore";

const key = (userId: string): string => `mindpattern.feedback.${userId}`;
const MAX_PENDING = 64;

export interface FeedbackTap {
  pid: string;
  resonated: boolean;
}

export interface MuteEvent {
  pid: string;
  mute: boolean;
}

export type FeedbackEvent = FeedbackTap | MuteEvent;

function isTap(event: FeedbackEvent): event is FeedbackTap {
  return typeof (event as FeedbackTap).resonated === "boolean";
}

/** Serializes read-modify-write cycles (audit M-35): two taps landing in
 *  the same frame must not read the same pending list and silently drop
 *  each other. */
let feedbackMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = feedbackMutex.then(operation, operation);
  feedbackMutex = run.catch(() => {});
  return run;
}

async function readPending(dataKey: Bytes, userId: string): Promise<FeedbackEvent[]> {
  const raw = await kv.getItem(key(userId));
  if (!raw) return [];
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(raw), buildAad("feedback-local", userId));
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is FeedbackEvent =>
        typeof e === "object" && e !== null && typeof (e as FeedbackEvent).pid === "string"
        && (typeof (e as FeedbackTap).resonated === "boolean" || typeof (e as MuteEvent).mute === "boolean"),
    );
  } catch {
    return []; // wrong key / corruption: disposable
  } finally {
    zeroize(plaintext);
  }
}

/** Record one tap (fire-and-forget friendly). */
export async function recordFeedbackTap(dataKey: Bytes, userId: string, pid: string, resonated: boolean): Promise<void> {
  await appendEvent(dataKey, userId, { pid, resonated });
}

/** Queue a pattern mute (or unmute) for the next recompute. */
export async function recordPatternMute(dataKey: Bytes, userId: string, pid: string, mute: boolean): Promise<void> {
  await appendEvent(dataKey, userId, { pid, mute });
}

async function appendEvent(dataKey: Bytes, userId: string, event: FeedbackEvent): Promise<void> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    await serialized(async () => {
      const pending = await readPending(keyCopy, userId);
      pending.push(event);
      let payload: Uint8Array<ArrayBuffer> | null = new TextEncoder().encode(JSON.stringify(pending.slice(-MAX_PENDING)));
      try {
        const blob = await encrypt(keyCopy, payload, buildAad("feedback-local", userId));
        await kv.setItem(key(userId), toBase64(blob));
      } finally {
        zeroize(payload);
        payload = null;
      }
    });
  } finally {
    zeroize(keyCopy);
  }
}

/** The opaque blob for the recompute body, or null when nothing is pending.
 *  Last write wins per pid for mutes; taps accumulate. */
export async function buildFeedbackBlob(dataKey: Bytes, userId: string): Promise<string | null> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    const pending = await readPending(keyCopy, userId);
    if (pending.length === 0) return null;
    const taps = pending.filter(isTap) as FeedbackTap[];
    const mutes = new Map<string, boolean>();
    for (const event of pending) {
      if (!isTap(event)) mutes.set(event.pid, event.mute);
    }
    const payload = new TextEncoder().encode(
      JSON.stringify({
        feedback: taps,
        muted: [...mutes.entries()].filter(([, m]) => m).map(([pid]) => pid),
        unmuted: [...mutes.entries()].filter(([, m]) => !m).map(([pid]) => pid),
      }),
    );
    try {
      // C-5: the AAD carries the seal DATE (UTC); the server accepts today
      // or yesterday to tolerate clock straddles across UTC midnight.
      const blob = await encrypt(keyCopy, payload, buildAad("feedback", userId, new Date().toISOString().slice(0, 10)));
      return toBase64(blob);
    } finally {
      zeroize(payload);
    }
  } finally {
    zeroize(keyCopy);
  }
}

/** Clear after a successful recompute (the server consumed the taps). */
export async function clearFeedback(userId: string): Promise<void> {
  await kv.removeItem(key(userId));
}
