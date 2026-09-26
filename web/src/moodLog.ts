/**
 * Device-local mood log for the baseline phase — ported from mobile's
 * moodLog.ts onto the kvstore seam + async WebCrypto. One number per day,
 * derived on-device from the day's check-in — never synced, never seen by
 * the server. It powers the streak + mood-trend view while the account is
 * below the pattern threshold.
 *
 * Privacy: the log is ENCRYPTED under the account's data key (AES-256-GCM,
 * AAD-bound to the account id). A device-storage reader gets ciphertext,
 * not a mood trend. A corrupt/tampered blob degrades to empty: this log is
 * disposable metadata and must never crash or lock the app.
 *
 * Key custody: public functions take the vault's SHARED dataKey buffer.
 * Every call SNAPSHOTS the key bytes at call time (a lock mid-await must
 * not produce a blob no future read can open) and zeroizes the copy in
 * finally.
 */
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv } from "./kvstore";
import { localDateISO } from "./dates";

export interface MoodDay {
  date: string; // YYYY-MM-DD
  value: number; // [-1, 1]
  /** Optional energy dimension: [-1, 1] where -1 is drained and +1 is
   *  energized. Absent = not tapped (never zero-filled). */
  energy?: number;
}

const key = (userId: string): string => `mindpattern.moodlog.${userId}`;
const MAX_DAYS = 400;

let logMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = logMutex.then(operation, operation);
  logMutex = run.catch(() => {});
  return run;
}

function yesterday(iso: string): string {
  const [y, m, d] = iso.split("-").map(Number) as [number, number, number];
  return localDateISO(new Date(y, m - 1, d - 1));
}

function todayIso(): string {
  return localDateISO();
}

function sanitize(raw: unknown): MoodDay[] {
  if (!Array.isArray(raw)) return [];
  const days: MoodDay[] = [];
  for (const item of raw.slice(0, MAX_DAYS)) {
    if (typeof item !== "object" || item === null) continue;
    const day = item as Record<string, unknown>;
    if (typeof day.date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(day.date)) continue;
    if (typeof day.value !== "number" || !Number.isFinite(day.value)) continue;
    const clean: MoodDay = { date: day.date, value: Math.max(-1, Math.min(1, day.value)) };
    if (typeof day.energy === "number" && Number.isFinite(day.energy)) {
      clean.energy = Math.max(-1, Math.min(1, day.energy));
    }
    days.push(clean);
  }
  days.sort((a, b) => a.date.localeCompare(b.date));
  return days;
}

async function read(dataKey: Bytes, userId: string): Promise<MoodDay[]> {
  const raw = await kv.getItem(key(userId));
  if (!raw) return [];
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(raw), buildAad("moodlog", userId));
    return sanitize(JSON.parse(new TextDecoder().decode(plaintext)));
  } catch {
    // Wrong key, corruption, or tampering: disposable.
    return [];
  } finally {
    zeroize(plaintext);
  }
}

async function write(dataKey: Bytes, userId: string, days: MoodDay[]): Promise<void> {
  const payload = new TextEncoder().encode(JSON.stringify(days.slice(-MAX_DAYS)));
  try {
    const blob = await encrypt(dataKey, payload, buildAad("moodlog", userId));
    await kv.setItem(key(userId), toBase64(blob));
  } finally {
    zeroize(payload);
  }
}

/** Record (or same-day replace) one mood value, optionally with energy. */
export async function recordMood(
  dataKey: Bytes,
  userId: string,
  date: string,
  value: number,
  energy?: number | null,
): Promise<void> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    await serialized(async () => {
      const { days } = { days: await read(keyCopy, userId) };
      const clean = Math.max(-1, Math.min(1, value));
      const existing = days.findIndex((d) => d.date === date);
      const prior = existing >= 0 ? days[existing] : undefined;
      const cleanEnergy =
        energy === null
          ? undefined
          : typeof energy === "number" && Number.isFinite(energy)
            ? Math.max(-1, Math.min(1, energy))
            : prior?.energy;
      const day: MoodDay = cleanEnergy === undefined ? { date, value: clean } : { date, value: clean, energy: cleanEnergy };
      if (existing >= 0) days[existing] = day;
      else days.push(day);
      await write(keyCopy, userId, days);
    });
  } finally {
    zeroize(keyCopy);
  }
}

/** The most recent *days* mood entries, oldest first. */
export async function recentMoods(dataKey: Bytes, userId: string, days = 30): Promise<MoodDay[]> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    return await serialized(async () => (await read(keyCopy, userId)).slice(-days));
  } finally {
    zeroize(keyCopy);
  }
}

/** Consecutive writing days ending today (yesterday counts, with grace). */
export async function localStreak(dataKey: Bytes, userId: string, today = todayIso()): Promise<number> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    const days = await serialized(() => read(keyCopy, userId));
    if (days.length === 0) return 0;
    const set = new Set(days.map((d) => d.date));
    let cursor = set.has(today) ? today : set.has(yesterday(today)) ? yesterday(today) : null;
    if (!cursor) return 0;
    let streak = 0;
    while (set.has(cursor)) {
      streak += 1;
      cursor = yesterday(cursor);
    }
    return streak;
  } finally {
    zeroize(keyCopy);
  }
}

/** Delete one day's value: deleting a journal entry must also drop that
 *  day's device-local mood value, or the local streak/trend keeps counting
 *  a day the user erased. */
export async function removeMoodDay(dataKey: Bytes, userId: string, date: string): Promise<void> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    await serialized(async () => {
      const days = await read(keyCopy, userId);
      const next = days.filter((d) => d.date !== date);
      if (next.length !== days.length) await write(keyCopy, userId, next);
    });
  } finally {
    zeroize(keyCopy);
  }
}

/** Forget the whole log (sign-out / account deletion). */
export async function clearMoodLog(userId: string): Promise<void> {
  await kv.removeItem(key(userId));
}
