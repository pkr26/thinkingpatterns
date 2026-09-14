/**
 * Device-local mood log for the baseline phase (pre-threshold feedback).
 *
 * One number per day, derived on-device from the day's entry — never
 * synced, never seen by the server. It powers the streak + mood-trend view
 * while the account is below the pattern threshold; after the threshold
 * the mini-brain's analysis (re-derived from the encrypted corpus)
 * replaces it.
 *
 * Privacy: the log is ENCRYPTED under the account's data key (AES-256-GCM,
 * AAD-bound to the account id) — the same key that encrypts entries. A
 * device-file-system reader gets ciphertext, not a mood trend. Values from
 * the pre-encryption format (raw JSON arrays) migrate transparently on
 * the next write. A corrupt/tampered blob degrades to empty: this log is
 * disposable metadata and must never crash or lock the app.
 *
 * Key custody: the public functions take the vault's SHARED dataKey buffer.
 * recordMood is commonly fire-and-forget, and vault.lock() (e.g. a
 * background transition) zeroizes that buffer mid-await — encrypting the
 * pending write under an all-zero key would produce a blob no future read
 * can open (the log would silently reset). Every public call therefore
 * SNAPSHOTS the key bytes into a private copy at call time, works from the
 * copy, and zeroizes the copy in finally.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";
import { zeroize } from "./crypto/kdf";

export interface MoodDay {
  date: string; // YYYY-MM-DD
  value: number; // [-1, 1]
}

const key = (userId: string): string => `mindpattern.moodlog.${userId}`;
const MAX_DAYS = 400;

/** Serializes every read-modify-write cycle: two rapid recordMood calls
 *  (or a record racing the legacy re-encryption write) used to lose one
 *  day's value to a last-write-wins race on a stale snapshot. */
let logMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = logMutex.then(operation, operation);
  logMutex = run.catch(() => {});
  return run;
}

function yesterday(iso: string): string {
  const d = new Date(`${iso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}

function todayIso(): string {
  return localDateISO();
}

/**
 * LOCAL calendar date (yyyy-mm-dd) in device time. `toISOString().slice(0,10)`
 * is the UTC day — wrong for everyone outside UTC in the evening — and it
 * feeds entry ids/dates and this log, so it must match the user's wall
 * calendar. Shared by the mood log and the entry screen.
 */
export function localDateISO(d: Date = new Date()): string {
  const year = String(d.getFullYear()).padStart(4, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function sanitize(raw: unknown): MoodDay[] {
  if (!Array.isArray(raw)) return [];
  const days: MoodDay[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) continue;
    const { date, value } = item as Record<string, unknown>;
    if (typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date)) continue;
    if (typeof value !== "number" || !Number.isFinite(value)) continue;
    days.push({ date, value: Math.max(-1, Math.min(1, value)) });
  }
  days.sort((a, b) => a.date.localeCompare(b.date));
  return days;
}

/**
 * Read the log. The returned flag says whether the stored bytes were the
 * legacy plaintext format (so the caller re-writes them encrypted).
 */
async function read(dataKey: Buffer, userId: string): Promise<{ days: MoodDay[]; legacy: boolean }> {
  const raw = await AsyncStorage.getItem(key(userId));
  if (!raw) return { days: [], legacy: false };
  if (raw.startsWith("[")) {
    // Pre-encryption format. Read-through migration: a user who only ever
    // READS (the Insights baseline view) must not keep a plaintext mood log
    // on disk forever — re-write the parsed days encrypted right away.
    try {
      const days = sanitize(JSON.parse(raw));
      await write(dataKey, userId, days);
      return { days, legacy: true };
    } catch {
      return { days: [], legacy: true };
    }
  }
  try {
    const plain = decrypt(
      dataKey,
      Buffer.from(raw, "base64"),
      buildAad("moodlog", userId),
    );
    return { days: sanitize(JSON.parse(plain.toString("utf8"))), legacy: false };
  } catch {
    // Wrong key (account switch), corruption, or tampering: disposable.
    return { days: [], legacy: false };
  }
}

async function write(dataKey: Buffer, userId: string, days: MoodDay[]): Promise<void> {
  const blob = encrypt(
    dataKey,
    Buffer.from(JSON.stringify(days.slice(-MAX_DAYS)), "utf8"),
    buildAad("moodlog", userId),
  );
  await AsyncStorage.setItem(key(userId), blob.toString("base64"));
}

/** Upsert one day's mood (latest value wins for the same date). */
export async function recordMood(dataKey: Buffer, userId: string, date: string, value: number): Promise<void> {
  // Snapshot the key NOW, at call time — NOT inside the serialized block,
  // which may run much later (or after a lock zeroized the shared buffer).
  const keyCopy = Buffer.from(dataKey);
  try {
    await serialized(async () => {
      const { days } = await read(keyCopy, userId);
      const clean = Math.max(-1, Math.min(1, value));
      const existing = days.findIndex((d) => d.date === date);
      if (existing >= 0) days[existing] = { date, value: clean };
      else days.push({ date, value: clean });
      await write(keyCopy, userId, days);
    });
  } finally {
    zeroize(keyCopy);
  }
}

/** The most recent *days* mood entries, oldest first. */
export async function recentMoods(dataKey: Buffer, userId: string, days = 30): Promise<MoodDay[]> {
  const keyCopy = Buffer.from(dataKey);
  try {
    const readResult = await read(keyCopy, userId);
    return readResult.days.slice(-days);
  } finally {
    zeroize(keyCopy);
  }
}

/** Consecutive writing days ending today (yesterday counts, with grace). */
export async function localStreak(dataKey: Buffer, userId: string, today = todayIso()): Promise<number> {
  const keyCopy = Buffer.from(dataKey);
  try {
    const { days } = await read(keyCopy, userId);
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

/** Test seam: wipe the log (sign-out hygiene for tests and account switch). */
export async function clearMoodLog(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
