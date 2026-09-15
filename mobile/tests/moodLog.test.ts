/**
 * The device-local mood log that powers the baseline-phase trend view.
 * Invariants: per-account isolation (by key AND by AAD), upsert-by-date,
 * clamped values, bounded history, streak grace — and, since the privacy
 * audit: the stored bytes are ENCRYPTED under the data key, a tampered or
 * wrong-key blob degrades to empty, and the legacy plaintext format
 * migrates transparently.
 */
import { beforeEach, describe, expect, it } from "vitest";
import storage from "./helpers/storageMock";

const { recordMood, recentMoods, localStreak, clearMoodLog, localDateISO } = await import("../src/moodLog");
const { buildAad, encrypt } = await import("../src/crypto/envelope");

const keyA = Buffer.alloc(32, 1);
const keyB = Buffer.alloc(32, 2);

const day = (offset: number): string => {
  const d = new Date(Date.UTC(2026, 8, 4 + offset));
  return d.toISOString().slice(0, 10);
};

const storedRaw = async (userId: string): Promise<string | null> =>
  storage.getItem(`mindpattern.moodlog.${userId}`);

beforeEach(() => {
  storage.__reset();
});

describe("moodLog", () => {
  it("records and returns days oldest-first", async () => {
    await recordMood(keyA, "u1", day(-2), -0.5);
    await recordMood(keyA, "u1", day(-1), 0.25);
    const moods = await recentMoods(keyA, "u1", 30);
    expect(moods.map((m) => m.value)).toEqual([-0.5, 0.25]);
  });

  it("stores ENCRYPTED bytes, never plaintext mood values", async () => {
    await recordMood(keyA, "u1", day(0), 0.66);
    const raw = await storedRaw("u1");
    expect(raw).not.toBeNull();
    expect(raw).not.toContain("0.66");
    expect(raw).not.toMatch(/^\[/); // not the legacy plaintext format
  });

  it("is AAD-bound: another account's key cannot read the log", async () => {
    await recordMood(keyA, "u1", day(0), 0.5);
    // Wrong key (different account): degrades to empty, never throws.
    expect(await recentMoods(keyB, "u1", 30)).toEqual([]);
  });

  it("isolates accounts by storage key", async () => {
    await recordMood(keyA, "u1", day(0), 0.5);
    expect(await recentMoods(keyA, "u2", 30)).toEqual([]);
  });

  it("a tampered blob degrades to empty, never throws", async () => {
    await recordMood(keyA, "u1", day(0), 0.5);
    const raw = (await storedRaw("u1")) as string;
    const flipped = raw.slice(0, -4) + (raw.endsWith("AAAA") ? "BBBB" : "AAAA");
    await storage.setItem("mindpattern.moodlog.u1", flipped);
    expect(await recentMoods(keyA, "u1", 30)).toEqual([]);
    expect(await localStreak(keyA, "u1", day(0))).toBe(0);
  });

  it("migrates the legacy plaintext format transparently", async () => {
    await storage.setItem(
      "mindpattern.moodlog.u1",
      JSON.stringify([{ date: day(-1), value: 0.3 }]),
    );
    const moods = await recentMoods(keyA, "u1", 30);
    expect(moods.map((m) => m.value)).toEqual([0.3]);
    // Next write re-stores the whole log encrypted.
    await recordMood(keyA, "u1", day(0), -0.2);
    const raw = await storedRaw("u1");
    expect(raw).not.toMatch(/^\[/);
    const all = await recentMoods(keyA, "u1", 30);
    expect(all.map((m) => m.value)).toEqual([0.3, -0.2]);
  });

  // M5: a read-only user (the Insights baseline view) must not keep a
  // plaintext mood log on disk forever — the read itself migrates it.
  it("read-through migration: a successful READ already re-stores encrypted bytes (M5)", async () => {
    await storage.setItem(
      "mindpattern.moodlog.u1",
      JSON.stringify([{ date: day(-1), value: 0.3 }]),
    );
    await recentMoods(keyA, "u1", 30); // read only — no write call from the caller
    const raw = await storedRaw("u1");
    expect(raw).not.toBeNull();
    expect(raw).not.toMatch(/^\[/); // no longer the legacy plaintext envelope
    expect(raw).not.toContain("0.3");
    // And the migrated ciphertext still decrypts to the same days.
    expect((await recentMoods(keyA, "u1", 30)).map((m) => m.value)).toEqual([0.3]);
  });

  it("a corrupt LEGACY blob degrades to empty instead of crashing the read", async () => {
    // Starts with "[" so the legacy path is taken, but the JSON is broken:
    // the parse failure must degrade to empty (and flag legacy for rewrite).
    await storage.setItem("mindpattern.moodlog.u1", "[{broken json");
    expect(await recentMoods(keyA, "u1", 30)).toEqual([]);
    expect(await localStreak(keyA, "u1", day(0))).toBe(0);
  });

  it("a decrypted payload that is not an array sanitizes to empty", async () => {
    // Valid AEAD, valid JSON — but the wrong SHAPE. Never render garbage.
    const notArray = encrypt(keyA, Buffer.from(JSON.stringify({ days: "lots" })), buildAad("moodlog", "u1"));
    await storage.setItem("mindpattern.moodlog.u1", notArray.toString("base64"));
    expect(await recentMoods(keyA, "u1", 30)).toEqual([]);
  });

  it("sanitize drops junk items from a legacy payload, keeping only valid days", async () => {
    await storage.setItem(
      "mindpattern.moodlog.u1",
      JSON.stringify([
        "junk",
        null,
        { date: "not-a-date", value: 0.1 },
        { date: "2026-09-01", value: "high" },
        { value: 0.4 },
        { date: "2026-09-02", value: 0.5 },
      ]),
    );
    expect(await recentMoods(keyA, "u1", 30)).toEqual([{ date: "2026-09-02", value: 0.5 }]);
  });

  it("upserts by date — one value per day", async () => {
    await recordMood(keyA, "u1", day(0), -0.5);
    await recordMood(keyA, "u1", day(0), 0.4);
    const moods = await recentMoods(keyA, "u1", 30);
    expect(moods).toHaveLength(1);
    expect(moods[0].value).toBe(0.4);
  });

  it("clamps out-of-range values", async () => {
    await recordMood(keyA, "u1", day(0), 7);
    const moods = await recentMoods(keyA, "u1", 30);
    expect(moods[0].value).toBe(1);
  });

  it("streak counts consecutive days ending today or yesterday", async () => {
    await recordMood(keyA, "u1", day(-3), 0.1);
    await recordMood(keyA, "u1", day(-2), 0.1);
    await recordMood(keyA, "u1", day(-1), 0.1);
    // Gap-free run ending yesterday → 3 (grace), not 0.
    expect(await localStreak(keyA, "u1", day(0))).toBe(3);
    await recordMood(keyA, "u1", day(0), 0.2);
    expect(await localStreak(keyA, "u1", day(0))).toBe(4);
  });

  it("streak breaks across a missed day", async () => {
    await recordMood(keyA, "u1", day(-4), 0.1);
    await recordMood(keyA, "u1", day(-2), 0.1); // gap at -3; nothing today or yesterday
    expect(await localStreak(keyA, "u1", day(0))).toBe(0);
  });

  it("corrupt storage degrades to empty, never throws", async () => {
    await storage.setItem("mindpattern.moodlog.u1", "{not json");
    expect(await recentMoods(keyA, "u1", 30)).toEqual([]);
    expect(await localStreak(keyA, "u1", day(0))).toBe(0);
  });

  it("clear removes everything for the account", async () => {
    await recordMood(keyA, "u1", day(0), 0.1);
    await clearMoodLog("u1");
    expect(await recentMoods(keyA, "u1", 30)).toEqual([]);
  });

  it("the AAD binds the log to the account id (regression for blob relocation)", async () => {
    // A log encrypted for u2 must not decrypt under u1's AAD even with the
    // right key — same anti-relocation property as entry blobs.
    const foreign = encrypt(keyA, Buffer.from(JSON.stringify([{ date: day(0), value: 0.9 }])), buildAad("moodlog", "u2"));
    await storage.setItem("mindpattern.moodlog.u1", foreign.toString("base64"));
    expect(await recentMoods(keyA, "u1", 30)).toEqual([]);
  });
});

describe("localDateISO", () => {
  // M9: entry dates and mood-log days must be the DEVICE-LOCAL calendar day;
  // toISOString().slice(0,10) is the UTC day and is wrong in the evening for
  // every non-UTC timezone.
  //
  // Pool note: these tests deliberately do NOT switch process.env.TZ. Under
  // vitest's `threads` pool (Stryker's vitest runner) the assignment never
  // reaches the process timezone — the Date getters stay on the ambient zone
  // and the east-of-UTC case deterministically fails there while passing
  // under the default `forks` pool. Instead, the expected day is derived
  // from getTimezoneOffset(): the SAME zone state the implementation's Date
  // getters read, so the assertion is valid under any ambient zone, any
  // pool, and any runner.
  const localDay = (d: Date): string =>
    new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 10);

  it("returns the local calendar day of the ambient zone, not the UTC day", () => {
    // One instant early in the UTC day, one late: every non-UTC zone puts at
    // least one of the two on a local day different from its UTC day (west
    // of UTC shifts the early one back a day, east of UTC shifts the late
    // one forward), so the UTC-day rendering is rejected as wrong whenever
    // the machine is not on UTC.
    for (const ms of [Date.UTC(2026, 8, 4, 2, 30), Date.UTC(2026, 8, 3, 23, 30)]) {
      const d = new Date(ms);
      const utcDay = d.toISOString().slice(0, 10);
      expect(localDateISO(d)).toBe(localDay(d));
      if (localDay(d) !== utcDay) {
        expect(localDateISO(d)).not.toBe(utcDay);
      }
    }
  });

  it("zero-pads month and day", () => {
    expect(localDateISO(new Date(2026, 0, 5))).toBe("2026-01-05");
    expect(localDateISO(new Date(2026, 10, 20))).toBe("2026-11-20");
  });
});

describe("L6: recordMood serialization (no lost updates)", () => {
  it("two concurrent recordMood calls for different days both persist", async () => {
    const dataKey = Buffer.alloc(32, 4);
    await Promise.all([
      recordMood(dataKey, "u1", "2026-09-01", 0.5),
      recordMood(dataKey, "u1", "2026-09-02", -0.5),
    ]);
    const days = await recentMoods(dataKey, "u1", 30);
    expect(days.map((d) => d.date)).toEqual(["2026-09-01", "2026-09-02"]);
  });
});

describe("vault-lock race (zeroize mid-write)", () => {
  // recordMood is fire-and-forget with the vault's SHARED dataKey buffer.
  // The bug: backgrounding mid-await ran vault.lock(), zeroizing the
  // buffer, and the pending write encrypted under an all-zero key — the
  // next read failed GCM and the mood history silently reset to empty.
  it("a lock landing mid-record cannot corrupt the log (key is snapshotted at call time)", async () => {
    const liveDataKey = Buffer.alloc(32, 5); // stands in for the vault's buffer
    const originalBytes = Buffer.from(liveDataKey); // the test's own copy
    // Zeroize the shared buffer the moment the stored bytes have been read
    // — the worst possible interleaving for the pending write.
    const originalGetItem = storage.getItem.bind(storage);
    let armed = true;
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      const value = await originalGetItem(k);
      if (armed && k === "mindpattern.moodlog.u1") {
        armed = false;
        liveDataKey.fill(0); // this is what vault.lock() does to the buffer
      }
      return value;
    };
    try {
      await recordMood(liveDataKey, "u1", "2026-09-01", 0.5);
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    // The pending write encrypted under the SNAPSHOT, not the zeroed buffer:
    // the day is intact under the original key bytes...
    expect(await recentMoods(originalBytes, "u1", 30)).toEqual([{ date: "2026-09-01", value: 0.5 }]);
    // ...and the stored blob is definitely NOT under the all-zero key.
    expect(await recentMoods(Buffer.alloc(32), "u1", 30)).toEqual([]);
  });

  it("a lock mid-READ cannot produce a spurious empty trend", async () => {
    const liveDataKey = Buffer.alloc(32, 6);
    const originalBytes = Buffer.from(liveDataKey);
    await recordMood(originalBytes, "u1", "2026-09-01", 0.25);
    liveDataKey.fill(0); // locked between reads — the next call snapshots
    // A read after a lock simply sees the locked (zeroed) key: degrades to
    // empty, as any wrong key does — but the log itself is intact.
    expect(await recentMoods(liveDataKey, "u1", 30)).toEqual([]);
    expect(await recentMoods(originalBytes, "u1", 30)).toEqual([{ date: "2026-09-01", value: 0.25 }]);
  });
});
