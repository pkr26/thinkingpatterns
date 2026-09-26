/** entryVersions (the rollback guard) and moodLog (device-local, encrypted)
 *  over the kvstore seam: persistence, tamper degradation, and the honest
 *  behaviors the History view leans on. */
import { beforeEach, describe, expect, it } from "vitest";
import { deriveMasterKey, fromBase64 } from "../src/crypto/core";
import {
  forgetAllEntryVersions,
  forgetEntryVersion,
  knownEntryVersion,
  observeEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";
import { clearMoodLog, localStreak, recentMoods, recordMood, removeMoodDay } from "../src/moodLog";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";

function freshBackend(): KvBackend {
  const map = new Map<string, string>();
  return {
    async getItem(key) {
      return map.get(key) ?? null;
    },
    async setItem(key, value) {
      map.set(key, value);
    },
    async removeItem(key) {
      map.delete(key);
    },
  };
}

const dataKeyFor = async (seed: string): Promise<Uint8Array<ArrayBuffer>> =>
  fromBase64(
    (() => {
      const bytes = new Uint8Array(new ArrayBuffer(32));
      for (let i = 0; i < 32; i += 1) bytes[i] = seed.charCodeAt(i % seed.length) || i + 1;
      let binary = "";
      for (const b of bytes) binary += String.fromCharCode(b);
      return btoa(binary);
    })(),
  );

beforeEach(() => {
  setKvBackendForTests(freshBackend());
  resetEntryVersionMirrors();
});

describe("entryVersions (audit M-2 rollback guard)", () => {
  it("advances marks, reports rollbacks, and persists encrypted", async () => {
    const key = await dataKeyFor("versions-key-1");
    const first = await observeEntryVersions("user-1", key, [
      { clientEntryId: "e-1", contentVersion: 1 },
      { clientEntryId: "e-2", contentVersion: 3 },
    ]);
    expect(first.advanced).toBe(true);
    expect(first.rolledBack).toEqual([]);
    expect(await knownEntryVersion("user-1", key, "e-1")).toBe(1);

    const rolled = await observeEntryVersions("user-1", key, [
      { clientEntryId: "e-1", contentVersion: 1 },
      { clientEntryId: "e-2", contentVersion: 2 }, // backwards vs the mark of 3
    ]);
    expect(rolled.rolledBack).toEqual(["e-2"]);

    // A fresh mirror re-learns from storage (the marks persisted).
    resetEntryVersionMirrors();
    expect(await knownEntryVersion("user-1", key, "e-2")).toBe(3);
  });

  it("a tampered/foreign store degrades to no memory, never a forged mark", async () => {
    const key = await dataKeyFor("versions-key-2");
    const other = await dataKeyFor("a-different-key");
    await observeEntryVersions("user-1", key, [{ clientEntryId: "e-1", contentVersion: 5 }]);
    // Reading with the WRONG key (rotation without rebind) yields nothing —
    // the guard degrades to "no memory", strictly honest.
    resetEntryVersionMirrors();
    expect(await knownEntryVersion("user-1", other, "e-1")).toBeNull();
  });

  it("forgetting a deleted entry allows a legitimate version-1 recreate", async () => {
    const key = await dataKeyFor("versions-key-3");
    await observeEntryVersions("user-1", key, [{ clientEntryId: "e-1", contentVersion: 4 }]);
    await forgetEntryVersion("user-1", key, "e-1");
    const after = await observeEntryVersions("user-1", key, [{ clientEntryId: "e-1", contentVersion: 1 }]);
    expect(after.rolledBack).toEqual([]);
    await forgetAllEntryVersions("user-1");
  });
});

describe("moodLog (device-local, encrypted, never synced)", () => {
  it("records, clamps, replaces same-day, and reads back", async () => {
    const key = await dataKeyFor("mood-key-1");
    await recordMood(key, "user-1", "2026-09-24", 0.5, -1);
    await recordMood(key, "user-1", "2026-09-25", 99); // clamps to 1
    await recordMood(key, "user-1", "2026-09-25", -0.5); // same-day replace
    const days = await recentMoods(key, "user-1");
    expect(days.map((d) => [d.date, d.value, d.energy ?? null])).toEqual([
      ["2026-09-24", 0.5, -1],
      // 09-25's same-day replace had no energy pick AND no prior energy on
      // that day, so the field stays absent ("not tapped" ≠ "neutral").
      ["2026-09-25", -0.5, null],
    ]);
  });

  it("streak counts consecutive days with yesterday grace", async () => {
    const key = await dataKeyFor("mood-key-2");
    await recordMood(key, "user-1", "2026-09-23", 0);
    await recordMood(key, "user-1", "2026-09-24", 0);
    await recordMood(key, "user-1", "2026-09-25", 0);
    expect(await localStreak(key, "user-1", "2026-09-25")).toBe(3);
    // Yesterday grace: today unwritten, so the streak counts backward
    // from yesterday — 25, 24, 23 = 3 consecutive writing days.
    expect(await localStreak(key, "user-1", "2026-09-26")).toBe(3);
    expect(await localStreak(key, "user-1", "2026-09-28")).toBe(0);
  });

  it("removing a day drops it from the trend (audit L-68)", async () => {
    const key = await dataKeyFor("mood-key-3");
    await recordMood(key, "user-1", "2026-09-25", 0.5);
    await removeMoodDay(key, "user-1", "2026-09-25");
    expect(await recentMoods(key, "user-1")).toHaveLength(0);
  });

  it("a corrupt blob degrades to empty (disposable metadata)", async () => {
    const key = await dataKeyFor("mood-key-4");
    await recordMood(key, "user-1", "2026-09-25", 0.5);
    const other = await dataKeyFor("wrong-key-entirely");
    expect(await recentMoods(other, "user-1")).toHaveLength(0);
    await clearMoodLog("user-1");
  });

  it("storage holds ciphertext, not mood values", async () => {
    const seen: string[] = [];
    const map = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
        seen.push(v);
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    const key = await dataKeyFor("mood-key-5");
    await recordMood(key, "user-1", "2026-09-25", 0.5);
    const persisted = seen.join("");
    expect(persisted).not.toContain("2026-09-25");
    expect(persisted).not.toContain("0.5");
  });
});
