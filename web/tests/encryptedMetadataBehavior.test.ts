import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { decrypt, encrypt, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests } from "../src/kvstore";
import { clearMoodLog, localStreak, recentMoods, recordMood, removeMoodDay } from "../src/moodLog";
import { entryV2Bindings, forgetAllEntryVersions, forgetEntryVersion, knownEntryVersion, noteV2BoundBatch, observeEntryVersions, resetEntryVersionMirrors } from "../src/entryVersions";

vi.mock("../src/crypto/core", async original => {
  const actual = await original<typeof import("../src/crypto/core")>();
  return { ...actual, encrypt: vi.fn(actual.encrypt), decrypt: vi.fn(actual.decrypt) };
});
const owner = "encrypted-metadata-owner";
let key: Uint8Array<ArrayBuffer>, records: Map<string, string>;
beforeEach(() => {
  records = new Map(); key = new Uint8Array(new ArrayBuffer(32)).fill(14); resetEntryVersionMirrors();
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); }, keys: async () => [...records.keys()] });
  vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
});
afterEach(() => { setKvBackendForTests(null); vi.restoreAllMocks(); vi.useRealTimers(); });
async function seed(slot: string, domain: string, value: unknown): Promise<void> {
  const raw = typeof value === "string" ? value : JSON.stringify(value);
  records.set(`mindpattern.${slot}.${owner}`, toBase64(await encrypt(key, new TextEncoder().encode(raw), buildAad(domain, owner))));
  vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
}
async function consumerBuffersCleared(): Promise<void> {
  for (const result of vi.mocked(decrypt).mock.results) {
    const value = await Promise.resolve(result.value).catch(() => null) as Uint8Array | null;
    if (value) expect(value.every(b => b === 0)).toBe(true);
  }
  for (const [secret] of vi.mocked(decrypt).mock.calls) if (secret !== key) expect(secret.every(b => b === 0)).toBe(true);
  for (const [secret, value] of vi.mocked(encrypt).mock.calls) {
    expect(value.every(b => b === 0)).toBe(true);
    if (secret !== key) expect(secret.every(b => b === 0)).toBe(true);
  }
}

it("returns an empty public mood collection before the first writing day and after its complete removal", async () => {
  expect(await recentMoods(key, owner)).toEqual([]); expect(await localStreak(key, owner)).toBe(0);
  await recordMood(key, owner, "2026-10-05", 1);
  await clearMoodLog(owner);
  expect(await recentMoods(key, owner)).toEqual([]); expect(await localStreak(key, owner, "2026-10-05")).toBe(0);
  await consumerBuffersCleared();
});

it("sanitizes authenticated mood metadata without allowing malformed dates, nonfinite values or extra fields", async () => {
  await seed("moodlog", "moodlog", '[null,42,{}, {"date":42,"value":0},{"date":"prefix2026-10-05","value":0},{"date":"2026-10-05suffix","value":0},{"date":"2026-1-05","value":0},{"date":"2026-10-04","value":"0"},{"date":"2026-10-04","value":1e400},{"date":"2026-10-03","value":-5,"energy":5,"private":"discard"},{"date":"2026-10-02","value":5,"energy":-5},{"date":"2026-10-01","value":0,"energy":1e400},{"date":"2026-09-30","value":0,"energy":"0"}]');
  expect(await recentMoods(key, owner)).toEqual([{ date: "2026-09-30", value: 0 }, { date: "2026-10-01", value: 0 }, { date: "2026-10-02", value: 1, energy: -1 }, { date: "2026-10-03", value: -1, energy: 1 }]);
  await consumerBuffersCleared();
});
it.each([null, {}, false, 1, "not JSON"])("degrades malformed disposable mood data to an empty log: %j", async value => {
  await seed("moodlog", "moodlog", value); expect(await recentMoods(key, owner)).toEqual([]); expect(await localStreak(key, owner)).toBe(0); await consumerBuffersCleared();
});
it("refuses a coercible array in an authenticated mood date instead of leaking a wrong-typed date to the chart", async () => {
  await seed("moodlog", "moodlog", [{ date: ["2026-10-05"], value: 0 }]); expect(await recentMoods(key, owner)).toEqual([]);
});
it("bounds stored mood history and preserves explicit energy removal, same-day replacement and missing-day deletion", async () => {
  const days = Array.from({ length: 401 }, (_, i) => ({ date: new Date(Date.UTC(2025, 0, i + 1)).toISOString().slice(0, 10), value: 0 }));
  await seed("moodlog", "moodlog", days);
  expect(await recentMoods(key, owner, 1000)).toEqual(days.slice(0, 400).sort((a, b) => a.date.localeCompare(b.date)));
  await recordMood(key, owner, days[400]!.date, 1);
  expect(await recentMoods(key, owner, 1000)).toEqual([...days.slice(1, 400), { date: days[400]!.date, value: 1 }]);
  await clearMoodLog(owner);
  await recordMood(key, owner, "2026-10-04", -3, 3);
  await recordMood(key, owner, "2026-10-04", 0.5, Number.NaN);
  expect(await recentMoods(key, owner)).toEqual([{ date: "2026-10-04", value: 0.5, energy: 1 }]);
  await recordMood(key, owner, "2026-10-04", -0.5, null);
  await recordMood(key, owner, "2026-10-05", 0, -3);
  expect(await recentMoods(key, owner, 1)).toEqual([{ date: "2026-10-05", value: 0, energy: -1 }]);
  const before = records.get(`mindpattern.moodlog.${owner}`); await removeMoodDay(key, owner, "absent"); expect(records.get(`mindpattern.moodlog.${owner}`)).toBe(before);
  await removeMoodDay(key, owner, "2026-10-05"); expect(await recentMoods(key, owner)).toEqual([{ date: "2026-10-04", value: -0.5 }]);
  await consumerBuffersCleared();
});
it("uses local yesterday across month/leap boundaries and its default current day", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date(2024, 2, 1, 12));
  await recordMood(key, owner, "2024-02-28", 0); await recordMood(key, owner, "2024-02-29", 0);
  expect(await localStreak(key, owner)).toBe(2);
  await recordMood(key, owner, "2024-03-01", 0); expect(await localStreak(key, owner)).toBe(3);
  await consumerBuffersCleared();
});
it("lets a rejected mood write fail loudly and continues serializing later successful writes", async () => {
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async () => { throw new Error("quota"); }, removeItem: async () => {} });
  await expect(recordMood(key, owner, "2026-10-04", 0)).rejects.toThrow(); await consumerBuffersCleared();
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); } });
  await Promise.all([recordMood(key, owner, "2026-10-04", -1), recordMood(key, owner, "2026-10-05", 1)]);
  expect(await recentMoods(key, owner)).toEqual([{ date: "2026-10-04", value: -1 }, { date: "2026-10-05", value: 1 }]);
});

it("ignores invalid authenticated rollback marks and accepts all safe positive integer boundaries", async () => {
  await seed("entryVersions", "entry-versions", '{"valid":1,"maximum":9007199254740991,"zero":0,"negative":-1,"fraction":1.5,"string":"2","null":null,"unsafe":9007199254740992,"nonfinite":1e400}');
  expect(await knownEntryVersion(owner, key, "valid")).toBe(1); expect(await knownEntryVersion(owner, key, "maximum")).toBe(Number.MAX_SAFE_INTEGER);
  for (const id of ["zero", "negative", "fraction", "string", "null", "unsafe", "nonfinite", "absent"]) expect(await knownEntryVersion(owner, key, id)).toBeNull();
  expect(await observeEntryVersions(owner, key, [0, -1, 1.5, Number.NaN, Infinity, Number.MAX_SAFE_INTEGER + 1].map((contentVersion, i) => ({ clientEntryId: `invalid-${i}`, contentVersion })))).toEqual({ advanced: false, rolledBack: [] });
  await consumerBuffersCleared();
});
it("retains in-session high-water marks against storage rollback, skips equal rows, and forgets just the erased entry", async () => {
  await observeEntryVersions(owner, key, [{ clientEntryId: "retained", contentVersion: 5 }, { clientEntryId: "erased", contentVersion: 3 }]);
  await seed("entryVersions", "entry-versions", { retained: 1, erased: 3 });
  expect(await knownEntryVersion(owner, key, "retained")).toBe(5);
  expect(await observeEntryVersions(owner, key, [{ clientEntryId: "retained", contentVersion: 5 }, { clientEntryId: "erased", contentVersion: 2 }])).toEqual({ advanced: false, rolledBack: ["erased"] });
  await noteV2BoundBatch(owner, key, new Set(["retained", "erased"]));
  await forgetEntryVersion(owner, key, "erased"); expect(await knownEntryVersion(owner, key, "erased")).toBeNull(); expect(await entryV2Bindings(owner, key)).toEqual(new Set(["retained"]));
  await forgetEntryVersion(owner, key, "retained"); expect(records.has(`mindpattern.entryVersions.${owner}`)).toBe(false);
  await forgetAllEntryVersions(owner); expect(await entryV2Bindings(owner, key)).toEqual(new Set());
  await consumerBuffersCleared();
});
it("loads only string v2-bound identifiers, returns independent sets and persists new bindings only once", async () => {
  await seed("entryV2Bound", "entry-v2-bound", ["old", null, 2, false, { id: "bad" }]);
  const first = await entryV2Bindings(owner, key); expect(first).toEqual(new Set(["old"])); first.add("caller-only"); expect(await entryV2Bindings(owner, key)).toEqual(new Set(["old"]));
  await noteV2BoundBatch(owner, key, new Set(["old", "new"])); await consumerBuffersCleared();
  const committed = records.get(`mindpattern.entryV2Bound.${owner}`); await noteV2BoundBatch(owner, key, new Set(["old", "new"])); expect(records.get(`mindpattern.entryV2Bound.${owner}`)).toBe(committed);
  resetEntryVersionMirrors(); expect(await entryV2Bindings(owner, key)).toEqual(new Set(["old", "new"]));
});
it("refuses an authenticated string masquerading as an iterable binding collection", async () => {
  await seed("entryV2Bound", "entry-v2-bound", '"protected"'); expect(await entryV2Bindings(owner, key)).toEqual(new Set());
});
it("forgets both in-memory protections at account erasure, and does not write an unchanged version observation", async () => {
  await observeEntryVersions(owner, key, [{ clientEntryId: "protected", contentVersion: 5 }]); await noteV2BoundBatch(owner, key, new Set(["protected"]));
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async () => { throw new Error("storage unavailable"); }, removeItem: async k => { records.delete(k); } });
  expect(await observeEntryVersions(owner, key, [{ clientEntryId: "protected", contentVersion: 5 }])).toEqual({ advanced: false, rolledBack: [] });
  await forgetAllEntryVersions(owner); expect(await knownEntryVersion(owner, key, "protected")).toBeNull(); expect(await entryV2Bindings(owner, key)).toEqual(new Set());
});
it.each([null, {}, "damaged", 1])("retains known binding protection when persistent metadata is unusable: %j", async value => {
  await noteV2BoundBatch(owner, key, new Set(["protected"])); await seed("entryV2Bound", "entry-v2-bound", value); expect(await entryV2Bindings(owner, key)).toEqual(new Set(["protected"]));
  await seed("entryVersions", "entry-versions", value); expect(await knownEntryVersion(owner, key, "absent")).toBeNull(); await consumerBuffersCleared();
});
