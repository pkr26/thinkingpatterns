import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { adoptLegacyPlaintextMutes, clearMutedPids, readMutedPids, writeMutedPids } from "../src/patternMutes";
import { clearPendingMeasure, loadPendingMeasure, savePendingMeasure, type PendingMeasure } from "../src/pendingMeasure";
import { buildFeedbackBlob, clearFeedback, recordFeedbackTap, recordPatternMute } from "../src/questionFeedback";
import { cadenceDue, clearMeasureCadence, parseCadence, readMeasureCadence, snoozeCadence, writeMeasureCadence } from "../src/measureCadence";
import { checkAnalysisGeneration, forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { clearThresholdNotice, recordThresholdNotice, thresholdNoticeShown } from "../src/thresholdNotice";
import { filterEntries, monthGrid, monthLabel, stepMonth } from "../src/historyFind";
import { newClientEntryId } from "../src/entryId";
import { __setLocaleForTests } from "../src/strings";
import * as platform from "../src/platform";

vi.mock("../src/crypto/core", async original => {
  const actual = await original<typeof import("../src/crypto/core")>();
  return { ...actual, encrypt: vi.fn(actual.encrypt), decrypt: vi.fn(actual.decrypt) };
});
const owner = "storage-behavior", other = "separate-storage-owner";
let key: Uint8Array<ArrayBuffer>, records: Map<string, string>;
beforeEach(async () => {
  records = new Map(); key = new Uint8Array(new ArrayBuffer(32)).fill(13);
  setKvBackendForTests({ getItem: async slot => records.get(slot) ?? null, setItem: async (slot, value) => { records.set(slot, value); }, removeItem: async slot => { records.delete(slot); }, keys: async () => [...records.keys()] });
  await forgetAnalysisGeneration(owner); window.localStorage.clear(); __setLocaleForTests("en");
  vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
});
afterEach(() => { setKvBackendForTests(null); vi.restoreAllMocks(); __setLocaleForTests("en"); });
async function sealed(domain: string, value: unknown): Promise<string> { return toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(value)), buildAad(domain, owner))); }
async function decoded(blob: string, domain: string, ...extra: string[]): Promise<unknown> { return JSON.parse(new TextDecoder().decode(await decrypt(key, fromBase64(blob), buildAad(domain, owner, ...extra)))); }
async function assertApiPlaintextCleared(): Promise<void> {
  const results = await Promise.allSettled(vi.mocked(decrypt).mock.results.map(result => result.value as Promise<Uint8Array>));
  for (const result of results) if (result.status === "fulfilled") expect(result.value.every(byte => byte === 0)).toBe(true);
  for (const [, plaintext] of vi.mocked(encrypt).mock.calls) expect(plaintext.every(byte => byte === 0)).toBe(true);
}

describe("persisted optional account metadata consumed by patient views", () => {
  it("round trips the muted set, isolates accounts, removes its legacy plaintext and erases public crypto buffers", async () => {
    await writeMutedPids(key, owner, ["old", "duplicate", "duplicate"]);
    expect(await readMutedPids(key, owner)).toEqual(new Set(["old", "duplicate"]));
    expect(await readMutedPids(key, other)).toEqual(new Set());
    const legacySlot = `mindpattern.mutedPids.v1.${owner}`;
    window.localStorage.setItem(legacySlot, JSON.stringify(["adopted", "", "x".repeat(256), "x".repeat(257), null, 4]));
    expect(await adoptLegacyPlaintextMutes(key, owner)).toEqual(new Set(["old", "duplicate", "adopted", "x".repeat(256)]));
    expect(window.localStorage.getItem(legacySlot)).toBeNull();
    expect(await readMutedPids(key, owner)).toEqual(new Set(["old", "duplicate", "adopted", "x".repeat(256)]));
    await assertApiPlaintextCleared();
    await clearMutedPids(owner); expect(await readMutedPids(key, owner)).toEqual(new Set());
  });
  it.each([{}, null, ["", 0, false, "x".repeat(257)], ["accepted", "accepted", "x".repeat(256)]])("validates authenticated stored mute ids: %j", async value => {
    records.set(`mindpattern.patternMutes.v1.${owner}`, await sealed("pattern-mutes", value));
    const expected = Array.isArray(value) && value[0] === "accepted" ? new Set(["accepted", "x".repeat(256)]) : new Set();
    expect(await readMutedPids(key, owner)).toEqual(expected);
  });
  it("drops malformed legacy values while retaining valid encrypted mutes, and recovers after an optional write failure", async () => {
    await writeMutedPids(key, owner, ["retained"]);
    const slot = `mindpattern.mutedPids.v1.${owner}`;
    window.localStorage.setItem(slot, "malformed JSON");
    expect(await adoptLegacyPlaintextMutes(key, owner)).toEqual(new Set(["retained"])); expect(window.localStorage.getItem(slot)).toBeNull();
    vi.spyOn(kv, "setItem").mockRejectedValueOnce(new Error("quota denied"));
    await expect(writeMutedPids(key, owner, ["failed"])).rejects.toThrow();
    await writeMutedPids(key, owner, ["recovered"]); expect(await readMutedPids(key, owner)).toEqual(new Set(["recovered"]));
  });
  it("treats damaged mute ciphertext as absent and keeps a no-legacy adoption side-effect free", async () => {
    records.set(`mindpattern.patternMutes.v1.${owner}`, "invalid ciphertext");
    expect(await readMutedPids(key, owner)).toEqual(new Set());
    expect(await adoptLegacyPlaintextMutes(key, owner)).toEqual(new Set());
    expect(records.get(`mindpattern.patternMutes.v1.${owner}`)).toBe("invalid ciphertext");
  });
  it("persists all standard questionnaire pick values and stable retry ids, isolates accounts and clears acknowledgement", async () => {
    for (const [kind, count] of [["phq9", 9], ["gad7", 7], ["phq2", 2]] as const) {
      for (const pick of [0, 1, 2, 3]) {
        const record: PendingMeasure = { kind, picks: Array(count).fill(pick), clientMeasureId: "x".repeat(128), date: "2026-10-05" };
        await savePendingMeasure(key, owner, record); expect(await loadPendingMeasure(key, owner)).toEqual(record);
      }
    }
    expect(await loadPendingMeasure(key, other)).toBeNull();
    await assertApiPlaintextCleared();
    await clearPendingMeasure(owner); expect(await loadPendingMeasure(key, owner)).toBeNull();
  });
  it.each([
    null, [], "text", { kind: "constructor" }, { kind: "unknown" },
    { clientMeasureId: "" }, { clientMeasureId: "x".repeat(129) }, { clientMeasureId: 1 },
    { picks: "invalid" }, { picks: [0] }, { picks: [0, 0, 0] }, { picks: [0, -1] }, { picks: [0, 4] }, { picks: [0, 1.2] }, { picks: [0, "1"] }, { picks: [0, null] },
    { date: 1 }, { date: "2026-1-05" }, { date: "prefix2026-10-05" }, { date: "2026-10-05suffix" },
  ])("rejects authenticated malformed pending questionnaire fields: %j", async fields => {
    const value = fields !== null && !Array.isArray(fields) && typeof fields === "object" ? { kind: "phq2", picks: [0, 3], clientMeasureId: "stable", date: "2026-10-05", ...fields } : fields;
    records.set(`mindpattern.pendingMeasure.${owner}`, await sealed("pending-measure", value));
    expect(await loadPendingMeasure(key, owner)).toBeNull();
  });
  it("keeps distinct concurrent feedback taps, applies the last mute per pattern and seals the recompute date", async () => {
    expect(await buildFeedbackBlob(key, owner)).toBeNull();
    await Promise.all([recordFeedbackTap(key, owner, "a", true), recordFeedbackTap(key, owner, "b", false)]);
    await recordPatternMute(key, owner, "a", true); await recordPatternMute(key, owner, "a", false); await recordPatternMute(key, owner, "b", true);
    vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
    const blob = await buildFeedbackBlob(key, owner); expect(blob).not.toBeNull();
    await assertApiPlaintextCleared();
    const output = await decoded(blob!, "feedback", new Date().toISOString().slice(0, 10)) as { feedback: { pid: string, resonated: boolean }[], muted: string[], unmuted: string[] };
    expect(output.feedback.sort((a, b) => a.pid.localeCompare(b.pid))).toEqual([{ pid: "a", resonated: true }, { pid: "b", resonated: false }]);
    expect(output.muted).toEqual(["b"]); expect(output.unmuted).toEqual(["a"]);
    await expect(decoded(blob!, "feedback", "2000-01-01")).rejects.toThrow();
    expect(await buildFeedbackBlob(key, other)).toBeNull();
    await clearFeedback(owner); expect(await buildFeedbackBlob(key, owner)).toBeNull();
  });
  it("retains only the newest 64 feedback events and accepts both valid event shapes from authenticated storage", async () => {
    const existing = [...Array.from({ length: 65 }, (_, n) => ({ pid: `event-${n}`, resonated: n % 2 === 0 })), null, {}, { pid: 4, resonated: true }, { pid: "invalid", resonated: 1, mute: "yes" }];
    records.set(`mindpattern.feedback.${owner}`, await sealed("feedback-local", existing));
    await recordPatternMute(key, owner, "last", true);
    const blob = (await buildFeedbackBlob(key, owner))!;
    const output = await decoded(blob, "feedback", new Date().toISOString().slice(0, 10)) as { feedback: unknown[], muted: string[], unmuted: string[] };
    expect(output.feedback).toEqual(existing.slice(2, 65)); expect(output.muted).toEqual(["last"]); expect(output.unmuted).toEqual([]);
  });
  it.each([null, {}, "not an array"])("treats invalid optional feedback as empty: %j", async value => {
    records.set(`mindpattern.feedback.${owner}`, await sealed("feedback-local", value)); expect(await buildFeedbackBlob(key, owner)).toBeNull();
  });
  it("shows and clears each account's one-time threshold notice independently", async () => {
    expect(await thresholdNoticeShown(owner)).toBe(false); await recordThresholdNotice(owner);
    expect(await thresholdNoticeShown(owner)).toBe(true); expect(await thresholdNoticeShown(other)).toBe(false);
    expect(records.get(`mindpattern.thresholdNotice.v1.${owner}`)).toBe(new Date().toISOString().slice(0, 10));
    await clearThresholdNotice(owner); expect(await thresholdNoticeShown(owner)).toBe(false);
  });
});

describe("check-in cadence and generation rollback contracts", () => {
  const off = { enabled: false, intervalWeeks: 4 as const, snoozedUntil: null };
  it("defaults invalid stored cadence to opt-out and validates each field independently", async () => {
    for (const raw of [null, "", "not JSON", "null", "false", "1", "[]"]) expect(parseCadence(raw)).toEqual(off);
    for (const enabled of [true, false, 1, "true", null]) for (const intervalWeeks of [2, 4, 8, 3, "4", null]) {
      expect(parseCadence(JSON.stringify({ enabled, intervalWeeks, snoozedUntil: "2026-10-05" }))).toEqual({ enabled: enabled === true, intervalWeeks: [2, 4, 8].includes(intervalWeeks as number) ? intervalWeeks : 4, snoozedUntil: "2026-10-05" });
    }
    for (const date of [null, 1, "2026-1-05", "prefix2026-10-05", "2026-10-05suffix"]) expect(parseCadence(JSON.stringify({ snoozedUntil: date }))).toEqual(off);
    await writeMeasureCadence(owner, { enabled: true, intervalWeeks: 8, snoozedUntil: null }); expect(await readMeasureCadence(owner)).toEqual({ enabled: true, intervalWeeks: 8, snoozedUntil: null });
    expect(await readMeasureCadence(other)).toEqual(off); await clearMeasureCadence(owner); expect(await readMeasureCadence(owner)).toEqual(off);
  });
  it("shows opt-in reminders exactly at each interval, suppresses unknown history and snoozes across month/year boundaries", () => {
    for (const intervalWeeks of [2, 4, 8] as const) {
      const on = { enabled: true, intervalWeeks, snoozedUntil: null };
      const start = new Date("2026-08-01T00:00:00Z");
      const date = (days: number) => new Date(start.getTime() + days * 86400000).toISOString().slice(0, 10);
      expect(cadenceDue(on, "2026-08-01", date(intervalWeeks * 7 - 1))).toBe(false); expect(cadenceDue(on, "2026-08-01", date(intervalWeeks * 7))).toBe(true);
      expect(cadenceDue(on, undefined, "2026-10-05")).toBe(false); expect(cadenceDue(on, null, "2026-10-05")).toBe(true); expect(cadenceDue(off, null, "2026-10-05")).toBe(false);
      expect(cadenceDue({ ...on, snoozedUntil: "2026-10-06" }, null, "2026-10-05")).toBe(false); expect(cadenceDue({ ...on, snoozedUntil: "2026-10-05" }, null, "2026-10-05")).toBe(true);
      expect(cadenceDue(on, "invalid", "2026-10-05")).toBe(false); expect(cadenceDue(on, "2026-08-01", "invalid")).toBe(false);
      expect(snoozeCadence(on, "2026-12-30")).toEqual({ ...on, snoozedUntil: "2027-01-02" });
    }
  });
  it("pins increasing analysis generations, rejects replay/missing/contradictory truth and repairs a stale durable mark", async () => {
    await checkAnalysisGeneration(owner, undefined, undefined);
    await checkAnalysisGeneration(owner, 5, 5); await checkAnalysisGeneration(owner, 5, 5);
    await expect(checkAnalysisGeneration(owner, 4, 4)).rejects.toThrow("freshness check"); await expect(checkAnalysisGeneration(owner, 5, 6)).rejects.toThrow("freshness check");
    for (const value of [undefined, NaN, Infinity]) { await expect(checkAnalysisGeneration(owner, value, 5)).rejects.toThrow(); await expect(checkAnalysisGeneration(owner, 5, value)).rejects.toThrow(); }
    records.set(`mindpattern.stateSeq.${owner}`, "2"); await checkAnalysisGeneration(owner, 5, 5); expect(records.get(`mindpattern.stateSeq.${owner}`)).toBe("5");
    records.set(`mindpattern.stateSeq.${owner}`, "7"); await expect(checkAnalysisGeneration(owner, 6, 6)).rejects.toThrow();
    await checkAnalysisGeneration(other, 1, 1); await forgetAnalysisGeneration(owner); await checkAnalysisGeneration(owner, 1, 1);
  });
});

describe("public journal search, calendar and wire id helpers", () => {
  it("finds NFC/NFD text case-insensitively, trims queries and matches date prefixes without filtering empty queries", () => {
    const rows = [{ clientEntryId: "a", entryDate: "2026-10-05", text: "CAFÉ with friends" }, { clientEntryId: "b", entryDate: "2026-09-01", text: "cafe\u0301, descanso" }, { clientEntryId: "c", entryDate: "2025-10-01", text: "Other writing" }];
    for (const query of [" café ", "CAFE", "cafe\u0301"]) expect(filterEntries(rows, query).map(row => row.clientEntryId)).toEqual(["a", "b"]);
    expect(filterEntries(rows, "2026").map(row => row.clientEntryId)).toEqual(["a", "b"]); expect(filterEntries(rows, "2026-10-05")).toEqual([rows[0]]);
    expect(filterEntries(rows, "")).toBe(rows); expect(filterEntries(rows, "  ")).toBe(rows); expect(filterEntries(rows, "unmatched")).toEqual([]);
    const plain = [{ clientEntryId: "plain", entryDate: "2026-10-05", text: "cafe strasse" }, { clientEntryId: "sharp", entryDate: "2026-10-05", text: "Straße" }];
    expect(filterEntries(plain, "café")).toEqual([plain[0]]);
    expect(filterEntries(plain, "strasse")).toEqual([plain[0]]);
    expect(filterEntries(plain, "straße")).toEqual([plain[1]]);
  });
  it("renders Monday-first UTC month cells including leap years and wraps month navigation in both directions", () => {
    const leads2026 = [3, 6, 6, 2, 4, 0, 2, 5, 1, 3, 6, 1], lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (let month = 1; month <= 12; month++) {
      const cells = monthGrid(2026, month), lead = leads2026[month - 1]!;
      expect(cells.slice(0, lead)).toEqual(Array(lead).fill({ iso: null, day: 0 }));
      expect(cells.slice(lead)).toEqual(Array.from({ length: lengths[month - 1]! }, (_, n) => ({ iso: `2026-${String(month).padStart(2, "0")}-${String(n + 1).padStart(2, "0")}`, day: n + 1 })));
      expect(stepMonth(2026, month, 1)).toEqual(month === 12 ? { year: 2027, month: 1 } : { year: 2026, month: month + 1 });
      expect(stepMonth(2026, month, -1)).toEqual(month === 1 ? { year: 2025, month: 12 } : { year: 2026, month: month - 1 });
    }
    expect(monthGrid(2024, 2).at(-1)).toEqual({ iso: "2024-02-29", day: 29 });
    expect(monthLabel(2026, 10)).toBe("October 2026"); __setLocaleForTests("es"); expect(monthLabel(2026, 10)).toBe("octubre 2026");
  });
  it("preserves nine random bytes in a URL-safe dated deduplication id", () => {
    const bytes = new Uint8Array(new ArrayBuffer(9)); bytes.set([255, 254, 253, 251, 250, 249, 247, 246, 245]);
    vi.spyOn(platform, "randomBytes").mockReturnValueOnce(bytes);
    const id = newClientEntryId("2026-10-05"); expect(id).toMatch(/^e-2026-10-05-[A-Za-z0-9_-]{12}$/);
    expect(fromBase64(id.slice("e-2026-10-05-".length).replace(/-/g, "+").replace(/_/g, "/"))).toEqual(bytes);
    expect(platform.randomBytes).toHaveBeenCalledWith(9);
  });
});
