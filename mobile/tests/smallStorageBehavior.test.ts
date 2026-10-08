import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv, createDecipheriv } from "node:crypto";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { clearPendingMeasure, erasePendingMeasure, loadPendingMeasure, savePendingMeasure, type PendingMeasure } from "../src/pendingMeasure";
import { buildFeedbackBlob, clearFeedback, eraseFeedback, recordFeedbackTap, recordPatternMute } from "../src/questionFeedback";
import { markAccountDeleted, changeLocalSessionOwner } from "../src/localWriteGuard";
import { checkAnalysisGeneration, forgetAnalysisGeneration, resetAnalysisGenerationMirrors } from "../src/stateSeqGuard";
import { clearThresholdNotice, recordThresholdNotice, thresholdNoticeShown } from "../src/thresholdNotice";
import { clearReminderPrefs, getReminderPrefs, nextReminderFireTime, setReminderEnabled, setReminderTime } from "../src/reminders";
import { clearLastMeasureDate, clearMeasureReminderPrefs, getMeasureReminderPrefs, lastMeasureCompletedOn, measureReminderDue, nextMeasureReminderFireTime, recordMeasureCompleted, setMeasureReminderEnabled, setMeasureReminderInterval } from "../src/measureReminders";

const owner = "11111111111111111111111111111111", other = "22222222222222222222222222222222", key = Buffer.alloc(32, 13);
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); runTestControl(setSecureStoreBackend, null); runTestControl(resetAnalysisGenerationMirrors); });
afterEach(() => { vi.restoreAllMocks(); });
function sealedText(domain: string, text: string): string {
  const nonce = Buffer.alloc(12, 3), cipher = createCipheriv("aes-256-gcm", key, nonce); cipher.setAAD(Buffer.from(JSON.stringify([domain, owner])));
  return Buffer.concat([nonce, cipher.update(text), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
function sealed(domain: string, value: unknown): string { return sealedText(domain, JSON.stringify(value)); }
function decoded(blob: string, domain: string, ...extra: string[]): any {
  const bytes = Buffer.from(blob, "base64"), decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12)); decipher.setAuthTag(bytes.subarray(-16));
  decipher.setAAD(Buffer.from(JSON.stringify([domain, owner, ...extra]))); return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]).toString());
}

it("persists all completed instrument picks with stable retry ids, isolates owners, and clears acknowledged records", async () => {
  for (const [kind, count] of [["phq9", 9], ["gad7", 7], ["phq2", 2]] as const) for (const pick of [0, 1, 2, 3]) {
    const record: PendingMeasure = { kind, picks: Array(count).fill(pick), clientMeasureId: "x".repeat(128), date: "2026-10-05" };
    await savePendingMeasure(key, owner, record); expect(await loadPendingMeasure(key, owner)).toEqual(record);
  }
  expect(await loadPendingMeasure(key, other)).toBeNull(); await clearPendingMeasure(owner); expect(await loadPendingMeasure(key, owner)).toBeNull();
});

it.each([
  null, [], "text", { kind: "constructor" }, { kind: "unknown" }, { kind: 3 }, { kind: ["phq2"] },
  { clientMeasureId: "" }, { clientMeasureId: "x".repeat(129) }, { clientMeasureId: 1 },
  { picks: "invalid" }, { picks: [0] }, { picks: [0, 0, 0] }, { picks: [0, -1] }, { picks: [0, 4] }, { picks: [0, 1.2] }, { picks: [0, "1"] }, { picks: [0, null] },
  { date: 1 }, { date: ["2026-10-05"] }, { date: "2026-1-05" }, { date: "prefix2026-10-05" }, { date: "2026-10-05suffix" },
])("refuses authenticated malformed pending questionnaire input %j", async fields => {
  const value = fields !== null && !Array.isArray(fields) && typeof fields === "object" ? { kind: "phq2", picks: [0, 3], clientMeasureId: "stable", date: "2026-10-05", ...fields } : fields;
  await storage.setItem(`@mindpattern/pending_measure_${owner}`, sealed("pending-measure", value)); expect(await loadPendingMeasure(key, owner)).toBeNull();
});
it("treats authenticated pending plaintext with invalid JSON as absent", async () => {
  await storage.setItem(`@mindpattern/pending_measure_${owner}`, sealedText("pending-measure", "{invalid authenticated JSON"));
  expect(await loadPendingMeasure(key, owner)).toBeNull();
});

it("keeps distinct concurrent feedback taps and the last mute choice in the server's date-bound recompute body", async () => {
  await Promise.all([recordFeedbackTap(key, owner, "a", true), recordFeedbackTap(key, owner, "b", false)]);
  await recordPatternMute(key, owner, "a", true); await recordPatternMute(key, owner, "a", false); await recordPatternMute(key, owner, "b", true);
  const blob = (await buildFeedbackBlob(key, owner))!, today = new Date().toISOString().slice(0, 10), output = decoded(blob, "feedback", today);
  expect(output.feedback.sort((a: any, b: any) => a.pid.localeCompare(b.pid))).toEqual([{ pid: "a", resonated: true }, { pid: "b", resonated: false }]);
  expect(output.muted).toEqual(["b"]); expect(output.unmuted).toEqual(["a"]); expect(() => decoded(blob, "feedback", "2000-01-01")).toThrow();
  expect(await buildFeedbackBlob(key, other)).toBeNull(); await clearFeedback(owner); expect(await buildFeedbackBlob(key, owner)).toBeNull();
});

it("keeps the newest hundred valid events and ignores malformed authenticated optional feedback", async () => {
  const events = Array.from({ length: 101 }, (_, n) => ({ pid: `event-${n}`, resonated: n % 2 === 0 }));
  await storage.setItem(`@mindpattern/question_feedback.${owner}`, sealed("feedback-local", [...events, null, {}, { pid: 4, resonated: true }, { pid: "invalid", resonated: 1, mute: "yes" }]));
  await recordPatternMute(key, owner, "last", true);
  const blob = (await buildFeedbackBlob(key, owner))!, output = decoded(blob, "feedback", new Date().toISOString().slice(0, 10));
  expect(output.feedback).toEqual(events.slice(2)); expect(output.muted).toEqual(["last"]); expect(output.unmuted).toEqual([]);
});
it.each([null, {}, "not an array"])("treats authenticated optional feedback %j as absent", async value => {
  await storage.setItem(`@mindpattern/question_feedback.${owner}`, sealed("feedback-local", value)); expect(await buildFeedbackBlob(key, owner)).toBeNull();
});

it("uses the authorized erasure lane to remove a deleted account's pending questionnaires and feedback", async () => {
  await savePendingMeasure(key, owner, { kind: "phq2", picks: [1, 3], clientMeasureId: "deleted-pending", date: "2026-10-05" });
  await recordFeedbackTap(key, owner, "deleted-feedback", true); markAccountDeleted(owner);
  await expect(clearPendingMeasure(owner)).rejects.toThrow("deleted"); await expect(clearFeedback(owner)).rejects.toThrow("deleted");
  await erasePendingMeasure(owner); await eraseFeedback(owner); expect(await loadPendingMeasure(key, owner)).toBeNull(); expect(await buildFeedbackBlob(key, owner)).toBeNull();
});

it("rejects a queued feedback callback before a retired native read can fail", async () => {
  vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("Native feedback read failed"));
  const operation = recordFeedbackTap(key, owner, "retired-feedback", true).catch(error => error); changeLocalSessionOwner(owner);
  expect(await operation).toMatchObject({ message: "The local write belongs to a retired account or key generation" });
});

it("holds increasing analysis generations across stale durable storage, absent truth, and genuine process restart", async () => {
  await checkAnalysisGeneration(owner, undefined, undefined); await checkAnalysisGeneration(owner, 5, 5); await checkAnalysisGeneration(owner, 5, 5);
  for (const [payload, echoed] of [[4, 4], [5, 6], [undefined, 5], [5, undefined], [NaN, 5], [5, Infinity]]) await expect(checkAnalysisGeneration(owner, payload, echoed)).rejects.toThrow("freshness check");
  await secureStore.setItem(`mindpattern.stateSeq.${owner}`, "2"); await checkAnalysisGeneration(owner, 5, 5);
  runTestControl(resetAnalysisGenerationMirrors); await expect(checkAnalysisGeneration(owner, 4, 4)).rejects.toThrow("freshness check");
  await secureStore.setItem(`mindpattern.stateSeq.${owner}`, "7"); await expect(checkAnalysisGeneration(owner, 6, 6)).rejects.toThrow("freshness check");
  await checkAnalysisGeneration(other, 1, 1); await forgetAnalysisGeneration(owner); await checkAnalysisGeneration(owner, 1, 1);
});

it("retains a generation in memory when native reads reject, then repairs it after storage recovers", async () => {
  await checkAnalysisGeneration(owner, 8, 8); const fail = vi.spyOn(secureStore, "getItem").mockRejectedValueOnce(new Error("Native storage unreadable"));
  await expect(checkAnalysisGeneration(owner, 7, 7)).rejects.toThrow("freshness check"); fail.mockRestore();
  await secureStore.removeItem(`mindpattern.stateSeq.${owner}`); await checkAnalysisGeneration(owner, 8, 8);
  runTestControl(resetAnalysisGenerationMirrors); await expect(checkAnalysisGeneration(owner, 7, 7)).rejects.toThrow("freshness check");
});

it("shows threshold notices per owner and releases both durable and unreadable-storage memory records", async () => {
  await clearThresholdNotice(owner); expect(await thresholdNoticeShown(owner)).toBe(false); await recordThresholdNotice(owner);
  expect(await thresholdNoticeShown(owner)).toBe(true); expect(await thresholdNoticeShown(other)).toBe(false);
  const read = vi.spyOn(secureStore, "getItem").mockRejectedValue(new Error("Native storage unavailable")); expect(await thresholdNoticeShown(owner)).toBe(true);
  await clearThresholdNotice(owner); expect(await thresholdNoticeShown(owner)).toBe(false); read.mockRestore(); expect(await thresholdNoticeShown(owner)).toBe(false);
});

it("round trips each valid daily reminder time and refuses out-of-range or fractional clock picks", async () => {
  for (const [hour, minute] of [[0, 0], [23, 59], [12, 30]]) {
    await setReminderTime(owner, hour!, minute!); await setReminderEnabled(owner, true); expect(await getReminderPrefs(owner)).toEqual({ enabled: true, hour, minute });
    for (const [badHour, badMinute] of [[-1, 0], [24, 0], [1.2, 0], [0, -1], [0, 60], [0, 1.2]]) { await setReminderTime(owner, badHour!, badMinute!); expect(await getReminderPrefs(owner)).toEqual({ enabled: true, hour, minute }); }
  }
  expect(await getReminderPrefs(other)).toEqual({ enabled: false, hour: 20, minute: 0 }); await clearReminderPrefs(owner); expect(await getReminderPrefs(owner)).toEqual({ enabled: false, hour: 20, minute: 0 });
});

it("validates stored daily and measure preference fields through the actual Settings readers", async () => {
  for (const value of [null, false, [], {}, { enabled: 1, hour: 20, minute: 0 }, { enabled: true, hour: -1, minute: 0 }, { enabled: true, hour: 24, minute: 0 }, { enabled: true, hour: 20, minute: 60 }, { enabled: true, hour: 20, minute: 0.2 }]) {
    await storage.setItem(`@mindpattern/reminders_${owner}`, JSON.stringify(value)); expect(await getReminderPrefs(owner)).toEqual({ enabled: false, hour: 20, minute: 0 });
  }
  for (const value of [null, false, [], {}, { enabled: 1, intervalWeeks: 4 }, { enabled: true, intervalWeeks: 3 }, { enabled: true, intervalWeeks: 4.2 }, { enabled: true, intervalWeeks: "4" }]) {
    await storage.setItem(`@mindpattern/measure_reminders_${owner}`, JSON.stringify(value)); expect(await getMeasureReminderPrefs(owner)).toEqual({ enabled: false, intervalWeeks: 4 });
  }
  for (const interval of [2, 4, 8]) { await setMeasureReminderInterval(owner, interval); await setMeasureReminderEnabled(owner, true); expect(await getMeasureReminderPrefs(owner)).toEqual({ enabled: true, intervalWeeks: interval }); }
  await setMeasureReminderInterval(owner, 99); expect(await getMeasureReminderPrefs(owner)).toEqual({ enabled: true, intervalWeeks: 8 });
  await clearMeasureReminderPrefs(owner); expect(await getMeasureReminderPrefs(owner)).toEqual({ enabled: false, intervalWeeks: 4 });
});

it("moves completion dates forward and drops hostile calendar stamps without inventing reminders", async () => {
  expect(await lastMeasureCompletedOn(owner)).toBeNull(); await recordMeasureCompleted(owner, "2026-10-05"); await recordMeasureCompleted(owner, "2026-10-04");
  expect(await lastMeasureCompletedOn(owner)).toBe("2026-10-05");
  for (const invalid of ["2026-02-29", "2026-04-31", "2026-99-99", "0026-10-05", "2026-2-05", " 2026-10-05", "2026-10-05-extra", "prefix2026-10-05", "2026-10-05suffix"]) {
    await recordMeasureCompleted(owner, invalid); expect(await lastMeasureCompletedOn(owner)).toBe("2026-10-05");
    await secureStore.setItem(`@mindpattern/last_measure_${other}`, invalid); expect(await lastMeasureCompletedOn(other)).toBeNull();
  }
  await recordMeasureCompleted(owner, "2026-10-06"); expect(await lastMeasureCompletedOn(owner)).toBe("2026-10-06"); await clearLastMeasureDate(owner); expect(await lastMeasureCompletedOn(owner)).toBeNull();
});

it("schedules daily reminders after the current wall time and wraps year and month boundaries", () => {
  for (const [now, expected] of [[new Date(2026, 11, 31, 19, 59), new Date(2026, 11, 31, 20)], [new Date(2026, 11, 31, 20), new Date(2027, 0, 1, 20)], [new Date(2026, 9, 31, 23), new Date(2026, 10, 1, 20)]]) expect(nextReminderFireTime(now!, 20, 0)).toEqual(expected);
});

it("computes each offered measure interval at its exact calendar boundary and schedules future due days", () => {
  for (const weeks of [2, 4, 8]) {
    expect(measureReminderDue("2026-08-01", weeks, new Date(2026, 7, 1 + weeks * 7 - 1))).toBe(false);
    expect(measureReminderDue("2026-08-01", weeks, new Date(2026, 7, 1 + weeks * 7))).toBe(true);
    expect(measureReminderDue(null, weeks, new Date(2026, 9, 5))).toBe(false);
    expect(nextMeasureReminderFireTime(new Date(2026, 7, 1, 8), "2026-08-01", weeks)).toEqual(new Date(2026, 7, 1 + weeks * 7, 20));
  }
  expect(nextMeasureReminderFireTime(new Date(2026, 11, 31, 20))).toEqual(new Date(2027, 0, 1, 20));
});

it("treats impossible calendar dates as absent rather than scheduling a fabricated check-in", () => {
  const now = new Date(2026, 9, 5, 10);
  for (const hostile of ["2026-02-29", "2026-04-31", "2026-00-01", "0026-10-05", "2026-13-01"])
    expect(measureReminderDue(hostile, 2, now)).toBe(false);
  for (const hostile of ["2027-02-31", "2027-04-31", "2027-1-01", "2027-10-05suffix"])
    expect(nextMeasureReminderFireTime(now, hostile, 2)).toEqual(new Date(2026, 9, 5, 20));
});

it("schedules the next evening after an exact due slot and ignores a due slot already in the past", () => {
  expect(nextMeasureReminderFireTime(new Date(2026, 7, 15, 20), "2026-08-01", 2)).toEqual(new Date(2026, 7, 16, 20));
  expect(nextMeasureReminderFireTime(new Date(2026, 9, 5, 21), "2026-08-01", 2)).toEqual(new Date(2026, 9, 6, 20));
});

it.each(["prefix7", "7suffix", "broken"])("retains an existing freshness watermark when the durable mark is malformed (%s)", async malformed => {
  await checkAnalysisGeneration(owner, 12, 12);
  await secureStore.setItem(`mindpattern.stateSeq.${owner}`, malformed);
  await expect(checkAnalysisGeneration(owner, 11, 11)).rejects.toThrow("freshness check");
  runTestControl(resetAnalysisGenerationMirrors);
  await expect(checkAnalysisGeneration(owner, 11, 11)).rejects.toThrow("freshness check");
});
it.each(["prefix7", "7suffix", "broken"])("retains an existing freshness watermark when a historical plaintext mark is malformed (%s)", async malformed => {
  await checkAnalysisGeneration(owner, 12, 12);
  await storage.setItem(`mindpattern.stateSeq.${owner}`, malformed);
  await expect(checkAnalysisGeneration(owner, 11, 11)).rejects.toThrow("freshness check");
});
it("adopts a two-digit historical generation and retains a rejected but observed durable watermark", async () => {
  await storage.setItem(`mindpattern.stateSeq.${owner}`, "13");
  await expect(checkAnalysisGeneration(owner, 12, 12)).rejects.toThrow("freshness check");
  await secureStore.removeItem(`mindpattern.stateSeq.${owner}`);
  await expect(checkAnalysisGeneration(owner, 12, 12)).rejects.toThrow("freshness check");
});
it("repairs an adopted historical mark below the existing in-memory watermark before restart", async () => {
  await checkAnalysisGeneration(owner, 12, 12); await storage.setItem(`mindpattern.stateSeq.${owner}`, "5");
  await checkAnalysisGeneration(owner, 12, 12); runTestControl(resetAnalysisGenerationMirrors);
  await expect(checkAnalysisGeneration(owner, 11, 11)).rejects.toThrow("freshness check");
});
it.each(["current-generation", "replay", "unreadable-native-mark"] as const)("settles a known %s without an unnecessary held native repair", async condition => {
  await checkAnalysisGeneration(owner, 12, 12);
  if (condition === "unreadable-native-mark") vi.spyOn(secureStore, "getItem").mockRejectedValueOnce(new Error("Native read unavailable"));
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), write = secureStore.setItem;
  vi.spyOn(secureStore, "setItem").mockImplementation(async (slot, value) => { await gate; return write(slot, value); });
  const checking = checkAnalysisGeneration(owner, condition === "current-generation" ? 12 : 11, condition === "current-generation" ? 12 : 11).then(() => "accepted", error => error.message);
  try {
    const result = await Promise.race([checking, new Promise<string>(resolve => setTimeout(() => resolve("blocked by unnecessary repair"), 100))]);
    expect(result).toBe(condition === "current-generation" ? "accepted" : "your pattern data failed its freshness check");
  } finally { release(); await checking; }
});
it.each(["daily", "measure"] as const)("does not publish a retired %s preference after its native read completes", async kind => {
  const update = kind === "daily" ? setReminderEnabled : setMeasureReminderEnabled;
  const current = kind === "daily" ? getReminderPrefs : getMeasureReminderPrefs;
  await update(owner, false);
  const slot = kind === "daily" ? `@mindpattern/reminders_${owner}` : `@mindpattern/measure_reminders_${owner}`;
  let release!: () => void, entered!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; }), read = storage.getItem;
  vi.spyOn(storage, "getItem").mockImplementationOnce(async key => { const value = await read(key); expect(key).toBe(slot); entered(); await gate; return value; });
  const saving = update(owner, true).catch(error => error);
  await Promise.race([reached, saving.then(() => { throw new Error("Preference skipped its durable read"); })]);
  changeLocalSessionOwner(other); release(); expect(await saving).toBeInstanceOf(Error);
  expect((await current(owner)).enabled).toBe(false);
});
it("does not publish retired completion metadata after its secure native read completes", async () => {
  await recordMeasureCompleted(owner, "2026-10-05");
  let release!: () => void, entered!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; }), read = secureStore.getItem;
  vi.spyOn(secureStore, "getItem").mockImplementationOnce(async slot => { const value = await read(slot); entered(); await gate; return value; });
  const saving = recordMeasureCompleted(owner, "2026-10-06");
  await Promise.race([reached, saving.then(() => { throw new Error("Completion skipped its durable read"); })]);
  changeLocalSessionOwner(other); release(); await saving; expect(await lastMeasureCompletedOn(owner)).toBe("2026-10-05");
});
it("settles an already recorded completion without waiting for a redundant native write", async () => {
  await recordMeasureCompleted(owner, "2026-10-05");
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), write = secureStore.setItem;
  vi.spyOn(secureStore, "setItem").mockImplementation(async (slot, value) => { await gate; return write(slot, value); });
  const saving = recordMeasureCompleted(owner, "2026-10-05");
  try { expect(await Promise.race([saving.then(() => "complete"), new Promise<string>(resolve => setTimeout(() => resolve("blocked by duplicate write"), 100))])).toBe("complete"); }
  finally { release(); await saving; }
});
it("reads unavailable native completion metadata as absent", async () => {
  vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("Native metadata read unavailable"));
  expect(await lastMeasureCompletedOn(owner)).toBeNull();
});
it("reads unavailable or wrong-key pending questionnaires as absent", async () => {
  await savePendingMeasure(key, owner, { kind: "phq2", picks: [1, 3], clientMeasureId: "wrong-key-pending", date: "2026-10-05" });
  expect(await loadPendingMeasure(Buffer.alloc(32, 47), owner)).toBeNull();
  vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("Native pending read unavailable"));
  expect(await loadPendingMeasure(key, owner)).toBeNull();
});
