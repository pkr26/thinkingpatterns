import { beforeEach, expect, it } from "vitest";
import { crisisDialogShownOn, recordCrisisDialogShown, resetCrisisDialogStampsForTests, sweepLegacyCrisisStamps } from "../src/crisisDialog";
import { INSTRUMENTS, maxScoreForMeasure, measureComplete, measurePayload, measureScore, optionSelected, safetyItemEndorsed, safetyItemValue } from "../src/measures";
import { localStore } from "../src/platform";
import { __setLocaleForTests, t } from "../src/strings";

beforeEach(() => { resetCrisisDialogStampsForTests(); window.localStorage.clear(); });
it("throttles support once per account/local date in memory, resets on reload, and clears legacy sensitive dates only once", async () => {
  const old = "mindpattern.crisisDialog.v1.old";
  localStore.set(old, "2026-10-05"); localStore.set("another.application", "retained");
  sweepLegacyCrisisStamps(); expect(localStore.get(old)).toBeNull(); expect(localStore.get("another.application")).toBe("retained");
  expect(await crisisDialogShownOn("one", "2026-10-05")).toBe(false);
  await recordCrisisDialogShown("one", "2026-10-05"); expect(await crisisDialogShownOn("one", "2026-10-05")).toBe(true);
  expect(await crisisDialogShownOn("two", "2026-10-05")).toBe(false); expect(await crisisDialogShownOn("one", "2026-10-06")).toBe(false);
  localStore.set(old, "new legacy stamp"); await recordCrisisDialogShown("one", "2026-10-06"); expect(localStore.get(old)).toBe("new legacy stamp");
  resetCrisisDialogStampsForTests(); expect(await crisisDialogShownOn("one", "2026-10-06")).toBe(false); expect(localStore.get(old)).toBeNull();
});
it("sweeps legacy stamps on either initial read or record without needing the App mount", async () => {
  for (const method of ["read", "record"]) {
    resetCrisisDialogStampsForTests(); localStore.set("mindpattern.crisisDialog.v1.account", "legacy");
    if (method === "read") await crisisDialogShownOn("account", "2026-10-05"); else await recordCrisisDialogShown("account", "2026-10-05");
    expect(localStore.get("mindpattern.crisisDialog.v1.account")).toBeNull();
  }
});
it("scores standard questionnaires from response values with finite clamping and excludes additional items", () => {
  for (const [id, size, ceiling] of [["phq9", 9, 27], ["gad7", 7, 21], ["phq2", 2, 6]] as const) {
    expect(maxScoreForMeasure(id)).toBe(ceiling);
    expect(measureScore(id, Array(size).fill(3))).toBe(ceiling);
    expect(measureScore(id, [...Array(size).fill(0), 3, 3])).toBe(0);
    for (const [value, score] of [[-3, 0], [0.4, 0], [0.5, 1], [1.49, 1], [1.5, 2], [2.5, 3], [99, 3], [Infinity, 0], [Number.NaN, 0], [null, 0]] as const) {
      expect(measureScore(id, Array(size).fill(value))).toBe(size * score);
    }
    expect(measureScore(id, [])).toBe(0); expect(measureComplete(id, Array(size).fill(0))).toBe(true);
    expect(measureComplete(id, Array(size - 1).fill(0))).toBe(false); expect(measureComplete(id, Array(size + 1).fill(0))).toBe(false); expect(measureComplete(id, Array(size).fill(null))).toBe(false);
    for (const invalid of [Number.NaN, Infinity, -1, 0.5, 4]) expect(measureComplete(id, [...Array(size - 1).fill(0), invalid])).toBe(false);
    expect(measureComplete(id, new Array<number>(size))).toBe(false);
    const missing = Array(size).fill(0); delete missing[size - 1]; expect(measureComplete(id, missing)).toBe(false);
  }
  expect(optionSelected([0, 2, 4], 1, 2)).toBe(true); expect(optionSelected([0, 2, 4], 1, 1)).toBe(false);
});
it("resolves each response scale value to the label displayed on its bilingual choice chip", () => {
  for (const [locale, labels] of [["en", ["Not at all", "Several days", "More than half the days", "Nearly every day"]], ["es", ["Para nada", "Varios días", "Más de la mitad de los días", "Casi todos los días"]]] as const) {
    __setLocaleForTests(locale);
    for (const id of ["phq9", "gad7", "phq2"] as const) expect(INSTRUMENTS[id].options.map(value => t(INSTRUMENTS[id].optionKey(value)))).toEqual(labels);
  }
  __setLocaleForTests("en");
});
it("carries the raw PHQ-9 safety response independently of total score and omits it for other instruments", () => {
  for (const [value, clamped] of [[-1, 0], [0, 0], [0.4, 0], [0.5, 1], [2.5, 3], [4, 3], [Infinity, null], [Number.NaN, null], [null, null]] as const) {
    const picks = [...Array(8).fill(0), value];
    expect(safetyItemValue("phq9", picks)).toBe(clamped); expect(safetyItemEndorsed("phq9", picks)).toBe((clamped ?? 0) > 0);
    expect(JSON.parse(measurePayload("phq9", picks, "2026-10-05"))).toEqual({ v: 1, measure: "phq9", score: clamped ?? 0, ...(clamped === null ? {} : { item9: clamped }), completed_at: "2026-10-05" });
  }
  for (const id of ["gad7", "phq2"] as const) { expect(safetyItemValue(id, [3, 3, 3])).toBeNull(); expect(safetyItemEndorsed(id, [3, 3, 3])).toBe(false); expect(JSON.parse(measurePayload(id, [1, 2], "2026-10-05"))).toEqual({ v: 1, measure: id, score: 3, completed_at: "2026-10-05" }); }
  for (const id of ["unreleased", "constructor", "toString", "__proto__", null, 1, {}, ["phq9"], { toString: null }, ""] as const) expect(maxScoreForMeasure(id)).toBeNull();
});
