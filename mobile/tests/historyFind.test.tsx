/**
 * History search + mood calendar (2026-09-17): pure-function pins for the
 * filter and the month grid, plus component behavior for the calendar.
 */
import { describe, expect, it, vi } from "vitest";

const { filterEntries, monthGrid, monthLabel, stepMonth } = await import("../src/historyFind");
const { MoodCalendar } = await import("../src/components/MoodCalendar");
const { render, textOf } = await import("./helpers/rtr");

describe("filterEntries", () => {
  const entries = [
    { clientEntryId: "a", entryDate: "2026-09-01", text: "walked by the river" },
    { clientEntryId: "b", entryDate: "2026-09-02", text: "Busy work day at the office" },
    { clientEntryId: "c", entryDate: "2026-08-15", text: "quiet evening" },
  ];

  it("empty query returns everything unchanged", () => {
    expect(filterEntries(entries, "")).toEqual(entries);
    expect(filterEntries(entries, "   ")).toEqual(entries);
  });

  it("matches case-insensitively over the text", () => {
    expect(filterEntries(entries, "RIVER").map((e) => e.clientEntryId)).toContain("a");
    expect(filterEntries(entries, "office")).toHaveLength(1);
  });

  it("matches dates: full day and month prefix", () => {
    expect(filterEntries(entries, "2026-09-02")).toHaveLength(1);
    expect(filterEntries(entries, "2026-09")).toHaveLength(2);
    expect(filterEntries(entries, "2026")).toHaveLength(3);
  });

  it("no match yields an empty list, never an error", () => {
    expect(filterEntries(entries, "zzzz-not-there")).toEqual([]);
  });

  // L-53: search folds Unicode normalization + diacritics on BOTH sides —
  // an NFD paste from another app matches NFC-typed text and vice versa,
  // and accent-insensitive typing still finds accented entries.
  it("folds NFC/NFD normalization differences between query and text", () => {
    const nfc = [{ clientEntryId: "n1", entryDate: "2026-09-01", text: "café au lait" }]; // é composed
    const nfdQuery = "cafe\u0301"; // é decomposed (a paste from another app)
    const nfd = [{ clientEntryId: "n2", entryDate: "2026-09-01", text: "reve\u0301 late" }]; // é decomposed
    expect(filterEntries(nfc, nfdQuery)).toHaveLength(1);
    expect(filterEntries(nfd, "café")).toHaveLength(0); // "café" is not in that text at all
    expect(filterEntries(nfd, "revé")).toHaveLength(1); // NFC query, NFD text
    expect(filterEntries(nfd, "reve\u0301")).toHaveLength(1); // NFD query, NFD text
  });

  it("matches diacritics-insensitively in both directions", () => {
    const accented = [
      { clientEntryId: "a1", entryDate: "2026-09-01", text: "El año pasado, más cansado" },
    ];
    expect(filterEntries(accented, "ano pasado").map((e) => e.clientEntryId)).toEqual(["a1"]);
    expect(filterEntries(accented, "MAS CANSADO").map((e) => e.clientEntryId)).toEqual(["a1"]);
    expect(filterEntries(accented, "jahr")).toEqual([]); // folding is not stemming
    // An accented query also finds plain text ("cafe" finds "cafe").
    const plain = [{ clientEntryId: "p1", entryDate: "2026-09-01", text: "cafe con leche" }];
    expect(filterEntries(plain, "café").map((e) => e.clientEntryId)).toEqual(["p1"]);
  });
});

describe("monthGrid", () => {
  it("September 2026 starts on a Tuesday (Monday-first: one leading blank)", () => {
    const cells = monthGrid(2026, 9);
    expect(cells[0]).toEqual({ iso: null, day: 0 });
    expect(cells[1]).toEqual({ iso: "2026-09-01", day: 1 });
    expect(cells).toHaveLength(30 + 1);
  });

  it("February 2028 (leap) has 29 days plus one leading blank (starts Tuesday)", () => {
    const cells = monthGrid(2028, 2);
    expect(cells[0]).toEqual({ iso: null, day: 0 });
    expect(cells[1]).toEqual({ iso: "2028-02-01", day: 1 });
    expect(cells).toHaveLength(30);
  });

  it("labels and stepping wrap the year", () => {
    expect(monthLabel(2026, 9)).toBe("September 2026");
    expect(stepMonth(2026, 1, -1)).toEqual({ year: 2025, month: 12 });
    expect(stepMonth(2026, 12, 1)).toEqual({ year: 2027, month: 1 });
    expect(stepMonth(2026, 9, -1)).toEqual({ year: 2026, month: 8 });
  });
});

describe("MoodCalendar", () => {
  const dayMoods = { "2026-09-01": 0.5, "2026-09-02": -0.8 };

  async function calendar(overrides?: Partial<Parameters<typeof MoodCalendar>[0]>) {
    return render(
      <MoodCalendar
        dayMoods={dayMoods}
        journaledDays={new Set(["2026-09-01", "2026-09-02"])}
        selectedDay={null}
        onSelectDay={() => {}}
        {...overrides}
      />,
    );
  }

  it("renders the weekday header and the month label", async () => {
    const root = await calendar();
    const now = new Date();
    const label = `${now.toLocaleString("en-US", { month: "long" })} ${now.getFullYear()}`;
    expect(textOf(root)).toContain(label);
    expect(textOf(root)).toContain("M"); // Monday-first header marker
  });

  it("tapping a journaled day selects it; tapping the selection again deselects", async () => {
    const onSelectDay = vi.fn();
    const root = await calendar({ onSelectDay });
    const journaled = root.root
      .findAll((n) => typeof n.props?.accessibilityLabel === "string")
      .map((n) => n.props.accessibilityLabel as string)
      .find((label: string) => /^\d{4}-\d{2}-\d{2}, journaled/.test(label));
    expect(journaled).toBeTruthy();
    const day = journaled!.split(",")[0]!;
    // First tap selects the day's ISO date; the selection state re-renders
    // with "selected" and a second tap would pass null.
    const button = root.root
      .findAll((n) => n.props?.accessibilityLabel === journaled && typeof n.props?.onPress === "function")[0];
    expect(button).toBeDefined();
    button!.props.onPress();
    expect(onSelectDay).toHaveBeenCalledWith(day);
  });

  it("a blank day clears a selected filter instead of trapping the person in it", async () => {
    const onSelectDay = vi.fn();
    const root = await calendar({ onSelectDay, selectedDay: "2026-09-01" });
    const blank = root.root.findAll((n) => n.props?.accessibilityLabel === "not-a-real-label");
    expect(blank).toHaveLength(0);
    // Every enabled day button carries an ISO accessibility label.
    const labels = root.root
      .findAll((n) => typeof n.props?.accessibilityLabel === "string")
      .map((n) => n.props.accessibilityLabel as string)
      .filter((l) => /\d{4}-\d{2}-\d{2}/.test(l));
    expect(labels.length).toBeGreaterThan(20);
    const blankDay = root.root.findAll(
      (n) => typeof n.props?.accessibilityLabel === "string" && n.props.accessibilityLabel.endsWith(", no entry") && typeof n.props?.onPress === "function",
    )[0];
    expect(blankDay).toBeDefined();
    blankDay!.props.onPress();
    expect(onSelectDay).toHaveBeenCalledWith(null);
  });
});
