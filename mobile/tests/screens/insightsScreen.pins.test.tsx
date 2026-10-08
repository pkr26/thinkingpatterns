/**
 * Deep-mutation pins for InsightsScreen (2026-09-15 Stryker campaign).
 *
 * Each block kills a specific surviving mutant class, verified mutant-by-
 * mutant with targeted `stryker run --mutate src/screens/InsightsScreen.tsx`
 * passes:
 *  - evidence-row presence guards (a row must be ABSENT when its stat is
 *    missing — `typeof x === "number" → true` used to render
 *    "undefined entries…" rows unchallenged),
 *  - boundary values (effect-size bands, sparkline trend thresholds, the
 *    n=2 "one day is a point" rule, streak/sparkline gating at 0/1/2),
 *  - the fmt fallback ("—") and sanitizer trust boundaries (label length,
 *    invalid-label cards, non-array patterns),
 *  - the full evidence-panel / chip / sparkline style contract and the
 *    accessibility labels of both expanders.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { ScrollView, Text, TouchableOpacity, View } from "react-native";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actualApi = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ...actualApi, ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

const refreshActiveDays = vi.fn(async () => {});
// L-59: the screen adopts the already-fetched count instead of re-fetching.
const applyActiveDays = vi.fn();
const beginProgressRead = vi.fn(async () => ({ owner: "user-1", generation: 0, request: 0 }));
const finishProgressRead = vi.fn();
const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ refreshActiveDays, applyActiveDays, beginProgressRead, finishProgressRead, unlockDays: 30, touchActivity }) };
});

const { api } = await import("../../src/api/client");
const { InsightsScreen } = await import("../../src/screens/InsightsScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { INSIGHTS_PAYLOAD_VERSION } = await import("../../src/crypto/journalCrypto");
const { render, flush, textOf, allText, act, allStyles, expectStyle, pressLabel, touchableByLabel } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const { recordMood, clearMoodLog, localDateISO } = await import("../../src/moodLog");
const storage = (await import("../helpers/storageMock")).default;

const dataKey = Buffer.alloc(32, 9);
const insightsBlob = (payload: unknown): string =>
  encrypt(
    dataKey,
    Buffer.from(JSON.stringify({ v: INSIGHTS_PAYLOAD_VERSION, ...(payload as Record<string, unknown>) })),
    buildAad("insights", "user-1", "patterns"),
  ).toString("base64");

const pattern = (over: Record<string, unknown> = {}) => ({
  kind: "temporal",
  label: "work",
  occurrences: 7,
  confidence: 0.62,
  detail: {},
  ...over,
});

const insightWith = (patterns: unknown[]) => ({
  phase: "insight" as const,
  active_days: 40,
  days_remaining: 0,
  blob: insightsBlob({ stats: { patterns } }),
});

/** Renders the screen with one pattern and expands its evidence panel. */
async function renderExpanded(patterns: unknown[]): Promise<ReturnType<typeof render>> {
  vi.mocked(api.insights).mockResolvedValue(insightWith(patterns) as never);
  const root = await render(<InsightsScreen />);
  await flush();
  await pressLabel(root, "Why am I seeing this?");
  await flush();
  return root;
}

/** The panel is an accordion (opening one card closes the last), so walk
 *  the cards in order: press the k-th card toggle, then run `check` while
 *  that card's panel is the open one. */
async function expandOneByOne(
  root: Awaited<ReturnType<typeof render>>,
  check: (text: string, index: number) => void,
): Promise<void> {
  const cardToggles = root.root.findAllByType(TouchableOpacity).filter((n) => {
    const label = (n.props as { accessibilityLabel?: string }).accessibilityLabel;
    return label === "Why am I seeing this? Evidence for this pattern" || label === "Hide the evidence";
  });
  for (let index = 0; index < cardToggles.length; index += 1) {
    await act(async () => {
      (cardToggles[index].props as { onPress?: () => void }).onPress?.();
    });
    await flush();
    check(textOf(root), index);
  }
}

/** No rendered style object may equal this exactly. */
function expectNoStyle(root: Awaited<ReturnType<typeof render>>, notExpected: Record<string, unknown>): void {
  const hit = allStyles(root).some((s) => JSON.stringify(s) === JSON.stringify(notExpected));
  if (hit) throw new Error(`style should NOT be rendered: ${JSON.stringify(notExpected)}`);
}

beforeEach(() => {
  resetApi(api as never);
  refreshActiveDays.mockClear();
  applyActiveDays.mockClear();
  touchActivity.mockClear();
  storage.__reset();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey });
});

describe("InsightsScreen pins: evidence-row presence guards", () => {
  it("a minimal detail renders ONLY the window and method rows — every stat row stays absent", async () => {
    const root = await renderExpanded([pattern({ detail: {} })]);
    const text = textOf(root);
    // The unconditional row and the always-present method note render…
    expect(text).toContain("Evidence window");
    expect(text).toContain("? → ?");
    expect(text).toContain("your own writing schedule"); // temporal method note
    // …and nothing else: each guard must keep its row out when the stat is
    // missing (guard→true used to render "undefined …" rows unchallenged).
    for (const absent of [
      "entries in your analysis window", // sample_days
      "Concentration", // day + day_fraction
      "Mood difference", // mood_delta
      "Size of the difference", // cohens_d
      "Day-after", // lag_days
      "Carryover", // carryover_recent
      "Swings", // spread_recent
      "Share of entries", // share
      "Earlier → recent", // share_recent + share_earlier
      "Returning for", // span_days
      "Tone", // negativity
      "Shift", // shift
    ]) {
      expect(text).not.toContain(absent);
    }
    // Exactly two rows (Evidence window, Method): the rows array starts
    // empty (a poisoned initial value used to survive unseen).
    const evidenceRows = root.root
      .findAllByType(View)
      .filter((n) => JSON.stringify((n.props as { style?: unknown }).style) === JSON.stringify({ flexDirection: "row", gap: 10 }));
    expect(evidenceRows).toHaveLength(2);
  });

  it("half-present pairs stay absent: day without day_fraction and the reverse", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ detail: { day: "Sunday" } }),
      pattern({ label: "sleep", detail: { day_fraction: 0.5 } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    // The accordion means each card must be checked while IT is open.
    await expandOneByOne(root, (text) => {
      expect(text).not.toContain("Concentration");
    });
  });

  it("half-present share pair stays absent in both directions", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ detail: { share_recent: 0.3 } }),
      pattern({ label: "sleep", detail: { share_earlier: 0.3 } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    await expandOneByOne(root, (text) => {
      expect(text).not.toContain("Earlier → recent");
    });
  });

  it("row keys render verbatim when the stats exist", async () => {
    const root = await renderExpanded([
      pattern({ detail: { sample_days: 63, day: "Sunday", day_fraction: 0.78 } }),
    ]);
    const text = textOf(root);
    expect(text).toContain("Based on");
    expect(text).toContain("Concentration");
  });

  it("an unknown kind gets no Method row (the note guard is real)", async () => {
    const root = await renderExpanded([pattern({ kind: "mystery_kind" })]);
    expect(textOf(root)).not.toContain("Method");
  });

  it("a shift without a baseline renders the fmt fallback dash", async () => {
    const root = await renderExpanded([
      pattern({ kind: "mood_shift", detail: { shift: -0.2 } }),
    ]);
    expect(textOf(root)).toContain("−0.20 against your baseline of —");
  });

  it("keeps legacy signed measurements consistent between summary and evidence", async () => {
    for (const direction of [undefined, "unrecognized", "lower", "higher"]) {
      const root = await renderExpanded([pattern({ kind: "mood_correlation", detail: { mood_delta: -0.4, direction } })]);
      const expected = direction === "higher" ? "higher" : "lower";
      expect(textOf(root)).toContain(`entries read ${expected} by 0.40`);
      expect(textOf(root)).toContain(`${expected} by 0.4`);
      root.unmount();
    }
    const root = await renderExpanded([pattern({ kind: "mood_shift", detail: { shift: 0, direction: "lower" } })]);
    expect(textOf(root)).toContain("No difference was measured");
    expect(textOf(root)).not.toContain("−0.00");
  });

  it.each([{ channel: "sleep_quality" }, { source: "tag" }])("keeps specialized summaries consistent with signed evidence: %j", async (specialized) => {
    for (const direction of [undefined, "unrecognized"]) {
      const root = await renderExpanded([pattern({ kind: "mood_correlation", detail: { ...specialized, mood_delta: 0.4, direction } })]);
      const summary = "channel" in specialized
        ? "your entries read higher the same day"
        : "Your entries read higher on days you tag";
      expect(textOf(root)).toContain(summary);
      expect(textOf(root)).toContain("entries read higher by 0.40");
      expect(textOf(root)).not.toContain("read lower");
      root.unmount();
    }
  });

  it.each([{ channel: "sleep_quality" }, { source: "tag" }])("does not manufacture specialized directions for absent or zero evidence: %j", async (specialized) => {
    for (const kind of ["mood_correlation", "link"]) {
      const root = await renderExpanded([pattern({ kind, detail: specialized })]);
      expect(textOf(root)).toContain("Details for this observation are unavailable");
      expect(textOf(root)).not.toContain("read lower");
      root.unmount();
    }
    const zero = await renderExpanded([pattern({ kind: "mood_correlation", detail: { ...specialized, mood_delta: 0, direction: "lower" } })]);
    expect(textOf(zero)).toContain("No difference was measured");
    expect(textOf(zero)).not.toContain("read lower");
  });

  it("does not manufacture zero baselines or a direction from incomplete cached evidence", async () => {
    const root = await renderExpanded([pattern({ kind: "avoidance", detail: { silences: 3, observed: 10 } })]);
    expect(textOf(root)).toContain("your usual silent-day rate is unavailable");
    expect(textOf(root)).not.toContain("silent-day rate is 0%");
    root.unmount();
    for (const direction of [undefined, "narrowed", "widened"]) {
      const activity = await renderExpanded([pattern({ kind: "activity_diversity", detail: { entropy_recent: 1.2, entropy_earlier: 2, direction } })]);
      expect(textOf(activity)).toContain(direction ? `has ${direction}` : "Details for this observation are unavailable");
      activity.unmount();
    }
  });
});

describe("InsightsScreen pins: every method note is real copy", () => {
  it("each v2/v3 kind shows its own method sentence in the panel", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "mood_correlation", detail: { mood_delta: -0.4 } }),
      pattern({ kind: "link", label: "sleep", detail: { lag_days: 1 } }),
      pattern({ kind: "inertia", label: "carry", detail: { carryover_recent: 0.5 } }),
      pattern({ kind: "instability", label: "spread", detail: { spread_recent: 0.9 } }),
      pattern({ kind: "mood_shift", detail: { shift: -0.2 } }),
      pattern({ kind: "recurring_phrase", label: "so tired" }),
      pattern({ kind: "rumination", label: "the worry" }),
      pattern({ kind: "topic", label: "guitar", detail: { share: 0.2 } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    // The accordion keeps exactly one panel open — walk the cards in order
    // and check each kind's own method sentence while its panel is open.
    const notes = [
      "Welch's t + effect-size gate",
      "shape of the best-replicated daily-diary link",
      "autocorrelation) compared with your own earlier norm",
      "The spread of your daily mood compared with your own earlier norm.",
      "control chart over your daily mood",
      "Near-duplicate sentence clustering across separated days.",
      "clusters near-identical negative sentences",
      "not from any fixed list",
    ];
    await expandOneByOne(root, (text, index) => {
      expect(text).toContain("Method"); // the row key itself
      expect(text).toContain(notes[index]);
    });
  });
});

describe("InsightsScreen pins: describe() tolerates absent detail per kind", () => {
  it("link and mood_shift cards with no detail at all use their fallbacks without crashing", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      { kind: "link", label: "sleep", occurrences: 3, confidence: 0.4 },
      { kind: "mood_shift", label: "overall", occurrences: 9, confidence: 0.4 },
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).not.toContain("your entries read lower than usual");
    expect(text).toContain("Details for this observation are unavailable. Refresh your observations to see the evidence.");
  });

  it("a steady topic without a share renders the sentence with nothing wedged in", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "topic", label: "tea", detail: {} }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("'tea' is a steady presence in your writing.");
  });
});

describe("InsightsScreen pins: sparklineSummary boundaries", () => {
  it("trend thresholds are strict at ±0.15 and a 2-day series can trend", async () => {
    const { sparklineSummary } = await import("../../src/screens/InsightsScreen");
    const day = (value: number): { date: string; value: number } => ({ date: "2026-09-01", value });
    // diff exactly +0.15 → steady (>= mutant would say rising). The
    // one-day halves make the subtraction float-exact.
    expect(sparklineSummary([day(0.15), day(0.3)])).toBe("Mood trend: steady over 2 days, latest positive");
    // diff exactly −0.15 → steady (<= mutant would say falling).
    expect(sparklineSummary([day(-0.15), day(-0.3)])).toBe("Mood trend: steady over 2 days, latest negative");
    // Halves must be halves: full-array averaging halves the diff and
    // would flatten this 0.2 gap into "steady".
    expect(sparklineSummary([day(0.4), day(0.4), day(0.6), day(0.6)])).toBe("Mood trend: rising over 4 days, latest positive");
    // Two days is already a trend (n <= 2 mutant would force "steady").
    expect(sparklineSummary([day(0.1), day(0.8)])).toBe("Mood trend: rising over 2 days, latest positive");
  });

  it("effect-size band edges are exclusive at 0.2 and 0.5", async () => {
    const { effectSizeWords } = await import("../../src/screens/InsightsScreen");
    expect(effectSizeWords(0.2)).toBe("a small difference");
    expect(effectSizeWords(0.5)).toBe("a medium-sized difference");
    expect(effectSizeWords(-0.2)).toBe("a small difference");
  });
});

describe("InsightsScreen pins: sparkline geometry and gating", () => {
  it("bars follow the day's sign: a zero day is a minimal up bar, never a down bar", async () => {
    await recordMood(dataKey, "user-1", localDateISO(new Date(Date.now() - 2 * 86_400_000)), 0);
    await recordMood(dataKey, "user-1", localDateISO(new Date(Date.now() - 1 * 86_400_000)), 0.5);
    await recordMood(dataKey, "user-1", localDateISO(), -0.5);
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 5, days_remaining: 25 } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Your mood, this month (stays on this device):");

    // Exactly one bar per day, sign-colored, with exact heights:
    // 0 → max(3, 0·20) = 3 up; 0.5 → 10 up; −0.5 → 10 down.
    const bars = allStyles(root).filter((s) => s.backgroundColor === "#93c7a6" || s.backgroundColor === "#d98a80");
    expect(bars).toHaveLength(3);
    expect(bars).toContainEqual({ backgroundColor: "#93c7a6", height: 3 });
    expect(bars).toContainEqual({ backgroundColor: "#93c7a6", height: 10 });
    expect(bars).toContainEqual({ backgroundColor: "#d98a80", height: 10 });

    // Half-cell containers pin the up/down split geometry.
    expectStyle(root, { height: 22, justifyContent: "flex-end" });
    expectStyle(root, { height: 22, justifyContent: "flex-start" });
    expectStyle(root, { flexDirection: "row", alignItems: "flex-end", height: 48, gap: 2, marginTop: 4 });
    expectStyle(root, { flex: 1, height: 48 });
    expectStyle(root, { borderRadius: 1 });
  });

  it("two mood days are not yet a trend: no sparkline heading", async () => {
    await recordMood(dataKey, "user-1", localDateISO(new Date(Date.now() - 86_400_000)), 0.5);
    await recordMood(dataKey, "user-1", localDateISO(), 0.5);
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 5, days_remaining: 25 } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).not.toContain("Your mood, this month");
  });

  it("no mood log: no streak line, and nothing reads a null-user log", async () => {
    await clearMoodLog("user-1");
    // A log parked under the null-user storage key (and null-user AAD)
    // must never be read when no user id is known.
    await recordMood(dataKey, null as never, localDateISO(), 0.5);
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 5, days_remaining: 25 } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).not.toContain("Writing streak");
    expect(textOf(root)).not.toContain("Your mood, this month");
  });

  it("a one-day streak reads singular — exactly", async () => {
    await recordMood(dataKey, "user-1", localDateISO(), 0.4);
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 29, days_remaining: 1 } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Writing streak: 1 day");
    expect(text).not.toContain("Writing streak: 1 days");
  });
});

describe("InsightsScreen pins: load lifecycle", () => {
  it("a stats.patterns that is not an array degrades to empty, not an error", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 40,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: { nope: 1 } } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Nothing solid yet");
    expect(text).not.toContain("Something went wrong");
    // The degradation is silent: no raw engine error leaks into the UI.
    expect(text).not.toMatch(/TypeError|not iterable|Cannot/);
  });

  it("a card with a valid kind but invalid label is dropped; its sibling still renders", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      { kind: "topic", label: 42, occurrences: 5, confidence: 0.5 },
      pattern({ kind: "topic", label: "legit theme" }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("legit theme");
    expect(text).not.toContain("Something went wrong");
  });

  it("a hostile 600-char label is truncated to 500 before rendering", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ label: "y".repeat(600) }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toMatch(/y{500}/);
    expect(text).not.toMatch(/y{501}/);
  });
});

describe("InsightsScreen pins: card chrome, chips and styles", () => {
  it("unknown lifecycle states read as 'observed'", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([pattern({ detail: { day: "Sunday" } })]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(allText(root)).toContain("observed");
  });

  it("chip styles follow the lifecycle state (strong vs early)", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ detail: { pattern_state: "confirmed" } }),
      pattern({ label: "sleep", detail: { pattern_state: "emerging" } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expectStyle(root, { color: "#93c7a6", fontSize: 11, fontWeight: "700" }); // stateStrong
    expectStyle(root, { color: "#a29a8c", fontSize: 11, fontWeight: "600" }); // stateEarly
    // The two chips pair with their own state text.
    const texts = allText(root);
    expect(texts).toContain("seen consistently");
    expect(texts).toContain("early evidence");
  });

  it("a non-new card's chip carries no suffix", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ detail: { pattern_state: "fading", is_new: false } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const texts = allText(root);
    expect(texts).toContain("fading");
    expect(texts.some((t) => t.includes("Stryker"))).toBe(false);
  });

  it("the presence flag mutes the KIND chip; a normal card keeps the accent", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "topic", label: "guitar", detail: { share: 0.3, presence: true } }),
      pattern({ kind: "topic", label: "work", detail: { share: 0.2 } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const colorOf = (node: unknown): unknown =>
      ((node as { props: { style: unknown } }).props.style as Record<string, unknown>[]).flat().findLast(
        (s) => s && typeof s === "object" && "color" in s,
      )?.color;
    const chips = root.root.findAllByType(Text).filter((n) => String(n.props.children) === "THEME");
    expect(chips).toHaveLength(2);
    expect(colorOf(chips[0])).toBe("#a29a8c"); // presence → muted chip
    expect(colorOf(chips[1])).toBe("#b6a9e3"); // normal → accent chip
  });

  it("the expanded evidence panel carries its full style contract", async () => {
    const root = await renderExpanded([pattern({ detail: { sample_days: 63, p_value: 0.001, negativity: 0.7 } })]);
    // Panel base + themed overlay.
    expectStyle(root, { padding: 12, gap: 8, marginTop: 2 });
    expectStyle(root, { backgroundColor: "#232019", borderRadius: 10 });
    // Row key/value pairs.
    expectStyle(root, { fontSize: 12, width: 128, flexShrink: 0 });
    expectStyle(root, { color: "#a29a8c" });
    expectStyle(root, { fontSize: 12, flex: 1, lineHeight: 16 });
    expectStyle(root, { color: "#cfc7ba" });
    // Toggle text, tech text, footnotes.
    expectStyle(root, { fontSize: 13, fontWeight: "600" });
    expectStyle(root, { color: "#b6a9e3" });
    expectStyle(root, { fontSize: 12, fontWeight: "600" });
    expectStyle(root, { fontSize: 11, marginTop: 2, lineHeight: 15 });
    // Card header row and the toggle hit area.
    expectStyle(root, { flexDirection: "row", justifyContent: "space-between", alignItems: "center" });
    expectStyle(root, { paddingVertical: 6 });
  });

  it("panel row/footnote texts carry their themed color overlays directly", async () => {
    const root = await renderExpanded([
      pattern({ kind: "mood_correlation", detail: { sample_days: 63, mood_delta: -0.4, p_value: 0.001 } }),
    ]);
    await pressLabel(root, "Technical details");
    await flush();
    // The style ARRAY of each specific text node, so the themed overlay
    // object is pinned to its node (a {} or [] mutant drops the color).
    // Text children can be string fragments in arrays — flatten first.
    const flat = (children: unknown): string => {
      if (typeof children === "string") return children;
      if (Array.isArray(children)) return children.map(flat).join("");
      return "";
    };
    const styleOfText = (fragment: string): unknown[] => {
      const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
      if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}: ${allText(root).join(" | ")}`);
      const style = (node.props as { style: unknown }).style;
      return Array.isArray(style) ? style : [style];
    };
    expect(styleOfText("Evidence window")).toContainEqual({ color: "#a29a8c" });
    expect(styleOfText("Based on")).toContainEqual({ color: "#a29a8c" });
    expect(styleOfText("63 journal entries")).toContainEqual({ color: "#cfc7ba" });
    expect(styleOfText("Hide technical details")).toContainEqual({ color: "#a29a8c" });
    expect(styleOfText("Significance")).toContainEqual({ color: "#a29a8c" });
    expect(styleOfText("p = 1.0e-3")).toContainEqual({ color: "#cfc7ba" });
    expect(styleOfText("Patterns like this can occasionally appear by chance")).toContainEqual({ color: "#a29a8c" });
    expect(styleOfText("An observation about your own data")).toContainEqual({ color: "#a29a8c" });
  });

  it("the lifecycle chip's strong style pairs with its own state text", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ detail: { pattern_state: "confirmed" } }),
      pattern({ label: "sleep", detail: { pattern_state: "emerging" } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const chipStyle = (state: string): unknown => {
      const flat = (children: unknown): string => {
        if (typeof children === "string") return children;
        if (Array.isArray(children)) return children.map(flat).join("");
        return "";
      };
      const node = root.root.findAllByType(Text).find((n) => flat(n.props.children) === state);
      if (!node) throw new Error(`no chip ${state}`);
      return (node.props as { style: unknown }).style;
    };
    expect(chipStyle("seen consistently")).toEqual({ color: "#93c7a6", fontSize: 11, fontWeight: "700" });
    expect(chipStyle("early evidence")).toEqual({ color: "#a29a8c", fontSize: 11, fontWeight: "600" });
  });

  it("both expanders expose their exact accessibility labels and state", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ detail: { sample_days: 63, p_value: 0.001 } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const why = touchableByLabel(root, "Why am I seeing this?");
    expect(why.props.accessibilityLabel).toBe("Why am I seeing this? Evidence for this pattern");
    expect(why.props.accessibilityState).toEqual({ expanded: false });
    await pressLabel(root, "Why am I seeing this?");
    await flush();
    expect(touchableByLabel(root, "Hide the evidence").props.accessibilityLabel).toBe("Hide the evidence");

    const tech = root.root
      .findAllByType(TouchableOpacity)
      .find((n) => (n.props as { accessibilityLabel?: string }).accessibilityLabel === "Technical details — the raw statistics");
    expect(tech).toBeDefined();
    expect(tech?.props.accessibilityState).toEqual({ expanded: false });

    await pressLabel(root, "Technical details");
    await flush();
    const techOpen = root.root
      .findAllByType(TouchableOpacity)
      .find((n) => (n.props as { accessibilityLabel?: string }).accessibilityLabel === "Hide technical details");
    expect(techOpen?.props.accessibilityState).toEqual({ expanded: true });
  });
});

describe("InsightsScreen pins: navigation-less operation", () => {
  it("a sensitive card's support button and the help button work without a navigation prop", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "rumination", label: "hidden", detail: { sensitive: true } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    await pressLabel(root, "Support resources");
    await pressLabel(root, "Need help now? Crisis resources");
    // The support button stays left-aligned (center={false}).
    const support = touchableByLabel(root, "Support resources");
    const style = (support.props as { style: unknown[] }).style;
    expect(style[1]).toBeFalsy(); // no `centered` entry
  });
});
describe("authenticated pattern descriptions across all shipped channels", () => {
  const cases: Array<[string, string, Record<string, unknown>, string]> = [
    ["energy_inertia", "ENERGY CARRYOVER", {}, "Your energy has been carrying over from day to day more than usual for you."],
    ["pa_inertia", "POSITIVE CARRYOVER", {}, "Your positive feelings have been carrying over from day to day more than usual for you."],
    ["na_inertia", "NEGATIVE CARRYOVER", {}, "Your negative feelings have been carrying over from day to day more than usual for you."],
    ["energy_mood_coupling", "ENERGY AND MOOD", {}, "Your energy and your mood have been moving together more closely than usual for you."],
    ["sense_making", "SENSE-MAKING", {}, "Your writing has leaned more on sense-making words — like 'because' and 'realize' — than it used to."],
    ["avoidance", "SILENCE AFTER", { share: 0.34, silences: 7, observed: 20, base_rate: 0.25 }, "The day after 'work' comes up, you tend not to write (34% of such days)."],
    ["cadence", "RHYTHM", { gap_spread_recent: 3.7, gap_spread_earlier: 1.2 }, "Your writing rhythm has been less regular than it used to be for you — longer stretches of silence between writing days."],
    ["link", "DAY-AFTER LINK", { direction: "lower" }, "The day after 'work' comes up, your entries read lower than usual for you."],
    ["link", "DAY-AFTER LINK", { direction: "higher", channel: "sleep_quality" }, "The day after a night you rated as rougher than your own usual, your entries read higher than usual for you."],
    ["link", "DAY-AFTER LINK", { direction: "lower", source: "tag" }, "The day after you tag 'work', your entries read lower than usual for you."],
    ["temporal", "TIMING", { day: "Tuesday", channel: "sleep_quality" }, "Your rougher nights (by your own ratings) fall most often on Tuesdays."],
    ["temporal", "TIMING", { channel: "sleep_quality" }, "Your rougher nights (by your own ratings) fall most often on certain days."],
    ["temporal", "TIMING", { day: "Thursday", source: "tag" }, "You tag 'work' most often on Thursdays."],
    ["temporal", "TIMING", { source: "tag" }, "You tag 'work' most often on certain days."],
    ["topic", "THEME", { share: 0.37, trend: "rising" }, "'work' has been taking up more space in your writing lately (37% of entries)."],
    ["topic", "THEME", { share: 0.42 }, "'work' is a steady presence in your writing (42% of entries)."],
    ["mood_shift", "MOOD TREND", { shift: 0.4 }, "Your entries have read higher than your usual baseline lately (a shift of 0.4)."],
    ["mood_shift", "MOOD TREND", { shift: -0.5, direction: "higher" }, "Your entries have read higher than your usual baseline lately (a shift of 0.5)."],
    ["authenticated-unknown", "PATTERN", {}, "'work' appeared 7 times."],
  ];
  it.each(cases)("renders the public %s/%s/%j card copy", async (kind, badge, detail, description) => {
    const root = await renderExpanded([pattern({ kind, detail })]);
    expect(allText(root)).toContain(badge); expect(allText(root)).toContain(description);
    if (kind === "avoidance") expect(textOf(root)).toContain("your usual silent-day rate is 25%");
    if (kind === "cadence") expect(textOf(root)).toContain("3.7");
    await act(async () => root.unmount());
  });
});

describe("evidence copy for every authenticated diary channel",()=>{
 it.each([
 ["energy_inertia","energy","your energy has been carrying over more strongly than it used to for you"],
 ["pa_inertia","positive_affect","your positive feelings have been carrying over more strongly than it used to for you"],
 ["na_inertia","negative_affect","your negative feelings have been carrying over more strongly than it used to for you"],
 ])("keeps the %s channel in its plain-language evidence",async(kind,channel,expected)=>{const root=await renderExpanded([pattern({kind,detail:{channel,carryover_recent:.7,carryover_earlier:.2}})]);expect(textOf(root)).toContain(expected);await act(async()=>root.unmount());});
 it("renders the actual sense-making rates and keeps absent past rates unavailable",async()=>{const root=await renderExpanded([pattern({kind:"sense_making",detail:{density_recent:2.7,density_earlier:1.3}})]);expect(textOf(root)).toContain("2.7 per 100 words lately, versus your earlier 1.3");});
 it("renders both widened and narrowed activity varieties without manufacturing a direction",async()=>{for(const direction of["widened","narrowed"]){const root=await renderExpanded([pattern({kind:"activity_diversity",detail:{entropy_recent:2.7,entropy_earlier:1.3,direction}})]);expect(textOf(root)).toContain("has "+direction+" compared");await act(async()=>root.unmount());}});
});
describe("complete sample and coupling evidence",()=>{
 it("renders entry counts independently beside the number of sample days",async()=>{const root=await renderExpanded([pattern({detail:{sample_days:8,sample_entries:23}})]);expect(textOf(root)).toContain("8 entries in your analysis window");expect(textOf(root)).toContain("23 journal entries");});
 it("renders actual coupling evidence and the protected technical numbers",async()=>{const root=await renderExpanded([pattern({kind:"energy_mood_coupling",detail:{coupling_recent:.72,coupling_earlier:.31}})]);expect(textOf(root)).toContain("your energy and your mood have been moving more in step than they used to");await pressLabel(root,"Technical details");expect(textOf(root)).toContain("0.72 vs 0.31");});
 it("explicit lower directions remain lower even when the cached signed measurement is positive",async()=>{for(const kind of["mood_correlation","mood_shift"]){const root=await renderExpanded([pattern({kind,detail:kind==="mood_correlation"?{mood_delta:.4,direction:"lower"}:{shift:.4,direction:"lower"}})]);expect(textOf(root)).toContain("read lower");expect(textOf(root)).not.toContain("read higher");await act(async()=>root.unmount());}});
});
