/**
 * InsightsScreen: phase-gated rendering, on-device decryption of the
 * patterns blob, per-kind copy, pull-to-refresh, and error surfacing.
 * Uses the REAL envelope crypto (AES-GCM against a local data key).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { ScrollView, ActivityIndicator } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock() };
});

const refreshActiveDays = vi.fn(async () => {});
// L-59: the screen adopts the already-fetched count instead of re-fetching.
const applyActiveDays = vi.fn();
const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ refreshActiveDays, applyActiveDays, unlockDays: 30, touchActivity }) };
});

const { api } = await import("../../src/api/client");
const { InsightsScreen } = await import("../../src/screens/InsightsScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { INSIGHTS_PAYLOAD_VERSION } = await import("../../src/crypto/MindPatternCrypto");
const { render, flush, textOf, allText, act } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");

const dataKey = Buffer.alloc(32, 9);
const insightsBlob = (payload: unknown): string =>
  encrypt(
    dataKey,
    Buffer.from(JSON.stringify({ v: INSIGHTS_PAYLOAD_VERSION, ...(payload as Record<string, unknown>) })),
    buildAad("insights", "user-1", "patterns"),
  ).toString("base64");

const pattern = (over: Record<string, unknown>) => ({
  kind: "temporal",
  label: "work",
  occurrences: 7,
  confidence: 0.62,
  detail: { day: "Sunday", day_fraction: 0.57 },
  ...over,
});

beforeEach(() => {
  resetApi(api as never);
  refreshActiveDays.mockClear();
  applyActiveDays.mockClear();
  touchActivity.mockClear();
  AlertlessReset();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey });
});

function AlertlessReset(): void {
  // no-op placeholder to keep beforeEach symmetric
}

describe("InsightsScreen phases", () => {
  it("shows the loading spinner only while the first load is in flight", async () => {
    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(
      () => new Promise((resolve) => (resolveInsights = resolve)),
    );
    const root = await render(<InsightsScreen />);
    // First paint (before any load): the phase spinner shows because the
    // phase is "loading", but the refresh control is NOT yet spinning.
    expect(root.root.findAllByType(ActivityIndicator).length).toBeGreaterThan(0);

    await act(async () => {
      resolveInsights?.({ phase: "baseline", active_days: 3, days_remaining: 27 });
    });
    await flush();
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(0);
    const scroll1 = root.root.findByType(ScrollView);
    expect((scroll1.props.refreshControl.props as { refreshing: boolean }).refreshing).toBe(false);
  });

  it("pins the visual language of the screen (patterns + error states)", async () => {
    // Design-system pass: fine print moved off the failing #5c6370 (3.13:1)
    // onto the theme's muted #8a91a3 (≥4.5:1 on every surface).
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "work" })] } }),
    } as never);
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen />);
    await flush();
    expectStyle(root, { flex: 1 }); // container base
    expectStyle(root, { backgroundColor: "#0f1115" }); // themed container
    expectStyle(root, { backgroundColor: "#1a1e26", borderRadius: 12, padding: 16, gap: 6 }); // card
    expectStyle(root, { color: "#b6bdc9", fontSize: 15, lineHeight: 21 }); // cardBody
    expectStyle(root, { color: "#7f9bff", fontSize: 11, fontWeight: "700", letterSpacing: 1 }); // kind
    expectStyle(root, { color: "#8a91a3", fontSize: 12 }); // meta (contrast fix)
    expectStyle(root, { fontSize: 12, textAlign: "center", marginTop: 8 }); // footnote base
    expectStyle(root, { color: "#8a91a3" }); // footnote themed color (contrast fix)

    // Empty state renders the card title style.
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [] } }),
    } as never);
    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      await onRefresh();
    });
    expectStyle(root, { color: "#e8eaf0", fontSize: 17, fontWeight: "700" }); // cardTitle

    // Error state on a failed refresh after a successful load.
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const scroll2 = root.root.findByType(ScrollView);
    const onRefresh2 = (scroll2.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      await onRefresh2();
    });
    expect(textOf(root)).toContain("offline");
    expectStyle(root, { color: "#ff6b6b", fontSize: 13 }); // error
    // Errors now carry a Retry affordance, not just pull-to-refresh.
    expect(textOf(root)).toContain("Try again");
  });

  it("clears previously rendered patterns when a refresh has no blob", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "work" })] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("You've mentioned 'work'");

    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
    } as never);
    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      await onRefresh();
    });
    expect(textOf(root)).not.toContain("You've mentioned 'work'");
    expect(textOf(root)).toContain("Nothing solid yet");
  });

  it("baseline: encourages writing with the exact countdown", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "baseline",
      active_days: 12,
      days_remaining: 18,
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Keep writing");
    expect(text).toContain("Keep writing — 18 days to your patterns");
    expect(text).toContain("any \"insight\" would");
    // Baseline shows neither the empty-insight state nor the insight footnote.
    expect(text).not.toContain("Nothing solid yet");
    expect(text).not.toContain("not advice or diagnosis");
    // L-59 pin: ONE /insights request per load — the counter applies from
    // the response this screen already holds, not a second fetch.
    expect(vi.mocked(api.insights)).toHaveBeenCalledTimes(1);
    expect(refreshActiveDays).not.toHaveBeenCalled();
    expect(applyActiveDays).toHaveBeenCalledWith(12);
    // Layout container contract.
    const scroll = root.root.findByType(ScrollView);
    expect(scroll.props.contentContainerStyle).toEqual({ padding: 20, gap: 14 });
    expect(scroll.props.style).toEqual([{ flex: 1 }, { backgroundColor: "#0f1115" }]);
  });

  it("renders no pattern cards on the very first paint", async () => {
    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(
      () => new Promise((resolve) => (resolveInsights = resolve)),
    );
    const root = await render(<InsightsScreen />);
    expect(allText(root).join(" ")).not.toMatch(/TIMING|MOOD LINK|REPEATED PHRASE|PATTERN\b/);
    await act(async () => {
      resolveInsights?.({ phase: "baseline", active_days: 1, days_remaining: 29 });
    });
    await flush();
  });

  it("clears a previous error when a new load starts", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("offline");

    let resolveRefresh!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(
      () => new Promise((resolve) => (resolveRefresh = resolve)),
    );
    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      void Promise.resolve(onRefresh());
    });
    expect(textOf(root)).not.toContain("offline");
    await act(async () => {
      resolveRefresh?.({ phase: "baseline", active_days: 1, days_remaining: 29 });
    });
    await flush();
  });

  it("insight phase with no evidence yet: honest empty state", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Nothing solid yet");
    expect(textOf(root)).toContain("not advice or diagnosis");
  });

  it("decrypts the blob and renders each pattern kind with its copy", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 40,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({ kind: "temporal", label: "work", occurrences: 7, detail: { day: "Sunday" } }),
            pattern({ kind: "temporal", label: "sleep", occurrences: 4, detail: {} }),
            pattern({ kind: "mood_correlation", label: "money", occurrences: 5, detail: { mood_delta: -0.42 } }),
            pattern({ kind: "mood_correlation", label: "family", occurrences: 4, detail: {} }),
            pattern({ kind: "recurring_phrase", label: "can't sleep", occurrences: 3 }),
            pattern({ kind: "mystery_kind", label: "unknown", occurrences: 2, confidence: 0.1 }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();

    const text = textOf(root);
    expect(text).toContain("You've mentioned 'work' 7 times, most often on Sundays.");
    expect(text).toContain("most often on the same days.");
    expect(text).toContain("read higher on days when 'money' comes up (mood shift of 0.4)");
    expect(text).toContain("read lower on days when 'family' comes up (mood shift of 0.0)");
    expect(text).toContain('The phrase "can\'t sleep" keeps returning — 3 times so far.');
    expect(text).toContain("'unknown' appeared 2 times.");
    // "strength N%" was renamed to plain "evidence density N%".
    expect(text).toContain("7 mentions · evidence density 62%");
    expect(text).toContain("2 mentions · evidence density 10%");

    // Kind labels pair with THEIR pattern card (card order: kind label,
    // evidence-state chip, then the describe text).
    const texts = allText(root);
    const byKind = (label: string): string => {
      const index = texts.indexOf(label);
      expect(index).toBeGreaterThanOrEqual(0);
      return texts[index + 2];
    };
    expect(byKind("TIMING")).toContain("You've mentioned 'work'");
    expect(byKind("MOOD LINK")).toContain("read higher on days when 'money'");
    expect(byKind("REPEATED PHRASE")).toContain('The phrase "can\'t sleep"');
    expect(byKind("PATTERN")).toContain("'unknown' appeared");
    // No baseline copy leaks into the insight phase.
    expect(text).not.toContain("Keep writing");
    expect(text).not.toContain("Nothing solid yet");
  });

  it("tolerates patterns without any detail object at all", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            { kind: "temporal", label: "work", occurrences: 4, confidence: 0.5, detail: undefined },
            { kind: "mood_correlation", label: "sleep", occurrences: 4, confidence: 0.5, detail: undefined },
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("most often on the same days.");
    expect(text).toContain("read lower on days when 'sleep' comes up (mood shift of 0.0)");
  });

  it("renders the v2 mood-trend kind and lifecycle badges", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 45,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({
              kind: "mood_shift",
              label: "recent mood",
              occurrences: 4,
              detail: { direction: "lower", shift: -0.6, baseline: 0.3, current: -0.3 },
            }),
            pattern({
              kind: "temporal",
              label: "work",
              occurrences: 9,
              detail: { day: "Sunday", pattern_state: "fading", is_new: false },
            }),
            pattern({
              kind: "recurring_phrase",
              label: "so tired",
              occurrences: 3,
              detail: { pattern_state: "emerging", is_new: true },
            }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();

    const text = textOf(root);
    expect(text).toContain("read lower than your usual baseline lately (a shift of 0.6)");
    expect(text).toContain("MOOD TREND");
    // Lifecycle metadata renders as evidence chips + the evidence-density meta line.
    expect(text).toContain("fading");
    expect(text).toContain("9 mentions · evidence density 62%");
    expect(text).toContain("early evidence · new");
    expect(text).toContain("3 mentions · evidence density 62%");
  });

  it("insight phase without a blob clears the pattern list", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Nothing solid yet");
  });

  it("shows a calm mapped message with a Retry button when loading fails", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("offline");
    // Retry affordance: re-runs the load.
    const { pressLabel } = await import("../helpers/rtr");
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 1, days_remaining: 29 } as never);
    await pressLabel(root, "Try again");
    await flush();
    expect(textOf(root)).not.toContain("offline");
    expect(textOf(root)).toContain("Keep writing");
  });

  // M2: a 401 from the insights fetch is surfaced honestly (the vault lock
  // itself is the client hook's job — covered in client.request/store tests)
  // and interaction on this screen restarts the inactivity countdown.
  it("surfaces a 401 from the insights fetch as calm copy, not raw server text", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.insights).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Session expired — please unlock again.");
    expect(textOf(root)).not.toContain("invalid token");
  });

  it("any touch on the screen resets the inactivity countdown", async () => {
    const root = await render(<InsightsScreen />);
    await flush();
    const scroll = root.root.findByType(ScrollView);
    await act(async () => {
      (scroll.props as { onTouchStart?: () => void }).onTouchStart?.();
    });
    expect(touchActivity).toHaveBeenCalledTimes(1);
  });

  it("renders the decrypted-patterns error path (tampered blob)", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: "AAAA", // too short — TamperError before any decryption
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("blob failed authentication");
  });

  it("pull-to-refresh reloads through the refresh control", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "baseline",
      active_days: 1,
      days_remaining: 29,
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();

    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      await onRefresh();
    });
    expect(api.insights).toHaveBeenCalledTimes(2);
  });

  it("falls back to the empty user id for AAD when none is stored", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    // Blob is bound to "" as userId then — build it that way.
    const blobForEmptyUser = encrypt(
      dataKey,
      Buffer.from(JSON.stringify({ v: INSIGHTS_PAYLOAD_VERSION, stats: { patterns: [pattern({ label: "work" })] } })),
      buildAad("insights", "", "patterns"),
    ).toString("base64");
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: blobForEmptyUser,
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("You've mentioned 'work'");
  });

  it("renders every delivered pattern as a card", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "a" }), pattern({ label: "b" })] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(allText(root).filter((t) => t.includes("TIMING"))).toHaveLength(2);
  });

  it("treats a stats object without a patterns list as empty", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: {} }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Nothing solid yet");
    expect(textOf(root)).not.toContain("appeared");
    // A missing stats key is a SUPPORTED shape, not an error.
    const joined = allText(root).join(" ");
    expect(joined).not.toMatch(/Cannot|error|failed/i);
  });

  it("tolerates payloads without a stats block", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({}),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Nothing solid yet");
    // The missing key is handled by the optional chain, not by the catch.
    expect(text).not.toContain("Cannot read properties");
    expect(text).not.toContain("failed to load");
  });

  it("falls back to a calm sentence for non-Error failures", async () => {
    vi.mocked(api.insights).mockRejectedValue("nope" as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Something went wrong — try again.");
  });

  it("hides the empty state while a refresh is in flight", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Nothing solid yet");

    let resolveRefresh!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(() => new Promise((resolve) => (resolveRefresh = resolve)));
    const { act } = await import("../helpers/rtr");
    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      void Promise.resolve(onRefresh());
    });
    expect(textOf(root)).not.toContain("Nothing solid yet"); // busy → hidden
    await act(async () => {
      resolveRefresh?.({ phase: "baseline", active_days: 1, days_remaining: 29 });
    });
    await flush();
  });
});

describe("InsightsScreen evidence view", () => {
  it("expands a card into its evidence panel with stats and method note", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 45,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({
              kind: "temporal",
              label: "work",
              occurrences: 9,
              detail: {
                day: "Sunday",
                day_fraction: 0.78,
                base_rate: 0.19,
                p_value: 0.000004,
                first_seen: "2026-07-12",
                last_seen: "2026-09-01",
                sample_days: 63,
                pattern_state: "emerging",
              },
            }),
          ],
        },
      }),
    } as never);
    const { pressLabel } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen />);
    await flush();

    // Collapsed by default: the stats live behind the toggle.
    expect(textOf(root)).not.toContain("Evidence window");
    await pressLabel(root, "Why am I seeing this?");
    await flush();

    const text = textOf(root);
    expect(text).toContain("Evidence window");
    expect(text).toContain("2026-07-12 → 2026-09-01");
    expect(text).toContain("63 entries in your analysis window");
    // Plain-language stat rows (evidence-panel rewrite).
    expect(text).toContain("78% of these mentions fell on Sundays — your baseline for Sundays is 19%");
    expect(text).toContain("your own writing schedule");
    expect(text).toContain("occasionally appear by chance");
    expect(text).toContain("not a diagnosis or advice");
    // Confidence framing: the lifecycle state reads as an evidence label.
    expect(text).toContain("early evidence");
  });

  it("labels the v3 kinds (link, rumination, dynamics) with their chips", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 60,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({ kind: "link", label: "sleep", occurrences: 11, detail: { direction: "lower", lag_days: 1 } }),
            pattern({ kind: "rumination", label: "can't sleep", occurrences: 9, detail: {} }),
            pattern({ kind: "inertia", label: "day-to-day mood", occurrences: 24, detail: {} }),
            pattern({ kind: "instability", label: "daily mood", occurrences: 21, detail: {} }),
            pattern({
              kind: "topic", label: "guitar", occurrences: 13,
              detail: { trend: "rising", share: 0.19, share_earlier: 0.06, share_recent: 0.31, entries: 13 },
            }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("DAY-AFTER LINK");
    expect(text).toContain("The day after 'sleep' comes up, your entries read lower than usual for you.");
    expect(text).toContain("REPEATED WORRY");
    expect(text).toContain("keeps returning across different days");
    expect(text).toContain("CARRYOVER");
    expect(text).toContain("carrying over from day to day more than usual");
    expect(text).toContain("SWINGS");
    expect(text).toContain("swung more widely than usual for you");
    // Emergent topic: discovered from the user's own words, not any fixed list.
    expect(text).toContain("THEME");
    expect(text).toContain("'guitar' has been taking up more space in your writing lately (19% of entries).");
  });

  it("baseline: shows the writing streak and the on-device mood sparkline", async () => {
    // The baseline-phase value is DEVICE-LOCAL: the streak and trend come
    // from the encrypted mood log, not the server.
    const { recordMood, localDateISO } = await import("../../src/moodLog");
    const dayAt = (back: number) => localDateISO(new Date(Date.now() - back * 86_400_000));
    await recordMood(dataKey, "user-1", dayAt(2), 0.4);
    await recordMood(dataKey, "user-1", dayAt(1), -0.6);
    await recordMood(dataKey, "user-1", dayAt(0), 0.2);

    vi.mocked(api.insights).mockResolvedValue({
      phase: "baseline",
      active_days: 12,
      days_remaining: 18,
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Keep writing — 18 days to your patterns");
    expect(text).toContain("Writing streak: 3 days");
    expect(text).toContain("Your mood, this month (stays on this device):");
    // The sparkline renders an up bar (positive day) and a down bar, with a
    // textual summary for screen readers (the bars are invisible to them).
    const styles = (await import("../helpers/rtr")).allStyles(root);
    expect(styles.some((s) => s.backgroundColor === "#59c98a")).toBe(true); // up bar
    expect(styles.some((s) => s.backgroundColor === "#e06c75")).toBe(true); // down bar
    const summary = root.root.findAll(
      (n) => n.props.accessibilityRole === "image" && typeof n.props.accessibilityLabel === "string",
    );
    expect(summary).toHaveLength(1);
    expect(summary[0].props.accessibilityLabel).toMatch(/^Mood trend: (rising|falling|steady) over 3 days, latest (positive|negative|neutral)$/);
  });

  it("the evidence panel renders plain-language rows, with raw stats behind Technical details", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 60,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({
              kind: "mood_correlation",
              label: "deadline",
              occurrences: 8,
              detail: {
                first_seen: "2026-07-01",
                last_seen: "2026-09-01",
                sample_days: 60,
                mood_delta: -0.4,
                direction: "lower",
                cohens_d: 0.8,
                lag_days: 1,
                n_after: 5,
                n_other: 40,
                carryover_recent: 0.5,
                carryover_earlier: 0.2,
                spread_recent: 0.9,
                spread_earlier: 0.4,
                share: 0.2,
                entries: 12,
                share_earlier: 0.1,
                share_recent: 0.3,
                trend: "rising",
                p_value: 0.001,
                span_days: 45,
                distinct_days: 12,
                negativity: 0.7,
                absolutist_per_100: 3.2,
                shift: -0.2,
                baseline: 0.1,
                pattern_state: "confirmed",
              },
            }),
          ],
        },
      }),
    } as never);
    const { pressLabel } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain(
      "Your entries read lower on days when 'deadline' comes up (mood shift of 0.4).",
    );

    await pressLabel(root, "Why am I seeing this?");
    await flush();
    let text = textOf(root);
    // Plain language: one sentence per stat, no jargon.
    expect(text).toContain("Mood difference");
    expect(text).toContain("entries read lower by 0.40 than your own norm");
    expect(text).toContain("Size of the difference");
    expect(text).toContain("a large difference"); // |d| = 0.8, in words
    expect(text).toContain("Carryover");
    expect(text).toContain("carrying over more strongly than it used to");
    expect(text).toContain("Swings");
    expect(text).toContain("wider range than it used to");
    expect(text).toContain("Tone");
    expect(text).toContain("the thought reads negative");
    expect(text).toContain("Returning for");
    expect(text).toContain("seen on 12 distinct days across 45 days");
    expect(text).toContain("Day-after");
    expect(text).toContain("~1 day later — seen on 5 such days vs 40 others");
    expect(text).toContain("Share of entries");
    expect(text).toContain("20% (12 entries, 8 mentions)");
    expect(text).toContain("Earlier → recent");
    expect(text).toContain("10% → 30%");
    expect(text).toContain("Shift");
    expect(text).toContain("−0.20 against your baseline of 0.10");
    // The lifecycle badge reads softly as a consistent finding.
    expect(text).toContain("seen consistently");
    // Raw stats are GATED: none visible before the second expander. (This
    // also pins the duplicate-Significance-row fix: one row, one place.)
    expect(text).not.toContain("Significance");
    expect(text).not.toContain("Cohen's d");

    await pressLabel(root, "Technical details");
    await flush();
    text = textOf(root);
    expect(text).toContain("Significance");
    expect(text).toContain("p = 1.0e-3 (corrected for running many tests)");
    expect(text).toContain("Cohen's d");
    expect(text).toContain("0.80");
    expect(text).toContain("Negativity score");
    expect(text).toContain("0.70");
    expect(text).toContain("Absolutist-word density");
    expect(text).toContain("3.2 per 100 words");
    expect(text).toContain("Carryover, recent vs earlier");
    expect(text).toContain("0.50 vs 0.20");
    expect(text).toContain("Spread, recent vs earlier");
    expect(text).toContain("0.90 vs 0.40");
    // Exactly one Significance row (the old panel pushed it twice for
    // rising topics — duplicate React keys).
    expect(allText(root).filter((t2) => t2 === "Significance")).toHaveLength(1);

    // Collapsing: the technical toggle, then the whole panel.
    await pressLabel(root, "Hide technical details");
    await flush();
    expect(textOf(root)).not.toContain("Cohen's d");
    await pressLabel(root, "Hide the evidence");
    await flush();
    expect(textOf(root)).not.toContain("Evidence window");
  });

  it("renders direction fallbacks, missing-field defaults and bare cards", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 60,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({ kind: "mood_shift", label: "overall mood", occurrences: 30, detail: { direction: "higher", shift: 0.3, baseline: 0.2 } }),
            pattern({ kind: "mood_shift", label: "baseline drift", occurrences: 12, detail: { direction: "lower" } }),
            pattern({ kind: "link", label: "caffeine", occurrences: 6, detail: { direction: "higher", lag_days: 1 } }),
            // A bare card: no occurrences, no confidence, no detail — every
            // sanitizer and evidence-row fallback engages.
            { kind: "inertia", label: "day-to-day mood" },
            pattern({ kind: "temporal", label: "work", occurrences: 9, detail: { day: "Sunday", day_fraction: 0.5 } }),
            pattern({ kind: "mood_correlation", label: "rain", occurrences: 4, detail: { mood_delta: 0.3, direction: "higher", share: 0.2, span_days: 30 } }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("MOOD TREND");
    expect(text).toContain("Your entries have read higher than your usual baseline lately (a shift of 0.3).");
    expect(text).toContain("Your entries have read lower than your usual baseline lately (a shift of 0.0).");
    expect(text).toContain("The day after 'caffeine' comes up, your entries read higher than usual for you.");
    expect(text).toContain("0 mentions · evidence density 0%");

    const { TouchableOpacity } = await import("react-native");
    const expand = async (i: number) => {
      const toggle = root.root.findAllByType(TouchableOpacity)[i];
      await act(async () => {
        (toggle.props as { onPress: () => void }).onPress();
      });
      await flush();
    };
    // One "Why am I seeing this?" + one mute affordance per card, plus the
    // persistent crisis-help button rendered after the cards.
    expect(root.root.findAllByType(TouchableOpacity)).toHaveLength(13);
    // The mute affordance is present on every ordinary card (2026-09-19).
    expect(text).toContain("Not about me anymore — mute");

    // The mood_shift card trending up renders the "+" direction.
    await expand(0);
    expect(textOf(root)).toContain("+0.30 against your baseline of 0.20");

    // The link card without sample counts shows "?" placeholders.
    await expand(4);
    expect(textOf(root)).toContain("~1 day later — seen on ? such days vs ? others");

    // Expanding the bare card shows the "?" fallbacks for missing fields.
    await expand(6);
    expect(textOf(root)).toContain("Evidence window");
    expect(textOf(root)).toContain("? → ?");

    // The temporal card without a base_rate reports a 0% baseline.
    await expand(8);
    expect(textOf(root)).toContain("50% of these mentions fell on Sundays — your baseline for Sundays is 0%");

    // The rain card: mood difference in the "higher" direction, and the
    // share/span rows without their optional counts.
    await expand(10);
    const rainText = textOf(root);
    expect(rainText).toContain("entries read higher by 0.30 than your own norm");
    expect(rainText).toContain("20% (? entries, 4 mentions)");
    expect(rainText).toContain("seen on ? distinct days across 30 days");
  });

  it("baseline singular: one remaining day and a one-day streak read naturally", async () => {
    const { recordMood, clearMoodLog, localDateISO } = await import("../../src/moodLog");
    await clearMoodLog("user-1"); // earlier tests in this file seeded the log
    await recordMood(dataKey, "user-1", localDateISO(), 0.4);
    vi.mocked(api.insights).mockResolvedValue({
      phase: "baseline",
      active_days: 29,
      days_remaining: 1,
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Keep writing — 1 day to your patterns");
    expect(text).toContain("Writing streak: 1 day");
    // One mood day is not a trend: no sparkline yet.
    expect(text).not.toContain("Your mood, this month");
  });
});

describe("M9: server-controlled values are sanitized before render", () => {
  it("renders a malformed days_remaining as 0 instead of trusting it", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "baseline",
      active_days: 3,
      days_remaining: "soon",
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Keep writing — 0 days to your patterns");
  });

  it("rejects an unknown phase instead of trusting it", async () => {
    vi.mocked(api.insights).mockImplementation(async () =>
      ({ phase: "super-insight", days_remaining: 0, active_days: 99 }) as never,
    );
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("unknown insights phase");
  });

  it("drops garbage pattern cards and clamps hostile numeric fields", async () => {
    vi.mocked(api.insights).mockImplementation(async () =>
      ({
        phase: "insight",
        days_remaining: 0,
        active_days: 40,
        blob: insightsBlob({
          stats: {
            patterns: [
              null,
              42,
              "junk",
              { kind: 7, label: "bad" },
              { kind: "topic", label: "legit theme", confidence: "high", occurrences: -3 },
            ],
          },
        }),
      }) as never,
    );
    const root = await render(<InsightsScreen />);
    await flush();
    // Only the well-formed card survives; hostile numbers degrade sanely.
    expect(textOf(root)).toContain("legit theme");
    expect(textOf(root)).toContain("evidence density 0%"); // non-numeric confidence -> 0, not NaN
    expect(textOf(root)).toContain("0 mentions"); // negative occurrences -> 0
    expect(textOf(root)).not.toContain("NaN");
    expect(textOf(root)).not.toContain("bad");
  });
});

describe("InsightsScreen sensitive-pattern cards (non-quoting)", () => {
  const insightWith = (patterns: unknown[]) => ({
    phase: "insight",
    active_days: 40,
    days_remaining: 0,
    blob: insightsBlob({ stats: { patterns } }),
  });

  it("a server-flagged sensitive pattern never renders its label, counts or stats", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({
        kind: "rumination",
        label: "the awful thought verbatim",
        occurrences: 9,
        detail: { sensitive: true, negativity: 0.9, pattern_state: "confirmed" },
      }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("A difficult thought has been returning across different days.");
    expect(text).toContain("Talking to a professional is never a wrong move.");
    expect(text).toContain("Support resources");
    // Nothing quoting or quantifying the thought leaks.
    expect(text).not.toContain("the awful thought verbatim");
    expect(text).not.toContain("9 mentions");
    expect(text).not.toContain("REPEATED WORRY");
    expect(text).not.toContain("Why am I seeing this?");
  });

  it("a suppress-tier label renders the non-quoting card even without the server flag", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "rumination", label: "want to disappear forever", occurrences: 4, detail: {} }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("A difficult thought has been returning across different days.");
    expect(text).not.toContain("want to disappear");
  });

  it("a rising 'cutting' topic renders the non-quoting card even without the server flag (client belt)", async () => {
    // The re-audit's probe: a 90-day corpus whose last month read "the urge
    // for cutting was loud" produced a QUOTED "'cutting' has been taking up
    // more space…" topic card. The bare topic word is suppress-tier now, so
    // the on-device belt (matchesCrisisSuppress) catches it even when the
    // server's sensitive flag is absent.
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "topic", label: "cutting", occurrences: 30, detail: { trend: "rising", share: 0.33 } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("A difficult thought has been returning across different days.");
    expect(text).not.toContain("cutting");
    expect(text).not.toContain("taking up more space");
    expect(text).not.toContain("THEME");
  });

  it("the support-resources link on a sensitive card navigates to Crisis", async () => {
    const nav = { navigate: vi.fn() };
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "rumination", label: "hidden", occurrences: 4, detail: { sensitive: true } }),
    ]) as never);
    const { pressLabel } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Support resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("a normal pattern renders unchanged next to a sensitive one", async () => {
    vi.mocked(api.insights).mockResolvedValue(insightWith([
      pattern({ kind: "temporal", label: "work", occurrences: 7, detail: { day: "Sunday" } }),
      pattern({ kind: "rumination", label: "secret thought", occurrences: 3, detail: { sensitive: true } }),
    ]) as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("You've mentioned 'work' 7 times, most often on Sundays.");
    expect(text).toContain("A difficult thought has been returning across different days.");
    expect(text).not.toContain("secret thought");
  });
});

describe("InsightsScreen presence-flagged topics", () => {
  it("a presence topic renders in the lighter secondary style", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 40,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({ kind: "topic", label: "guitar", occurrences: 13, detail: { share: 0.3, presence: true } }),
            pattern({ kind: "topic", label: "work", occurrences: 9, detail: { share: 0.2 } }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    // Both render; the presence one's describe text is muted, not body-colored.
    expect(textOf(root)).toContain("'guitar' is a steady presence in your writing (30% of entries).");
    const texts = root.root.findAllByType((await import("react-native")).Text);
    const guitar = texts.find((n) => String(n.props.children).includes("guitar"));
    const work = texts.find((n) => String(n.props.children).includes("'work' is a steady"));
    // Later style entries win (RN precedence) — take the LAST color.
    const colorOf = (node: unknown) =>
      ((node as { props: { style: unknown } }).props.style as Record<string, unknown>[]).flat().findLast(
        (s) => s && typeof s === "object" && "color" in s,
      )?.color;
    expect(colorOf(guitar)).toBe("#8a91a3"); // muted — down-ranked
    expect(colorOf(work)).toBe("#b6bdc9"); // body
  });
});

describe("InsightsScreen path to help + accessibility", () => {
  it("shows a persistent crisis-resources link (the audit's missing path)", async () => {
    const nav = { navigate: vi.fn() };
    const root = await render(<InsightsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Need help now? Crisis resources");
    const { pressLabel } = await import("../helpers/rtr");
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("the evidence expander reports its expanded state", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "work" })] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const { touchableByLabel, pressLabel } = await import("../helpers/rtr");
    const toggle = touchableByLabel(root, "Why am I seeing this?");
    expect(toggle.props.accessibilityState).toEqual({ expanded: false });
    await pressLabel(root, "Why am I seeing this?");
    await flush();
    expect(touchableByLabel(root, "Hide the evidence").props.accessibilityState).toEqual({ expanded: true });
  });

  it("cards without raw statistics do not offer a Technical details expander", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "work" })] } }),
    } as never);
    const { pressLabel } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen />);
    await flush();
    await pressLabel(root, "Why am I seeing this?");
    await flush();
    expect(textOf(root)).toContain("Evidence window");
    expect(textOf(root)).not.toContain("Technical details");
  });

  it("the refresh control carries Android colors too", async () => {
    const root = await render(<InsightsScreen />);
    await flush();
    const scroll = root.root.findByType(ScrollView);
    expect(scroll.props.refreshControl.props.tintColor).toBe("#4f7cff");
    expect(scroll.props.refreshControl.props.colors).toEqual(["#4f7cff"]);
  });
});

describe("narrative render cap (same discipline as the label)", () => {
  const withNarrative = (narrative: string) =>
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({
        stats: { patterns: [pattern({ label: "work", detail: { day: "Sunday", day_fraction: 0.57, narrative } })] },
      }),
    } as never);

  it("a hostile over-long narrative renders only its first 500 characters", async () => {
    withNarrative(`${"n".repeat(600)}`);
    const root = await render(<InsightsScreen />);
    await flush();
    // Exactly the capped run is rendered — never a longer one.
    expect(allText(root)).toContain("n".repeat(500));
    expect(allText(root).some((t) => t.includes("n".repeat(501)))).toBe(false);
  });

  it("a narrative of exactly 500 characters renders whole", async () => {
    withNarrative("m".repeat(500));
    const root = await render(<InsightsScreen />);
    await flush();
    expect(allText(root)).toContain("m".repeat(500));
  });
});

describe("sparklineSummary", () => {
  it("describes rising, falling and steady trends with the latest day", async () => {
    const { sparklineSummary } = await import("../../src/screens/InsightsScreen");
    const day = (value: number): { date: string; value: number } => ({ date: "2026-09-01", value });
    expect(sparklineSummary([day(-0.6), day(-0.5), day(0.5), day(0.6)])).toBe(
      "Mood trend: rising over 4 days, latest positive",
    );
    expect(sparklineSummary([day(0.6), day(0.5), day(-0.5), day(-0.6)])).toBe(
      "Mood trend: falling over 4 days, latest negative",
    );
    expect(sparklineSummary([day(0.1), day(-0.1), day(0.05)])).toBe(
      "Mood trend: steady over 3 days, latest positive",
    );
    expect(sparklineSummary([day(0), day(0), day(0), day(0)])).toBe(
      "Mood trend: steady over 4 days, latest neutral",
    );
    // Degenerate inputs stay sane (the component guards these, the summary
    // must not crash if reused): one day is a point, not a trend.
    expect(sparklineSummary([day(0.4)])).toBe("Mood trend: steady over 1 day, latest positive");
    expect(sparklineSummary([])).toBe("Mood trend: steady over 0 days, latest neutral");
  });
});

describe("effectSizeWords", () => {
  it("maps |d| bands to plain words (sign-agnostic)", async () => {
    const { effectSizeWords } = await import("../../src/screens/InsightsScreen");
    expect(effectSizeWords(0.1)).toBe("a very small difference");
    expect(effectSizeWords(-0.3)).toBe("a small difference");
    expect(effectSizeWords(0.65)).toBe("a medium-sized difference");
    expect(effectSizeWords(-1.2)).toBe("a large difference");
  });
});

describe("InsightsScreen per-pattern mute (2026-09-19)", () => {
  const seeded = (patterns: unknown[]) => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 45,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns } }),
    } as never);
  };

  it("muting hides the card optimistically and queues the encrypted event", async () => {
    const { pressLabel } = await import("../helpers/rtr");
    const storage = (await import("../helpers/storageMock")).default;
    seeded([
      pattern({ kind: "topic", label: "guitar", detail: { pattern_pid: "topic:guitar" } }),
      pattern({ kind: "temporal", label: "work", detail: { day: "Sunday", day_fraction: 0.57, pattern_pid: "temporal:work" } }),
    ]);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("guitar");
    // The FIRST mute affordance belongs to the first card (guitar).
    await pressLabel(root, "Not about me anymore — mute");
    await flush();
    // Optimistic: the card is gone from the visible list…
    expect(textOf(root)).not.toContain("guitar");
    expect(textOf(root)).toContain("work");
    // …the muted section appeared with the honest caption…
    expect(textOf(root)).toContain("Show muted (1)");
    expect(textOf(root)).toContain("Muted patterns stay out of your questions.");
    expect(textOf(root)).toContain("Muted — hidden here now");
    // …and the encrypted event is queued for the next recompute.
    const raw = await storage.getItem("@mindpattern/question_feedback.user-1");
    expect(raw).toBeTruthy();
  });

  it("unmute restores the card and queues the reverse event", async () => {
    const { pressLabel } = await import("../helpers/rtr");
    const storage = (await import("../helpers/storageMock")).default;
    const envelope = await import("../../src/crypto/envelope");
    seeded([
      pattern({ kind: "topic", label: "guitar", detail: { pattern_pid: "topic:guitar" } }),
    ]);
    const root = await render(<InsightsScreen />);
    await flush();
    await pressLabel(root, "Not about me anymore — mute");
    await flush();
    await pressLabel(root, "Show muted (1)");
    await flush();
    // The collapsed row shows kind and label, with the Unmute action.
    expect(textOf(root)).toContain("THEME · guitar");
    await pressLabel(root, "Unmute");
    await flush();
    expect(textOf(root)).toContain("guitar");
    expect(textOf(root)).not.toContain("Show muted");
    // The queue's last word on this pid is the unmute.
    const raw = await storage.getItem("@mindpattern/question_feedback.user-1");
    expect(raw).toBeTruthy();
    const plain = envelope.decrypt(
      dataKey,
      Buffer.from(raw!, "base64"),
      envelope.buildAad("feedback-local", "user-1"),
    );
    const events = JSON.parse(plain.toString("utf8")) as Array<{ pid: string; mute?: boolean }>;
    const guitarEvents = events.filter((e) => e.pid === "topic:guitar");
    expect(guitarEvents[guitarEvents.length - 1]?.mute).toBe(false);
  });

  it("a server-muted pattern renders only in the muted section (never displaces visible cards)", async () => {
    seeded([
      pattern({ kind: "topic", label: "taxes", detail: { pattern_pid: "topic:taxes", muted: true } }),
      pattern({ kind: "temporal", label: "work", detail: { pattern_pid: "temporal:work" } }),
    ]);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).not.toContain("taxes");
    expect(textOf(root)).toContain("work");
    expect(textOf(root)).toContain("Show muted (1)");
  });

  it("sensitive cards never offer the mute affordance", async () => {
    seeded([
      pattern({ kind: "rumination", label: "cutting myself", detail: { sensitive: true, pattern_pid: "rumination:xyz" } }),
    ]);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("A difficult thought has been returning");
    expect(textOf(root)).not.toContain("Not about me anymore — mute");
    expect(textOf(root)).not.toContain("Show muted");
  });

  it("all patterns muted shows the honest empty state, not a false 'nothing solid'", async () => {
    const { pressLabel } = await import("../helpers/rtr");
    seeded([
      pattern({ kind: "topic", label: "guitar", detail: { pattern_pid: "topic:guitar" } }),
    ]);
    const root = await render(<InsightsScreen />);
    await flush();
    await pressLabel(root, "Not about me anymore — mute");
    await flush();
    expect(textOf(root)).toContain("Every current pattern is muted — unmute one below, or keep writing.");
  });
});

describe("L-58: the main pattern-card list respects the phase gate", () => {
  it("a baseline response that ships a blob anyway renders NO pattern cards", async () => {
    // Server-trust boundary: only the two real phases are accepted, and
    // each section gates on its own phase — the main list was the one
    // section that did not.
    vi.mocked(api.insights).mockResolvedValue({
      phase: "baseline",
      active_days: 3,
      days_remaining: 27,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "work" })] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("Keep writing");
    expect(textOf(root)).not.toContain("You've mentioned 'work'");
    expect(textOf(root)).not.toContain("TIMING");
    // The insight-phase empty state belongs to the insight phase alone.
    expect(textOf(root)).not.toContain("Nothing solid yet");
  });
});

describe("L-61: a server-muted sensitive pattern keeps its support card", () => {
  it("muted + sensitive renders the non-quoting card, quotes nothing, offers no mute", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 45,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({
              kind: "rumination",
              label: "a heavy returning thought",
              occurrences: 9,
              detail: { sensitive: true, muted: true, pattern_pid: "rumination:heavy" },
            }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    // The support pointer stays up…
    expect(text).toContain("A difficult thought has been returning across different days.");
    expect(text).toContain("Talking to a professional is never a wrong move.");
    // …nothing quoting or quantifying the thought leaks…
    expect(text).not.toContain("a heavy returning thought");
    expect(text).not.toContain("9 mentions");
    // …and the muted section does NOT absorb it (sensitive cards never
    // travel there — their support pointer must stay put).
    expect(text).not.toContain("Show muted");
    expect(text).not.toContain("Not about me anymore — mute");
  });

  it("an ALL-muted list with one muted sensitive card is not a false 'nothing solid'", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 45,
      days_remaining: 0,
      blob: insightsBlob({
        stats: {
          patterns: [
            pattern({ kind: "topic", label: "guitar", detail: { pattern_pid: "topic:guitar", muted: true } }),
            pattern({
              kind: "rumination",
              label: "hidden heavy thought",
              detail: { sensitive: true, muted: true, pattern_pid: "rumination:x" },
            }),
          ],
        },
      }),
    } as never);
    const root = await render(<InsightsScreen />);
    await flush();
    const text = textOf(root);
    // The sensitive support card is the one visible card — the empty state
    // (which would claim there is nothing here) must not fire over it.
    expect(text).toContain("A difficult thought has been returning across different days.");
    expect(text).not.toContain("Nothing solid yet");
    expect(text).toContain("Show muted (1)"); // the ordinary mute is listed
  });
});

describe("L-60: overlapping loads are sequenced (older cannot replace newer)", () => {
  it("a stale response landing after a newer one never overwrites its patterns", async () => {
    let resolveOld!: (v: unknown) => void;
    let resolveNew!: (v: unknown) => void;
    vi.mocked(api.insights)
      .mockImplementationOnce(() => new Promise((resolve) => (resolveOld = resolve)))
      .mockImplementationOnce(() => new Promise((resolve) => (resolveNew = resolve)));
    const root = await render(<InsightsScreen />);
    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      void Promise.resolve(onRefresh()); // the newer load starts while the old is in flight
    });
    // The newer load answers FIRST with the current truth…
    await act(async () => {
      resolveNew?.({
        phase: "insight",
        active_days: 45,
        days_remaining: 0,
        blob: insightsBlob({ stats: { patterns: [pattern({ label: "fresh-card" })] } }),
      });
    });
    await flush();
    expect(textOf(root)).toContain("fresh-card");
    // …then the older response finally lands: it must be discarded, not
    // rendered over the newer snapshot.
    await act(async () => {
      resolveOld?.({
        phase: "insight",
        active_days: 31,
        days_remaining: 0,
        blob: insightsBlob({ stats: { patterns: [pattern({ label: "stale-card" })] } }),
      });
    });
    await flush();
    expect(textOf(root)).toContain("fresh-card");
    expect(textOf(root)).not.toContain("stale-card");
    await act(async () => root.unmount());
  });

  it("a superseded load's failure does not poison the screen with a stale error", async () => {
    let rejectOld!: (e: unknown) => void;
    let resolveNew!: (v: unknown) => void;
    vi.mocked(api.insights)
      .mockImplementationOnce(() => new Promise((_resolve, reject) => (rejectOld = reject)))
      .mockImplementationOnce(() => new Promise((resolve) => (resolveNew = resolve)));
    const root = await render(<InsightsScreen />);
    const scroll = root.root.findByType(ScrollView);
    const onRefresh = (scroll.props.refreshControl.props as { onRefresh: () => unknown }).onRefresh;
    await act(async () => {
      void Promise.resolve(onRefresh());
    });
    await act(async () => {
      resolveNew?.({ phase: "baseline", active_days: 1, days_remaining: 29 });
    });
    await flush();
    expect(textOf(root)).toContain("Keep writing");
    // The older request now FAILS — its error belongs to a superseded load.
    await act(async () => {
      rejectOld?.(new Error("stale failure"));
    });
    await flush();
    expect(textOf(root)).toContain("Keep writing");
    expect(textOf(root)).not.toContain("Something went wrong");
    await act(async () => root.unmount());
  });
});

describe("M-36: weekday words localize at render time", () => {
  it("localWeekday maps the backend's English DAY_NAMES onto the locale", async () => {
    const { localWeekday } = await import("../../src/screens/InsightsScreen");
    const { __setLocaleForTests } = await import("../../src/strings");
    // English passes through unchanged (tests pin the en baseline).
    __setLocaleForTests("en");
    try {
      expect(localWeekday("Monday")).toBe("Monday");
      expect(localWeekday("Sunday")).toBe("Sunday");
      // Unknown/attacker text passes through untouched — never crashes,
      // never invents a date.
      expect(localWeekday(" Fry-day ")).toBe(" Fry-day ");
      expect(localWeekday("")).toBe("");
      expect(localWeekday("constructor")).toBe("constructor");
    } finally {
      __setLocaleForTests("en");
    }
    // Spanish renders Spanish weekdays — "la mayoría de las veces en
    // Monday" was the shipped sentence before this fix.
    __setLocaleForTests("es");
    try {
      expect(localWeekday("Monday")).toBe("lunes");
      expect(localWeekday("Tuesday")).toBe("martes");
      expect(localWeekday("Sunday")).toBe("domingo");
    } finally {
      __setLocaleForTests("en");
    }
  });

  it("the temporal card renders the Spanish weekday inside Spanish copy", async () => {
    const { __setLocaleForTests } = await import("../../src/strings");
    __setLocaleForTests("es");
    try {
      vi.mocked(api.insights).mockResolvedValue({
        phase: "insight",
        active_days: 40,
        days_remaining: 0,
        blob: insightsBlob({
          stats: { patterns: [pattern({ kind: "temporal", label: "trabajo", detail: { day: "Monday" } })] },
        }),
      } as never);
      const root = await render(<InsightsScreen />);
      await flush();
      const text = textOf(root);
      expect(text).toContain("Ha mencionado 'trabajo' 7 veces, la mayoría de las veces en lunes.");
      expect(text).not.toContain("Monday");
      await act(async () => root.unmount());
    } finally {
      __setLocaleForTests("en");
    }
  });
});
