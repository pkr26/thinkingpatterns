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
const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ refreshActiveDays, unlockDays: 30, touchActivity }) };
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
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      active_days: 31,
      days_remaining: 0,
      blob: insightsBlob({ stats: { patterns: [pattern({ label: "work" })] } }),
    } as never);
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen />);
    await flush();
    expectStyle(root, { flex: 1, backgroundColor: "#0f1115" }); // container
    expectStyle(root, { backgroundColor: "#1a1e26", borderRadius: 12, padding: 16, gap: 6 }); // card
    expectStyle(root, { color: "#b6bdc9", fontSize: 15, lineHeight: 21 }); // cardBody
    expectStyle(root, { color: "#7f9bff", fontSize: 11, fontWeight: "700", letterSpacing: 1 }); // kind
    expectStyle(root, { color: "#5c6370", fontSize: 12 }); // meta + footnote share the shape
    expectStyle(root, { color: "#5c6370", fontSize: 12, textAlign: "center", marginTop: 8 }); // footnote

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
    expect(refreshActiveDays).toHaveBeenCalledTimes(1);
    // Layout container contract.
    const scroll = root.root.findByType(ScrollView);
    expect(scroll.props.contentContainerStyle).toEqual({ padding: 20, gap: 14 });
    expect(scroll.props.style).toEqual({ flex: 1, backgroundColor: "#0f1115" });
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
    expect(text).toContain("7 mentions · strength 62%");
    expect(text).toContain("2 mentions · strength 10%");

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
    // Lifecycle metadata renders as evidence chips + the strength meta line.
    expect(text).toContain("fading");
    expect(text).toContain("9 mentions · strength 62%");
    expect(text).toContain("early evidence · new");
    expect(text).toContain("3 mentions · strength 62%");
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

  it("shows the error message when loading fails", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("server unreachable"));
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("server unreachable");
  });

  // M2: a 401 from the insights fetch is surfaced honestly (the vault lock
  // itself is the client hook's job — covered in client.request/store tests)
  // and interaction on this screen restarts the inactivity countdown.
  it("surfaces a 401 from the insights fetch instead of swallowing it", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.insights).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("invalid token");
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

  it("falls back to the generic message for non-Error failures", async () => {
    vi.mocked(api.insights).mockRejectedValue("nope" as never);
    const root = await render(<InsightsScreen />);
    await flush();
    expect(textOf(root)).toContain("failed to load insights");
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
    expect(text).toContain("78% on Sundays");
    expect(text).toContain("your own writing schedule");
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
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<InsightsScreen />);
    await flush();

    const text = textOf(root);
    expect(text).toContain("Keep writing — 18 days to your patterns");
    expect(text).toContain("Writing streak: 3 days");
    expect(text).toContain("Your mood, this month (stays on this device):");
    // The sparkline renders both an up bar (positive day) and a down bar.
    expectStyle(root, { backgroundColor: "#59c98a", borderRadius: 1 });
    expectStyle(root, { backgroundColor: "#e06c75", borderRadius: 1 });
  });

  it("the evidence panel renders every supported stat row for a pattern", async () => {
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
    const text = textOf(root);
    expect(text).toContain("Mood difference");
    expect(text).toContain("lower by 0.40 vs your own norm");
    expect(text).toContain("Effect size");
    expect(text).toContain("Cohen's d = 0.80");
    expect(text).toContain("Day-to-day carryover");
    expect(text).toContain("recent 0.50 vs earlier 0.20");
    expect(text).toContain("Mood spread");
    expect(text).toContain("recent 0.90 vs earlier 0.40");
    expect(text).toContain("Tone");
    expect(text).toContain("reads negative (0.70); absolutist words 3.2/100");
    expect(text).toContain("Recurring over");
    expect(text).toContain("45 days (12 distinct days)");
    expect(text).toContain("Significance");
    expect(text).toContain("p = 1.0e-3 (FDR-corrected)");
    expect(text).toContain("Lag");
    expect(text).toContain("~1 day later (5 such days vs 40 others)");
    expect(text).toContain("Share of entries");
    expect(text).toContain("20% (12 entries, 8 mentions)");
    expect(text).toContain("Earlier → recent");
    expect(text).toContain("10% → 30%");
    expect(text).toContain("Shift");
    expect(text).toContain("−0.20 vs baseline 0.10");
    // The lifecycle badge reads as an established finding.
    expect(text).toContain("established");

    // The toggle collapses the panel again.
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
    expect(text).toContain("0 mentions · strength 0%");

    const { TouchableOpacity } = await import("react-native");
    const expand = async (i: number) => {
      const toggle = root.root.findAllByType(TouchableOpacity)[i];
      await act(async () => {
        (toggle.props as { onPress: () => void }).onPress();
      });
      await flush();
    };
    expect(root.root.findAllByType(TouchableOpacity)).toHaveLength(6); // one "Why am I seeing this?" per card

    // The mood_shift card trending up renders the "+" direction.
    await expand(0);
    expect(textOf(root)).toContain("+0.30 vs baseline 0.20");

    // The link card without sample counts shows "?" placeholders.
    await expand(2);
    expect(textOf(root)).toContain("~1 day later (? such days vs ? others)");

    // Expanding the bare card shows the "?" fallbacks for missing fields.
    await expand(3);
    expect(textOf(root)).toContain("Evidence window");
    expect(textOf(root)).toContain("? → ?");

    // The temporal card without a base_rate reports a 0% baseline.
    await expand(4);
    expect(textOf(root)).toContain("50% on Sundays (your baseline: 0%)");

    // The rain card: mood difference in the "higher" direction, and the
    // share/span rows without their optional counts.
    await expand(5);
    const rainText = textOf(root);
    expect(rainText).toContain("higher by 0.30 vs your own norm");
    expect(rainText).toContain("20% (? entries, 4 mentions)");
    expect(rainText).toContain("30 days (? distinct days)");
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
    expect(textOf(root)).toContain("strength 0%"); // non-numeric confidence -> 0, not NaN
    expect(textOf(root)).toContain("0 mentions"); // negative occurrences -> 0
    expect(textOf(root)).not.toContain("NaN");
    expect(textOf(root)).not.toContain("bad");
  });
});
