/**
 * Deep-mutation pins for QuestionScreen (2026-09-15 Stryker campaign).
 *
 * Each block kills a specific surviving mutant class:
 *  - presence guards (no baseline card before a load, no stale generic card
 *    after the phase moves to insight, notice/day-counter cleared per load),
 *  - the hostile-summary total arm (days_remaining null ⇒ no "Day X of Y"),
 *  - busy spinners during the consent-Continue recompute,
 *  - node-exact style contracts (notice card, baseline card, title/question/
 *    fine print/day counter, insight card, caption, left-aligned ghosts),
 *  - the consent dialog button contract and the bridge's exact failure copy.
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, Text, View } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity }) };
});

/** The built-in day-one pool is mocked so tests control the exact question
 *  text (and rotation) — the pool's own date logic lives in
 *  tests/genericQuestions.test.ts. */
const genericQuestionForDate = vi.fn((_date?: string): string => "What took up most space in your mind today?");
vi.mock("../../src/genericQuestions", () => ({
  genericQuestionForDate: (date?: string) => genericQuestionForDate(date),
}));

const { api, ApiError } = await import("../../src/api/client");
const { QuestionScreen } = await import("../../src/screens/QuestionScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { takeStashedDraft } = await import("../../src/store");
const { render, flush, textOf, allText, pressLabel, touchableByLabel, pressAlertButton, lastAlert } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const dataKey = Buffer.alloc(32, 5);
const FOR_DATE = "2026-09-03";
const questionBlob = (question: string, forDate = FOR_DATE): string =>
  encrypt(
    dataKey,
    Buffer.from(JSON.stringify({ for_date: forDate, question })),
    buildAad("question", "user-1", forDate),
  ).toString("base64");

const CONSENT_KEY = "@mindpattern/keyship_consent_user-1";
const GENERIC = "What took up most space in your mind today?";

beforeEach(() => {
  resetApi(api as never);
  Alert.alert.mockClear();
  touchActivity.mockClear();
  genericQuestionForDate.mockClear();
  genericQuestionForDate.mockReturnValue(GENERIC);
  storage.__reset();
  void storage.setItem(CONSENT_KEY, "1");
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-1");
  takeStashedDraft("user-1");
  takeStashedDraft("user-2");
});

/** The style of the Text node whose flattened content contains `fragment`. */
function styleOfText(root: Awaited<ReturnType<typeof render>>, fragment: string): unknown {
  const flat = (children: unknown): string => {
    if (typeof children === "string") return children;
    if (typeof children === "number") return String(children);
    if (Array.isArray(children)) return children.map(flat).join("");
    return "";
  };
  const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
  if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}: ${allText(root).join(" | ")}`);
  return (node.props as { style: unknown }).style;
}

/** The style ARRAY of the Text node whose flattened content contains `fragment`. */
function styleArrayOfText(root: Awaited<ReturnType<typeof render>>, fragment: string): unknown[] {
  const style = styleOfText(root, fragment);
  return Array.isArray(style) ? style : [style];
}

/** The style of the closest View ancestor of the Text matching `fragment`. */
function parentViewStyle(root: Awaited<ReturnType<typeof render>>, fragment: string): unknown {
  const flat = (children: unknown): string => {
    if (typeof children === "string") return children;
    if (typeof children === "number") return String(children);
    if (Array.isArray(children)) return children.map(flat).join("");
    return "";
  };
  const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
  if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}`);
  let cursor = node.parent;
  while (cursor && cursor.type !== View) cursor = cursor.parent;
  if (!cursor) throw new Error(`no View ancestor for ${JSON.stringify(fragment)}`);
  return (cursor.props as { style: unknown }).style;
}

describe("QuestionScreen pins: card presence guards", () => {
  it("no baseline card before any load (guard needs phase AND generic AND no question)", async () => {
    // A server-side phase failure leaves the phase unknown and the generic
    // unset — with the mount auto-load this is the only "no card" state a
    // user can still see, and the render guard must hold in it.
    vi.mocked(api.insights).mockRejectedValue(new ApiError(500, "boom"));
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).not.toContain("For now, one question a day");
    expect(textOf(root)).not.toContain("questions start coming from YOUR patterns");
  });

  it("a stale generic never re-renders after the phase moves to insight", async () => {
    // Load 1 (mount auto-load): baseline — the generic pool fills the card.
    vi.mocked(api.insights).mockResolvedValueOnce({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    // Load 2 (explicit): insight phase, no stored question, no pattern strong enough.
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: false } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain(GENERIC);
    await pressLabel(root, "Refresh");
    await flush();
    // The notice card is up; the stale generic card must NOT be.
    expect(textOf(root)).toContain("No recurring pattern has enough evidence yet");
    expect(textOf(root)).not.toContain("For now, one question a day");
    expect(textOf(root)).not.toContain(GENERIC);
  });

  it("the notice clears when a later load succeeds", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    // 404 twice: the mount auto-load and the first explicit press; the
    // second press then reads the stored question and clears the notice.
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    vi.mocked(api.recompute).mockResolvedValueOnce({ question_stored: false } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("No recurring pattern has enough evidence yet");
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("What repeats?");
    expect(textOf(root)).not.toContain("No recurring pattern has enough evidence yet");
  });

  it("an OFFLINE phase check drops the day counter from the previous load", async () => {
    vi.mocked(api.insights)
      .mockResolvedValueOnce({ phase: "baseline", active_days: 4, days_remaining: 26 } as never)
      .mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("Day 4 of 30");
    await pressLabel(root, "Refresh");
    await flush();
    // Offline the day counter is unknowable AND the phase is only assumed
    // (audit L-57): the counter from the previous load is gone and the
    // honest "can't reach the server" caption replaces the baseline
    // program copy entirely.
    expect(textOf(root)).not.toContain("Day 4 of");
    expect(textOf(root)).not.toContain("After 30 days of writing");
    expect(textOf(root)).toContain("Can't reach the server right now");
  });

  it("a null days_remaining degrades to the default threshold — never 'Day 4 of 4'", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: null } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain(GENERIC);
    expect(textOf(root)).not.toContain("Day 4 of");
    expect(textOf(root)).toContain("After 30 days of writing");
  });
});

describe("QuestionScreen pins: busy during the consent-Continue recompute", () => {
  it("Continue starts a busy recompute: screen spinner AND button spinner", async () => {
    await storage.removeItem(CONSENT_KEY);
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    // 404 twice: the mount auto-load stops at the key step; the explicit
    // press reaches the consent explainer and the recompute.
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    let resolveRecompute!: (v: unknown) => void;
    vi.mocked(api.recompute).mockImplementation(() => new Promise((resolve) => (resolveRecompute = resolve)));
    const { ActivityIndicator } = await import("react-native");

    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(lastAlert()[0]).toBe("Your key, briefly");
    await pressAlertButton("Continue");
    await flush();
    // busy=true: the screen-level indicator plus the button's own spinner.
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(2);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveRecompute?.({ question_stored: true });
    });
    await flush();
    expect(textOf(root)).toContain("What repeats?");
  });
});

describe("QuestionScreen pins: node-exact style contracts", () => {
  it("the notice card composes base and themed overlays exactly", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: false } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    // The mount auto-load stops at the key step; the explicit press runs the
    // recompute whose "no pattern yet" notice is the pin's subject.
    await pressLabel(root, "Show today's question");
    await flush();
    expect(parentViewStyle(root, "No recurring pattern")).toEqual([
      { padding: 22, gap: 12 },
      { backgroundColor: "#1a1e26", borderRadius: 14 },
    ]);
    expect(styleOfText(root, "No recurring pattern")).toEqual({ color: "#b6bdc9", fontSize: 15, lineHeight: 22 });
  });

  it("the baseline card: view, title, question, fine print, day counter, ghost button", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(parentViewStyle(root, "For now, one question a day")).toEqual([
      { padding: 22, gap: 12 },
      { backgroundColor: "#1a1e26", borderRadius: 14 },
    ]);
    expect(styleArrayOfText(root, "Today")).toEqual([
      { fontSize: 12, fontWeight: "700", letterSpacing: 1.5 },
      { color: "#7f9bff" },
    ]);
    expect(styleArrayOfText(root, GENERIC)).toEqual([
      { fontSize: 22, fontWeight: "600", lineHeight: 30 },
      { color: "#e8eaf0" },
    ]);
    expect(styleOfText(root, "For now, one question a day")).toEqual({ color: "#8a91a3", fontSize: 12, lineHeight: 17 });
    expect(styleOfText(root, "Day 4 of 30")).toEqual({ color: "#8a91a3", fontSize: 12 });
    expect((touchableByLabel(root, "Write about this").props as { style: unknown[] }).style).toEqual([
      { padding: 12 },
      false,
      { minHeight: 44 },
    ]);
  });

  it("the insight card: title overlay, question, fine print, ghost button", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(parentViewStyle(root, "What repeats?")).toEqual([
      { padding: 22, gap: 12 },
      { backgroundColor: "#1a1e26", borderRadius: 14 },
    ]);
    expect(styleArrayOfText(root, "Today")).toEqual([
      { fontSize: 12, fontWeight: "700", letterSpacing: 1.5 },
      { color: "#7f9bff" },
    ]);
    expect(styleArrayOfText(root, "What repeats?")).toEqual([
      { fontSize: 22, fontWeight: "600", lineHeight: 30 },
      { color: "#e8eaf0" },
    ]);
    expect(styleOfText(root, "One question a day. No advice")).toEqual({ color: "#8a91a3", fontSize: 12 });
    expect((touchableByLabel(root, "Write about this").props as { style: unknown[] }).style).toEqual([
      { padding: 12 },
      false,
      { minHeight: 44 },
    ]);
  });

  it("the caption carries its base + themed style array", async () => {
    // Default mock = baseline: the mount auto-load swaps the caption to the
    // on-device variant; its style array is the pin (same in both phases).
    const root = await render(<QuestionScreen />);
    await flush();
    expect(styleArrayOfText(root, "nothing leaves this device for it")).toEqual([
      { textAlign: "center", marginTop: 8, lineHeight: 16 },
      { color: "#8a91a3", fontSize: 12 },
    ]);
  });
});

describe("QuestionScreen pins: dialog and bridge contracts", () => {
  it("the key-shipment explainer's buttons are exactly Not-now(cancel) / Continue", async () => {
    await storage.removeItem(CONSENT_KEY);
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(lastAlert()[2]).toEqual([
      { text: "Not now", style: "cancel" },
      { text: "Continue", onPress: expect.any(Function) },
    ]);
  });

  it("the bridge's no-account alert quotes its exact sentence", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    const nav = { navigate: vi.fn() };
    const root = await render(<QuestionScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Write about this");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Session damaged", "Account id missing — please sign in again.");
    expect(nav.navigate).not.toHaveBeenCalled();
  });
});
