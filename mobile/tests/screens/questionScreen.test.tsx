/**
 * QuestionScreen: the audit-fixed order of operations — phase check before
 * any key-bearing call, 404-only fallthrough into the processing session,
 * and honest errors for everything else — plus the first-use informed
 * consent for the key shipment itself.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

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
const { TamperError } = await import("../../src/crypto/envelope");
const { takeStashedDraft } = await import("../../src/store");
const { render, flush, textOf, pressLabel, touchableByLabel, pressAlertButton, lastAlert } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const dataKey = Buffer.alloc(32, 5);
const FOR_DATE = "2026-09-03";
const questionBlob = (question: string, forDate = FOR_DATE, patternPid?: string): string =>
  encrypt(
    dataKey,
    Buffer.from(
      JSON.stringify({ for_date: forDate, question, ...(patternPid !== undefined ? { pattern_pid: patternPid } : {}) }),
    ),
    buildAad("question", "user-1", forDate),
  ).toString("base64");

/** Pre-record the key-shipment acknowledgment so flow tests reach load()
 *  directly; consent-flow tests clear it explicitly. */
const CONSENT_KEY = "@mindpattern/keyship_consent_user-1";

beforeEach(() => {
  resetApi(api as never);
  Alert.alert.mockClear();
  touchActivity.mockClear();
  genericQuestionForDate.mockClear();
  genericQuestionForDate.mockReturnValue("What took up most space in your mind today?");
  storage.__reset();
  void storage.setItem(CONSENT_KEY, "1");
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-1");
  // The draft stash is module state: consume leftovers so the bridge tests
  // cannot leak a stashed question into an unrelated test.
  takeStashedDraft("user-1");
  takeStashedDraft("user-2");
});

/** Find a touchable by its accessibilityLabel (busy buttons swap their
 *  visible label for a spinner, so text search no longer finds them). */
async function touchableByA11yLabel(root: Awaited<ReturnType<typeof render>>, label: string) {
  const { TouchableOpacity } = await import("react-native");
  const node = root.root
    .findAllByType(TouchableOpacity)
    .find((n) => n.props.accessibilityLabel === label);
  if (!node) throw new Error(`no touchable with accessibilityLabel ${JSON.stringify(label)}`);
  return node;
}

describe("QuestionScreen", () => {
  it("auto-loads today's question on mount — key-free, no tap needed", async () => {
    // Default mock: baseline phase → the on-device generic pool answers.
    // The mount effect must show the question WITHOUT any press, and must
    // not have shipped anything key-bearing to do it.
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("What took up most space in your mind today?");
    expect(textOf(root)).toContain("For now, one question a day.");
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    // Settled first paint: no spinner, button shows Refresh.
    const { ActivityIndicator } = await import("react-native");
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(0);
    expect(touchableByLabel(root, "Refresh").props.disabled).toBe(false);
  });

  it("auto-load stops at the key-bearing step: no session, no consent dialog on mount", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "none"));
    const root = await render(<QuestionScreen />);
    await flush();
    // The mount auto-load reached step 3 and STOPPED: the explicit button
    // remains the only path that may ship the data key.
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(api.recompute).not.toHaveBeenCalled();
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Show today's question");
  });

  it("pins the visual language of the screen (question shown)", async () => {
    // Design-system pass: theme-composed styles, muted fine print off the
    // failing #5c6370, button on the AA-passing primary fill.
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What did you notice?") } as never);
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<QuestionScreen />);
    await flush();
    expectStyle(root, { flex: 1, justifyContent: "center" }); // container base
    expectStyle(root, { backgroundColor: "#0f1115", padding: 24, gap: 18 }); // container themed
    expectStyle(root, { padding: 22, gap: 12 }); // card base
    expectStyle(root, { backgroundColor: "#1a1e26", borderRadius: 14 }); // card themed
    expectStyle(root, { fontSize: 12, fontWeight: "700", letterSpacing: 1.5 }); // cardTitle base
    expectStyle(root, { fontSize: 22, fontWeight: "600", lineHeight: 30 }); // question base
    expectStyle(root, { color: "#e8eaf0" }); // question themed
    expectStyle(root, { color: "#8a91a3", fontSize: 12 }); // footnote (contrast fix)
    expectStyle(root, { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" }); // PrimaryButton
    expectStyle(root, { backgroundColor: "#3b5bdb", minHeight: 44 }); // primary fill (AA fix)
    expectStyle(root, { color: "#ffffff", fontSize: 16 }); // button text
  });

  it("renders the error style on failures", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("offline");
    expectStyle(root, { fontSize: 13, textAlign: "center" }); // error base
    expectStyle(root, { color: "#ff6b6b" }); // error themed
  });

  it("below the threshold shows TODAY'S question from the on-device pool — neutral, no key, no consent", async () => {
    await storage.removeItem(CONSENT_KEY); // even with no acknowledgment on record…
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    // Day-one value: a real reflective question, rendered as a normal card.
    expect(textOf(root)).toContain("What took up most space in your mind today?");
    expect(textOf(root)).toContain("For now, one question a day.");
    expect(textOf(root)).toContain("your questions start coming from YOUR patterns.");
    expect(textOf(root)).toContain("Day 4 of 30");
    // Neutral: no alert role, no error color anywhere in the tree.
    expect(root.root.findAll((n) => n.props.accessibilityRole === "alert")).toHaveLength(0);
    const { allStyles } = await import("../helpers/rtr");
    expect(allStyles(root).some((s) => s.color === "#ff6b6b")).toBe(false);
    // …nothing leaves the device for it: no key-bearing call, no stored-
    // question fetch, and — the whole point — NO consent explainer.
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(api.questionToday).not.toHaveBeenCalled();
    expect(Alert.alert).not.toHaveBeenCalled();
    // The caption swaps to the on-device truth.
    expect(textOf(root)).toContain("nothing leaves this device for it.");
    expect(textOf(root)).not.toContain("held in memory for up to 5 minutes, never stored.");
  });

  it("an OFFLINE phase check (status 0) still renders the on-device question, not an error card", async () => {
    // The phase fetch needs the network; the generic pool does not. An
    // offline user gets the question — with the HONEST offline caption
    // (2026-09-20 audit L-57): status 0 means "no response", the phase is
    // unknowable, so the card never asserts the baseline program copy at
    // an account that may already be in the insight phase.
    vi.mocked(api.insights).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("What took up most space in your mind today?");
    expect(textOf(root)).toContain("Can't reach the server right now");
    // The baseline program copy is NOT shown while the phase is assumed.
    expect(textOf(root)).not.toContain("After 30 days of writing");
    expect(textOf(root)).not.toContain("nothing leaves this device for it.");
    // No error surface at all: no alert role, no error color, no dialog.
    expect(root.root.findAll((n) => n.props.accessibilityRole === "alert")).toHaveLength(0);
    const { allStyles } = await import("../helpers/rtr");
    expect(allStyles(root).some((s) => s.color === "#ff6b6b")).toBe(false);
    expect(Alert.alert).not.toHaveBeenCalled();
    // …and nothing key-bearing or network-bound ran past the failed check.
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(api.questionToday).not.toHaveBeenCalled();
  });

  it("a SERVER error (500) on the phase check stays an error — no offline fallback", async () => {
    vi.mocked(api.insights).mockRejectedValue(new ApiError(500, "boom"));
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("The server hit a problem — try again in a moment.");
    expect(textOf(root)).not.toContain("What took up most space in your mind today?");
  });

  it("the day-one question rotates with the date (one per day)", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    genericQuestionForDate.mockReturnValueOnce("First day question").mockReturnValueOnce("Second day question");
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("First day question");
    await pressLabel(root, "Refresh");
    await flush();
    expect(textOf(root)).toContain("Second day question");
    expect(genericQuestionForDate).toHaveBeenCalledTimes(2);
  });

  it("a hostile summary shape degrades the day counter, never the question", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: "four", days_remaining: null } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("What took up most space in your mind today?");
    expect(textOf(root)).not.toContain("Day NaN");
    // Unknown total: the line falls back to the default threshold.
    expect(textOf(root)).toContain("After 30 days of writing");
  });

  it("'Write about this' bridges the day-one question into the journal draft", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    const nav = { navigate: vi.fn() };
    const root = await render(<QuestionScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Write about this");
    await flush();
    const { peekDraft, takeStashedDraft } = await import("../../src/store");
    expect(peekDraft("user-1")).toBe("What took up most space in your mind today?");
    expect(nav.navigate).toHaveBeenCalledWith("Entry");
    takeStashedDraft("user-1"); // leave nothing behind for other tests
  });

  it("'Write about this' bridges a pattern-based question the same way", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    const nav = { navigate: vi.fn() };
    const root = await render(<QuestionScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Write about this");
    await flush();
    const { takeStashedDraft } = await import("../../src/store");
    expect(takeStashedDraft("user-1")).toBe("What repeats?");
    expect(nav.navigate).toHaveBeenCalledWith("Entry");
  });

  it("the bridge stays put (and honest) when the account id is missing", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    const nav = { navigate: vi.fn() };
    const root = await render(<QuestionScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Write about this");
    await flush();
    expect(lastAlert()[0]).toBe("Session damaged");
    expect(nav.navigate).not.toHaveBeenCalled();
  });

  it("shows a stored question without opening a processing session", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What did you notice?") } as never);
    const root = await render(<QuestionScreen />);
    await flush();

    expect(textOf(root)).toContain("What did you notice?");
    expect(textOf(root)).toContain("One question a day. No advice — just something to sit with.");
    expect(textOf(root)).toContain("Refresh");
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("a feedback_blob_invalid recompute opens a FRESH processing session for the retry (M-12)", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found")) // mount auto-load: stops at the key step
      .mockRejectedValueOnce(new ApiError(404, "not found")) // the press's phase-2 read
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    // Seed a pending tap so buildFeedbackBlob actually ships a blob — the
    // server's feedback pre-flight is what fails with feedback_blob_invalid
    // (consuming the single-use processing token on the way out).
    const { recordFeedbackTap } = await import("../../src/questionFeedback");
    await recordFeedbackTap(dataKey, "user-1", "pid-x", true);
    let opens = 0;
    vi.mocked(api.openProcessingSession).mockImplementation(async () => {
      opens += 1;
      return { session_token: `st-${opens}` } as never;
    });
    vi.mocked(api.recompute)
      .mockRejectedValueOnce(new ApiError(422, "feedback blob failed authentication", "feedback_blob_invalid"))
      .mockResolvedValue({ question_stored: true } as never);

    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();

    // The dead token must NOT be replayed (a guaranteed 403
    // processing_session_invalid): the retry runs on a freshly opened
    // session, the corrupted feedback queue is dropped, and the question
    // still loads in the same flow.
    expect(api.openProcessingSession).toHaveBeenCalledTimes(2);
    expect(api.recompute).toHaveBeenNthCalledWith(1, "st-1", expect.any(String));
    expect(api.recompute).toHaveBeenNthCalledWith(2, "st-2");
    expect(textOf(root)).toContain("What repeats?");
    expect(await storage.getItem("@mindpattern/question_feedback.user-1")).toBeNull();
  });

  it("on 404, opens the key-bearing session once and only on consent", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    // 404 twice: the mount auto-load consumes the first (and stops at the
    // key-bearing step); the explicit press consumes the second before its
    // recompute path re-reads the stored question.
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: true } as never);

    const root = await render(<QuestionScreen />);
    await flush();
    expect(api.openProcessingSession).not.toHaveBeenCalled(); // the mount never ships the key
    await pressLabel(root, "Show today's question");
    await flush();

    expect(api.openProcessingSession).toHaveBeenCalledWith(dataKey.toString("base64"));
    expect(api.recompute).toHaveBeenCalledWith("st", undefined); // no pending feedback taps
    expect(textOf(root)).toContain("What repeats?");
  });

  it("reports when the mini-brain has no solid pattern yet", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: false } as never);

    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("No recurring pattern has enough evidence yet — keep writing.");
  });

  it("a failed recompute surfaces calm copy without a dialog", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
    vi.mocked(api.recompute).mockRejectedValue(new ApiError(500, "boom"));

    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("The server hit a problem — try again in a moment.");
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("a local crypto failure AFTER a consented recompute still gets a dialog", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found")) // mount auto-load: stops at the key step
      .mockRejectedValueOnce(new ApiError(404, "not found")) // the press's phase-2 read
      .mockResolvedValue({ for_date: FOR_DATE, blob: "AAAA" } as never); // TamperError post-recompute
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: true } as never);

    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);
    expect(Alert.alert).toHaveBeenCalledWith("Could not load question", "blob failed authentication");
    expect(textOf(root)).toContain("blob failed authentication");
  });

  it("does NOT fall through to the key-bearing branch on non-404 failures", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(500, "boom"));

    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("The server hit a problem — try again in a moment.");
    expect(textOf(root)).not.toContain("boom");
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("clears a previous error while a new load is in flight", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("offline");

    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(
      () => new Promise((resolve) => (resolveInsights = resolve)),
    );
    const { firePress, act } = await import("../helpers/rtr");
    await firePress(root, "Show today's question");
    expect(textOf(root)).not.toContain("offline");
    await act(async () => {
      resolveInsights?.({ phase: "baseline", active_days: 1, days_remaining: 29 });
    });
    await flush();
  });

  it("session expiry maps to calm copy without a dialog", async () => {
    vi.mocked(api.insights).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("Session expired — please unlock again.");
    expect(textOf(root)).not.toContain("invalid token");
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  // M2: interaction on this screen (not just Entry typing) restarts the
  // inactivity countdown — a reader is not idle.
  it("any touch on the screen resets the inactivity countdown", async () => {
    const { View } = await import("react-native");
    const root = await render(<QuestionScreen />);
    await flush();
    const container = root.root.findAllByType(View)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (container.props as { onTouchStart?: () => void }).onTouchStart?.();
    });
    await act(async () => {
      (container.props as { onTouchStart?: () => void }).onTouchStart?.();
    });
    expect(touchActivity).toHaveBeenCalledTimes(2);
  });

  it("local crypto failures get a dialog", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: "AAAA" } as never); // TamperError

    const root = await render(<QuestionScreen />);
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not load question", "blob failed authentication");
    expect(textOf(root)).toContain("blob failed authentication");
  });

  it("requires a stored account id", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("account id missing — sign in again");
  });

  it("non-Error rejections fall back to the calm generic sentence", async () => {
    vi.mocked(api.insights).mockRejectedValue("nope" as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("Something went wrong — try again.");
    expect(Alert.alert).toHaveBeenCalled();
  });

  it("the crisis link is one tap away and navigates to Crisis", async () => {
    const nav = { navigate: vi.fn() };
    const root = await render(<QuestionScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("disables the button and shows the spinner while busy", async () => {
    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(() => new Promise((resolve) => (resolveInsights = resolve)));
    const root = await render(<QuestionScreen />);
    const helpers = await import("../helpers/rtr");
    const reactNative = await import("react-native");
    // The MOUNT auto-load is already in flight against the pending phase
    // check — the busy state needs no press to exist.
    const btn = await touchableByA11yLabel(root, "Show today's question");
    expect(btn.props.disabled).toBe(true);
    expect(btn.props.accessibilityState).toEqual({ disabled: true, busy: true });
    // Two spinners: the screen-level indicator and the busy button's own.
    expect(root.root.findAllByType(reactNative.ActivityIndicator)).toHaveLength(2);
    await helpers.act(async () => {
      resolveInsights?.({ phase: "insight", active_days: 31, days_remaining: 0 });
    });
    await flush();
    // Load finished (empty blob → honest error), button re-enabled with its label back.
    expect((await touchableByA11yLabel(root, "Show today's question")).props.disabled).toBe(false);
    expect(root.root.findAllByType(reactNative.ActivityIndicator)).toHaveLength(0);
  });

  it("a second press while busy is a no-op (the guard, not just the disabled flag)", async () => {
    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(() => new Promise((resolve) => (resolveInsights = resolve)));
    const root = await render(<QuestionScreen />);
    const { act } = await import("../helpers/rtr");
    // The mount auto-load is in flight; fire the press handler directly (a
    // leaked press past the disabled control): the busy guard swallows it —
    // no second phase check.
    const btn = await touchableByA11yLabel(root, "Show today's question");
    await act(async () => {
      void (btn.props as { onPress: () => unknown }).onPress?.();
    });
    await flush();
    expect(api.insights).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveInsights?.({ phase: "baseline", active_days: 1, days_remaining: 29 });
    });
    await flush();
  });
});

describe("H5: vault/account binding before shipping the data key", () => {
  it("refuses the processing session when the vault keys belong to another account", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "none"));
    vault.lock();
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-2");
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(vi.mocked(api.openProcessingSession)).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("do not match");
  });
});

describe("QuestionScreen key-shipment consent (informed consent fix)", () => {
  // The consent gate sits INSIDE the load, immediately before the ONE
  // key-bearing step: pre-threshold users never see it (no key ships for an
  // on-device question), and key-free reads — the phase check, today's
  // stored question — are allowed to run before it.
  const insightNoQuestion = () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
  };

  it("the first recompute explains the key shipment BEFORE anything key-bearing runs", async () => {
    await storage.removeItem(CONSENT_KEY); // no acknowledgment on record
    insightNoQuestion();
    const root = await render(<QuestionScreen />);
    await flush();
    // The mount auto-load stopped at the key step with NO dialog of its own.
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(lastAlert()[0]).toBe("Your key, briefly");
    expect(lastAlert()[1]).toContain("held in memory for up to 5 minutes");
    expect(lastAlert()[1]).toContain("never stored");
    // Key-free reads ran on both loads (mount + press); the key-bearing
    // session still did not.
    expect(api.insights).toHaveBeenCalledTimes(2);
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("'Continue' records the acknowledgment per account and proceeds", async () => {
    await storage.removeItem(CONSENT_KEY);
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found")) // mount auto-load: stops at the key step
      .mockRejectedValueOnce(new ApiError(404, "not found")) // the press's phase-2 read
      .mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: true } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    await pressAlertButton("Continue");
    await flush();
    expect(await storage.getItem(CONSENT_KEY)).toBe("1");
    expect(textOf(root)).toContain("What repeats?");
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);

    // A second tap loads directly — no explainer, no second session.
    Alert.alert.mockClear();
    await pressLabel(root, "Refresh");
    await flush();
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(api.questionToday).toHaveBeenCalledTimes(4); // auto, press, post-recompute, refresh
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);
  });

  it("'Not now' records nothing and ships nothing", async () => {
    await storage.removeItem(CONSENT_KEY);
    insightNoQuestion();
    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    await pressAlertButton("Not now");
    await flush();
    expect(await storage.getItem(CONSENT_KEY)).toBeNull();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("a consent-check storage failure errs toward asking again, not skipping", async () => {
    await storage.removeItem(CONSENT_KEY);
    insightNoQuestion();
    // Sabotage storage reads: the explainer must appear (fail-honest).
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      const root = await render(<QuestionScreen />);
      await flush();
      await pressLabel(root, "Show today's question");
      await flush();
      expect(lastAlert()[0]).toBe("Your key, briefly");
      expect(api.openProcessingSession).not.toHaveBeenCalled();
    } finally {
      storage.getItem = original;
    }
  });

  it("without a stored account id the explainer is never reached and the load says why", async () => {
    // getUserId → null: the key-free decrypt step fails first with the
    // honest account error, so the consent gate is never approached.
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    await pressLabel(root, "Show today's question");
    await flush();
    expect(lastAlert()[0]).not.toBe("Your key, briefly");
    expect(textOf(root)).toContain("account id missing");
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("the honest caption matches the phase: key shipment only post-threshold", async () => {
    // The default mock is baseline phase: the mount auto-load swaps the
    // caption to the on-device truth immediately…
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("nothing leaves this device for it.");
    expect(textOf(root)).not.toContain("held in memory for up to 5 minutes, never stored.");
    // …and post-threshold the key-shipment honesty returns.
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    await pressLabel(root, "Refresh");
    await flush();
    expect(textOf(root)).toContain("held in memory for up to 5 minutes, never stored.");
  });
});

describe("QuestionScreen feedback attribution (pattern_pid)", () => {
  const insightPhase = () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
  };

  /** Decrypt the locally stored pending taps (the record the recompute ships). */
  const readTaps = async (): Promise<Array<{ pid: string; resonated: boolean }>> => {
    const { decrypt } = await import("../../src/crypto/envelope");
    const raw = await storage.getItem("@mindpattern/question_feedback.user-1");
    if (raw === null) return [];
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", "user-1"));
    return JSON.parse(plain.toString("utf8")) as Array<{ pid: string; resonated: boolean }>;
  };

  it("a stored question carrying pattern_pid offers the taps and records THAT pid", async () => {
    insightPhase();
    vi.mocked(api.questionToday).mockResolvedValue({
      for_date: FOR_DATE,
      blob: questionBlob("What repeats?", FOR_DATE, "pid-1"),
    } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("What repeats?");
    expect(textOf(root)).toContain("This resonated");
    expect(textOf(root)).toContain("Not me");
    await pressLabel(root, "This resonated");
    await flush();
    expect(await readTaps()).toEqual([{ pid: "pid-1", resonated: true }]);
  });

  it("an ordinary stored question (no pid) never offers the taps", async () => {
    insightPhase();
    vi.mocked(api.questionToday).mockResolvedValue({
      for_date: FOR_DATE,
      blob: questionBlob("What did you notice?"),
    } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("What did you notice?");
    expect(textOf(root)).not.toContain("This resonated");
    expect(textOf(root)).not.toContain("Not me");
  });

  it("a refresh that swaps the question re-attributes the taps to the NEW pid", async () => {
    insightPhase();
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "none")) // first load: nothing stored
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("What repeats?", FOR_DATE, "pid-a") } as never) // post-recompute
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("What changed?", FOR_DATE, "pid-b") } as never); // refresh
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: true } as never);
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("What repeats?");
    expect(textOf(root)).toContain("This resonated");
    await pressLabel(root, "Refresh");
    await flush();
    expect(textOf(root)).toContain("What changed?");
    await pressLabel(root, "Not me");
    await flush();
    // The pid follows the question swap — never the previous question's.
    expect(await readTaps()).toEqual([{ pid: "pid-b", resonated: false }]);
  });

  it("a refresh onto a pid-less question clears the stale pid (no taps offered)", async () => {
    insightPhase();
    vi.mocked(api.questionToday)
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("What repeats?", FOR_DATE, "pid-a") } as never)
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("A plain follow-up?") } as never);
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("This resonated");
    await pressLabel(root, "Refresh");
    await flush();
    expect(textOf(root)).toContain("A plain follow-up?");
    expect(textOf(root)).not.toContain("This resonated");
    expect(textOf(root)).not.toContain("Not me");
  });
});
