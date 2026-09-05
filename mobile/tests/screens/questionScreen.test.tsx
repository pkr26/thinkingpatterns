/**
 * QuestionScreen: the audit-fixed order of operations — phase check before
 * any key-bearing call, 404-only fallthrough into the processing session,
 * and honest errors for everything else.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock() };
});

const { api, ApiError } = await import("../../src/api/client");
const { QuestionScreen } = await import("../../src/screens/QuestionScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { TamperError } = await import("../../src/crypto/envelope");
const { render, flush, textOf, pressLabel, touchableByLabel } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");

const dataKey = Buffer.alloc(32, 5);
const FOR_DATE = "2026-09-03";
const questionBlob = (question: string, forDate = FOR_DATE): string =>
  encrypt(
    dataKey,
    Buffer.from(JSON.stringify({ for_date: forDate, question })),
    buildAad("question", "user-1", forDate),
  ).toString("base64");

beforeEach(() => {
  resetApi(api as never);
  Alert.alert.mockClear();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-1");
});

describe("QuestionScreen", () => {
  it("starts empty with the invitation button", async () => {
    const root = await render(<QuestionScreen />);
    await flush();
    expect(textOf(root)).toContain("Show today's question");
    expect(textOf(root)).not.toContain("One question a day");
    // Idle first paint: no spinner, button enabled.
    const { ActivityIndicator } = await import("react-native");
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(0);
    expect(touchableByLabel(root, "Show today's question").props.disabled).toBe(false);
  });

  it("pins the visual language of the screen (question shown)", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What did you notice?") } as never);
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expectStyle(root, { flex: 1, backgroundColor: "#0f1115", padding: 24, justifyContent: "center", gap: 18 });
    expectStyle(root, { backgroundColor: "#1a1e26", borderRadius: 14, padding: 22, gap: 12 });
    expectStyle(root, { color: "#7f9bff", fontSize: 12, fontWeight: "700", letterSpacing: 1.5 });
    expectStyle(root, { color: "#e8eaf0", fontSize: 22, fontWeight: "600", lineHeight: 30 });
    expectStyle(root, { color: "#5c6370", fontSize: 12 });
    expectStyle(root, { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center" });
    expectStyle(root, { color: "#fff", fontSize: 16, fontWeight: "600" });
  });

  it("renders the error style on failures", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("offline");
    expectStyle(root, { color: "#ff6b6b", fontSize: 13, textAlign: "center" });
  });

  it("refuses below the threshold without touching keys", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "baseline", active_days: 4, days_remaining: 26 } as never);
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("one question per day starts after day 30.");
    expect(vi.mocked(api.openProcessingSession)).not.toHaveBeenCalled();
  });

  it("shows a stored question without opening a processing session", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("What did you notice?") } as never);
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();

    expect(textOf(root)).toContain("What did you notice?");
    expect(textOf(root)).toContain("One question a day. No advice — just something to sit with.");
    expect(textOf(root)).toContain("Refresh");
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("on 404, opens the key-bearing session once and only on consent", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday)
      .mockRejectedValueOnce(new ApiError(404, "not found"))
      .mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("What repeats?") } as never);
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: true } as never);

    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();

    expect(api.openProcessingSession).toHaveBeenCalledWith(dataKey.toString("base64"));
    expect(api.recompute).toHaveBeenCalledWith("st");
    expect(textOf(root)).toContain("What repeats?");
  });

  it("reports when the mini-brain has no solid pattern yet", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(404, "not found"));
    vi.mocked(api.recompute).mockResolvedValue({ question_stored: false } as never);

    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("No recurring pattern has enough evidence yet — keep writing.");
  });

  it("does NOT fall through to the key-bearing branch on non-404 failures", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockRejectedValue(new ApiError(500, "boom"));

    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("boom");
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("clears a previous error while a new load is in flight", async () => {
    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
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

  it("session expiry maps to the unlock hint without a dialog", async () => {
    vi.mocked(api.insights).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("Session expired — unlock again.");
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("local crypto failures get a dialog", async () => {
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: "AAAA" } as never); // TamperError

    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not load question", "blob failed authentication");
    expect(textOf(root)).toContain("blob failed authentication");
  });

  it("requires a stored account id", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("account id missing — sign in again");
  });

  it("non-Error rejections fall back to the generic message", async () => {
    vi.mocked(api.insights).mockRejectedValue("nope" as never);
    const root = await render(<QuestionScreen />);
    await pressLabel(root, "Show today's question");
    await flush();
    expect(textOf(root)).toContain("could not load today's question");
    expect(Alert.alert).toHaveBeenCalled();
  });

  it("disables the button and shows the spinner while busy", async () => {
    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(() => new Promise((resolve) => (resolveInsights = resolve)));
    const root = await render(<QuestionScreen />);
    const helpers = await import("../helpers/rtr");
    const reactNative = await import("react-native");
    await helpers.firePress(root, "Show today's question");
    expect(touchableByLabel(root, "Show today's question").props.disabled).toBe(true);
    expect(root.root.findAllByType(reactNative.ActivityIndicator)).toHaveLength(1);
    await helpers.act(async () => {
      resolveInsights?.({ phase: "insight", active_days: 31, days_remaining: 0 });
    });
    await flush();
    // Load finished (empty blob → honest error), button re-enabled with its label back.
    expect(touchableByLabel(root, "Show today's question").props.disabled).toBe(false);
    expect(root.root.findAllByType(reactNative.ActivityIndicator)).toHaveLength(0);
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
