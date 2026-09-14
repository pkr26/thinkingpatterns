/**
 * OnboardingScreen: three calm panels shown once after registration, the
 * privacy-policy link on the encryption panel, the no-reset + 13+
 * acknowledgments, the completion write, and the already-seen escape hatch.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock() };
});

const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity }) };
});

const { api } = await import("../../src/api/client");
const { OnboardingScreen } = await import("../../src/screens/OnboardingScreen");
const { hasSeenOnboarding, recordOnboardingSeen } = await import("../../src/onboarding");
const { render, flush, textOf, pressLabel, allText, touchableByLabel, act } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const nav = { navigate: vi.fn(), replace: vi.fn() };

beforeEach(() => {
  resetApi(api as never);
  storage.__reset();
  touchActivity.mockClear();
  nav.navigate.mockClear();
  nav.replace.mockClear();
});

describe("OnboardingScreen", () => {
  it("walks the three panels in order and records the acknowledgment on completion", async () => {
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("1 of 3");
    expect(textOf(root)).toContain("Write each day");
    expect(textOf(root)).toContain("patterns too slow to notice");
    expect(textOf(root)).toContain("Never advice, never a diagnosis.");

    await pressLabel(root, "Continue");
    expect(textOf(root)).toContain("2 of 3");
    expect(textOf(root)).toContain("Your words stay yours");
    expect(textOf(root)).toContain("the server stores only ciphertext");
    expect(textOf(root)).toContain("held in memory for up to 5 minutes");

    await pressLabel(root, "Continue");
    expect(textOf(root)).toContain("3 of 3");
    expect(textOf(root)).toContain("Keep your password safe");
    expect(textOf(root)).toContain("There is no password reset");
    expect(textOf(root)).toContain("MindPattern is for people 13 and older");

    await pressLabel(root, "I understand — start writing");
    await flush();
    expect(await hasSeenOnboarding("user-1")).toBe(true);
    expect(nav.replace).toHaveBeenCalledWith("Entry");
  });

  it("the encryption panel links to the privacy policy (and only that panel has it)", async () => {
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    expect(allText(root).join(" ")).not.toContain("Read the privacy policy");
    await pressLabel(root, "Continue");
    await pressLabel(root, "Read the privacy policy");
    expect(nav.navigate).toHaveBeenCalledWith("Privacy");
  });

  it("crisis help is one tap away", async () => {
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("landing here already-seen routes straight to the journal (never lecture twice)", async () => {
    await recordOnboardingSeen("user-1");
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    expect(nav.replace).toHaveBeenCalledWith("Entry");
  });

  it("a missing account id still completes — there is nothing to bind the flag to", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Continue");
    await pressLabel(root, "Continue");
    await pressLabel(root, "I understand — start writing");
    await flush();
    expect(nav.replace).toHaveBeenCalledWith("Entry");
    expect(await hasSeenOnboarding("user-1")).toBe(false);
  });

  it("a storage failure on completion never blocks the journal", async () => {
    const original = storage.setItem;
    storage.setItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      const root = await render(<OnboardingScreen navigation={nav} />);
      await flush();
      await pressLabel(root, "Continue");
      await pressLabel(root, "Continue");
      await pressLabel(root, "I understand — start writing");
      await flush();
      expect(nav.replace).toHaveBeenCalledWith("Entry");
    } finally {
      storage.setItem = original;
    }
  });

  it("a failed seen-check stays on the panels (fail toward showing, never hiding)", async () => {
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      const root = await render(<OnboardingScreen navigation={nav} />);
      await flush();
      expect(nav.replace).not.toHaveBeenCalled();
      expect(textOf(root)).toContain("Write each day");
    } finally {
      storage.getItem = original;
    }
  });

  it("advancing panels restarts the inactivity countdown", async () => {
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Continue");
    await pressLabel(root, "Continue");
    expect(touchActivity).toHaveBeenCalledTimes(2);
  });

  it("a double-tap on the final button completes once (the busy guard)", async () => {
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush(); // the mount seen-check used the default (resolved) mock
    await pressLabel(root, "Continue");
    await pressLabel(root, "Continue");
    vi.mocked(api.getUserId).mockClear();
    let resolveUserId!: (v: string | null) => void;
    vi.mocked(api.getUserId).mockImplementation(() => new Promise((resolve) => (resolveUserId = resolve)));
    const btn = touchableByLabel(root, "I understand — start writing");
    await act(async () => {
      // Two invocations before the first await settles: the guard swallows one.
      void (btn.props as { onPress: () => unknown }).onPress?.();
      void (btn.props as { onPress: () => unknown }).onPress?.();
    });
    await act(async () => resolveUserId("user-1"));
    await flush();
    expect(api.getUserId).toHaveBeenCalledTimes(1);
    expect(nav.replace).toHaveBeenCalledTimes(1);
  });

  it("a failed account read on mount skips the seen-check quietly", async () => {
    vi.mocked(api.getUserId).mockRejectedValue(new Error("storage gone"));
    const root = await render(<OnboardingScreen navigation={nav} />);
    await flush();
    expect(nav.replace).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Write each day");
  });

  it("an unmount mid seen-check cancels the route swap", async () => {
    let resolveUserId!: (v: string | null) => void;
    vi.mocked(api.getUserId).mockImplementation(() => new Promise((resolve) => (resolveUserId = resolve)));
    await recordOnboardingSeen("user-1"); // would trigger the swap if it landed
    const root = await render(<OnboardingScreen navigation={nav} />);
    await act(async () => root.unmount()); // cleanup runs: cancelled = true
    await act(async () => resolveUserId("user-1"));
    await flush();
    expect(nav.replace).not.toHaveBeenCalled();
  });
});
