/** Onboarding panels + the per-account completion stamp, and the static
 *  privacy screen. */
import { describe, expect, it, vi } from "vitest";
import { hasSeenOnboarding, markOnboardingSeen, Onboarding } from "../src/views/Onboarding";
import { Privacy } from "../src/views/Privacy";
import { press, render, textOf } from "./helpers/rtr";
import { localStore } from "../src/platform";

describe("onboarding", () => {
  it("advances through the three panels and finishes", async () => {
    const onDone = vi.fn();
    const root = await render(<Onboarding onDone={onDone} />);
    expect(textOf(root)).toContain("A journal that is yours alone");
    expect(textOf(root)).toContain("Step 1 of 3");
    await press(root, "Next");
    expect(textOf(root)).toContain("Thirty honest days");
    await press(root, "Next");
    expect(textOf(root)).toContain("You are in control");
    expect(onDone).not.toHaveBeenCalled();
    await press(root, "Start journaling");
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it("the completion stamp is per-account and round-trips through the seam", () => {
    expect(hasSeenOnboarding("user-1", localStore.get)).toBe(false);
    markOnboardingSeen("user-1", localStore.set);
    expect(hasSeenOnboarding("user-1", localStore.get)).toBe(true);
    expect(hasSeenOnboarding("user-2", localStore.get)).toBe(false);
  });
});

describe("privacy screen", () => {
  it("states the honest security model and goes back", async () => {
    const onBack = vi.fn();
    const root = await render(<Privacy onBack={onBack} />);
    const text = textOf(root);
    expect(text).toContain("everything you write");
    expect(text).toContain("single-use processing session");
    expect(text).toContain("never what");
    await press(root, "Back");
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});
