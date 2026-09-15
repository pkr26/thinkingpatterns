/**
 * Deep-mutation pins for OnboardingScreen (2026-09-15 Stryker campaign).
 *
 * Each block kills a specific surviving mutant class:
 *  - the null-user early return on mount (a poisoned null-user seen key must
 *    not route away from the panels),
 *  - the null-user completion (recordOnboardingSeen must NOT be called with
 *    a null id),
 *  - the busy flag on the final button (spinner + accessibilityState while
 *    the completion write is in flight),
 *  - the PrimaryButton's exact accessibility labels, including the
 *    "Continue to panel N of 3" template (string + arithmetic mutants),
 *  - the full style contract pinned per node (container / counter / title /
 *    body / 13+ line), as exact style arrays so base+overlay both hold.
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { ActivityIndicator, Text, TouchableOpacity, View } from "react-native";

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
const { render, flush, textOf, allText, pressLabel, act } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const nav = { navigate: vi.fn(), replace: vi.fn() };

/** Flatten a Text node's children (they may be arrays) to its exact string. */
const flat = (children: unknown): string => {
  if (typeof children === "string") return children;
  if (typeof children === "number") return String(children);
  if (Array.isArray(children)) return children.map(flat).join("");
  return "";
};

/** The Text node whose flattened content satisfies the match (string = exact). */
function textNode(root: Awaited<ReturnType<typeof render>>, match: string | ((s: string) => boolean)) {
  const pred = typeof match === "string" ? (s: string) => s === match : match;
  const node = root.root.findAllByType(Text).find((n) => pred(flat(n.props.children)));
  if (!node) throw new Error(`no matching Text node for ${String(match)}: ${allText(root).join(" | ")}`);
  return node;
}

beforeEach(() => {
  resetApi(api as never);
  storage.__reset();
  touchActivity.mockClear();
  nav.navigate.mockClear();
  nav.replace.mockClear();
});

describe("OnboardingScreen pins: null-user paths", () => {
  it("a null user id on mount returns before the seen-check — a poisoned null key must not reroute", async () => {
    // `if (!userId) return` → false would consult hasSeenOnboarding(null).
    await recordOnboardingSeen(null as never); // the null-user key says "seen"
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<OnboardingScreen navigation={nav as never} />);
    await flush();
    expect(nav.replace).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Write each day");
  });

  it("completing with a null user id writes no seen flag under the null key", async () => {
    // `if (userId)` → true would call recordOnboardingSeen(null).
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<OnboardingScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Continue");
    await pressLabel(root, "Continue");
    await pressLabel(root, "I understand — start writing");
    await flush();
    expect(nav.replace).toHaveBeenCalledWith("Entry");
    expect(await hasSeenOnboarding(null as never)).toBe(false);
  });
});

describe("OnboardingScreen pins: the final button's busy state", () => {
  it("finishing disables the button and swaps the label for a spinner", async () => {
    const root = await render(<OnboardingScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Continue");
    await pressLabel(root, "Continue");
    let resolveUserId!: (v: string | null) => void;
    vi.mocked(api.getUserId).mockImplementation(() => new Promise((resolve) => (resolveUserId = resolve)));
    await pressLabel(root, "I understand — start writing");
    const final = root.root
      .findAllByType(TouchableOpacity)
      .find((n) => n.props.accessibilityLabel === "I understand — start writing");
    expect(final).toBeDefined();
    expect(final.props.accessibilityState).toEqual({ disabled: true, busy: true });
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(1);
    await act(async () => resolveUserId("user-1"));
    await flush();
  });
});

describe("OnboardingScreen pins: exact accessibility labels", () => {
  it("the continue button names the next panel exactly, and the last button its own label", async () => {
    const root = await render(<OnboardingScreen navigation={nav as never} />);
    await flush();
    const byA11y = (label: string) =>
      root.root.findAllByType(TouchableOpacity).find((n) => n.props.accessibilityLabel === label);
    // Template literal + `index + 2` arithmetic + PANELS.length interpolation.
    expect(byA11y("Continue to panel 2 of 3")).toBeDefined();
    await pressLabel(root, "Continue");
    expect(byA11y("Continue to panel 3 of 3")).toBeDefined();
    await pressLabel(root, "Continue");
    expect(byA11y("I understand — start writing")).toBeDefined();
  });
});

describe("OnboardingScreen pins: the per-node style contract", () => {
  it("container, counter, title and body carry base + themed overlays exactly", async () => {
    const root = await render(<OnboardingScreen navigation={nav as never} />);
    await flush();
    const container = root.root.findAllByType(View).find((n) => n.props.onTouchStart === touchActivity);
    expect(container).toBeDefined();
    expect(container.props.style).toEqual(
      [{ flex: 1, justifyContent: "center" }, { backgroundColor: "#0f1115", padding: 24, gap: 18 }],
    );
    expect(textNode(root, "1 of 3").props.style).toEqual({ color: "#8a91a3", fontSize: 12 });
    expect(textNode(root, "Write each day").props.style).toEqual(
      [{ fontSize: 26, fontWeight: "700", lineHeight: 33 }, { color: "#e8eaf0" }],
    );
    expect(textNode(root, (s) => s.startsWith("After 30 days of writing")).props.style).toEqual(
      [{ fontSize: 16, lineHeight: 24 }, { color: "#b6bdc9" }],
    );
  });

  it("panel 3's 13+ line carries its exact single-object style", async () => {
    const root = await render(<OnboardingScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Continue");
    await pressLabel(root, "Continue");
    const age = textNode(root, (s) => s.includes("MindPattern is for people 13 and older"));
    expect(age.props.style).toEqual({ color: "#b6bdc9", fontSize: 13, lineHeight: 19 });
  });
});
