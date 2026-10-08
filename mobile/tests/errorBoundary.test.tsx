/**
 * Root ErrorBoundary (2026-10-01 audit L-4): a render-time throw must
 * never white-screen the app — the fallback stays usable (calm copy,
 * retry) and carries a crisis-resources escape hatch that renders
 * independent of the crashed tree. The audit commit shipped the boundary
 * with zero tests while CI was quota-blocked; this suite is the coverage
 * that should have landed with it.
 *
 * The crash is detonated by a discrete state update, never on first mount:
 * React 19 recovers a concurrent-mount throw by re-rendering synchronously
 * (and reports the unwind as a recoverable error), which both muddies the
 * assertion and surfaces as an unhandled error in vitest. A throw from an
 * event-driven update is caught by the boundary in one synchronous pass.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React, { useEffect, useState } from "react";
import { Linking, Text, View, Pressable } from "react-native";
import { darkTheme } from "../src/theme";
import type { ReactTestRenderer } from "react-test-renderer";

const { ErrorBoundary } = await import("../src/ErrorBoundary");
const { render, act, allText } = await import("./helpers/rtr");

/** Test-side hooks into the harness's armed state (assigned from an
 *  effect so the setters are the live committed ones). */
const controls: { detonate?: () => void; defuse?: () => void } = {};

function Toggle({ armed }: { armed: boolean }): React.JSX.Element {
  if (armed) throw new Error("render exploded PRIVATE-JOURNAL-SENTINEL");
  return <Text>calm tree</Text>;
}

function Harness(): React.JSX.Element {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    controls.detonate = () => setArmed(true);
    controls.defuse = () => setArmed(false);
  });
  return (
    <ErrorBoundary>
      <Toggle armed={armed} />
    </ErrorBoundary>
  );
}

/** Press the Pressable whose subtree text contains `fragment`. */
async function pressByRole(root: ReactTestRenderer, role: string, fragment: string): Promise<void> {
  const node = root.root
    .findAll((n) => n.props?.accessibilityRole === role && typeof n.props?.onPress === "function")
    .find((n) => n.findAllByType(Text).some((t) => String(t.props.children).includes(fragment)));
  if (!node) throw new Error(`no ${role} containing ${JSON.stringify(fragment)}`);
  await act(async () => {
    await node.props.onPress();
  });
}

describe("ErrorBoundary (2026-10-01 audit L-4)", () => {
  beforeEach(() => {
    // componentDidCatch's diagnostics and React's own caught-error logging
    // are noise here; the assertions below pin the behavior, not the log.
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    Linking.openURL.mockClear();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("passes a healthy tree through untouched", async () => {
    const root = await render(
      <ErrorBoundary>
        <Text>calm tree</Text>
      </ErrorBoundary>,
    );
    expect(allText(root).join(" ")).toContain("calm tree");
  });

  it("a render-time throw swaps in the calm fallback: journal-safe copy, retry, crisis escape", async () => {
    const root = await render(<Harness />);
    expect(allText(root).join(" ")).toContain("calm tree");
    await act(async () => {
      controls.detonate!();
    });
    const text = allText(root).join(" ");
    expect(text).toContain("Something went wrong");
    expect(text).toContain("Your journal is safe and encrypted on this device.");
    // The load-bearing escape hatch renders even though the child tree died.
    expect(text).toContain("Crisis resources");
    const flattened = (style: unknown): Record<string, unknown> => Array.isArray(style) ? Object.assign({}, ...style) : style as Record<string, unknown>;
    const container = root.root.findByType(View);
    expect(flattened(container.props.style)).toEqual({ flex: 1, alignItems: "center", justifyContent: "center", padding: 32, gap: 16, backgroundColor: darkTheme.colors.bg });
    const textNodes = root.root.findAllByType(Text);
    const nodeFor = (fragment: string) => textNodes.find(node => String(node.props.children).includes(fragment))!;
    expect(flattened(nodeFor("Something went wrong").props.style)).toEqual({ fontSize: 20, fontWeight: "700", color: darkTheme.colors.text });
    expect(flattened(nodeFor("Your journal is safe").props.style)).toEqual({ fontSize: 14, textAlign: "center", lineHeight: 20, color: darkTheme.colors.muted });
    expect(flattened(nodeFor("Try again").props.style)).toEqual({ color: darkTheme.colors.text, fontWeight: "700" });
    expect(flattened(nodeFor("Crisis resources").props.style)).toEqual({ color: darkTheme.colors.muted });
    for (const button of root.root.findAllByType(Pressable)) expect(flattened(button.props.style)).toEqual({ borderRadius: 12, paddingHorizontal: 20, paddingVertical: 12, backgroundColor: darkTheme.colors.card });
    expect(console.warn).toHaveBeenCalledWith("render_error_boundary");
    expect(JSON.stringify(vi.mocked(console.warn).mock.calls)).not.toContain("PRIVATE-JOURNAL-SENTINEL");
  });

  it("Try again re-mounts the children once the crash source is gone", async () => {
    const root = await render(<Harness />);
    await act(async () => {
      controls.detonate!();
    });
    expect(allText(root).join(" ")).toContain("Something went wrong");
    await act(async () => {
      controls.defuse!();
    });
    await pressByRole(root, "button", "Try again");
    expect(allText(root).join(" ")).toContain("calm tree");
  });

  it("the crisis escape opens the helpline and swallows a refused URL", async () => {
    const root = await render(<Harness />);
    await act(async () => {
      controls.detonate!();
    });
    Linking.openURL.mockResolvedValueOnce(true);
    await pressByRole(root, "link", "Crisis resources");
    // A refused openURL (no handler on the device) must not re-throw into
    // the already-failed tree — the catch is part of the contract.
    Linking.openURL.mockRejectedValueOnce(new Error("no url handler"));
    await expect(pressByRole(root, "link", "Crisis resources")).resolves.toBeUndefined();
    expect(Linking.openURL).toHaveBeenCalledWith("https://findahelpline.com");
  });
});
