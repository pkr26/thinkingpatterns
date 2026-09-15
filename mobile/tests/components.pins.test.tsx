/**
 * Deep-mutation pins for the shared components (2026-09-15 Stryker campaign):
 * buttons.tsx (PrimaryButton / GhostButton / CrisisHelpButton) and
 * InlineStatus.tsx (InlineStatus / NoticeChip).
 *
 * Every survivor is pinned by asserting the EXACT style array on the
 * TouchableOpacity / View / Text node it belongs to — including the literal
 * `false` entries the `&&` overlays produce — plus the accessibility-label
 * routing (`??` vs `&&`) and InlineStatus's null-message / tone gates.
 */
// @ts-nocheck

import { describe, expect, it, vi } from "vitest";
import React from "react";
import { ActivityIndicator, Text, TouchableOpacity, View } from "react-native";

const { PrimaryButton, GhostButton, CrisisHelpButton } = await import("../src/components/buttons");
const { InlineStatus, NoticeChip } = await import("../src/components/InlineStatus");
const { render, textOf, touchableByLabel } = await import("./helpers/rtr");

describe("PrimaryButton pins: the exact style-array contract", () => {
  it("enabled: primary base + fill overlay + the literal false (NO dimmed entry)", async () => {
    const root = await render(<PrimaryButton label="Save entry" onPress={() => {}} />);
    const btn = touchableByLabel(root, "Save entry");
    expect(btn.props.style).toEqual([
      { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" },
      { backgroundColor: "#3b5bdb", minHeight: 44 },
      false,
    ]);
  });

  it("busy: the dimmed overlay {opacity: 0.6} is the third array entry", async () => {
    const root = await render(<PrimaryButton label="Save entry" onPress={() => {}} busy />);
    const btn = root.root.findAllByType(TouchableOpacity)[0];
    expect(btn.props.style).toEqual([
      { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" },
      { backgroundColor: "#3b5bdb", minHeight: 44 },
      { opacity: 0.6 },
    ]);
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(1);
  });

  it("disabled: dimmed too (the overlay keys off isDisabled, not just busy)", async () => {
    const root = await render(<PrimaryButton label="Save entry" onPress={() => {}} disabled />);
    const btn = root.root.findAllByType(TouchableOpacity)[0];
    expect((btn.props.style as unknown[])[2]).toEqual({ opacity: 0.6 });
    expect(btn.props.disabled).toBe(true);
  });
});

describe("GhostButton pins: centering, touch target, label routing", () => {
  it("default center=true: ghost base + centered + minHeight in order", async () => {
    const root = await render(<GhostButton label="Switch mode" onPress={() => {}} />);
    const btn = touchableByLabel(root, "Switch mode");
    expect(btn.props.style).toEqual([{ padding: 12 }, { alignItems: "center" }, { minHeight: 44 }]);
    // The default accessibilityLabel IS the visible label (?? routing).
    expect(btn.props.accessibilityLabel).toBe("Switch mode");
  });

  it("center={false}: the centered entry is the literal false, never the style", async () => {
    const root = await render(<GhostButton label="Support resources" onPress={() => {}} center={false} />);
    const btn = touchableByLabel(root, "Support resources");
    expect(btn.props.style).toEqual([{ padding: 12 }, false, { minHeight: 44 }]);
  });

  it("an explicit accessibilityLabel overrides the visible label (??, not &&)", async () => {
    const root = await render(
      <GhostButton label="Get help" onPress={() => {}} accessibilityLabel="Get help — crisis resources" />,
    );
    expect(touchableByLabel(root, "Get help").props.accessibilityLabel).toBe("Get help — crisis resources");
  });
});

describe("CrisisHelpButton pins", () => {
  it("the help surface and its label text carry their exact styles", async () => {
    const root = await render(<CrisisHelpButton onPress={() => {}} />);
    const btn = touchableByLabel(root, "Need help now? Crisis resources");
    expect(btn.props.style).toEqual([
      { padding: 16, alignItems: "center", justifyContent: "center" },
      { backgroundColor: "#242a38", borderRadius: 10, minHeight: 44 },
    ]);
    const label = root.root.findAllByType(Text)[0];
    expect(label.props.style).toEqual([{ fontWeight: "700" }, { color: "#e8eaf0", fontSize: 14 }]);
  });
});

describe("InlineStatus pins", () => {
  it("a null message renders nothing at all — not even a View", async () => {
    const empty = await render(<InlineStatus message={null} />);
    expect(empty.root.findAllByType(View)).toHaveLength(0);
    expect(empty.root.findAllByType(Text)).toHaveLength(0);
    expect(textOf(empty)).toBe("");
  });

  it("the status line: exact surface array and the DEFAULT ok tone's success color", async () => {
    const root = await render(<InlineStatus message="Saved ✓" />);
    const view = root.root.findAll((n) => n.props.accessibilityLiveRegion === "polite")[0];
    expect(view).toBeDefined();
    expect(view.props.style).toEqual([
      { paddingVertical: 10, paddingHorizontal: 14, alignItems: "center" },
      { backgroundColor: "#141821", borderRadius: 10 },
    ]);
    // tone defaults to "ok" → success color (a "" default or a false tone
    // condition would render the neutral muted color instead).
    expect(root.root.findAllByType(Text)[0].props.style).toEqual({ color: "#59c98a", fontSize: 13 });
  });

  it("the neutral tone renders the muted color exactly", async () => {
    const root = await render(<InlineStatus message="Saved — will sync when online" tone="neutral" />);
    expect(root.root.findAllByType(Text)[0].props.style).toEqual({ color: "#8a91a3", fontSize: 13 });
  });
});

describe("NoticeChip pins", () => {
  it("the chip surface and its text carry their exact styles", async () => {
    const root = await render(<NoticeChip text="Draft restored" />);
    const view = root.root.findAll((n) => n.props.accessibilityRole === "text")[0];
    expect(view).toBeDefined();
    expect(view.props.style).toEqual([
      { alignSelf: "flex-start", paddingVertical: 6, paddingHorizontal: 12 },
      { backgroundColor: "#1a1e26", borderRadius: 12 },
    ]);
    expect(root.root.findAllByType(Text)[0].props.style).toEqual({ color: "#8a91a3", fontSize: 12 });
  });
});
