/**
 * Shared UI components: the calm error-copy mapper (no raw server text in
 * dialogs), the button family (roles, states, ≥44pt targets), the transient
 * inline status, and the nav row with its unmistakable help action.
 */
import { describe, expect, it, vi } from "vitest";
import React from "react";
import { ActivityIndicator, Text, TouchableOpacity } from "react-native";

const { ApiError } = await import("../src/api/client");
const { requestFailureCopy, calmFallbackCopy } = await import("../src/components/errors");
const { PrimaryButton, GhostButton, CrisisHelpButton } = await import("../src/components/buttons");
const { InlineStatus, NoticeChip } = await import("../src/components/InlineStatus");
const { NavRow } = await import("../src/components/NavRow");
const { render, textOf, pressLabel, touchableByLabel } = await import("./helpers/rtr");

describe("requestFailureCopy", () => {
  it("maps statuses to calm copy, never echoing server detail", () => {
    expect(requestFailureCopy(new ApiError(0, "server unreachable — check the server URL"))).toBe(
      "Couldn't reach the server — check your connection.",
    );
    expect(requestFailureCopy(new ApiError(401, "invalid token"))).toBe("Session expired — please unlock again.");
    expect(requestFailureCopy(new ApiError(403, "verification_failed"))).toBe("The server refused that request.");
    expect(requestFailureCopy(new ApiError(404, "not found"))).toBe("That isn't on the server (anymore).");
    expect(requestFailureCopy(new ApiError(409, "conflict"))).toBe(
      "That conflicts with something the server already has.",
    );
    expect(requestFailureCopy(new ApiError(413, "quota_exceeded: 268435456 bytes"))).toBe(
      "That's more data than the server can accept.",
    );
    expect(requestFailureCopy(new ApiError(429, "rate_limited", "rate_limited", 30_000))).toBe(
      "Too many attempts — wait a moment, then try again.",
    );
    expect(requestFailureCopy(new ApiError(500, "TypeError: cannot read properties"))).toBe(
      "The server hit a problem — try again in a moment.",
    );
    expect(requestFailureCopy(new ApiError(400, "validation_error: field required"))).toBe(
      "The server didn't accept that request.",
    );
  });

  it("passes through our own local Error copy and calms non-Error failures", () => {
    expect(requestFailureCopy(new Error("vault is locked"))).toBe("vault is locked");
    expect(requestFailureCopy("exploded")).toBe("Something went wrong — try again.");
  });
});

describe("calmFallbackCopy", () => {
  it("maps ApiError but replaces everything else with the caller's sentence", () => {
    expect(calmFallbackCopy(new ApiError(0, "x"), "The export didn't complete.")).toContain("Couldn't reach the server");
    expect(calmFallbackCopy(new Error("disk full"), "The export didn't complete.")).toBe("The export didn't complete.");
  });
});

describe("PrimaryButton", () => {
  it("renders its label, fires onPress, and carries role/state", async () => {
    const onPress = vi.fn();
    const root = await render(<PrimaryButton label="Save entry" onPress={onPress} />);
    const btn = touchableByLabel(root, "Save entry");
    expect(btn.props.accessibilityRole).toBe("button");
    expect(btn.props.accessibilityState).toEqual({ disabled: false, busy: false });
    expect(btn.props.style).toEqual(
      expect.arrayContaining([expect.objectContaining({ minHeight: 44 })]),
    );
    await pressLabel(root, "Save entry");
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it("busy swaps the label for a spinner and disables", async () => {
    const onPress = vi.fn();
    const root = await render(<PrimaryButton label="Save entry" onPress={onPress} busy />);
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(1);
    expect(textOf(root)).not.toContain("Save entry");
    const btn = root.root.findAllByType(TouchableOpacity)[0];
    expect(btn.props.disabled).toBe(true);
    expect(btn.props.accessibilityState).toEqual({ disabled: true, busy: true });
    // The label still reaches the screen reader while hidden visually.
    expect(btn.props.accessibilityLabel).toBe("Save entry");
  });

  it("the danger variant uses the danger fill", async () => {
    const root = await render(<PrimaryButton label="Delete" onPress={() => {}} danger />);
    const btn = root.root.findAllByType(TouchableOpacity)[0];
    const flat = (btn.props.style as unknown[]).flat() as Record<string, unknown>[];
    expect(flat.some((s) => s.backgroundColor === "#c0392b")).toBe(true);
  });
});

describe("GhostButton", () => {
  it("fires, carries hitSlop for the 44pt target, and supports disabled", async () => {
    const onPress = vi.fn();
    const root = await render(<GhostButton label="Sign out instead" onPress={onPress} />);
    const btn = touchableByLabel(root, "Sign out instead");
    expect(btn.props.hitSlop).toEqual({ top: 12, bottom: 12, left: 12, right: 12 });
    expect(btn.props.accessibilityRole).toBe("button");
    await pressLabel(root, "Sign out instead");
    expect(onPress).toHaveBeenCalledTimes(1);

    const disabledRoot = await render(<GhostButton label="Sign out instead" onPress={onPress} disabled center={false} />);
    expect(touchableByLabel(disabledRoot, "Sign out instead").props.accessibilityState).toEqual({ disabled: true });
  });
});

describe("CrisisHelpButton", () => {
  it("is visually and semantically distinct from ordinary buttons", async () => {
    const onPress = vi.fn();
    const root = await render(<CrisisHelpButton onPress={onPress} />);
    expect(textOf(root)).toContain("Need help now? Crisis resources");
    const btn = touchableByLabel(root, "Need help now? Crisis resources");
    const flat = (btn.props.style as unknown[]).flat() as Record<string, unknown>[];
    expect(flat.some((s) => s.backgroundColor === "#242a38")).toBe(true); // helpBg, not card
    await pressLabel(root, "Need help now? Crisis resources");
    expect(onPress).toHaveBeenCalledTimes(1);
  });
});

describe("InlineStatus", () => {
  it("renders nothing without a message and a live-region line with one", async () => {
    const empty = await render(<InlineStatus message={null} />);
    expect(textOf(empty)).toBe("");

    const root = await render(<InlineStatus message="Saved ✓" />);
    expect(textOf(root)).toContain("Saved ✓");
    const node = root.root.findAll((n) => n.props.accessibilityLiveRegion === "polite")[0];
    expect(node.props.accessibilityLabel).toBe("Saved ✓");
  });

  it("the neutral tone uses muted color", async () => {
    const root = await render(<InlineStatus message="Saved — will sync when online" tone="neutral" />);
    const text = root.root.findAllByType(Text)[0];
    expect(text.props.style).toMatchObject({ color: "#8a91a3" });
  });
});

describe("NoticeChip", () => {
  it("renders the notice text with a text role", async () => {
    const root = await render(<NoticeChip text="Draft restored" />);
    expect(textOf(root)).toContain("Draft restored");
    const node = root.root.findAll((n) => n.props.accessibilityRole === "text")[0];
    expect(node.props.accessibilityLabel).toBe("Draft restored");
  });
});

describe("NavRow", () => {
  it("renders every item, distinguishes help, and caps label scaling", async () => {
    const nav = { a: vi.fn(), b: vi.fn() };
    const root = await render(
      <NavRow
        items={[
          { label: "Patterns", onPress: nav.a },
          { label: "Get help", onPress: nav.b, tone: "help", accessibilityLabel: "Get help — crisis resources" },
        ]}
      />,
    );
    await pressLabel(root, "Patterns");
    expect(nav.a).toHaveBeenCalledTimes(1);
    await pressLabel(root, "Get help");
    expect(nav.b).toHaveBeenCalledTimes(1);

    const labels = root.root.findAllByType(Text);
    for (const label of labels) expect(label.props.maxFontSizeMultiplier).toBe(1.3);
    const helpBtn = touchableByLabel(root, "Get help");
    expect(helpBtn.props.accessibilityLabel).toBe("Get help — crisis resources");
    const helpStyle = (helpBtn.props.style as unknown[]).flat() as Record<string, unknown>[];
    expect(helpStyle.some((s) => s.backgroundColor === "#242a38")).toBe(true);
    const helpText = labels.find((l) => l.props.children === "Get help");
    expect(helpText.props.style).toMatchObject({ fontWeight: "700" });
  });
});

describe("keyConsent persistence", () => {
  it("records, reads and clears the per-account acknowledgment", async () => {
    const storage = (await import("./helpers/storageMock")).default;
    storage.__reset();
    const { hasKeyShipConsent, recordKeyShipConsent, clearKeyShipConsent } = await import(
      "../src/components/keyConsent"
    );
    expect(await hasKeyShipConsent("user-1")).toBe(false);
    await recordKeyShipConsent("user-1");
    expect(await hasKeyShipConsent("user-1")).toBe(true);
    // Account-bound: another account is not covered.
    expect(await hasKeyShipConsent("user-2")).toBe(false);
    await clearKeyShipConsent("user-1");
    expect(await hasKeyShipConsent("user-1")).toBe(false);
  });
});

describe("components under the light theme", () => {
  it("buttons and nav render the light palette (useColorScheme honored)", async () => {
    const { useColorScheme } = await import("react-native");
    vi.mocked(useColorScheme).mockReturnValue("light");
    try {
      const { View } = await import("react-native");
      const root = await render(
        <View>
          <PrimaryButton label="Go" onPress={() => {}} />
          <NavRow items={[{ label: "Get help", onPress: () => {}, tone: "help" }]} />
        </View>,
      );
      const { allStyles } = await import("./helpers/rtr");
      const styles = allStyles(root);
      expect(styles.some((s) => s.backgroundColor === "#2f4bd0")).toBe(true); // light primary
      expect(styles.some((s) => s.backgroundColor === "#e4e9f5")).toBe(true); // light helpBg
      expect(styles.some((s) => s.backgroundColor === "#3b5bdb")).toBe(false); // no dark leakage
    } finally {
      vi.mocked(useColorScheme).mockReturnValue("dark");
    }
  });
});
