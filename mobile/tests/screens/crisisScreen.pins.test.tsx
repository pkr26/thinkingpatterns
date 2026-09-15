/**
 * Deep-mutation pins for CrisisScreen (2026-09-15 Stryker campaign).
 *
 * Every block kills specific surviving mutant classes:
 *  - the three /[-_]([A-Za-z]{2})\b/ regex mutants (single-letter capture,
 *    negated separator class, negated letter class) via exact "en-US"→"US"
 *    and "en_GB"→"GB" parses,
 *  - the `effectiveRegion === null → false` mutant (unknown region must keep
 *    the US-first layout on the most safety-critical screen),
 *  - every dropped/emptied style ARRAY and overlay OBJECT on its exact node
 *    (theme colors, the 44pt touch targets, the contentContainer padding),
 *  - every StyleSheet base object and its fontWeight/flexDirection string
 *    literals via exact-object assertions.
 *
 * Only provably-equivalent mutant left to a source suppression: the
 * match?.[1] optional chain (see src/screens/CrisisScreen.tsx).
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, ScrollView, Text, View } from "react-native";

// Same layered react-native mock as crisisScreen.test.tsx: controllable
// Platform.OS and Linking.openURL on top of the rnMock primitives.
const mocks = vi.hoisted(() => ({
  openURL: vi.fn(async (_url: string) => true),
  platform: { os: "ios" as "ios" | "android" },
}));
vi.mock("react-native", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-native")>();
  return {
    ...actual,
    Platform: {
      OS: mocks.platform.os,
      select: <T,>(opts: { ios?: T; android?: T; native?: T; default?: T }): T => {
        const perPlatform = mocks.platform.os === "ios" ? opts.ios : opts.android;
        return perPlatform ?? opts.native ?? (opts.default as T);
      },
    },
    Linking: { openURL: mocks.openURL },
  };
});

const { CrisisScreen, deviceRegion } = await import("../../src/screens/CrisisScreen");
const { render, flush, textOf, allText, allStyles, expectStyle, touchableByLabel } = await import("../helpers/rtr");

/** The dark theme's exact literals (theme.test pins the palette itself). */
const T = {
  bg: "#0f1115",
  card: "#1a1e26",
  border: "#222733",
  text: "#e8eaf0",
  body: "#b6bdc9",
  muted: "#8a91a3",
  accent: "#7f9bff",
  radiusLg: 12,
  minTouch: 44,
  xl: 20,
};

/** StyleSheet.create is the identity in the mock, so these ARE the literals
 *  shipped in StyleSheet.create at the bottom of CrisisScreen.tsx. */
const styles = {
  container: { flex: 1 },
  headline: { fontSize: 20, fontWeight: "700", lineHeight: 27 },
  body: { fontSize: 15, lineHeight: 22 },
  action: { flexDirection: "row", alignItems: "center", padding: 16, gap: 12 },
  actionLabel: { fontSize: 16, fontWeight: "700" },
  actionDetail: { marginTop: 3, lineHeight: 18 },
  actionGo: { fontSize: 14, fontWeight: "700" },
  link: { padding: 4 },
  linkText: { fontSize: 15, fontWeight: "600" },
  divider: { height: 1, marginTop: 6 },
  note: { fontSize: 12, lineHeight: 18 },
};

const flat = (children: unknown): string => {
  if (typeof children === "string") return children;
  if (Array.isArray(children)) return children.map(flat).join("");
  return "";
};

/** The style ARRAY of the Text node whose flattened text contains
 *  `fragment` — pins the themed overlay to ITS node, so a dropped overlay
 *  ({}) or emptied array ([]) on that line fails here even when a sibling
 *  still renders the same color. */
const styleArrayOfText = (root: any, fragment: string): unknown[] => {
  const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
  if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}: ${allText(root).join(" | ")}`);
  const style = node.props.style;
  return Array.isArray(style) ? style : [style];
};

beforeEach(() => {
  mocks.openURL.mockReset();
  mocks.openURL.mockImplementation(async () => true);
  Alert.alert.mockClear();
  mocks.platform.os = "ios";
});

describe("CrisisScreen pins: deviceRegion regex (exact two-letter capture)", () => {
  it("parses hyphen and underscore locales to the exact uppercased region", async () => {
    const original = Intl.DateTimeFormat;
    try {
      const withLocale = (locale: string) =>
        vi.stubGlobal("Intl", {
          ...Intl,
          DateTimeFormat: () => ({ resolvedOptions: () => ({ locale }) }),
        });
      // A one-letter capture, [^-_] as the separator class, or [^A-Za-z] as
      // the capture class all fail to match "en-US" — each regex mutant
      // returns null here instead of "US".
      withLocale("en-US");
      expect(deviceRegion()).toBe("US");
      withLocale("en_GB");
      expect(deviceRegion()).toBe("GB");
    } finally {
      vi.stubGlobal("Intl", original);
    }
  });
});

describe("CrisisScreen pins: unknown region keeps the US-first layout", () => {
  it("a locale with no region subtag renders the US layout, not the non-US one", async () => {
    const original = Intl.DateTimeFormat;
    try {
      vi.stubGlobal("Intl", {
        ...Intl,
        DateTimeFormat: () => ({ resolvedOptions: () => ({ locale: "en" }) }),
      });
      const root = await render(<CrisisScreen />);
      await flush();
      const text = textOf(root);
      // effectiveRegion === null must keep usFirst TRUE (mutant: `=== null`
      // -> false flips to the non-US layout).
      expect(text).toContain("These are US services");
      expect(text).not.toContain("doesn't look like the US");
      expect(allText(root)).not.toContain("Call 911 (US)");
    } finally {
      vi.stubGlobal("Intl", original);
    }
  });
});

describe("CrisisScreen pins: the full StyleSheet contract", () => {
  it("renders every base style object exactly ({} and string mutants die)", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    for (const base of Object.values(styles)) {
      expectStyle(root, base);
    }
    // None of the emptied {} placeholders may appear anywhere instead.
    expect(allStyles(root)).not.toContainEqual({});
  });

  it("the ScrollView carries [container, bg-overlay] and the exact contentContainer padding", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    const scroll = root.root.findByType(ScrollView);
    expect(scroll.props.style).toEqual([styles.container, { backgroundColor: T.bg }]);
    expect(scroll.props.contentContainerStyle).toEqual({ padding: T.xl, gap: 14 });
  });

  it("every ActionButton carries [action, themed card overlay] on its own touchable", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    const overlay = { backgroundColor: T.card, borderRadius: T.radiusLg, minHeight: T.minTouch };
    for (const label of ["Call or text 988", "Text HOME to 741741", "Chat online at 988lifeline.org", "Call 911"]) {
      expect(touchableByLabel(root, label).props.style).toEqual([styles.action, overlay]);
      // The label/detail column is the flex:1 View directly inside.
      const inner = touchableByLabel(root, label).findAllByType(View);
      expect(inner.map((n) => n.props.style)).toContainEqual({ flex: 1 });
    }
  });

  it("the helpline link carries [link, {minHeight, justifyContent: center}] and its exact hitSlop", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    const link = touchableByLabel(root, "Open findahelpline.com");
    expect(link.props.style).toEqual([styles.link, { minHeight: T.minTouch, justifyContent: "center" }]);
    expect(link.props.hitSlop).toEqual({ top: 12, bottom: 12, left: 12, right: 12 });
    expect(link.props.accessibilityRole).toBe("link");
    expect(link.props.accessibilityLabel).toBe("Open findahelpline.com — crisis lines worldwide");
  });

  it("the divider View carries [divider, border-colored overlay]", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    const divider = root.root
      .findAllByType(View)
      .find((n) => Array.isArray(n.props.style) && JSON.stringify(n.props.style[0]) === JSON.stringify(styles.divider));
    expect(divider).toBeDefined();
    expect(divider.props.style).toEqual([styles.divider, { backgroundColor: T.border }]);
  });
});

describe("CrisisScreen pins: themed text overlays pinned to their own nodes", () => {
  it("US layout: headline, both static bodies, the US note and the disclaimer note", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    expect(styleArrayOfText(root, "If you are thinking about harming yourself")).toEqual([
      styles.headline,
      { color: T.text },
    ]);
    expect(styleArrayOfText(root, "Please reach out right now")).toEqual([styles.body, { color: T.body }]);
    expect(styleArrayOfText(root, "What to expect when you call or text")).toEqual([styles.body, { color: T.body }]);
    expect(styleArrayOfText(root, "These are US services")).toEqual([styles.body, { color: T.body }]);
    expect(styleArrayOfText(root, "MindPattern is a journal")).toEqual([styles.note, { color: T.muted }]);
    expect(styleArrayOfText(root, "Open findahelpline.com")).toEqual([styles.linkText, { color: T.accent }]);
  });

  it("non-US layout: both region bodies carry the same body-color overlays", async () => {
    const root = await render(<CrisisScreen region="DE" />);
    await flush();
    expect(styleArrayOfText(root, "doesn't look like the US")).toEqual([styles.body, { color: T.body }]);
    expect(styleArrayOfText(root, "In the US, these are the national services")).toEqual([styles.body, { color: T.body }]);
  });

  it("every action button's label, detail and Go texts carry their own overlays", async () => {
    const root = await render(<CrisisScreen />);
    await flush();
    expect(styleArrayOfText(root, "Call or text 988")).toEqual([styles.actionLabel, { color: T.text }]);
    expect(styleArrayOfText(root, "988 Suicide & Crisis Lifeline")).toEqual([
      styles.actionDetail,
      { color: T.muted, fontSize: 13 },
    ]);
    expect(styleArrayOfText(root, "Crisis Text Line")).toEqual([styles.actionDetail, { color: T.muted, fontSize: 13 }]);
    expect(styleArrayOfText(root, "Go")).toEqual([styles.actionGo, { color: T.accent }]);
  });
});
