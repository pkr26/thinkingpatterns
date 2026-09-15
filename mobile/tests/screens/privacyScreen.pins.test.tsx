/**
 * Deep-mutation pins for PrivacyScreen (2026-09-15 Stryker campaign).
 *
 * The screen is static content, so every survivor is a style mutant: base
 * StyleSheet entries, themed overlays, and the style arrays that combine
 * them. Each is pinned to its exact node with exact-array equality (the
 * global expectStyle matcher only proves SOME node renders an object, which
 * is why the overlays survived).
 */
// @ts-nocheck

import { describe, expect, it, vi } from "vitest";
import React from "react";
import { ScrollView, Text, View } from "react-native";

const { PrivacyScreen } = await import("../../src/screens/PrivacyScreen");
const { render, flush, allText } = await import("../helpers/rtr");

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

describe("PrivacyScreen pins: the full per-node style contract", () => {
  it("scroll surface, headline, sections and footer carry their exact styles", async () => {
    const root = await render(<PrivacyScreen navigation={{ navigate: vi.fn() } as never} />);
    await flush();

    const scroll = root.root.findAllByType(ScrollView)[0];
    expect(scroll.props.style).toEqual([{ flex: 1 }, { backgroundColor: "#0f1115" }]);
    expect(scroll.props.contentContainerStyle).toEqual({ padding: 20, gap: 14 });

    expect(textNode(root, "Privacy, in plain language").props.style).toEqual(
      [{ fontSize: 22, fontWeight: "700", lineHeight: 29 }, { color: "#e8eaf0" }],
    );

    // Exactly five section stacks, each with its gap-only container style.
    const sections = root.root.findAllByType(View);
    expect(sections).toHaveLength(5);
    for (const section of sections) expect(section.props.style).toEqual({ gap: 6 });

    const titles = [
      "What is encrypted",
      "What the server sees",
      "The one exception: pattern analysis",
      "Optional AI analysis",
      "Deleting your data",
    ];
    for (const title of titles) {
      expect(textNode(root, title).props.style).toEqual(
        [{ fontSize: 12, fontWeight: "700", letterSpacing: 1.5, textTransform: "uppercase" }, { color: "#7f9bff" }],
      );
    }
    const bodies = [
      "Everything you write",
      "Your username, the calendar dates",
      "Patterns are computed by the server",
      "Off by default for every account",
      "Deleting your account removes",
    ];
    for (const body of bodies) {
      expect(textNode(root, (s) => s.startsWith(body)).props.style).toEqual(
        [{ fontSize: 15, lineHeight: 22 }, { color: "#b6bdc9" }],
      );
    }

    expect(textNode(root, (s) => s.startsWith("This policy lives inside the app")).props.style).toEqual(
      { color: "#8a91a3", fontSize: 12, lineHeight: 17 },
    );
  });
});
