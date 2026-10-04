/** Span-level phrase highlighting (deep audit 2026-09-29, HIGH): the
 *  drilldown used to <mark> the WHOLE entry whenever the pattern label
 *  appeared anywhere in it — highlighting everything is highlighting
 *  nothing. These pins hold the normalized-match → raw-offset mapping and
 *  the mark-only-the-span rendering. */
import { describe, expect, it } from "vitest";
import React from "react";

import { HighlightedEntry, rawMatchSpans } from "../src/views/PatientView";
import { render } from "./helpers/rtr";

describe("rawMatchSpans", () => {
  it("maps a normalized match back to raw offsets (punctuation survives)", async () => {
    // The label arrives as the engine formed it ("can't" folds to "can t"
    // on BOTH sides — apostrophes become spaces, never deleted).
    const text = "Long day. Can't sleep, mind won't stop. Tomorrow maybe better.";
    const spans = rawMatchSpans(text, "can't sleep, mind won't stop");
    expect(spans.length).toBe(1);
    const [a, b] = spans[0]!;
    expect(text.slice(a, b)).toBe("Can't sleep, mind won't stop");
  });

  it("marks every occurrence, not just the first", async () => {
    const text = "one quiet phrase here and one quiet phrase again";
    const spans = rawMatchSpans(text, "quiet phrase");
    expect(spans.length).toBe(2);
    expect(text.slice(spans[0]![0], spans[0]![1])).toBe("quiet phrase");
    expect(text.slice(spans[1]![0], spans[1]![1])).toBe("quiet phrase");
  });

  it("folds accents on the label side (café labels match café entries)", async () => {
    const text = "una tarde en el café con amigos";
    const spans = rawMatchSpans(text, "cafe");
    expect(spans.length).toBe(1);
    expect(text.slice(spans[0]![0], spans[0]![1])).toBe("café");
  });

  it("returns nothing when the phrase is absent or the label folds empty", async () => {
    expect(rawMatchSpans("nothing relevant here", "quiet phrase")).toEqual([]);
    expect(rawMatchSpans("anything at all", "!!!")).toEqual([]);
  });
});

describe("HighlightedEntry rendering", () => {
  async function markTexts(node: React.ReactElement): Promise<string[]> {
    const renderer = await render(node);
    const marks = renderer.root.findAllByType("mark");
    return marks.map((m) => (m.props as { children: string }).children);
  }

  it("wraps ONLY the matched span in <mark>, keeping the rest plain", async () => {
    const text = "Morning was fine but the can't sleep, mind won't stop came back at night.";
    const marks = await markTexts(<HighlightedEntry text={text} label="can't sleep, mind won't stop" />);
    expect(marks).toEqual(["can't sleep, mind won't stop"]);
  });

  it("renders one mark per occurrence", async () => {
    const marks = await markTexts(
      <HighlightedEntry text="guitar morning, then work, then guitar night" label="guitar" />,
    );
    expect(marks).toEqual(["guitar", "guitar"]);
  });

  it("plain text passes through untouched when there is no match", async () => {
    const marks = await markTexts(<HighlightedEntry text="an ordinary entry" label="absent phrase" />);
    expect(marks).toEqual([]);
  });
});
