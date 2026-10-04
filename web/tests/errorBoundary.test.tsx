/** ErrorBoundary / ViewBoundary (deep audit 2026-09-29 HIGH): a render
 *  crash used to unmount the whole SPA — a white screen mid-journal, with
 *  the draft seal never running. These pins hold the two layers: calm
 *  fallback copy (localized), the draft seal firing on catch, and the
 *  view boundary recovering on navigation without a reload. */
// @ts-nocheck

import { describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";

vi.mock("../src/entryDraft", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/entryDraft")>();
  return { ...actual, preserveActiveDraft: vi.fn(async () => {}) };
});

import { preserveActiveDraft } from "../src/entryDraft";
import { ErrorBoundary, ViewBoundary } from "../src/ErrorBoundary";
import { render, textOf, press } from "./helpers/rtr";

const seal = vi.mocked(preserveActiveDraft);

function Boom(): React.JSX.Element {
  throw new Error("render exploded");
}

describe("ErrorBoundary (top level)", () => {
  it("catches a render crash and shows calm copy instead of a white screen", async () => {
    const root = await render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    const text = textOf(root);
    expect(text).toContain("Something went wrong");
    expect(text).toContain("Your words are still safe");
    // No raw error text leaks to the user.
    expect(text).not.toContain("render exploded");
  });
});

describe("ViewBoundary (per view)", () => {
  it("seals the active draft when it catches a crash", async () => {
    seal.mockClear();
    await render(
      <ViewBoundary resetKey="today">
        <Boom />
      </ViewBoundary>,
    );
    expect(seal).toHaveBeenCalled();
  });

  it("recovers via Try again without a reload", async () => {
    let explode = true;
    function MaybeBoom(): React.JSX.Element | null {
      if (explode) throw new Error("boom");
      return <p>recovered view</p>;
    }
    const root = await render(
      <ViewBoundary resetKey="today">
        <MaybeBoom />
      </ViewBoundary>,
    );
    expect(textOf(root)).toContain("Something went wrong");
    explode = false;
    await press(root, "Try again");
    expect(textOf(root)).toContain("recovered view");
  });

  it("resets when resetKey changes (navigation away from a crashed view)", async () => {
    let explode = true;
    function MaybeBoom(): React.JSX.Element | null {
      if (explode) throw new Error("boom");
      return <p>next view renders</p>;
    }
    function Harness({ resetKey }: { resetKey: string }) {
      return (
        <ViewBoundary resetKey={resetKey}>
          <MaybeBoom />
        </ViewBoundary>
      );
    }
    const root = await render(<Harness resetKey="today" />);
    expect(textOf(root)).toContain("Something went wrong");
    explode = false;
    await act(async () => {
      root.update(<Harness resetKey="history" />);
    });
    expect(textOf(root)).toContain("next view renders");
  });
});
