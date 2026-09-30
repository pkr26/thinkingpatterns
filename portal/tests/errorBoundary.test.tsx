/** ErrorBoundary / ViewBoundary (deep audit 2026-09-29 HIGH): a render
 *  crash used to unmount the whole portal mid-review. Pins: calm fallback
 *  copy (no raw error text), the view boundary's recovery on retry, and
 *  reset on view change. */
import { describe, expect, it } from "vitest";
import React from "react";
import { act } from "react";

import { ErrorBoundary, ViewBoundary } from "../src/ErrorBoundary";
import { render, textOf, press } from "./helpers/rtr";

function Boom(): React.JSX.Element {
  throw new Error("render exploded");
}

describe("ErrorBoundary (top level)", () => {
  it("catches a render crash and shows calm copy", async () => {
    const root = await render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    const text = textOf(root);
    expect(text).toContain("Something went wrong");
    expect(text).toContain("Reloading usually fixes it");
    expect(text).not.toContain("render exploded");
  });
});

describe("ViewBoundary (per view)", () => {
  it("recovers via Try again without a reload", async () => {
    let explode = true;
    function MaybeBoom(): React.JSX.Element | null {
      if (explode) throw new Error("boom");
      return <p>recovered view</p>;
    }
    const root = await render(
      <ViewBoundary resetKey="patient">
        <MaybeBoom />
      </ViewBoundary>,
    );
    expect(textOf(root)).toContain("Something went wrong");
    explode = false;
    await press(root, "Try again");
    expect(textOf(root)).toContain("recovered view");
  });

  it("resets when resetKey changes (back to caselist from a crashed chart)", async () => {
    let explode = true;
    function MaybeBoom(): React.JSX.Element | null {
      if (explode) throw new Error("boom");
      return <p>caselist renders</p>;
    }
    function Harness({ resetKey }: { resetKey: string }) {
      return (
        <ViewBoundary resetKey={resetKey}>
          <MaybeBoom />
        </ViewBoundary>
      );
    }
    const root = await render(<Harness resetKey="patient" />);
    expect(textOf(root)).toContain("Something went wrong");
    explode = false;
    await act(async () => {
      root.update(<Harness resetKey="patients" />);
    });
    expect(textOf(root)).toContain("caselist renders");
  });
});
