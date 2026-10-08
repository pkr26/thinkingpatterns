// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { ErrorBoundary } from "../src/ErrorBoundary";

afterEach(() => { vi.restoreAllMocks(); document.body.replaceChildren(); });

it("renders the crash recovery panel with readable width, spacing and page padding", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  function Boom(): React.JSX.Element { throw new Error("boom"); }
  const container = document.createElement("div");
  document.body.append(container);
  const root = createRoot(container);
  try {
    await act(async () => { root.render(<ErrorBoundary><Boom /></ErrorBoundary>); });
    const page = container.querySelector("main")!;
    expect(page).not.toBeNull();
    const layout = getComputedStyle(page);
    expect(layout.maxWidth).toBe("560px");
    expect(layout.margin).toBe(`${window.innerHeight / 10}px auto`);
    expect(page.style.padding).toBe("0 var(--space-4)");
    const action = container.querySelector("button")!;
    expect(action.textContent).toBe("Reload the page");
    expect(action.parentElement!.style.marginTop).toBe("var(--space-3)");
  } finally {
    await act(async () => { root.unmount(); });
  }
});
