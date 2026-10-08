// @vitest-environment jsdom
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const render = vi.fn();
const createRoot = vi.fn(() => ({ render }));
const initTheme = vi.fn();
vi.mock("react-dom/client", () => ({ createRoot }));
vi.mock("../src/theme", () => ({ initTheme }));
vi.mock("../src/App", () => ({ App: () => <main>Journal</main> }));
vi.mock("../src/ErrorBoundary", () => ({
  ErrorBoundary: ({ children }: { children: React.ReactNode }) => children,
}));

describe("browser startup", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    document.body.innerHTML = '<div id="root"></div>';
  });
  afterEach(() => { document.body.replaceChildren(); });

  it("initializes live theme tracking and mounts the app inside its error boundary", async () => {
    await import("../src/main");
    expect(initTheme).toHaveBeenCalledOnce();
    expect(createRoot).toHaveBeenCalledWith(document.getElementById("root"));
    expect(render).toHaveBeenCalledOnce();
    const tree = render.mock.calls[0]![0] as React.ReactElement<{ children: React.ReactElement }>;
    const { ErrorBoundary } = await import("../src/ErrorBoundary");
    const { App } = await import("../src/App");
    expect(tree.type).toBe(ErrorBoundary);
    expect(tree.props.children.type).toBe(App);
  });

  it("reports the missing root before attempting to mount", async () => {
    document.body.replaceChildren();
    await expect(import("../src/main")).rejects.toThrow("#root missing in index.html");
    expect(createRoot).not.toHaveBeenCalled();
    expect(render).not.toHaveBeenCalled();
  });
});
