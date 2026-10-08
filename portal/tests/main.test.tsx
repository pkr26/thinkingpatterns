// @vitest-environment jsdom
import { act } from "react";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ fail: false, roots: [] as Root[] }));
vi.mock("../src/App", () => ({
  App: () => {
    if (state.fail) throw new Error("view failed during startup");
    return <p>Therapist workspace is ready</p>;
  },
}));
vi.mock("react-dom/client", async importOriginal => {
  const actual = await importOriginal<typeof import("react-dom/client")>();
  return {
    ...actual,
    createRoot: (...args: Parameters<typeof actual.createRoot>) => {
      const root = actual.createRoot(...args);
      state.roots.push(root);
      return root;
    },
  };
});

beforeEach(() => {
  vi.resetModules();
  state.fail = false;
  document.body.innerHTML = '<div id="root"></div>';
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(async () => {
  await act(async () => { for (const root of state.roots.splice(0)) root.unmount(); });
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

it("starts the therapist workspace in the page root", async () => {
  await act(async () => { await import("../src/main"); });
  expect(document.getElementById("root")?.textContent).toBe("Therapist workspace is ready");
});

it("reports a missing page root before attempting to render", async () => {
  document.body.innerHTML = "";
  await expect(import("../src/main")).rejects.toThrow("#root missing in index.html");
  expect(state.roots).toHaveLength(0);
});

it("shows the recoverable startup error surface when the app fails to render", async () => {
  state.fail = true;
  vi.spyOn(console, "error").mockImplementation(() => {});
  await act(async () => { await import("../src/main"); });
  expect(document.querySelector('[role="alert"]')?.textContent).toContain("Saved records stay encrypted");
  expect(document.querySelector("button")?.textContent).toBe("Reload the page");
});
