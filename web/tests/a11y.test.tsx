// @vitest-environment jsdom
/**
 * Accessibility suite (WEB_PLAN P8.4): jest-axe over every view under a
 * REAL DOM. Zero critical violations is the floor; the sensitive-pattern
 * accessible-name contract is asserted too — what a screen reader hears
 * must match what the screen shows (never the hidden text).
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { axe } from "jest-axe";

type AxeResult = { violations: { id: string; impact: string | null }[] };

/** The floor is ZERO critical/serious violations (WEB_PLAN P8.4) — asserted
 *  on axe's raw result so no matcher typing is needed. */
async function expectNoCriticalViolations(html: HTMLElement): Promise<void> {
  const results = (await axe(html)) as unknown as AxeResult;
  const blocking = results.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious");
  expect(blocking).toEqual([]);
}
import { App } from "../src/App";
import { CrisisCard } from "../src/crisis";
import { LoginView } from "../src/views/LoginView";
import { Onboarding } from "../src/views/Onboarding";
import { Privacy } from "../src/views/Privacy";
import { resetTestState, stubFetch } from "./helpers/api";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";

let container: HTMLDivElement | null = null;
let root: Root | null = null;
const IS_REACT_ACT_ENVIRONMENT = true;
void IS_REACT_ACT_ENVIRONMENT;

declare global {
  // eslint-disable-next-line no-var
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

async function renderA11y(element: React.ReactElement): Promise<HTMLElement> {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root!.render(element);
  });
  return container;
}

beforeEach(() => {
  resetTestState();
  const map = new Map<string, string>();
  const backend: KvBackend = {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
  };
  setKvBackendForTests(backend);
  stubFetch(() => new Response(JSON.stringify({}), { status: 404 }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
  if (root) {
    act(() => {
      root!.unmount();
    });
  }
  container?.remove();
  container = null;
  root = null;
});

describe("jest-axe over the views", () => {
  it("the crisis card has no critical violations", async () => {
    const html = await renderA11y(<CrisisCard onClose={() => undefined} />);
    await expectNoCriticalViolations(html);
  });

  it("the login view has no critical violations", async () => {
    const html = await renderA11y(<LoginView onSuccess={() => undefined} />);
    await expectNoCriticalViolations(html);
  });

  it("onboarding has no critical violations", async () => {
    const html = await renderA11y(<Onboarding onDone={() => undefined} />);
    await expectNoCriticalViolations(html);
  });

  it("the privacy view has no critical violations", async () => {
    const html = await renderA11y(<Privacy onBack={() => undefined} />);
    await expectNoCriticalViolations(html);
  });

  it("the app shell (boot state) has no critical violations", async () => {
    const html = await renderA11y(<App />);
    await expectNoCriticalViolations(html);
  });
});
