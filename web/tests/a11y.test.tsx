// @vitest-environment jsdom
/**
 * Accessibility suite (WEB_PLAN P8.4): jest-axe over every view under a
 * REAL DOM. Zero critical violations is the floor. The real-DOM surface
 * also carries two security-adjacent contracts the react-test-renderer
 * suites cannot express (audit 2026-09-25): hostile decrypted journal text
 * must serialize as inert TEXT in an actual DOM, and the sensitive-pattern
 * accessible name (aria-label/title — what a screen reader hears) must
 * never carry the hidden phrase.
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
import { HistoryView } from "../src/views/History";
import { PatternsView } from "../src/views/Patterns";
import { MeasuresView } from "../src/views/Measures";
import { ShareView } from "../src/views/Share";
import { SettingsView } from "../src/views/Settings";
import { QuestionView } from "../src/views/Question";
import { EntryView } from "../src/views/Entry";
import { encryptEntry } from "../src/crypto/patient";
import { encrypt, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { vault } from "../src/vault";
import { resetTestState, stubFetch, installSession } from "./helpers/api";
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

describe("jest-axe over the in-app views (LOW e, audit 2026-09-26)", () => {
  // The suite used to stop at the pre-login surfaces; Measures, Share,
  // Settings, Question and Entry render under a signed-in, unlocked
  // session with terminal API failures (the beforeEach 404 stub) — their
  // honest error/empty states are part of the accessible surface.
  beforeEach(() => {
    installSession("user-1");
    vault.unlock(
      { authKey: new Uint8Array(new ArrayBuffer(32)), dataKey: new Uint8Array(new ArrayBuffer(32)).fill(9) },
      "user-1",
    );
  });

  it("the entry view has no critical violations", async () => {
    const html = await renderA11y(<EntryView onSaved={() => undefined} />);
    await expectNoCriticalViolations(html);
  });

  it("the measures view has no critical violations", async () => {
    const html = await renderA11y(<MeasuresView onCrisis={() => undefined} />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
    });
    await expectNoCriticalViolations(html);
  });

  it("the share view has no critical violations", async () => {
    const html = await renderA11y(<ShareView />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
    });
    await expectNoCriticalViolations(html);
  });

  it("the settings view (unknown-LLM branch) has no critical violations", async () => {
    const html = await renderA11y(<SettingsView onLockdown={() => undefined} />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
    });
    await expectNoCriticalViolations(html);
  });

  it("the question view (generic-question branch) has no critical violations", async () => {
    const html = await renderA11y(<QuestionView onRefreshed={() => undefined} />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
    });
    await expectNoCriticalViolations(html);
  });
});

describe("real-DOM serialization of hostile decrypted text (audit 2026-09-25)", () => {
  const HOSTILE = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script><a href="javascript:window.__pwned=3">x</a>`;

  it("renders inert: present as text, no script/img/anchor nodes, no execution", async () => {
    installSession("user-1");
    vault.unlock(
      { authKey: new Uint8Array(new ArrayBuffer(32)), dataKey: new Uint8Array(new ArrayBuffer(32)).fill(9) },
      "user-1",
    );
    const dataKey = new Uint8Array(new ArrayBuffer(32)).fill(9);
    const { blobB64 } = await encryptEntry(dataKey, "user-1", "e-hostile", HOSTILE, "2026-09-25T12:00:00Z", 0, undefined, 1);
    stubFetch((url) => {
      if (url.includes("/entries?")) {
        return new Response(
          JSON.stringify([{ id: "r1", client_entry_id: "e-hostile", blob: blobB64, entry_date: "2026-09-25", received_at: "r", content_version: 1 }]),
          { status: 200, headers: { "Content-Type": "application/json", "X-Entries-Revision": "1" } },
        );
      }
      return new Response(JSON.stringify({ detail: "unmatched" }), { status: 404 });
    });
    const html = await renderA11y(<HistoryView />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
    });
    // The payload IS in the document — as serialized TEXT, verbatim.
    expect(html.textContent).toContain("<img src=x onerror=");
    // And nothing parsed as markup, nothing executed, no javascript: href.
    expect(html.querySelectorAll("script")).toHaveLength(0);
    expect(html.querySelectorAll("img")).toHaveLength(0);
    expect(html.querySelectorAll("iframe")).toHaveLength(0);
    expect(html.querySelectorAll("a[href]")).toHaveLength(0);
    expect((globalThis as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("the sensitive-pattern accessible-name contract (audit 2026-09-25)", () => {
  it("no accessible name in the DOM carries the hidden phrase", async () => {
    const USER = "user-1";
    const dataKey = new Uint8Array(new ArrayBuffer(32)).fill(6);
    installSession(USER);
    vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)), dataKey }, USER);
    const payload = JSON.stringify({
      v: 2,
      stats: { patterns: [{ kind: "rumination", label: "I want to disappear forever", occurrences: 7, confidence: 0.9, detail: { pattern_pid: "rumination:x", pattern_state: "confirmed", sensitive: true } }] },
      state_seq: 3,
    });
    const blob = await encrypt(dataKey, new TextEncoder().encode(payload), buildAad("insights", USER, "patterns"));
    stubFetch((url) => {
      if (url.endsWith("/insights") && !url.includes("recompute")) {
        return new Response(
          JSON.stringify({ phase: "active", active_days: 40, streak: 3, days_remaining: 0, blob: toBase64(blob), state_seq: 3 }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ detail: "unmatched" }), { status: 404 });
    });
    const html = await renderA11y(<PatternsView onCrisis={() => undefined} />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
    });
    // What is SHOWN: the calm non-quoting card.
    expect(html.textContent).toContain("A difficult thought has been returning");
    // What a screen reader would hear (every accessible-name channel) must
    // match what is shown — never the hidden phrase.
    for (const element of html.querySelectorAll("[aria-label], [title], [aria-labelledby]")) {
      const name = `${element.getAttribute("aria-label") ?? ""} ${element.getAttribute("title") ?? ""}`;
      expect(name).not.toContain("disappear");
    }
    expect(html.textContent).not.toContain("disappear");
  });
});
