/** MeasuresView load-path hardening (audit 2026-09-26): M-W1 — every
 *  terminal failure (500/429/409) must leave the screen honest with the
 *  history emptied, never a permanent "Loading…" wedge; LOW a — the walk's
 *  20-page cap gets the entries-walk terminal probe, so a hostile server
 *  feeding endless continuations surfaces a loud error instead of a
 *  silent stop. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MeasuresView } from "../src/views/Measures";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { render, settle, textOf } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const USER = "user-1";

const memoryBackend = (): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
    async keys() {
      return [...map.keys()];
    },
  };
};

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(4);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("MeasuresView terminal failures (M-W1, audit 2026-09-26)", () => {
  it("a 500 surfaces an honest error and empties the history — never a permanent Loading wedge", async () => {
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse({ detail: "database on fire" }, { status: 500 });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 4);
    expect(textOf(root)).toContain("database on fire");
    // Unstuck: the loading state resolved to the honest empty history.
    expect(textOf(root)).not.toContain("Loading…");
    expect(textOf(root)).toContain("Nothing recorded yet.");
  });

  it("a 429 (throttled) and a 409 (collection changed mid-walk) also resolve honestly", async () => {
    for (const status of [429, 409]) {
      stubFetch((url) => {
        if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse({ detail: `slow down (${status})` }, { status });
        return jsonResponse({}, { status: 404 });
      });
      const root = await render(<MeasuresView onCrisis={() => undefined} />);
      await settle(60, 4);
      expect(textOf(root)).toContain(`slow down (${status})`);
      expect(textOf(root)).not.toContain("Loading…");
    }
  });
});

describe("MeasuresView walk limit (LOW a, audit 2026-09-26)", () => {
  it("a hostile server with endless continuations hits the 21st-page probe and a loud error, not a silent stop", async () => {
    let pages = 0;
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        pages += 1;
        const offset = new URL(url, ORIGIN).searchParams.get("offset") ?? "0";
        // One (garbage-blob) row per page and a continuation that never
        // ends — exactly the lying-server shape the entries walk defends
        // against.
        return jsonResponse(
          [{ id: `r${pages}`, client_measure_id: `m-${pages}`, blob: "QUJD", measure_date: "2026-09-01", received_at: "r" }],
          { headers: { "X-Next-Offset": String(Number(offset) + 1), "X-Measures-Revision": "9" } },
        );
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 8);
    // 20 walk pages + the one terminal probe:
    expect(pages).toBe(21);
    expect(textOf(root)).toContain("safe limit");
    expect(textOf(root)).not.toContain("Loading…");
  });

  it("a clean single page never probes again (the probe runs only at the cap)", async () => {
    let pages = 0;
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        pages += 1;
        return jsonResponse([], { headers: { "X-Measures-Revision": "3" } });
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 4);
    expect(pages).toBe(1);
    expect(textOf(root)).toContain("Nothing recorded yet.");
    expect(textOf(root)).not.toContain("safe limit");
  });
});
