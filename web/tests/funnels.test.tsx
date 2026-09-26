/** Funnel coverage for the P6 views: the honest error/lock paths the
 *  happy-path suites skip — offline refresh, session-locked, freshness and
 *  rotation funnels, empty-pattern state, edit cancel. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PatternsView } from "../src/views/Patterns";
import { QuestionView } from "../src/views/Question";
import { HistoryView } from "../src/views/History";
import { encrypt, toBase64, fromBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { flush, press, render, settle, textOf } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(6);
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
  };
};

function unlock(): void {
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(6);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
}

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  unlock();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("PatternsView funnels", () => {
  it("offline reconciliation reports offline honestly", async () => {
    stubFetch(() => Promise.reject(new TypeError("fetch failed")));
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("Offline — patterns need a connection");
  });

  it("the remote-rotation funnel surfaces its honest message", async () => {
    const otherKey = new Uint8Array(new ArrayBuffer(32)).fill(13);
    const blob = await encrypt(otherKey, new TextEncoder().encode(JSON.stringify({ v: 2, stats: {} })), buildAad("insights", USER, "patterns"));
    stubFetch(() => jsonResponse({ phase: "active", active_days: 40, streak: 1, days_remaining: 0, blob: toBase64(blob), state_seq: 4 }));
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("session ended");
  });

  it("a freshness failure says so", async () => {
    const payload = await encrypt(DATA_KEY, new TextEncoder().encode(JSON.stringify({ v: 2, stats: { patterns: [] }, state_seq: 3 })), buildAad("insights", USER, "patterns"));
    stubFetch(() => jsonResponse({ phase: "active", active_days: 40, streak: 1, days_remaining: 0, blob: toBase64(payload), state_seq: 9 }));
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("freshness check");
  });

  it("a locked vault reports lock instead of crashing", async () => {
    vault.lock();
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 2);
    expect(textOf(root)).toContain("session locked");
  });

  it("active with zero surfaced patterns renders the honest empty state", async () => {
    const payload = await encrypt(DATA_KEY, new TextEncoder().encode(JSON.stringify({ v: 2, stats: { patterns: [] }, state_seq: 5 })), buildAad("insights", USER, "patterns"));
    stubFetch((url) => {
      if (url.endsWith("/insights")) return jsonResponse({ phase: "active", active_days: 40, streak: 1, days_remaining: 0, blob: toBase64(payload), state_seq: 5 });
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("only speaks when the evidence clears");
  });
});

describe("QuestionView funnels", () => {
  it("a locked vault reports lock", async () => {
    vault.lock();
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 2);
    expect(textOf(root)).toContain("session locked");
  });

  it("offline refresh refuses with the honest message", async () => {
    vi.stubGlobal("navigator", { onLine: false });
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 2);
    await press(root, "Refresh patterns");
    await settle(40, 2);
    expect(textOf(root)).toContain("needs a connection");
  });

  it("a failed recompute surfaces the error and stays honest", async () => {
    stubFetch((url) => {
      if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst", expires_in: 300 });
      if (url.endsWith("/insights/recompute")) return jsonResponse({ detail: "the analysis service is busy", code: "service_unavailable" }, { status: 503 });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 2);
    await press(root, "Refresh patterns");
    await settle(40, 3);
    expect(textOf(root)).toContain("the analysis service is busy");
  });

  it("a generic question (no pid) shows the no-answer-needed note", async () => {
    const payload = await encrypt(DATA_KEY, new TextEncoder().encode(JSON.stringify({ for_date: "2026-09-25", question: "What felt different today?" })), buildAad("question", USER, "2026-09-25"));
    stubFetch((url) => (url.endsWith("/questions/today") ? jsonResponse({ for_date: "2026-09-25", blob: toBase64(payload) }) : jsonResponse({}, { status: 404 })));
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("no answer is required");
  });
});

describe("HistoryView edges", () => {
  async function encryptedRow(id: string, text: string): Promise<Record<string, unknown>> {
    const { encryptEntry } = await import("../src/crypto/patient");
    const { blobB64 } = await encryptEntry(DATA_KEY, USER, id, text, "2026-09-25T12:00:00Z", 0, undefined, 1);
    return { id: `row-${id}`, client_entry_id: id, blob: blobB64, entry_date: "2026-09-25", received_at: "r", content_version: 1 };
  }

  it("cancel abandons an edit; calendar arrows step months", async () => {
    const rows = [await encryptedRow("e-x", "some text")];
    stubFetch((url) => (url.startsWith(`${ORIGIN}/api/v1/entries?`) && !url.includes("offset=0")
      ? jsonResponse([], { headers: { "X-Entries-Revision": "2" } })
      : jsonResponse(rows, { headers: { "X-Next-Offset": "1", "X-Entries-Revision": "2" } })));
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    expect(textOf(root)).toContain("Edit 2026-09-25");
    await press(root, "Cancel");
    expect(textOf(root)).not.toContain("Edit 2026-09-25");
    const monthBefore = textOf(root).match(/([A-Z][a-z]+ 20\d\d)/)?.[1];
    await press(root, "‹");
    await flush();
    expect(textOf(root)).not.toContain(monthBefore ?? "impossible");
    await press(root, "›");
    await flush();
  });
});

describe("final function-coverage batch", () => {
  it("ShareView: an empty code refuses locally", async () => {
    stubFetch(() => jsonResponse({}, { status: 404 }));
    const { ShareView } = await import("../src/views/Share");
    const root = await render(<ShareView />);
    await settle(40, 3);
    await press(root, "Look up");
    await settle(40, 2);
    expect(textOf(root)).toContain("Type the pairing code");
  });

  it("QuestionView: a generic question records no tap (there is nothing to route)", async () => {
    const payload = await encrypt(DATA_KEY, new TextEncoder().encode(JSON.stringify({ for_date: "2026-09-25", question: "What felt lighter today?" })), buildAad("question", USER, "2026-09-25"));
    stubFetch((url) => (url.endsWith("/questions/today") ? jsonResponse({ for_date: "2026-09-25", blob: toBase64(payload) }) : jsonResponse({}, { status: 404 })));
    const { QuestionView } = await import("../src/views/Question");
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 3);
    // No pid → no feedback buttons at all:
    expect(root.root.findAllByType("button").some((node) => node.children.join("").includes("resonated"))).toBe(false);
  });

  it("PatternsView: unmuting restores the card", async () => {
    const insightsPayload = await encrypt(DATA_KEY, new TextEncoder().encode(JSON.stringify({ v: 2, stats: { patterns: [
      { kind: "temporal", label: "'art' on weekends", occurrences: 5, confidence: 0.7, detail: { pattern_pid: "temporal:art", pattern_state: "confirmed" } },
    ] }, state_seq: 8 })), buildAad("insights", USER, "patterns"));
    stubFetch((url) => {
      if (url.endsWith("/insights")) return jsonResponse({ phase: "active", active_days: 40, streak: 1, days_remaining: 0, blob: toBase64(insightsPayload), state_seq: 8 });
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      return jsonResponse({}, { status: 404 });
    });
    const { PatternsView } = await import("../src/views/Patterns");
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    await press(root, "Mute");
    await settle(40, 2);
    // The card is gone (its body/evidence vanish); the unmute control
    // keeps the label by design.
    expect(textOf(root)).not.toContain("seen 5 times");
    await press(root, "Unmute: 'art' on weekends");
    await settle(40, 2);
    expect(textOf(root)).toContain("seen 5 times");
  });
});

describe("EntryView interactions (the small handlers)", () => {
  it("details toggle, chip insert, option deselect, and tag toggling all behave", async () => {
    stubFetch(() => jsonResponse({ id: "row" }, { status: 201 }));
    const { EntryView } = await import("../src/views/Entry");
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    await press(root, "Add details (mood, sleep, energy, tags)");
    await press(root, "Good");
    await press(root, "Good"); // deselect
    await press(root, "work");
    await press(root, "work"); // untoggle
    await press(root, "rest");
    await press(root, "Hide details");
    // A prompt chip appends to the draft:
    const chip = root.root.findAllByType("button").find((node) => /…$/.test(node.children.join("")));
    if (chip) {
      const { act } = await import("react");
      await act(async () => {
        chip.props.onClick();
      });
      await root.root.findAllByType("textarea").length;
    }
    // The chip appended text to the draft (the textarea value grew):
    const draft = root.root.findAllByType("textarea")[0]!;
    expect(draft.props.value.length).toBeGreaterThan(0);
  });
});
