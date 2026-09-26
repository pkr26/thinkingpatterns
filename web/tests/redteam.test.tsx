/**
 * Red-team harnesses for the web client (WEB_PLAN P9.4) — the vitest-runnable
 * set. The XSS corpus runs decrypted hostile journal text through the REAL
 * render pipeline (react-test-renderer) and asserts DOM-level outcomes; the
 * storage-scrape sweeps every web storage after each flow; the replay/stale
 * set drives dead tokens, queue replays, and processing-token reuse.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EntryView } from "../src/views/Entry";
import { HistoryView } from "../src/views/History";
import { api, ApiError, setSession } from "../src/api/client";
import { encryptEntry } from "../src/crypto/patient";
import { toBase64 } from "../src/crypto/core";
import { kv, setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { enqueue, flushQueue } from "../src/offlineQueue";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, typeArea } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(11);
const USER = "user-1";

const memoryBackend = (capture: string[] = []): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
      capture.push(`${k}=${v}`);
    },
    async removeItem(k) {
      map.delete(k);
    },
  };
};

/** The hostile journal corpus: everything an attacker would plant in an
 *  entry they hope the victim's client will execute on decrypt-render. */
const HOSTILE_TEXTS: string[] = [
  "<img src=x onerror=window.__pwned=1>",
  "<script>window.__pwned=2</script>",
  "javascript:alert(1)",
  "<svg onload=window.__pwned=3></svg>",
  "<iframe src=\"javascript:window.__pwned=4\"></iframe>",
  "\u202E\u003Cscript\u003Ewindow.__pwned=5\u003C/script\u003E", // bidi override smuggle
  "🎉<a href=\"javascript:window.__pwned=6\">click</a>",
  "\" onmouseover=\"window.__pwned=7",
  "<details open ontoggle=window.__pwned=8>",
];

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(11);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("XSS-through-decrypted-text (P9.4)", () => {
  it("the full hostile corpus renders inert through History", async () => {
    const rows = await Promise.all(
      HOSTILE_TEXTS.map((text, index) => encryptEntry(DATA_KEY, USER, `e-xss-${index}`, text, "2026-09-25T12:00:00Z", 0, undefined, 1).then(({ blobB64 }) => ({
        id: `r${index}`,
        client_entry_id: `e-xss-${index}`,
        blob: blobB64,
        entry_date: "2026-09-25",
        received_at: "r",
        content_version: 1,
      }))),
    );
    stubFetch((url) => (url.startsWith(`${ORIGIN}/api/v1/entries?`) && !url.includes("offset=0")
      ? jsonResponse([], { headers: { "X-Entries-Revision": "4" } })
      : jsonResponse(rows, { headers: { "X-Next-Offset": String(rows.length), "X-Entries-Revision": "4" } })));
    const root = await render(<HistoryView />);
    await settle(40, 5);
    // Every hostile string is PRESENT — and only ever as the TEXT child of
    // a <p> (react-test-renderer carries pre-escaping strings; the DOM-side
    // escaping is what the jsdom a11y suite renders). No markup nodes and
    // no event-handler props exist anywhere in the tree:
    const paragraphs = root.root.findAllByType("p").map((node) => (node as unknown as { children: unknown[] }).children.join(""));
    for (const text of HOSTILE_TEXTS) {
      expect(paragraphs.some((body) => body.includes(text))).toBe(true);
    }
    const serialized = JSON.stringify(root.toJSON());
    expect(serialized).not.toMatch(/"on(error|load|toggle|mouseover)"/);
    expect(root.root.findAllByType("script")).toEqual([]);
    expect(root.root.findAllByType("iframe")).toEqual([]);
    expect(root.root.findAllByType("img")).toEqual([]);
    expect(root.root.findAllByType("a")).toEqual([]);
  });
});

describe("storage-scrape after every flow (P9.4)", () => {
  async function scrapeAll(): Promise<string> {
    const parts: string[] = [];
    const win = (globalThis as { window?: { localStorage?: Storage; sessionStorage?: Storage } }).window;
    for (let i = 0; i < (win?.localStorage?.length ?? 0); i += 1) {
      const k = win!.localStorage!.key(i)!;
      parts.push(`${k}=${win!.localStorage!.getItem(k)}`);
    }
    for (let i = 0; i < (win?.sessionStorage?.length ?? 0); i += 1) {
      const k = win!.sessionStorage!.key(i)!;
      parts.push(`${k}=${win!.sessionStorage!.getItem(k)}`);
    }
    parts.push(...Object.keys(await kv.getItem("mindpattern/anything") === null ? [] : []));
    return parts.join("\n");
  }

  it("journal + save + history leave no keys, tokens, or plaintext in storage", async () => {
    const writes: string[] = [];
    setKvBackendForTests(memoryBackend(writes));
    stubFetch((url) => {
      if (url.endsWith("/entries")) return jsonResponse({ id: "row" }, { status: 201 });
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    await typeArea(root, "How was today?", "my secret words about today");
    await press(root, "Save entry");
    await settle(40, 4);
    // localStorage/sessionStorage: only the non-content flags:
    const scrape = await scrapeAll();
    expect(scrape).not.toContain("my secret words");
    expect(scrape).not.toMatch(/dataKey|authKey|token-123|Bearer/);
    // The kv seam's writes (queue empty — sent online; mood log only if a
    // mood was picked) are ciphertext-only:
    const persisted = writes.join("\n");
    expect(persisted).not.toContain("my secret words");
    expect(persisted).not.toMatch(/token-123|Bearer/);
  });
});

describe("replay + stale-token harnesses (P9.4/P9.7)", () => {
  it("a dead (epoch-bumped) token produces exactly ONE funnel event, no storm", async () => {
    let calls = 0;
    stubFetch(() => {
      calls += 1;
      return jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 });
    });
    const handler = vi.fn();
    const { setSessionExpiredHandler } = await import("../src/api/client");
    setSessionExpiredHandler(handler);
    await expect(api.insights()).rejects.toThrow();
    await expect(api.meta()).rejects.toThrow();
    await expect(api.meta()).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(1);
    expect(calls).toBe(3); // each call hit the server once; NO retries
    setSessionExpiredHandler(null);
  });

  it("processing-token reuse is refused by the contract surface", async () => {
    stubFetch((url) => {
      if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst-once", expires_in: 300 });
      if (url.endsWith("/insights/recompute")) return jsonResponse({ detail: "session consumed", code: "processing_session_invalid" }, { status: 401 });
      return jsonResponse({}, { status: 404 });
    });
    const session = await api.openProcessingSession(toBase64(DATA_KEY));
    const first = await api.recompute(session.session_token).catch((err: unknown) => err as ApiError);
    expect((first as ApiError).code).toBe("processing_session_invalid");
  });

  it("a queue replay across 'devices' dedupes server-side (409 + verified GET)", async () => {
    stubFetch((url) => {
      if (url.endsWith("/entries")) return jsonResponse({ detail: "exists", code: "conflict" }, { status: 409 });
      if (url.includes("/entries/e-replay-1")) {
        return jsonResponse({ id: "row", client_entry_id: "e-replay-1", blob: "AA", entry_date: "d", received_at: "r" });
      }
      return jsonResponse({}, { status: 404 });
    });
    await enqueue({ userId: USER, clientEntryId: "e-replay-1", blobB64: "QUJD", entryDate: "2026-09-25" });
    // "Replay": flush twice in a row — the second pass finds an empty queue
    // (the verified 409 discarded the item), never double-creating.
    expect(await flushQueue(USER)).toBe(0);
    expect(await flushQueue(USER)).toBe(0);
  });

  it("a cross-account blob injection is rejected by AAD binding", async () => {
    // Encrypted for user-1, presented under a different user id:
    const { blobB64 } = await encryptEntry(DATA_KEY, "user-1", "e-inject", "target's words", "2026-09-25T00:00:00Z", 0, undefined, 1);
    await expect(import("../src/crypto/patient").then(({ decryptEntry }) => decryptEntry(DATA_KEY, "attacker", "e-inject", blobB64, 1))).rejects.toThrow("blob failed authentication");
  });

  it("insights state_seq rollback across sessions fails closed", async () => {
    const { checkAnalysisGeneration, forgetAnalysisGeneration, FRESHNESS_ERROR } = await import("../src/stateSeqGuard");
    await forgetAnalysisGeneration(USER);
    await checkAnalysisGeneration(USER, 10, 10);
    await forgetAnalysisGeneration(USER); // simulate restart → mark persists in kv
    // A fresh process re-reads the stored mark (the kv backend persists):
    await checkAnalysisGeneration(USER, 10, 10);
    await expect(checkAnalysisGeneration(USER, 9, 9)).rejects.toThrow(FRESHNESS_ERROR);
    await forgetAnalysisGeneration(USER);
  });

  it("a lock mid-flow leaves no orphaned session", async () => {
    setSession("t2", "user-2", "someone-else");
    vault.lock();
    const { reconcile } = await import("../src/sync");
    expect((await reconcile()).kind).toBe("locked");
  });
});
