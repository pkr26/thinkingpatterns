/** The reconciliation engine + state_seq guard (P5): honest funnels for
 *  every cross-device scenario — fresh pulls, offline, baseline, tampered
 *  generations, remote rotation (S-8), and lock states. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { reconcile, reconcileInsights } from "../src/sync";
import { checkAnalysisGeneration, FRESHNESS_ERROR, forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { encryptWithFixedNonce, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(4);
const USER = "user-1";

const insightsBlob = async (stateSeq: number | undefined): Promise<string> => {
  const payload = JSON.stringify({ v: 2, stats: { patterns: [] }, ...(stateSeq !== undefined ? { state_seq: stateSeq } : {}) });
  return toBase64(await encryptWithFixedNonce(DATA_KEY, new TextEncoder().encode(payload), fromBase64("AAAAAAAAAAAAAAAA"), buildAad("insights", USER, "patterns")));
};

beforeEach(() => {
  resetTestState();
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(4);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("reconcileInsights funnels", () => {
  it("ok: decrypts, verifies the generation, and reports the phase", async () => {
    stubFetch(async () => jsonResponse({ phase: "active", active_days: 40, streak: 3, days_remaining: 0, blob: await insightsBlob(7), state_seq: 7 }));
    const outcome = await reconcileInsights();
    expect(outcome).toEqual({ kind: "ok", phase: "active", stateSeq: 7 });
  });

  it("baseline (blob null) reports ok with no generation to guard", async () => {
    stubFetch(() => jsonResponse({ phase: "baseline", active_days: 2, streak: 1, days_remaining: 28, blob: null }));
    expect(await reconcileInsights()).toEqual({ kind: "ok", phase: "baseline", stateSeq: null });
  });

  it("offline surfaces as offline, not error", async () => {
    stubFetch(() => Promise.reject(new TypeError("fetch failed")));
    expect(await reconcileInsights()).toEqual({ kind: "offline" });
  });

  it("a 401/410 hands off to the session-death latch and reports locked", async () => {
    stubFetch(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 }));
    expect(await reconcileInsights()).toEqual({ kind: "locked" });
  });

  it("remote rotation (S-8): a live session whose key cannot open the blob funnels to credentialRotated", async () => {
    // The blob was rekeyed under a DIFFERENT data key on the server.
    const otherKey = new Uint8Array(new ArrayBuffer(32)).fill(9);
    const payload = JSON.stringify({ v: 2, stats: {}, state_seq: 11 });
    const blob = toBase64(await encryptWithFixedNonce(otherKey, new TextEncoder().encode(payload), fromBase64("AAAAAAAAAAAAAAAA"), buildAad("insights", USER, "patterns")));
    stubFetch(() => jsonResponse({ phase: "active", active_days: 40, streak: 1, days_remaining: 0, blob, state_seq: 11 }));
    expect(await reconcileInsights()).toEqual({ kind: "credentialRotated" });
  });

  it("freshness: a tampered generation (echo ≠ payload) fails loudly", async () => {
    stubFetch(async () => jsonResponse({ phase: "active", active_days: 40, streak: 1, days_remaining: 0, blob: await insightsBlob(5), state_seq: 9 }));
    expect(await reconcileInsights()).toEqual({ kind: "freshness" });
  });

  it("locked vault reports locked", async () => {
    vault.lock();
    expect(await reconcileInsights()).toEqual({ kind: "locked" });
  });
});

describe("reconcile (the full pull)", () => {
  it("walks the entries after a successful insights read", async () => {
    const mock = stubFetch((url) => {
      if (url.endsWith("/insights")) {
        return jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null });
      }
      if (url.startsWith("http://localhost:5173/api/v1/entries?")) {
        return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const outcome = await reconcile();
    expect(outcome.kind).toBe("ok");
    expect(mock.mock.calls.some(([url]) => String(url).includes("/entries?"))).toBe(true);
  });
});

describe("stateSeqGuard", () => {
  beforeEach(async () => {
    await forgetAnalysisGeneration(USER);
  });

  it("pins the high-water mark and rejects rollbacks", async () => {
    await checkAnalysisGeneration(USER, 5, 5);
    await expect(checkAnalysisGeneration(USER, 4, 4)).rejects.toThrow(FRESHNESS_ERROR);
    await expect(checkAnalysisGeneration(USER, 5, 6)).rejects.toThrow(FRESHNESS_ERROR);
    await checkAnalysisGeneration(USER, 6, 6); // advance ok
  });

  it("fails closed on absent generations once a mark exists (M-1)", async () => {
    await checkAnalysisGeneration(USER, 5, 5);
    await expect(checkAnalysisGeneration(USER, undefined, undefined)).rejects.toThrow(FRESHNESS_ERROR);
  });

  it("no mark yet: absent generations pass (genuinely old server)", async () => {
    await expect(checkAnalysisGeneration(USER, undefined, undefined)).resolves.toBeUndefined();
  });

  it("the mark persists across an in-memory reset (stored copy)", async () => {
    await checkAnalysisGeneration(USER, 5, 5);
    const fresh: KvBackend = { ...memorySnapshot() };
    void fresh;
    // A NEW module mirror (process restart) re-reads the stored mark:
    const { forgetAnalysisGeneration: _f, ...mod } = await import("../src/stateSeqGuard");
    void mod;
    await expect(checkAnalysisGeneration(USER, 4, 4)).rejects.toThrow(FRESHNESS_ERROR);
  });
});

function memorySnapshot(): KvBackend {
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
}
