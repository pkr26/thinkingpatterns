/** The reconciliation engine + state_seq guard (P5): honest funnels for
 *  every cross-device scenario — fresh pulls, offline, baseline, tampered
 *  generations, remote rotation (S-8), and lock states. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { reconcile, reconcileInsights } from "../src/sync";
import { checkAnalysisGeneration, FRESHNESS_ERROR, forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { encryptWithFixedNonce, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests } from "../src/kvstore";
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
  it("stays one insights round-trip: no full-journal walk on focus events", async () => {
    const mock = stubFetch((url) => {
      if (url.endsWith("/insights")) {
        return jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null });
      }
      if (url.includes("/entries?")) {
        return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const outcome = await reconcile();
    expect(outcome.kind).toBe("ok");
    // The walk re-downloaded the account's entire ciphertext and discarded
    // it on every focus — the History view owns that walk (audit
    // 2026-09-25). Reconcile must not page entries at all.
    expect(mock.mock.calls.some(([url]) => String(url).includes("/entries?"))).toBe(false);
    expect(mock.mock.calls.filter(([url]) => String(url).endsWith("/insights"))).toHaveLength(1);
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

  it("the stored mark is authoritative with an empty mirror (process restart)", async () => {
    // A fresh process has no mirror — the persisted mark alone must referee.
    const map = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    map.set(`mindpattern.stateSeq.${USER}`, "9");
    await expect(checkAnalysisGeneration(USER, 8, 8)).rejects.toThrow(FRESHNESS_ERROR);
    await expect(checkAnalysisGeneration(USER, 9, 9)).resolves.toBeUndefined();
    await checkAnalysisGeneration(USER, 10, 10);
    expect(map.get(`mindpattern.stateSeq.${USER}`)).toBe("10");
  });

  it("the persisted mark never regresses (cross-tab CAS)", async () => {
    const map = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    // A sibling tab already advanced the durable mark to 12. A stale tab
    // (mirror 11) seeing payload 11 must fail against highWater 12 — it
    // can neither pass nor overwrite the newer mark.
    map.set(`mindpattern.stateSeq.${USER}`, "12");
    await expect(checkAnalysisGeneration(USER, 11, 11)).rejects.toThrow(FRESHNESS_ERROR);
    expect(map.get(`mindpattern.stateSeq.${USER}`)).toBe("12");
    // And a legitimate advance writes forward only.
    await checkAnalysisGeneration(USER, 13, 13);
    expect(map.get(`mindpattern.stateSeq.${USER}`)).toBe("13");
  });

  it("self-heals a tampered/stale stored mark upward, never downward", async () => {
    const map = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return map.get(k) ?? null;
      },
      async setItem(k, v) {
        map.set(k, v);
      },
      async removeItem(k) {
        map.delete(k);
      },
    });
    await checkAnalysisGeneration(USER, 10, 10);
    expect(map.get(`mindpattern.stateSeq.${USER}`)).toBe("10");
    // On-device tamper drops the stored copy to 4; the live mirror (10)
    // must win the max and repair storage back up.
    map.set(`mindpattern.stateSeq.${USER}`, "4");
    await expect(checkAnalysisGeneration(USER, 10, 10)).resolves.toBeUndefined();
    expect(map.get(`mindpattern.stateSeq.${USER}`)).toBe("10");
  });
});
