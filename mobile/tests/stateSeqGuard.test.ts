import { runTestControl } from "./helpers/testControl";
/**
 * Rollback-guard pins (2026-09-19 contract): the payload's embedded
 * analysis generation must equal the plaintext echo, and neither may move
 * below this device's pinned high-water mark.
 *
 * 2026-09-26 (audit LOW): the persisted mark lives in secureStore now —
 * AES-GCM under the per-install Keychain/Keystore key — so storage
 * assertions round-trip through secureStore, and the tamper tests below
 * pin the new semantics: an EDITED record fails the GCM tag and reads as
 * absent (never as a valid, possibly lowered pin); within a session the
 * in-memory mirror remains the authority; a v1 plaintext mark migrates
 * sealed, read-through, once.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const store = new Map<string, string>();

vi.mock("@react-native-async-storage/async-storage", () => ({
  default: {
    getItem: async (k: string) => store.get(k) ?? null,
    setItem: async (k: string, v: string) => void store.set(k, v),
    removeItem: async (k: string) => void store.delete(k),
  },
}));

import { secureStore } from "../src/secureStore";
import {
  FRESHNESS_ERROR,
  checkAnalysisGeneration,
  forgetAnalysisGeneration,
  resetAnalysisGenerationMirrors,
} from "../src/stateSeqGuard";

beforeEach(() => {
  store.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** An envelope-shaped record whose ciphertext was written WITHOUT the
 *  device key — exactly what a local attacker's edit looks like. */
function tamperSealed(key: string, plain: string): void {
  store.set(key, JSON.stringify({ v: 1, c: Buffer.from(plain, "utf8").toString("base64") }));
}

describe("checkAnalysisGeneration", () => {
  it("passes and pins when payload matches echo and advances", async () => {
    await expect(checkAnalysisGeneration("u1", 3, 3)).resolves.toBeUndefined();
    expect(await secureStore.getItem("mindpattern.stateSeq.u1")).toBe("3");
    // Sealed on disk: the raw stored bytes are the secureStore envelope,
    // never a plaintext decimal a local attacker could simply lower.
    expect(store.get("mindpattern.stateSeq.u1")).toMatch(/^\{"v":1,"c":"/);
  });

  it("rejects a replayed-older blob: payload disagrees with the echo", async () => {
    await checkAnalysisGeneration("u2", 2, 2); // pin 2
    await expect(checkAnalysisGeneration("u2", 1, 2)).rejects.toThrow(FRESHNESS_ERROR);
  });

  it("rejects a both-copies rollback: value moves below the pinned high-water", async () => {
    await checkAnalysisGeneration("u3", 5, 5); // pin 5
    await expect(checkAnalysisGeneration("u3", 4, 4)).rejects.toThrow(FRESHNESS_ERROR);
  });

  it("equal high-water re-check passes and self-heals a tampered stored copy", async () => {
    await checkAnalysisGeneration("u4", 7, 7);
    tamperSealed("mindpattern.stateSeq.u4", "6"); // tamper below, without the key
    await expect(checkAnalysisGeneration("u4", 7, 7)).resolves.toBeUndefined();
    expect(await secureStore.getItem("mindpattern.stateSeq.u4")).toBe("7");
  });

  it("absent values (old server / baseline) pass silently", async () => {
    await expect(checkAnalysisGeneration("u5", undefined, undefined)).resolves.toBeUndefined();
    await expect(checkAnalysisGeneration("u5", undefined, 2)).resolves.toBeUndefined();
    await expect(checkAnalysisGeneration("u5", 2, undefined)).resolves.toBeUndefined();
    expect(store.has("mindpattern.stateSeq.u5")).toBe(false);
  });

  it("non-finite values pass as absent", async () => {
    await expect(checkAnalysisGeneration("u6", Number.NaN, 2)).resolves.toBeUndefined();
    await expect(checkAnalysisGeneration("u6", 2, Number.POSITIVE_INFINITY)).resolves.toBeUndefined();
  });

  it("device-local pins are per user", async () => {
    await checkAnalysisGeneration("u7", 4, 4);
    await checkAnalysisGeneration("u8", 1, 1); // lower generation, other user
    expect(await secureStore.getItem("mindpattern.stateSeq.u7")).toBe("4");
    expect(await secureStore.getItem("mindpattern.stateSeq.u8")).toBe("1");
  });

  it("forgetAnalysisGeneration clears the pin", async () => {
    await checkAnalysisGeneration("u9", 3, 3);
    await forgetAnalysisGeneration("u9");
    // A rolled-back value would now pass: the pin is genuinely gone.
    await expect(checkAnalysisGeneration("u9", 1, 1)).resolves.toBeUndefined();
  });
});

describe("sealed persistence (2026-09-26 audit LOW)", () => {
  it("an EDITED mark fails the GCM tag and reads as absent — never a valid lower pin", async () => {
    await checkAnalysisGeneration("t1", 8, 8); // sealed under the device key
    const key = "mindpattern.stateSeq.t1";
    tamperSealed(key, "2"); // a local attacker's edit, no device key
    runTestControl(resetAnalysisGenerationMirrors); // fresh process: no mirror either
    // The tampered record cannot present itself as a genuine (lowered)
    // mark: it reads as ABSENT, and the documented deletion residual
    // applies across a restart — the check degrades to "no memory" and
    // re-pins from what the server next delivers.
    await expect(checkAnalysisGeneration("t1", 5, 5)).resolves.toBeUndefined();
    expect(await secureStore.getItem(key)).toBe("5"); // re-pinned, sealed
    // …and the NEXT check fails closed against the re-established mark.
    await expect(checkAnalysisGeneration("t1", 4, 4)).rejects.toThrow(FRESHNESS_ERROR);
  });

  it("within a session the in-memory mirror is the authority over a tampered stored mark", async () => {
    await checkAnalysisGeneration("t2", 9, 9);
    tamperSealed("mindpattern.stateSeq.t2", "lowered");
    // The mirror (9) refuses the replay of 7 outright…
    await expect(checkAnalysisGeneration("t2", 7, 7)).rejects.toThrow(FRESHNESS_ERROR);
    // …and the self-heal rewrite restores the sealed record to the truth.
    expect(await secureStore.getItem("mindpattern.stateSeq.t2")).toBe("9");
  });

  it("a v1 plaintext mark migrates sealed read-through and still enforces", async () => {
    store.set("mindpattern.stateSeq.t3", "9"); // the pre-2026-09-26 format
    await expect(checkAnalysisGeneration("t3", 5, 5)).rejects.toThrow(FRESHNESS_ERROR);
    // Adopted AND re-written sealed: no plaintext decimal remains on disk.
    expect(await secureStore.getItem("mindpattern.stateSeq.t3")).toBe("9");
    expect(store.get("mindpattern.stateSeq.t3")).toMatch(/^\{"v":1,"c":"/);
  });
});
