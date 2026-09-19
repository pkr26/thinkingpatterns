/**
 * Rollback-guard pins (2026-09-19 contract): the payload's embedded
 * analysis generation must equal the plaintext echo, and neither may move
 * below this device's pinned high-water mark.
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

import {
  FRESHNESS_ERROR,
  checkAnalysisGeneration,
  forgetAnalysisGeneration,
} from "../src/stateSeqGuard";

beforeEach(() => {
  store.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("checkAnalysisGeneration", () => {
  it("passes and pins when payload matches echo and advances", async () => {
    await expect(checkAnalysisGeneration("u1", 3, 3)).resolves.toBeUndefined();
    expect(store.get("mindpattern.stateSeq.u1")).toBe("3");
  });

  it("rejects a replayed-older blob: payload disagrees with the echo", async () => {
    await checkAnalysisGeneration("u2", 2, 2); // pin 2
    await expect(checkAnalysisGeneration("u2", 1, 2)).rejects.toThrow(FRESHNESS_ERROR);
  });

  it("rejects a both-copies rollback: value moves below the pinned high-water", async () => {
    await checkAnalysisGeneration("u3", 5, 5); // pin 5
    await expect(checkAnalysisGeneration("u3", 4, 4)).rejects.toThrow(FRESHNESS_ERROR);
  });

  it("equal high-water re-check passes without rewriting storage", async () => {
    await checkAnalysisGeneration("u4", 7, 7);
    store.set("mindpattern.stateSeq.u4", "6"); // tamper below
    await expect(checkAnalysisGeneration("u4", 7, 7)).resolves.toBeUndefined();
    expect(store.get("mindpattern.stateSeq.u4")).toBe("7");
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
    expect(store.get("mindpattern.stateSeq.u7")).toBe("4");
    expect(store.get("mindpattern.stateSeq.u8")).toBe("1");
  });

  it("forgetAnalysisGeneration clears the pin", async () => {
    await checkAnalysisGeneration("u9", 3, 3);
    await forgetAnalysisGeneration("u9");
    // A rolled-back value would now pass: the pin is genuinely gone.
    await expect(checkAnalysisGeneration("u9", 1, 1)).resolves.toBeUndefined();
  });
});
