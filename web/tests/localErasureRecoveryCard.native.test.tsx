/** Draft public recovery-control regression. Not promoted or executed. */
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { kv, setKvBackendForTests } from "../src/kvstore";
import * as erasure from "../src/localErasure";
import { applyLanguagePref } from "../src/strings";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { render, textOfNode } from "./helpers/rtr";

let root: ReactTestRenderer | undefined;
const originalCalls: Promise<unknown>[] = [];
let settledCalls = 0;

function remember<T>(pending: Promise<T>): Promise<T> {
  originalCalls.push(pending);
  void pending.catch(() => undefined);
  return pending; // App receives the identical Promise from the actual exported producer.
}

async function finishOriginalCalls(): Promise<void> {
  while (settledCalls < originalCalls.length) {
    const batch = originalCalls.slice(settledCalls);
    settledCalls = originalCalls.length;
    await act(async () => { await Promise.allSettled(batch); });
  }
}

beforeEach(() => {
  vi.useRealTimers();
  resetTestState();
  applyLanguagePref("en");
  originalCalls.length = 0;
  settledCalls = 0;
  const resume = erasure.resumeConfirmedErasures;
  const pending = erasure.pendingLocalErasures;
  vi.spyOn(erasure, "resumeConfirmedErasures").mockImplementation(() => remember(resume()));
  vi.spyOn(erasure, "pendingLocalErasures").mockImplementation(() => remember(pending()));
  stubFetch(url => remember((async () => {
    if (new URL(url).pathname.endsWith("/meta")) return jsonResponse({ unlock_days: 30 });
    throw new Error("SetupError: unexpected unauthenticated recovery transport " + new URL(url).pathname);
  })()));
});

afterEach(async () => {
  try {
    await finishOriginalCalls();
    if (root) await act(async () => { root!.unmount(); root = undefined; });
    await finishOriginalCalls();
  } finally {
    root = undefined;
    resetTestState();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});

it("an unreadable deletion checkpoint keeps the public local-cleanup retry control and retains the account writing", async () => {
  const slot = "mindpattern.erase.recovery-owner";
  const writingSlot = "mindpattern.safetyPlan.recovery-owner";
  const writing = "retained opaque account writing";
  const unreadable = JSON.stringify({ v: 2, owner: "recovery-owner", remoteConfirmed: true, keys: [writingSlot] });
  const records = new Map<string, string>([[slot, unreadable], [writingSlot, writing]]);
  setKvBackendForTests({
    getItem: async key => records.get(key) ?? null,
    setItem: async (key, value) => { records.set(key, value); },
    removeItem: async key => { records.delete(key); },
    keys: async () => [...records.keys()],
    compareAndSet: async (key, before, after, _permit, stillCurrent) => {
      if (stillCurrent && !stillCurrent() || (records.get(key) ?? null) !== before) return false;
      records.set(key, after);
      return true;
    },
  });
  root = await render(<App />);
  await finishOriginalCalls();
  const retry = root.root.findAllByType("button").find(node => textOfNode(node) === "Retry local cleanup");
  // First assertion is the actual named public control, after the real rejected producers settle.
  expect(retry).toBeDefined();
  expect(retry!.props.disabled).not.toBe(true);
  expect(await kv.getItem(slot)).toBe(unreadable);
  expect(await kv.getItem(writingSlot)).toBe(writing);
});
