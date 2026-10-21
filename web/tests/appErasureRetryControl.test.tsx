/** Public unauthenticated erasure recovery; original factory Promise custody. */
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { setKvBackendForTests, StorageCommitError } from "../src/kvstore";
import * as erasure from "../src/localErasure";
import { applyLanguagePref } from "../src/strings";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { flush, render, textOf, textOfNode } from "./helpers/rtr";

let root: ReactTestRenderer | undefined;
const originalResponses: Promise<Response>[] = [];
const originalResumes: ReturnType<typeof erasure.resumeConfirmedErasures>[] = [];
let transportFault: unknown;
let factoryFault: unknown;
let authoredDeletionRefusal: DOMException;

function knownDeletionRefusal(error: unknown): boolean {
  return error instanceof StorageCommitError && error.message === "Local deletion did not finish — retry before leaving this device."
    && error.cause === authoredDeletionRefusal;
}
async function completion<T>(pending: Promise<T>, label: string, allowAuthoredRefusal = false): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([pending, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("SetupError: erasure producer completion deadline: " + label)), 5000);
    })]);
  } catch (error) {
    if (!(allowAuthoredRefusal && knownDeletionRefusal(error)))
      throw new Error("SetupError: erasure original producer failed: " + label, { cause: error });
  } finally { if (timer) clearTimeout(timer); }
}
async function producerBarrier(predicate: () => boolean, label: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (transportFault || factoryFault) throw new Error("SetupError: erasure producer fault: " + label, { cause: transportFault ?? factoryFault });
    if (Date.now() >= deadline) throw new Error("SetupError: erasure public producer deadline: " + label);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
}

beforeEach(() => {
  vi.useRealTimers(); resetTestState(); applyLanguagePref("en");
  originalResponses.length = 0; originalResumes.length = 0; transportFault = undefined; factoryFault = undefined;
  authoredDeletionRefusal = new DOMException("Authored backend deletion refusal", "NotAllowedError");
  const original = erasure.resumeConfirmedErasures;
  vi.spyOn(erasure, "resumeConfirmedErasures").mockImplementation(() => {
    const pending = original();
    originalResumes.push(pending);
    void pending.catch(error => { if (!knownDeletionRefusal(error)) factoryFault = error; });
    return pending; // The shipped App receives the identical original Promise.
  });
  stubFetch(url => {
    const pending = (async () => {
      if (new URL(url).pathname.endsWith("/meta")) return jsonResponse({ unlock_days: 30 });
      throw new Error("SetupError: unexpected erasure-recovery transport " + new URL(url).pathname);
    })();
    originalResponses.push(pending);
    void pending.catch(error => { transportFault = error; });
    return pending;
  });
});
afterEach(async () => {
  try {
    if (root) await act(async () => { root!.unmount(); root = undefined; });
    for (const pending of originalResponses) await completion(pending, "owned transport");
    for (const pending of originalResumes) await completion(pending, "owned erasure factory", true);
    if (transportFault || factoryFault) throw new Error("SetupError: owned erasure producer cleanup failed", { cause: transportFault ?? factoryFault });
  } finally { root = undefined; resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals(); }
});

it("an unfinished confirmed erasure keeps a named public retry control and retires only its encrypted records after retry", async () => {
  let refuseDeletion = true;
  const records = new Map<string, string>([
    ["mindpattern.safetyPlan.erased", "retained encrypted plan"],
    ["mindpattern.safetyPlan.other", "other account encrypted plan"],
    ["mindpattern.erase.erased", JSON.stringify({ v: 1, owner: "erased", remoteConfirmed: true, keys: ["mindpattern.safetyPlan.erased"] })],
  ]);
  setKvBackendForTests({
    getItem: async key => records.get(key) ?? null,
    setItem: async (key, value) => { records.set(key, value); },
    removeItem: async key => {
      if (refuseDeletion && key === "mindpattern.safetyPlan.erased") throw authoredDeletionRefusal;
      records.delete(key);
    },
    compareAndSet: async (key, before, after, _permit, stillCurrent) => {
      if (stillCurrent && !stillCurrent() || (records.get(key) ?? null) !== before) return false;
      records.set(key, after); return true;
    },
    keys: async () => [...records.keys()],
  });
  root = await render(<App />);
  await producerBarrier(() => originalResumes.length > 0, "initial actual erasure admission");
  await act(async () => { await completion(originalResumes[0]!, "initial authored refusal", true); });
  await producerBarrier(() => textOf(root!).includes("Unfinished local deletion"), "completed initial public recovery");
  expect(records.get("mindpattern.safetyPlan.erased")).toBe("retained encrypted plan");
  const retry = root.root.findAllByType("button").find(node => textOfNode(node) === "Retry local cleanup");
  // The missing named control is a direct body assertion before handler use.
  expect(retry).toBeDefined();
  expect(retry!.props.disabled).not.toBe(true);
  const prior = new Set(originalResumes);
  refuseDeletion = false;
  await act(async () => { retry!.props.onClick(); });
  await producerBarrier(() => originalResumes.some(pending => !prior.has(pending)), "public retry actual erasure admission");
  const retryOriginal = originalResumes.find(pending => !prior.has(pending))!;
  await act(async () => { await completion(retryOriginal, "acknowledged actual retry"); });
  await flush();
  await producerBarrier(() => !textOf(root!).includes("Unfinished local deletion"), "completed public retry retirement");
  expect(records.has("mindpattern.safetyPlan.erased")).toBe(false);
  expect(records.has("mindpattern.erase.erased")).toBe(false);
  expect(records.get("mindpattern.safetyPlan.other")).toBe("other account encrypted plan");
  expect(textOf(root)).not.toContain("Unfinished local deletion");
});
