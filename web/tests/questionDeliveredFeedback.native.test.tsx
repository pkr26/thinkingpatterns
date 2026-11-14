import nodeCrypto from "node:crypto";
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { QuestionView } from "../src/views/Question";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { isDisabled, press, render, textOf } from "./helpers/rtr";

const OWNER = "a".repeat(32), KEY = Buffer.alloc(32, 6), DATE = "2026-10-07";
const operations = new Set<Promise<unknown>>();
function track<T>(operation: Promise<T>): Promise<T> {
  operations.add(operation);
  void operation.then(() => operations.delete(operation), () => operations.delete(operation));
  return operation; // Preserve the actual provider Promise and its delivery order.
}
async function drainNativeWork() {
  for (let quiet = 0; quiet < 3;) {
    if (operations.size) { await Promise.allSettled([...operations]); quiet = 0; }
    else quiet++;
    await new Promise<void>(resolve => setTimeout(resolve, 0));
  }
}
function questionResponse() {
  const cipher = nodeCrypto.createCipheriv("aes-256-gcm", KEY, Buffer.alloc(12, 4));
  cipher.setAAD(Buffer.from(JSON.stringify(["question", OWNER, DATE]), "ascii"));
  const plain = Buffer.from(JSON.stringify({ for_date: DATE, question: "A delivered reflection", pattern_pid: "topic:delivered" }));
  const blob = Buffer.concat([Buffer.alloc(12, 4), cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString("base64");
  return { for_date: DATE, blob };
}
function openFeedback(blob: string) {
  const bytes = Buffer.from(blob, "base64");
  // The server permits today or yesterday when the UTC date rolls over.
  for (const daysAgo of [0, 1]) {
    const day = new Date(Date.now() - daysAgo * 86400000).toISOString().slice(0, 10);
    try {
      const decipher = nodeCrypto.createDecipheriv("aes-256-gcm", KEY, bytes.subarray(0, 12));
      decipher.setAAD(Buffer.from(JSON.stringify(["feedback", OWNER, day]), "ascii"));
      decipher.setAuthTag(bytes.subarray(-16));
      return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]).toString("utf8"));
    } catch { /* Try the other accepted date, without changing the app clock. */ }
  }
  throw new Error("SetupError: the actual first recompute feedback could not be independently authenticated");
}

beforeEach(() => {
  resetTestState(); installSession(OWNER);
  vault.unlock({ authKey: new Uint8Array(KEY), dataKey: new Uint8Array(KEY) }, OWNER);
  for (const method of ["importKey", "encrypt", "decrypt"] as const) {
    const native = crypto.subtle[method].bind(crypto.subtle);
    vi.spyOn(crypto.subtle, method).mockImplementation(((...args: unknown[]) => track((native as (...args: unknown[]) => Promise<unknown>)(...args))) as never);
  }
});
afterEach(async () => {
  await drainNativeWork();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); resetTestState();
});

it("omits already delivered feedback from the next public refresh without a new choice", async () => {
  const bodies: Array<Record<string, unknown> | undefined> = [];
  const notices: string[] = [];
  stubFetch((url, init) => {
    if (url.endsWith("/questions/today")) return jsonResponse(questionResponse());
    if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "declared-processing", expires_in: 300 });
    if (url.endsWith("/insights/recompute")) {
      bodies.push(init.body === undefined ? undefined : JSON.parse(String(init.body)));
      return jsonResponse({ phase: "insight" });
    }
    if (url.endsWith("/insights")) return jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null });
    return jsonResponse({ code: "not_found" }, { status: 404 });
  });
  const root = await render(<QuestionView onRefreshed={message => notices.push(message)} />);
  const refreshCompleted = (count: number): boolean =>
    notices.length === count && !isDisabled(root, "Refresh patterns") && bodies.length === count;
  try {
    await act(async () => { await drainNativeWork(); });
    if (!textOf(root).includes("A delivered reflection")) throw new Error("SetupError: initial independently encrypted question was not admitted");
    await press(root, "This resonated");
    await act(async () => { await drainNativeWork(); });
    await press(root, "Refresh patterns");
    await act(async () => { await drainNativeWork(); });
    if (!refreshCompleted(1) || typeof bodies[0]?.feedback_blob !== "string") {
      throw new Error("SetupError: first feedback-bearing refresh did not complete");
    }
    expect(openFeedback(bodies[0].feedback_blob)).toEqual({ feedback: [{ pid: "topic:delivered", resonated: true }], muted: [], unmuted: [] });
    await press(root, "Refresh patterns");
    await act(async () => { await drainNativeWork(); });
    if (!refreshCompleted(2)) {
      throw new Error("SetupError: second refresh did not complete");
    }
    // This is the actual authenticated HTTP request body, with all production
    // queue/receipt, operation ownership, API and native crypto code retained.
    expect(bodies[1]).toBeUndefined();
  } finally {
    await act(async () => { await drainNativeWork(); root.unmount(); });
  }
});
