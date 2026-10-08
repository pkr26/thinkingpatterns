import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { t } from "../src/strings";
import { auth, clearSession, setSession } from "../src/api/client";
import { reconcile, reconcileInsights } from "../src/sync";
import { buildAad } from "../src/crypto/aad";
import { encryptWithFixedNonce, toBase64 } from "../src/crypto/core";
import { forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { setKvBackendForTests, StorageCommitError } from "../src/kvstore";
import { vault } from "../src/vault";
import { withLock } from "../src/platform";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const owner = "sync-native-current", stateKey = `mindpattern.stateSeq.${owner}`;
const key = (byte = 101) => new Uint8Array(new ArrayBuffer(32)).fill(byte);
let physical: Map<string, string>;
type DeviceEvent = (operation: "read" | "write", key: string) => void;
let event: DeviceEvent | undefined;
beforeEach(async () => {
  resetTestState(); installSession(owner); vault.unlock({ authKey: key(), dataKey: key() }, owner);
  physical = new Map(); event = undefined;
  setKvBackendForTests({
    async getItem(k) { const captured = physical.get(k) ?? null; event?.("read", k); return captured; },
    async setItem(k, value) { physical.set(k, value); event?.("write", k); },
    async removeItem(k) { physical.delete(k); }, async keys() { return [...physical.keys()]; },
  });
  await forgetAnalysisGeneration(owner);
});
afterEach(() => { event = undefined; setKvBackendForTests(null); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function blob(wrongKey = false) {
  const plaintext = new TextEncoder().encode(JSON.stringify({ v: 2, stats: { patterns: [] }, state_seq: 7 }));
  const sealed = await encryptWithFixedNonce(key(wrongKey ? 109 : 101), plaintext, new Uint8Array(new ArrayBuffer(12)), buildAad("insights", owner, "patterns"));
  return toBase64(sealed);
}
async function deliverSummary(wrongKey = false) {
  const cipher = await blob(wrongKey);
  stubFetch(() => jsonResponse({ phase: "insight", active_days: 40, streak: 3, days_remaining: 0, state_seq: 7, blob: cipher }));
}
type Retirement = "lock" | "fresh-key" | "fresh-account" | "credential" | "unadopted-account";
function retire(kind: Retirement) {
  if (kind === "lock") vault.lock();
  else if (kind === "fresh-key") vault.unlock({ authKey: key(107), dataKey: key(107) }, owner);
  else if (kind === "credential") installSession(owner);
  else if (kind === "unadopted-account") installSession("replacement-account");
  else { installSession("replacement-account"); vault.unlock({ authKey: key(107), dataKey: key(107) }, "replacement-account"); }
}
it.each(["lock", "fresh-key", "fresh-account", "credential", "unadopted-account"] as const)("refuses old decrypted insights at an actual WebCrypto successful receipt: %s", async kind => {
  await deliverSummary(); const nativeDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => { const plaintext = await nativeDecrypt(...args); retire(kind); return plaintext; });
  expect(await reconcileInsights()).toEqual({ kind: "locked" });
  expect(physical.has(stateKey)).toBe(false);
});
it.each(["lock", "fresh-key", "fresh-account", "credential", "unadopted-account"] as const)("keeps an actual Native authentication failure quiet after retirement: %s", async kind => {
  await deliverSummary(true); const nativeDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    try { return await nativeDecrypt(...args); }
    catch (nativeFailure) { retire(kind); throw nativeFailure; }
  });
  expect(await reconcileInsights()).toEqual({ kind: "locked" }); expect(physical.has(stateKey)).toBe(false);
});
it.each(["read", "write"] as const)("refuses plaintext after a generation-check physical %s receipt retires its account key", async operation => {
  await deliverSummary(); if (operation === "read") physical.set(stateKey, "7");
  event = (kind, name) => { if (kind === operation && name === stateKey) retire("fresh-key"); };
  expect(await reconcileInsights()).toEqual({ kind: "locked" });
});
it.each([false, true])("surfaces a real generation commit refusal correctly: retired=%s", async retired => {
  await deliverSummary();
  event = (kind, name) => {
    if (kind === "write" && name === stateKey) { if (retired) retire("fresh-key"); throw new Error("device commit receipt failed"); }
  };
  if (retired) expect(await reconcileInsights()).toEqual({ kind: "locked" });
  else await expect(reconcileInsights()).rejects.toBeInstanceOf(StorageCommitError);
});
it("refuses the vault's foreign owner before Native HTTP or crypto admission", async () => {
  vault.unlock({ authKey: key(), dataKey: key() }, "another-owner");
  const fetch = stubFetch(() => { throw new Error("foreign vault must not dispatch HTTP"); });
  expect(await reconcileInsights()).toEqual({ kind: "locked" }); expect(fetch).not.toHaveBeenCalled();
});
it("reports a missing session as locked without sending Native HTTP", async () => {
  clearSession(); const fetch = stubFetch(() => { throw new Error("signed-out reconcile must not dispatch HTTP"); });
  expect(await reconcileInsights()).toEqual({ kind: "locked" }); expect(fetch).not.toHaveBeenCalled();
});
it("refuses a malformed v2 token owner during the actual pre-envelope session interval", async () => {
  clearSession(); vault.lock();
  stubFetch(() => jsonResponse({ token: "new-v2-token", user_id: null, role: "user", key_scheme: "v2" }));
  const token = await auth.login("tester", toBase64(key()));
  // LoginView installs this tuple before its envelope request, and final
  // adoptSession later validates the token. No key has been adopted yet.
  setSession(token.token, token.user_id, "tester", token.expires_in);
  const fetch = stubFetch(() => { throw new Error("malformed owner must not dispatch protected HTTP"); });
  expect(await reconcileInsights()).toEqual({ kind: "locked" }); expect(fetch).not.toHaveBeenCalled();
});
it("keeps a protected API refusal quiet after a same-owner key replacement", async () => {
  stubFetch(() => { retire("fresh-key"); return jsonResponse({ detail: "provider unavailable" }, { status: 503 }); });
  expect(await reconcileInsights()).toEqual({ kind: "locked" });
});
it("refuses a baseline summary received after a same-owner key replacement", async () => {
  stubFetch(() => { retire("fresh-key"); return jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null }); });
  expect(await reconcileInsights()).toEqual({ kind: "locked" });
});
it("does not mislabel a sanitized server error or a non-session 410 as credential rotation", async () => {
  stubFetch(() => jsonResponse({ detail: "maintenance unavailable" }, { status: 503 }));
  expect(await reconcileInsights()).toEqual({ kind: "error", message: t("errors.serverError") });
  stubFetch(() => jsonResponse({ detail: "gone", code: "another_condition" }, { status: 410 }));
  expect(await reconcileInsights()).toEqual({ kind: "locked" });
});
it("uses localized fallback for an unrecognized protected API status", async () => {
  stubFetch(() => jsonResponse({ detail: "server-controlled unrecognized condition" }, { status: 400 }));
  expect(await reconcileInsights()).toEqual({ kind: "error", message: t("errors.generic") });
});
it("honors the exact reconcile lock already held by a competing document", async () => {
  const tails = new Map<string, Promise<unknown>>();
  const locks = { request: async <T>(name: string, callback: () => Promise<T>): Promise<T> => {
    const run = (tails.get(name) ?? Promise.resolve()).then(callback, callback); tails.set(name, run.catch(() => undefined)); return run;
  } };
  vi.stubGlobal("navigator", { ...navigator, locks });
  let acquired!: () => void, release!: () => void;
  const entered = new Promise<void>(resolve => { acquired = resolve; }), receipt = new Promise<void>(resolve => { release = resolve; });
  const sibling = withLock("mindpattern-reconcile", async () => { acquired(); await receipt; }); await entered;
  stubFetch(() => jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null }));
  const work = reconcile(); let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const outcome = await Promise.race([work.then(() => "released", () => "released"), new Promise<string>(resolve => { timer = setTimeout(() => resolve("still owned by sibling"), 100); })]);
    expect(outcome).toBe("still owned by sibling");
  } finally { if (timer !== undefined) clearTimeout(timer); release(); await sibling; await work; }
});
