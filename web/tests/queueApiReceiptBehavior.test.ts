import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { auth, sessionUserId, setSession } from "../src/api/client";
import { abortInFlightFlush, enqueue, flushQueue } from "../src/offlineQueue";
import { kv, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const owner = "queue-native-api-receipt";
let physical: Map<string, string>;
beforeEach(() => {
  resetTestState(); installSession(owner); physical = new Map();
  setKvBackendForTests({ getItem: async k => physical.get(k) ?? null, setItem: async (k, v) => { physical.set(k, v); }, removeItem: async k => { physical.delete(k); }, keys: async () => [...physical.keys()] });
});
afterEach(() => { abortInFlightFlush(); setKvBackendForTests(null); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function nativeBody(status: number, body: unknown) {
  let deliver!: () => void;
  const response = new Response(new ReadableStream<Uint8Array>({ start(controller) {
    deliver = () => { controller.enqueue(new TextEncoder().encode(JSON.stringify(body))); controller.close(); };
  } }), { status, headers: { "Content-Type": "application/json" } });
  return { response, deliver };
}
it.each([[200, "login-first"], [200, "entry-first"], [409, "login-first"], [409, "entry-first"]] as const)
  ("keeps account ciphertext coherent across paired actual API response bodies: %s/%s", async (status, order) => {
    await enqueue({ userId: owner, clientEntryId: "old-entry", blobB64: "retained encrypted writing", entryDate: "2026-10-07" });
    const queue = [...physical.keys()].find(k => k.startsWith("mindpattern/queue.v1.items."))!, before = physical.get(queue);
    const entry = nativeBody(status, status === 200 ? { id: "server-accepted" } : { detail: "conflicting entry" });
    const login = nativeBody(200, { token: "new-verified-token", user_id: owner, role: "patient", expires_in: 3600 });
    let entryRequested!: () => void, loginRequested!: () => void;
    const posted = new Promise<void>(resolve => { entryRequested = resolve; }), authenticated = new Promise<void>(resolve => { loginRequested = resolve; });
    const replacementVerifierRequests: string[] = [];
    stubFetch((url, init) => {
      if (url.endsWith("/auth/login")) { loginRequested(); return login.response; }
      if (url.endsWith("/entries") && init.method === "POST") { entryRequested(); return entry.response; }
      if (new Headers(init.headers).get("Authorization") === "Bearer new-verified-token") replacementVerifierRequests.push(url);
      return new Response(JSON.stringify({ detail: "unavailable verification" }), { status: 503, headers: { "Content-Type": "application/json" } });
    });
    const drain = flushQueue(owner), adopt = auth.login("tester", "verified-key-proof").then(token => { setSession(token.token, token.user_id, "tester"); });
    await Promise.all([posted, authenticated]);
    // Two physical HTTP body deliveries in one browser task. The installed
    // ReadableStream/Response and actual API wrappers supply every courier.
    if (order === "login-first") { login.deliver(); entry.deliver(); }
    else { entry.deliver(); login.deliver(); }
    const [sent] = await Promise.all([drain, adopt]);
    expect(sessionUserId()).toBe(owner); expect(sent).toBe(0);
    expect(physical.get(queue)).toBe(before);
    expect(replacementVerifierRequests).toEqual([]);
  });
it.each(["queue-first", "login-first"] as const)("keeps Native queue commit admission coherent with a verified login's write-permit receipt: %s", async order => {
  const replacement = "verified-next-owner", replacementKey = new Uint8Array(new ArrayBuffer(32)).fill(91);
  await enqueue({ userId: owner, clientEntryId: "accepted-before-login", blobB64: "old encrypted writing", entryDate: "2026-10-07" });
  const queue = [...physical.keys()].find(k => k.startsWith("mindpattern/queue.v1.items."))!, before = physical.get(queue);
  let serverAccepted = false, actorRead!: () => void, queueRead!: () => void, deliverActor!: () => void, deliverQueue!: () => void;
  const actorStarted = new Promise<void>(resolve => { actorRead = resolve; }), queueStarted = new Promise<void>(resolve => { queueRead = resolve; });
  const actorReceipt = new Promise<void>(resolve => { deliverActor = resolve; }), queueReceipt = new Promise<void>(resolve => { deliverQueue = resolve; });
  setKvBackendForTests({
    async getItem(key) {
      const captured = physical.get(key) ?? null;
      if (key === writeGenerationKey(replacement)) { actorRead(); await actorReceipt; }
      if (key === queue && serverAccepted) { queueRead(); await queueReceipt; }
      return captured;
    },
    async setItem(key, value) { physical.set(key, value); }, async removeItem(key) { physical.delete(key); }, async keys() { return [...physical.keys()]; },
  });
  stubFetch((url, init) => {
    if (url.endsWith("/auth/login")) return jsonResponse({ token: "next-authenticated-token", user_id: replacement, role: "patient", expires_in: 3600 });
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer token-123"); serverAccepted = true;
    return jsonResponse({ id: "physically-accepted" });
  });
  const token = await auth.login("next-patient", "authenticated-proof");
  // Real key-tag hashing and the exported permit helper precede adoption.
  // Both Native reads have completed physically before their JS couriers.
  const adopt = kv.captureWritePermit(replacement, replacementKey).then(() => { setSession(token.token, token.user_id, "next-patient"); });
  await actorStarted; const work = flushQueue(owner); await queueStarted;
  if (order === "queue-first") { deliverQueue(); deliverActor(); } else { deliverActor(); deliverQueue(); }
  const [sent] = await Promise.all([work, adopt]); replacementKey.fill(0);
  expect(sent).toBe(1); expect(sessionUserId()).toBe(replacement);
  if (order === "queue-first") expect(physical.has(queue)).toBe(false);
  else expect(physical.get(queue)).toBe(before);
});
