/** Public App/Login/Patterns ordering regression.
 * Synthetic owned loopback HTTP/browser and Map backend are explicit.
 * Native fetch/Response/WebCrypto Promises are forwarded unchanged. A finite
 * unconditional timer releases A on both source versions; only independent
 * durable decryption and the restored public muted state are behavior oracles.
 */
import { createCipheriv, createDecipheriv, hkdfSync, pbkdf2Sync } from "node:crypto";
import { createServer, type Server } from "node:http";
import { act } from "react";
import type { ReactTestInstance, ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { hasSession, sessionUserId } from "../src/api/client";
import * as mutes from "../src/patternMutes";
import * as feedback from "../src/questionFeedback";
import { kv, newWriteGeneration, setKvBackendForTests, writeGenerationKey, type WritePermit } from "../src/kvstore";
import { applyLanguagePref } from "../src/strings";
import { vault } from "../src/vault";
import { resetTestState } from "./helpers/api";
import { buttonByLabel, isDisabled, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const OWNER = "0123456789abcdef0123456789abcdef";
const USERNAME = "pattern_mute_order_patient", PASSWORD = "correct horse battery staple";
const TOKEN = "synthetic-owned-pattern-order-bearer";
const SLOT = `mindpattern.patternMutes.v1.${OWNER}`, GENERATION = writeGenerationKey(OWNER);
const A = { pid: "topic:earlier-a", label: "A repeated morning observation" };
const B = { pid: "topic:later-b", label: "A repeated evening observation" };
const RELEASE_MS = 250; // Setup only; no timing/count behavioral assertion.
const nativeFetch = globalThis.fetch;
let root: ReactTestRenderer | undefined, server: Server | undefined;
let originals: Promise<unknown>[], writes: Promise<void>[], adoptions: Promise<Set<string>>[];
let faults: unknown[], restores: (() => void)[], records: Map<string, string>;
let key: Buffer, auth: Buffer, salt: Buffer, origin: string;
let held: boolean, armed: boolean, retired: boolean, release: () => void;
let timer: ReturnType<typeof setTimeout> | undefined;
let loginVerified: boolean;
const setup = (message: string, cause?: unknown): Error => new Error("SetupError: pattern-mute order producer: " + message, { cause });
function own<T>(original: Promise<T>): Promise<T> {
  originals.push(original);
  void original.then(undefined, cause => { faults.push(cause); });
  return original; // Exact original Promise; no async or replacement wrapper.
}
async function finite<T>(original: Promise<T>, label: string): Promise<T> {
  let deadline!: ReturnType<typeof setTimeout>;
  try { return await Promise.race([original, new Promise<T>((_yes, no) => { deadline = setTimeout(() => no(setup(label + " fixture deadline")), 15000); })]); }
  finally { clearTimeout(deadline); }
}
async function drain(): Promise<void> {
  let previous = -1;
  while (previous !== originals.length) {
    previous = originals.length;
    const results = await finite(Promise.allSettled(originals), "owned original producers");
    const failure = results.find(result => result.status === "rejected");
    if (failure?.status === "rejected") throw setup("unknown original producer rejection", failure.reason);
  }
  if (faults.length) throw setup("native/server observer fault", faults[0]);
}
async function until(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15000;
  while (!ready()) {
    if (faults.length) throw setup("producer refused before " + label, faults[0]);
    if (Date.now() >= deadline) throw setup(label + " public precondition deadline");
    await act(async () => { await new Promise<void>(yes => setTimeout(yes, 5)); });
  }
}
function seal(plaintext: Buffer, aad: string, nonceByte: number, dataKey: Buffer): string {
  const nonce = Buffer.alloc(12, nonceByte), cipher = createCipheriv("aes-256-gcm", dataKey, nonce);
  let positive: Buffer | undefined;
  try {
    cipher.setAAD(Buffer.from(aad)); const bytes = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag(), decipher = createDecipheriv("aes-256-gcm", dataKey, nonce);
    decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(tag);
    positive = Buffer.concat([decipher.update(bytes), decipher.final()]);
    if (!positive.equals(plaintext)) throw setup("independent authenticated fixture control differs");
    return Buffer.concat([nonce, bytes, tag]).toString("base64");
  } catch (cause) { throw setup("independent fixture seal/open refused", cause); }
  finally { nonce.fill(0); positive?.fill(0); }
}
function durablePids(): unknown {
  const wire = records.get(SLOT);
  if (typeof wire !== "string") throw setup("no original durable encrypted mute commit");
  const bytes = Buffer.from(wire, "base64"); let plain: Buffer | undefined;
  try {
    if (bytes.length < 28 || bytes.toString("base64") !== wire) throw setup("durable wire is not canonical authenticated ciphertext");
    const decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(JSON.stringify(["pattern-mutes", OWNER]))); decipher.setAuthTag(bytes.subarray(-16));
    plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
    return JSON.parse(plain.toString("utf8")) as unknown;
  } catch (cause) { throw setup("independent durable authenticated open refused", cause); }
  finally { plain?.fill(0); bytes.fill(0); }
}
function visibleCards(label: string): ReactTestInstance[] {
  if (!root) throw setup("missing mounted public App");
  return root.root.findAllByType("section").filter(node => node.findAllByType("h2").some(title => textOfNode(title) === label));
}
async function mute(label: string): Promise<void> {
  if (!root) throw setup("missing mounted public App");
  const cards = visibleCards(label);
  if (cards.length !== 1) throw setup("expected exactly one visible pattern card " + label);
  const controls: ReactTestInstance[] = cards[0]!.findAllByType("button").filter(node => textOfNode(node) === "Mute");
  if (controls.length !== 1 || controls[0]!.props.disabled === true || typeof controls[0]!.props.onClick !== "function") throw setup("public Mute is not enabled");
  await act(async () => { controls[0]!.props.onClick(); }); // Shipping handler intentionally returns void.
}
async function retire(): Promise<void> {
  if (retired) return; retired = true;
  const cleanup: unknown[] = [];
  if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
  try { release(); } catch (cause) { cleanup.push(cause); }
  try { await drain(); } catch (cause) { cleanup.push(cause); }
  if (root) { const mounted = root; root = undefined; try { await act(async () => { mounted.unmount(); }); } catch (cause) { cleanup.push(cause); } }
  try { await drain(); } catch (cause) { cleanup.push(cause); }
  for (const restore of restores.splice(0).reverse()) { try { restore(); } catch (cause) { cleanup.push(cause); } }
  try { vi.restoreAllMocks(); vi.unstubAllGlobals(); resetTestState(); } catch (cause) { cleanup.push(cause); }
  if (server) {
    const current = server; server = undefined;
    try { current.closeAllConnections(); await finite(new Promise<void>((yes, no) => current.close(cause => cause ? no(cause) : yes())), "owned server close"); } catch (cause) { cleanup.push(cause); }
  }
  key?.fill(0); auth?.fill(0); salt?.fill(0);
  if (globalThis.fetch !== nativeFetch) cleanup.push(setup("original fetch identity was not restored"));
  if (cleanup.length) throw setup("owned original producer/cleanup failed", cleanup[0]);
}

beforeEach(async () => {
  resetTestState(); vi.useRealTimers(); applyLanguagePref("en");
  originals = []; writes = []; adoptions = []; faults = []; restores = []; records = new Map();
  root = undefined; server = undefined; held = false; armed = false; retired = false; timer = undefined; release = () => undefined; loginVerified = false;
  salt = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  key = Buffer.from("4f934c7143c31fdf26d9ed3e715e0a76eaa07832dbd901dc15cba497f44b62d0", "hex");
  const master = pbkdf2Sync(PASSWORD, salt, 600000, 32, "sha256");
  auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  const kek = Buffer.from(hkdfSync("sha256", master, salt, "mindpattern/envelope/v2", 32)); master.fill(0);
  const params = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 };
  const wrapped = seal(key, JSON.stringify({ context: "envelope", kdf_params: params, username: USERNAME }), 41, kek); kek.fill(0);
  const payload = Buffer.from(JSON.stringify({ v: 2, state_seq: 8, stats: { patterns: [A, B].map(row => ({
    kind: "topic", label: row.label, occurrences: 4, confidence: 0.8,
    detail: { pattern_pid: row.pid, pattern_state: "confirmed" },
  })) } }));
  const insights = seal(payload, JSON.stringify(["insights", OWNER, "patterns"]), 42, key); payload.fill(0);
  setKvBackendForTests({
    getItem(slot) {
      const value = records.get(slot) ?? null;
      const original = new Promise<string | null>(yes => {
        if (armed && !held && slot === GENERATION) {
          held = true; let released = false;
          release = () => { if (!released) { released = true; yes(value); } };
        } else yes(value);
      });
      return own(original);
    },
    setItem(slot, value, permit?: WritePermit) {
      const original = new Promise<void>((yes, no) => {
        // Declared Map scope; strengthen the authored commit with the exact
        // captured generation, without claiming native IDB transaction proof.
        if (permit && (permit.owner !== OWNER || permit.generation !== (records.get(GENERATION) ?? null))) { no(setup("authored backend generation mismatch")); return; }
        records.set(slot, value); yes();
      }); return own(original);
    },
    removeItem(slot) { return own(new Promise<void>(yes => { records.delete(slot); yes(); })); },
    keys() { return own(Promise.resolve([...records.keys()])); },
    compareAndSet(slot, expected, value, _permit, stillCurrent) { return own(new Promise<boolean>(yes => {
      if ((stillCurrent && !stillCurrent()) || (records.get(slot) ?? null) !== expected) { yes(false); return; } records.set(slot, value); yes(true);
    })); },
  });
  const subtle = crypto.subtle;
  for (const name of ["importKey", "deriveBits", "encrypt", "decrypt"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(subtle, name), original = subtle[name];
    const observer = (...args: unknown[]) => { try { return own(Reflect.apply(original, subtle, args) as Promise<unknown>); } catch (cause) { faults.push(cause); throw setup("native " + name + " threw", cause); } };
    Object.defineProperty(subtle, name, { configurable: true, writable: true, value: observer });
    restores.push(() => { if (subtle[name] !== observer) throw setup("native observer identity changed"); if (descriptor) Object.defineProperty(subtle, name, descriptor); else if (!Reflect.deleteProperty(subtle, name)) throw setup("native observer removal failed"); if (subtle[name] !== original) throw setup("native identity not restored"); });
  }
  for (const name of ["text", "json"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(Response.prototype, name), original = Response.prototype[name];
    const observer = function(this: Response, ...args: unknown[]) { try { return own(Reflect.apply(original, this, args) as Promise<unknown>); } catch (cause) { faults.push(cause); throw setup("native Response " + name + " threw", cause); } };
    Object.defineProperty(Response.prototype, name, { configurable: true, writable: true, value: observer });
    restores.push(() => { if (Response.prototype[name] !== observer) throw setup("Response observer identity changed"); if (descriptor) Object.defineProperty(Response.prototype, name, descriptor); else if (!Reflect.deleteProperty(Response.prototype, name)) throw setup("Response observer removal failed"); if (Response.prototype[name] !== original) throw setup("Response identity not restored"); });
  }
  const write = mutes.writeMutedPids, adopt = mutes.adoptLegacyPlaintextMutes, patternFeedback = feedback.recordPatternMute;
  vi.spyOn(mutes, "writeMutedPids").mockImplementation((...args) => { const original = write(...args); writes.push(original); return own(original); });
  vi.spyOn(mutes, "adoptLegacyPlaintextMutes").mockImplementation((...args) => { const original = adopt(...args); adoptions.push(original); return own(original); });
  vi.spyOn(feedback, "recordPatternMute").mockImplementation((...args) => own(patternFeedback(...args)));
  await kv.setItem(GENERATION, await newWriteGeneration(OWNER, new Uint8Array(key)));
  server = createServer((request, response) => {
    const chunks: Buffer[] = []; request.on("data", chunk => chunks.push(Buffer.from(chunk)));
    request.on("error", cause => { faults.push(cause); });
    request.on("end", () => {
      const original = (async () => {
        const url = new URL(request.url ?? "", origin), path = url.pathname, method = request.method ?? "";
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown> : {};
        let value: unknown;
        if (path === "/api/v1/auth/salt" && method === "POST" && body.username === USERNAME) value = { salt: salt.toString("base64") };
        else if (path === "/api/v1/auth/login" && method === "POST" && body.username === USERNAME && body.verifier === auth.toString("base64")) { loginVerified = true; value = { token: TOKEN, user_id: OWNER, expires_in: 86400, role: "user", key_scheme: "v2" }; }
        else if (path === "/api/v1/meta" && method === "GET") value = { version: "synthetic-native", api_version: "v1", unlock_ttl_minutes: 30, sharing_enabled: true, llm_available: false, audio_available: false };
        else {
          if (request.headers.authorization !== "Bearer " + TOKEN) throw setup("protected original request lacks current bearer");
          if (path === "/api/v1/auth/key-envelope" && method === "GET") value = { key_scheme: "v2", salt: salt.toString("base64"), kdf_params: params, wrapped_data_key: wrapped };
          else if (path === "/api/v1/insights" && method === "GET") value = { phase: "insight", active_days: 8, days_remaining: 22, streak: 2, state_seq: 8, blob: insights };
          else if (path === "/api/v1/account/voice-consent" && method === "GET") value = { enabled: false, active_for_current_policy: false, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null };
          else if (path === "/api/v1/account/llm-consent" && method === "GET") value = { enabled: false, active_for_current_policy: false, llm_consent_at: null, llm_consent_disclosure: null, llm_consent_policy: null };
          else throw setup("unknown owned HTTP method/path " + method + " " + path);
        }
        response.writeHead(200, { "Content-Type": "application/json" }); response.end(JSON.stringify(value));
      })();
      own(original); void original.catch(() => { if (!response.headersSent) response.writeHead(500); response.end(); });
    });
  });
  server.on("error", cause => { faults.push(cause); });
  await finite(new Promise<void>((yes, no) => { server!.once("error", no); server!.listen(0, "127.0.0.1", () => { server!.removeListener("error", no); yes(); }); }), "owned server listen");
  const address = server.address(); if (!address || typeof address === "string") throw setup("owned server address"); origin = `http://127.0.0.1:${address.port}`;
  const savedWindow = window; vi.stubGlobal("window", { ...savedWindow, location: { ...savedWindow.location, origin, href: origin + "/" } });
  const fetchObserver = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || !url.pathname.startsWith("/api/v1/") || !init?.signal || init.signal.aborted) throw setup("unowned native fetch input");
    return own(nativeFetch(input, init));
  }; vi.stubGlobal("fetch", fetchObserver);
  restores.push(() => { if (globalThis.fetch !== fetchObserver) throw setup("fetch observation identity changed"); });
});
afterEach(async () => { await retire(); });

it.each(["healthy-sequential-control", "held-earlier-generation-read"] as const)(
  "separate visible public mutes retain both independently decrypted pattern ids: %s", async scenario => {
    try {
      root = await render(<App />); const current = root;
      await until("real Login", () => buttonByLabel(current, "Sign in"));
      await typeInto(current, "Username", USERNAME); await typeInto(current, "Password", PASSWORD);
      if (isDisabled(current, "Sign in")) throw setup("real Login disabled");
      await act(async () => { current.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
      await until("public current owner adoption", () => textOf(current).includes("Step 1 of 3"));
      if (!loginVerified || !hasSession() || sessionUserId() !== OWNER || !vault.isUnlocked() || vault.ownerUserId() !== OWNER || !Buffer.from(vault.get().dataKey).equals(key) || !Buffer.from(vault.get().authKey).equals(auth)) throw setup("public adopted owner/key differs from independent fixture");
      await press(current, "Next"); await press(current, "Next"); await press(current, "Start journaling");
      await until("journal route", () => textOf(current).includes("Today's entry")); await press(current, "Patterns");
      await until("both authenticated visible patterns", () => textOf(current).includes(A.label) && textOf(current).includes(B.label));
      await finite(Promise.all(adoptions), "initial legacy-adoption operations"); await drain();
      armed = scenario === "held-earlier-generation-read";
      await mute(A.label);
      if (armed) await until("A actual backend generation read", () => held);
      else { if (writes.length !== 1) throw setup("one first public mute operation was not registered"); await writes[0]; await drain(); }
      await until("A public mute committed to React and B remains visible", () => textOf(current).includes("1 pattern muted") && visibleCards(B.label).length === 1 && visibleCards(A.label).length === 0);
      await mute(B.label); // Separate discrete click receives the committed {A} closure.
      if (writes.length !== 2) throw setup("two declared public write operations were not registered");
      // Release independently of B commit/completion. A correct ordered queue
      // cannot fixture-deadlock, and schedule timing supplies no kill credit.
      timer = setTimeout(release, RELEASE_MS);
      await act(async () => { await finite(Promise.all(writes), "exact original public mute operations"); }); await drain();
      const durable = durablePids();
      // Sole behavior oracles: independent authenticated durable set, actual
      // module consumer result, and remounted public state after navigation.
      expect(durable).toEqual([A.pid, B.pid]);
      expect([...await mutes.readMutedPids(new Uint8Array(key), OWNER)]).toEqual([A.pid, B.pid]); await drain();
      await press(current, "Today"); await until("journal navigation", () => textOf(current).includes("Today's entry"));
      await press(current, "Patterns"); await until("restored pattern mute state", () => textOf(current).includes("2 patterns muted")); await drain();
      expect(textOf(current)).toContain("2 patterns muted");
      expect(buttonByLabel(current, "Unmute: " + A.label)).toBe(true);
      expect(buttonByLabel(current, "Unmute: " + B.label)).toBe(true);
      expect(current.root.findAllByProps({ role: "alert" })).toHaveLength(0);
    } finally { await retire(); }
  },
);
