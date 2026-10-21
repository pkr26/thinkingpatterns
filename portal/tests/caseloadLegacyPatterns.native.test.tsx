/** Separate tools-only Patient674 witness. Actual App/Login/MFA, production
 * scan and native WebCrypto consume independently authenticated older payloads.
 * Owned Node HTTP and original native fetch Promises provide finite transport. */
import { createCipheriv, createDecipheriv, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import * as cryptography from "../src/crypto";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const USERNAME = "synthetic_legacy_scan";
const PASSWORD = "correct horse battery staple";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const OWNER = "0123456789abcdef0123456789abcdef";
const PATIENTS = ["fedcba9876543210fedcba9876543210", "11111111111111111111111111111111"];
const TOKEN = "synthetic-native-legacy-scan-token";
const nativeFetch = globalThis.fetch;
type Scenario = "older-authenticated-stats-without-patterns" | "authenticated-empty-patterns-positive-control";
type Witness = { requests: { path: string; method: string }[]; transportFaults: string[]; nativeFetchPromisesCreated: number; nativeFetchPromisesCompleted: number; nativeResponseBodiesCompleted: number };

function seal(key: Buffer, aad: string[], plain: Buffer): string {
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, nonce);
  const associated = Buffer.from(JSON.stringify(aad)); cipher.setAAD(associated);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]), tag = cipher.getAuthTag();
  const open = createDecipheriv("aes-256-gcm", key, nonce); open.setAAD(associated); open.setAuthTag(tag);
  const verified = Buffer.concat([open.update(encrypted), open.final()]);
  if (!verified.equals(plain)) throw new Error("SetupError: independent AES-GCM fixture did not authenticate");
  verified.fill(0); return Buffer.concat([nonce, encrypted, tag]).toString("base64");
}

function fixture(scenario: Scenario, patientIds: readonly string[] = PATIENTS) {
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/portal-wrap/v1"), 32));
  const identity = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = identity.privateKey.export({ type: "pkcs8", format: "der" });
  const publicDer = identity.publicKey.export({ type: "spki", format: "der" });
  try {
    const rows = patientIds.map((id, index) => {
      const ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const ephDer = ephemeral.publicKey.export({ type: "spki", format: "der" });
      const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: identity.publicKey });
      const kek = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephDer, publicDer]), Buffer.from("mindpattern/wrap/v1"), 32));
      const dataKey = randomBytes(32);
      const stats = scenario === "older-authenticated-stats-without-patterns"
        ? { avg_sentiment: 0, total_entries: 4, active_days: 4 }
        : { avg_sentiment: 0, total_entries: 4, active_days: 4, patterns: [] };
      try {
        return {
          patient: { user_id: id, username: `Synthetic legacy scan ${index + 1}`, status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null,
            ephemeral_pub: ephDer.toString("base64"), wrapped_key: seal(kek, ["consent-wrap", id, OWNER], dataKey), share_voice: false,
            summary_eph_pub: ephDer.toString("base64"), summary_blob: seal(kek, ["caseload-summary", id, OWNER], Buffer.from(JSON.stringify({ patterns: id === "__proto__" ? 3 : 1, sensitive: true, newest: "2026-09-30", for_date: "2026-09-30" }))), summary_updated_at: "2026-09-30T00:00:00Z" },
          insights: { phase: "insight", active_days: 4, streak: 1, days_remaining: 0, state_seq: 7,
            blob: seal(dataKey, ["insights", id, "patterns"], Buffer.from(JSON.stringify({ v: 2, state_seq: 7, stats }))) },
        };
      } finally { shared.fill(0); kek.fill(0); dataKey.fill(0); }
    });
    return { verifier: auth.toString("base64"), publicKeyB64: publicDer.toString("base64"), privateEnvelope: seal(wrap, ["therapist-key", USERNAME], privateDer), rows };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); privateDer.fill(0); }
}

async function finite<T>(name: string, original: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([original, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`ExecutionError: original producer did not complete: ${name}`)), 15_000); })]); }
  finally { if (timer) clearTimeout(timer); }
}
async function completed(name: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: public producer completion not observed: ${name}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  await flush();
}


type Transport = { server: Server; originals: Promise<Response>[]; retire: () => Promise<void> };
let root: ReactTestRenderer | undefined, owned: Transport | undefined;
async function transport(account: ReturnType<typeof fixture>, witness: Witness, refusedPatient?: string): Promise<Transport> {
  let origin = "";
  const server = createServer((request, response) => {
    void (async () => {
      let body = ""; for await (const chunk of request) body += String(chunk);
      const url = new URL(request.url ?? "", origin), path = url.pathname;
      witness.requests.push({ path, method: request.method ?? "GET" });
      if (body.includes(PASSWORD)) throw new Error("SetupError: plaintext password reached native HTTP receiver");
      const parsed = body ? JSON.parse(body) as Record<string, unknown> : {};
      let value: unknown, status = 200;
      if (path === "/api/v1/meta") value = { sharing_available: true };
      else if (path === "/api/v1/auth/salt") value = { salt: SALT };
      else if (path === "/api/v1/auth/login") {
        if (parsed.username !== USERNAME || parsed.verifier !== account.verifier) throw new Error("SetupError: native login verifier differs from independent600k account");
        if (parsed.totp_code === undefined) { status = 401; value = { detail: "MFA is required", code: "totp_required" }; }
        else {
          if (parsed.totp_code !== "123456") throw new Error("SetupError: native MFA scenario received an unowned code");
          value = { token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86_400, mfa_enrollment_required: false };
        }
      } else {
        if (request.headers.authorization !== `Bearer ${TOKEN}`) throw new Error("SetupError: native protected HTTP request lacks current bearer");
        if (path === "/api/v1/auth/logout") { status = 204; value = undefined; }
        else if (path === "/api/v1/therapist/me") value = { username: USERNAME, display_name: "Dr. Native Legacy Scan", wrap_pub_key: account.publicKeyB64, wrap_key_blob: account.privateEnvelope, totp_enabled: true };
        else if (path === "/api/v1/therapist/patients") value = account.rows.map(row => row.patient);
        else {
          const row = account.rows.find(candidate => path === `/api/v1/therapist/patients/${candidate.patient.user_id}/insights`);
          if (!row) throw new Error(`SetupError: unexpected native HTTP producer ${path}`);
          if (row.patient.user_id === refusedPatient) { status = 403; value = { detail: "Sharing was revoked before this scan" }; }
          else value = row.insights;
        }
      }
      response.once("finish", () => { witness.nativeResponseBodiesCompleted += 1; });
      response.writeHead(status, { "Content-Type": "application/json" }); response.end(value === undefined ? undefined : JSON.stringify(value));
    })().catch(error => {
      witness.transportFaults.push(`SetupError: native receiver fault: ${String(error)}`);
      if (!response.headersSent) response.writeHead(500, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ detail: "owned fixture failure", code: "witness_setup_fault" }));
    });
  });
  server.on("error", error => { witness.transportFaults.push(`SetupError: native HTTP server fault: ${String(error)}`); });
  await finite("HTTP bind", new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); }));
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: owned native server has no address");
  origin = `http://127.0.0.1:${address.port}`;
  // The actual API verifies native Response.url against the configured App
  // origin. Install this owned public test host origin before rendering App;
  // no response-origin property or API session/private state is rewritten.
  vi.stubGlobal("window", { ...window, location: { ...window.location, origin } });
  const originals: Promise<Response>[] = [];
  vi.stubGlobal("fetch", (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const source = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (source.origin !== window.location.origin) throw new Error("SetupError: native fetch wrapper received an unexpected public origin");
    const url = new URL(source.pathname + source.search, origin);
    const original = nativeFetch(url, init); originals.push(original); witness.nativeFetchPromisesCreated += 1;
    void original.then(() => { witness.nativeFetchPromisesCompleted += 1; }, error => { witness.transportFaults.push(`SetupError: genuine native fetch failure: ${String(error)}`); });
    return original;
  });
  const current: Transport = { server, originals, retire: async () => {
    await finite("all native fetch settlement", Promise.allSettled(originals));
    vi.unstubAllGlobals();
    server.closeAllConnections(); await finite("owned native HTTP retirement", new Promise<void>((resolve, reject) => server.close(error => error ? reject(new Error(`SetupError: native HTTP retirement: ${String(error)}`)) : resolve())));
     if (owned === current) owned = undefined;
  } }; owned = current; return current;
}

beforeEach(() => { vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = ""; });
afterEach(async () => {
  await act(async () => { root?.unmount(); }); root = undefined; clearSession();
  const current = owned; owned = undefined; if (current) await current.retire();
  vi.restoreAllMocks(); vi.unstubAllGlobals();
});

it.each(["older-authenticated-stats-without-patterns", "authenticated-empty-patterns-positive-control"] as const)("actual authenticated manual triage scan completes %s and retires stale sensitive summaries", async scenario => {
  const witness: Witness = { requests: [], transportFaults: [], nativeFetchPromisesCreated: 0, nativeFetchPromisesCompleted: 0, nativeResponseBodiesCompleted: 0 };
  const originals: { patient: string; promise: ReturnType<typeof cryptography.decryptInsights> }[] = [];
  let current: Transport | undefined;
  try {
    const account = fixture(scenario); current = await transport(account, witness);
    const realDecrypt = cryptography.decryptInsights;
    vi.spyOn(cryptography, "decryptInsights").mockImplementation((...args) => {
      const expected = account.rows.find(row => row.patient.user_id === args[1]);
      if (!expected || expected.insights.blob !== args[2]) throw new Error("SetupError: scan decrypt observes an unowned patient or wire");
      const original = realDecrypt(...args); originals.push({ patient: args[1], promise: original });  return original;
    });
    root = await render(<App />);
    await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD); await press(root, "Sign in");
    await completed("password-only native401 and MFA stage", () => root!.root.findAllByType("button").some(button => textOfNode(button) === "Verify code"));
    if (hasSession() || witness.requests.some(row => row.path === "/api/v1/therapist/me")) throw new Error("SetupError: password-only native401 did not fence App identity adoption");

    await typeInto(root, "Authenticator code (or recovery code)", "123456"); await press(root, "Verify code");
    await completed("actual caseload and authenticated old sensitive summaries", () => textOf(root!).includes("2 of your patients have sensitive cards") && root!.root.findAllByType("button").some(button => textOfNode(button) === "Scan caseload for triage"));
    await press(root, "Scan caseload for triage"); await press(root, "Start the triage scan");
    await completed("two original authenticated scan decrypt producers", () => originals.length === 2);
    let opened!: Awaited<ReturnType<typeof cryptography.decryptInsights>>[];
    try { await act(async () => { opened = await finite("unchanged native scan decrypt Promises", Promise.all(originals.map(row => row.promise))); }); }
    catch (error) { throw new Error(`SetupError: original authenticated scan decrypt failed: ${String(error)}`); }
    await completed("public scan busy retirement", () => root!.root.findAllByType("button").some(button => textOfNode(button) === "Scan caseload for triage" && button.props.disabled !== true));
    await finite("native HTTP producers settle", Promise.allSettled(current.originals)); await flush(8);
    if (witness.transportFaults.length || witness.nativeFetchPromisesCreated !== witness.nativeFetchPromisesCompleted || witness.nativeResponseBodiesCompleted !== witness.nativeFetchPromisesCreated
      || originals.map(row => row.patient).join(",") !== PATIENTS.join(",") || opened.some(payload => payload.state_seq !== 7 || payload.stats.avg_sentiment !== 0 || Object.prototype.hasOwnProperty.call(payload.stats, "patterns") !== (scenario === "authenticated-empty-patterns-positive-control"))) {
      throw new Error(`SetupError: completed native/public producer custody differs from the independent scan fixture: ${JSON.stringify(witness.transportFaults)}`);
    }


    // These finite UI expectations live directly in the registered body.
    expect(root.root.findAllByType("p").filter(node => textOfNode(node).includes("0 patterns (scanned just now)"))).toHaveLength(2);
    expect(textOf(root)).not.toContain("have sensitive cards");
    expect(textOf(root)).not.toContain("has a sensitive card");
    expect(textOf(root)).not.toContain("Something went wrong");
    expect(root.root.findAll(node => node.props.role === "alert")).toHaveLength(0);
    expect(hasSession()).toBe(true);

    if (scenario === "authenticated-empty-patterns-positive-control") {
      // This is an accepted wire ID, not a new-user UUID-generator claim.
      // Keep the fallback payload authentically encrypted and let the real
      // client construct its own HTTP403 refusal after a successful roster.
      await act(async () => { root?.unmount(); }); root = undefined; clearSession();
      await current.retire(); current = undefined; vi.restoreAllMocks();
      const prototypeWitness: Witness = { requests: [], transportFaults: [], nativeFetchPromisesCreated: 0, nativeFetchPromisesCompleted: 0, nativeResponseBodiesCompleted: 0 };
      const prototypeAccount = fixture(scenario, ["__proto__", PATIENTS[0]!]);
      current = await transport(prototypeAccount, prototypeWitness, "__proto__");
      root = await render(<App />);
      await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD); await press(root, "Sign in");
      await completed("prototype-ID public MFA stage", () => root!.root.findAllByType("button").some(button => textOfNode(button) === "Verify code"));
      await typeInto(root, "Authenticator code (or recovery code)", "123456"); await press(root, "Verify code");
      await completed("prototype-ID authenticated dated caseload summary and scan toolbar", () => textOf(root!).includes("3 patterns as of") && root!.root.findAllByType("button").some(button => textOfNode(button) === "Scan caseload for triage"));
      await press(root, "Scan caseload for triage");
      if (root.root.findAllByType("button").some(button => textOfNode(button) === "Start the triage scan")) await press(root, "Start the triage scan");
      await completed("prototype-ID real denied scan response", () => prototypeWitness.requests.some(request => request.path === "/api/v1/therapist/patients/__proto__/insights"));
      await finite("prototype-ID original native fetch settlement", Promise.allSettled(current.originals));
      await completed("prototype-ID public scan busy retirement", () => root!.root.findAllByType("button").some(button => textOfNode(button) === "Scan caseload for triage" && button.props.disabled !== true));
      await flush(8);
      expect(prototypeWitness.transportFaults).toEqual([]);
      expect(textOf(root)).toContain("3 patterns as of");
    }


  }
  finally {
    await act(async () => { root?.unmount(); }); root = undefined; clearSession();
    await finite("owned scan producer retirement", Promise.allSettled(originals.map(row => row.promise)));
    vi.restoreAllMocks(); if (current) await current.retire();
  }
});
