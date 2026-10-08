/** Password proofs against actual credential storage, native crypto and HTTP
 * responses. A late provider answer may never authenticate a new vault. */
import crypto from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError } from "../src/api/client";
import { verifyPasswordForVault } from "../src/reauth";
import { vault } from "../src/vault";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { engine } from "./helpers/nodeEngine";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import { runTestControl } from "./helpers/testControl";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";

const USER = "a".repeat(32), PASSWORD = "native password proof", SALT = Buffer.alloc(16, 3);
const MASTER = crypto.pbkdf2Sync(PASSWORD, SALT, 600000, 32, "sha256");
const AUTH = Buffer.from(crypto.hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/auth/v1", 32));
const DATA = Buffer.from(crypto.hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/data/v1", 32));
let loginStatus: number, loginOwner: string, rejectTransport: boolean;
let responseBoundary: ((path: string) => Promise<void>) | undefined;
let transportBoundary: (() => Promise<void>) | undefined;
const held: Array<() => void> = [];
function open(known = true) {
  vault.unlock({ masterKey: Buffer.from(MASTER), authKey: known ? Buffer.from(AUTH) : Buffer.alloc(32), dataKey: Buffer.from(DATA) }, USER, { authKeyKnown: known });
}
function gate() {
  let entered = false, release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; }); held.push(release);
  return { run: async () => { entered = true; await pending; }, entered: () => entered, release };
}
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  await api.setSession("native bearer", USER, "alice"); await api.cacheSalt("alice", SALT.toString("base64")); open();
  loginStatus = 200; loginOwner = USER; rejectTransport = false; responseBoundary = undefined; transportBoundary = undefined;
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    if (rejectTransport) { await transportBoundary?.(); throw new Error("Native network unavailable"); }
    const path = new URL(url).pathname; const request = JSON.parse(String(init.body));
    const validProof = request.username === "alice" && request.verifier === AUTH.toString("base64");
    const status = path.endsWith("/auth/login") ? (validProof ? loginStatus : 401) : 200;
    const value = path.endsWith("/auth/salt") ? { salt: SALT.toString("base64") }
      : status === 200 ? { token: "new native bearer", user_id: loginOwner, role: "user", expires_in: 900 }
      : { error: { code: status === 401 ? "invalid_credentials" : "server_error", message: "Native login refused" } };
    const response = new Response(JSON.stringify(value), { status }); Object.defineProperty(response, "url", { value: url });
    const json = response.json.bind(response);
    response.json = async () => { const value = await json(); await responseBoundary?.(path); return value; };
    return response;
  });
});
afterEach(async () => {
  for (const release of held.splice(0)) release(); vi.restoreAllMocks(); vault.lock();
  await api.clearSession(); vi.unstubAllGlobals(); vi.useRealTimers();
});

it.each(["username", "cached-salt", "remote-salt", "cached-write", "derivation", "online-proof"] as const)("a retired native %s answer cannot release the old password proof", async phase => {
  const pause = gate();
  if (["remote-salt", "cached-write"].includes(phase)) await api.clearCachedSalt("alice");
  if (phase === "online-proof") open(false);
  if (phase === "username" || phase === "cached-salt") {
    const read = storage.getItem.bind(storage);
    vi.spyOn(storage, "getItem").mockImplementation(async key => {
      const value = await read(key);
      if ((phase === "username" && key === "@mindpattern/username") || (phase === "cached-salt" && key.includes("salt_") && value !== null)) await pause.run();
      return value;
    });
  } else if (phase === "cached-write") {
    const write = storage.setItem.bind(storage);
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { await write(key, value); if (key.includes("salt_")) await pause.run(); });
  } else if (phase === "derivation") {
    const derive = engine.pbkdf2.bind(engine);
    vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => {
      derive(password, salt, iterations, length, digest, (error, output) => { void pause.run().then(() => callback(error, output)); });
    });
  } else responseBoundary = async path => { if (path.endsWith(phase === "online-proof" ? "/auth/login" : "/auth/salt")) await pause.run(); };
  const proof = verifyPasswordForVault(PASSWORD);
  await vi.waitFor(() => expect(pause.entered()).toBe(true));
  // Same account and identical original vault: only credential retirement
  // distinguishes this new authenticated lifecycle from the old attempt.
  if (phase === "cached-write") {
    // The native credential writer is held, so credential retirement must
    // wait for it. A vault replacement can occur independently meanwhile.
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.from(AUTH), dataKey: Buffer.alloc(32, 7) }, USER);
  } else { await api.clearSession(); await api.setSession("replacement bearer", USER, "alice"); }
  pause.release();
  expect(await proof).toEqual({ ok: false, reason: "locked" });
  expect(await api.isLoggedIn()).toBe(true); expect(vault.get().authKeyKnown).toBe(phase !== "online-proof");
});

it.each(["data", "authentication"] as const)("a native proof cannot adopt a changed %s key slot", async slot => {
  const pause = gate(); open(false); responseBoundary = async path => { if (path.endsWith("/auth/login")) await pause.run(); };
  const proof = verifyPasswordForVault(PASSWORD); await vi.waitFor(() => expect(pause.entered()).toBe(true));
  if (slot === "authentication") vault.adoptAuthKey(Buffer.alloc(32, 9));
  else vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: Buffer.alloc(32, 7) }, USER, { authKeyKnown: false });
  const replacement = vault.get(); pause.release();
  expect(await proof).toEqual({ ok: false, reason: "locked" });
  expect(vault.get().authKey).toBe(replacement.authKey); expect(vault.get().dataKey).toBe(replacement.dataKey);
  expect(vault.get().authKey).toEqual(Buffer.alloc(32, 9));
});

it("a native proof cannot authenticate a different account's vault", async () => {
  const pause = gate(); const read = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async key => { const value = await read(key); if (key === "@mindpattern/username") await pause.run(); return value; });
  const proof = verifyPasswordForVault(PASSWORD); await vi.waitFor(() => expect(pause.entered()).toBe(true));
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, "b".repeat(32)); pause.release();
  expect(await proof).toEqual({ ok: false, reason: "locked" }); expect(vault.ownerUserId()).toBe("b".repeat(32));
});

it.each([401, 500, "transport"] as const)("a native biometric login failure %s keeps the unknown authentication slot", async failure => {
  open(false); if (failure === "transport") rejectTransport = true; else loginStatus = failure;
  expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: failure === 401 ? "wrong-password" : "offline" });
  expect(vault.get().authKeyKnown).toBe(false); expect(vault.get().authKey).toEqual(Buffer.alloc(32));
});
it.each(["biometric-rejection", "biometric-transport", "salt-transport"] as const)("a late %s failure reports retirement rather than blaming the replacement password", async phase => {
  const pause = gate();
  if (phase.startsWith("biometric")) open(false); else await api.clearCachedSalt("alice");
  if (phase === "biometric-rejection") { loginStatus = 500; responseBoundary = async path => { if (path.endsWith("/auth/login")) await pause.run(); }; }
  else { rejectTransport = true; transportBoundary = pause.run; }
  const proof = verifyPasswordForVault(PASSWORD); await vi.waitFor(() => expect(pause.entered()).toBe(true));
  await api.clearSession(); await api.setSession("replacement bearer", USER, "alice"); pause.release();
  expect(await proof).toEqual({ ok: false, reason: "locked" }); expect(await api.isLoggedIn()).toBe(true);
});
it("a native biometric proof for another server account refuses key adoption", async () => {
  open(false); loginOwner = "b".repeat(32);
  expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "locked" }); expect(vault.get().authKeyKnown).toBe(false);
});
it("a current native biometric proof publishes a separately owned key and its verifier", async () => {
  open(false); expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: true, verifierB64: AUTH.toString("base64") });
  expect(vault.get().authKeyKnown).toBe(true); expect(vault.get().authKey).toEqual(AUTH); expect(vault.get().dataKey).toEqual(DATA);
});
it("a delayed native local mismatch is retired while the visible retry floor is pending", async () => {
  const pause = gate(), derive = engine.pbkdf2.bind(engine);
  vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => {
    derive(password, salt, iterations, length, digest, (error, output) => { void pause.run().then(() => callback(error, output)); });
  });
  const proof = verifyPasswordForVault("wrong native password"); await vi.waitFor(() => expect(pause.entered()).toBe(true));
  vi.useFakeTimers(); pause.release(); await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
  await vi.waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
  await api.clearSession(); await vi.advanceTimersByTimeAsync(500);
  expect(await proof).toEqual({ ok: false, reason: "locked" });
});
it("native username loss yields account recovery rather than a password verdict", async () => {
  await secureStore.removeItem("@mindpattern/username"); expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "no-account" });
});
it("unavailable native salt transport reports an offline proof", async () => {
  await api.clearCachedSalt("alice"); rejectTransport = true; expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "offline" });
});
it("a completed native proof erases all provider-held owned secret buffers", async () => {
  const input = engine.hkdfSync.bind(engine), allocations: Buffer[] = [];
  vi.spyOn(engine, "hkdfSync").mockImplementation((digest, master, salt, info, size) => { allocations.push(master); return input(digest, master, salt, info, size); });
  expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: true, verifierB64: AUTH.toString("base64") });
  expect(allocations.length).toBeGreaterThan(0); for (const allocation of allocations) expect(allocation.every(byte => byte === 0)).toBe(true);
});
it.each(["username", "cached-salt", "remote-salt", "cached-write"] as const)("retirement after native %s settles before another unavailable provider job", async phase => {
  const unavailable = gate(); let retired = false;
  if (phase === "remote-salt" || phase === "cached-write") await api.clearCachedSalt("alice");
  const replaceVault = () => vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.from(AUTH), dataKey: Buffer.alloc(32, 9) }, USER);
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await read(key);
    if (phase === "username" && key === "@mindpattern/username" && !retired) { retired = true; await api.clearSession(); }
    if (phase === "username" && retired && key.includes("salt_")) await unavailable.run();
    if (phase === "cached-salt" && key.includes("salt_") && value !== null && !retired) { retired = true; replaceVault(); }
    return value;
  });
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    await write(key, value);
    if (phase === "remote-salt" && retired && key.includes("salt_")) await unavailable.run();
    if (phase === "cached-write" && key.includes("salt_") && !retired) { retired = true; replaceVault(); }
  });
  if (phase === "remote-salt") responseBoundary = async path => { if (path.endsWith("/auth/salt") && !retired) { retired = true; replaceVault(); } };
  if (phase === "cached-salt" || phase === "cached-write") {
    const derive = engine.pbkdf2.bind(engine);
    vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => {
      derive(password, salt, iterations, length, digest, (error, output) => { void unavailable.run().then(() => callback(error, output)); });
    });
  }
  let result: unknown; const proof = verifyPasswordForVault(PASSWORD).then(value => { result = value; return value; });
  try {
    // This is a public completion assertion with a finite Native provider
    // gate. Its failure is an assertion, and the held job is then released;
    // neither the Vitest watchdog nor an infinite fixture earns a kill.
    await vi.waitFor(() => expect(result).toEqual({ ok: false, reason: "locked" }), { timeout: 1000 });
  } finally { unavailable.release(); await proof; }
});
