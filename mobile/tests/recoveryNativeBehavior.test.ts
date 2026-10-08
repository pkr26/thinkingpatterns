/** Recovery through Native credential/storage/crypto providers. The Native
 * server independently authenticates the kit, processing key and new wrap. */
import crypto from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError } from "../src/api/client";
import { recoverAccountWithKey } from "../src/recoveryFlow";
import * as kdf from "../src/crypto/kdf";
import * as recoveryCrypto from "../src/crypto/recovery";
import type { KdfParams } from "../src/crypto/keyEnvelope";
import { engine } from "./helpers/nodeEngine";
import { setSecureStoreBackend } from "../src/secureStore";
import { vault } from "../src/vault";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
const USER = "a".repeat(32), OTHER = "b".repeat(32), KEY = Buffer.alloc(32, 4), DATA = Buffer.alloc(32, 7), PASSWORD = "a new Native recovery password";
function hkdf(key: Buffer, salt: Buffer, label: string) { return Buffer.from(crypto.hkdfSync("sha256", key, salt, label, 32)); }
function sealed(scheme: "v1" | "v2") {
  const kek = hkdf(KEY, Buffer.alloc(32), scheme === "v1" ? "mindpattern/recovery/v1" : "mindpattern/recovery-seal/v2"), nonce = Buffer.alloc(12, 9);
  const cipher = crypto.createCipheriv("aes-256-gcm", kek, nonce); cipher.setAAD(Buffer.from(JSON.stringify(["recovery", USER, "data-key"])));
  return Buffer.concat([nonce, cipher.update(DATA), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
const PREPARED_SEALS = { v1: sealed("v1"), v2: sealed("v2") };
let scheme: "v1" | "v2", canonical: unknown, processing: unknown, resetStatus: number, recoveryStatus: number, resets: number;
let reportedScheme: unknown, cachedBody: Record<string, unknown> | undefined;
let inNativeServer = false;
let boundary: ((path: string) => Promise<void>) | undefined;
let nativeCompletion: ((path: string) => void) | undefined;
const releases: Array<() => void> = [];
function gate() { let entered = false, release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; }); releases.push(release); return { run: async () => { entered = true; await pending; }, entered: () => entered, release }; }
function proof() { return scheme === "v1" ? KEY.toString("base64") : hkdf(KEY, Buffer.alloc(32), "mindpattern/recovery-verifier/v2").toString("base64"); }
function kit(selected: "v1" | "v2" = scheme) { return `mindpattern-recovery:${selected}:${KEY.toString("base64")}`; }
function deliverNativeEvent(turns: number, event: () => void): void { if (turns === 0) event(); else queueMicrotask(() => deliverNativeEvent(turns - 1, event)); }
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock(); await api.clearSession();
  scheme = "v2"; canonical = "alice"; processing = "native-processing"; resetStatus = 200; recoveryStatus = 200; reportedScheme = "v2"; resets = 0; cachedBody = undefined; boundary = undefined; nativeCompletion = undefined;
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    inNativeServer = true;
    try {
    const path = new URL(url).pathname, body = JSON.parse(String(init.body)); let value: unknown, status = 200;
    if (path.endsWith("/auth/recover")) {
      status = recoveryStatus;
      if (body.username !== "alice" || body.verifier !== proof() || body.scheme !== scheme) status = 401;
      value = status === 200 ? { token: "recovered native bearer", user_id: USER, role: "user", key_scheme: "v2", recovery_scheme: reportedScheme, username: canonical, recovery_wrapped_data_key: PREPARED_SEALS[scheme] }
        : { error: { code: "invalid_credentials", message: "Recovery proof rejected" } };
    } else if (path.endsWith("/processing/sessions")) {
      status = body.data_key === DATA.toString("base64") ? 200 : 403;
      value = status === 200 ? { session_token: processing } : { error: { code: "invalid_credentials", message: "Recovered key rejected" } };
    } else if (path.endsWith("/account/recovery/password")) {
      status = resetStatus;
      const headers = new Headers(init.headers);
      try {
        if (body.proof !== proof() || headers.get("X-Processing-Token") !== "native-processing") throw new Error("Recovery authorization rejected");
        const salt = Buffer.from(body.new_salt, "base64"), params = body.new_kdf_params;
        const master = crypto.pbkdf2Sync(PASSWORD, salt, params.iterations, 32, "sha256");
        if (body.new_verifier !== hkdf(master, Buffer.alloc(32), "mindpattern/auth/v1").toString("base64")) throw new Error("New verifier rejected");
        const wrap = Buffer.from(body.wrapped_data_key, "base64"), decipher = crypto.createDecipheriv("aes-256-gcm", hkdf(master, salt, "mindpattern/envelope/v2"), wrap.subarray(0, 12));
        decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username: typeof canonical === "string" && canonical ? canonical : "alice" }))); decipher.setAuthTag(wrap.subarray(-16));
        if (!Buffer.concat([decipher.update(wrap.subarray(12, -16)), decipher.final()]).equals(DATA)) throw new Error("New envelope rejected");
      } catch { status = 400; }
      if (status === 200) { resets++; cachedBody = body; }
      value = status === 200 ? {} : { error: { code: "reset_refused", message: "Native reset refused" } };
    } else throw new Error("Unexpected Native route " + path);
    const response = new Response(JSON.stringify(value), { status }); Object.defineProperty(response, "url", { value: url });
    const json = response.json.bind(response); response.json = async () => { const answer = await json(); await boundary?.(path); nativeCompletion?.(path); return answer; }; return response;
    } finally { inNativeServer = false; }
  });
});
afterEach(async () => { for (const release of releases.splice(0)) release(); vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals(); });

it.each(["v1", "v2"] as const)("a Native %s kit installs the recovered key and a usable password envelope", async selected => {
  scheme = selected; reportedScheme = selected;
  const result = await recoverAccountWithKey("  alice  ", ` \n ${kit()} \n`, PASSWORD, "v2");
  expect(result).toMatchObject({ userId: USER, username: "alice", dataKey: DATA, localCacheReady: true }); expect(resets).toBe(1); expect(await api.isLoggedIn()).toBe(true);
  expect(await api.getCachedSalt("alice")).toBe(cachedBody!.new_salt);
  expect(await api.getCachedKeyEnvelope("alice")).toMatchObject({ scheme: "v2", saltB64: cachedBody!.new_salt, wrappedB64: cachedBody!.wrapped_data_key });
});
it.each([undefined, null, "", 0, false, {}, []])("native canonical username %j falls back to the trimmed requested account", async value => {
  canonical = value; const result = await recoverAccountWithKey(" alice ", kit(), PASSWORD, "v2"); expect(result.username).toBe("alice"); expect(await api.getUsername()).toBe("alice"); expect(resets).toBe(1);
});
it.each([null, undefined, "", 0, false, {}, []])("native processing token %j cannot reset or publish success", async value => {
  processing = value; await expect(recoverAccountWithKey("alice", kit(), PASSWORD, "v2")).rejects.toThrow("Invalid processing-session response"); expect(resets).toBe(0); expect(await api.isLoggedIn()).toBe(false);
});
it("a Native authentication refusal does not install recovery credentials", async () => {
  recoveryStatus = 401; await expect(recoverAccountWithKey("alice", kit(), PASSWORD, "v2")).rejects.toMatchObject({ status: 401 }); expect(await api.isLoggedIn()).toBe(false); expect(resets).toBe(0);
});
it.each([undefined, null, "v1", "future"]) ("a Native recovery scheme %j cannot silently reinterpret a v2 kit", async value => {
  reportedScheme = value; await expect(recoverAccountWithKey("alice", kit(), PASSWORD, "v2")).rejects.toThrow("recovery scheme does not match"); expect(resets).toBe(0); expect(await api.isLoggedIn()).toBe(false);
});
it("a labeled v2 kit refuses a legacy UI selection before sending the raw recovery secret", async () => {
  await expect(recoverAccountWithKey("alice", ` \n ${kit()} \n`, PASSWORD, "v1")).rejects.toThrow("v2 recovery kit cannot be used as a legacy kit"); expect(await api.isLoggedIn()).toBe(false); expect(resets).toBe(0);
});
it("a Native legacy kit with omitted scheme metadata retains the explicit v1 selection", async () => {
  scheme = "v1"; reportedScheme = undefined;
  const result = await recoverAccountWithKey("alice", kit(), PASSWORD, "v1"); expect(result.dataKey).toEqual(DATA); expect(resets).toBe(1);
});
it("the active Native UI attempt can complete with an explicit current callback", async () => {
  const result = await recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => true }); expect(result.dataKey).toEqual(DATA); expect(resets).toBe(1);
});
it("a retired Native UI attempt cannot start recovery", async () => {
  await expect(recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => false })).rejects.toMatchObject({ code: "stale_operation" }); expect(resets).toBe(0); expect(await api.isLoggedIn()).toBe(false);
});
it("a retired UI rejects promptly while the next Native recovery provider is unavailable", async () => {
  const held = gate(), fetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => { await held.run(); return fetch(...args); });
  let result: unknown;
  const observed = recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => false }).catch(error => { result = error; });
  try { await vi.waitFor(() => expect(result).toMatchObject({ code: "stale_operation" }), { timeout: 1000 }); }
  finally { held.release(); await observed; }
});
it("a malformed copied kit fails before any recovery session can be installed", async () => {
  await expect(recoverAccountWithKey("alice", "not a Native recovery kit", PASSWORD, "v2")).rejects.toThrow("recovery key must be 32 bytes"); expect(await api.isLoggedIn()).toBe(false);
});
it.each(["salt", "envelope"] as const)("an acknowledged Native reset with failed %s caching preserves committed success and removes both stale caches", async phase => {
  const write = storage.setItem.bind(storage);
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { if (key.startsWith(phase === "salt" ? "@mindpattern/salt_" : "@mindpattern/keyenvelope_")) throw new Error("Native cache write unavailable"); await write(key, value); });
  const result = await recoverAccountWithKey("alice", kit(), PASSWORD, "v2"); expect(result.dataKey).toEqual(DATA); expect(result.localCacheReady).toBe(false); expect(resets).toBe(1);
  expect(await api.isLoggedIn()).toBe(true); expect(await api.getCachedSalt("alice")).toBeNull(); expect(await api.getCachedKeyEnvelope("alice")).toBeNull();
});
it("a retired failed Native cache write cannot clear a newer foreground cache", async () => {
  let active = true, first = true;
  const held = gate(), write = storage.setItem.bind(storage);
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (first && key.startsWith("@mindpattern/salt_")) { first = false; await held.run(); throw new Error("Native salt-cache write failed"); }
    await write(key, value);
  });
  const observed = recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => active }).catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  // The next foreground attempt queues usable current credentials behind
  // the failing native write without changing the authenticated account.
  const nextSalt = api.cacheSalt("alice", cachedBody!.new_salt as string);
  const nextEnvelope = api.cacheKeyEnvelope("alice", { scheme: "v2", saltB64: cachedBody!.new_salt as string, wrappedB64: cachedBody!.wrapped_data_key as string, kdfParams: cachedBody!.new_kdf_params as KdfParams });
  active = false; held.release(); await Promise.all([nextSalt, nextEnvelope]);
  expect(await observed).toMatchObject({ code: "stale_operation" });
  expect(await api.getCachedSalt("alice")).toBe(cachedBody!.new_salt);
  expect(await api.getCachedKeyEnvelope("alice")).toMatchObject({ scheme: "v2", wrappedB64: cachedBody!.wrapped_data_key });
});
it("retirement during Native cache cleanup cannot publish a recovered key", async () => {
  let active = true, first = true;
  const held = gate(), remove = storage.removeItem.bind(storage), write = storage.setItem.bind(storage), open = recoveryCrypto.unsealDataKeyWithRecoveryScheme, owned: Buffer[] = [];
  vi.spyOn(recoveryCrypto, "unsealDataKeyWithRecoveryScheme").mockImplementation((...args) => { const key = open(...args); if (key) owned.push(key); return key; });
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { if (key.startsWith("@mindpattern/salt_")) throw new Error("Native cache unavailable"); await write(key, value); });
  vi.spyOn(storage, "removeItem").mockImplementation(async key => { await remove(key); if (first && key.startsWith("@mindpattern/salt_")) { first = false; await held.run(); } });
  const observed = recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => active }).catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); active = false; held.release();
  expect(await observed).toMatchObject({ code: "stale_operation" }); expect(owned).toHaveLength(1); expect(owned[0]).toEqual(Buffer.alloc(32));
});
it.each(["recovery", "processing", "reset"] as const)("a held Native %s answer cannot publish into a newer account", async phase => {
  const held = gate(); boundary = async path => { if (path.endsWith(phase === "recovery" ? "/auth/recover" : phase === "processing" ? "/processing/sessions" : "/account/recovery/password")) await held.run(); };
  const recovery = recoverAccountWithKey("alice", kit(), PASSWORD, "v2"); const observed = recovery.catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); await api.setSession("newer bearer", OTHER, "bob"); held.release();
  expect(await observed).toBeInstanceOf(Error); expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBe("bob"); expect(await api.isLoggedIn()).toBe(true);
});
it.each(Array.from({ length: 16 }, (_, index) => index + 1))("Native login completion with replacement delivery phase %i cannot replace the newer account", async turns => {
  let replacement: Promise<void> | undefined;
  nativeCompletion = path => { if (path.endsWith("/auth/recover")) deliverNativeEvent(turns, () => { replacement = api.setSession("newer Native bearer", OTHER, "bob"); }); };
  const error = await recoverAccountWithKey("alice", kit(), PASSWORD, "v2").catch(error => error);
  await vi.waitFor(() => expect(replacement).toBeDefined()); await replacement;
  expect(error).toMatchObject({ code: "stale_operation" }); expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBe("bob"); expect(await api.isLoggedIn()).toBe(true);
});
// These provider-event orders all retire the attempt before its public
// completion. Later deliveries happen after a valid outcome has returned.
it.each(Array.from({ length: 7 }, (_, index) => index + 1))("Native envelope caching with retirement delivery phase %i cannot return a retired secret", async turns => {
  let active = true;
  const write = storage.setItem.bind(storage), open = recoveryCrypto.unsealDataKeyWithRecoveryScheme, owned: Buffer[] = [];
  vi.spyOn(recoveryCrypto, "unsealDataKeyWithRecoveryScheme").mockImplementation((...args) => { const key = open(...args); if (key) owned.push(key); return key; });
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { await write(key, value); if (key.startsWith("@mindpattern/keyenvelope_")) deliverNativeEvent(turns, () => { active = false; }); });
  const error = await recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => active }).catch(error => error);
  expect(error).toMatchObject({ code: "stale_operation" }); expect(owned).toHaveLength(1); expect(owned[0]).toEqual(Buffer.alloc(32));
});
it.each(["recovery", "processing", "reset"] as const)("a retired UI cannot use a held Native %s answer to publish recovery", async phase => {
  let active = true;
  const held = gate(), open = recoveryCrypto.unsealDataKeyWithRecoveryScheme, owned: Buffer[] = [];
  vi.spyOn(recoveryCrypto, "unsealDataKeyWithRecoveryScheme").mockImplementation((...args) => { const key = open(...args); if (key) owned.push(key); return key; });
  boundary = async path => { if (path.endsWith(phase === "recovery" ? "/auth/recover" : phase === "processing" ? "/processing/sessions" : "/account/recovery/password")) await held.run(); };
  const observed = recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => active }).catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); active = false; held.release();
  expect(await observed).toMatchObject({ code: "stale_operation" }); expect(resets).toBe(phase === "reset" ? 1 : 0);
  for (const key of owned) expect(key).toEqual(Buffer.alloc(32));
});
it("a retired Native recovery response preserves retirement when the crypto provider becomes unavailable", async () => {
  let active = true;
  const held = gate(), decipher = engine.createDecipheriv.bind(engine);
  boundary = async path => { if (path.endsWith("/auth/recover")) await held.run(); };
  vi.spyOn(engine, "createDecipheriv").mockImplementation((...args) => { if (!active && !inNativeServer) throw new Error("Native cryptography unavailable"); return decipher(...args); });
  const observed = recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => active }).catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); active = false; held.release();
  expect(await observed).toMatchObject({ code: "stale_operation" }); expect(resets).toBe(0);
});
it("a retired Native PBKDF completion reports retirement before a newly unavailable HKDF job", async () => {
  let active = true;
  const held = gate(), derive = engine.pbkdf2.bind(engine), hkdf = engine.hkdfSync.bind(engine);
  vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => { derive(password, salt, iterations, length, digest, (error, output) => { void held.run().then(() => callback(error, output)); }); });
  vi.spyOn(engine, "hkdfSync").mockImplementation((...args) => { if (!active && !inNativeServer) throw new Error("Native HKDF provider unavailable"); return hkdf(...args); });
  const observed = recoverAccountWithKey("alice", kit(), PASSWORD, "v2", { stillCurrent: () => active }).catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); active = false; held.release();
  expect(await observed).toMatchObject({ code: "stale_operation" }); expect(resets).toBe(0);
});
it("a retired Native PBKDF completion erases its owned master instead of resetting", async () => {
  const held = gate(), derive = engine.pbkdf2.bind(engine), owned: Buffer[] = [], master = kdf.deriveMasterKeyAsync;
  vi.spyOn(kdf, "deriveMasterKeyAsync").mockImplementation(async (...args) => { const result = await master(...args); owned.push(result); return result; });
  vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => { derive(password, salt, iterations, length, digest, (error, output) => { void held.run().then(() => callback(error, output)); }); });
  const pending = recoverAccountWithKey("alice", kit(), PASSWORD, "v2"), observed = pending.catch(error => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); await api.setSession("replacement bearer", OTHER, "bob"); held.release();
  expect(await observed).toMatchObject({ code: "stale_operation" }); expect(owned).toHaveLength(1); expect(owned[0]).toEqual(Buffer.alloc(32)); expect(await api.getUserId()).toBe(OTHER); expect(resets).toBe(0);
});
it.each(["envelope-kdf", "envelope-wrap", "reset"] as const)("a Native %s failure erases the newly derived authentication allocation", async phase => {
  const auth = kdf.deriveAuthKey, owned: Buffer[] = [];
  vi.spyOn(kdf, "deriveAuthKey").mockImplementation(master => { const result = auth(master); owned.push(result); return result; });
  if (phase === "envelope-kdf") { const hkdf = engine.hkdfSync.bind(engine); vi.spyOn(engine, "hkdfSync").mockImplementation((digest, input, salt, info, size) => { if (info.toString() === "mindpattern/envelope/v2") throw new Error("Native HKDF provider unavailable"); return hkdf(digest, input, salt, info, size); }); }
  else if (phase === "envelope-wrap") {
    const cipher = engine.createCipheriv.bind(engine);
    vi.spyOn(engine, "createCipheriv").mockImplementation((...args) => {
      // Credential storage also uses native AES before this allocation.
      // The fault belongs to the account-envelope wrapping job only.
      if (owned.length) throw new Error("Native wrapping provider unavailable");
      return cipher(...args);
    });
  }
  else resetStatus = 500;
  await expect(recoverAccountWithKey("alice", kit(), PASSWORD, "v2")).rejects.toBeInstanceOf(Error);
  expect(owned).toHaveLength(1); expect(owned[0]).toEqual(Buffer.alloc(32)); expect(await api.isLoggedIn()).toBe(false); expect(resets).toBe(0);
});
it.each(["committed", "refused"] as const)("a %s Native recovery erases every owned secret except the returned data key", async outcome => {
  resetStatus = outcome === "committed" ? 200 : 500;
  const derive = kdf.deriveMasterKeyAsync, masters: Buffer[] = [], inputs: Buffer[] = [], outputs: ArrayBuffer[] = [], wrappingKeys: Buffer[] = [], dataKeys: Buffer[] = [];
  vi.spyOn(kdf, "deriveMasterKeyAsync").mockImplementation(async (...args) => { const master = await derive(...args); masters.push(master); return master; });
  const hkdf = engine.hkdfSync.bind(engine);
  vi.spyOn(engine, "hkdfSync").mockImplementation((digest, input, salt, info, size) => {
    const output = hkdf(digest, input, salt, info, size);
    if (!inNativeServer) { inputs.push(input, salt); outputs.push(output as ArrayBuffer); }
    return output;
  });
  const cipher = engine.createCipheriv.bind(engine);
  vi.spyOn(engine, "createCipheriv").mockImplementation((...args) => {
    const created = cipher(...args), update = created.update.bind(created);
    created.update = ((...values: Parameters<typeof created.update>) => {
      const value = values[0];
      if (Buffer.isBuffer(value) && value.length === 32 && value.equals(DATA)) { wrappingKeys.push(args[1] as Buffer); dataKeys.push(value); }
      return update(...values);
    }) as typeof created.update;
    return created;
  });
  const pending = recoverAccountWithKey("alice", kit(), PASSWORD, "v2");
  if (outcome === "refused") await expect(pending).rejects.toMatchObject({ status: 500 }); else expect((await pending).dataKey).toEqual(DATA);
  expect(masters).toHaveLength(1); expect(wrappingKeys).toHaveLength(1); expect(dataKeys).toHaveLength(1);
  for (const allocation of [...masters, ...inputs, ...wrappingKeys]) expect(allocation.every(byte => byte === 0)).toBe(true);
  for (const allocation of outputs) expect(new Uint8Array(allocation).every(byte => byte === 0)).toBe(true);
  expect(dataKeys[0]).toEqual(outcome === "committed" ? DATA : Buffer.alloc(32));
});
