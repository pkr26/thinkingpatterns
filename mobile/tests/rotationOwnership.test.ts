import { runTestControl } from "./helpers/testControl";
/** Shipping helpers/crypto, controlled transport/native waits. These cases
 * prove ownership retirement, not physical-device scheduling or provider I/O. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, getBaseUrl, setBaseUrl } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import { vault } from "../src/vault";
import { localWriteScopeEpoch, __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import * as localRekey from "../src/localRekey";
import * as reauth from "../src/reauth";
import * as crypto from "../src/crypto/journalCrypto";
import { rotatePassword } from "../src/rotation";
import { deriveMasterKey } from "../src/crypto/kdf";
import { envelopeKek, wrapDataKey, defaultKdfParams } from "../src/crypto/keyEnvelope";
const USER = "11111111111111111111111111111111", OTHER = "22222222222222222222222222222222";
const PASSWORD = "owned original password", SALT = Buffer.alloc(16, 3), NEW_PASSWORD = "a replacement passphrase 42!";
const input = { username: "original", userId: USER, oldPassword: PASSWORD, newPassword: NEW_PASSWORD };
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { resolve, promise }; }
function unlock(userId: string, biometric = false) {
  const keys = crypto.deriveKeys(PASSWORD, SALT);
  if (biometric) keys.authKey.fill(0);
  vault.unlock(keys, userId, { authKeyKnown: !biometric }); return vault.get();
}
async function replace(user = OTHER) { await api.setSession("replacement-token", user, "replacement"); return unlock(user); }
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  await api.setSession("original-token", USER, "original"); unlock(USER);
  vi.spyOn(api, "getCachedSalt").mockResolvedValue(SALT.toString("base64"));
});
afterEach(() => { vi.restoreAllMocks(); vault.lock(); });

describe("fresh proof ownership", () => {
  it("rejects a username lookup that spans a same-owner vault replacement", async () => {
    const held = deferred<string | null>(), started = deferred<void>();
    vi.spyOn(api, "getUsername").mockImplementation(async () => { started.resolve(); return held.promise; });
    const proof = reauth.verifyPasswordForVault(PASSWORD); await started.promise;
    const replacement = await replace(USER); held.resolve("original");
    expect(await proof).toEqual({ ok: false, reason: "locked" });
    expect(vault.get().authKey).toBe(replacement.authKey);
  });
  it("does not adopt a late biometric password proof into the new account", async () => {
    unlock(USER, true); const held = deferred<{ token: string; user_id: string }>(), started = deferred<void>();
    vi.spyOn(api, "login").mockImplementation(async () => { started.resolve(); return held.promise; });
    const proof = reauth.verifyPasswordForVault(PASSWORD); await started.promise;
    await api.setSession("new-token", OTHER, "replacement"); const replacement = unlock(OTHER, true);
    held.resolve({ token: "old-result", user_id: USER });
    expect(await proof).toEqual({ ok: false, reason: "locked" });
    expect(vault.get().authKey).toBe(replacement.authKey); expect(vault.get().authKeyKnown).toBe(false);
    expect(vault.get().authKey.equals(Buffer.alloc(32))).toBe(true);
  });
});

describe("password rotation ownership", () => {
  function stubRouting() {
    vi.spyOn(reauth, "verifyPasswordForVault").mockResolvedValue({ ok: true, verifierB64: "original-proof" });
    vi.spyOn(api, "keyEnvelope").mockResolvedValue({ key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null });
    vi.spyOn(api, "listConsents").mockResolvedValue([]);
  }
  it("retires a rotation whose first checkpoint read spans account replacement", async () => {
    const held = deferred<string | null>(), started = deferred<void>();
    vi.spyOn(localRekey, "pendingLocalRekeyOldSalt").mockImplementation(async () => { started.resolve(); return held.promise; });
    const server = vi.spyOn(api, "rekeyStoredData"), proof = vi.spyOn(reauth, "verifyPasswordForVault");
    const pending = rotatePassword(input); await started.promise; const replacement = await replace(); held.resolve(null);
    expect(await pending).toMatchObject({ ok: false, reason: "server", detail: undefined });
    expect(proof).not.toHaveBeenCalled(); expect(server).not.toHaveBeenCalled();
    expect(vault.get().dataKey).toBe(replacement.dataKey); expect(vault.ownerUserId()).toBe(OTHER);
  });
  it("wipes its delayed derivation without locking the replacement vault", async () => {
    stubRouting(); const held = deferred<ReturnType<typeof crypto.deriveKeys>>(), started = deferred<void>();
    const owned = crypto.deriveKeys(PASSWORD, SALT);
    vi.spyOn(crypto, "deriveKeysAsync").mockImplementationOnce(async () => { started.resolve(); return held.promise; });
    const server = vi.spyOn(api, "rekeyStoredData"), pending = rotatePassword(input);
    await started.promise; const replacement = await replace(); held.resolve(owned);
    expect(await pending).toMatchObject({ ok: false, reason: "server" }); expect(server).not.toHaveBeenCalled();
    expect(owned.masterKey.equals(Buffer.alloc(32))).toBe(true); expect(owned.authKey.equals(Buffer.alloc(32))).toBe(true);
    expect(owned.dataKey.equals(Buffer.alloc(32))).toBe(true); expect(vault.get().dataKey).toBe(replacement.dataKey);
  });
  it("keeps a prepared journal and stops a late processing-session result before corpus dispatch", async () => {
    stubRouting(); const held = deferred<{ session_token: string }>(), started = deferred<void>();
    vi.spyOn(api, "openProcessingSession").mockImplementation(async () => { started.resolve(); return held.promise; });
    const server = vi.spyOn(api, "rekeyStoredData"), pending = rotatePassword(input);
    await started.promise; const replacement = await replace(); held.resolve({ session_token: "retired-token" });
    expect(await pending).toMatchObject({ ok: false, reason: "server" }); expect(server).not.toHaveBeenCalled();
    expect(await localRekey.pendingLocalRekey(USER)).toBe(true); expect(vault.get().dataKey).toBe(replacement.dataKey);
  });
  function v2() {
    stubRouting(); const params = defaultKdfParams(), key = Buffer.from(vault.get().dataKey);
    const master = deriveMasterKey(PASSWORD, SALT, params.iterations), kek = envelopeKek(master, SALT);
    const wrapped = wrapDataKey(key, kek, input.username, params).toString("base64"); master.fill(0); kek.fill(0); key.fill(0);
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: { ...params }, wrapped_data_key: wrapped });
    vi.spyOn(api, "openProcessingSession").mockResolvedValue({ session_token: "current-key-probe", expires_in_seconds: 30 });
  }
  it("does not cache, re-login or lock a replacement after an uncertain old credential transaction", async () => {
    v2(); const held = deferred<Record<string, unknown>>(), started = deferred<void>();
    vi.spyOn(api, "changePassword").mockImplementation(async () => { started.resolve(); return held.promise; });
    const cache = vi.spyOn(api, "cacheSalt"), login = vi.spyOn(api, "login"); const pending = rotatePassword(input);
    await started.promise; const replacement = await replace(); held.resolve({ ok: true });
    expect(await pending).toMatchObject({ ok: false, reason: "server" }); expect(cache).not.toHaveBeenCalled(); expect(login).not.toHaveBeenCalled();
    expect(vault.get().dataKey).toBe(replacement.dataKey); expect(vault.ownerUserId()).toBe(OTHER);

    // Exercise the public cache reader after a separate, successfully
    // acknowledged rotation login is retired at its caller continuation.
    // A same-origin path change has one admission epoch; a cross-origin
    // change has a second epoch and is deliberately not this producer.
    cache.mockRestore(); login.mockRestore(); vi.mocked(api.getCachedSalt).mockRestore();
    const previousUrl = await getBaseUrl();
    const sourceUrl = "https://rotation-owner.example.test/first";
    const replacementUrl = "https://rotation-owner.example.test/second";
    const write = storage.setItem.bind(storage);
    let acknowledgementClaimed = false;
    let originChange: ReturnType<typeof setBaseUrl> | undefined;
    let attempt: ReturnType<typeof rotatePassword> | undefined;
    let writeObserver: { mockRestore(): void } | undefined;
    try {
      expect(await setBaseUrl(sourceUrl)).toBeNull();
      await api.setSession("original retry bearer", USER, "original"); unlock(USER); v2();
      vi.mocked(api.changePassword).mockResolvedValue({ ok: true });
      vi.spyOn(api, "login").mockResolvedValue({ token: "acknowledged rotated bearer", user_id: USER });
      await api.cacheSalt(input.username, SALT.toString("base64"));
      expect(await api.getCachedSalt(input.username)).toBe(SALT.toString("base64"));
      writeObserver = vi.spyOn(storage, "setItem").mockImplementation((slot, value) => {
        const actualWrite = write(slot, value);
        if (slot !== "@mindpattern/token" || acknowledgementClaimed) return actualWrite;
        acknowledgementClaimed = true;
        // Delegate the exact encrypted bytes before delivering the ordinary
        // AsyncStorage Promise receipt. Six explicit deliveries correspond
        // to the installed secureStore/credential/adoptSession wrapper path;
        // they are a finite producer premise, not a turn-budget oracle.
        return new Promise<void>((resolve, reject) => {
          void actualWrite.then(() => setImmediate(() => {
            resolve();
            queueMicrotask(() => queueMicrotask(() => queueMicrotask(() =>
              queueMicrotask(() => queueMicrotask(() => queueMicrotask(() => {
                originChange = setBaseUrl(replacementUrl);
                void originChange.catch(() => {});
              }))))));
          }), reject);
        });
      });
      attempt = rotatePassword(input);
      expect(await attempt).toMatchObject({ ok: false, reason: "server" });
      expect(originChange).toBeDefined();
      expect(await originChange).toBeNull();
      expect(await getBaseUrl()).toBe(replacementUrl);
      expect(await api.getUserId()).toBe(USER);
      // The replacement endpoint has not supplied this username's salt.
      expect(await api.getCachedSalt(input.username)).toBeNull();
    } finally {
      try { if (attempt) await attempt.catch(() => {}); }
      finally {
        try { if (originChange) await originChange.catch(() => {}); }
        finally { writeObserver?.mockRestore(); await setBaseUrl(previousUrl); }
      }
    }
  });
  it("allows its own fresh biometric proof to replace only its placeholder auth key", async () => {
    unlock(USER, true); v2(); vi.mocked(reauth.verifyPasswordForVault).mockRestore();
    vi.spyOn(api, "changePassword").mockResolvedValue({ ok: true });
    const login = vi.spyOn(api, "login").mockResolvedValue({ token: "new-password-token", user_id: USER });
    const outcome = await rotatePassword(input);
    expect(outcome).toMatchObject({ ok: true, scheme: "v2", sessionScope: localWriteScopeEpoch() });
    expect(login).toHaveBeenCalledTimes(2); expect(vault.ownerUserId()).toBe(USER); expect(vault.get().authKeyKnown).toBe(true);
  });
  it("allows its own session transition and returns the exact completion scope", async () => {
    v2(); vi.spyOn(api, "changePassword").mockResolvedValue({ ok: true });
    vi.spyOn(api, "login").mockResolvedValue({ token: "new-password-token", user_id: USER });
    const previous = localWriteScopeEpoch(), outcome = await rotatePassword(input);
    expect(outcome).toMatchObject({ ok: true, scheme: "v2", sessionScope: localWriteScopeEpoch() });
    expect(localWriteScopeEpoch()).toBeGreaterThan(previous); expect(await api.getUserId()).toBe(USER);
    expect(vault.ownerUserId()).toBe(USER); expect(vault.get().authKeyKnown).toBe(true);
  });
});
