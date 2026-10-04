/**
 * rotatePassword's v2 branch (2026-09-26 crypto wave): the O(1) password
 * change — local unwrap with the old password, re-wrap of the SAME random
 * data key under a fresh salt, one PUT /account/password transaction, then
 * re-login. The corpus is NOT rekeyed, grants are NOT re-wrapped, the vault
 * STAYS unlocked on the unchanged data key, and the biometric wrap and
 * unlock proof survive.
 *
 * Idiom: tests/securityPins.test.ts (mocked transport, REAL crypto — the
 * node engine behind the same seam). The v1 ladder keeps its pins there;
 * this file pins the v2 route plus the 409 key_scheme_conflict bridge.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const store = new Map<string, string>();

vi.mock("@react-native-async-storage/async-storage", () => ({
  default: {
    getItem: async (k: string) => store.get(k) ?? null,
    setItem: async (k: string, v: string) => void store.set(k, v),
    removeItem: async (k: string) => store.delete(k),
    multiRemove: async (keys: readonly string[]) => {
      for (const k of keys) store.delete(k);
    },
    getAllKeys: async () => Array.from(store.keys()),
  },
}));

const USER = "abababababababababababababababab";
const OLD_PASSWORD = "correct old password";
const NEW_PASSWORD = "a strong new passphrase 42!";
const OLD_VERIFIER_B64 = "b2xkLXZlcmlmaWVy";

const apiState = {
  scheme: "v2" as "v1" | "v2",
  /** The v2 envelope the server hands out (built from real crypto below). */
  keyEnvelope: null as null | Record<string, unknown>,
  failChangePassword: null as null | { status: number; code?: string; message: string },
  failRelogin: null as null | Error,
};

vi.mock("../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api/client")>();
  class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
      public code?: string,
      public retryAfterMs?: number,
    ) {
      super(message);
    }
  }
  return {
    ...actual,
    ApiError,
    canonicalOrigin: actual.canonicalOrigin,
    api: {
      getCachedSalt: async () => "c2FsdHNhbHRzYWx0c2FsdA==",
      saltFor: async () => ({ salt: "c2FsdHNhbHRzYWx0c2FsdA==" }),
      cacheSalt: vi.fn(async () => {}),
      keyEnvelope: vi.fn(async () => apiState.keyEnvelope),
      cacheKeyEnvelope: vi.fn(async () => {}),
      getCachedKeyEnvelope: vi.fn(async () => null),
      clearCachedKeyEnvelope: vi.fn(async () => {}),
      changePassword: vi.fn(async () => {
        if (apiState.failChangePassword) {
          const f = apiState.failChangePassword;
          throw new ApiError(f.status, f.message, f.code);
        }
        return {};
      }),
      // The v1 ladder's endpoints: present as SPIES so the v2 route can be
      // pinned to never touch them.
      openProcessingSession: vi.fn(async (key: string) => ({ session_token: `tok-${key.slice(0, 6)}` })),
      rekeyStoredData: vi.fn(async () => ({ entries: 0, insights: 0, measures: 0 })),
      listConsents: vi.fn(async () => []),
      rewrapConsent: vi.fn(async () => ({})),
      rotateCredential: vi.fn(async () => {
        throw new ApiError(409, "this account uses the v2 key envelope", "key_scheme_conflict");
      }),
      login: vi.fn(async () => {
        if (apiState.failRelogin) throw apiState.failRelogin;
        return { token: "fresh", user_id: USER };
      }),
      setSession: vi.fn(async () => {}),
      listEntriesPage: vi.fn(async () => ({ entries: [], nextOffset: null, revision: null })),
      listMeasuresPage: vi.fn(async () => []),
    },
  };
});

vi.mock("../src/reauth", () => ({
  verifyPasswordForVault: async (password: string) =>
    password === OLD_PASSWORD
      ? { ok: true as const, verifierB64: OLD_VERIFIER_B64 }
      : { ok: false as const, reason: "wrong-password" as const },
}));

import { api, ApiError } from "../src/api/client";
import { rotatePassword } from "../src/rotation";
import { vault } from "../src/vault";
import { deriveKeys, deriveKeysAsync } from "../src/crypto/MindPatternCrypto";
import { deriveMasterKey } from "../src/crypto/kdf";
import { envelopeKek, unwrapDataKey, wrapDataKey, defaultKdfParams } from "../src/crypto/keyEnvelope";
import { enableBiometricUnlock, hasBiometricUnlock } from "../src/biometricUnlock";
import * as Keychain from "react-native-keychain";

const keychainMock = Keychain as unknown as { __reset: () => void };

/** The account's random data key — the one thing that must NEVER change. */
const DATA_KEY = Buffer.alloc(32, 9);
const SALT = Buffer.alloc(16, 3);
const PARAMS = defaultKdfParams();

/** The v2 envelope as the server would store/serve it: the random data key
 *  wrapped under the OLD password's KEK. Real crypto, fixed inputs. */
function buildEnvelope(password: string): { wrappedB64: string } {
  const master = deriveMasterKey(password, SALT, PARAMS.iterations);
  const kek = envelopeKek(master, SALT);
  return { wrappedB64: wrapDataKey(DATA_KEY, kek, "alice", PARAMS).toString("base64") };
}

/** Unwrap a wrapped blob the flow produced, under the keys the flow claims. */
function unwrapUnder(wrappedB64: string, password: string, saltB64: string): Buffer {
  const keys = deriveKeys(password, Buffer.from(saltB64, "base64"));
  return unwrapDataKey(Buffer.from(wrappedB64, "base64"), envelopeKek(keys.masterKey, Buffer.from(saltB64, "base64")), "alice", PARAMS);
}

beforeEach(() => {
  store.clear();
  apiState.scheme = "v2";
  apiState.keyEnvelope = {
    key_scheme: "v2",
    salt: SALT.toString("base64"),
    kdf_params: PARAMS,
    wrapped_data_key: buildEnvelope(OLD_PASSWORD).wrappedB64,
  };
  apiState.failChangePassword = null;
  apiState.failRelogin = null;
  keychainMock.__reset();
  vi.mocked(api.changePassword).mockClear();
  vi.mocked(api.openProcessingSession).mockClear();
  vi.mocked(api.cacheKeyEnvelope).mockClear();
  vi.mocked(api.login).mockClear();
  vi.mocked(api.rekeyStoredData).mockClear();
  vi.mocked(api.rewrapConsent).mockClear();
  vi.mocked(api.rotateCredential).mockClear();
  // The session is unlocked on the account's random data key (the state a
  // v2 unlock leaves behind).
  vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(DATA_KEY) }, USER);
});

describe("rotatePassword v2 branch (O(1) rewrap)", () => {
  it("rewraps the SAME data key under a fresh salt and never touches the corpus", async () => {
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toEqual({
      ok: true,
      scheme: "v2",
      sessionScope: expect.any(Number),
      counts: { entries: 0, insights: 0, measures: 0 },
      rewrapped: 0,
      rewrapFailures: [],
    });
    // M-1 (2026-09-28 wire change): the possession probe ships on every PUT —
    // a processing session opened with the CURRENT (unwrapped) data key
    // FIRST, its token riding the password change as X-Processing-Token
    // (the client-side arg here), exactly the proof the v1→v2 migration
    // path sends on /account/key-envelope/upgrade.
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);
    expect(api.openProcessingSession).toHaveBeenCalledWith(DATA_KEY.toString("base64"));
    expect(api.openProcessingSession.mock.invocationCallOrder[0]).toBeLessThan(
      api.changePassword.mock.invocationCallOrder[0]!,
    );
    // One transaction, exactly the contract's payload shape.
    expect(api.changePassword).toHaveBeenCalledTimes(1);
    const [verifier, newSaltB64, newVerifierB64, wrappedB64, processingToken, newParams] = vi.mocked(
      api.changePassword,
    ).mock.calls[0] as [string, string, string, string, string, unknown];
    expect(verifier).toBe(OLD_VERIFIER_B64);
    // The token on the PUT is the one the CURRENT data key's session minted.
    expect(processingToken).toBe(`tok-${DATA_KEY.toString("base64").slice(0, 6)}`);
    expect(Buffer.from(newSaltB64, "base64")).toHaveLength(16);
    expect(newParams).toBeUndefined(); // keeps the account's current params
    // The new verifier is the NEW password's derivation under the NEW salt.
    const expectedKeys = await deriveKeysAsync(NEW_PASSWORD, Buffer.from(newSaltB64, "base64"));
    expect(newVerifierB64).toBe(expectedKeys.authKey.toString("base64"));
    // The wrapped blob is 60 bytes and opens under the NEW password to the
    // SAME random data key — the whole point of v2.
    expect(Buffer.from(wrappedB64, "base64")).toHaveLength(60);
    expect(unwrapUnder(wrappedB64, NEW_PASSWORD, newSaltB64)).toEqual(DATA_KEY);

    // The v1 ladder is untouched: no rekey, no consent rewrap, no old PUT.
    expect(api.rekeyStoredData).not.toHaveBeenCalled();
    expect(api.rewrapConsent).not.toHaveBeenCalled();
    expect(api.rotateCredential).not.toHaveBeenCalled();

    // Re-login under the new credential; the vault STAYS unlocked on the
    // unchanged data key with the new auth key adopted.
    expect(api.login).toHaveBeenCalledWith("alice", newVerifierB64);
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.get().dataKey).toEqual(DATA_KEY);
    // The next unlock is offline-capable: the new envelope is cached.
    expect(api.cacheKeyEnvelope).toHaveBeenCalledWith(
      "alice",
      expect.objectContaining({ scheme: "v2", saltB64: newSaltB64, wrappedB64 }),
    );
  });

  it("re-audit 2026-09-27: a NON-default-params envelope (800k) rewraps at the account's OWN count — the next unlock succeeds", async () => {
    // The account's envelope carries 800k iterations (a server-tuned
    // profile). The AAD of the re-wrap declares those SAME params (the
    // server retains them when new_kdf_params is absent), so the KEK must
    // be derived at 800k too — the old code derived at the 600k default and
    // the next unlock (which derives at the envelope's own count) failed
    // authentication: the password change bricked the account.
    const heavy = { ...PARAMS, iterations: 800_000 };
    const oldMaster = deriveMasterKey(OLD_PASSWORD, SALT, heavy.iterations);
    apiState.keyEnvelope = {
      key_scheme: "v2",
      salt: SALT.toString("base64"),
      kdf_params: heavy,
      wrapped_data_key: wrapDataKey(DATA_KEY, envelopeKek(oldMaster, SALT), "alice", heavy).toString("base64"),
    };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome.ok).toBe(true);
    const [, newSaltB64, , wrappedB64] = vi.mocked(api.changePassword).mock.calls[0] as [string, string, string, string, unknown];
    // The cached envelope keeps the account's params...
    const record = vi.mocked(api.cacheKeyEnvelope).mock.calls[0]![1] as { kdfParams: { iterations: number } };
    expect(record.kdfParams.iterations).toBe(800_000);
    // ...and the NEXT unlock — deriving at the envelope's own count — opens
    // the re-wrapped envelope to the SAME random data key.
    const nextMaster = deriveMasterKey(NEW_PASSWORD, Buffer.from(newSaltB64, "base64"), heavy.iterations);
    const nextKey = unwrapDataKey(
      Buffer.from(wrappedB64, "base64"),
      envelopeKek(nextMaster, Buffer.from(newSaltB64, "base64")),
      "alice",
      heavy,
    );
    expect(nextKey).toEqual(DATA_KEY);
  });

  it("keeps the biometric wrap and the unlock proof (the data key never changed)", async () => {
    await enableBiometricUnlock(USER, Buffer.from(DATA_KEY));
    store.set(`@mindpattern/unlockproof_${USER}`, "sealed-proof");
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome.ok).toBe(true);
    expect(await hasBiometricUnlock(USER)).toBe(true);
    expect(store.get(`@mindpattern/unlockproof_${USER}`)).toBe("sealed-proof");
  });

  it("a wrong OLD password fails at verify (the reauth oracle)", async () => {
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "wrong password",
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toEqual({ ok: false, stage: "verify", reason: "wrong-password" });
    expect(api.changePassword).not.toHaveBeenCalled();
  });

  it("an envelope that does not open under the old password is wrong-password, not a server error", async () => {
    // The server hands an envelope wrapped under a DIFFERENT password (the
    // password changed elsewhere): GCM authentication is the oracle.
    apiState.keyEnvelope = {
      key_scheme: "v2",
      salt: SALT.toString("base64"),
      kdf_params: PARAMS,
      wrapped_data_key: buildEnvelope("a different password entirely").wrappedB64,
    };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toEqual({ ok: false, stage: "verify", reason: "wrong-password" });
    expect(api.changePassword).not.toHaveBeenCalled();
    // Nothing moved: the vault still holds the (now server-side-stale) key,
    // but no relogin was attempted with a dead credential.
    expect(api.login).not.toHaveBeenCalled();
  });

  it("a 403 on the PUT maps to wrong-password with nothing changed", async () => {
    apiState.failChangePassword = { status: 403, code: "verification_failed", message: "verifier rejected" };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("credential");
      expect(outcome.reason).toBe("wrong-password");
    }
    expect(api.login).not.toHaveBeenCalled();
  });

  // --- M-1 client side (2026-09-28 wire change) --------------------------------
  // The PUT demands the possession probe on every call; a refused probe is
  // an honest typed failure and the flow NEVER falls back to a tokenless
  // PUT (that would smuggle the new envelope past the probe).
  it("a 403 processing_session_invalid on the PUT fails honestly — NO tokenless retry", async () => {
    apiState.failChangePassword = {
      status: 403,
      code: "processing_session_invalid",
      message: "processing session missing or expired",
    };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    // The password was RIGHT (the verifier passed the mock's gate) — the
    // session was not. Never classified as wrong-password.
    expect(outcome).toMatchObject({ ok: false, stage: "credential", reason: "server" });
    if (!outcome.ok) expect(outcome.detail).toMatch(/encryption key session/i);
    // Exactly ONE PUT, carrying the token — no second, tokenless attempt.
    expect(api.changePassword).toHaveBeenCalledTimes(1);
    const [, , , , processingToken] = vi.mocked(api.changePassword).mock.calls[0] as [
      string,
      string,
      string,
      string,
      string,
    ];
    expect(processingToken).toBe(`tok-${DATA_KEY.toString("base64").slice(0, 6)}`);
    // Nothing moved: no re-login with a credential the server never adopted.
    expect(api.login).not.toHaveBeenCalled();
    expect(vault.isUnlocked()).toBe(true);
  });

  it("a 422 processing_session_required on the PUT fails honestly — NO tokenless retry", async () => {
    apiState.failChangePassword = {
      status: 422,
      code: "processing_session_required",
      message: "processing session token required (X-Processing-Token)",
    };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toMatchObject({ ok: false, stage: "credential", reason: "server" });
    expect(api.changePassword).toHaveBeenCalledTimes(1);
    expect(api.login).not.toHaveBeenCalled();
  });

  it("a processing session that cannot OPEN aborts before the PUT (typed, not thrown)", async () => {
    vi.mocked(api.openProcessingSession).mockRejectedValueOnce(new Error("network unreachable"));
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toEqual({ ok: false, stage: "credential", reason: "offline", detail: "network unreachable" });
    expect(api.changePassword).not.toHaveBeenCalled();
    expect(api.login).not.toHaveBeenCalled();
  });

  it("an unauthenticated session key (open → 403 processing_session_invalid) surfaces the honest-retry copy", async () => {
    vi.mocked(api.openProcessingSession).mockRejectedValueOnce(
      new ApiError(403, "processing session missing or expired", "processing_session_invalid"),
    );
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toMatchObject({ ok: false, stage: "credential", reason: "server" });
    if (!outcome.ok) expect(outcome.detail).toMatch(/encryption key session/i);
    expect(api.changePassword).not.toHaveBeenCalled();
  });

  it("a failed re-login caches the new envelope FIRST, then locks and drops the wrap", async () => {
    await enableBiometricUnlock(USER, Buffer.from(DATA_KEY));
    // A NON-ApiError rejection = the network died (the offline bucket);
    // ApiError-shaped failures classify as "server".
    apiState.failRelogin = new Error("network unreachable");
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome).toEqual({ ok: false, stage: "relogin", reason: "offline" });
    // The password HAS changed server-side: the cached envelope must let
    // the next (offline) unlock succeed with the NEW password.
    expect(api.cacheKeyEnvelope).toHaveBeenCalledWith(
      "alice",
      expect.objectContaining({ scheme: "v2" }),
    );
    const record = vi.mocked(api.cacheKeyEnvelope).mock.calls[0]![1] as { saltB64: string; wrappedB64: string };
    expect(unwrapUnder(record.wrappedB64, NEW_PASSWORD, record.saltB64)).toEqual(DATA_KEY);
    // The old auth key is dead — lock + wrap drop (the F-4 discipline).
    expect(vault.isUnlocked()).toBe(false);
    expect(await hasBiometricUnlock(USER)).toBe(false);
  });

  it("unusable envelope params refuse honestly instead of deriving garbage", async () => {
    apiState.keyEnvelope = {
      key_scheme: "v2",
      salt: SALT.toString("base64"),
      kdf_params: { algorithm: "argon2id", version: 1, iterations: 3, memory_kib: 65536, parallelism: 1 },
      wrapped_data_key: buildEnvelope(OLD_PASSWORD).wrappedB64,
    };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("verify");
      expect(outcome.reason).toBe("server");
      expect(outcome.detail).toMatch(/cannot derive/i);
    }
    expect(api.changePassword).not.toHaveBeenCalled();
  });
});

describe("the atomic v1 protocol (upgraded elsewhere)", () => {
  it("an old server response cannot authorize the atomic v1 rotation", async () => {
    apiState.keyEnvelope = { key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null };
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    // The v1 ladder runs (rekey etc. against its own mocked endpoints) and
    // dies at the retired credential endpoint with the scheme conflict.
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("rekey");
      expect(outcome.reason).toBe("offline");
      expect(outcome.detail).toMatch(/atomic password rotation/i);
    }
    expect(api.rotateCredential).not.toHaveBeenCalled();
  });
});
