/**
 * The v1→v2 key-envelope upgrade (src/envelopeUpgrade.ts, 2026-09-26):
 * wraps the CURRENT vault data key under the password-derived KEK, proves
 * possession via a processing session, uploads with both proof headers,
 * and never blindly retries a 403 envelope_key_mismatch.
 *
 * Idiom: tests/rotationV2.test.ts (mocked transport, REAL crypto).
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
const OTHER_USER = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const PASSWORD = "correct old password";
const VERIFIER_B64 = "dmVyaWZpZXItYjY0";

const upgradeState = {
  keyEnvelope: null as null | Record<string, unknown>,
  failUpgrade: null as null | { status: number; code?: string; message: string },
  failSession: null as null | Error,
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
    api: {
      keyEnvelope: vi.fn(async () => upgradeState.keyEnvelope),
      cacheKeyEnvelope: vi.fn(async () => {}),
      openProcessingSession: vi.fn(async () => {
        if (upgradeState.failSession) throw upgradeState.failSession;
        return { session_token: "proc-tok" };
      }),
      upgradeKeyEnvelope: vi.fn(async () => {
        if (upgradeState.failUpgrade) {
          const f = upgradeState.failUpgrade;
          throw new ApiError(f.status, f.message, f.code);
        }
        return {};
      }),
    },
  };
});

vi.mock("../src/reauth", () => ({
  verifyPasswordForVault: async (password: string) =>
    password === PASSWORD
      ? { ok: true as const, verifierB64: VERIFIER_B64 }
      : { ok: false as const, reason: "wrong-password" as const },
}));

import { api, ApiError } from "../src/api/client";
import { upgradeKeyProtection } from "../src/envelopeUpgrade";
import { vault } from "../src/vault";
import { changeLocalSessionOwner, __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { deriveKeys } from "../src/crypto/MindPatternCrypto";
import { deriveMasterKey } from "../src/crypto/kdf";
import { defaultKdfParams, envelopeKek, unwrapDataKey } from "../src/crypto/keyEnvelope";

/** The account's v1-derived data key — what the upgrade must wrap VERBATIM. */
const SALT = Buffer.alloc(16, 3);
const DATA_KEY = deriveKeys(PASSWORD, SALT).dataKey;
const PARAMS = defaultKdfParams();

beforeEach(() => {
  __resetLocalKeyLifecycleForTests();
  store.clear();
  upgradeState.keyEnvelope = { key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null };
  upgradeState.failUpgrade = null;
  upgradeState.failSession = null;
  vi.mocked(api.upgradeKeyEnvelope).mockClear();
  vi.mocked(api.openProcessingSession).mockClear();
  vi.mocked(api.cacheKeyEnvelope).mockClear();
  vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(DATA_KEY) }, USER);
});

describe("upgradeKeyProtection (v1 → v2)", () => {
  it("does not ship a retained old-account key or wrap after password derivation resumes in a replacement session", async () => {
    const kdf = await import("../src/crypto/kdf"); const original = kdf.deriveMasterKeyAsync; let release!: () => void;
    const gate = vi.spyOn(kdf, "deriveMasterKeyAsync").mockImplementationOnce(async (...args) => {
      const key = await original(...args); await new Promise<void>(resolve => { release = resolve; }); return key;
    });
    const pending = upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: VERIFIER_B64 });
    await vi.waitFor(() => expect(release).toBeTypeOf("function"));
    changeLocalSessionOwner(OTHER_USER); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 4), dataKey: Buffer.alloc(32, 8) }, OTHER_USER);
    release(); const outcome = await pending; gate.mockRestore();
    expect(outcome.ok).toBe(false); expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled(); expect(api.cacheKeyEnvelope).not.toHaveBeenCalled();
    expect(vault.ownerUserId()).toBe(OTHER_USER);
  });
  it("wraps the CURRENT data key, proves possession, and uploads with both proofs", async () => {
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD });
    expect(outcome).toEqual({ ok: true, already: false });

    // Possession: the processing session carries the vault's data key.
    expect(api.openProcessingSession).toHaveBeenCalledWith(DATA_KEY.toString("base64"));
    // Both proofs + the envelope on one request.
    expect(api.upgradeKeyEnvelope).toHaveBeenCalledWith(PARAMS, expect.any(String), "proc-tok", VERIFIER_B64);
    const wrappedB64 = (vi.mocked(api.upgradeKeyEnvelope).mock.calls[0] as unknown[])[1] as string;
    expect(Buffer.from(wrappedB64, "base64")).toHaveLength(60);
    // The wrap opens under the password-derived KEK to the SAME key — the
    // whole upgrade is a no-op for every stored blob.
    const master = deriveMasterKey(PASSWORD, SALT, PARAMS.iterations);
    expect(unwrapDataKey(Buffer.from(wrappedB64, "base64"), envelopeKek(master, SALT), "alice", PARAMS)).toEqual(
      DATA_KEY,
    );
    // The next unlock (incl. offline) is v2: the envelope is cached.
    expect(api.cacheKeyEnvelope).toHaveBeenCalledWith(
      "alice",
      expect.objectContaining({ scheme: "v2", wrappedB64 }),
    );
    // The session is untouched — same data key, same vault state.
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.get().dataKey).toEqual(DATA_KEY);
  });

  it("an already-v2 account is an honest no-op (nothing sent)", async () => {
    upgradeState.keyEnvelope = { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: Buffer.alloc(60, 7).toString("base64") };
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD });
    expect(outcome).toEqual({ ok: true, already: true });
    expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    // The local cache still learns the scheme for offline unlocks.
    expect(api.cacheKeyEnvelope).toHaveBeenCalled();
  });

  it("a wrong password (self-verify path) fails at verify", async () => {
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: "nope" });
    expect(outcome).toEqual({ ok: false, stage: "verify", reason: "wrong-password" });
    expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });

  it("403 envelope_key_mismatch is typed, never auto-retried", async () => {
    upgradeState.failUpgrade = { status: 403, code: "envelope_key_mismatch", message: "key did not authenticate" };
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: VERIFIER_B64 });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("upgrade");
      expect(outcome.reason).toBe("key-mismatch");
      expect(outcome.detail).toMatch(/does not match/i);
    }
  });

  it("a 403 verifier rejection maps to wrong-password (retryable)", async () => {
    upgradeState.failUpgrade = { status: 403, code: "verification_failed", message: "verifier rejected" };
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: "stale-verifier" });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("upgrade");
      expect(outcome.reason).toBe("wrong-password");
      expect(outcome.detail).toBe("verifier rejected");
    }
  });

  it("a 401 session death is typed so the screen can explain the unlock hop", async () => {
    upgradeState.failUpgrade = { status: 401, code: "unauthorized", message: "invalid token" };
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: VERIFIER_B64 });
    expect(outcome).toEqual({ ok: false, stage: "upgrade", reason: "session-expired" });
  });

  it("a pre-envelope server (404) and an unreachable server fail with distinct honesty", async () => {
    vi.mocked(api.keyEnvelope).mockRejectedValueOnce(new ApiError(404, "not found", "not_found"));
    const legacy = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD });
    expect(legacy.ok).toBe(false);
    if (!legacy.ok) {
      expect(legacy.reason).toBe("server");
      expect(legacy.detail).toMatch(/does not support/i);
    }

    vi.mocked(api.keyEnvelope).mockRejectedValueOnce(new ApiError(0, "server unreachable"));
    const offline = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD });
    expect(offline).toEqual({ ok: false, stage: "verify", reason: "offline" });
  });

  it("refuses when the vault is locked or bound to another account", async () => {
    vault.lock();
    const locked = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: VERIFIER_B64 });
    expect(locked).toEqual({ ok: false, stage: "verify", reason: "locked" });

    vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(DATA_KEY) }, OTHER_USER);
    const foreign = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: VERIFIER_B64 });
    expect(foreign.ok).toBe(false);
    if (!foreign.ok) expect(foreign.reason).toBe("locked");
    expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });
});
