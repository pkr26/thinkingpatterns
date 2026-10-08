import { runTestControl } from "./helpers/testControl";
/**
 * The v1→v2 key-envelope upgrade (src/envelopeUpgrade.ts, 2026-09-26):
 * wraps the CURRENT vault data key under the password-derived KEK, proves
 * possession via a processing session, uploads with both proof headers,
 * and never blindly retries a 403 envelope_key_mismatch.
 *
 * Idiom: tests/rotationV2.test.ts (mocked transport, REAL crypto).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { engine } from "./helpers/nodeEngine";

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
      getUsername: vi.fn(async () => "alice"),
      getCachedSalt: vi.fn(async () => SALT.toString("base64")),
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

const INPUT = { username: "alice", userId: USER, password: PASSWORD, verifierB64: VERIFIER_B64 };
const CHANGED = { ok: false, stage: "verify", reason: "locked", detail: "The account or key changed; unlock again before upgrading" };

describe("upgrade public failures, ownership, and native custody", () => {
  it("uses an already-verified caller proof without another password verification", async () => {
    const verifierB64 = "YWxyZWFkeS12ZXJpZmllZC1wcm9vZg==";
    vi.mocked(verifyPasswordForVault).mockResolvedValueOnce({ ok: false, reason: "offline" });
    try {
      expect(await upgradeKeyProtection({ ...INPUT, verifierB64 })).toEqual({ ok: true, already: false });
      expect(api.upgradeKeyEnvelope).toHaveBeenCalledWith(PARAMS, expect.any(String), "proc-tok", verifierB64);
      expect(verifyPasswordForVault).not.toHaveBeenCalled();
    } finally { vi.mocked(verifyPasswordForVault).mockReset().mockImplementation(async password => password === PASSWORD ? { ok: true, verifierB64: VERIFIER_B64 } : { ok: false, reason: "wrong-password" }); }
  });
  it("refuses a generation frozen during account metadata before any native wrap or possession request", async () => {
    vi.mocked(api.keyEnvelope).mockImplementationOnce(async () => { freezeLocalKeyWrites(USER); return upgradeState.keyEnvelope as never; });
    expect(await upgradeKeyProtection(INPUT)).toEqual(CHANGED); expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });
  it("classifies native derivation resumed after an epoch change as a wrapping failure before uploading", async () => {
    const pbkdf = engine.pbkdf2.bind(engine);
    vi.spyOn(engine, "pbkdf2").mockImplementationOnce((password, salt, iterations, size, digest, callback) => pbkdf(password, salt, iterations, size, digest, (error, key) => { advanceLocalWriteScope(); callback(error, key); }));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "wrap", reason: "offline", detail: "The account or unlocked key changed during the upgrade" });
    expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });
  it("classifies a generation frozen during native derivation as a wrapping failure", async () => {
    const pbkdf = engine.pbkdf2.bind(engine);
    vi.spyOn(engine, "pbkdf2").mockImplementationOnce((password, salt, iterations, size, digest, callback) => pbkdf(password, salt, iterations, size, digest, (error, key) => { freezeLocalKeyWrites(USER); callback(error, key); }));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "wrap", reason: "offline", detail: "Key rotation is in progress; local writes are paused" });
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });
  it("refuses a changed vault owner even when the public vault retains the same data-key allocation", async () => {
    const original = vault.get().dataKey, pbkdf = engine.pbkdf2.bind(engine);
    vi.spyOn(engine, "pbkdf2").mockImplementationOnce((password, salt, iterations, size, digest, callback) => pbkdf(password, salt, iterations, size, digest, (error, key) => {
      vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: original }, OTHER_USER); callback(error, key);
    }));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "wrap", reason: "offline", detail: "The account or unlocked key changed during the upgrade" });
    expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled(); expect(vault.ownerUserId()).toBe(OTHER_USER);
  });
  it.each(["locked", "no-account", "offline"] as const)("preserves the self-verification %s outcome without wrapping or posting", async reason => {
    vi.mocked(verifyPasswordForVault).mockResolvedValueOnce({ ok: false, reason });
    expect(await upgradeKeyProtection({ ...INPUT, verifierB64: undefined })).toEqual({ ok: false, stage: "verify", reason });
    expect(api.keyEnvelope).not.toHaveBeenCalled(); expect(api.openProcessingSession).not.toHaveBeenCalled();
  });
  it("reports the complete changed-account outcome when a failed real native password proof resumes in a replacement account", async () => {
    const actual = await vi.importActual<typeof import("../src/reauth")>("../src/reauth");
    vi.mocked(verifyPasswordForVault).mockImplementationOnce(password => actual.verifyPasswordForVault(password));
    const pbkdf = engine.pbkdf2.bind(engine);
    vi.spyOn(engine, "pbkdf2").mockImplementationOnce((password, salt, iterations, size, digest, callback) => pbkdf(password, salt, iterations, size, digest, (error, key) => {
      changeLocalSessionOwner(OTHER_USER);
      vault.unlock({ masterKey: Buffer.alloc(32, 4), authKey: Buffer.alloc(32, 5), dataKey: Buffer.alloc(32, 6) }, OTHER_USER);
      callback(error, key);
    }));
    expect(await upgradeKeyProtection({ ...INPUT, verifierB64: undefined })).toEqual(CHANGED);
    expect(api.keyEnvelope).not.toHaveBeenCalled(); expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
    expect(vault.ownerUserId()).toBe(OTHER_USER); expect(vault.get().dataKey).toEqual(Buffer.alloc(32, 6));
  });

  it.each([null, {}, { key_scheme: "v3", salt: SALT.toString("base64") }, { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: { algorithm: "argon2id" }, wrapped_data_key: "opaque" }])("explains unsupported account metadata before deriving or shipping a key: %j", async raw => {
    upgradeState.keyEnvelope = raw;
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "verify", reason: "server", detail: "this account's key envelope uses parameters this app cannot derive — update the app first" });
    expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });

  it("reports the whole legacy-server outcome without disguising it as an offline failure", async () => {
    vi.mocked(api.keyEnvelope).mockRejectedValueOnce(new ApiError(404, "private server detail"));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "verify", reason: "server", detail: "this server does not support the newer key protection yet" });
  });

  it("accepts the minimum eight-byte account salt and creates an interoperable wrap", async () => {
    const salt = Buffer.alloc(8, 11); upgradeState.keyEnvelope = { key_scheme: "v1", salt: salt.toString("base64") };
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: true, already: false });
    const call = vi.mocked(api.upgradeKeyEnvelope).mock.calls[0]!;
    const master = deriveMasterKey(PASSWORD, salt, PARAMS.iterations), kek = envelopeKek(master, salt);
    try { expect(unwrapDataKey(Buffer.from(call[1], "base64"), kek, INPUT.username, call[0])).toEqual(DATA_KEY); }
    finally { master.fill(0); kek.fill(0); }
  });

  it.each(["processing", "upload"] as const)("normalizes public %s failures while suppressing all server-authored copy", async phase => {
    const fail = phase === "processing" ? vi.mocked(api.openProcessingSession) : vi.mocked(api.upgradeKeyEnvelope);
    fail.mockRejectedValueOnce(new ApiError(502, "<script>private server copy</script>"));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "upgrade", reason: "server", detail: undefined });
    expect(api.cacheKeyEnvelope).not.toHaveBeenCalled();
  });

  it.each([
    [new ApiError(409, "expired native session", "processing_session_invalid"), { ok: false, stage: "upgrade", reason: "offline" }],
    [new Error("Native TLS stream stopped"), { ok: false, stage: "upgrade", reason: "offline", detail: "Native TLS stream stopped" }],
    ["native provider refused", { ok: false, stage: "upgrade", reason: "offline", detail: undefined }],
  ])("preserves the public upgrade classification for %s", async (error, expected) => {
    vi.mocked(api.upgradeKeyEnvelope).mockRejectedValueOnce(error);
    expect(await upgradeKeyProtection(INPUT)).toEqual(expected); expect(api.cacheKeyEnvelope).not.toHaveBeenCalled();
  });

  it.each([new ApiError(0, "private remote copy"), new Error("Native KDF stopped"), "native KDF refused"])("returns a typed wrapping failure and never posts a failed native derivation: %s", async error => {
    vi.spyOn(engine, "pbkdf2").mockImplementationOnce((_password, _salt, _iterations, _size, _digest, callback) => callback(error as Error));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: false, stage: "wrap", reason: error instanceof ApiError ? "server" : "offline", detail: error instanceof Error && !(error instanceof ApiError) ? error.message : undefined });
    expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });

  it.each([true, false])("keeps a successful upgrade usable after an unavailable optional cache, already=%s", async already => {
    if (already) upgradeState.keyEnvelope = { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: Buffer.alloc(60, 7).toString("base64") };
    vi.mocked(api.cacheKeyEnvelope).mockRejectedValueOnce(new Error("Native cache is temporarily read-only"));
    expect(await upgradeKeyProtection(INPUT)).toEqual({ ok: true, already }); expect(vault.get().dataKey).toEqual(DATA_KEY);
  });

  it.each(["reauth", "metadata", "processing", "upload", "cache", "already-cache"] as const)("refuses a replacement account at the awaited %s boundary", async phase => {
    const replace = () => { changeLocalSessionOwner(OTHER_USER); vault.unlock({ masterKey: Buffer.alloc(32, 4), authKey: Buffer.alloc(32, 5), dataKey: Buffer.alloc(32, 6) }, OTHER_USER); };
    if (phase === "already-cache") upgradeState.keyEnvelope = { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: Buffer.alloc(60, 7).toString("base64") };
    if (phase === "reauth") vi.mocked(verifyPasswordForVault).mockImplementationOnce(async () => { replace(); return { ok: true, verifierB64: VERIFIER_B64 }; });
    if (phase === "metadata") vi.mocked(api.keyEnvelope).mockImplementationOnce(async () => { replace(); return upgradeState.keyEnvelope as never; });
    if (phase === "processing") vi.mocked(api.openProcessingSession).mockImplementationOnce(async () => { replace(); return { session_token: "proc-tok" } as never; });
    if (phase === "upload") vi.mocked(api.upgradeKeyEnvelope).mockImplementationOnce(async () => { replace(); return {} as never; });
    if (phase.endsWith("cache")) vi.mocked(api.cacheKeyEnvelope).mockImplementationOnce(async () => { replace(); });
    const outcome = await upgradeKeyProtection({ ...INPUT, verifierB64: phase === "reauth" ? undefined : VERIFIER_B64 });
    expect(outcome).toEqual(phase === "processing" || phase === "upload" ? { ok: false, stage: "upgrade", reason: "offline", detail: "The account or unlocked key changed during the upgrade" } : CHANGED);
    expect(vault.ownerUserId()).toBe(OTHER_USER); expect(vault.get().dataKey).toEqual(Buffer.alloc(32, 6));
    if (phase === "processing") expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
    if (phase === "reauth" || phase === "metadata") expect(api.openProcessingSession).not.toHaveBeenCalled();
    if (phase !== "cache" && phase !== "already-cache") expect(api.cacheKeyEnvelope).not.toHaveBeenCalled();
  });

  it("refuses a same-account key allocation replacement with identical data-key bytes", async () => {
    vi.mocked(api.keyEnvelope).mockImplementationOnce(async () => { vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(DATA_KEY) }, USER); return upgradeState.keyEnvelope as never; });
    expect(await upgradeKeyProtection(INPUT)).toEqual(CHANGED); expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(vault.get().dataKey).toEqual(DATA_KEY);
  });

  it.each(["success", "cipher-failure", "upload-failure"] as const)("erases actual native provider-held master, wrapping key, and plaintext allocations after %s", async phase => {
    const masters: Buffer[] = [], keys: Buffer[] = [], plaintext: Buffer[] = [];
    const hkdf = engine.hkdfSync.bind(engine), create = engine.createCipheriv.bind(engine);
    vi.spyOn(engine, "hkdfSync").mockImplementation((digest, master, salt, label, size) => { masters.push(master); return hkdf(digest, master, salt, label, size); });
    vi.spyOn(engine, "createCipheriv").mockImplementation((algorithm, key, nonce) => {
      keys.push(key); const cipher = create(algorithm, key, nonce), update = cipher.update.bind(cipher);
      vi.spyOn(cipher, "update").mockImplementation((value: Buffer) => { plaintext.push(value); if (phase === "cipher-failure") throw new Error("Native envelope cipher failed"); return update(value); }); return cipher;
    });
    if (phase === "upload-failure") vi.mocked(api.upgradeKeyEnvelope).mockRejectedValueOnce(new ApiError(502, "private remote failure"));
    const outcome = await upgradeKeyProtection(INPUT); expect(outcome.ok).toBe(phase === "success");
    expect(masters).toHaveLength(1); expect(keys).toHaveLength(1); expect(plaintext).toHaveLength(1);
    for (const allocation of [...masters, ...keys, ...plaintext]) expect(allocation.every(value => value === 0)).toBe(true);
    expect(vault.get().dataKey).toEqual(DATA_KEY);
  });
});

vi.mock("../src/reauth", () => ({
  verifyPasswordForVault: vi.fn(async (password: string) =>
    password === PASSWORD
      ? { ok: true as const, verifierB64: VERIFIER_B64 }
      : { ok: false as const, reason: "wrong-password" as const }),
}));

import { api, ApiError } from "../src/api/client";
import { upgradeKeyProtection } from "../src/envelopeUpgrade";
import { vault } from "../src/vault";
import { advanceLocalWriteScope, changeLocalSessionOwner, freezeLocalKeyWrites, __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { deriveKeys } from "../src/crypto/journalCrypto";
import { deriveMasterKey } from "../src/crypto/kdf";
import { defaultKdfParams, envelopeKek, unwrapDataKey } from "../src/crypto/keyEnvelope";
import { verifyPasswordForVault } from "../src/reauth";

/** The account's v1-derived data key — what the upgrade must wrap VERBATIM. */
const SALT = Buffer.alloc(16, 3);
const DATA_KEY = deriveKeys(PASSWORD, SALT).dataKey;
const PARAMS = defaultKdfParams();

beforeEach(() => {
  vi.restoreAllMocks();
  runTestControl(__resetLocalKeyLifecycleForTests);
  store.clear();
  upgradeState.keyEnvelope = { key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null };
  upgradeState.failUpgrade = null;
  upgradeState.failSession = null;
  vi.mocked(api.upgradeKeyEnvelope).mockClear();
  vi.mocked(api.openProcessingSession).mockClear();
  vi.mocked(api.cacheKeyEnvelope).mockClear();
  vi.mocked(api.keyEnvelope).mockClear();
  vi.mocked(verifyPasswordForVault).mockClear();
  vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(DATA_KEY) }, USER);
});
afterEach(() => { vi.restoreAllMocks(); vault.lock(); });

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
    upgradeState.failUpgrade = { status: 403, code: "verification_failed", message: "<script>alert(1)</script> credencial rechazada" };
    const outcome = await upgradeKeyProtection({ username: "alice", userId: USER, password: PASSWORD, verifierB64: "stale-verifier" });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("upgrade");
      expect(outcome.reason).toBe("wrong-password");
      expect(outcome.detail).toBeUndefined();
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
    expect(foreign).toEqual({ ok: false, stage: "verify", reason: "locked" });
    expect(api.upgradeKeyEnvelope).not.toHaveBeenCalled();
  });
});
