/**
 * Security pins from the 2026-09-20 remediation wave (fourth-pass
 * fixes; originally test file auditFixes2026b.test.ts).
 *
 *   M-1  — stateSeqGuard fails closed once a high-water mark exists; the
 *          in-memory mirror survives storage tampering and self-heals it.
 *   M-2  — entry content-version AAD (v2 binding, v1 fallback) and the
 *          per-entry high-water store (rollback detection, delete-forget,
 *          rotation rebind).
 *   M-3  — the first-origin pin: login warns when the selected server
 *          differs from the pinned origin; setSession refuses non-server
 *          account ids.
 *   H-1  — rotatePassword orchestration against a mocked server.
 *   F-4  — rotation failure paths self-clean (audit round 2, 2026-09-21):
 *          a credential- or relogin-stage failure after the server rekeyed
 *          still locks the vault and drops the biometric wrap.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const store = new Map<string, string>();

vi.mock("@react-native-async-storage/async-storage", () => ({
  default: {
    getItem: async (k: string) => store.get(k) ?? null,
    setItem: async (k: string, v: string) => void store.set(k, v),
    removeItem: async (k: string) => void store.delete(k),
    multiRemove: async (keys: readonly string[]) => {
      for (const k of keys) store.delete(k);
    },
    getAllKeys: async () => Array.from(store.keys()),
  },
}));

// --- shared mocks for the rotation flow -------------------------------------

const apiState = {
  baseUrl: "https://real.example.test",
  cachedSalt: "c2FsdHNhbHRzYWx0c2FsdA==", // "saltsaltsaltsalt"
  consents: [] as Array<Record<string, unknown>>,
  rekeyResult: { entries: 2, insights: 2, measures: 1 },
  consentsRewrapped: undefined as number | undefined,
  failAt: null as null | "rekey" | "credential" | "relogin" | "verify",
  /** Audit 2026-09-28: make rotateCredential answer 409 key_scheme_conflict
   *  (the account upgraded to the v2 envelope from another device). */
  credentialConflict: false,
};

vi.mock("../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api/client")>();
  const { changeLocalSessionOwner } = await import("../src/localWriteGuard");
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
    getBaseUrl: async () => apiState.baseUrl,
    api: {
      getCachedSalt: async () => apiState.cachedSalt,
      saltFor: async () => ({ salt: apiState.cachedSalt }),
      cacheSalt: vi.fn(async () => {}),
      // v2 key-scheme routing (2026-09-26): default v1 so the H-1 pins below
      // keep exercising the resumable rekey ladder; the v2 branch (O(1)
      // rewrap via PUT /account/password) has its own suite in
      // tests/rotationV2.test.ts.
      keyEnvelope: async () => ({ key_scheme: "v1", salt: apiState.cachedSalt, kdf_params: null, wrapped_data_key: null }),
      openProcessingSession: async (key: string) => ({ session_token: `tok-${key.slice(0, 6)}` }),
      rekeyStoredData: vi.fn(async (_old, _next, _proof, body) => {
        if (apiState.failAt === "rekey") {
          throw new ApiError(400, "old key did not authenticate every blob", "rekey_key_mismatch");
        }
        if (apiState.failAt === "credential") throw new ApiError(503, "atomic rotation unavailable");
        if (apiState.credentialConflict) throw new ApiError(409, "account uses the newer key protection", "key_scheme_conflict");
        return { ...apiState.rekeyResult, consents_rewrapped: apiState.consentsRewrapped, credential_rotated: true, operation_id: body.operation_id };
      }),
      listConsents: async () => apiState.consents,
      rewrapConsent: vi.fn(async () => ({})),
      rotateCredential: vi.fn(async () => {
        if (apiState.failAt === "credential") throw new ApiError(503, "server busy");
        if (apiState.credentialConflict) {
          throw new ApiError(409, "account uses the newer key protection", "key_scheme_conflict");
        }
        return {};
      }),
      login: vi.fn(async () => {
        if (apiState.failAt === "relogin") throw new ApiError(0, "network unreachable");
        return { token: "fresh", user_id: USER };
      }),
      setSession: async (_token: string, userId: string) => {
        changeLocalSessionOwner(userId);
      },
      listEntriesPage: vi.fn(async () => ({ entries: [], nextOffset: null, revision: null })),
      listMeasuresPage: vi.fn(async () => []),
      // independent audit 2026-09-27 (P2): the rotation's offline-queue drain
      // uploads through this seam (default success; per-test overrides make
      // the drain fail to pin the abort).
      createQueuedEntry: vi.fn(async () => ({})),
      getEntry: async () => {
        throw new ApiError(404, "entry not found", "not_found");
      },
    },
  };
});

// reauth is verified separately in its own suite; the rotation flow treats
// it as the typed-password oracle.
vi.mock("../src/reauth", () => ({
  verifyPasswordForVault: async (password: string) =>
    password === "correct old password"
      ? { ok: true as const, verifierB64: "b2xkLXZlcmlmaWVy" }
      : { ok: false as const, reason: "wrong-password" as const },
}));

// 2026-09-26 audit H-2: controllable derivation seam. The default delegates
// to the REAL deriveKeysAsync (every other rotation test runs the real
// PBKDF2 path); the typed-catch test rejects once to prove a local throw
// before the server flow becomes {ok:false} instead of an escaped rejection.
const deriveKeysAsync = vi.hoisted(() => vi.fn());
vi.mock("../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/MindPatternCrypto")>();
  const real = actual.deriveKeysAsync;
  deriveKeysAsync.mockImplementation((...args: Parameters<typeof real>) => real(...args));
  return { ...actual, deriveKeysAsync: (...args: Parameters<typeof real>) => deriveKeysAsync(...args) };
});

import { checkAnalysisGeneration, FRESHNESS_ERROR, forgetAnalysisGeneration } from "../src/stateSeqGuard";
// 2026-09-26 audit LOW: the state-seq mark persists through the sealed
// secureStore lane now — assertions about the stored copy round-trip
// through the same facade the guard uses.
import { secureStore } from "../src/secureStore";
// M-3/L-7 client-shape tests live in tests/client.rotation.test.ts against
// the REAL client module (this file mocks it for the rotation flow).
import {
  forgetAllEntryVersions,
  knownEntryVersion,
  observeEntryVersions,
  rebindEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";
import { api, ApiError } from "../src/api/client";
import { decryptEntry, deriveKeysAsync, encryptEntry } from "../src/crypto/MindPatternCrypto";
import { rotatePassword } from "../src/rotation";
import { vault } from "../src/vault";
import { enableBiometricUnlock, hasBiometricUnlock } from "../src/biometricUnlock";
import * as Keychain from "react-native-keychain";

const keychainMock = Keychain as unknown as { __reset: () => void };

const DATA_KEY = Buffer.alloc(32, 9);
const USER = "0123456789abcdef0123456789abcdef";

/** Rotation starts from a password-unlocked, verified account. A retry
 * restores the original keys with writes still suspended by its checkpoint. */
async function unlockRotationOwner(writeSuspended = false): Promise<void> {
  const keys = await deriveKeysAsync("correct old password", Buffer.from(apiState.cachedSalt, "base64"));
  vault.unlock(keys, USER, { writeSuspended });
}

beforeEach(async () => {
  (await import("../src/localRekey")).__resetLocalKeyLifecycleForTests();
  store.clear();
  vi.clearAllMocks();
  apiState.failAt = null;
  apiState.credentialConflict = false;
  apiState.consents = [];
  apiState.consentsRewrapped = undefined;
  keychainMock.__reset();
  vault.lock();
  // independent audit 2026-09-27 (P2): the queue-drain seam resets to
  // success like every other server spy.
  vi.mocked(api.createQueuedEntry).mockReset();
  vi.mocked(api.createQueuedEntry).mockImplementation(async () => ({}));
  // H-2 seam: clear call history/queued rejections, keep the delegating
  // default implementation.
  deriveKeysAsync.mockClear();
});

// --- M-1: rollback guard -----------------------------------------------------

describe("stateSeqGuard fail-closed (M-1)", () => {
  it("passes absent values only while NO high-water mark exists", async () => {
    await expect(checkAnalysisGeneration("m1a", undefined, undefined)).resolves.toBeUndefined();
    await expect(checkAnalysisGeneration("m1a", 5, 5)).resolves.toBeUndefined();
    // A mark now exists: the same absent-values pair is a protocol
    // downgrade a compromised server controls — it must fail closed.
    await expect(checkAnalysisGeneration("m1a", undefined, undefined)).rejects.toThrow(FRESHNESS_ERROR);
    await expect(checkAnalysisGeneration("m1a", 7, undefined)).rejects.toThrow(FRESHNESS_ERROR);
    await forgetAnalysisGeneration("m1a");
    await expect(checkAnalysisGeneration("m1a", undefined, undefined)).resolves.toBeUndefined();
  });

  it("survives on-device storage tampering via the in-memory mirror (and self-heals it)", async () => {
    await expect(checkAnalysisGeneration("m1b", 9, 9)).resolves.toBeUndefined();
    // The device-access adversary zeroes the persisted mark...
    store.delete("mindpattern.stateSeq.m1b");
    // ...but the mirror remembers: a both-copies rollback still throws.
    await expect(checkAnalysisGeneration("m1b", 4, 4)).rejects.toThrow(FRESHNESS_ERROR);
    // And the persisted copy was rewritten (self-heal), so the defense
    // survives a process restart too. 2026-09-26: the rewrite is sealed
    // (secureStore envelope, GCM-verified under the Keychain-held key) —
    // read it back through the same facade, never the raw slot.
    expect(await secureStore.getItem("mindpattern.stateSeq.m1b")).toBe("9");
  });

  it("still catches payload/echo disagreement", async () => {
    await expect(checkAnalysisGeneration("m1c", 3, 4)).rejects.toThrow(FRESHNESS_ERROR);
  });
});

// --- M-2: entry version binding + high-water store ---------------------------

describe("entry content-version binding (M-2)", () => {
  it("encrypts under the v2 AAD and decrypts through the ladder (v2 first, v1 fallback)", () => {
    const v2blob = encryptEntry({ dataKey: DATA_KEY }, USER, "e-1", "text", "2026-09-20", null, undefined, 2).blobB64;
    expect(decryptEntry({ dataKey: DATA_KEY }, USER, "e-1", v2blob, 2).text).toBe("text");
    // A v1-shaped blob (no version in the AAD) still decrypts when the row
    // declares version 1 — the legacy acceptance rule.
    const v1blob = encryptEntry({ dataKey: DATA_KEY }, USER, "e-2", "legacy", "2026-09-20", null).blobB64;
    expect(decryptEntry({ dataKey: DATA_KEY }, USER, "e-2", v1blob, 1).text).toBe("legacy");
    // The version is IN the binding: v2 ciphertext does not decrypt under a
    // different declared version.
    expect(() => decryptEntry({ dataKey: DATA_KEY }, USER, "e-1", v2blob, 3)).toThrow();
  });

  // Audit 2026-09-28 (MEDIUM): the 2026-09-26 M-M1 gating (legacy fallback
  // for declared version 1 ONLY) failed closed on rows the SERVER itself
  // legally produces — entries.py bumps content_version when a legacy
  // client edits while keeping the legacy blob bytes, so those rows
  // vanished from the app as TamperError. The mobile ladder now mirrors
  // the server's crypto.entry_aad_candidates (v2 then v1 for ANY version).
  // A stale-blob-with-fresh-echo replay is still caught by the high-water
  // marks pinned below — that is where the rollback protection lives.
  it("a legacy-bound blob decrypts at ANY declared version (server-legitimate rows, audit 2026-09-28)", () => {
    const legacyBlob = encryptEntry({ dataKey: DATA_KEY }, USER, "e-stale", "stale text", "2026-09-19", null).blobB64;
    expect(decryptEntry({ dataKey: DATA_KEY }, USER, "e-stale", legacyBlob, 1).text).toBe("stale text");
    expect(decryptEntry({ dataKey: DATA_KEY }, USER, "e-stale", legacyBlob, 2).text).toBe("stale text");
    expect(decryptEntry({ dataKey: DATA_KEY }, USER, "e-stale", legacyBlob, 5).text).toBe("stale text");
    // The version is still IN the v2 binding: a v2-bound blob decrypts
    // neither under a different declared version nor through the legacy
    // three-part AAD, and a foreign owner still fails authentication.
    const v2blob = encryptEntry({ dataKey: DATA_KEY }, USER, "e-v2b", "v2 text", "2026-09-20", null, undefined, 2).blobB64;
    expect(() => decryptEntry({ dataKey: DATA_KEY }, USER, "e-v2b", v2blob, 3)).toThrow();
    expect(() => decryptEntry({ dataKey: DATA_KEY }, "user-OTHER", "e-v2b", v2blob, 2)).toThrow(
      expect.objectContaining({ name: "TamperError" }),
    );
  });

  it("flags a rolled-back row and remembers the high-water mark", async () => {
    resetEntryVersionMirrors();
    const first = await observeEntryVersions(USER, DATA_KEY, [
      { clientEntryId: "e-1", contentVersion: 3 },
      { clientEntryId: "e-2", contentVersion: 1 },
    ]);
    expect(first.rolledBack).toEqual([]);
    expect(await knownEntryVersion(USER, DATA_KEY, "e-1")).toBe(3);
    const rolled = await observeEntryVersions(USER, DATA_KEY, [
      { clientEntryId: "e-1", contentVersion: 2 }, // replayed older blob + echo
    ]);
    expect(rolled.rolledBack).toEqual(["e-1"]);
    // The store itself is ciphertext under the data key, AAD-bound to the user.
    const raw = store.get("mindpattern.entryVersions." + USER);
    expect(raw).toBeTruthy();
    expect(raw).not.toContain('"e-1"'); // serialized plaintext never lands raw
  });

  it("forgets a deleted entry's mark (recreate at version 1 is legitimate)", async () => {
    resetEntryVersionMirrors();
    await observeEntryVersions(USER, DATA_KEY, [{ clientEntryId: "e-x", contentVersion: 4 }]);
    const { forgetEntryVersion } = await import("../src/entryVersions");
    await forgetEntryVersion(USER, DATA_KEY, "e-x");
    expect(await knownEntryVersion(USER, DATA_KEY, "e-x")).toBeNull();
    const after = await observeEntryVersions(USER, DATA_KEY, [{ clientEntryId: "e-x", contentVersion: 1 }]);
    expect(after.rolledBack).toEqual([]);
  });

  it("rebinds the store under a rotated data key and drops corrupt bytes to empty", async () => {
    resetEntryVersionMirrors();
    await observeEntryVersions(USER, DATA_KEY, [{ clientEntryId: "e-1", contentVersion: 2 }]);
    const newKey = Buffer.alloc(32, 5);
    await rebindEntryVersions(USER, DATA_KEY, newKey);
    resetEntryVersionMirrors();
    expect(await knownEntryVersion(USER, newKey, "e-1")).toBe(2);
    // A corrupt persisted blob degrades to an empty map, never a crash.
    store.set("mindpattern.entryVersions." + USER, "bm90IGNpcGhlcnRleHQ=");
    resetEntryVersionMirrors();
    expect(await knownEntryVersion(USER, newKey, "e-1")).toBeNull();
    await forgetAllEntryVersions(USER);
  });
});

// --- H-1: rotation orchestration ----------------------------------------------

describe("rotatePassword (H-1/M-3)", () => {
  beforeEach(() => unlockRotationOwner());
  it("runs the full flow and re-wraps active grants", async () => {
    apiState.consents = [
      {
        id: "c".repeat(32),
        therapist_id: "t".repeat(32),
        display_name: "Dr. Real",
        username: "drreal",
        status: "active",
        granted_at: "2026-09-01T00:00:00Z",
        revoked_at: null,
        therapist_wrap_pub_key: null, // replaced below with a real SPKI
      },
      {
        id: "d".repeat(32),
        therapist_id: "u".repeat(32),
        display_name: "Dr. Gone",
        username: "drgone",
        status: "revoked",
        granted_at: "2026-08-01T00:00:00Z",
        revoked_at: "2026-08-02T00:00:00Z",
      },
    ];
    // A real P-256 SPKI for the wrap (the crypto must actually run).
    const { engine } = await import("../src/crypto/engine");
    const pair = engine.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const spki = pair.publicKey.export({ format: "der", type: "spki" }) as Buffer;
    (apiState.consents[0] as Record<string, unknown>).therapist_wrap_pub_key = spki.toString("base64");

    const rewrap = vi.mocked(api.rewrapConsent);
    rewrap.mockClear();
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.counts.entries).toBe(2);
      expect(outcome.rewrapped).toBe(1); // revoked grant is skipped
      expect(outcome.rewrapFailures).toEqual([]);
    }
    expect(rewrap).not.toHaveBeenCalled();
    expect(api.rotateCredential).not.toHaveBeenCalled();
    const request = vi.mocked(api.rekeyStoredData).mock.calls[0]![3];
    expect(request.consent_wraps).toHaveLength(1);
    expect(request.consent_wraps[0]!.consent_id).toBe("c".repeat(32));
    expect(request.consent_wraps[0]!.therapist_wrap_pub_key).toBe(spki.toString("base64"));
    expect(request.consent_wraps[0]!.wrapped_key).toBeTruthy();
    expect(request.consent_wraps[0]!.ephemeral_pub).toBeTruthy();
  });

  it("reports the server's zero committed wraps when a grant was revoked during rotation", async () => {
    const { engine } = await import("../src/crypto/engine");
    const pair = engine.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    apiState.consents = [{ id: "c".repeat(32), therapist_id: "t".repeat(32), status: "active",
      therapist_wrap_pub_key: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64") }];
    apiState.consentsRewrapped = 0;
    const outcome = await rotatePassword({ username: "alice", userId: USER,
      oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" });
    expect(outcome).toMatchObject({ ok: true, rewrapped: 0, rewrapFailures: [] });
    expect(vi.mocked(api.rekeyStoredData).mock.calls[0]![3].consent_wraps).toHaveLength(1);
    expect(api.rewrapConsent).not.toHaveBeenCalled();
  });

  it("refuses to run with a wrong current password", async () => {
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "wrong password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.stage).toBe("verify");
  });

  it("retries a lost atomic response with the identical durable operation, body and token headers", async () => {
    vi.mocked(api.rekeyStoredData).mockRejectedValueOnce(new Error("response lost after commit"));
    const input = { username: "alice", userId: USER, oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" };
    const first = await rotatePassword(input);
    expect(first).toMatchObject({ ok: false, stage: "rekey" });
    expect(api.login).not.toHaveBeenCalled();
    expect(await (await import("../src/localRekey")).pendingLocalRekey(USER)).toBe(true);
    const original = vi.mocked(api.rekeyStoredData).mock.calls[0]!;
    await unlockRotationOwner(true);
    const second = await rotatePassword(input);
    expect(second.ok).toBe(true);
    expect(vi.mocked(api.rekeyStoredData).mock.calls[1]).toEqual(original);
    expect(api.rotateCredential).not.toHaveBeenCalled();
    expect(await (await import("../src/localRekey")).pendingLocalRekey(USER)).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
  });

  it("never bypasses an atomic key mismatch using a readable sample journal or measure", async () => {
    apiState.failAt = "rekey";
    const outcome = await rotatePassword({ username: "alice", userId: USER, oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" });
    expect(outcome).toMatchObject({ ok: false, stage: "rekey", reason: "server" });
    expect(api.listEntriesPage).not.toHaveBeenCalled();
    expect(api.listMeasuresPage).not.toHaveBeenCalled();
    expect(api.rotateCredential).not.toHaveBeenCalled();
    expect(api.login).not.toHaveBeenCalled();
  });

  it("retains the checkpoint and refuses a different new password on retry", async () => {
    vi.mocked(api.rekeyStoredData).mockRejectedValueOnce(new Error("response lost"));
    const input = { username: "alice", userId: USER, oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" };
    await rotatePassword(input);
    const original = [...store.entries()];
    await unlockRotationOwner(true);
    const second = await rotatePassword({ ...input, newPassword: "a DIFFERENT strong passphrase!" });
    expect(second.ok).toBe(false);
    expect(api.rekeyStoredData).toHaveBeenCalledOnce();
    expect([...store.entries()]).toEqual(original);
    expect(vault.isUnlocked()).toBe(false);
  });

  it("an unsupported old server response cannot become a credential commit", async () => {
    vi.mocked(api.rekeyStoredData).mockResolvedValueOnce({ entries: 2, insights: 2, measures: 1 });
    const outcome = await rotatePassword({ username: "alice", userId: USER, oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" });
    expect(outcome).toMatchObject({ ok: false, stage: "rekey" });
    expect(api.rotateCredential).not.toHaveBeenCalled();
    expect(api.login).not.toHaveBeenCalled();
  });

  it("cacheSalt failure after a committed reset remains a successful rotation", async () => {
    vi.mocked(api.cacheSalt).mockRejectedValueOnce(new Error("disk full"));
    const outcome = await rotatePassword({ username: "alice", userId: USER, oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" });
    expect(outcome.ok).toBe(true);
    expect(vault.isUnlocked()).toBe(false);
  });

  it("a broken active sharing grant blocks before remote commit", async () => {
    apiState.consents = [{ id: "c".repeat(32), therapist_id: "t".repeat(32), status: "active", therapist_wrap_pub_key: null }];
    const outcome = await rotatePassword({ username: "alice", userId: USER, oldPassword: "correct old password", newPassword: "a strong new passphrase 42!" });
    expect(outcome).toMatchObject({ ok: false, stage: "rewrap" });
    expect(api.rekeyStoredData).not.toHaveBeenCalled();
    expect(api.rotateCredential).not.toHaveBeenCalled();
  });

  // 2026-09-26 audit H-2: the flow used to draw its fresh salt from
  // globalThis.crypto.getRandomValues — React Native ships no Web Crypto
  // global, so the call crashed on device. The rotation must run end-to-end
  // with that global deleted, proving the engine seam (quick-crypto on
  // device / node:crypto here) is the only entropy source.
  it("rotates successfully when globalThis.crypto does not exist (no Web Crypto dependency)", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    const hadGlobalCrypto = descriptor !== undefined;
    if (hadGlobalCrypto) {
      delete (globalThis as { crypto?: unknown }).crypto;
    }
    try {
      expect((globalThis as { crypto?: unknown }).crypto).toBeUndefined();
      const outcome = await rotatePassword({
        username: "alice",
        userId: USER,
        oldPassword: "correct old password",
        newPassword: "a strong new passphrase 42!",
      });
      expect(outcome.ok).toBe(true);
    } finally {
      if (hadGlobalCrypto) {
        Object.defineProperty(globalThis, "crypto", descriptor!);
      }
    }
  });

  // H-2: an unexpected LOCAL throw (derivation/seam failure) must surface as
  // a typed outcome, never an escaped rejection — the old code called
  // freshSalt() outside the try block entirely.
  it("maps an unexpected pre-flow throw to a typed outcome instead of escaping", async () => {
    deriveKeysAsync.mockRejectedValueOnce(new Error("boom"));
    await expect(
      rotatePassword({
        username: "alice",
        userId: USER,
        oldPassword: "correct old password",
        newPassword: "a strong new passphrase 42!",
      }),
    ).resolves.toMatchObject({ ok: false, stage: "verify", reason: "offline" });
  });
});

// --- Audit round 2 (2026-09-21) F-4: failure paths must self-clean -----------

describe("rotatePassword failure-path cleanup (audit round 2, 2026-09-21, F-4)", () => {
  // Constraint under test: stages 5/6 fail only AFTER the server rekeyed the
  // blobs (stage 3). The vault's OLD data key is dead server-side from that
  // point — returning {ok:false} while it stays unlocked (or while the
  // biometric wrap can still restore it) would seal any entry written in the
  // retry window under a key nothing can decrypt with.
  async function unlockWithWrap(): Promise<void> {
    await unlockRotationOwner();
    // A wrap sealed under the OLD data key — exactly the stale-key hazard.
    await enableBiometricUnlock(USER, vault.get().dataKey);
    expect(vault.isUnlocked()).toBe(true);
    expect(await hasBiometricUnlock(USER)).toBe(true);
  }

  it("an atomic commit failure locks the vault and drops the biometric wrap before returning ok:false", async () => {
    await unlockWithWrap();
    apiState.failAt = "credential"; // rotateCredential rejects (503)
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.stage).toBe("rekey");
    expect(vault.isUnlocked()).toBe(false);
    expect(await hasBiometricUnlock(USER)).toBe(false);
  });

  it("a relogin-stage failure locks the vault and drops the biometric wrap before returning ok:false", async () => {
    await unlockWithWrap();
    apiState.failAt = "relogin"; // login rejects (network unreachable)
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.stage).toBe("relogin");
    expect(vault.isUnlocked()).toBe(false);
    expect(await hasBiometricUnlock(USER)).toBe(false);
  });

  // Audit 2026-09-28 (MEDIUM): the key_scheme_conflict branch used to
  // return WITHOUT the lock + biometric-wrap drop, on the strength of a
  // comment claiming "NOTHING moved yet" — false: stage 3's
  // api.rekeyStoredData had already committed the rekey, so the vault's
  // OLD data key was dead for every stored blob exactly as in the generic
  // branch above. Same F-4 self-clean, same observable contract.
  it("a key_scheme_conflict credential failure also locks the vault and drops the wrap (audit 2026-09-28)", async () => {
    await unlockWithWrap();
    apiState.credentialConflict = true; // rotateCredential rejects (409 key_scheme_conflict)
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.stage).toBe("rekey");
      // Server-controlled error detail is never reflected through the
      // client-authored rotation outcome.
      expect(outcome.detail).toBeUndefined();
    }
    expect(vault.isUnlocked()).toBe(false);
    expect(await hasBiometricUnlock(USER)).toBe(false);
  });
});

// --- rotation × offline queue (independent audit 2026-09-27, P2) ---------------
//
// The v1 ladder's queue discipline, parity with the web fix: drain FIRST
// (abort honestly if anything cannot leave), rewrap whatever is still held
// locally AFTER the server rotation (rejected entries + racing writes), and
// never let a rewrap failure unwind a completed rotation.
describe("rotatePassword × offline queue (P2, 2026-09-27)", () => {
  beforeEach(() => unlockRotationOwner());
  const OLD_PASSWORD = "correct old password";
  const NEW_PASSWORD = "a strong new passphrase 42!";

  it("a queue that cannot drain ABORTS before any server-side step", async () => {
    const { enqueue, queueLength } = await import("../src/offlineQueue");
    const { encrypt } = await import("../src/crypto/envelope");
    const { buildAad } = await import("../src/crypto/aad");
    const oldKeys = await deriveKeysAsync(OLD_PASSWORD, Buffer.from(apiState.cachedSalt, "base64"));
    await enqueue({
      userId: USER,
      clientEntryId: "block-1",
      blobB64: encrypt(oldKeys.dataKey, Buffer.from("still pending"), buildAad("entry", USER, "block-1", "1")).toString("base64"),
      entryDate: "2026-09-27",
    });
    // 503 = retryable: the item stays queued no matter how often the drain
    // tries — exactly the "cannot leave right now" case.
    vi.mocked(api.createQueuedEntry).mockRejectedValue(new ApiError(503, "server busy"));
    // Earlier tests in this file accumulate on this spy (no global reset) —
    // clear it so the not-called assertion below is this test's alone.
    vi.mocked(api.rekeyStoredData).mockClear();

    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });

    expect(outcome).toEqual({ ok: false, stage: "verify", reason: "queue-blocked" });
    // NOTHING moved server-side — the ladder cannot even start (the rekey
    // is its first server step; credential only ever follows it).
    expect(api.rekeyStoredData).not.toHaveBeenCalled();
    // The item survives locally, still sealed under the still-current key.
    expect(await queueLength(USER)).toBe(1);
  });

  it("a queue that drains proceeds, and a REJECTED entry left behind is rewrapped old→new", async () => {
    const { enqueue, flushQueue, rejectedEntries } = await import("../src/offlineQueue");
    const { encrypt, decrypt } = await import("../src/crypto/envelope");
    const { buildAad } = await import("../src/crypto/aad");
    const oldKeys = await deriveKeysAsync(OLD_PASSWORD, Buffer.from(apiState.cachedSalt, "base64"));
    // Park one entry in the REJECTED store (a 400 upload rejection): the
    // drain only flushes the QUEUE, so this one must ride the rewrap.
    vi.mocked(api.createQueuedEntry).mockRejectedValueOnce(new ApiError(400, "invalid blob"));
    await enqueue({
      userId: USER,
      clientEntryId: "reject-1",
      blobB64: encrypt(oldKeys.dataKey, Buffer.from("rejected text"), buildAad("entry", USER, "reject-1", "1")).toString("base64"),
      entryDate: "2026-09-27",
    });
    await flushQueue(USER);
    expect(await rejectedEntries(USER)).toHaveLength(1);
    vi.mocked(api.cacheSalt).mockClear();

    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: OLD_PASSWORD,
      newPassword: NEW_PASSWORD,
    });

    expect(outcome.ok).toBe(true);
    // The rotation resealed the rejected blob under the NEW data key, same
    // AAD: it opens with the keys the next unlock will have.
    const newSaltB64 = (vi.mocked(api.cacheSalt).mock.calls.at(-1) as [string, string])[1];
    const newKeys = await deriveKeysAsync(NEW_PASSWORD, Buffer.from(newSaltB64, "base64"));
    const rejected = await rejectedEntries(USER);
    expect(rejected).toHaveLength(1);
    expect(
      decrypt(newKeys.dataKey, Buffer.from(rejected[0]!.blobB64, "base64"), buildAad("entry", USER, "reject-1", "1")).toString(),
    ).toBe("rejected text");
    expect(() =>
      decrypt(oldKeys.dataKey, Buffer.from(rejected[0]!.blobB64, "base64"), buildAad("entry", USER, "reject-1", "1")),
    ).toThrow();
  });
});
