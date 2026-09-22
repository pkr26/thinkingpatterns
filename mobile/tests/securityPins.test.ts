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
  failAt: null as null | "rekey" | "credential" | "relogin" | "verify",
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
    getBaseUrl: async () => apiState.baseUrl,
    api: {
      getCachedSalt: async () => apiState.cachedSalt,
      saltFor: async () => ({ salt: apiState.cachedSalt }),
      cacheSalt: async () => {},
      openProcessingSession: async (key: string) => ({ session_token: `tok-${key.slice(0, 6)}` }),
      rekeyStoredData: vi.fn(async () => {
        if (apiState.failAt === "rekey") {
          throw new ApiError(400, "old key did not authenticate every blob", "rekey_key_mismatch");
        }
        return apiState.rekeyResult;
      }),
      listConsents: async () => apiState.consents,
      rewrapConsent: vi.fn(async () => ({})),
      rotateCredential: async () => {
        if (apiState.failAt === "credential") throw new ApiError(503, "server busy");
        return {};
      },
      login: async () => {
        if (apiState.failAt === "relogin") throw new ApiError(0, "network unreachable");
        return { token: "fresh", user_id: "abababababababababababababababab" };
      },
      setSession: async () => {},
      listEntriesPage: vi.fn(async () => ({ entries: [], nextOffset: null, revision: null })),
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

import { checkAnalysisGeneration, FRESHNESS_ERROR, forgetAnalysisGeneration } from "../src/stateSeqGuard";
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
import { decryptEntry, encryptEntry } from "../src/crypto/MindPatternCrypto";
import { rotatePassword } from "../src/rotation";
import { vault } from "../src/vault";
import { enableBiometricUnlock, hasBiometricUnlock } from "../src/biometricUnlock";
import * as Keychain from "react-native-keychain";

const keychainMock = Keychain as unknown as { __reset: () => void };

const DATA_KEY = Buffer.alloc(32, 9);
const USER = "0123456789abcdef0123456789abcdef";

beforeEach(() => {
  store.clear();
  apiState.failAt = null;
  apiState.consents = [];
  keychainMock.__reset();
  vault.lock();
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
    // survives a process restart too.
    expect(store.get("mindpattern.stateSeq.m1b")).toBe("9");
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
    expect(rewrap).toHaveBeenCalledTimes(1);
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

  it("continues an interrupted rotation when the blobs are already under the new key", async () => {
    // First attempt: rekey succeeded, credential rotation failed.
    apiState.failAt = "credential";
    const first = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(first.ok).toBe(false);
    // Retry: rekey now answers rekey_key_mismatch; the flow verifies the new
    // key reads the journal (empty here → trivially true) and finishes.
    apiState.failAt = null;
    vi.mocked(api.rekeyStoredData).mockRejectedValueOnce(
      new ApiError(400, "old key did not authenticate", "rekey_key_mismatch") as never,
    );
    const second = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(second.ok).toBe(true);
  });

  it("fails honestly when the retry's new password cannot read an already-rotated journal", async () => {
    vi.mocked(api.rekeyStoredData).mockRejectedValueOnce(
      new ApiError(400, "old key did not authenticate", "rekey_key_mismatch") as never,
    );
    // listEntriesPage returns rows whose blob only the FIRST new password
    // could read — the retry uses a different new password.
    const foreignBlob = encryptEntry({ dataKey: Buffer.alloc(32, 1) }, USER, "e-9", "x", "2026-09-20", null, undefined, 1).blobB64;
    vi.mocked(api.listEntriesPage).mockResolvedValueOnce({
      entries: [{ id: "i", client_entry_id: "e-9", blob: foreignBlob, entry_date: "2026-09-20", received_at: "r", content_version: 1 }],
      nextOffset: null,
      revision: null,
    } as never);
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a DIFFERENT strong passphrase!",
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe("already-rotated-unverifiable");
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
    vault.unlock({
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.alloc(32, 2),
      dataKey: Buffer.alloc(32, 3),
    });
    // A wrap sealed under the OLD data key — exactly the stale-key hazard.
    await enableBiometricUnlock(USER, Buffer.alloc(32, 7));
    expect(vault.isUnlocked()).toBe(true);
    expect(await hasBiometricUnlock(USER)).toBe(true);
  }

  it("a credential-stage failure locks the vault and drops the biometric wrap before returning ok:false", async () => {
    await unlockWithWrap();
    apiState.failAt = "credential"; // rotateCredential rejects (503)
    const outcome = await rotatePassword({
      username: "alice",
      userId: USER,
      oldPassword: "correct old password",
      newPassword: "a strong new passphrase 42!",
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.stage).toBe("credential");
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
});
