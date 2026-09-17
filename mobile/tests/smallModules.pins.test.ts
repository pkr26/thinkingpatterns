/**
 * Deep-mutation pins for the small modules (2026-09-15 Stryker campaign):
 *  - secureStore: an envelope whose `c` is a byte ARRAY reads as absent (the
 *    typeof-string guard is real), and a v1-path failure falls into the
 *    legacy path — pinned by an envelope whose JSON text itself base64-
 *    decodes to a valid forgery-free blob (only the emptied catch would
 *    return it),
 *  - unlockProof: the sealed marker plaintext is exactly
 *    "mindpattern-unlock-proof/v1", and unlockProofExists is really false
 *    when nothing is stored,
 *  - entryId: the + and / base64url mappings with stubbed engine bytes,
 *  - onboarding: a fresh module starts with NO pending onboarding, and the
 *    persisted seen sentinel is exactly "1",
 *  - genericQuestions: the exact per-date pick (djb2 ×33),
 *  - kdf: the async derivation accepts an exactly-8-byte salt,
 *  - envelope: a supplied nonce of the wrong length fails loudly.
 *
 * Equivalents are suppressed at the source (secureStore's deviceKey cache
 * fast path, the utf8 encoding literal; entryId's unreachable padding
 * strip; genericQuestions' loop bound — see those files).
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

const { encrypt, encryptWithFixedNonce, decrypt, buildAad } = await import("../src/crypto/envelope");
const { deriveMasterKeyAsync, MIN_ITERATIONS } = await import("../src/crypto/kdf");

beforeEach(() => {
  storage.__reset();
});

/** A fresh secureStore module graph backed by a KNOWN device key. */
async function freshSecureStore(key: Buffer) {
  vi.resetModules();
  const freshStorage = (await import("@react-native-async-storage/async-storage")).default as typeof storage;
  await freshStorage.setItem("@mindpattern/device_k", key.toString("base64"));
  const mod = await import("../src/secureStore");
  return { freshStorage, secureStore: mod.secureStore };
}

describe("secureStore pins", () => {
  it("an envelope whose c is a byte ARRAY reads as absent, not as decryptable", async () => {
    const key = Buffer.alloc(32, 9);
    const { freshStorage, secureStore } = await freshSecureStore(key);
    // A perfectly valid ciphertext — planted under c as JSON numbers.
    const blob = encrypt(key, Buffer.from("array-envelope-secret"));
    await freshStorage.setItem("k", JSON.stringify({ v: 1, c: Array.from(blob) }));
    // typeof c !== "string" must hold the line: the mutant would feed the
    // array through Buffer.from(numbers) and return the plaintext.
    expect(await secureStore.getItem("k")).toBeNull();
  });

  it("an emptied v1 catch falls through to the legacy path — pinned with a self-decoding envelope", async () => {
    // Construct an envelope string whose base64-valid characters ("v1c" +
    // c) decode to a REAL ciphertext: nonce chosen so the first three
    // base64 chars of the blob are exactly "v1c".
    const key = Buffer.alloc(32, 9);
    const { freshStorage, secureStore } = await freshSecureStore(key);
    const nonce = Buffer.from([0xbf, 0x57, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const blob = encryptWithFixedNonce(key, Buffer.from("forged-legacy-secret"), undefined, nonce);
    const s = blob.toString("base64");
    expect(s.startsWith("v1c")).toBe(true); // the construction holds
    const c = s.slice(3);
    const raw = `{"v":1,"c":"${c}"}`;
    // Precondition 1: c on its own must fail decryption (so the v1 path
    // throws and the catch decides the outcome).
    expect(() => decrypt(key, Buffer.from(c, "base64"))).toThrow();
    // Precondition 2: the envelope's own filtered characters decode to the
    // valid blob — exactly what the legacy path would feed to decrypt if
    // the catch were emptied.
    expect(decrypt(key, Buffer.from(raw.replace(/[^A-Za-z0-9+/=]/g, ""), "base64")).toString("utf8")).toBe(
      "forged-legacy-secret",
    );
    await freshStorage.setItem("k", raw);
    // The intact catch returns null; the emptied-catch mutant falls through
    // to the legacy path and returns the forged-looking plaintext.
    expect(await secureStore.getItem("k")).toBeNull();
  });
});

describe("unlockProof pins", () => {
  // The secureStore tests above call vi.resetModules(), so every later test
  // must import the storage helper and the module under test from the SAME
  // fresh module graph (the top-level `storage` binding points at the old,
  // orphaned instance).
  it("the sealed marker is exactly 'mindpattern-unlock-proof/v1'", async () => {
    const s = (await import("./helpers/storageMock")).default;
    const { storeUnlockProof } = await import("../src/unlockProof");
    const dataKey = Buffer.alloc(32, 7);
    await storeUnlockProof(dataKey, "u9");
    const raw = await s.getItem("@mindpattern/unlockproof_u9");
    expect(raw).not.toBeNull();
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("unlockproof", "u9"));
    expect(plain.toString("utf8")).toBe("mindpattern-unlock-proof/v1");
  });

  it("unlockProofExists is genuinely false when nothing is stored (and after clear)", async () => {
    const s = (await import("./helpers/storageMock")).default;
    await s.__reset();
    const { storeUnlockProof, clearUnlockProof, unlockProofExists } = await import("../src/unlockProof");
    expect(await unlockProofExists("u-none")).toBe(false);
    const dataKey = Buffer.alloc(32, 7);
    await storeUnlockProof(dataKey, "u1");
    expect(await unlockProofExists("u1")).toBe(true);
    await clearUnlockProof("u1");
    expect(await unlockProofExists("u1")).toBe(false);
  });
});

describe("entryId pins", () => {
  it("maps + and / to - and _ exactly (stubbed engine bytes)", async () => {
    const { engine } = await import("../src/crypto/engine");
    const { newClientEntryId } = await import("../src/entryId");
    // base64 of [0xfb,0,0, 0xff,0,0, 0,0,0] is "+wAA/wAAAAAA" — one of each
    // special character, and no padding (9 bytes is a multiple of 3).
    const original = engine.randomBytes;
    try {
      engine.randomBytes = (() => Buffer.from([0xfb, 0, 0, 0xff, 0, 0, 0, 0, 0])) as typeof engine.randomBytes;
      expect(newClientEntryId("2026-01-31")).toBe("e-2026-01-31--wAA_wAAAAAA");
    } finally {
      engine.randomBytes = original;
    }
  });
});

describe("onboarding pins", () => {
  it("a fresh module starts with NO pending onboarding", async () => {
    vi.resetModules();
    const fresh = await import("../src/onboarding");
    expect(fresh.takePendingOnboarding()).toBe(false);
    fresh.queueOnboarding();
    expect(fresh.takePendingOnboarding()).toBe(true);
    expect(fresh.takePendingOnboarding()).toBe(false);
  });

  it("recordOnboardingSeen persists exactly the '1' sentinel", async () => {
    const s = (await import("./helpers/storageMock")).default;
    const { recordOnboardingSeen } = await import("../src/onboarding");
    await recordOnboardingSeen("user-1");
    expect(await s.getItem("@mindpattern/onboarding_seen_user-1")).toBe("1");
  });
});

describe("genericQuestions pins", () => {
  it("the djb2×33 rotation picks the exact pool slot per date", async () => {
    const { genericQuestionForDate } = await import("../src/genericQuestions");
    // 2026-09-17: the pool grew 8 -> 60, so the same djb2 rotation lands
    // on new slots — recomputed against the shipped pool (the parity test
    // pins the pool itself array-for-array).
    expect(genericQuestionForDate("2026-09-07")).toBe("What did you get through today that felt heavy?");
    expect(genericQuestionForDate("2026-09-08")).toBe("What conversation stayed with you today?");
    expect(genericQuestionForDate("2026-10-01")).toBe("When did you feel understood today?");
  });
});

describe("kdf and envelope pins", () => {
  it("deriveMasterKeyAsync accepts an exactly-8-byte salt (both floors inclusive)", async () => {
    const master = await deriveMasterKeyAsync("pw", Buffer.alloc(8, 1), MIN_ITERATIONS);
    expect(master).toHaveLength(32);
    expect(master.equals(await deriveMasterKeyAsync("pw", Buffer.alloc(8, 1), MIN_ITERATIONS))).toBe(true);
  });

  it("a supplied nonce of the wrong length fails with the exact message", () => {
    const key = Buffer.alloc(32, 1);
    // 2026-09-16: the seam moved out of encrypt() — the production
    // signature takes exactly (key, plaintext, aad) and randomizes the
    // nonce; only encryptWithFixedNonce accepts one (red-team finding A5).
    expect(encrypt.length).toBe(3);
    expect(encryptWithFixedNonce.length).toBe(4);
    expect(() => encryptWithFixedNonce(key, Buffer.from("x"), undefined, Buffer.alloc(11))).toThrow(/nonce must be 12 bytes/);
    expect(() => encryptWithFixedNonce(key, Buffer.from("x"), undefined, Buffer.alloc(13))).toThrow(/nonce must be 12 bytes/);
  });
});
