/**
 * Encrypted-at-rest session storage (H3 fix).
 *
 * AsyncStorage is an unencrypted plist/SQLite file on both platforms: a
 * forensic tool, an ADB/iTunes backup, or a malicious sideloaded app used
 * to read the bearer token verbatim. This wrapper AES-256-GCM-encrypts
 * every stored value under a random per-install key. That key is held in
 * iOS Keychain / Android Keystore through react-native-keychain, with an
 * "this device only" iOS accessibility class. A backup therefore contains
 * ciphertext but not the key needed to open it.
 *
 * There is intentionally NO runtime AsyncStorage fallback for the device
 * key. If native Keychain/Keystore is not linked or unavailable, sign-in
 * fails closed instead of creating a recoverable session secret in a file.
 * Tests can inject a backend with setSecureStoreBackend; production code
 * never selects an insecure backend.
 *
 * Storage schema: values are a versioned envelope { v: 1, c: <base64
 * ciphertext> }; legacy bare-base64 ciphertext migrates transparently on
 * read (read-through, the moodLog idiom). Corrupt payloads read as absent.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as Keychain from "react-native-keychain";
import { decrypt, encrypt } from "./crypto/envelope";
import { engine } from "./crypto/engine";

/** Raw persistence behind the encrypted facade. Value ciphertext can stay
 * in AsyncStorage; the device key itself must be hardware/OS-keystore held. */
export interface SecureStoreBackend {
  /** The per-install device key, base64 — null when never generated. */
  readDeviceKey(): Promise<string | null>;
  writeDeviceKey(keyB64: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

/** Old clients used this AsyncStorage key. It is read once only to migrate a
 * valid key into Keychain, then removed. New releases never write it. */
const LEGACY_DEVICE_KEY_STORAGE = "@mindpattern/device_k";
const KEYCHAIN_SERVICE = "com.mindpattern.session-device-key.v1";
const KEYCHAIN_USERNAME = "mindpattern-device-key";

/** Keychain / Keystore-backed custody. `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`
 * prevents iOS migration/backups from carrying the data key to another
 * device, and (audit fix 9, 2026-09-21) demands a passcode like the
 * biometric wrap does — on a passcode-less device the bearer token was
 * protected only by the OS sandbox. Android's implementation uses the
 * Android Keystore. We do not demand hardware-only security level: many
 * legitimate Android devices lack StrongBox, while Keystore-backed
 * software storage is still materially safer than a plaintext app
 * database. */
const keychainBackend: SecureStoreBackend = {
  async readDeviceKey(): Promise<string | null> {
    const credentials = await Keychain.getGenericPassword({ service: KEYCHAIN_SERVICE });
    if (!credentials) return null;
    if (credentials.username !== KEYCHAIN_USERNAME) return null;
    return credentials.password;
  },
  async writeDeviceKey(keyB64: string): Promise<void> {
    const result = await Keychain.setGenericPassword(KEYCHAIN_USERNAME, keyB64, {
      service: KEYCHAIN_SERVICE,
      accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
    });
    if (!result) throw new Error("device secure storage rejected the session key");
  },
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
};

let backend: SecureStoreBackend = keychainBackend;

/** Backend swap seam for tests. Passing null restores the production
 * Keychain/Keystore backend — never an insecure file-backed key. The key
 * cache is dropped so a backend with different custody never serves a stale
 * device key. */
export function setSecureStoreBackend(next: SecureStoreBackend | null): void {
  backend = next ?? keychainBackend;
  cachedKey = null;
  keyPromise = null;
}

let cachedKey: Buffer | null = null;
/** Single-flight initialization: concurrent first callers share ONE
 *  in-flight promise. Without it, two first calls both read null, generate
 *  DIFFERENT keys and both write — the module cache then holds one key
 *  while storage holds the other, and half the stored ciphertext is
 *  undecryptable after a restart. */
let keyPromise: Promise<Buffer> | null = null;

async function loadDeviceKey(): Promise<Buffer> {
  let raw = await backend.readDeviceKey();
  // One-way migration from versions that stored the device key beside the
  // ciphertext. Do not remove the legacy bytes until Keychain durably takes
  // them; a Keychain failure then fails closed without destroying an active
  // user's still-recoverable session.
  if (raw === null && backend === keychainBackend) {
    const legacy = await AsyncStorage.getItem(LEGACY_DEVICE_KEY_STORAGE);
    const legacyKey = legacy ? Buffer.from(legacy, "base64") : null;
    if (legacy && legacyKey?.length === 32) {
      await backend.writeDeviceKey(legacy);
      await AsyncStorage.removeItem(LEGACY_DEVICE_KEY_STORAGE);
      raw = legacy;
    } else if (legacy) {
      // It cannot decrypt a valid envelope, so retaining even malformed
      // key-like bytes in a plaintext store only creates a future leak.
      await AsyncStorage.removeItem(LEGACY_DEVICE_KEY_STORAGE);
    }
  }
  const stored = raw ? Buffer.from(raw, "base64") : null;
  // A stored key must be exactly 32 bytes; anything else is corrupt, so
  // treat it as absent and re-derive — otherwise every setItem throws and
  // every getItem silently reads null forever.
  if (stored && stored.length === 32) {
    cachedKey = stored;
  } else {
    const key = Buffer.from(engine.randomBytes(32));
    await backend.writeDeviceKey(key.toString("base64"));
    // Cache only AFTER the key is durably persisted: caching before the
    // write would leave a never-stored key behind on failure (e.g. disk
    // full), and that session's ciphertext would be undecryptable after a
    // restart — silent data loss.
    cachedKey = key;
  }
  return cachedKey;
}

function deviceKey(): Promise<Buffer> {
  // Stryker disable next-line ConditionalExpression: cachedKey is only ever set inside loadDeviceKey, which always leaves keyPromise non-null resolving to the same Buffer — the fast path is indistinguishable from returning keyPromise
  if (cachedKey) return Promise.resolve(cachedKey);
  // A failed initialization must not poison later callers: drop the promise
  // so the next call retries fresh.
  keyPromise ??= loadDeviceKey().catch((err: unknown) => {
    keyPromise = null;
    throw err;
  });
  return keyPromise;
}

async function setEncrypted(key: string, value: string): Promise<void> {
  // Stryker disable next-line StringLiteral: an empty encoding string falls back to Buffer's default utf8 decoding (verified byte-identical for every input)
  const blob = encrypt(await deviceKey(), Buffer.from(value, "utf8"));
  await backend.setItem(key, JSON.stringify({ v: 1, c: blob.toString("base64") }));
}

export const secureStore = {
  setItem: setEncrypted,
  /** null when absent; undefined-vault-safe: corrupt ciphertext reads as
   *  absent (a wiped/tampered store must not brick the session). */
  async getItem(key: string): Promise<string | null> {
    const raw = await backend.getItem(key);
    if (!raw) return null;
    if (raw.startsWith("{")) {
      // The v1 envelope. base64 never contains "{", so a leading brace is
      // an unambiguous format marker — anything else inside (wrong version,
      // corrupt ciphertext) reads as absent.
      try {
        const parsed = JSON.parse(raw) as { v?: unknown; c?: unknown };
        if (parsed.v !== 1 || typeof parsed.c !== "string") return null;
        return decrypt(await deviceKey(), Buffer.from(parsed.c, "base64")).toString("utf8");
      } catch {
        return null;
      }
    }
    // Legacy bare-base64 ciphertext — read-through migration to the v1
    // envelope (same idiom as the mood log). A failed rewrite never fails
    // the read; the legacy copy is only dropped once the new write lands.
    try {
      const value = decrypt(await deviceKey(), Buffer.from(raw, "base64")).toString("utf8");
      await setEncrypted(key, value).catch(() => {});
      return value;
    } catch {
      return null;
    }
  },
  async removeItem(key: string): Promise<void> {
    await backend.removeItem(key);
  },
};
