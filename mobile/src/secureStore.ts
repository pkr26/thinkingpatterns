/**
 * Encrypted-at-rest session storage (H3 fix).
 *
 * AsyncStorage is an unencrypted plist/SQLite file on both platforms: a
 * forensic tool, an ADB/iTunes backup, or a malicious sideloaded app used
 * to read the bearer token verbatim. This wrapper AES-256-GCM-encrypts
 * every stored value under a random per-install key, so a backup contains
 * only ciphertext and the token can no longer be lifted by grepping.
 *
 * HONEST limitations, stated plainly:
 *  - The per-install device key lives in AsyncStorage too, and device
 *    backups therefore include BOTH the key and the ciphertext it
 *    protects. A fully-controlled device attacker recovers the session.
 *  - The complete fix is Keychain/Keystore custody of the device key
 *    (kSecAttrAccessible...ThisDeviceOnly / StrongBox) via
 *    react-native-keychain — pending native integration. The
 *    AsyncStorage device-key backend below is explicitly a FALLBACK.
 *
 * The seam: all encryption, envelope and key-caching logic lives in this
 * module; raw persistence (device key custody + value storage) sits
 * behind SecureStoreBackend. Swapping in react-native-keychain later
 * changes ONLY the backend — callers keep using `secureStore` unchanged.
 *
 * Storage schema: values are a versioned envelope { v: 1, c: <base64
 * ciphertext> }; legacy bare-base64 ciphertext migrates transparently on
 * read (read-through, the moodLog idiom). Corrupt payloads read as absent.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { decrypt, encrypt } from "./crypto/envelope";
import { engine } from "./crypto/engine";

/** Raw persistence behind the encrypted facade. A future
 *  react-native-keychain backend re-implements readDeviceKey/
 *  writeDeviceKey with hardware-backed custody; value storage may stay. */
export interface SecureStoreBackend {
  /** The per-install device key, base64 — null when never generated. */
  readDeviceKey(): Promise<string | null>;
  writeDeviceKey(keyB64: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

const DEVICE_KEY_STORAGE = "@mindpattern/device_k";

/** The fallback backend: everything in AsyncStorage, device key included.
 *  See the header — backups currently include key and ciphertext. */
const asyncStorageBackend: SecureStoreBackend = {
  readDeviceKey: () => AsyncStorage.getItem(DEVICE_KEY_STORAGE),
  writeDeviceKey: (keyB64) => AsyncStorage.setItem(DEVICE_KEY_STORAGE, keyB64),
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
};

let backend: SecureStoreBackend = asyncStorageBackend;

/** Backend swap seam (tests, and the future keychain integration). Passing
 *  null restores the AsyncStorage fallback. The key cache is dropped so a
 *  backend with different key custody never serves a stale device key. */
export function setSecureStoreBackend(next: SecureStoreBackend | null): void {
  backend = next ?? asyncStorageBackend;
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
  const raw = await backend.readDeviceKey();
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
