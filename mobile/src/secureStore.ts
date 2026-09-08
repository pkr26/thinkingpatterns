/**
 * Encrypted-at-rest session storage (H3 fix).
 *
 * AsyncStorage is an unencrypted plist/SQLite file on both platforms: a
 * forensic tool, an ADB/iTunes backup, or a malicious sideloaded app used
 * to read the bearer token verbatim. This wrapper AES-256-GCM-encrypts
 * every stored value under a random per-install key, so a backup contains
 * only ciphertext and the token can no longer be lifted by grepping.
 *
 * HONEST limitation: the per-install key lives in AsyncStorage too, so a
 * fully-controlled device attacker can still recover the session. The
 * complete fix is Keychain (kSecAttrAccessible / StrongBox) via
 * react-native-keychain — this seam exists so that swap is one module.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { decrypt, encrypt } from "./crypto/envelope";
import { engine } from "./crypto/engine";

const DEVICE_KEY_STORAGE = "@mindpattern/device_k";
let cachedKey: Buffer | null = null;
/** Single-flight initialization: concurrent first callers share ONE
 *  in-flight promise. Without it, two first calls both read null, generate
 *  DIFFERENT keys and both write — the module cache then holds one key
 *  while storage holds the other, and half the stored ciphertext is
 *  undecryptable after a restart. */
let keyPromise: Promise<Buffer> | null = null;

async function loadDeviceKey(): Promise<Buffer> {
  const raw = await AsyncStorage.getItem(DEVICE_KEY_STORAGE);
  const stored = raw ? Buffer.from(raw, "base64") : null;
  // A stored key must be exactly 32 bytes; anything else is corrupt, so
  // treat it as absent and re-derive — otherwise every setItem throws and
  // every getItem silently reads null forever.
  if (stored && stored.length === 32) {
    cachedKey = stored;
  } else {
    const key = Buffer.from(engine.randomBytes(32));
    await AsyncStorage.setItem(DEVICE_KEY_STORAGE, key.toString("base64"));
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

export const secureStore = {
  async setItem(key: string, value: string): Promise<void> {
    const blob = encrypt(await deviceKey(), Buffer.from(value, "utf8"));
    await AsyncStorage.setItem(key, blob.toString("base64"));
  },
  /** null when absent; undefined-vault-safe: corrupt ciphertext reads as
   *  absent (a wiped/tampered store must not brick the session). */
  async getItem(key: string): Promise<string | null> {
    const raw = await AsyncStorage.getItem(key);
    if (!raw) return null;
    try {
      return decrypt(await deviceKey(), Buffer.from(raw, "base64")).toString("utf8");
    } catch {
      return null;
    }
  },
  async removeItem(key: string): Promise<void> {
    await AsyncStorage.removeItem(key);
  },
};
