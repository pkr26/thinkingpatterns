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

async function deviceKey(): Promise<Buffer> {
  if (cachedKey) return cachedKey;
  const raw = await AsyncStorage.getItem(DEVICE_KEY_STORAGE);
  if (raw) {
    cachedKey = Buffer.from(raw, "base64");
  } else {
    cachedKey = Buffer.from(engine.randomBytes(32));
    await AsyncStorage.setItem(DEVICE_KEY_STORAGE, cachedKey.toString("base64"));
  }
  return cachedKey;
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
