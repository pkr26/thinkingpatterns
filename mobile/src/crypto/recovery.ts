/**
 * The recovery-key envelope (wave 3, 2026-09-30): the client-side half of
 * the opt-in recovery kit. A random 32-byte RECOVERY KEY (shown to the
 * user once, as base64) seals a copy of the account's data key:
 *
 *   recovery_kek = HKDF-SHA256(recovery_key, info="mindpattern/recovery/v1")
 *   sealed       = AES-256-GCM(recovery_kek, data_key,
 *                              aad="recovery/<user_id>/data-key")
 *
 * The server stores the sealed copy and the scrypt verifier of the
 * recovery key — it can open neither. Blob layout is the envelope
 * module's standard nonce||ciphertext||tag (60 bytes for a 32-byte key),
 * matching the backend's WRAPPED_DATA_KEY_BYTES contract.
 */
import { encrypt, decrypt } from "./envelope";
import { buildAad } from "./aad";
import { engine } from "./engine";

function hkdfSha256(ikm: Buffer, info: Buffer): Buffer {
  return Buffer.from(engine.hkdfSync("sha256", ikm, Buffer.alloc(32), info, 32) as ArrayBuffer);
}

const RECOVERY_INFO = "mindpattern/recovery/v1";

export const RECOVERY_KEY_SIZE = 32;

export function generateRecoveryKey(): Buffer {
  return Buffer.from(engine.randomBytes(RECOVERY_KEY_SIZE));
}

function recoveryKek(recoveryKey: Buffer): Buffer {
  return hkdfSha256(recoveryKey, Buffer.from(RECOVERY_INFO, "utf8"));
}

export function recoveryKeyToB64(recoveryKey: Buffer): string {
  return recoveryKey.toString("base64");
}

export function recoveryKeyFromB64(text: string): Buffer | null {
  const trimmed = text.trim().replace(/\s+/g, "");
  try {
    const raw = Buffer.from(trimmed, "base64");
    return raw.length === RECOVERY_KEY_SIZE ? raw : null;
  } catch {
    return null;
  }
}

export function sealDataKeyForRecovery(
  recoveryKey: Buffer,
  dataKey: Buffer,
  userId: string,
): Buffer {
  return encrypt(recoveryKek(recoveryKey), dataKey, buildAad("recovery", userId, "data-key"));
}

export function unsealDataKeyWithRecovery(
  recoveryKey: Buffer,
  sealed: Buffer,
  userId: string,
): Buffer | null {
  try {
    return decrypt(recoveryKek(recoveryKey), sealed, buildAad("recovery", userId, "data-key"));
  } catch {
    return null; // wrong key, wrong account, or a tampered blob
  }
}
