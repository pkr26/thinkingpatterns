/**
 * The recovery-key envelope (wave 3, 2026-09-30): the client-side half of
 * the opt-in recovery kit. A random 32-byte RECOVERY KEY (shown to the
 * user once, as base64) seals a copy of the account's data key:
 *
 *   v2 (2026-10-01 audit C1 — all NEW kits):
 *     verifier = HKDF-SHA256(recovery_key, info="mindpattern/recovery-verifier/v2")
 *              — the ONLY value the server ever sees (scrypt-hashed there);
 *                it opens nothing.
 *     seal_kek = HKDF-SHA256(recovery_key, info="mindpattern/recovery-seal/v2")
 *              — never leaves the device.
 *     sealed   = AES-256-GCM(seal_kek, data_key, aad="recovery/<user_id>/data-key")
 *
 *   v1 (legacy kits, kept verifiable until replaced): the RAW recovery key
 *   doubled as both the server verifier and the seal-KEK input under the
 *   single label "mindpattern/recovery/v1" — a server that observed the
 *   transmitted key could open the sealed data key (the 2026-10-01 audit's
 *   zero-knowledge break). unsealDataKeyWithRecoveryScheme still opens v1
 *   blobs so existing kits keep working; replacing a kit always writes v2.
 *
 * The server stores the sealed copy and the scrypt verifier — it can open
 * neither. Blob layout is the envelope module's standard
 * nonce||ciphertext||tag (60 bytes for a 32-byte key), matching the
 * backend's WRAPPED_DATA_KEY_BYTES contract.
 */
import { encrypt, decrypt } from "./envelope";
import { buildAad } from "./aad";
import { engine } from "./engine";

function hkdfSha256(ikm: Buffer, info: Buffer): Buffer {
  return Buffer.from(engine.hkdfSync("sha256", ikm, Buffer.alloc(32), info, 32) as ArrayBuffer);
}

const RECOVERY_INFO = "mindpattern/recovery/v1";
const RECOVERY_VERIFIER_INFO_V2 = "mindpattern/recovery-verifier/v2";
const RECOVERY_SEAL_INFO_V2 = "mindpattern/recovery-seal/v2";

export type RecoveryScheme = "v1" | "v2";

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

export function recoveryKitText(recoveryKey: Buffer): string {
  return `mindpattern-recovery:v2:${recoveryKeyToB64(recoveryKey)}`;
}

export function recoveryKeyFromB64(text: string): Buffer | null {
  const trimmed = text.trim().replace(/\s+/g, "").replace(/^mindpattern-recovery:v[12]:/, "");
  if (!/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) return null;
  try {
    const raw = Buffer.from(trimmed, "base64");
    if (raw.length === RECOVERY_KEY_SIZE && raw.toString("base64") === trimmed) return raw;
    raw.fill(0);
    return null;
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

/** v2 seal: the data key under the never-transmitted seal label. */
export function sealDataKeyForRecoveryV2(
  recoveryKey: Buffer,
  dataKey: Buffer,
  userId: string,
): Buffer {
  const kek = hkdfSha256(recoveryKey, Buffer.from(RECOVERY_SEAL_INFO_V2, "utf8"));
  try {
    return encrypt(kek, dataKey, buildAad("recovery", userId, "data-key"));
  } finally {
    kek.fill(0);
  }
}

/** v2 verifier: the ONLY value derived from the recovery key that is ever
 *  sent to the server (it is scrypt-hashed there and can open nothing). */
export function recoveryVerifierKeyV2(recoveryKey: Buffer): Buffer {
  return hkdfSha256(recoveryKey, Buffer.from(RECOVERY_VERIFIER_INFO_V2, "utf8"));
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

/** Open a sealed data-key copy under the scheme the server reported. */
export function unsealDataKeyWithRecoveryScheme(
  recoveryKey: Buffer,
  sealed: Buffer,
  userId: string,
  scheme: RecoveryScheme,
): Buffer | null {
  if (scheme === "v2") {
    const kek = hkdfSha256(recoveryKey, Buffer.from(RECOVERY_SEAL_INFO_V2, "utf8"));
    try {
      return decrypt(kek, sealed, buildAad("recovery", userId, "data-key"));
    } catch {
      return null;
    } finally {
      kek.fill(0);
    }
  }
  return unsealDataKeyWithRecovery(recoveryKey, sealed, userId);
}
