/**
 * Offline unlock proof (C1 fix).
 *
 * The old offline-unlock path derived keys from the password and a cached
 * salt and unlocked the vault with NO verification — any string "unlocked"
 * the app offline, and a mistyped password then encrypted new entries
 * under a wrong data key (permanently undecryptable).
 *
 * At every ONLINE login we seal a fixed marker under the data key. Offline
 * unlock now proves the password: derive, try to open the seal, and only
 * unlock on success. A wrong password fails the AEAD authentication.
 *
 * Threat-model note: this makes the device itself an offline oracle for
 * password GUESSES — that trade-off is inherent to any local unlock and
 * is bounded by PBKDF2(600k) per guess plus a deliberate delay on
 * failure. The seal reveals nothing about the key beyond guess correctness.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";

const proofKey = (userId: string): string => `@mindpattern/unlockproof_${userId}`;
const PROOF_PLAINTEXT = Buffer.from("mindpattern-unlock-proof/v1", "utf8");

/** Call exactly once after a VERIFIED online login (or registration):
 *  seals the marker under the account's data key. */
export async function storeUnlockProof(dataKey: Buffer, userId: string): Promise<void> {
  const blob = encrypt(dataKey, PROOF_PLAINTEXT, buildAad("unlockproof", userId));
  await AsyncStorage.setItem(proofKey(userId), blob.toString("base64"));
}

export type ProofResult = "ok" | "wrong" | "absent";

/** Prove a derived data key offline. */
export async function verifyUnlockProof(dataKey: Buffer, userId: string): Promise<ProofResult> {
  const raw = await AsyncStorage.getItem(proofKey(userId));
  if (!raw) return "absent";
  try {
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("unlockproof", userId));
    return plain.equals(PROOF_PLAINTEXT) ? "ok" : "wrong";
  } catch {
    return "wrong";
  }
}

export async function clearUnlockProof(userId: string): Promise<void> {
  await AsyncStorage.removeItem(proofKey(userId));
}

export async function unlockProofExists(userId: string): Promise<boolean> {
  return (await AsyncStorage.getItem(proofKey(userId))) !== null;
}
