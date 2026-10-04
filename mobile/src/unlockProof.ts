/**
 * Authenticated marker for offline password verification.
 * An online login seals a fixed marker under the account data key. Offline
 * unlock must decrypt that marker successfully before opening the vault.
 *
 * The marker permits offline password guesses, as any local password unlock
 * does. PBKDF2 cost protects each guess; unlockBackoff adds a persistent delay
 * to failed attempts through the app.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";
import { accountStorageKey } from "./accountStorage";
import { captureLocalWritePermit, commitLocalWrite } from "./localWriteGuard";

const proofKey = accountStorageKey.unlockProof;
const PROOF_PLAINTEXT = Buffer.from("mindpattern-unlock-proof/v1", "utf8");

/** Call exactly once after a VERIFIED online login (or registration):
 *  seals the marker under the account's data key. */
export async function storeUnlockProof(dataKey: Buffer, userId: string): Promise<void> {
  const permit = captureLocalWritePermit(userId, dataKey);
  const blob = encrypt(dataKey, PROOF_PLAINTEXT, buildAad("unlockproof", userId));
  await commitLocalWrite(permit, () => AsyncStorage.setItem(proofKey(userId), blob.toString("base64")));
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
