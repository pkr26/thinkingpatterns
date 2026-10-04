/** Fresh-password verification and action-bound step-up for web. */
import { api, auth, sessionUsername, type StepUpAction } from "./api/client";
import { deriveMasterKey, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { validateKdfParams } from "./crypto/envelope";
import { derivePatientKeys } from "./crypto/keys";
import { vault } from "./vault";

export const LOCAL_MISMATCH_DELAY_MS = 500;

function keysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index]! ^ b[index]!;
  return difference === 0;
}

export type ReauthResult =
  | { ok: true; verifier: string }
  | { ok: false; reason: "locked" | "no-account" | "wrong-password" | "offline" };

export async function verifyPasswordForVault(password: string): Promise<ReauthResult> {
  if (!password) return { ok: false, reason: "wrong-password" };
  const username = sessionUsername();
  const owner = vault.ownerUserId();
  if (!vault.isUnlocked() || !owner) return { ok: false, reason: "locked" };
  if (!username) return { ok: false, reason: "no-account" };
  const original = vault.get();
  const current = (): boolean => {
    if (!vault.isUnlocked() || vault.ownerUserId() !== owner || sessionUsername() !== username) return false;
    const now = vault.get();
    return now.authKey === original.authKey && now.dataKey === original.dataKey;
  };

  let salt: Bytes | null = null;
  let derived: Awaited<ReturnType<typeof derivePatientKeys>> | null = null;
  try {
    let saltResponse: { salt: string };
    let envelope: Awaited<ReturnType<typeof api.keyEnvelope>>;
    try {
      [saltResponse, envelope] = await Promise.all([auth.saltFor(username), api.keyEnvelope()]);
    } catch {
      return { ok: false, reason: current() ? "offline" : "locked" };
    }
    if (!current()) return { ok: false, reason: "locked" };
    salt = fromBase64(saltResponse.salt);
    let iterations: number | undefined;
    if (envelope.key_scheme === "v2") {
      if (envelope.kdf_params == null) return { ok: false, reason: "offline" };
      try {
        iterations = validateKdfParams(envelope.kdf_params).iterations;
      } catch {
        return { ok: false, reason: "offline" };
      }
    }
    derived = await derivePatientKeys(await deriveMasterKey(password, salt, iterations));
    if (!current()) return { ok: false, reason: "locked" };
    if (!keysEqual(derived.authKey, original.authKey)) {
      await new Promise((resolve) => setTimeout(resolve, LOCAL_MISMATCH_DELAY_MS));
      return { ok: false, reason: current() ? "wrong-password" : "locked" };
    }
    return { ok: true, verifier: toBase64(derived.authKey) };
  } catch {
    return { ok: false, reason: current() ? "offline" : "locked" };
  } finally {
    zeroize(salt, derived?.masterKey, derived?.authKey, derived?.dataKey);
  }
}

export type FreshStepUpResult =
  | { ok: true; proof: string }
  | { ok: false; reason: "locked" | "no-account" | "wrong-password" | "offline" };

export async function freshStepUp(password: string, action: StepUpAction): Promise<FreshStepUpResult> {
  const verified = await verifyPasswordForVault(password);
  if (!verified.ok) return verified;
  const result = await api.stepUp(verified.verifier, action);
  return { ok: true, proof: result.proof };
}
