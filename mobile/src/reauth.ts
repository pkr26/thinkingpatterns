/**
 * Password re-authentication for destructive actions (H2 fix).
 *
 * "Confirm with your sign-in key" used to read the authKey straight from
 * the unlocked vault — two taps on an unattended, foregrounded phone could
 * delete the journal. These helpers re-derive the auth key from a password
 * the user types RIGHT NOW and compare it to the vault's key in constant
 * time; the caller only gets the verifier when the password is correct.
 */
import { api, ApiError } from "./api/client";
import { deriveKeysAsync } from "./crypto/MindPatternCrypto";
import { zeroize } from "./crypto/kdf";
import { vault } from "./vault";

/** Constant-time equality for equal-length secret buffers. */
function keysEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export type ReauthResult =
  | { ok: true; verifierB64: string }
  | { ok: false; reason: "locked" | "no-account" | "wrong-password" | "offline" };

/**
 * Verify `password` against the vault's unlocked auth key. Returns the
 * base64 auth key (the server "verifier") only on a match; every derived
 * buffer is zeroized either way.
 */
export async function verifyPasswordForVault(password: string): Promise<ReauthResult> {
  if (!password) return { ok: false, reason: "wrong-password" };
  if (!vault.isUnlocked()) return { ok: false, reason: "locked" };
  const username = await api.getUsername();
  if (!username) return { ok: false, reason: "no-account" };

  let saltB64: string | null = await api.getCachedSalt(username);
  if (!saltB64) {
    try {
      const { salt } = await api.saltFor(username);
      saltB64 = salt;
      await api.cacheSalt(username, salt);
    } catch {
      return { ok: false, reason: "offline" };
    }
  }
  if (!saltB64) return { ok: false, reason: "offline" };

  // Async derivation: the sync path freezes the JS thread ~100-400ms.
  const derived = await deriveKeysAsync(password, Buffer.from(saltB64, "base64"));
  const matches = keysEqual(derived.authKey, vault.get().authKey);
  if (!matches) {
    zeroize(derived.masterKey, derived.authKey, derived.dataKey);
    return { ok: false, reason: "wrong-password" };
  }
  const verifierB64 = derived.authKey.toString("base64");
  zeroize(derived.masterKey, derived.dataKey);
  return { ok: true, verifierB64 };
}

/**
 * Why did a verifier-checked call (account deletion, LLM consent) fail?
 *
 * 403 verification_failed = the verifier itself was rejected: the typed
 * password no longer matches the account's current credentials (or the
 * local derivation drifted). This is NOT a session death — the vault can
 * stay unlocked and the user may retry with another password.
 *
 * 401 = the session itself is dead; the client's unauthorized hook has
 * already locked the vault by the time the caller sees the error, so the
 * only path forward is re-unlock. (A failed LOGIN's 401 carries no token
 * and never trips that hook — see setUnauthorizedHandler.)
 *
 * The v1 error code is authoritative; a legacy server without the envelope
 * maps 403-on-a-verified-endpoint to the same meaning (detail-text
 * fallback).
 */
export function isVerificationFailedError(err: unknown): boolean {
  if (!(err instanceof ApiError) || err.status !== 403) return false;
  return err.code === undefined || err.code === "verification_failed";
}

export function isSessionExpiredError(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401;
}
