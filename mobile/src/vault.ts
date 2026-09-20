/**
 * Session-scoped key vault. Holds the unlocked keys in memory only —
 * never AsyncStorage, never disk. Zeroized on sign-out / account deletion.
 *
 * The vault is observable: the bearer token survives an app restart on
 * disk, but these keys do not, so navigation subscribes and shows the
 * unlock screen until the user re-derives them from their password.
 *
 * The vault also records WHICH account the keys belong to (ownerUserId).
 * Every operation that ships a key to the server (processing sessions)
 * must check that binding: without it, a session/vault desync would
 * deliver one account's data key into another account's session.
 */
import type { Keys } from "./crypto/MindPatternCrypto";
import { zeroize } from "./crypto/kdf";

type Listener = () => void;
const listeners = new Set<Listener>();

function notify(): void {
  for (const listener of listeners) listener();
}

/** What an unlocked session actually holds. The master key is NOT retained:
 *  unlock() zeroizes it immediately, and keeping the (zeroed) field on the
 *  stored state only invited a future caller to read dead bytes silently.
 *
 *  authKeyKnown (H-2) is false ONLY for a biometric unlock: that path
 *  restores the data key but stores PLACEHOLDER ZEROS in the authKey slot
 *  (the auth key exists to log in with the password and is never stored
 *  under biometrics). Nothing may compare a derived key against an unknown
 *  slot and report a verdict — reauth.ts verifies ONLINE in that case.
 *  Unknown never counts as a match anywhere: fail closed. */
export type SessionKeys = Pick<Keys, "authKey" | "dataKey"> & { authKeyKnown: boolean };

let current: SessionKeys | null = null;
let ownerUserId: string | null = null;

export const vault = {
  /** Unlock with the account these keys were derived for. The id is what
   *  lets key-shipping operations prove the keys match the session.
   *  opts.authKeyKnown defaults to true; UnlockScreen's biometric path is
   *  the one caller that passes false (placeholder-zero auth key). */
  unlock(keys: Keys, userId?: string, opts: { authKeyKnown?: boolean } = {}): void {
    if (current) zeroize(current.authKey, current.dataKey);
    zeroize(keys.masterKey); // only auth/data keys are useful from here on
    current = { authKey: keys.authKey, dataKey: keys.dataKey, authKeyKnown: opts.authKeyKnown ?? true };
    ownerUserId = userId ?? null;
    notify();
  },
  get(): SessionKeys {
    if (!current) throw new Error("vault is locked");
    // A fresh object per call: callers cannot mutate the vault's own
    // reference or swap its keys. The buffers are shared on purpose —
    // zeroize-on-lock must still reach every copy.
    return { authKey: current.authKey, dataKey: current.dataKey, authKeyKnown: current.authKeyKnown };
  },
  isUnlocked(): boolean {
    return current !== null;
  },
  /** The account id the unlocked keys belong to, or null if unknown
   *  (legacy callers) — key-shipping code must treat null as unverified. */
  ownerUserId(): string | null {
    return ownerUserId;
  },
  /** H-2: hand the REAL auth key to a session whose slot held placeholder
   *  zeros, after the typed password was verified ONLINE (the derived auth
   *  key IS the login verifier — see reauth.ts). The replaced placeholder
   *  is zeroized like every key hand-off, and later re-auths compare
   *  locally again. Throws when locked; keeps the session's owner and data
   *  key untouched. The buffer becomes vault-owned (zeroized on lock). */
  adoptAuthKey(authKey: Buffer): void {
    if (!current) throw new Error("vault is locked");
    zeroize(current.authKey); // placeholder zeros — no real material lost
    current = { authKey, dataKey: current.dataKey, authKeyKnown: true };
    notify();
  },
  lock(): void {
    if (current) zeroize(current.authKey, current.dataKey);
    current = null;
    ownerUserId = null;
    notify();
  },
  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
};
