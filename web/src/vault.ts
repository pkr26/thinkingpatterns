/**
 * Session-scoped key vault (ported from mobile's vault.ts). Holds the
 * unlocked keys in memory only — never localStorage/sessionStorage/
 * IndexedDB, never disk (WEB_PLAN D-4). Zeroized on lock/sign-out.
 *
 * The vault is observable: React subscribes and re-renders on lock/unlock,
 * so navigation can never race key state.
 *
 * The vault also records WHICH account the keys belong to (ownerUserId).
 * Every operation that ships a key to the server (processing sessions)
 * must check that binding: without it, a session/vault desync would
 * deliver one account's data key into another account's session.
 */
import { zeroize, type Bytes } from "./crypto/core";

type Listener = () => void;
const listeners = new Set<Listener>();

function notify(): void {
  for (const listener of listeners) listener();
}

/** What an unlocked session actually holds. The master key is NOT
 *  retained: unlock() zeroizes it immediately — only the auth/data keys
 *  are useful from here on (the auth key is the login verifier, needed
 *  again for re-authenticated actions). */
export interface SessionKeys {
  authKey: Bytes;
  dataKey: Bytes;
}

let current: SessionKeys | null = null;
let ownerUserId: string | null = null;

export const vault = {
  /** Unlock with the account these keys were derived for. The id is what
   *  lets key-shipping operations prove the keys match the session; it is
   *  also zeroized masterKey's last stop — nothing retains it. */
  unlock(keys: { authKey: Bytes; dataKey: Bytes; masterKey?: Bytes }, userId?: string): void {
    if (current) zeroize(current.authKey, current.dataKey);
    if (keys.masterKey) zeroize(keys.masterKey);
    current = { authKey: keys.authKey, dataKey: keys.dataKey };
    ownerUserId = userId ?? null;
    notify();
  },
  get(): SessionKeys {
    if (!current) throw new Error("vault is locked");
    // A fresh object per call: callers cannot mutate the vault's own
    // reference or swap its keys. The buffers are shared on purpose —
    // zeroize-on-lock must still reach every copy.
    return { authKey: current.authKey, dataKey: current.dataKey };
  },
  isUnlocked(): boolean {
    return current !== null;
  },
  /** The account id the unlocked keys belong to, or null — key-shipping
   *  code must treat null as unverified. */
  ownerUserId(): string | null {
    return ownerUserId;
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
