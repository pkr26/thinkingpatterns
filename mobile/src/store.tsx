/**
 * Tiny app state: auth tri-state, vault-unlock flag, and the 30-day progress
 * counter (memory-only — journaling-frequency metadata does not belong on
 * disk in plaintext). All heavy state lives encrypted on the server and is
 * decrypted on demand.
 */
import React, { createContext, useContext, useEffect, useState } from "react";
import { AppState } from "react-native";
import { api } from "./api/client";
import { vault } from "./vault";
import { clearUnlockProof } from "./unlockProof";
import { clearRecomputeStamp } from "./brainSync";

/** "loading" prevents the login-flash race: a saved session must never be
 *  overwritten by an alternate sign-in before AsyncStorage resolves. */
export type AuthStatus = "loading" | "loggedOut" | "loggedIn";

/** Foreground inactivity limit: an unlocked phone on a table must not keep
 *  the derived keys hot indefinitely (auto-lock previously fired only on
 *  background/inactive transitions). */
const IDLE_LOCK_MS = 5 * 60_000;

/** Server-reported unlock_days is attacker-controllable text from the
 *  network: only a sane positive integer is adopted. */
function sanitizeUnlockDays(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isInteger(value)) return null;
  if (value < 1 || value > 365) return null;
  return value;
}

interface SessionState {
  authStatus: AuthStatus;
  /** True only while the key vault holds this session's derived keys. */
  unlocked: boolean;
  activeDays: number;
  unlockDays: number;
  markLoggedIn: () => void;
  setUnlockDays: (days: number) => void;
  refreshActiveDays: () => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionState>({
  authStatus: "loading",
  unlocked: false,
  activeDays: 0,
  unlockDays: 30,
  markLoggedIn: () => {},
  setUnlockDays: () => {},
  refreshActiveDays: async () => {},
  signOut: async () => {},
});

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [authStatus, setAuthStatus] = useState<AuthStatus>("loading");
  const [unlocked, setUnlocked] = useState(vault.isUnlocked());
  const [activeDays, setActiveDays] = useState(0);
  const [unlockDays, setUnlockDays] = useState(30);

  useEffect(() => {
    let cancelled = false;
    api.isLoggedIn().then((logged) => {
      if (!cancelled) setAuthStatus(logged ? "loggedIn" : "loggedOut");
    });
    api
      .meta()
      .then((m) => {
        const days = sanitizeUnlockDays(m?.unlock_days);
        if (!cancelled && days !== null) setUnlockDays(days);
      })
      .catch(() => {}); // offline / old server: keep the 30-day default
    // Cold restart: the bearer token survives on disk but the key vault
    // does not — navigation shows the unlock gate until it reopens.
    let idleTimer: ReturnType<typeof setTimeout> | null = null;
    const armIdleLock = (): void => {
      if (idleTimer) clearTimeout(idleTimer);
      if (vault.isUnlocked()) {
        idleTimer = setTimeout(() => vault.lock(), IDLE_LOCK_MS);
      }
    };
    const unsubscribe = vault.subscribe(() => {
      setUnlocked(vault.isUnlocked());
      armIdleLock(); // a fresh unlock restarts the idle countdown
    });
    const appStateSub = AppState.addEventListener("change", (state) => {
      if (state === "background" || state === "inactive") {
        if (idleTimer) clearTimeout(idleTimer);
        vault.lock();
      } else if (state === "active") {
        armIdleLock();
      }
    });
    return () => {
      cancelled = true;
      if (idleTimer) clearTimeout(idleTimer);
      unsubscribe();
      appStateSub.remove();
    };
  }, []);

  const refreshActiveDays = async () => {
    try {
      const insights = await api.insights();
      if (typeof insights?.active_days === "number" && Number.isFinite(insights.active_days)) {
        setActiveDays(insights.active_days);
      }
    } catch {
      // offline / not yet computed — keep last known value
    }
  };

  const signOut = async () => {
    // Best-effort server revocation (retires every token for the account);
    // local cleanup proceeds regardless of connectivity.
    try {
      await api.logout();
    } catch {
      // offline: the token also dies at natural expiry
    }
    vault.lock();
    // Local account hygiene (shared-device confidentiality): the cached
    // KDF salt, the offline-unlock proof and the recompute stamp are what
    // let a LATER user of this device interact with the previous account's
    // credentials — they are wiped here. The offline queue is deliberately
    // KEPT: its entries are ciphertext, account-bound by mechanism
    // (flushQueue skips foreign userIds), and wiping them would destroy
    // the signed-out user's unsynced entries. Only full account deletion
    // (SettingsScreen) clears the queue.
    const userId = await api.getUserId();
    const username = await api.getUsername();
    if (userId) {
      await clearRecomputeStamp(userId).catch(() => {});
      await clearUnlockProof(userId).catch(() => {});
    }
    if (username) await api.clearCachedSalt(username).catch(() => {});
    await api.clearSession();
    setAuthStatus("loggedOut");
    setActiveDays(0);
  };

  return (
    <SessionContext.Provider
      value={{
        authStatus,
        unlocked,
        activeDays,
        unlockDays,
        markLoggedIn: () => setAuthStatus("loggedIn"),
        setUnlockDays,
        refreshActiveDays,
        signOut,
      }}
    >
      {children}
    </SessionContext.Provider>
  );
}

export function useSession(): SessionState {
  return useContext(SessionContext);
}
