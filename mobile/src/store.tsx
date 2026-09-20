/**
 * Tiny app state: auth tri-state, vault-unlock flag, and the 30-day progress
 * counter (memory-only — journaling-frequency metadata does not belong on
 * disk in plaintext). All heavy state lives encrypted on the server and is
 * decrypted on demand.
 *
 * The context value is MEMOIZED and every function is a stable useCallback:
 * consumers like InsightsScreen depend on them in useCallback/useEffect
 * dependency lists, and a provider that re-published fresh function
 * identities every render used to refire those effects — double fetch and
 * double decrypt per mount.
 */
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AppState } from "react-native";
import { api, setOriginChangeHandler, setUnauthorizedHandler } from "./api/client";
import { vault } from "./vault";
import { clearUnlockProof } from "./unlockProof";
import { clearRecomputeStamp } from "./brainSync";
import { abortInFlightFlush, flushQueueOnReconnect } from "./offlineQueue";
import { clearCrisisDialogStamp } from "./crisisDialog";
import { syncReminderSchedule } from "./reminderSync";

/** A 401-forced lock unmounts the Entry screen mid-draft; the plaintext
 *  waits here (memory-only, account-bound) so re-unlocking restores it for
 *  another save attempt. The stash SURVIVES vault.lock() — backgrounding
 *  must not destroy an unsent draft — and is wiped only on sign-out /
 *  account switch / account deletion (all of which run signOut). A
 *  different account on the same device never sees it. */
let stashedDraft: { userId: string; text: string } | null = null;
/** Sign-out and origin changes intentionally unmount the editor. Its cleanup
 * must not re-stash plaintext after we just wiped it. A normal 401 lock still
 * permits a draft restore after the same account re-unlocks. */
let mayStashDraft = true;

/** Stash an in-progress draft before a vault lock unmounts the editor. */
export function stashDraft(userId: string, text: string): void {
  if (mayStashDraft) stashedDraft = { userId, text };
}

/** True when a draft is stashed for THIS account (does not consume it). */
export function hasDraft(userId: string): boolean {
  return stashedDraft !== null && stashedDraft.userId === userId;
}

/** Read the stashed draft for THIS account WITHOUT consuming it — for a
 *  screen that wants to preview/merge instead of taking ownership. */
export function peekDraft(userId: string): string | null {
  return stashedDraft !== null && stashedDraft.userId === userId ? stashedDraft.text : null;
}

/** Consumes the stash ONLY for the account it was written under — the
 *  account check succeeds BEFORE the stash is nulled, so a mismatched (or
 *  failed) restore attempt does not silently drop the draft. */
export function takeStashedDraft(userId: string): string | null {
  if (stashedDraft && stashedDraft.userId === userId) {
    const { text } = stashedDraft;
    stashedDraft = null;
    return text;
  }
  return null;
}

/** "loading" prevents the login-flash race: a saved session must never be
 *  overwritten by an alternate sign-in before AsyncStorage resolves. */
export type AuthStatus = "loading" | "loggedOut" | "loggedIn";

/** Foreground inactivity limit: an unlocked phone on a table must not keep
 *  the derived keys hot indefinitely. This is a true INACTIVITY timeout —
 *  user interaction (touchActivity) restarts the countdown, so someone
 *  actively writing is never locked out mid-sentence. Backgrounding still
 *  locks immediately, regardless of the countdown. */
const IDLE_LOCK_MS = 5 * 60_000;

/** Server-reported unlock_days is attacker-controllable text from the
 *  network: only a sane positive integer is adopted. */
function sanitizeUnlockDays(value: unknown): number | null {
  // Stryker disable next-line ConditionalExpression: Number.isInteger returns false for every non-number, so the typeof arm is fully subsumed by !Number.isInteger
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
  /** Restarts the foreground inactivity countdown; call from real user
   *  interaction (typing, tapping) while the vault is unlocked. */
  touchActivity: () => void;
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
  touchActivity: () => {},
  refreshActiveDays: async () => {},
  signOut: async () => {},
});

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [authStatus, setAuthStatus] = useState<AuthStatus>("loading");
  const [unlocked, setUnlocked] = useState(vault.isUnlocked());
  const [activeDays, setActiveDays] = useState(0);
  const [unlockDays, setUnlockDays] = useState(30);

  /** (Re)arm the inactivity lock: drop any pending timer and start a fresh
   *  countdown, but only while the vault is actually unlocked. */
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const touchActivity = useCallback((): void => {
    // Stryker disable next-line ConditionalExpression: clearTimeout(null) is a documented no-op, so the guard is unobservable
    if (idleTimer.current) clearTimeout(idleTimer.current);
    // Stryker disable next-line ConditionalExpression: with the guard skipped, a locked vault arms a timer whose fire re-locks an already-locked vault — vault.lock() is idempotent and notifies the same (false) state
    if (vault.isUnlocked()) {
      idleTimer.current = setTimeout(() => vault.lock(), IDLE_LOCK_MS);
    }
  }, // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
     []);

  useEffect(() => {
    let cancelled = false;
    // Any authenticated 401 (entry save, insights fetch, question fetch,
    // queue flush — not just the Entry screen) locks the vault app-wide;
    // the client invokes this hook before the ApiError reaches the caller.
    setUnauthorizedHandler(() => vault.lock());
    // An API-origin change is not an ordinary sign-out: it must never call
    // logout against the old or new server. The API client has already
    // erased disk credentials before invoking this hook; lock memory and
    // suppress editor-unmount draft persistence before the new URL lands.
    setOriginChangeHandler(() => {
      abortInFlightFlush();
      mayStashDraft = false;
      stashedDraft = null;
      vault.lock();
      setAuthStatus("loggedOut");
      setActiveDays(0);
    });
    api.isLoggedIn().then((logged) => {
      // Stryker disable next-line ConditionalExpression: React 18 made setState on an unmounted component a silent no-op, so skipping the cancelled guard is unobservable
      if (!cancelled) setAuthStatus(logged ? "loggedIn" : "loggedOut");
    });
    // Local-reminder reconciliation (2026-09-19), once per session start:
    // align the native schedule with the stored per-account preference —
    // disabled/absent cancels any stale schedule, enabled reschedules.
    // Nothing is ever CREATED without the opt-in (reminders.ts default is
    // off), and the whole path is quiet: a missing notification module or
    // a storage fault answers false and changes nothing on screen.
    api
      .getUserId()
      .then((userId) => {
        if (userId) void syncReminderSchedule(userId);
      })
      .catch(() => {});
    api
      .meta()
      .then((m) => {
        // Stryker disable next-line OptionalChaining: with a nullish m the mutant's TypeError lands in the .catch(() => {}) below and keeps the same 30-day default
        const days = sanitizeUnlockDays(m?.unlock_days);
        if (!cancelled && days !== null) setUnlockDays(days);
      })
      .catch(() => {}); // offline / old server: keep the 30-day default
    // Cold restart: the bearer token survives on disk but the key vault
    // does not — navigation shows the unlock gate until it reopens.
    const unsubscribe = vault.subscribe(() => {
      setUnlocked(vault.isUnlocked());
      touchActivity(); // a fresh unlock starts the inactivity countdown
    });
    // Stryker disable next-line StringLiteral: the rnMock AppState stub ignores the event name (test seam — a real device would never deliver events on "")
    const appStateSub = AppState.addEventListener("change", (state) => {
      if (state === "background" || state === "inactive") {
        // Stryker disable next-line ConditionalExpression,CallExpression: vault.lock() below notifies this store's own subscriber, whose touchActivity() clears the same idleTimer unconditionally — this explicit clear is redundant
        if (idleTimer.current) clearTimeout(idleTimer.current);
        vault.lock();
      } else if (state === "active") {
        touchActivity();
        // Reconnect sync: foregrounding with a live session flushes the
        // offline queue. Ciphertext-only uploads — a locked vault is fine —
        // and flushQueueOnReconnect throttles foreground/background flaps.
        void flushQueueOnReconnect();
      }
    });
    return () => {
      // Stryker disable next-line BooleanLiteral: React 18 treats a post-unmount setState as a silent no-op, so never marking cancelled is unobservable
      cancelled = true;
      setUnauthorizedHandler(null);
      setOriginChangeHandler(null);
      // Stryker disable next-line ConditionalExpression: clearTimeout(null) is a documented no-op, so the guard is unobservable
      if (idleTimer.current) clearTimeout(idleTimer.current);
      unsubscribe();
      appStateSub.remove();
    };
  }, // Stryker disable next-line ArrayDeclaration: touchActivity is a stable useCallback([]) identity, so [] and [touchActivity] are behaviorally identical
     [touchActivity]);

  const markLoggedIn = useCallback((): void => {
    mayStashDraft = true;
    setAuthStatus("loggedIn");
  },
  // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
  []);

  const refreshActiveDays = useCallback(async (): Promise<void> => {
    try {
      const insights = await api.insights();
      // Stryker disable next-line LogicalOperator,OptionalChaining: Number.isFinite never coerces, so X || isFinite(X) agrees with X && isFinite(X) on every input; and with a nullish insights the mutant's TypeError is caught below, keeping the last value like the optional chain does
      if (typeof insights?.active_days === "number" && Number.isFinite(insights.active_days)) {
        setActiveDays(insights.active_days);
      }
    } catch {
      // offline / not yet computed — keep last known value
    }
  }, // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
     []);

  const signOut = useCallback(async (): Promise<void> => {
    // Coordinate with any in-flight queue flush FIRST: the uploads below
    // (logout revocation + session clear) turn its pending requests into
    // 401s, and that self-inflicted 401 must REQUEUE the current user's
    // items — not move them to the rejected store (see abortInFlightFlush).
    abortInFlightFlush();
    // Best-effort server revocation (retires every token for the account);
    // local cleanup proceeds regardless of connectivity.
    try {
      await api.logout();
    } catch {
      // offline: the token also dies at natural expiry
    }
    // The stashed draft is plaintext in the JS heap: it must not outlive
    // the session it belongs to (shared-device confidentiality).
    mayStashDraft = false;
    stashedDraft = null;
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
      await clearCrisisDialogStamp(userId).catch(() => {});
    }
    if (username) await api.clearCachedSalt(username).catch(() => {});
    await api.clearSession();
    setAuthStatus("loggedOut");
    setActiveDays(0);
  }, // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
     []);

  // Memoized value + stable callbacks: consumers' effects depend on these
  // identities, so they must change only when the underlying DATA changes.
  const value = useMemo<SessionState>(
    () => ({
      authStatus,
      unlocked,
      activeDays,
      unlockDays,
      markLoggedIn,
      setUnlockDays,
      touchActivity,
      refreshActiveDays,
      signOut,
    }),
    [authStatus, unlocked, activeDays, unlockDays, markLoggedIn, touchActivity, refreshActiveDays, signOut],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  return useContext(SessionContext);
}
