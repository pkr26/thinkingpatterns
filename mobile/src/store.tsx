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
import { eraseDeletedAccountLocals, retryPendingAccountErasures } from "./accountErasure";
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AppState } from "react-native";
import { api, setOriginChangeHandler, setUnauthorizedHandler } from "./api/client";
import { commitActiveAccountWrite, localWriteScopeEpoch } from "./localWriteGuard";
import { vault } from "./vault";
import { clearUnlockProof } from "./unlockProof";
import { clearRecomputeStamp } from "./brainSync";
import { abortInFlightFlush, flushQueueOnReconnect } from "./offlineQueue";
import { abortInFlightAudioFlush, flushAudioQueue } from "./audioQueue";
import { clearCrisisDialogStamp } from "./crisisDialog";
import { syncReminderSchedule, syncMeasureReminderSchedule } from "./reminderSync";
import { clearLastMeasureDate, clearMeasureReminderPrefs } from "./measureReminders";
import { disableBiometricUnlock } from "./biometricUnlock";
import { cancelDailyReminder, cancelMeasureReminder } from "./nativeFeatures";
import { loadHapticsSetting } from "./haptics";
import type { JournalDraft } from "./journalDraft";
import { scrubAllVoiceScratchFiles } from "./audio/voiceScratch";

/** A 401-forced lock unmounts the Entry screen mid-draft; the plaintext
 *  waits here (memory-only, account-bound) so re-unlocking restores it for
 *  another save attempt. The stash SURVIVES vault.lock() — backgrounding
 *  must not destroy an unsent draft — and is wiped only on sign-out /
 *  account switch / account deletion (all of which run signOut). A
 *  different account on the same device never sees it. */
let stashedDraft: { userId: string; text: string; journal?: JournalDraft; origin?: string } | null = null;
/** Sign-out and origin changes intentionally unmount the editor. Its cleanup
 * must not re-stash plaintext after we just wiped it. A normal 401 lock still
 * permits a draft restore after the same account re-unlocks. */
let mayStashDraft = true;

/** Stash an in-progress draft before a vault lock unmounts the editor. */
export function stashDraft(userId: string, text: string, journal?: JournalDraft, origin?: string): void {
  if (mayStashDraft) stashedDraft = { userId, text, journal: journal ? { ...journal, tags: [...journal.tags] } : undefined, origin };
}
/** Complete in-process editor fallback; Question's text-only bridge keeps
 * its existing semantics. Never import a fallback from another server. */
export function peekStashedJournalDraft(userId: string, origin: string): JournalDraft | null {
  const record = stashedDraft;
  return record?.userId === userId && record.origin === origin && record.journal
    ? { ...record.journal, tags: [...record.journal.tags] } : null;
}
export function clearStashedJournalDraft(userId: string, origin: string, editorId: string, revision: number): void {
  const draft = peekStashedJournalDraft(userId, origin);
  if (draft && draft.editorId === editorId && draft.revision <= revision) stashedDraft = null;
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
export function takeStashedDraft(userId: string, origin?: string): string | null {
  if (stashedDraft && stashedDraft.userId === userId && (origin === undefined || stashedDraft.origin === undefined || stashedDraft.origin === origin)) {
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

export interface ProgressRead { owner: string; generation: number; request: number }
interface SessionState {
  authStatus: AuthStatus;
  /** True only while the key vault holds this session's derived keys. */
  unlocked: boolean;
  activeDays: number;
  /** Zero is meaningful only after a valid authoritative server response. */
  activeDaysKnown: boolean;
  activeDaysLoading: boolean;
  unlockDays: number;
  erasureIncomplete: boolean;
  markLoggedIn: () => void;
  setUnlockDays: (days: number) => void;
  /** Restarts the foreground inactivity countdown; call from real user
   *  interaction (typing, tapping) while the vault is unlocked. */
  touchActivity: () => void;
  refreshActiveDays: () => Promise<void>;
  /** Applies a server-known active-days count WITHOUT a second /insights
   *  round-trip: the Insights screen already holds that response, and
   *  issuing a second GET per load doubled latency and rate budget
   *  (audit L-59). Server value, sanitized like refreshActiveDays does. */
  beginProgressRead: () => Promise<ProgressRead | null>;
  finishProgressRead: (read: ProgressRead) => void;
  applyActiveDays: (days: unknown, read: ProgressRead) => void;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionState>({
  authStatus: "loading",
  unlocked: false,
  activeDays: 0,
  activeDaysKnown: false,
  activeDaysLoading: false,
  unlockDays: 30,
  erasureIncomplete: false,
  markLoggedIn: () => {},
  setUnlockDays: () => {},
  touchActivity: () => {},
  refreshActiveDays: async () => {},
  applyActiveDays: () => {},
  beginProgressRead: async () => null,
  finishProgressRead: () => {},
  signOut: async () => {},
});

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [authStatus, setAuthStatus] = useState<AuthStatus>("loading");
  const [unlocked, setUnlocked] = useState(vault.isUnlocked());
  const lastProgressResume = useRef({ auth: "loading" as AuthStatus, unlocked: false });
  const [activeDays, setActiveDays] = useState(0);
  const [activeDaysKnown, setActiveDaysKnown] = useState(false);
  const [activeDaysLoading, setActiveDaysLoading] = useState(false);
  const progressOwner = useRef<string | null>(null);
  const accountGeneration = useRef(0);
  const progressRequest = useRef(0);
  const [unlockDays, setUnlockDays] = useState(30);
  const [erasureIncomplete, setErasureIncomplete] = useState(false);

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
    const bootGeneration = accountGeneration.current;
    const ownsBootGeneration = () => !cancelled && bootGeneration === accountGeneration.current;
    // Any authenticated 401 (entry save, insights fetch, question fetch,
    // queue flush — not just the Entry screen) locks the vault app-wide;
    // the client invokes this hook before the ApiError reaches the caller.
    setUnauthorizedHandler((death) => {
      vault.lock();
      if (!death.accountDeleted) return;
      accountGeneration.current++;
      abortInFlightFlush(); abortInFlightAudioFlush();
      mayStashDraft = false; stashedDraft = null;
      setAuthStatus("loggedOut");
      setActiveDays(0); progressOwner.current = null;
      setActiveDaysKnown(false); setActiveDaysLoading(false);
      if (death.userId) {
        void eraseDeletedAccountLocals(death.userId, death.username, { origin: death.origin })
          .then(failures => setErasureIncomplete(failures.length > 0))
          .catch(() => setErasureIncomplete(true));
      } else {
        void api.clearSession().catch(() => {});
      }
    });
    // An API-origin change is not an ordinary sign-out: it must never call
    // logout against the old or new server. The API client has already
    // erased disk credentials before invoking this hook; lock memory and
    // suppress editor-unmount draft persistence before the new URL lands.
    setOriginChangeHandler(() => {
      accountGeneration.current++;
      abortInFlightFlush();
      // 2026-10-01 audit H1: an in-flight AUDIO flush must stop too — its
      // rows are origin-pinned and would otherwise refuse item-by-item.
      abortInFlightAudioFlush();
      mayStashDraft = false;
      stashedDraft = null;
      vault.lock();
      setAuthStatus("loggedOut");
      setActiveDays(0);
      progressOwner.current = null; setActiveDaysKnown(false); setActiveDaysLoading(false);
    });
    // Audit fix 19 (2026-09-21): the haptics preference loads at session
    // start, not on the first Settings visit — the module defaults to
    // enabled, so a stored "off" (the sensory-anxiety setting) pulsed after
    // every cold start until Settings happened to be opened.
    void loadHapticsSetting();
    // Pending authoritative erasure owns the boot barrier. Credential
    // hydration, unlock navigation, reminders, and authenticated metadata
    // cannot observe the retained tuple until retry has first retired it.
    void (async () => {
      try { await scrubAllVoiceScratchFiles(); }
      catch {
        if (ownsBootGeneration()) {
          setErasureIncomplete(true);
          setAuthStatus("loggedOut");
        }
        return;
      }
      let remaining: number;
      try { remaining = await retryPendingAccountErasures(); }
      catch {
        if (ownsBootGeneration()) {
          setErasureIncomplete(true);
          setAuthStatus("loggedOut");
        }
        return;
      }
      if (!ownsBootGeneration()) return;
      setErasureIncomplete(remaining > 0);
      if (remaining > 0) {
        setAuthStatus("loggedOut");
        return;
      }
      const logged = await api.isLoggedIn().catch(() => false);
      // isLoggedIn restores the process-local owner after a cold restart;
      // fence all following hydration work to that newly established scope.
      const hydrationScope = localWriteScopeEpoch();
      if (!ownsBootGeneration() || hydrationScope !== localWriteScopeEpoch()) return;
      setAuthStatus(logged ? "loggedIn" : "loggedOut");

      // Local-reminder reconciliation (2026-09-19), once per clean boot:
      // nothing is created without its persisted opt-in.
      api.getUserId().then((userId) => {
        if (!ownsBootGeneration() || hydrationScope !== localWriteScopeEpoch()) return;
        if (userId) void syncReminderSchedule(userId);
        if (userId) void syncMeasureReminderSchedule(userId);
      }).catch(() => {});
      api.meta().then((m) => {
        const days = sanitizeUnlockDays(m?.unlock_days);
        if (ownsBootGeneration() && hydrationScope === localWriteScopeEpoch() && days !== null) setUnlockDays(days);
      }).catch(() => {}); // offline / old server: keep the 30-day default
    })();
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
        // offline queue (and, since wave 2 2026-09-30, the kept-recording
        // queue). Ciphertext-only uploads — a locked vault is fine — and
        // flushQueueOnReconnect throttles foreground/background flaps.
        void flushQueueOnReconnect().then(() => flushAudioQueue()).catch(() => {});
        // E-10 (2026-09-21): an always-open app used to keep a stale
        // activeDays count across midnight (it refreshed only at
        // login/unlock and on insights loads). Foregrounding re-reads the
        // server's count; the call fails closed to the last value offline.
        void refreshActiveDays();
      }
    });
    return () => {
      accountGeneration.current++;
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
    accountGeneration.current++;
    mayStashDraft = true;
    setAuthStatus("loggedIn");
    setErasureIncomplete(false);
  },
  // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
  []);

  const refreshActiveDays = useCallback(async (): Promise<void> => {
    const generation = accountGeneration.current;
    const request = ++progressRequest.current;
    setActiveDaysLoading(true);
    try {
      const owner = await api.getUserId();
      if (generation !== accountGeneration.current || request !== progressRequest.current) return;
      if (!owner) { progressOwner.current = null; setActiveDays(0); setActiveDaysKnown(false); return; }
      if (progressOwner.current !== null && progressOwner.current !== owner) {
        setActiveDays(0); setActiveDaysKnown(false);
      }
      progressOwner.current = owner;
      const insights = await api.insights();
      const currentOwner = await api.getUserId();
      if (generation !== accountGeneration.current || request !== progressRequest.current || currentOwner !== owner) return;
      // Stryker disable next-line LogicalOperator,OptionalChaining: Number.isFinite never coerces, so X || isFinite(X) agrees with X && isFinite(X) on every input; and with a nullish insights the mutant's TypeError is caught below, keeping the last value like the optional chain does
      if (typeof insights?.active_days === "number" && Number.isFinite(insights.active_days) && insights.active_days >= 0) {
        setActiveDays(Math.min(3650, Math.floor(insights.active_days)));
        setActiveDaysKnown(true);
      }
    } catch {
      // offline / not yet computed — keep last known value
    } finally {
      if (generation === accountGeneration.current && request === progressRequest.current) setActiveDaysLoading(false);
    }
  }, // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
     []);

  // A saved bearer may boot directly to Unlock. The provider owns progress
  // hydration, so a gate unmount or a missed foreground event cannot leave
  // a manufactured zero after a verified unlock. No data key is sent here.
  useEffect(() => {
    const previous = lastProgressResume.current;
    lastProgressResume.current = { auth: authStatus, unlocked };
    if (authStatus === "loggedIn" && (previous.auth !== "loggedIn" || (unlocked && !previous.unlocked))) void refreshActiveDays();
  }, [authStatus, unlocked, refreshActiveDays]);

  /** Capture ownership and ordering before a screen fetches metadata. */
  const beginProgressRead = useCallback(async (): Promise<ProgressRead | null> => {
    const generation = accountGeneration.current, request = ++progressRequest.current;
    setActiveDaysLoading(true);
    let read: ProgressRead | null = null;
    try {
      const owner = await api.getUserId();
      if (generation !== accountGeneration.current || request !== progressRequest.current) return null;
      if (!owner) { progressOwner.current = null; setActiveDays(0); setActiveDaysKnown(false); return null; }
      if (progressOwner.current !== null && progressOwner.current !== owner) { setActiveDays(0); setActiveDaysKnown(false); }
      progressOwner.current = owner;
      read = { owner, generation, request }; return read;
    } catch { return null; }
    finally { if (!read && generation === accountGeneration.current && request === progressRequest.current) setActiveDaysLoading(false); }
  }, []);
  const finishProgressRead = useCallback((read: ProgressRead): void => {
    if (read.generation === accountGeneration.current && read.request === progressRequest.current && read.owner === progressOwner.current) setActiveDaysLoading(false);
  }, []);
  /** Adopt only the response belonging to the captured account/request.
   * Server-controlled values still receive the same type/range refusal. */
  const applyActiveDays = useCallback((days: unknown, read: ProgressRead): void => {
    if (!read || read.generation !== accountGeneration.current || read.request !== progressRequest.current || read.owner !== progressOwner.current) return;
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) return;
    progressRequest.current++;
    setActiveDays(Math.min(3650, Math.floor(days)));
    setActiveDaysKnown(true); setActiveDaysLoading(false);
  }, // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
     []);

  const signOut = useCallback(async (): Promise<void> => {
    const generation = ++accountGeneration.current;
    const scope = localWriteScopeEpoch();
    const knownOwner = vault.ownerUserId();
    const isCurrent = () => generation === accountGeneration.current && scope === localWriteScopeEpoch();
    progressOwner.current = null; setActiveDaysKnown(false); setActiveDaysLoading(false); setActiveDays(0);
    // Plaintext is removed immediately, before a possibly offline logout.
    // An old editor's unmount may not re-stash it into the closed session.
    mayStashDraft = false;
    stashedDraft = null;
    abortInFlightFlush();
    abortInFlightAudioFlush();
    vault.lock();
    setAuthStatus("loggedOut");
    // Snapshot the original credential identity before network revocation.
    // A replacement login/origin invalidates this entire continuation.
    const [resolvedOwner, username] = await Promise.all([api.getUserId().catch(() => null), api.getUsername().catch(() => null)]);
    if (!isCurrent()) return;
    const userId = resolvedOwner ?? knownOwner;
    try { await api.logout(); } catch { /* offline: the old token expires naturally */ }
    if (!isCurrent()) return;
    // Retain unsynced ciphertext. Only the original account's local proof,
    // preference and device reminder traces are sign-out cleanup targets.
    const clean = async (operation: () => Promise<unknown>): Promise<boolean> => {
      if (!isCurrent()) return false;
      await operation().catch(() => {});
      return isCurrent();
    };
    if (userId) {
      const cleanOwned = (operation: () => Promise<unknown>) => clean(() => commitActiveAccountWrite(userId, operation));
      if (!(await cleanOwned(() => clearRecomputeStamp(userId)))) return;
      if (!(await cleanOwned(() => clearUnlockProof(userId)))) return;
      if (!(await cleanOwned(() => clearCrisisDialogStamp(userId)))) return;
      if (!(await cleanOwned(() => clearLastMeasureDate(userId)))) return;
      if (!(await cleanOwned(() => clearMeasureReminderPrefs(userId)))) return;
      if (!(await cleanOwned(() => disableBiometricUnlock(userId)))) return;
    }
    if (!(await clean(cancelDailyReminder))) return;
    if (!(await clean(cancelMeasureReminder))) return;
    if (username) {
      if (!(await clean(() => api.clearCachedKeyEnvelope(username)))) return;
      if (!(await clean(() => api.clearCachedSalt(username)))) return;
    }
    if (!isCurrent()) return;
    // clearSession itself serializes credential mutation and rejects if a
    // newer account/origin takes ownership while its native writes await.
    await api.clearSession();
  }, // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
     []);

  // Memoized value + stable callbacks: consumers' effects depend on these
  // identities, so they must change only when the underlying DATA changes.
  const value = useMemo<SessionState>(
    () => ({
      authStatus,
      unlocked,
      activeDays,
      activeDaysKnown,
      activeDaysLoading,
      unlockDays,
      erasureIncomplete,
      markLoggedIn,
      setUnlockDays,
      touchActivity,
      refreshActiveDays,
      applyActiveDays,
      beginProgressRead,
      finishProgressRead,
      signOut,
    }),
    [authStatus, unlocked, activeDays, activeDaysKnown, activeDaysLoading, unlockDays, erasureIncomplete, markLoggedIn, touchActivity, refreshActiveDays, applyActiveDays, beginProgressRead, finishProgressRead, signOut],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  return useContext(SessionContext);
}
