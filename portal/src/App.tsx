/**
 * App shell: a four-state machine — login → key unlock → patients → one
 * patient. All key material lives in React state (memory only): closing
 * the tab forgets everything; there is nothing sensitive in storage
 * beyond per-patient visit-date stamps (see PatientView — since 2026-09-20
 * those live in per-tab sessionStorage, or in lock-scrubbed localStorage
 * where sessionStorage is unavailable).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { clearSession, api, hasSession, setUnauthorizedHandler, type Patient } from "./api";
import { unlockWrapPrivateKeyWithNotesKey, openNotesKeyring, wipeNotesKeyring, type NotesKeyring } from "./crypto";
import { LoginView, type PortalKeys } from "./views/LoginView";
import { PatientsView, resetScanConfirmation } from "./views/PatientsView";
import { PatientView, type PortalSession } from "./views/PatientView";
import { InfoBanner } from "./ui";
import { ViewBoundary } from "./ErrorBoundary";
import { localStore, sessionStore, visitAnchorStore } from "./platform";
import { readPatientRoute, writePatientRoute } from "./browserRoute";

type View =
  | { kind: "login"; error?: string }
  | { kind: "patients" }
  | { kind: "patient"; patient: Patient };

/** Idle auto-lock (2026-09-17): 10 minutes without interaction drops
 *  every key from memory — a chart left open on a shared clinic laptop
 *  shows decrypted journal text exactly until the clinician walks away. */
const IDLE_LOCK_MS = 10 * 60 * 1000;

/** Best-effort overwrite for extractable raw key bytes. CryptoKey instances
 * are deliberately non-extractable; dropping their last reference is the
 * browser-supported way to clear those. The wrap KEK is zeroed the moment
 * the private key is unwrapped (see onLoginReady) — AND here too, because
 * the 2026-09-19 audit showed the FAILED-unlock path (me() error or
 * TamperError) used to return with the password-derived KEK still live:
 * onLoginReady swallows its own error, so LoginView's finally-block
 * wipeKeys never ran. Every holder that reaches this function leaves
 * zeroed. */
function wipePortalSession(
  value: { noteKey?: Uint8Array; noteKeyV2?: Uint8Array; historicalNoteKeys?: Uint8Array[]; wrapKek?: Uint8Array } | null,
): void {
  if (!value) return;
  value.wrapKek?.fill(0);
  value.noteKey?.fill(0);
  value.noteKeyV2?.fill(0);
  for (const key of value.historicalNoteKeys ?? []) key.fill(0);
}

export function App(): React.JSX.Element {
  const [view, setView] = useState<View>({ kind: "login" });
  const [session, setSessionState] = useState<PortalSession | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const sessionRef = useRef<PortalSession | null>(null);
  const lifecycle = useRef(0);
  const loginAttempt = useRef(0);
  useEffect(() => {
    if (!session) return;
    let generation = 0;
    let alive = true;
    const followHistory = async (): Promise<void> => {
      const request = ++generation;
      const patientId = readPatientRoute();
      if (!patientId) { setView({ kind: "patients" }); return; }
      // Resolve only against this authenticated clinician's accessible list.
      // A URL alone never grants chart access or creates a patient object.
      try {
        const patients = await api.patients();
        if (!alive || request !== generation) return;
        const patient = patients.find(row => row.user_id === patientId);
        if (patient) setView({ kind: "patient", patient });
        else { setNotice("That patient is not available to this account."); setView({ kind: "patients" }); }
      } catch (error) {
        if (!alive || request !== generation) return;
        setNotice(error instanceof Error ? error.message : "The patient could not be opened. Retry when connected.");
        setView({ kind: "patients" });
      }
    };
    const onHistory = (): void => { void followHistory(); };
    window.addEventListener("popstate", onHistory);
    window.addEventListener("hashchange", onHistory);
    if (readPatientRoute()) onHistory();
    return () => { alive = false; generation += 1; window.removeEventListener("popstate", onHistory); window.removeEventListener("hashchange", onHistory); };
  }, [session]);

  const replacePortalSession = useCallback((next: PortalSession | null): void => {
    const previous = sessionRef.current;
    if (previous && previous !== next) wipePortalSession(previous);
    sessionRef.current = next;
    setSessionState(next);
  }, []);

  const lockDown = useCallback((message: string, opts?: { clearAnchors?: boolean }) => {
    lifecycle.current += 1;
    loginAttempt.current += 1;
    const retiring = sessionRef.current;
    // Visit-date stamps (audit L-75, 2026-09-20 decision): while anchors
    // are session-backed they DELIBERATELY survive this lock boundary — a
    // 10-minute idle lock or a token expiry mid-clinic-day must not erase
    // the "new since reviewed" delta; the browser session's end clears
    // them. The 2026-09-26 audit round (L) added ONE carve-out: an
    // EXPLICIT sign-out clears the session-backed stamps too — leaving the
    // workstation for the day should not leave per-patient date stamps
    // behind for whoever uses the tab next. Idle-lock retention stays the
    // accepted L-75 trade-off. Only the localStorage fallback keeps the
    // unconditional scrub-on-lock contract, because localStorage would
    // otherwise outlive the session.
    if (retiring) {
      if (opts?.clearAnchors === true) {
        sessionStore.removePrefix(`mindpattern.lastVisit.${retiring.userId}.`);
        localStore.removePrefix(`mindpattern.lastVisit.${retiring.userId}.`);
      } else if (!visitAnchorStore.sessionBacked()) {
        localStore.removePrefix(`mindpattern.lastVisit.${retiring.userId}.`);
      }
    }
    // 2026-09-26 audit M-P1: revoke the bearer SERVER-SIDE before the local
    // teardown. POST /auth/logout bumps the account's token epoch, so a
    // bearer copied off this shared clinic machine (default TTL: 24h) dies
    // with this lock instead of outliving it. Best-effort by contract:
    // api.logout() deliberately does not ride the session's abort
    // controller, so the clearSession() below cannot cancel it, and any
    // failure (offline backend, token already expired on the 401 path) is
    // swallowed — the local lockdown must never wait on, or be blocked by,
    // the network. The same fire happens on every lockDown route in: the
    // sign-out button, the idle lock, the 401-expiry latch, and a bfcache
    // restore.
    if (hasSession()) {
      void api.logout().catch(() => {});
    }
    // S-4 (pentest 2026-09-26): the interrupted-rotation recovery salt is
    // repair material for a live session, not something any lock boundary
    // should keep around — scrub it alongside the credentials teardown.
    if (retiring) {
      sessionStore.removePrefix(`mindpattern.interruptedRotateSalt.${retiring.userId}`);
    }
    clearSession();
    replacePortalSession(null);
    setDisplayName("");
    setUnlockError("");
    setNotice(message);
    // Re-audit 2026-09-27 (L): the triage-scan "don't ask again" latch is
    // module state and survives everything above — without this reset, a
    // DIFFERENT therapist signing into the same tab inherits the previous
    // therapist's acknowledgment. Every lock boundary (explicit sign-out,
    // idle lock, 401 expiry) ends the session, so the latch dies here too.
    resetScanConfirmation();
    setView({ kind: "login" });
  }, [replacePortalSession]);

  // Session-expiry (2026-09-17): any 401 swaps the UI to an explicit
  // expired state instead of a cryptic banner over live keys.
  useEffect(() => {
    setUnauthorizedHandler(() => lockDown("Session expired — please sign in again."));
    return () => setUnauthorizedHandler(null);
  }, []);

  // Teardown matters on route replacement / hot reload too, not just the
  // explicit sign-out button. Same L-75 rule as lockDown: session-backed
  // anchors survive (the browser session owns their lifetime); only the
  // localStorage fallback is scrubbed, matching its old contract.
  useEffect(() => () => {
    lifecycle.current += 1;
    clearSession();
    const retiring = sessionRef.current;
    if (retiring && !visitAnchorStore.sessionBacked()) {
      localStore.removePrefix(`mindpattern.lastVisit.${retiring.userId}.`);
    }
    wipePortalSession(retiring);
    sessionRef.current = null;
    // independent audit 2026-09-27: the triage-scan "don't ask again" latch
    // is MODULE state, so it survives this component's unmount — without
    // this reset, an HMR remount (and any future remount path) would keep
    // the previous mount's acknowledgment alive. Harmless in production,
    // where the only unmount is this tab's teardown.
    resetScanConfirmation();
  }, []);

  // Idle auto-lock: reset on any real interaction.
  // 2026-09-26 audit round (M): only INTERACTION events re-arm the timer —
  // the old list included bare `mousemove`, so a mouse jiggler (or a
  // shared laptop's wandering cursor) kept decrypted charts and live keys
  // on screen indefinitely. A visibilitychange listener covers the
  // forgotten-foreground-tab case: background tabs throttle timers, so the
  // overdue setTimeout may not fire until the user returns; a tab hidden
  // longer than the idle threshold now locks the moment it becomes visible
  // again, through the same lockDown path.
  useEffect(() => {
    if (!session) return;
    let timer = setTimeout(() => lockDown("Locked after inactivity — sign in again to continue."), IDLE_LOCK_MS);
    // independent audit 2026-09-27: the wall-clock stamp of the last REAL
    // interaction. The visibility handler needs it to close the gap where
    // idle accrued BEFORE the tab was hidden used to go unmeasured (see
    // onVisibility below).
    let lastInteractionAt = Date.now();
    const bump = (): void => {
      lastInteractionAt = Date.now();
      clearTimeout(timer);
      timer = setTimeout(() => lockDown("Locked after inactivity — sign in again to continue."), IDLE_LOCK_MS);
    };
    const events: (keyof WindowEventMap)[] = ["click", "keydown", "scroll", "wheel", "touchstart"];
    events.forEach((ev) => window.addEventListener(ev, bump, { passive: true }));
    let hiddenAt: number | null = null;
    const onVisibility = (): void => {
      if (typeof document === "undefined") return;
      if (document.hidden) {
        hiddenAt = Date.now();
        return;
      }
      if (hiddenAt !== null) {
        // independent audit 2026-09-27: lock on the OLDER of the two clocks.
        // The old check used only the hidden duration, so 9 idle minutes in
        // the foreground followed by a 2-minute hide slipped under a
        // 10-minute threshold and re-shown the decrypted chart. Idle accrued
        // BEFORE hiding counts exactly like time spent hidden.
        const now = Date.now();
        if (Math.max(now - hiddenAt, now - lastInteractionAt) >= IDLE_LOCK_MS) {
          lockDown("Locked after inactivity — sign in again to continue.");
        }
      }
      hiddenAt = null;
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibility);
    }
    return () => {
      clearTimeout(timer);
      events.forEach((ev) => window.removeEventListener(ev, bump));
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVisibility);
      }
    };
  }, [session]);

  // bfcache restore (2026-09-19): navigating away and pressing Back past
  // the idle window restores the tab from the back/forward cache with the
  // decrypted journal DOM frozen in it — Cache-Control cannot touch bfcache
  // and the overdue idle setTimeout only fires AFTER the restore, so the
  // old code flashed decrypted patient text for a beat before locking. A
  // persisted pageshow locks down synchronously, before first paint.
  useEffect(() => {
    const onPageshow = (event: PageTransitionEvent): void => {
      if (event.persisted) lockDown("Restored from the browser cache — sign in again.");
    };
    window.addEventListener("pageshow", onPageshow);
    return () => window.removeEventListener("pageshow", onPageshow);
  }, [lockDown]);

  const onLoginReady = async (keys: PortalKeys) => {
    const startedAt = lifecycle.current;
    const attempt = ++loginAttempt.current;
    setUnlockError("");
    setNotice(null);
    let identityNotes: Uint8Array | null = null; let custody: NotesKeyring | null = null; let adopted = false;
    try {
      const me = await api.me();
      const { privateKey, noteKeyV2 } = await unlockWrapPrivateKeyWithNotesKey(
        keys.wrapKek,
        me.wrap_key_blob,
        keys.username,
      );
      // The wrap KEK's only job is this one unwrap; the session keeps the
      // non-extractable private-key handle instead. Zero the raw KEK bytes
      // now so a memory disclosure for the rest of the session (extension,
      // crash dump) cannot recover the key that decrypts wrap_key_blob.
      identityNotes = noteKeyV2;
      custody = me.notes_keyring_blob ? await openNotesKeyring(keys.wrapKek, keys.userId, me.notes_keyring_blob) : null;
      keys.wrapKek.fill(0);
      // A 401, explicit logout, or component teardown may have occurred
      // while the encrypted wrap key was being fetched/decrypted.  Never
      // resurrect a completed session after that boundary.
      if (attempt !== loginAttempt.current || startedAt !== lifecycle.current || !hasSession()) {
        wipePortalSession(keys); noteKeyV2.fill(0); custody?.active.fill(0); for (const key of custody?.historical ?? []) key.fill(0);
        return;
      }
      replacePortalSession({
        username: keys.username,
        userId: keys.userId,
        noteKey: keys.noteKey,
        noteKeyV2: custody?.active ?? noteKeyV2,
        historicalNoteKeys: custody ? [...custody.historical, noteKeyV2] : [],
        ...(custody ? { custodyVersion: me.custody_version ?? 0 } : {}),
        privateKey,
        publicKeyB64: me.wrap_pub_key,
      });
      adopted = true;
      setDisplayName(me.display_name);
      setView({ kind: "patients" });
    } catch (err) {
      wipePortalSession(keys);
      if (attempt === loginAttempt.current && startedAt === lifecycle.current) {
        // 2026-09-26 audit follow-up (portal N-3): this path runs AFTER
        // setSession minted a fresh 24 h bearer. Dropping it from memory
        // without revocation left the token server-valid — the one
        // session-end route that skipped M-P1's logout fire. Best-effort,
        // same contract as lockDown: never block the local teardown.
        void api.logout().catch(() => {});
        clearSession();
        replacePortalSession(null);
        setUnlockError(
          err instanceof Error && err.name === "TamperError"
            ? "your stored sharing key could not be unlocked with this password — sign in with the account's password"
            : err instanceof Error
              ? err.message
              : "could not unlock your sharing key",
        );
        setView({ kind: "login" });
      }
    } finally { if (!adopted) { identityNotes?.fill(0); wipeNotesKeyring(custody); } }
  };

  if (view.kind === "login") {
    return (
      <>
        {notice && <InfoBanner message={notice} flush />}
        {unlockError && (
          <div className="banner banner--error banner--flush" role="alert">
            {unlockError}
          </div>
        )}
        <LoginView onReady={(keys) => onLoginReady(keys)} />
      </>
    );
  }

  if (!session) {
    return <p className="unlocking">Unlocking…</p>;
  }

  if (view.kind === "patient") {
    return (
      // 2026-09-29 audit HIGH: a crash inside one patient's chart falls
      // back to a calm panel instead of unmounting the portal; the key
      // makes navigating back to the caselist recover without a reload.
      <ViewBoundary
        // 2026-10-01 audit L: every patient chart shared resetKey "patient"
        // — a boundary that failed for patient A never reset when patient
        // B opened. Reset per patient id.
        resetKey={`patient:${view.patient.user_id}`}
      >
        <PatientView
          patient={view.patient}
          session={session}
          onBack={() => { writePatientRoute(null); setView({ kind: "patients" }); }}
          // 2026-09-26 audit round (L): an explicit sign-out also clears the
          // session-backed visit anchors (see lockDown's carve-out).
          onSignOut={() => lockDown("Signed out. Your in-memory keys were cleared.", { clearAnchors: true })}
        />
      </ViewBoundary>
    );
  }

  return (
    <ViewBoundary resetKey="patients">
      <PatientsView
        displayName={displayName}
        session={session}
        onOpen={(patient) => { writePatientRoute(patient.user_id); setView({ kind: "patient", patient }); }}
        onSignOut={() => {
          // Same explicit-sign-out anchor carve-out as the chart's button.
          lockDown("Signed out. Your in-memory keys were cleared.", { clearAnchors: true });
        }}
        // NEW-3 / F.4 (2026-09-22): a successful password change killed every
        // bearer (the server bumps the token epoch), so the lock-down notice
        // says why the user is suddenly back at the sign-in screen.
        onSessionsEnded={() => {
          lockDown("Password changed. Every session — including this one — has ended; sign in with your new password.");
        }}
      />
    </ViewBoundary>
  );
}
