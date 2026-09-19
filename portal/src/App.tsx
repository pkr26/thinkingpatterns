/**
 * App shell: a four-state machine — login → key unlock → patients → one
 * patient. All key material lives in React state (memory only): closing
 * the tab forgets everything; there is nothing sensitive in localStorage
 * beyond per-patient visit-date stamps (see PatientView).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { clearSession, api, hasSession, setUnauthorizedHandler, type Patient } from "./api";
import { unlockWrapPrivateKey } from "./crypto";
import { LoginView, type PortalKeys } from "./views/LoginView";
import { PatientsView } from "./views/PatientsView";
import { PatientView, type PortalSession } from "./views/PatientView";
import { theme } from "./ui";
import { localStore } from "./platform";

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
function wipePortalSession(value: { noteKey?: Uint8Array; wrapKek?: Uint8Array } | null): void {
  if (!value) return;
  value.wrapKek?.fill(0);
  value.noteKey?.fill(0);
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

  const replacePortalSession = useCallback((next: PortalSession | null): void => {
    const previous = sessionRef.current;
    if (previous && previous !== next) wipePortalSession(previous);
    sessionRef.current = next;
    setSessionState(next);
  }, []);

  const lockDown = useCallback((message: string) => {
    lifecycle.current += 1;
    loginAttempt.current += 1;
    const retiring = sessionRef.current;
    if (retiring) localStore.removePrefix(`mindpattern.lastVisit.${retiring.userId}.`);
    clearSession();
    replacePortalSession(null);
    setDisplayName("");
    setUnlockError("");
    setNotice(message);
    setView({ kind: "login" });
  }, [replacePortalSession]);

  // Session-expiry (2026-09-17): any 401 swaps the UI to an explicit
  // expired state instead of a cryptic banner over live keys.
  useEffect(() => {
    setUnauthorizedHandler(() => lockDown("Session expired — please sign in again."));
    return () => setUnauthorizedHandler(null);
  }, []);

  // Teardown matters on route replacement / hot reload too, not just the
  // explicit sign-out button.
  useEffect(() => () => {
    lifecycle.current += 1;
    clearSession();
    const retiring = sessionRef.current;
    if (retiring) localStore.removePrefix(`mindpattern.lastVisit.${retiring.userId}.`);
    wipePortalSession(retiring);
    sessionRef.current = null;
  }, []);

  // Idle auto-lock: reset on any real interaction.
  useEffect(() => {
    if (!session) return;
    let timer = setTimeout(() => lockDown("Locked after inactivity — sign in again to continue."), IDLE_LOCK_MS);
    const bump = (): void => {
      clearTimeout(timer);
      timer = setTimeout(() => lockDown("Locked after inactivity — sign in again to continue."), IDLE_LOCK_MS);
    };
    const events: (keyof WindowEventMap)[] = ["click", "keydown", "mousemove", "scroll", "touchstart"];
    events.forEach((ev) => window.addEventListener(ev, bump, { passive: true }));
    return () => {
      clearTimeout(timer);
      events.forEach((ev) => window.removeEventListener(ev, bump));
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
    try {
      const me = await api.me();
      const privateKey = await unlockWrapPrivateKey(keys.wrapKek, me.wrap_key_blob, keys.username);
      // The wrap KEK's only job is this one unwrap; the session keeps the
      // non-extractable private-key handle instead. Zero the raw KEK bytes
      // now so a memory disclosure for the rest of the session (extension,
      // crash dump) cannot recover the key that decrypts wrap_key_blob.
      keys.wrapKek.fill(0);
      // A 401, explicit logout, or component teardown may have occurred
      // while the encrypted wrap key was being fetched/decrypted.  Never
      // resurrect a completed session after that boundary.
      if (attempt !== loginAttempt.current || startedAt !== lifecycle.current || !hasSession()) {
        wipePortalSession(keys);
        return;
      }
      replacePortalSession({
        username: keys.username,
        userId: keys.userId,
        noteKey: keys.noteKey,
        privateKey,
        publicKeyB64: me.wrap_pub_key,
      });
      setDisplayName(me.display_name);
      setView({ kind: "patients" });
    } catch (err) {
      wipePortalSession(keys);
      if (attempt === loginAttempt.current && startedAt === lifecycle.current) {
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
    }
  };

  if (view.kind === "login") {
    return (
      <>
        {notice && (
          <div style={{ backgroundColor: "#1d2433", color: "#a8c0f0", padding: "10px 16px", fontSize: 14 }}>
            {notice}
          </div>
        )}
        {unlockError && (
          <div style={{ backgroundColor: "#2a1a17", color: "#f0b6ad", padding: "10px 16px", fontSize: 14 }}>
            {unlockError}
          </div>
        )}
        <LoginView onReady={(keys) => onLoginReady(keys)} />
      </>
    );
  }

  if (!session) {
    return <p style={{ color: theme.text }}>Unlocking…</p>;
  }

  if (view.kind === "patient") {
    return (
      <PatientView
        patient={view.patient}
        session={session}
        onBack={() => setView({ kind: "patients" })}
        onSignOut={() => lockDown("Signed out. Your in-memory keys were cleared.")}
      />
    );
  }

  return (
    <PatientsView
      displayName={displayName}
      session={session}
      onOpen={(patient) => setView({ kind: "patient", patient })}
      onSignOut={() => {
        lockDown("Signed out. Your in-memory keys were cleared.");
      }}
    />
  );
}
