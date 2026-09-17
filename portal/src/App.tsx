/**
 * App shell: a four-state machine — login → key unlock → patients → one
 * patient. All key material lives in React state (memory only): closing
 * the tab forgets everything; there is nothing sensitive in localStorage
 * beyond per-patient visit-date stamps (see PatientView).
 */
import { useEffect, useState } from "react";
import { clearSession, api, setUnauthorizedHandler, type Patient } from "./api";
import { unlockWrapPrivateKey } from "./crypto";
import { LoginView, type PortalKeys } from "./views/LoginView";
import { PatientsView } from "./views/PatientsView";
import { PatientView, type PortalSession } from "./views/PatientView";
import { theme } from "./ui";

type View =
  | { kind: "login"; error?: string }
  | { kind: "patients" }
  | { kind: "patient"; patient: Patient };

/** Idle auto-lock (2026-09-17): 10 minutes without interaction drops
 *  every key from memory — a chart left open on a shared clinic laptop
 *  shows decrypted journal text exactly until the clinician walks away. */
const IDLE_LOCK_MS = 10 * 60 * 1000;

export function App(): React.JSX.Element {
  const [view, setView] = useState<View>({ kind: "login" });
  const [session, setSession] = useState<PortalSession | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const lockDown = (message: string) => {
    clearSession();
    setSession(null);
    setNotice(message);
    setView({ kind: "login" });
  };

  // Session-expiry (2026-09-17): any 401 swaps the UI to an explicit
  // expired state instead of a cryptic banner over live keys.
  useEffect(() => {
    setUnauthorizedHandler(() => lockDown("Session expired — please sign in again."));
    return () => setUnauthorizedHandler(null);
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

  const onLoginReady = async (keys: PortalKeys, token: { token: string }, baseUrl: string) => {
    setUnlockError("");
    setNotice(null);
    try {
      const me = await api.me();
      const privateKey = await unlockWrapPrivateKey(keys.wrapKek, me.wrap_key_blob, keys.username);
      setSession({
        username: keys.username,
        userId: keys.userId,
        wrapKek: keys.wrapKek,
        noteKey: keys.noteKey,
        privateKey,
        publicKeyB64: me.wrap_pub_key,
      });
      setDisplayName(me.display_name);
      setView({ kind: "patients" });
    } catch (err) {
      clearSession();
      setUnlockError(
        err instanceof Error && err.name === "TamperError"
          ? "your stored sharing key could not be unlocked with this password — sign in with the account's password"
          : err instanceof Error
            ? err.message
            : "could not unlock your sharing key",
      );
      setView({ kind: "login" });
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
        <LoginView onReady={(keys, token, baseUrl) => void onLoginReady(keys, token, baseUrl)} />
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
      />
    );
  }

  return (
    <PatientsView
      displayName={displayName}
      session={session}
      onOpen={(patient) => setView({ kind: "patient", patient })}
      onSignOut={() => {
        clearSession();
        setSession(null);
        setView({ kind: "login" });
      }}
    />
  );
}
