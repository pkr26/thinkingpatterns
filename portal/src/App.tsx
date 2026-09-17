/**
 * App shell: a four-state machine — login → key unlock → patients → one
 * patient. All key material lives in React state (memory only): closing
 * the tab forgets everything; there is nothing sensitive in localStorage
 * beyond per-patient visit-date stamps (see PatientView).
 */
import { useState } from "react";
import { clearSession, api, type Patient } from "./api";
import { unlockWrapPrivateKey } from "./crypto";
import { LoginView, type PortalKeys } from "./views/LoginView";
import { PatientsView } from "./views/PatientsView";
import { PatientView, type PortalSession } from "./views/PatientView";
import { theme } from "./ui";

type View =
  | { kind: "login"; error?: string }
  | { kind: "patients" }
  | { kind: "patient"; patient: Patient };

export function App(): React.JSX.Element {
  const [view, setView] = useState<View>({ kind: "login" });
  const [session, setSession] = useState<PortalSession | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [unlockError, setUnlockError] = useState("");

  const onLoginReady = async (keys: PortalKeys, token: { token: string }, baseUrl: string) => {
    setUnlockError("");
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
      onOpen={(patient) => setView({ kind: "patient", patient })}
      onSignOut={() => {
        clearSession();
        setSession(null);
        setView({ kind: "login" });
      }}
    />
  );
}
