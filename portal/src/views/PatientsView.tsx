/**
 * Patients: the therapist's consented patient list, the pairing-code
 * generator (how a new patient connects), and the honest empty/revoked
 * states. Selecting an active patient opens the pattern view.
 */
import { useCallback, useEffect, useState } from "react";
import { api, type Patient } from "../api";
import { Button, Card, ErrorBanner, Note, theme } from "../ui";

const dayOf = (iso: string): string => iso.slice(0, 10);

export function PatientsView(props: { onOpen: (patient: Patient) => void; onSignOut: () => void; displayName: string }): React.JSX.Element {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [pairingCode, setPairingCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(() => {
    api.patients().then(setPatients).catch((err) => setError(err instanceof Error ? err.message : "could not load patients"));
  }, []);
  useEffect(refresh, [refresh]);

  const newCode = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    setPairingCode(null);
    try {
      const { code } = await api.newPairingCode();
      setPairingCode(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not create a pairing code");
    } finally {
      setBusy(false);
    }
  };

  const active = patients.filter((p) => p.status === "active");
  const stopped = patients.filter((p) => p.status !== "active");

  return (
    <main style={{ backgroundColor: theme.bg, minHeight: "100vh", color: theme.body, padding: 24, maxWidth: 860, margin: "0 auto" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <h1 style={{ color: theme.text, fontSize: 20, margin: 0 }}>Patients — {props.displayName}</h1>
        <Button label="Sign out" small onPress={props.onSignOut} />
      </header>

      <Card title="Connect a new patient">
        <Note>
          Generate a pairing code and read it to your patient. They enter it in their app, see your
          name, and confirm with their password. The code works once and expires in 15 minutes.
        </Note>
        {pairingCode && (
          <p data-testid="pairing-code" style={{ margin: 0, color: theme.text, fontSize: 28, letterSpacing: 6, fontWeight: 700 }}>
            {pairingCode}
          </p>
        )}
        <Button label={busy ? "Generating…" : "Generate pairing code"} onPress={newCode} disabled={busy} />
      </Card>

      <ErrorBanner message={error} />

      <h2 style={{ color: theme.muted, fontSize: 13, letterSpacing: 1, marginTop: 22 }}>ACTIVE</h2>
      {active.length === 0 && <Note>No patients are sharing with you yet.</Note>}
      {active.map((patient) => (
        <Card key={patient.user_id}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <div>
              <strong style={{ color: theme.text, fontSize: 15 }}>{patient.username}</strong>
              <Note>sharing since {dayOf(patient.granted_at)}</Note>
            </div>
            <Button label="Open patterns" onPress={() => props.onOpen(patient)} />
          </div>
        </Card>
      ))}

      {stopped.length > 0 && (
        <>
          <h2 style={{ color: theme.muted, fontSize: 13, letterSpacing: 1, marginTop: 22 }}>STOPPED SHARING</h2>
          {stopped.map((patient) => (
            <Card key={patient.user_id} deep>
              <strong style={{ color: theme.text, fontSize: 14 }}>{patient.username}</strong>
              <Note>
                access ended {patient.revoked_at ? dayOf(patient.revoked_at) : "recently"} — their
                entries and patterns are no longer reachable. Your notes about this patient stay.
              </Note>
            </Card>
          ))}
        </>
      )}
    </main>
  );
}
