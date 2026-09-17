/**
 * Patients: the therapist's consented patient list, the pairing-code
 * generator (how a new patient connects), and the honest empty/revoked
 * states. Selecting an active patient opens the pattern view.
 */
import { useCallback, useEffect, useState } from "react";
import { api, type Patient } from "../api";
import { localStore } from "../platform";
import { Button, Card, ErrorBanner, Note, theme } from "../ui";
import type { PortalSession } from "./PatientView";

const dayOf = (iso: string): string => iso.slice(0, 10);

/** Per-patient caseload triage summary (2026-09-17): pattern count,
 *  sensitive-card presence, and new-since-reviewed — derived by fetching
 *  and decrypting each active patient's insights sequentially (the read
 *  rate limits are per-account and sequential is the polite shape). */
export interface CaseloadScanRow {
  userId: string;
  patterns: number;
  sensitive: boolean;
  newSinceReviewed: number;
  lastReviewed: string | null;
}

export function PatientsView(props: {
  onOpen: (patient: Patient) => void;
  onSignOut: () => void;
  displayName: string;
  session?: PortalSession;
}): React.JSX.Element {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [pairingCode, setPairingCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scan, setScan] = useState<Record<string, CaseloadScanRow> | null>(null);
  const [scanning, setScanning] = useState(false);

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

  const scanCaseload = async () => {
    if (scanning || !props.session) return;
    setScanning(true);
    setError("");
    const rows: Record<string, CaseloadScanRow> = {};
    try {
      const { decryptInsights, unwrapPatientDataKey } = await import("../crypto");
      for (const patient of patients.filter((p) => p.status === "active")) {
        try {
          const summary = await api.patientInsights(patient.user_id);
          const stamp = localStore.get(`mindpattern.lastVisit.${props.session.userId}.${patient.user_id}`);
          const row: CaseloadScanRow = {
            userId: patient.user_id,
            patterns: 0,
            sensitive: false,
            newSinceReviewed: 0,
            lastReviewed: stamp ? dayOf(stamp) : null,
          };
          if (summary.blob && summary.phase === "insight" && patient.ephemeral_pub && patient.wrapped_key) {
            const dataKey = await unwrapPatientDataKey(
              props.session.privateKey,
              patient.ephemeral_pub,
              patient.wrapped_key,
              patient.user_id,
              props.session.userId,
              props.session.publicKeyB64,
            );
            const payload = await decryptInsights(dataKey, patient.user_id, summary.blob);
            const surfaced = payload.stats.patterns ?? [];
            row.patterns = surfaced.length;
            row.sensitive = surfaced.some((p) => p.detail.sensitive === true);
            row.newSinceReviewed = stamp
              ? surfaced.filter((p) => p.detail.first_seen && p.detail.first_seen > stamp).length
              : surfaced.length;
          }
          rows[patient.user_id] = row;
        } catch {
          rows[patient.user_id] = {
            userId: patient.user_id, patterns: -1, sensitive: false,
            newSinceReviewed: -1, lastReviewed: null,
          }; // -1 = could not scan (revoked mid-scan, dead key): honest blank
        }
      }
      setScan(rows);
    } finally {
      setScanning(false);
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
      {active.length > 1 && (
        <div style={{ marginBottom: 10 }}>
          <Button label={scanning ? "Scanning caseload…" : "Scan caseload for triage"} small onPress={() => void scanCaseload()} disabled={scanning} />
          <span style={{ color: theme.muted, fontSize: 12, marginLeft: 10 }}>
            Fetches each patient's decrypted pattern counts sequentially — nothing is stored.
          </span>
        </div>
      )}
      {active.length === 0 && <Note>No patients are sharing with you yet.</Note>}
      {active.map((patient) => {
        const row = scan?.[patient.user_id];
        return (
        <Card key={patient.user_id}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <div>
              <strong style={{ color: theme.text, fontSize: 15 }}>{patient.username}</strong>
              <Note>
                sharing since {dayOf(patient.granted_at)}
                {row && row.patterns >= 0 && ` · ${row.patterns} pattern${row.patterns === 1 ? "" : "s"}`}
                {row && row.newSinceReviewed > 0 && ` · ${row.newSinceReviewed} new`}
                {row && row.lastReviewed && ` · reviewed ${row.lastReviewed}`}
              </Note>
              {row?.sensitive && (
                <Note tone="warn">a sensitive card is present — review ordering puts it first</Note>
              )}
            </div>
            <Button label="Open patterns" onPress={() => props.onOpen(patient)} />
          </div>
        </Card>
        );
      })}

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
