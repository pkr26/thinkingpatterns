/**
 * Patients: the therapist's consented patient list, the pairing-code
 * generator (how a new patient connects), and the honest empty/revoked
 * states. Selecting an active patient opens the pattern view.
 */
import { useCallback, useEffect, useState } from "react";
import { api, type Patient } from "../api";
import { decryptCaseloadSummary, decryptInsights, keyFingerprint, unwrapPatientDataKey } from "../crypto";
import type { Bytes, CaseloadSummary } from "../crypto";
import { visitAnchorStore } from "../platform";
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
  /** Audit fix 17 (2026-09-21): the patients-load failure (not pairing-code
   *  or scan errors) offers an in-page retry of the fetch. */
  const [loadFailed, setLoadFailed] = useState(false);
  const [scan, setScan] = useState<Record<string, CaseloadScanRow> | null>(null);
  const [scanning, setScanning] = useState(false);
  /** This therapist's own wrap-key fingerprint (shown beside the pairing
   * code so the patient can verify it after lookup — 2026-09-17 audit). */
  const [fingerprint, setFingerprint] = useState<string | null>(null);

  useEffect(() => {
    if (!props.session) return;
    let cancelled = false;
    keyFingerprint(props.session.publicKeyB64)
      .then((fp) => { if (!cancelled) setFingerprint(fp); })
      .catch(() => { if (!cancelled) setFingerprint(null); });
    return () => { cancelled = true; };
  }, [props.session]);

  const refresh = useCallback(() => {
    setError("");
    setLoadFailed(false);
    api.patients().then(setPatients).catch((err) => {
      setError(err instanceof Error ? err.message : "could not load patients");
      setLoadFailed(true);
    });
  }, []);
  useEffect(refresh, [refresh]);

  // Caseload summaries (2026-09-19): the server writes a small ECIS-wrapped
  // summary per active consent at each patient recompute. Decrypting them
  // here makes triage O(1) per patient (no full insight fetches) and — the
  // safety point — surfaces a sensitive card's PRESENCE without opening
  // every chart. Failures degrade to "no summary": the row renders "—"
  // and the manual scan below remains the fallback.
  const [summaries, setSummaries] = useState<Record<string, CaseloadSummary | null>>({});
  useEffect(() => {
    if (!props.session || patients.length === 0) return;
    let cancelled = false;
    void (async () => {
      const next: Record<string, CaseloadSummary | null> = {};
      for (const patient of patients) {
        if (patient.status !== "active" || !patient.summary_blob || !patient.summary_eph_pub) {
          continue;
        }
        next[patient.user_id] = await decryptCaseloadSummary(
          props.session!.privateKey,
          props.session!.publicKeyB64,
          patient.summary_eph_pub,
          patient.summary_blob,
          patient.user_id,
          props.session!.userId,
        );
      }
      if (!cancelled) setSummaries(next);
    })();
    return () => { cancelled = true; };
  }, [props.session, patients]);

  const sensitiveCount = Object.values(summaries).filter((s) => s?.sensitive === true).length;

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
      for (const patient of patients.filter((p) => p.status === "active")) {
        try {
          const summary = await api.patientInsights(patient.user_id);
          // Same L-75 anchor store the chart uses (sessionStorage first,
          // lock-scrubbed localStorage fallback): the scan and the chart
          // must agree on which stamp the delta counts from.
          const stamp = visitAnchorStore.get(`mindpattern.lastVisit.${props.session.userId}.${patient.user_id}`);
          const row: CaseloadScanRow = {
            userId: patient.user_id,
            patterns: 0,
            sensitive: false,
            newSinceReviewed: 0,
            lastReviewed: stamp ? dayOf(stamp) : null,
          };
          if (summary.blob && summary.phase === "insight" && patient.ephemeral_pub && patient.wrapped_key) {
            // Keep the concrete ArrayBuffer-backed crypto type. A generic
            // Uint8Array could include SharedArrayBuffer storage, which the
            // WebCrypto helper intentionally rejects.
            let dataKey: Bytes | null = null;
            try {
              dataKey = await unwrapPatientDataKey(
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
            } finally {
              // Caseload scans unwrap each patient's data key in turn. It is
              // needed only for this one decrypt; retain no raw key bytes
              // after either a successful scan or a decrypt failure.
              dataKey?.fill(0);
            }
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
        {fingerprint && (
          <p data-testid="key-fingerprint" style={{ margin: "2px 0 0", color: theme.text, fontSize: 15, letterSpacing: 2, fontWeight: 600 }}>
            {fingerprint}
          </p>
        )}
        {fingerprint && (
          <Note>Your key fingerprint — ask your patient to read theirs back after they look you up; a mismatch means a key was substituted in transit.</Note>
        )}
        <Button label={busy ? "Generating…" : "Generate pairing code"} onPress={newCode} disabled={busy} />
      </Card>

      <ErrorBanner message={error} />
      {loadFailed && (
        // Audit fix 17 (2026-09-21): recovery from a failed caseload load
        // used to require a reload or sign-out.
        <div style={{ marginTop: 8 }}>
          <Button label="Retry loading patients" small onPress={refresh} />
        </div>
      )}

      {sensitiveCount > 0 && (
        <div data-testid="sensitive-banner" style={{ marginBottom: 14 }}>
          <Note tone="warn">
            {sensitiveCount} of your patients {sensitiveCount === 1 ? "has a sensitive card" : "have sensitive cards"} in
            their current patterns. Opening {sensitiveCount === 1 ? "that chart" : "those charts"} puts the
            non-quoting card first — the wording itself is never echoed here.
          </Note>
        </div>
      )}

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
        const summary = summaries[patient.user_id];
        return (
        <Card key={patient.user_id}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <div>
              <strong style={{ color: theme.text, fontSize: 15 }}>{patient.username}</strong>
              <Note>
                sharing since {dayOf(patient.granted_at)}
                {/* M-21 (2026-09-20): a manual scan row is FRESHER than the
                    server's last-recompute summary, so it wins when both
                    exist; the summary count otherwise renders with its
                    as-of date (forDate), because "4 patterns" is only
                    interpretable next to the date it was true of. */}
                {row && row.patterns >= 0 && ` · ${row.patterns} pattern${row.patterns === 1 ? "" : "s"} (scanned just now)`}
                {(!row || row.patterns < 0) && summary && ` · ${summary.patterns} pattern${summary.patterns === 1 ? "" : "s"} as of ${summary.forDate ?? "an unknown date"}`}
                {row && row.newSinceReviewed > 0 && ` · ${row.newSinceReviewed} new`}
                {row && row.lastReviewed && ` · reviewed ${row.lastReviewed}`}
              </Note>
              {(row?.sensitive || summary?.sensitive) && (
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
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
                <div>
                  <strong style={{ color: theme.text, fontSize: 14 }}>{patient.username}</strong>
                  <Note>
                    access ended {patient.revoked_at ? dayOf(patient.revoked_at) : "recently"} — their
                    entries and patterns are no longer reachable. Your notes about this patient stay.
                  </Note>
                </div>
                {/* M-22 (2026-09-20): the copy above promises the notes stay,
                    but nothing could reach them. The chart opens in its
                    notes-only mode for stopped consents (the server permits
                    note access at any consent status). */}
                <Button label="Open my notes" small onPress={() => props.onOpen(patient)} />
              </div>
            </Card>
          ))}
        </>
      )}
    </main>
  );
}
