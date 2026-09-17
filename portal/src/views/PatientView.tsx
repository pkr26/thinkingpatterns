/**
 * The patient view: pattern cards with their evidence, the drill-down
 * into the journal entries behind a pattern, and the therapist's notes.
 *
 * Read-only by construction: no endpoint here can write patient data.
 * The one write path is the therapist's OWN notes (encrypted under the
 * therapist's password-derived key — the patient's app never sees them).
 *
 * "Since your last visit" is computed locally (localStorage holds only a
 * date stamp per patient, never content): patterns whose first_seen is
 * newer than the last visit are flagged — the pre-session delta.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type Note, type Patient, type PortalEntry } from "../api";
import {
  decryptEntry,
  decryptInsights,
  decryptNote,
  encryptNote,
  unwrapPatientDataKey,
  type PatternPayload,
} from "../crypto";
import { Button, Card, ErrorBanner, Note as NoteText, theme } from "../ui";
import { localStore } from "../platform";

export interface PortalSession {
  username: string;
  userId: string;
  wrapKek: Uint8Array<ArrayBuffer>;
  noteKey: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
  publicKeyB64: string;
}

interface OpenNote extends Note {
  text: string;
}

interface EntryRow {
  entry_date: string;
  text: string;
  sentiment: number | null | undefined;
}

const dayOf = (iso: string): string => iso.slice(0, 10);

const lastVisitKey = (therapistId: string, userId: string): string =>
  `mindpattern.lastVisit.${therapistId}.${userId}`;

function describePattern(pattern: PatternPayload): string {
  const d = pattern.detail;
  // Crisis-adjacent wording is never quoted back (the same contract the
  // patient's app renders); the drill-down still shows the full entries.
  if (d.sensitive) {
    return "A difficult thought has been returning in the patient's writing — the entries below show it in the patient's own words.";
  }
  switch (pattern.kind) {
    case "temporal":
      return `'${pattern.label}' concentrates on ${d.day ?? "certain days"} (${d.day_count ?? "?"} of ${pattern.occurrences} mentions).`;
    case "mood_correlation":
      return `Entries read ${d.direction === "lower" ? "lower" : "higher"} on days '${pattern.label}' appears (mood delta ${String(d.mood_delta ?? "?")}).`;
    case "link":
      return `About ${String(d.lag_days ?? 1)} day(s) after '${pattern.label}' comes up, entries read ${String(d.direction ?? "lower")}.`;
    case "mood_shift":
      return `Entries have read ${String(d.direction ?? "lower")} than the patient's own baseline lately.`;
    case "inertia":
      return "Mood has been carrying over day to day more than usual for this patient.";
    case "instability":
      return "Daily mood has swung more widely than usual for this patient.";
    case "rumination":
    case "recurring_phrase":
      return `The phrase '${pattern.label}' has returned ${pattern.occurrences} times.`;
    case "topic":
      return `'${pattern.label}' has been taking up more space in the writing.`;
    default:
      return `'${pattern.label}' — ${pattern.occurrences} mentions.`;
  }
}

function evidenceRows(pattern: PatternPayload): [string, string][] {
  const d = pattern.detail;
  const rows: [string, string][] = [];
  if (d.pattern_state) rows.push(["state", String(d.pattern_state)]);
  if (typeof d.first_seen === "string") rows.push(["first seen", dayOf(d.first_seen)]);
  if (typeof d.last_seen === "string") rows.push(["last seen", dayOf(d.last_seen)]);
  rows.push(["mentions", String(pattern.occurrences)]);
  if (typeof d.sample_days === "number") rows.push(["window entries", String(d.sample_days)]);
  if (d.p_value !== undefined) rows.push(["p (corrected)", String(d.p_value)]);
  if (d.cohens_d !== undefined) rows.push(["effect (Cohen's d)", String(d.cohens_d)]);
  if (typeof d.strength === "number") rows.push(["evidence density", `${Math.round(d.strength * 100)}%`]);
  if (Array.isArray(d.evidence_dates)) rows.push(["evidence days", String(d.evidence_dates.length)]);
  return rows;
}

function newNoteId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function PatientView(props: { patient: Patient; session: PortalSession; onBack: () => void }): React.JSX.Element {
  const { patient, session } = props;
  const [patterns, setPatterns] = useState<PatternPayload[] | null>(null);
  const [phaseNote, setPhaseNote] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<PatternPayload | null>(null);
  const [entries, setEntries] = useState<EntryRow[] | null>(null);
  const [notes, setNotes] = useState<OpenNote[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [newCount, setNewCount] = useState(0);

  const load = useCallback(async () => {
    setError("");
    try {
      const summary = await api.patientInsights(patient.user_id);
      if (!summary.blob || summary.phase !== "insight") {
        setPhaseNote(
          summary.phase === "baseline"
            ? `Still in the baseline phase — ${summary.days_remaining} active day(s) until patterns surface.`
            : "No pattern data has been computed yet for this patient.",
        );
        setPatterns([]);
        return;
      }
      if (!patient.ephemeral_pub || !patient.wrapped_key) {
        throw new Error("this consent carries no key material");
      }
      const dataKey = await unwrapPatientDataKey(
        session.privateKey,
        patient.ephemeral_pub,
        patient.wrapped_key,
        patient.user_id,
        session.userId,
        session.publicKeyB64,
      );
      const payload = await decryptInsights(dataKey, patient.user_id, summary.blob);
      const surfaced = payload.stats.patterns ?? [];
      // The pre-session delta: how many patterns are new since the last
      // visit (stamp updated after this render, so this visit counts once).
      const stamp = localStore.get(lastVisitKey(session.userId, patient.user_id));
      setNewCount(stamp ? surfaced.filter((p) => p.detail.first_seen && p.detail.first_seen > stamp).length : 0);
      localStore.set(lastVisitKey(session.userId, patient.user_id), new Date().toISOString());
      setPatterns(surfaced);

      const noteRows = await api.notes(patient.user_id);
      const opened: OpenNote[] = [];
      for (const row of noteRows) {
        try {
          opened.push({ ...row, text: await decryptNote(session.noteKey, session.userId, patient.user_id, row.client_note_id, row.blob) });
        } catch {
          opened.push({ ...row, text: "(note could not be decrypted with this account's key)" });
        }
      }
      setNotes(opened);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not load this patient");
    }
  }, [patient, session]);

  useEffect(() => {
    void load();
  }, [load]);

  const selectedPid = selected?.detail.pattern_pid ?? null;
  const patternNotes = useMemo(
    () => notes.filter((n) => n.pattern_pid !== null && n.pattern_pid === selectedPid),
    [notes, selectedPid],
  );
  const generalNotes = useMemo(() => notes.filter((n) => n.pattern_pid === null), [notes]);

  const openDrilldown = async (pattern: PatternPayload) => {
    setSelected(pattern);
    setEntries(null);
    setError("");
    try {
      const dates = pattern.detail.evidence_dates ?? [];
      if (dates.length === 0) {
        setEntries([]);
        return;
      }
      const rows = await api.patientEntries(patient.user_id, {
        since: dates[0],
        until: dates[dates.length - 1]!,
        limit: 500,
      });
      const dataKey = await unwrapPatientDataKey(
        session.privateKey,
        patient.ephemeral_pub ?? "",
        patient.wrapped_key ?? "",
        patient.user_id,
        session.userId,
        session.publicKeyB64,
      );
      const keep = new Set(dates);
      const evidenceDates = new Set(rows.map((r) => r.entry_date).filter((d) => keep.has(d)));
      const decrypted: EntryRow[] = [];
      for (const row of rows as PortalEntry[]) {
        if (!evidenceDates.has(row.entry_date)) continue;
        const payload = await decryptEntry(dataKey, patient.user_id, row);
        decrypted.push({
          entry_date: row.entry_date,
          text: payload.text,
          sentiment: payload.sentiment,
        });
      }
      decrypted.sort((a, b) => (a.entry_date < b.entry_date ? 1 : -1));
      setEntries(decrypted);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not load the evidence entries");
    }
  };

  const saveNote = async () => {
    if (!draft.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      const clientNoteId = newNoteId();
      const sealed = await encryptNote(
        session.noteKey,
        session.userId,
        patient.user_id,
        clientNoteId,
        draft.trim(),
      );
      const created = await api.createNote(patient.user_id, {
        client_note_id: clientNoteId,
        pattern_pid: selectedPid,
        blob: sealed.blobB64,
      });
      setNotes((prev) => [...prev, { ...created, text: draft.trim() }]);
      setDraft("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not save the note");
    } finally {
      setBusy(false);
    }
  };

  const removeNote = async (note: OpenNote) => {
    if (busy) return;
    setBusy(true);
    try {
      await api.deleteNote(note.id);
      setNotes((prev) => prev.filter((n) => n.id !== note.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not delete the note");
    } finally {
      setBusy(false);
    }
  };

  const labelMatches = (text: string, label: string): boolean =>
    label.length > 0 && text.toLowerCase().includes(label.toLowerCase());

  return (
    <main style={{ backgroundColor: theme.bg, minHeight: "100vh", color: theme.body, padding: 24, maxWidth: 860, margin: "0 auto" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <div>
          <h1 style={{ color: theme.text, fontSize: 20, margin: 0 }}>{patient.username}</h1>
          <NoteText>
            sharing since {dayOf(patient.granted_at)} · read-only — you cannot change their data
            {newCount > 0 && ` · ${newCount} pattern${newCount === 1 ? "" : "s"} new since your last visit`}
          </NoteText>
        </div>
        <Button label="Back to patients" small onPress={props.onBack} />
      </header>

      <ErrorBanner message={error} />

      {phaseNote && <Card title="Baseline phase"><NoteText>{phaseNote}</NoteText></Card>}

      {patterns === null && !phaseNote && <NoteText>Loading decrypted patterns… (keys never leave this page)</NoteText>}

      {patterns !== null && patterns.length === 0 && !phaseNote && (
        <Card title="Patterns"><NoteText>No recurring pattern has enough evidence yet.</NoteText></Card>
      )}

      {selected ? (
        <Card title={selected.detail.sensitive ? "A difficult thought has been returning" : `${selected.kind} — ${selected.label}`}>
          <NoteText>{describePattern(selected)}</NoteText>
          <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 16px", fontSize: 13 }}>
            {evidenceRows(selected).map(([k, v]) => (
              <div key={k} style={{ display: "contents" }}>
                <span style={{ color: theme.muted }}>{k}</span>
                <span style={{ color: theme.body }}>{v}</span>
              </div>
            ))}
          </div>
          <Button label="Back to all patterns" small onPress={() => { setSelected(null); setEntries(null); }} />
        </Card>
      ) : (
        patterns?.map((pattern) => (
          <Card key={`${pattern.kind}:${pattern.label}`} title={pattern.detail.sensitive ? "A difficult thought has been returning" : pattern.label}>
            <NoteText>{describePattern(pattern)}</NoteText>
            {pattern.detail.is_new && <NoteText tone="ok">new since your last visit window</NoteText>}
            <Button label="See the evidence" small onPress={() => void openDrilldown(pattern)} />
          </Card>
        ))
      )}

      {selected && (
        <Card title={`Evidence entries (${entries?.length ?? 0})`}>
          {entries === null && <NoteText>Decrypting the entries behind this pattern…</NoteText>}
          {entries !== null && entries.length === 0 && (
            <NoteText>No decryptable entries behind this pattern (the evidence window may predate the shared corpus).</NoteText>
          )}
          {entries?.map((entry) => (
            <div key={entry.entry_date} style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 8 }}>
              <strong style={{ color: theme.text, fontSize: 13 }}>{entry.entry_date}</strong>
              {typeof entry.sentiment === "number" && (
                <span style={{ color: theme.muted, fontSize: 12, marginLeft: 8 }}>mood {entry.sentiment.toFixed(2)}</span>
              )}
              <p style={{ margin: "4px 0 0", fontSize: 14, lineHeight: 1.5, color: theme.body }}>
                {selected && labelMatches(entry.text, selected.label) ? <mark>{entry.text}</mark> : entry.text}
              </p>
            </div>
          ))}
        </Card>
      )}

      <Card title={selected ? "Notes on this pattern" : "General notes about this patient"}>
        {selected && patternNotes.length === 0 && <NoteText>No notes on this pattern yet.</NoteText>}
        {!selected && generalNotes.length === 0 && <NoteText>No notes yet.</NoteText>}
        {(selected ? patternNotes : generalNotes).map((note) => (
          <div key={note.id} style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 8 }}>
            <NoteText>{note.text}</NoteText>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ color: theme.muted, fontSize: 11 }}>{dayOf(note.created_at)}</span>
              <Button label="Delete" small danger onPress={() => void removeNote(note)} disabled={busy} />
            </div>
          </div>
        ))}
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={selected ? "Note about this pattern…" : "Note about this patient…"}
          rows={3}
          style={{
            backgroundColor: theme.cardDeep,
            color: theme.text,
            border: `1px solid ${theme.border}`,
            borderRadius: theme.radius,
            padding: 10,
            fontSize: 14,
            fontFamily: "inherit",
          }}
        />
        <div>
          <Button label={busy ? "Saving…" : "Save note"} onPress={saveNote} disabled={busy || !draft.trim()} />
        </div>
        <NoteText>Notes are encrypted under YOUR password before leaving this page — the patient never sees them.</NoteText>
      </Card>
    </main>
  );
}
