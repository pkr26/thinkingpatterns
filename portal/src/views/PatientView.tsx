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

/** Session-note starters (2026-09-17): light scaffolds, never clinical
 *  templates — the therapist's own record, their own words. */
const NOTE_TEMPLATES: readonly string[] = [
  "Session focus:\n- \n- \n",
  "Observed together:\n- \n",
  "Homework / between-session plan:\n- \n",
  "Questions for next visit:\n- \n",
];

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
    case "avoidance":
      return `The day after '${pattern.label}' comes up, the patient tends not to write (${String(pattern.detail.silences ?? "?")} of ${String(pattern.detail.observed ?? "?")} observable such days).`;
    case "cadence":
      return "The patient's writing rhythm has been less regular than their earlier norm.";
    default:
      return `'${pattern.label}' — ${pattern.occurrences} mentions.`;
  }
}

/** Review ordering (2026-09-17): sensitive cards and down-shifts lead the
 *  list — observation-only still permits TRIAGE ordering — then rumination,
 *  then everything else by evidence density. */
function sortForReview(patterns: PatternPayload[]): PatternPayload[] {
  const rank = (p: PatternPayload): number => {
    if (p.detail.sensitive) return 0;
    if (p.kind === "mood_shift" && p.detail.direction !== "higher") return 1;
    if (p.kind === "rumination" || p.kind === "avoidance") return 2;
    return 3;
  };
  return [...patterns].sort((a, b) =>
    rank(a) - rank(b) || (b.detail.strength ?? 0) - (a.detail.strength ?? 0),
  );
}

/** Inline-SVG mood sparkline over the drill-down entries (their sentiment
 *  is already decrypted on this page). Pure presentation; the accessible
 *  label summarizes the window. */
function MoodSparkline(props: { points: { date: string; sentiment: number }[] }): React.JSX.Element | null {
  const pts = props.points.filter((p) => typeof p.sentiment === "number");
  if (pts.length < 2) return null;
  const w = 320;
  const h = 48;
  const step = w / (pts.length - 1);
  const y = (v: number): number => h / 2 - (v * (h / 2 - 3));
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${y(p.sentiment as number).toFixed(1)}`).join(" ");
  const avg = pts.reduce((sum, p) => sum + (p.sentiment as number), 0) / pts.length;
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      style={{ width: "100%", maxWidth: 420, height: 48, display: "block", marginTop: 8 }}
      role="img"
      aria-label={`Mood over the ${pts.length} evidence days (average ${(avg).toFixed(2)})`}
    >
      <line x1={0} y1={h / 2} x2={w} y2={h / 2} stroke={theme.border} strokeWidth={1} />
      <path d={path} fill="none" stroke={theme.accent} strokeWidth={1.6} />
    </svg>
  );
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
  const [lastReviewed, setLastReviewed] = useState<string | null>(null);
  const [stats, setStats] = useState<{ avg_sentiment?: number; total_entries?: number; active_days?: number; first_date?: string; last_date?: string } | null>(null);
  /** Notes search filter (client-side: notes are already decrypted here). */
  const [noteQuery, setNoteQuery] = useState("");
  /** The note being edited (id + textarea buffer). */
  const [editing, setEditing] = useState<{ id: string; text: string } | null>(null);

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
      const surfaced = sortForReview(payload.stats.patterns ?? []);
      // The pre-session delta (2026-09-17 fix): the stamp moves ONLY on the
      // explicit "Mark reviewed" action — a 30-second glance no longer
      // resets the delta, and a second browser sees the same anchor.
      const stamp = localStore.get(lastVisitKey(session.userId, patient.user_id));
      setLastReviewed(stamp ? dayOf(stamp) : null);
      setNewCount(stamp ? surfaced.filter((p) => p.detail.first_seen && p.detail.first_seen > stamp).length : surfaced.length);
      setStats(payload.stats);
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

  const saveNoteEdit = async (note: OpenNote) => {
    if (!editing || busy) return;
    setBusy(true);
    setError("");
    try {
      const sealed = await encryptNote(
        session.noteKey,
        session.userId,
        patient.user_id,
        note.client_note_id,
        editing.text.trim(),
      );
      const updated = await api.updateNote(note.id, sealed.blobB64);
      setNotes((prev) => prev.map((n) => (n.id === updated.id ? { ...updated, text: editing.text.trim() } : n)));
      setEditing(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not save the note edit");
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
            {newCount > 0 && ` · ${newCount} pattern${newCount === 1 ? "" : "s"} new${lastReviewed ? ` since you marked reviewed ${lastReviewed}` : " for you to review"}`}
          </NoteText>
        </div>
        <div className="no-print" style={{ display: "flex", gap: 8 }}>
          <Button label="Print session summary" small onPress={() => window.print()} />
          <Button label="Back to patients" small onPress={props.onBack} />
        </div>
      </header>

      <div className="no-print" style={{ marginBottom: 14 }}>
        <Button
          label={lastReviewed ? "Mark reviewed (update the delta anchor)" : "Mark reviewed (start the delta anchor)"}
          small
          onPress={() => {
            const now = new Date().toISOString();
            localStore.set(lastVisitKey(session.userId, patient.user_id), now);
            setLastReviewed(dayOf(now));
            setNewCount(0);
          }}
        />
        <span style={{ color: theme.muted, fontSize: 12, marginLeft: 10 }}>
          {lastReviewed
            ? `New-pattern counting is anchored to ${lastReviewed}; it moves only when you mark reviewed.`
            : "The new-pattern count anchors the first time you mark reviewed."}
        </span>
      </div>

      <ErrorBanner message={error} />

      {phaseNote && <Card title="Baseline phase"><NoteText>{phaseNote}</NoteText></Card>}

      {stats && patterns !== null && patterns.length > 0 && (
        <Card title="Account summary">
          <NoteText>
            {stats.total_entries ?? "?"} entries · {stats.active_days ?? "?"} active days
            {typeof stats.avg_sentiment === "number" && ` · average reading ${stats.avg_sentiment.toFixed(2)}`}
            {stats.first_date && stats.last_date && ` · ${dayOf(stats.first_date)} → ${dayOf(stats.last_date)}`}
          </NoteText>
        </Card>
      )}

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
          {entries !== null && <MoodSparkline points={entries.map((e) => ({ date: e.entry_date, sentiment: e.sentiment ?? 0 }))} />}
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
        {(selected ? patternNotes : generalNotes).length > 2 && (
          <input
            value={noteQuery}
            onChange={(e) => setNoteQuery(e.target.value)}
            placeholder="Search notes…"
            aria-label="Search notes"
            style={{
              backgroundColor: theme.cardDeep,
              color: theme.text,
              border: `1px solid ${theme.border}`,
              borderRadius: theme.radius,
              padding: "6px 10px",
              fontSize: 13,
              width: "100%",
              marginBottom: 8,
            }}
          />
        )}
        {selected && patternNotes.length === 0 && <NoteText>No notes on this pattern yet.</NoteText>}
        {!selected && generalNotes.length === 0 && <NoteText>No notes yet.</NoteText>}
        {(selected ? patternNotes : generalNotes)
          .filter((n) => n.text.toLowerCase().includes(noteQuery.trim().toLowerCase()))
          .map((note) => (
          <div key={note.id} style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 8 }}>
            {editing?.id === note.id ? (
              <>
                <textarea
                  value={editing.text}
                  onChange={(e) => setEditing({ id: note.id, text: e.target.value })}
                  placeholder="Editing note…"
                  rows={3}
                  style={{
                    backgroundColor: theme.cardDeep,
                    color: theme.text,
                    border: `1px solid ${theme.border}`,
                    borderRadius: theme.radius,
                    padding: 10,
                    fontSize: 14,
                    fontFamily: "inherit",
                    width: "100%",
                  }}
                />
                <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
                  <Button label={busy ? "Saving…" : "Save edit"} small onPress={() => void saveNoteEdit(note)} disabled={busy || !editing.text.trim()} />
                  <Button label="Cancel" small onPress={() => setEditing(null)} disabled={busy} />
                </div>
              </>
            ) : (
              <NoteText>{note.text}</NoteText>
            )}
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ color: theme.muted, fontSize: 11 }}>{dayOf(note.created_at)}</span>
              <Button label="Edit" small onPress={() => setEditing({ id: note.id, text: note.text })} disabled={busy} />
              <Button label="Delete" small danger onPress={() => void removeNote(note)} disabled={busy} />
            </div>
          </div>
        ))}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
          <span style={{ color: theme.muted, fontSize: 12, alignSelf: "center" }}>Start from:</span>
          {NOTE_TEMPLATES.map((tpl) => (
            <button
              key={tpl}
              type="button"
              onClick={() => setDraft(draft.trim() ? `${draft.trimEnd()}
${tpl}` : tpl)}
              style={{
                backgroundColor: theme.cardDeep,
                color: theme.body,
                border: `1px solid ${theme.border}`,
                borderRadius: theme.radius,
                padding: "4px 10px",
                fontSize: 12,
                cursor: "pointer",
              }}
            >
              {tpl.split("\n")[0]!.split(":")[0]}
            </button>
          ))}
          {(selected ? patternNotes : generalNotes).length > 0 && (
            <button
              type="button"
              onClick={() => setDraft((selected ? patternNotes : generalNotes)[0]?.text ?? draft)}
              style={{
                backgroundColor: theme.cardDeep,
                color: theme.body,
                border: `1px solid ${theme.border}`,
                borderRadius: theme.radius,
                padding: "4px 10px",
                fontSize: 12,
                cursor: "pointer",
              }}
            >
              Copy forward last note
            </button>
          )}
        </div>
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

      {/* Print-only session summary (2026-09-17): everything a paper record
          needs, nothing the interactive chrome shows. window.print() with
          .no-print hiding. */}
      <div className="print-only" style={{ display: "none" }}>
        <h1 style={{ fontSize: 18 }}>MindPattern session summary — {patient.username}</h1>
        <p style={{ fontSize: 12 }}>
          Sharing since {dayOf(patient.granted_at)} · summary generated {new Date().toISOString().slice(0, 10)}
          {lastReviewed && ` · delta anchored ${lastReviewed}`}
          {newCount > 0 && ` · ${newCount} new pattern${newCount === 1 ? "" : "s"}`}
        </p>
        {stats && (
          <p style={{ fontSize: 12 }}>
            {stats.total_entries ?? "?"} entries · {stats.active_days ?? "?"} active days
            {typeof stats.avg_sentiment === "number" && ` · average reading ${stats.avg_sentiment.toFixed(2)}`}
          </p>
        )}
        {(patterns ?? []).map((pattern) => (
          <div key={`${pattern.kind}:${pattern.label}`} style={{ borderTop: "1px solid #999", paddingTop: 6, marginTop: 6 }}>
            <strong style={{ fontSize: 13 }}>{pattern.detail.sensitive ? "A difficult thought (non-quoting)" : `${pattern.kind} — ${pattern.label}`}</strong>
            <p style={{ fontSize: 12, margin: "2px 0" }}>{describePattern(pattern)}</p>
            <p style={{ fontSize: 11, color: "#333" }}>
              {evidenceRows(pattern).map(([k, v]) => `${k}: ${v}`).join(" · ")}
            </p>
          </div>
        ))}
        {(selected ? patternNotes : generalNotes).length > 0 && (
          <>
            <h2 style={{ fontSize: 14, marginTop: 10 }}>Therapist notes ({selected ? "this pattern" : "general"})</h2>
            {(selected ? patternNotes : generalNotes).map((note) => (
              <p key={note.id} style={{ fontSize: 12, borderTop: "1px solid #999", paddingTop: 4 }}>
                {dayOf(note.created_at)} — {note.text}
              </p>
            ))}
          </>
        )}
        <p style={{ fontSize: 10, color: "#555", marginTop: 10 }}>
          Observations from the patient's own encrypted journal — not a diagnosis. Generated by MindPattern.
        </p>
      </div>

      <style>{`
        @media print {
          .no-print, .no-print * { display: none !important; }
          .print-only { display: block !important; }
          body { background: #fff !important; color: #000 !important; }
        }
      `}</style>
    </main>
  );
}
