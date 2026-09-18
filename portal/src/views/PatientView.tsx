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
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  api,
  THERAPIST_ENTRY_PAGE_SIZE,
  THERAPIST_NOTE_PAGE_SIZE,
  type Note,
  type Patient,
  type PortalEntry,
} from "../api";
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
  id: string;
  entry_date: string;
  text: string;
  sentiment: number | null | undefined;
}

const dayOf = (iso: string): string => iso.slice(0, 10);
// The server also caps each page at 2 MiB of raw ciphertext.  Keep the
// client-side aggregate finite: an evidence card describes at most 60 dates,
// and 200 entries is already substantially more than a clinician can review
// in one drill-down without turning the browser into an unbounded cache.
const ENTRY_PAGE_SIZE = THERAPIST_ENTRY_PAGE_SIZE;
const MAX_ENTRY_PAGES = 8;
const MAX_EVIDENCE_ENTRIES = ENTRY_PAGE_SIZE * MAX_ENTRY_PAGES;
const NOTE_PAGE_SIZE = THERAPIST_NOTE_PAGE_SIZE;
const MAX_NOTE_PAGES = 20;
const MAX_NOTES_PER_LOAD = 1_000;
// A revision mismatch means the server refused to combine pages from two
// collection snapshots. Restart once from offset zero; retrying forever lets
// a busy or hostile server turn a read-only chart into an unbounded request
// loop.
const MAX_COLLECTION_CHANGE_RESTARTS = 1;

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

function patternKey(pattern: PatternPayload, index: number): string {
  return pattern.detail.pattern_pid ?? `${pattern.kind}:${pattern.label}:${index}`;
}

function isRetryableCollectionChange(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409 && error.code === "collection_changed";
}

async function loadStableCollection<T>(load: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await load();
    } catch (error) {
      if (!isRetryableCollectionChange(error) || attempt >= MAX_COLLECTION_CHANGE_RESTARTS) {
        throw error;
      }
    }
  }
}

export function PatientView(props: {
  patient: Patient;
  session: PortalSession;
  onBack: () => void;
  onSignOut?: () => void;
}): React.JSX.Element {
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
  // Every async decrypt/load carries this generation.  Leaving the patient,
  // signing out, or selecting another pattern makes old plaintext results
  // ineligible to repopulate React state.
  const loadGeneration = useRef(0);
  const drilldownGeneration = useRef(0);

  const load = useCallback(async () => {
    const operation = ++loadGeneration.current;
    setError("");
    setPatterns(null);
    setPhaseNote(null);
    setStats(null);
    setNotes([]);
    setSelected(null);
    setEntries(null);
    setNoteQuery("");
    setEditing(null);

    // Notes are intentionally available during the patient's baseline
    // phase, and after a sharing revoke where the server permits the
    // therapist's own record.  Load them independently of insights so an
    // early baseline return cannot silently hide existing notes.
    const notesLoad = (async (): Promise<void> => {
      const noteRows = await loadStableCollection(async (): Promise<Note[]> => {
        const rows: Note[] = [];
        let offset = 0;
        let revision: string | undefined;
        // One extra request is a bounded terminal probe: compatibility mode
        // infers a cursor from a headerless full final page, so exactly twenty
        // complete pages must be allowed to prove there is no twenty-first.
        for (let page = 0; page <= MAX_NOTE_PAGES; page += 1) {
          const currentPage = await api.notes(
            patient.user_id,
            revision === undefined ? { offset } : { offset, expectedRevision: revision },
          );
          // A revision must be present on the first modern page and stay
          // constant thereafter. A header appearing only after a legacy
          // first page cannot prove that the already-retained rows belong to
          // its snapshot, so fail rather than silently mixing histories.
          if (revision === undefined && currentPage.revision !== undefined) {
            if (offset !== 0) {
              throw new Error("server changed the note pagination protocol mid-load");
            }
            revision = currentPage.revision;
          } else if (revision !== undefined && currentPage.revision !== revision) {
            throw new Error("server returned an inconsistent note snapshot revision");
          }
          if (page === MAX_NOTE_PAGES) {
            if (currentPage.notes.length > 0) {
              throw new Error("note history exceeds this portal's safe page limit");
            }
            break;
          }
          if (rows.length + currentPage.notes.length > MAX_NOTES_PER_LOAD) {
            throw new Error("note history exceeds this portal's safe entry limit");
          }
          rows.push(...currentPage.notes);
          if (currentPage.nextOffset === null) break;
          offset = currentPage.nextOffset;
        }
        return rows;
      });
      const opened: OpenNote[] = [];
      for (const row of noteRows) {
        try {
          opened.push({ ...row, text: await decryptNote(session.noteKey, session.userId, patient.user_id, row.client_note_id, row.blob) });
        } catch {
          opened.push({ ...row, text: "(note could not be decrypted with this account's key)" });
        }
      }
      if (operation === loadGeneration.current) setNotes(opened);
    })().catch((err: unknown) => {
      if (operation === loadGeneration.current) {
        setError(err instanceof Error ? err.message : "could not load therapist notes");
      }
    });

    try {
      const summary = await api.patientInsights(patient.user_id);
      if (!summary.blob || summary.phase !== "insight") {
        if (operation !== loadGeneration.current) return;
        setPhaseNote(
          summary.phase === "baseline"
            ? `Still in the baseline phase — ${summary.days_remaining} active day(s) until patterns surface. Your private clinician notes remain available below.`
            : "No pattern data has been computed yet for this patient.",
        );
        setPatterns([]);
      } else {
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
        let payload: Awaited<ReturnType<typeof decryptInsights>>;
        try {
          payload = await decryptInsights(dataKey, patient.user_id, summary.blob);
        } finally {
          dataKey.fill(0);
        }
        if (operation !== loadGeneration.current) return;
        const surfaced = sortForReview(payload.stats.patterns ?? []);
        // The pre-session delta (2026-09-17 fix): the stamp moves ONLY on the
        // explicit "Mark reviewed" action — a 30-second glance no longer
        // resets the delta, and a second browser sees the same anchor.
        const stamp = localStore.get(lastVisitKey(session.userId, patient.user_id));
        setLastReviewed(stamp ? dayOf(stamp) : null);
        setNewCount(stamp ? surfaced.filter((p) => p.detail.first_seen && p.detail.first_seen > stamp).length : surfaced.length);
        setStats(payload.stats);
        setPatterns(surfaced);
      }
    } catch (err) {
      if (operation === loadGeneration.current) {
        setError(err instanceof Error ? err.message : "could not load this patient");
      }
    } finally {
      await notesLoad;
    }
  }, [patient, session]);

  useEffect(() => {
    void load();
    return () => {
      loadGeneration.current += 1;
      drilldownGeneration.current += 1;
    };
  }, [load]);

  const selectedPid = selected?.detail.pattern_pid ?? null;
  const patternNotes = useMemo(
    () => notes.filter((n) => n.pattern_pid !== null && n.pattern_pid === selectedPid),
    [notes, selectedPid],
  );
  const generalNotes = useMemo(() => notes.filter((n) => n.pattern_pid === null), [notes]);

  const openDrilldown = async (pattern: PatternPayload) => {
    const operation = ++drilldownGeneration.current;
    setSelected(pattern);
    setEntries(null);
    setError("");
    try {
      const dates = pattern.detail.evidence_dates ?? [];
      if (dates.length === 0) {
        if (operation === drilldownGeneration.current) setEntries([]);
        return;
      }
      if (!patient.ephemeral_pub || !patient.wrapped_key) {
        throw new Error("this consent carries no key material");
      }
      const orderedDates = [...dates].sort();
      const rows = await loadStableCollection(async (): Promise<PortalEntry[]> => {
        const snapshotRows: PortalEntry[] = [];
        let offset = 0;
        let revision: string | undefined;
        // A headerless full page from an older backend has an ambiguous end.
        // Permit one empty probe after the retained-page cap, but never retain
        // its contents: an actual extra entry still fails closed below.
        for (let page = 0; page <= MAX_ENTRY_PAGES; page += 1) {
          const pageParams = {
            since: orderedDates[0],
            until: orderedDates[orderedDates.length - 1]!,
            offset,
          };
          const currentPage = await api.patientEntries(
            patient.user_id,
            revision === undefined ? pageParams : { ...pageParams, expectedRevision: revision },
          );
          if (revision === undefined && currentPage.revision !== undefined) {
            if (offset !== 0) {
              throw new Error("server changed the evidence pagination protocol mid-load");
            }
            revision = currentPage.revision;
          } else if (revision !== undefined && currentPage.revision !== revision) {
            throw new Error("server returned an inconsistent evidence snapshot revision");
          }
          if (page === MAX_ENTRY_PAGES) {
            if (currentPage.entries.length > 0) {
              throw new Error("evidence window exceeds this portal's safe page limit");
            }
            break;
          }
          if (snapshotRows.length + currentPage.entries.length > MAX_EVIDENCE_ENTRIES) {
            throw new Error("evidence window exceeds this portal's safe entry limit");
          }
          snapshotRows.push(...currentPage.entries);
          if (currentPage.nextOffset === null) break;
          offset = currentPage.nextOffset;
        }
        return snapshotRows;
      });
      const dataKey = await unwrapPatientDataKey(
        session.privateKey,
        patient.ephemeral_pub,
        patient.wrapped_key,
        patient.user_id,
        session.userId,
        session.publicKeyB64,
      );
      const keep = new Set(dates);
      const decrypted: EntryRow[] = [];
      const seen = new Set<string>();
      try {
        for (const row of rows) {
          if (!keep.has(row.entry_date) || seen.has(row.id)) continue;
          seen.add(row.id);
          const payload = await decryptEntry(dataKey, patient.user_id, row);
          decrypted.push({
            id: row.id,
            entry_date: row.entry_date,
            text: payload.text,
            sentiment: payload.sentiment,
          });
        }
      } finally {
        dataKey.fill(0);
      }
      decrypted.sort((a, b) => b.entry_date.localeCompare(a.entry_date) || a.id.localeCompare(b.id));
      if (operation === drilldownGeneration.current) setEntries(decrypted);
    } catch (err) {
      if (operation === drilldownGeneration.current) {
        setError(err instanceof Error ? err.message : "could not load the evidence entries");
      }
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
          {props.onSignOut && <Button label="Sign out" small danger onPress={props.onSignOut} />}
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
          <Button label="Back to all patterns" small onPress={() => {
            drilldownGeneration.current += 1;
            setSelected(null);
            setEntries(null);
          }} />
        </Card>
      ) : (
        patterns?.map((pattern, index) => (
          <Card key={patternKey(pattern, index)} title={pattern.detail.sensitive ? "A difficult thought has been returning" : pattern.label}>
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
            <div key={entry.id} style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 8 }}>
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
        <NoteText>
          Private clinician notes are encrypted under YOUR password before leaving this page. They are not shared with the patient or added to their journal, and may remain in your account after the patient stops sharing; delete them when your records policy requires it.
        </NoteText>
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
        {(patterns ?? []).map((pattern, index) => (
          <div key={patternKey(pattern, index)} style={{ borderTop: "1px solid #999", paddingTop: 6, marginTop: 6 }}>
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
