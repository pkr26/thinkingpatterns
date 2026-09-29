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
 *
 * Item 9 (clinical review 2026-09-27): a decrypted phq9 payload carrying
 * an endorsed item 9 renders a clearly-visible bordered safety row in the
 * measures card AND the printed summary ("Item 9 endorsed (self-harm
 * question) — follow your clinical protocol · C-SSRS follow-up
 * recommended"). Surfacing a fact the clinician's workflow requires is
 * the app's charter; interpreting the score is not — the notice never
 * says anything about severity or diagnosis.
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
  type PortalMeasure,
} from "../api";
import {
  decryptEntry,
  decryptInsights,
  decryptNote,
  encryptNote,
  decryptMeasure,
  type MeasureReading,
  unwrapPatientDataKey,
  type PatternPayload,
} from "../crypto";
import { Button, Card, Disclosure, ErrorBanner, Note as NoteText, theme } from "../ui";
import { printPage, randomBytes, visitAnchorStore } from "../platform";

export interface PortalSession {
  username: string;
  userId: string;
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
// Measures (audit L-76, 2026-09-20): the server continues with validated
// offset cursors over a deterministic order, so the chart pages through
// EVERYTHING it will share instead of silently dropping measure #61+.
// 20 pages × 100 rows = 2_000 rows — exactly the backend's per-patient
// measure quota, so a full traversal is always finite and complete.
// 2026-09-26 audit L: the traversal now runs the snapshot-revision
// contract (X-Measures-Revision pinning + one collection_changed
// restart), so MAX_MEASURE_PAGES retains pages plus one bounded terminal
// probe, like entries and notes. The page size itself lives in the api
// layer (THERAPIST_MEASURE_PAGE_SIZE), which now always sends it.
const MAX_MEASURE_PAGES = 20;
/** Rendering window per instrument: the trend row shows the newest 60
 *  readings and says so when older ones exist — an honest display slice,
 *  never a silent data truncation (everything fetched is decrypted and
 *  counted). */
const MEASURE_TREND_WINDOW = 60;
// A revision mismatch means the server refused to combine pages from two
// collection snapshots. Restart once from offset zero; retrying forever lets
// a busy or hostile server turn a read-only chart into an unbounded request
// loop.
const MAX_COLLECTION_CHANGE_RESTARTS = 1;

const lastVisitKey = (therapistId: string, userId: string): string =>
  `mindpattern.lastVisit.${therapistId}.${userId}`;

/** Local calendar date (YYYY-MM-DD) on the CLINICIAN's clock (audit L-80,
 *  2026-09-20).  The delta anchor and the printed "generated" date use
 *  this one basis: a UTC `toISOString()` stamp read "yesterday" for
 *  clinicians east of UTC during their evening, while the pattern dates
 *  they compare against are plain calendar days.  Anchoring to the local
 *  calendar day keeps "marked reviewed" on the same date the clinician's
 *  wall clock showed, and the anchor-vs-first_seen comparison stays a
 *  pure date-to-date comparison with no time-of-day seam. */
export function localDateISO(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

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
      // direction is absent when the backend could not resolve one; render
      // the honest unknown like the neighboring arms, never a fabricated
      // "higher" (audit L-82 — `=== "lower" ? … : "higher"` fell through
      // to a positive-sounding claim for undefined).
      return `Entries read ${String(d.direction ?? "?")} on days '${pattern.label}' appears (mood delta ${String(d.mood_delta ?? "?")}).`;
    case "link":
      // Same L-82 rule as mood_correlation: direction is absent when the
      // backend could not resolve one — render the honest unknown, never a
      // fabricated "lower" (2026-09-26 audit round, L).
      return `About ${String(d.lag_days ?? 1)} day(s) after '${pattern.label}' comes up, entries read ${String(d.direction ?? "?")}.`;
    case "mood_shift":
      // Ditto — "lower" used to be invented for an undefined direction.
      return `Entries have read ${String(d.direction ?? "?")} than the patient's own baseline lately.`;
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
 *  label summarizes the window.
 *
 *  Points arrive pre-filtered to numeric sentiment (see the call site):
 *  entries without an explicit mood pick carry null, and coercing those
 *  to 0 fabricated a mid-scale trend for patients who never make mood
 *  picks — audit H-13.  A null must never become a number on its way to
 *  this chart. */
function MoodSparkline(props: { points: { date: string; sentiment: number }[] }): React.JSX.Element | null {
  const pts = props.points;
  if (pts.length < 2) return null;
  const w = 320;
  const h = 48;
  const step = w / (pts.length - 1);
  const y = (v: number): number => h / 2 - (v * (h / 2 - 3));
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${y(p.sentiment).toFixed(1)}`).join(" ");
  const avg = pts.reduce((sum, p) => sum + p.sentiment, 0) / pts.length;
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className="sparkline"
      role="img"
      aria-label={`Mood over the ${pts.length} mood-tagged evidence entries (average ${(avg).toFixed(2)})`}
    >
      <line x1={0} y1={h / 2} x2={w} y2={h / 2} stroke={theme.border} strokeWidth={1} />
      {/* 2026-09-29 teal wave: accentBright (#7ce4d2, 11.39:1 on the card
          surface) — the base accent stroke missed the 3:1 non-text floor
          on --surface. */}
      <path d={path} fill="none" stroke={theme.accentBright} strokeWidth={1.6} />
    </svg>
  );
}

/** 2026-09-28 audit F7: the per-instrument measures trend — the same
 *  inline-SVG language as the mood sparkline, rendered above the exact
 *  text line (which stays for precision and print). Scores are plotted
 *  against the group's own maximum; interpretation stays the
 *  clinician's, and the aria-label carries the numbers a screen reader
 *  needs (the line alone is not accessible information). */
function MeasureTrend(props: { instrument: string; readings: { measureDate: string; score: number }[] }): React.JSX.Element | null {
  const pts = props.readings;
  if (pts.length < 2) return null;
  const w = 320;
  const h = 40;
  const max = Math.max(...pts.map((p) => p.score), 1);
  const step = w / (pts.length - 1);
  const y = (v: number): number => h - 4 - (v / max) * (h - 8);
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${y(p.score).toFixed(1)}`).join(" ");
  const scores = pts.map((p) => p.score);
  const first = scores[0]!;
  const last = scores[scores.length - 1]!;
  const low = Math.min(...scores);
  const high = Math.max(...scores);
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className="trend"
      role="img"
      aria-label={`${props.instrument} trend over ${pts.length} readings: first ${first}, latest ${last}, low ${low}, high ${high} (higher is more of what the instrument measures; interpretation is the clinician's)`}
    >
      <line x1={0} y1={h - 4} x2={w} y2={h - 4} stroke={theme.border} strokeWidth={1} />
      <path d={path} fill="none" stroke={theme.accentBright} strokeWidth={1.6} />
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
  // F-6 (2026-09-21): through the platform seam, not bare crypto.
  const bytes = randomBytes(8);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** 2026-09-28 audit F8: a note's surviving pattern anchor after a revoke,
 *  named in human terms instead of the raw pid ("phrase:a4adc4d084fc").
 *  The pid's coarse kind prefix is the same topic id the server already
 *  holds in plaintext. Every kind the engine emits — and both LEGACY
 *  phrase pids from before the rumination/recurring_phrase unification
 *  (brain.py _phrase_pid) — maps to a name; anything unrecognized still
 *  degrades to "a pattern". */
export function patternAnchorLabel(pid: string | null): string {
  if (!pid) return "a pattern";
  const kind = pid.split(":")[0] ?? "";
  const names: Record<string, string> = {
    phrase: "a recurring phrase",
    rumination: "a recurring phrase",
    recurring_phrase: "a recurring phrase",
    temporal: "a day-of-week pattern",
    topic: "a topic pattern",
    link: "a day-after pattern",
    mood_correlation: "a mood correlation",
    mood_shift: "a mood shift",
    inertia: "a mood-carryover pattern",
    instability: "a mood-swing pattern",
    avoidance: "an avoidance pattern",
    cadence: "a writing-rhythm pattern",
    coupling: "an energy–mood coupling",
    sensemaking: "a sense-making pattern",
    diversity: "an activity-variety pattern",
  };
  return names[kind] ?? "a pattern";
}

/** 2026-09-28 audit F2: phrase highlighting must survive the engine's
 *  label normalization. Pattern labels arrive punctuation/space-stripped
 *  ("can't sleep mind won't stop") while journal entries keep their
 *  punctuation ("can't sleep, mind won't stop.") — a raw includes()
 *  never matched the multi-word case (verified live: 0 <mark> elements).
 *  Fold both sides to letters+digits before comparing. 2026-09-29: the
 *  engine also ASCII-folds accented letters when it builds labels
 *  (_fold_sentiment_text: "café" → "cafe") while entries keep their
 *  accents — fold marks away on THIS side too (NFD + strip combining
 *  marks) so accented recurring phrases still match. */
function normalizeForMatch(text: string): string {
  const folded = text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
  return folded.replace(/[^a-z0-9]+/g, " ").trim();
}

function patternKey(pattern: PatternPayload, index: number): string {
  return pattern.detail.pattern_pid ?? `${pattern.kind}:${pattern.label}:${index}`;
}

/** Item 9 (clinical review 2026-09-27): the render gate for the safety
 *  row — a PHQ-9 reading whose raw item-9 response is endorsed (> 0).
 *  The phq9 check lives HERE as well as in the crypto sanitizers: the
 *  field names a PHQ-9 question, so no other instrument's row may ever
 *  render it, whatever a (hostile or future) payload carries. */
function isItem9Flagged(reading: MeasureReading): boolean {
  return reading.measure === "phq9" && (reading.item9 ?? 0) > 0;
}

function isRetryableCollectionChange(error: unknown): boolean {  // The backend signals "rows changed while paging" two ways: the
  // revision-aware `collection_changed` and the legacy code `conflict`
  // (same 409, same "…changed while paging; retry the request" detail).
  // Both are safe to answer with exactly one restart from offset zero —
  // audit L-79: retrying only the former turned the latter into a hard
  // error where a single restart was always sufficient.
  return error instanceof ApiError
    && error.status === 409
    && (error.code === "collection_changed" || error.code === "conflict");
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

/** 2026-09-26 audit L: analysis-generation rollback guard — the portal
 *  mirror of the patient clients' stateSeqGuard (web/src/stateSeqGuard.ts).
 *  AES-GCM authenticates WHO and WHAT a ciphertext belongs to, never WHICH
 *  VERSION it is: without this check a compromised server could replay an
 *  earlier, cryptographically valid patterns blob and this chart would
 *  render it as today's truth. The backend (schemas.InsightsResponse)
 *  embeds a monotonic state_seq inside the encrypted payload AND echoes
 *  the same value in the plaintext response; two checks make a rollback
 *  loud:
 *
 *    1. payload.state_seq === response.state_seq — a replayed-older blob
 *       disagrees with the row's echoed generation.
 *    2. payload.state_seq >= this session's high-water mark — even a
 *       both-copies rollback moves the value backwards. The mark is
 *       deliberately MEMORY-ONLY and per patient (this portal persists
 *       nothing — see App's storage posture), so it spans the tab's
 *       lifetime rather than the device's; a fresh page load starts a
 *       fresh mark, exactly like the patient web client's first run.
 *
 *  An absent or non-integer payload seq FAILS CLOSED: the backend has
 *  embedded state_seq in every patterns blob since the 2026-09-19
 *  contract, so a payload without one is either pre-contract legacy data
 *  or a tampered blob — neither may render as today's truth. A mismatch
 *  surfaces through the chart's honest load-error path (banner + retry),
 *  mirroring the patient client's typed freshness error. */
const INSIGHTS_FRESHNESS_ERROR =
  "this patient's pattern data failed its freshness check — it may be an older snapshot replayed by the server; sign out and back in, then contact support if it repeats";

/** Session-lifetime high-water marks per patient user id. */
const insightsHighWater = new Map<string, number>();

/** Test seam: forget the in-memory high-water marks (the mirror of the
 *  patient client's forgetAnalysisGeneration helper). */
export function resetInsightsFreshness(): void {
  insightsHighWater.clear();
}

/** 2026-09-26 audit follow-up (portal N-1): exported for the caseload
 *  scan — PatientsView.decryptInsights consumes the SAME blobs and was
 *  left unguarded, so a server replaying an older valid blob still fed
 *  stale triage data (sensitive-first sort, sensitive banner) there. */
export function verifyInsightsGeneration(
  userId: string,
  payloadSeq: unknown,
  echoedSeq: number,
): void {
  if (
    typeof payloadSeq !== "number"
    || !Number.isSafeInteger(payloadSeq)
    || payloadSeq < 0
    || payloadSeq !== echoedSeq
  ) {
    throw new Error(INSIGHTS_FRESHNESS_ERROR);
  }
  if (payloadSeq < (insightsHighWater.get(userId) ?? 0)) {
    throw new Error(INSIGHTS_FRESHNESS_ERROR);
  }
  insightsHighWater.set(userId, payloadSeq);
}

export function PatientView(props: {
  patient: Patient;
  session: PortalSession;
  onBack: () => void;
  onSignOut?: () => void;
}): React.JSX.Element {
  const { patient, session } = props;
  /** Notes-only chart mode (audit M-22, 2026-09-20): a stopped/revoked
   *  consent ends entries/patterns/measures, but the server permits this
   *  therapist's OWN notes at any consent status — and the list view
   *  promises "Your notes about this patient stay".  In this mode the
   *  insights and measures loads are skipped entirely (they would only
   *  403/404) and the pattern chrome is hidden. */
  const notesOnly = patient.status !== "active";
  const [patterns, setPatterns] = useState<PatternPayload[] | null>(null);
  const [phaseNote, setPhaseNote] = useState<string | null>(null);
  const [error, setError] = useState("");
  /** Audit fix 17 (2026-09-21): a failed CHART load (insights or notes)
   *  offers an in-page retry; drill-down and note-action failures still
   *  render the banner alone. */
  const [loadFailed, setLoadFailed] = useState(false);
  const [selected, setSelected] = useState<PatternPayload | null>(null);
  const [entries, setEntries] = useState<EntryRow[] | null>(null);
  const [notes, setNotes] = useState<OpenNote[]>([]);
  // F-6 (2026-09-21): the note draft is CONTEXT-SCOPED — one buffer for the
  // general composer, one for the pattern-anchored composer. A single
  // shared buffer used to carry general-patient text into a pattern note
  // (and back), silently mis-anchoring it.
  const [drafts, setDrafts] = useState<{ general: string; pattern: string }>({
    general: "",
    pattern: "",
  });
  const draft = selected ? drafts.pattern : drafts.general;
  const setDraft = (value: string): void => {
    setDrafts((prev) => (selected ? { ...prev, pattern: value } : { ...prev, general: value }));
  };
  const [busy, setBusy] = useState(false);
  const [newCount, setNewCount] = useState(0);
  const [lastReviewed, setLastReviewed] = useState<string | null>(null);
  /** Patient-recorded wellbeing measures (MBC, 2026-09-19), decrypted
   *  with the consent-unwrapped data key. Display only — interpretation
   *  belongs to the clinician, and the copy says so. */
  const [measures, setMeasures] = useState<MeasureReading[] | null>(null);
  /** 2026-09-26 audit L: a failed measures traversal is no longer silently
   *  "no measures" — the honest inline line names the failure without
   *  blocking the rest of the chart (patterns/notes keep rendering). */
  const [measuresError, setMeasuresError] = useState<string | null>(null);
  const [stats, setStats] = useState<{ avg_sentiment?: number; total_entries?: number; active_days?: number; first_date?: string; last_date?: string } | null>(null);
  /** Notes search filter (client-side: notes are already decrypted here). */
  const [noteQuery, setNoteQuery] = useState("");
  /** P3 (2026-09-21): the note edit history — decrypted prior texts per
   *  note id, loaded on demand from the revisions endpoint.
   *  2026-09-26 audit round (L): historyFailed records, per note id, that
   *  revisions EXISTED but could not be decrypted (cross-key or corrupt
   *  blobs) — clinically distinct from "this note was never edited", which
   *  is what an empty list must keep meaning. */
  const [history, setHistory] = useState<Record<string, string[]>>({});
  const [historyFailed, setHistoryFailed] = useState<Record<string, boolean>>({});
  const [historyBusy, setHistoryBusy] = useState<string | null>(null);
  /** The note being edited (id + textarea buffer). */
  const [editing, setEditing] = useState<{ id: string; text: string } | null>(null);
  /** Two-step delete (audit M-23, 2026-09-20): one stray click must never
   *  destroy a clinical note.  The first press only arms the confirm
   *  button for THAT note; the second press performs the DELETE. */
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  // Every async decrypt/load carries this generation.  Leaving the patient,
  // signing out, or selecting another pattern makes old plaintext results
  // ineligible to repopulate React state.
  const loadGeneration = useRef(0);
  const drilldownGeneration = useRef(0);
  /** 2026-09-26 audit round (L): the per-context idempotency key for note
   *  creation — minted on a draft's first save attempt, reused across its
   *  byte-identical retries, cleared on success or either 409 code
   *  ("conflict" / "version_conflict" — see saveNote). */
  const pendingNoteId = useRef<{ general: string | null; pattern: string | null }>({
    general: null,
    pattern: null,
  });

  const load = useCallback(async () => {
    const operation = ++loadGeneration.current;
    setError("");
    setLoadFailed(false);
    setPatterns(null);
    setPhaseNote(null);
    setStats(null);
    setNotes([]);
    setSelected(null);
    setEntries(null);
    setNoteQuery("");
    setEditing(null);
    setConfirmDeleteId(null);
    setMeasures(null);
    setMeasuresError(null);

    // Measures (MBC): loaded independently of insights so a baseline-phase
    // patient's recorded questionnaires still surface.  Skipped entirely
    // for stopped consents — the read requires an active consent.
    // 2026-09-26 audit L: the traversal runs the IDENTICAL snapshot
    // contract as entries and notes (loadStableCollection one-restart,
    // X-Measures-Revision pinning, bounded terminal probe). The old silent
    // `seen` id-dedupe heuristic is gone: a pre-paging backend that
    // ignores offsets used to be papered over client-side, which is
    // exactly the cross-snapshot drift the revision contract exists to
    // refuse — now it surfaces as an honest measures-load failure instead.
    const measuresLoad = (async (): Promise<void> => {
      try {
        if (notesOnly || !patient.ephemeral_pub || !patient.wrapped_key) return;
        // Page through EVERYTHING the server will share (audit L-76): the
        // traversal below once sliced to the newest 60 rows and silently
        // dropped the rest while the write quota kept charging them.
        const rows = await loadStableCollection(async (): Promise<PortalMeasure[]> => {
          const snapshotRows: PortalMeasure[] = [];
          let offset = 0;
          let revision: string | undefined;
          // One extra request is a bounded terminal probe: compatibility
          // mode infers a cursor from a headerless full final page, so
          // exactly twenty complete pages must be allowed to prove there is
          // no twenty-first (which is also the backend's 2_000-row quota).
          for (let page = 0; page <= MAX_MEASURE_PAGES; page += 1) {
            const currentPage = await api.patientMeasures(
              patient.user_id,
              revision === undefined ? { offset } : { offset, expectedRevision: revision },
            );
            // A revision must be present on the first modern page and stay
            // constant thereafter. A header appearing only after a legacy
            // first page cannot prove that the already-retained rows belong
            // to its snapshot, so fail rather than silently mixing
            // histories — the same fence as entries and notes.
            if (revision === undefined && currentPage.revision !== undefined) {
              if (offset !== 0) {
                throw new Error("server changed the measures pagination protocol mid-load");
              }
              revision = currentPage.revision;
            } else if (revision !== undefined && currentPage.revision !== revision) {
              throw new Error("server returned an inconsistent measures snapshot revision");
            }
            if (page === MAX_MEASURE_PAGES) {
              if (currentPage.measures.length > 0) {
                throw new Error("measure history exceeds this portal's safe page limit");
              }
              break;
            }
            snapshotRows.push(...currentPage.measures);
            if (currentPage.nextOffset === null) break;
            offset = currentPage.nextOffset;
          }
          return snapshotRows;
        });
        if (operation !== loadGeneration.current || rows.length === 0) return;
        const dataKey = await unwrapPatientDataKey(
          session.privateKey,
          patient.ephemeral_pub,
          patient.wrapped_key,
          patient.user_id,
          session.userId,
          session.publicKeyB64,
        );
        const readings: MeasureReading[] = [];
        try {
          for (const row of rows) {
            const reading = await decryptMeasure(dataKey, patient.user_id, row);
            if (reading) readings.push(reading);
          }
        } finally {
          dataKey.fill(0);
        }
        // Oldest first for the trend row.
        readings.sort((a, b) => a.measureDate.localeCompare(b.measureDate));
        if (operation === loadGeneration.current) setMeasures(readings);
      } catch (err) {
        // Measures still never block the chart — but the failure is no
        // longer silent (2026-09-26 audit L): an honest inline line says
        // the questionnaire trail could not be loaded and why.
        if (operation === loadGeneration.current) {
          setMeasuresError(err instanceof Error ? err.message : "could not load this patient's recorded measures");
        }
      }
    })();

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
        setLoadFailed(true);
      }
    });

    if (notesOnly) {
      // Stopped consent (M-22): entries/patterns/measures are gone; the
      // insights read would only fail.  Notes remain (loaded above) and
      // the header carries the honest "sharing ended" line.
      await notesLoad;
      return;
    }

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
        // 2026-09-26 audit L: rollback-replay guard — the seq embedded in
        // the decrypted payload must equal the response's plaintext echo
        // and never move backwards within this session (see
        // verifyInsightsGeneration above). A mismatch throws and lands in
        // this load's honest error path: banner + in-page retry, exactly
        // like any other failed chart load.
        verifyInsightsGeneration(patient.user_id, payload.state_seq, summary.state_seq);
        if (operation !== loadGeneration.current) return;
        const surfaced = sortForReview(payload.stats.patterns ?? []);
        // The pre-session delta (2026-09-17 fix): the stamp moves ONLY on the
        // explicit "Mark reviewed" action — a 30-second glance no longer
        // resets the delta. Storage basis per the L-75 decision: the anchor
        // is PER-TAB (a second tab or browser legitimately starts from its
        // own anchor — see portal/README.md), per-tab sessionStorage
        // (survives idle locks, dies with the browser session), falling
        // back to lock-scrubbed localStorage where sessionStorage is
        // unavailable.
        const stamp = visitAnchorStore.get(lastVisitKey(session.userId, patient.user_id));
        setLastReviewed(stamp ? dayOf(stamp) : null);
        setNewCount(stamp ? surfaced.filter((p) => p.detail.first_seen && p.detail.first_seen > stamp).length : surfaced.length);
        setStats(payload.stats);
        setPatterns(surfaced);
      }
    } catch (err) {
      if (operation === loadGeneration.current) {
        setError(err instanceof Error ? err.message : "could not load this patient");
        setLoadFailed(true);
      }
    } finally {
      await notesLoad;
      await measuresLoad;
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
  const loadHistory = useCallback(
    async (note: { id: string; client_note_id: string }) => {
      if (!session || historyBusy) return;
      setHistoryBusy(note.id);
      try {
        const revisions = await api.noteRevisions(note.id);
        const texts: string[] = [];
        try {
          for (const rev of revisions) {
            texts.push(
              await decryptNote(session.noteKey, session.userId, patient.user_id, note.client_note_id, rev.blob),
            );
          }
        } catch (err) {
          // 2026-09-26 audit round (L): the FETCH succeeded but a revision
          // blob failed to decrypt. Storing [] alone rendered "no earlier
          // text recorded" — making a corrupt/cross-key history read as a
          // never-edited note in a clinical record. Record the failure
          // distinctly (rendered as its own honest line below) and log it
          // instead of swallowing it silently.
          console.warn("note history failed to decrypt", { noteId: note.id, err });
          setHistoryFailed((prev) => ({ ...prev, [note.id]: true }));
          setHistory((prev) => ({ ...prev, [note.id]: [] }));
          return;
        }
        setHistory((prev) => ({ ...prev, [note.id]: texts }));
      } catch {
        // The revisions FETCH itself failed: an honest empty history for a
        // load that never happened (the pinned P3 degradation).
        setHistory((prev) => ({ ...prev, [note.id]: [] }));
      } finally {
        setHistoryBusy(null);
      }
    },
    [session, patient.user_id, historyBusy],
  );

  const patternNotes = useMemo(
    () => notes.filter((n) => n.pattern_pid !== null && n.pattern_pid === selectedPid),
    [notes, selectedPid],
  );
  const generalNotes = useMemo(() => notes.filter((n) => n.pattern_pid === null), [notes]);
  /** F1 (GUI drill 2026-09-28): after a revoke the pattern selector is gone,
   *  but pattern-anchored notes REMAIN — the API serves the therapist's own
   *  chart at any consent status, and the list view promises "Your notes
   *  about this patient stay". The notes-only chart therefore renders the
   *  WHOLE chart chronologically; each anchored note carries its pid so the
   *  anchor survives the pattern it once pointed at (the same coarse topic
   *  id the server already holds in plaintext). */
  const chartNotes = useMemo(
    () => (selected ? patternNotes : notesOnly ? notes : generalNotes),
    [selected, patternNotes, notesOnly, notes, generalNotes],
  );
  /** Measures grouped per instrument, newest-active instrument first
   *  (audit L-76, 2026-09-20).  The decrypted instrument name is part of
   *  the display — "14" is only interpretable next to the questionnaire
   *  that produced it, and the day a second instrument exists, one flat
   *  list would interleave unrelated scales.  `measures` arrives sorted
   *  oldest-first, so each group keeps that order; only the last
   *  MEASURE_TREND_WINDOW readings render, with the remainder counted in
   *  `hidden` for the honest "+N earlier not shown" line. */
  // P3 (2026-09-21): friendly instrument names for the MBC trend lines —
  // PHQ-9 is joined by GAD-7 (anxiety) and PHQ-2 (brief screen). Scores
  // are never interpreted; the label names the instrument only.
  const measureLabel = (instrument: string): string =>
    (
      {
        phq9: "PHQ-9 (depression)",
        gad7: "GAD-7 (anxiety)",
        phq2: "PHQ-2 (brief)",
      } as Record<string, string>
    )[instrument] ?? instrument;

  const measureGroups = useMemo(() => {
    if (!measures) return [] as { instrument: string; readings: MeasureReading[]; hidden: number }[];
    const byInstrument = new Map<string, MeasureReading[]>();
    for (const reading of measures) {
      const bucket = byInstrument.get(reading.measure);
      if (bucket) bucket.push(reading);
      else byInstrument.set(reading.measure, [reading]);
    }
    return [...byInstrument.entries()]
      .map(([instrument, readings]) => ({
        instrument,
        readings: readings.slice(-MEASURE_TREND_WINDOW),
        hidden: Math.max(0, readings.length - MEASURE_TREND_WINDOW),
      }))
      .sort((a, b) => {
        const aNewest = a.readings[a.readings.length - 1]?.measureDate ?? "";
        const bNewest = b.readings[b.readings.length - 1]?.measureDate ?? "";
        return bNewest.localeCompare(aNewest);
      });
  }, [measures]);
  const hiddenMeasureCount = measureGroups.reduce((sum, group) => sum + group.hidden, 0);

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
          // Per-item degradation (audit L-78, 2026-09-20): one
          // undecryptable entry (relocated blob, dead consent key, corrupt
          // row) used to abort the whole loop and discard every other
          // decryptable entry behind the pattern.  Notes and measures
          // already degrade per row; entries now do too.  Key-material
          // failures above remain hard errors — they affect every row.
          try {
            const payload = await decryptEntry(dataKey, patient.user_id, row);
            decrypted.push({
              id: row.id,
              entry_date: row.entry_date,
              text: payload.text,
              sentiment: payload.sentiment,
            });
          } catch {
            decrypted.push({
              id: row.id,
              entry_date: row.entry_date,
              text: "(entry could not be decrypted with this consent's key)",
              sentiment: null,
            });
          }
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
    // 2026-09-26 audit round (L): the client_note_id is allocated on the
    // FIRST save attempt of the current draft and REUSED across retries of
    // that draft (the backend contract at app/api/therapist.py — idempotency
    // on (therapist, client_note_id) for a BYTE-IDENTICAL replay — so a
    // timeout + user re-press no longer mints a second clinical note). A
    // retry is byte-identical only when the request never reached the
    // server; a manual re-press re-encrypts with a FRESH GCM nonce, and the
    // server answers different bytes under a stored id with 409
    // version_conflict (commit 7b7337a) — never an in-place rewrite. A
    // fresh id is therefore minted after a SUCCESSFUL save (the next note
    // is a new note) or either 409 (the id is burned server-side). The id
    // is scoped per draft context, like the draft buffers themselves (F-6).
    const scope = selected ? "pattern" : "general";
    if (!pendingNoteId.current[scope]) pendingNoteId.current[scope] = newNoteId();
    const clientNoteId = pendingNoteId.current[scope];
    try {
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
      pendingNoteId.current[scope] = null;
    } catch (err) {
      // Either 409 means the server rejected THIS id: "conflict" (the id
      // was already used for another patient) or "version_conflict"
      // (different bytes under the stored note — unavoidable on a manual
      // retry, since every attempt encrypts with a fresh GCM nonce).
      // Retrying with a burned id can only fail again, so the next attempt
      // mints a fresh one; without this the composer would be stuck on an
      // unsavable draft forever. Any other failure (timeout, offline) KEEPS
      // the id — that is exactly the byte-identical idempotent-retry case
      // the backend contract exists for.
      if (
        err instanceof ApiError
        && err.status === 409
        && (err.code === "conflict" || err.code === "version_conflict")
      ) {
        pendingNoteId.current[scope] = null;
      }
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
      setConfirmDeleteId(null);
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
      // base_version (deep-audit 2026-09-28): the server requires the
      // version this edit was based on; a colleague's edit that landed
      // first answers 409 version_conflict instead of silently
      // overwriting it.
      const updated = await api.updateNote(note.id, sealed.blobB64, note.version ?? 1);
      setNotes((prev) => prev.map((n) => (n.id === updated.id ? { ...updated, text: editing.text.trim() } : n)));
      setEditing(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Another therapist's edit committed first. Drop this edit and
        // reload so the winning version is visible; the editor's draft
        // text stays on screen once for a manual re-apply.
        setError("this note changed on another device while you edited it — showing the current version; re-apply your changes if still needed");
        setEditing(null);
        await load();
        return;
      }
      setError(err instanceof Error ? err.message : "could not save the note edit");
    } finally {
      setBusy(false);
    }
  };

  // 2026-09-28 audit F2: normalized on both sides (see normalizeForMatch)
  // — the raw includes() never fired for punctuation-stripped labels.
  // 2026-09-29: the GUARD tests the normalized needle, not the raw label
  // — a punctuation-only label would otherwise fold to "" and match
  // every entry ("".includes in String.prototype is always true).
  const labelMatches = (text: string, label: string): boolean => {
    const needle = normalizeForMatch(label);
    return needle.length > 0 && normalizeForMatch(text).includes(needle);
  };

  return (
    <main className="portal-main">
      <header className="portal-head">
        <div>
          <h1>{patient.username}</h1>
          <NoteText>
            {notesOnly
              ? `sharing ended ${patient.revoked_at ? dayOf(patient.revoked_at) : "recently"} — their entries and patterns are no longer reachable; your private notes below remain`
              : `sharing since ${dayOf(patient.granted_at)} · read-only — you cannot change their data`}
            {!notesOnly && newCount > 0 && ` · ${newCount} pattern${newCount === 1 ? "" : "s"} new${lastReviewed ? ` since you marked reviewed ${lastReviewed}` : " for you to review"}`}
          </NoteText>
        </div>
        <div className="no-print row row--wrap">
          <Button label="Print session summary" small onPress={printPage} />
          <Button label="Back to patients" small onPress={props.onBack} />
          {props.onSignOut && <Button label="Sign out" small danger onPress={props.onSignOut} />}
        </div>
      </header>

      {!notesOnly && (
        <div className="no-print row row--wrap mb-14">
          <Button
            label={lastReviewed ? "Mark reviewed (update the delta anchor)" : "Mark reviewed (start the delta anchor)"}
            small
            onPress={() => {
              // L-80 (2026-09-20): the anchor is the CLINICIAN-LOCAL calendar
              // date, not a UTC instant — a clinician east of UTC marking reviewed
              // in their evening must not see "yesterday" as the anchor.
              // L-75: the stamp persists in per-tab sessionStorage (it
              // survives idle locks and dies with the browser session).
              const now = localDateISO(new Date());
              visitAnchorStore.set(lastVisitKey(session.userId, patient.user_id), now);
              setLastReviewed(now);
              setNewCount(0);
            }}
          />
          <span className="hint">
            {lastReviewed
              ? `New-pattern counting is anchored to ${lastReviewed} on this computer's calendar; it moves only when you mark reviewed.`
              : "The new-pattern count anchors the first time you mark reviewed."}
          </span>
        </div>
      )}

      <ErrorBanner message={error} />
      {loadFailed && (
        // Audit fix 17 (2026-09-21): recovery from a failed load used to
        // require a reload or sign-out; the retry re-runs the whole load
        // (it invalidates any earlier generation's results itself).
        <div className="no-print mt-8">
          <Button label="Retry loading this patient" small onPress={() => void load()} />
        </div>
      )}

      {notesOnly && (
        <Card title="Sharing ended">
          <NoteText>
            This patient stopped sharing. Their journal entries, patterns, and recorded measures are no
            longer reachable; your private clinician notes below remain, and may remain in your account
            after the patient stops sharing — delete them when your records policy requires it.
          </NoteText>
        </Card>
      )}

      {phaseNote && <Card title="Baseline phase"><NoteText>{phaseNote}</NoteText></Card>}

      {measureGroups.length > 0 && (
        <Card title={`Recorded measures (${measures?.length ?? 0})`}>
          {measureGroups.map((group) => (
            <div key={group.instrument}>
              <MeasureTrend instrument={measureLabel(group.instrument)} readings={group.readings} />
              <NoteText>
                {measureLabel(group.instrument)}: {group.readings.map((m) => `${m.measureDate}: ${m.score}`).join("  ·  ")}
              </NoteText>
              {/* Item 9 (clinical review 2026-09-27): an endorsed PHQ-9
                  item 9 mandates follow-up REGARDLESS of the total — the
                  raw response now rides the payload, and each flagged
                  reading surfaces as a bordered row. This is a FACT the
                  clinician's workflow requires, surfaced verbatim: no
                  score interpretation, no diagnosis language (the app's
                  charter). Readings without the field render exactly as
                  before, and the phq9 guard lives HERE too, not only in
                  the crypto layer — a gad7 row must never show it. */}
              {group.readings.filter(isItem9Flagged).map((m) => (
                <div key={`${group.instrument}-${m.measureDate}-item9`} className="measure-flag">
                  {`${m.measureDate}: PHQ-9 item 9 endorsed (self-harm question) — follow your clinical protocol · C-SSRS follow-up recommended`}
                </div>
              ))}
            </div>
          ))}
          {hiddenMeasureCount > 0 && (
            <NoteText tone="warn">
              +{hiddenMeasureCount} earlier measure{hiddenMeasureCount === 1 ? "" : "s"} not shown — the trend shows the newest {MEASURE_TREND_WINDOW} per recorded instrument.
            </NoteText>
          )}
          <NoteText>
            Patient-recorded questionnaire scores, shared with you by consent.
            MindPattern displays them; interpretation is yours.
          </NoteText>
        </Card>
      )}

      {measuresError && !measureGroups.length && (
        // 2026-09-26 audit L: a failed measures traversal is stated
        // honestly instead of rendering as "the patient recorded nothing"
        // — the difference matters clinically (no questionnaire vs. an
        // unloadable one). Deliberately NOT a chart-level loadFailed: the
        // patterns and notes above/below are unaffected, so only this one
        // card is replaced by the explanation. The chart retry control
        // re-runs the measures load with everything else.
        <Card title="Recorded measures">
          <NoteText tone="warn">
            Could not load this patient's recorded measures — {measuresError}.
            The rest of this chart is unaffected.
          </NoteText>
        </Card>
      )}

      {stats && patterns !== null && patterns.length > 0 && (
        <Card title="Account summary">
          <NoteText>
            {stats.total_entries ?? "?"} entries · {stats.active_days ?? "?"} active days
            {typeof stats.avg_sentiment === "number" && ` · average reading ${stats.avg_sentiment.toFixed(2)}`}
            {stats.first_date && stats.last_date && ` · ${dayOf(stats.first_date)} → ${dayOf(stats.last_date)}`}
          </NoteText>
        </Card>
      )}

      {/* L-77 (2026-09-20): gate on !error — a failed insights load used to
          leave this line on screen forever beside the error banner, reading
          as an endless decrypt.  notesOnly never fetches patterns at all. */}
      {!notesOnly && patterns === null && !phaseNote && !error && (
        <NoteText>Loading decrypted patterns… (keys never leave this page)</NoteText>
      )}

      {patterns !== null && patterns.length === 0 && !phaseNote && (
        <Card title="Patterns"><NoteText>No recurring pattern has enough evidence yet.</NoteText></Card>
      )}

      {selected ? (
        <Card title={selected.detail.sensitive ? "A difficult thought has been returning" : `${selected.kind} — ${selected.label}`}>
          <NoteText>{describePattern(selected)}</NoteText>
          <dl className="evidence-grid">
            {evidenceRows(selected).map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
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
            {/* 2026-09-28 audit F3: the badge derives from the SAME local
                anchor as the header count (first_seen > anchor; everything
                counts when no anchor exists), so marking reviewed clears
                the count AND every badge together — the server-side is_new
                flag used here could stay green for a whole server
                generation after the clinician marked the chart reviewed. */}
            {(lastReviewed !== null
              ? Boolean(pattern.detail.first_seen && pattern.detail.first_seen > lastReviewed)
              : true) && (
              <NoteText tone="ok">
                {lastReviewed !== null
                  ? `new since you marked reviewed ${lastReviewed}`
                  : "new for you to review"}
              </NoteText>
            )}
            <Button label="See the evidence" small onPress={() => void openDrilldown(pattern)} />
          </Card>
        ))
      )}

      {selected && (
        // Audit fix 15 (2026-09-21): this card carries the patient's full
        // decrypted journal text — it must never reach paper.
        <Card className="no-print" title={`Evidence entries (${entries?.length ?? 0})`}>
          {/* H-13 (2026-09-20): entries without an explicit mood pick carry
              null sentiment; they are DROPPED here, never coerced to 0 —
              `?? 0` fabricated a mid-scale trend and average for patients
              who never make mood picks (the normal case on mobile). */}
          {entries !== null && (
            <MoodSparkline
              points={entries
                .filter((e): e is EntryRow & { sentiment: number } => typeof e.sentiment === "number")
                .map((e) => ({ date: e.entry_date, sentiment: e.sentiment }))}
            />
          )}
          {entries === null && <NoteText>Decrypting the entries behind this pattern…</NoteText>}
          {entries !== null && entries.length === 0 && (
            <NoteText>No decryptable entries behind this pattern (the evidence window may predate the shared corpus).</NoteText>
          )}
          {entries?.map((entry) => (
            <div key={entry.id} className="entry-row">
              <strong className="entry-date">{entry.entry_date}</strong>
              {typeof entry.sentiment === "number" && (
                <span className="entry-mood">mood {entry.sentiment.toFixed(2)}</span>
              )}
              {/* Audit fix 16 (2026-09-21): journal entries are multi-line;
                  pre-wrap keeps the patient's line breaks (.entry-text). */}
              <p className="entry-text">
                {selected && labelMatches(entry.text, selected.label) ? <mark>{entry.text}</mark> : entry.text}
              </p>
            </div>
          ))}
        </Card>
      )}

      {/* Audit fix 15 (2026-09-21): the note composer (search filter,
          templates, draft) is interactive chrome — excluded from print. */}
      <Card
        className="no-print"
        title={
          selected
            ? "Notes on this pattern"
            : notesOnly
              ? "My notes about this patient"
              : "General notes about this patient"
        }
      >
        {chartNotes.length > 2 && (
          <input
            value={noteQuery}
            onChange={(e) => setNoteQuery(e.target.value)}
            placeholder="Search notes…"
            aria-label="Search notes"
            className="input note-search"
          />
        )}
        {selected && patternNotes.length === 0 && <NoteText>No notes on this pattern yet.</NoteText>}
        {!selected && chartNotes.length === 0 && <NoteText>No notes yet.</NoteText>}
        {chartNotes
          .filter((n) => n.text.toLowerCase().includes(noteQuery.trim().toLowerCase()))
          .map((note) => (
          <div key={note.id} className="entry-row">
            {editing?.id === note.id ? (
              <>
                <textarea
                  value={editing.text}
                  onChange={(e) => setEditing({ id: note.id, text: e.target.value })}
                  placeholder="Editing note…"
                  aria-label={`Edit note from ${dayOf(note.created_at)}`}
                  rows={3}
                  className="textarea"
                />
                <div className="row mt-6">
                  <Button label={busy ? "Saving…" : "Save edit"} small onPress={() => void saveNoteEdit(note)} disabled={busy || !editing.text.trim()} />
                  <Button label="Cancel" small onPress={() => setEditing(null)} disabled={busy} />
                </div>
              </>
            ) : (
              <NoteText>{note.text}</NoteText>
            )}
            <div className="row">
              <span className="note-date">{dayOf(note.created_at)}</span>
              {/* F1 (GUI drill 2026-09-28): in the notes-only chart an
                  anchored note names its pid — the one anchor that survives
                  the ended share (never note-derived text; the pid is the
                  same coarse topic id the server already holds).
                  2026-09-28 audit F8: the pid is rendered in human terms
                  (patternAnchorLabel) — the raw "phrase:a4adc4d084fc" was
                  opaque to every reader. */}
              {notesOnly && note.pattern_pid && (
                <span className="note-anchor">on {patternAnchorLabel(note.pattern_pid)}</span>
              )}
              <Button label="Edit" small onPress={() => { setEditing({ id: note.id, text: note.text }); setConfirmDeleteId(null); }} disabled={busy} />
              {/* Final-verification 2026-09-22: the note edit history used to
                  be reachable ONLY from a button inside this screen's hidden
                  print-only block — invisible on screen, unclickable on
                  paper.  The affordance lives HERE, in the interactive
                  notes card; the printed summary renders whatever history
                  was loaded but never anything clickable. */}
              {note.updated_at > note.created_at && (
                <Button
                  label={
                    historyBusy === note.id
                      ? "Loading history…"
                      : history[note.id] === undefined
                        ? "View history"
                        : "Hide history"
                  }
                  small
                  onPress={() => {
                    if (history[note.id] !== undefined) {
                      setHistory((prev) => {
                        const next = { ...prev };
                        delete next[note.id];
                        return next;
                      });
                      setHistoryFailed((prev) => {
                        const next = { ...prev };
                        delete next[note.id];
                        return next;
                      });
                      return;
                    }
                    void loadHistory(note);
                  }}
                  disabled={busy || historyBusy === note.id}
                />
              )}
              <Button
                label={confirmDeleteId === note.id ? "Confirm delete" : "Delete"}
                small
                danger
                onPress={() => {
                  // M-23 (2026-09-20): DELETE is irreversible; the first
                  // press only arms the confirmation for THIS note.
                  if (confirmDeleteId !== note.id) {
                    setConfirmDeleteId(note.id);
                    return;
                  }
                  void removeNote(note);
                }}
                disabled={busy}
              />
              {confirmDeleteId === note.id && (
                <span className="delete-confirm">
                  Permanently delete this note? Press again to confirm.
                </span>
              )}
            </div>
            {(() => {
              const priorTexts = history[note.id];
              if (priorTexts === undefined) return null;
              if (historyFailed[note.id] === true) {
                // 2026-09-26 audit round (L): revisions existed but their
                // blobs would not decrypt — never read as "never edited".
                return (
                  <p className="history-line">
                    (earlier versions could not be decrypted)
                  </p>
                );
              }
              if (priorTexts.length === 0) {
                return (
                  <p className="history-line">
                    no earlier text recorded
                  </p>
                );
              }
              return (
                <div className="history-line">
                  {priorTexts.map((text, i) => (
                    <p key={i}>
                      previous ({i + 1}): {text}
                    </p>
                  ))}
                </div>
              );
            })()}
          </div>
        ))}
        <div className="tpl-row">
          <span className="hint tpl-row__label">Start from:</span>
          {NOTE_TEMPLATES.map((tpl) => (
            <button
              key={tpl}
              type="button"
              onClick={() => setDraft(draft.trim() ? `${draft.trimEnd()}
${tpl}` : tpl)}
              className="tpl-chip"
            >
              {tpl.split("\n")[0]!.split(":")[0]}
            </button>
          ))}
          {chartNotes.length > 0 && (
            <button
              type="button"
              onClick={() => {
                // H-13 (2026-09-20): notes arrive created_at ASCENDING, so
                // the newest note — the one "copy forward" promises — is the
                // LAST element.  `[0]` seeded the draft with the oldest
                // session's text.  F1: in the notes-only chart the pool is
                // the WHOLE chart (anchored notes included).
                const source = chartNotes.at(-1);
                if (source) setDraft(source.text);
              }}
              className="tpl-chip"
            >
              Copy forward last note
            </button>
          )}
        </div>
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={selected ? "Note about this pattern…" : "Note about this patient…"}
          aria-label={selected ? "New note about this pattern" : "New note about this patient"}
          rows={3}
          className="textarea"
        />
        <div>
          <Button label={busy ? "Saving…" : "Save note"} onPress={saveNote} disabled={busy || !draft.trim()} />
        </div>
        {/* 2026-09-28 audit F5: the full privacy/retention paragraph is one
            click away; the summary line names what matters at a glance. */}
        <Disclosure summary="How private clinician notes are encrypted">
          Private clinician notes are encrypted under YOUR password before leaving this page. They are not shared with the patient or added to their journal, and may remain in your account after the patient stops sharing; delete them when your records policy requires it.
        </Disclosure>
      </Card>

      {/* Print-only session summary (2026-09-17): everything a paper record
          needs, nothing the interactive chrome shows. Under print this is
          the ONLY visible block (audit 15, 2026-09-21). 2026-09-26 CSP
          hardening: the block's presentation lives entirely in
          public/print.css (.print-* classes — loaded via
          <link media="print"> in index.html) and in portal.css
          (.print-only { display: none } keeps it hidden on screen), so the
          inline <style> tag — and with it style-src 'unsafe-inline' — is
          gone from the chart. */}
      <div className="print-only">
        <h1>MindPattern session summary — {patient.username}</h1>
        <p className="print-meta">
          {notesOnly
            ? `Sharing ended ${patient.revoked_at ? dayOf(patient.revoked_at) : "recently"} — notes-only record`
            : `Sharing since ${dayOf(patient.granted_at)}`}{" "}
          · summary generated {localDateISO(new Date())}
          {lastReviewed && ` · delta anchored ${lastReviewed} (clinic-local date)`}
          {newCount > 0 && ` · ${newCount} new pattern${newCount === 1 ? "" : "s"}`}
        </p>
        {stats && (
          <p className="print-meta">
            {stats.total_entries ?? "?"} entries · {stats.active_days ?? "?"} active days
            {typeof stats.avg_sentiment === "number" && ` · average reading ${stats.avg_sentiment.toFixed(2)}`}
          </p>
        )}
        {/* Audit fix 15 (2026-09-21): recorded measures join the printed
            summary (same per-instrument display slice as the interactive
            card, hidden remainder disclosed) — the paper record keeps the
            measurement-based-care trail. */}
        {measureGroups.length > 0 && (
          <>
            <h2 className="print-h2">Recorded measures</h2>
            {measureGroups.map((group) => (
              <div key={group.instrument}>
                <p className="print-line">
                  {measureLabel(group.instrument)}: {group.readings.map((m) => `${m.measureDate}: ${m.score}`).join("  ·  ")}
                  {group.hidden > 0 && ` · +${group.hidden} earlier not shown`}
                </p>
                {/* Item 9 (2026-09-27): the paper record carries the same
                    flagged facts as the screen — plain text, bordered, no
                    clickable affordances (audit 15's print rule). */}
                {group.readings.filter(isItem9Flagged).map((m) => (
                  <p key={`${group.instrument}-${m.measureDate}-item9`} className="print-line print-flag">
                    {`${m.measureDate}: PHQ-9 item 9 endorsed (self-harm question) — follow your clinical protocol · C-SSRS follow-up recommended`}
                  </p>
                ))}
              </div>
            ))}
          </>
        )}
        {(patterns ?? []).map((pattern, index) => (
          <div key={patternKey(pattern, index)} className="print-item">
            <strong>{pattern.detail.sensitive ? "A difficult thought (non-quoting)" : `${pattern.kind} — ${pattern.label}`}</strong>
            <p className="print-line">{describePattern(pattern)}</p>
            <p className="print-evidence">
              {evidenceRows(pattern).map(([k, v]) => `${k}: ${v}`).join(" · ")}
            </p>
          </div>
        ))}
        {chartNotes.length > 0 && (
          <>
            <h2 className="print-h2">
              Therapist notes ({selected ? "this pattern" : notesOnly ? "all" : "general"})
            </h2>
            {chartNotes.map((note) => {
              const edited = note.updated_at > note.created_at;
              const priorTexts = history[note.id];
              return (
                <div key={note.id} className="print-note">
                  <p className="print-note-p">
                    {dayOf(note.created_at)} — {note.text}
                    {/* F1 (GUI drill 2026-09-28): the paper record carries the
                        same surviving anchor the notes-only screen shows
                        (2026-09-28 audit F8: human terms, not the raw pid). */}
                    {notesOnly && note.pattern_pid && (
                      <span className="print-edited"> · on {patternAnchorLabel(note.pattern_pid)}</span>
                    )}
                    {/* Final-verification 2026-09-22: this summary is paper —
                        it must never carry a clickable affordance (the old
                        "view history" button here was both unreachable on
                        screen, inside display:none, and dead on paper).
                        The edited marker is plain text; prior revisions
                        print only when the therapist loaded them from the
                        interactive notes card above. */}
                    {edited && (
                      <span className="print-edited">edited</span>
                    )}
                  </p>
                  {priorTexts !== undefined && priorTexts.length > 0 && (
                    <div className="print-prior">
                      {priorTexts.map((text, i) => (
                        <p key={i}>
                          previous ({i + 1}): {text}
                        </p>
                      ))}
                    </div>
                  )}
                  {priorTexts !== undefined && priorTexts.length === 0 && (
                    <p className="print-prior-line">
                      {historyFailed[note.id] === true
                        ? "(earlier versions could not be decrypted)"
                        : "no earlier text recorded"}
                    </p>
                  )}
                </div>
              );
            })}
          </>
        )}
        <p className="print-footer">
          Observations from the patient's own encrypted journal — not a diagnosis. Generated by MindPattern.
        </p>
      </div>
    </main>
  );
}
