/**
 * Measures (WEB_PLAN P7.1): PHQ-9 / GAD-7 / PHQ-2 questionnaires. The app
 * never interprets a score — no severity bands, no advice (the charter);
 * the trend is the patient's own data. Item 9 (self-harm) endorsement
 * gently points at the offline crisis resources AFTER the response is
 * safely saved. Scores travel encrypted under AAD "measure".
 *
 * 2026-09-26 audit LOW (offline gap): a completed questionnaire that fails
 * to send (offline / status 0) no longer dies with an error banner — the
 * record persists data-key-encrypted (pendingMeasure.ts) and is restored +
 * retried on the next mount under the SAME client_measure_id (the server
 * is idempotent by that id; mobile MeasuresScreen parity).
 *
 * Redesign 2026-09-26: instruments switch through a segmented control,
 * answers are aria-pressed chips (never the danger color), completion
 * shows a progress track, and the trend renders as a real SVG bar chart
 * with dates and the latest score highlighted.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "../crypto/core";
import { buildAad } from "../crypto/aad";
import { INSTRUMENTS, MEASURE_IDS, maxScoreForMeasure, measureComplete, measurePayload, optionSelected, safetyItemEndorsed, type MeasureId } from "../measures";
import { t } from "../strings";

const MEASURE_NAMES: Record<MeasureId, string> = {
  phq9: "PHQ-9",
  gad7: "GAD-7",
  phq2: "PHQ-2",
};
import { localDateISO } from "../dates";
import { cadenceDue, readMeasureCadence, snoozeCadence, writeMeasureCadence, type MeasureCadencePref } from "../measureCadence";
import { loadPendingMeasure, savePendingMeasure, clearPendingMeasure, type PendingMeasure } from "../pendingMeasure";
import { randomBytes } from "../platform";
import { vault } from "../vault";
import { kv,type WritePermit } from "../kvstore";
import { Button, Card, Chip, ErrorBanner, Note, ProgressTrack, SegmentedControl, Skeleton } from "../ui";

interface DecodedMeasure {
  id: string;
  measureId: MeasureId;
  score: number;
  date: string;
}

interface TrendPoint {
  score: number;
  max: number;
  date: string;
}

/** The safe walk cap for the history download (LOW a, audit 2026-09-26):
 *  20 pages of up to 100 rows each — beyond this a hostile server feeding
 *  endless continuations must hit a terminal probe, not a silent stop. */
const MAX_MEASURE_PAGES = 20;

/** Do the on-screen answers still match a pending record's picks? (The
 *  reuse gate that keeps ONE client_measure_id across a questionnaire's
 *  retries — audit 2026-09-26 LOW.) */
function samePicks(a: readonly (number | null)[], b: readonly (number | null)[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/** The patient's own trend: plain bars, dates visible, latest highlighted.
 *  No severity bands, no interpretation (charter).
 *
 *  2026-09-29 deep audit (data-viz MEDIUM): one record used to render a
 *  single ~14px bar in a 140px box — visually an EMPTY card. With < 2
 *  points the chart is a stat line instead (date + score, no SVG), and
 *  the chart itself gains a baseline and a taller plot so early trends
 *  are actually readable. The aria-label carries the numbers (the old
 *  label announced nothing quantitative to screen readers). */
function TrendChart({ points }: { points: TrendPoint[] }): React.JSX.Element {
  if (points.length < 2) {
    const only = points[0];
    return (
      <p className="chart-stat" role="img" aria-label={t("measures.trendSingleA11y", only ? { date: only.date, score: only.score, max: only.max } : { date: "", score: 0, max: 0 })}>
        {only ? t("measures.trendSingle", { date: only.date, score: only.score, max: only.max }) : ""}
      </p>
    );
  }
  const barWidth = 14;
  const gap = 6;
  const width = points.length * (barWidth + gap);
  const height = 96; // was 64: a minimum plot height that reads as data
  const values = points.map((p) => p.score / p.max);
  const a11y = t("measures.trendA11yWithValue", {
    count: points.length,
    first: points[0]!.date,
    last: points[points.length - 1]!.date,
    low: Math.round(Math.min(...values) * 100),
    high: Math.round(Math.max(...values) * 100),
    latest: points[points.length - 1]!.score,
    max: points[points.length - 1]!.max,
  });
  return (
    <svg className="chart" viewBox={`0 0 ${Math.max(width, 140)} ${height + 16}`} role="img" aria-label={a11y} style={{ maxWidth: 560 }}>
      {/* The dashed baseline the Patterns chart already has: without it a
          single row of bars floats in empty space. */}
      <line x1={0} y1={height} x2={Math.max(width, 140)} y2={height} className="chart__baseline" />
      {points.map((point, index) => {
        const magnitude = Math.max(6, Math.round((point.score / point.max) * (height - 10)));
        const x = index * (barWidth + gap);
        const isLast = index === points.length - 1;
        return (
          <g key={point.date + index}>
            <rect x={x} y={height - magnitude} width={barWidth} height={magnitude} rx={3.5} className={`chart__bar${isLast ? " chart__bar--last" : ""}`}>
              <title>{`${point.date}: ${point.score}/${point.max}`}</title>
            </rect>
            {isLast && (
              <text x={x + barWidth / 2} y={height - magnitude - 5} textAnchor="middle" className="chart__axis">
                {point.score}
              </text>
            )}
          </g>
        );
      })}
      <text x={0} y={height + 12} className="chart__axis">{points[0]!.date.slice(5)}</text>
      <text x={Math.max(width, 140)} y={height + 12} textAnchor="end" className="chart__axis">{points[points.length - 1]!.date.slice(5)}</text>
    </svg>
  );
}

export function MeasuresView(props: { onCrisis: () => void }): React.JSX.Element {
  const [active, setActive] = useState<MeasureId>("phq9");
  const [responses, setResponses] = useState<(number | null)[]>([]);
  const [history, setHistory] = useState<DecodedMeasure[] | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);
  const [item9, setItem9] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // The opt-in check-in cadence (clinical review 2026-09-27): the
  // preference loads once per mount; the banner it gates on is computed
  // LOCALLY from the history this view already decrypts. null = not yet
  // read (no banner).
  const [cadence, setCadence] = useState<MeasureCadencePref | null>(null);
  const generation = useRef(0);
  // The pending-record machinery (audit 2026-09-26 LOW): the record for
  // the questionnaire currently in flight, and a mount-once guard for the
  // restore+retry effect below.
  const pendingRef = useRef<PendingMeasure | null>(null);
  const retriedRef = useRef(false);
  // When the restore path seeds responses for a specific instrument, the
  // [active]-reset effect must not wipe them one commit later.
  const restoreSeedRef = useRef<MeasureId | null>(null);

  const instrument = INSTRUMENTS[active];
  const itemText = (index: number): string => t(`measures.${active}.item${index + 1}`);
  const optionLabel = (value: number): string => t(`measures.option${value}`);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    setError("");
    const keys = vault.get();
    const decoded: DecodedMeasure[] = [];
    try {
      let revision: string | undefined;
      let offset = 0;
      let complete = false;
      for (let page = 0; page < MAX_MEASURE_PAGES; page += 1) {
        const result = await api.listMeasuresPage({ offset, ...(revision !== undefined ? { expectedRevision: revision } : {}) });
        if (generation.current !== run) return;
        revision = result.revision;
        for (const row of result.measures) {
          // 2026-09-28 audit (LOW): re-check the lock inside the per-row
          // loop — keys.dataKey is the vault's SHARED buffer, and a lock
          // landing mid-walk zeroizes it, so every remaining row would
          // fail GCM and be skipped as tampered/foreign. A locked vault
          // stops the walk with the honest locked message instead; the
          // rows already decrypted still render.
          if (!vault.isUnlocked()) {
            decoded.sort((a, b) => a.date.localeCompare(b.date));
            setHistory(decoded);
            setError(t("common.sessionLocked"));
            return;
          }
          try {
            let plain: Bytes | null = null;
            try {
              plain = await decrypt(keys.dataKey, fromBase64(row.blob), buildAad("measure", owner, row.client_measure_id));
              const payload = JSON.parse(new TextDecoder().decode(plain)) as { measure?: unknown; score?: unknown };
              if (typeof payload.measure === "string" && (MEASURE_IDS as readonly string[]).includes(payload.measure) && typeof payload.score === "number") {
                // Score-ceiling honesty (mobile contract): a phq2 row must
                // never render a phq9-scale number — out-of-range rows are
                // corrupt or hostile and are skipped, never clamped.
                const ceiling = maxScoreForMeasure(payload.measure);
                if (ceiling !== null && payload.score >= 0 && payload.score <= ceiling) {
                  decoded.push({ id: row.id, measureId: payload.measure as MeasureId, score: payload.score, date: row.measure_date });
                }
              }
            } finally {
              zeroize(plain);
            }
          } catch {
            // Tampered/foreign row: skipped, never rendered.
          }
        }
        if (result.nextOffset === null) {
          complete = true;
          break;
        }
        offset = result.nextOffset;
      }
      // LOW a (audit 2026-09-26): the walk hit its page cap without a
      // terminal page — a hostile server that keeps returning continuations
      // must not park this view paging forever, and a legitimate end must
      // be PROVEN. Port of the entries-walk terminal probe (api/client.ts
      // listEntriesWalk): one extra page decides "complete" vs "lying
      // continuation" (loud error, terminal handler above renders it).
      if (!complete) {
        const probe = await api.listMeasuresPage({ offset, ...(revision !== undefined ? { expectedRevision: revision } : {}) });
        if (generation.current !== run) return;
        if (probe.measures.length !== 0 || probe.nextOffset !== null) {
          // A plain Error (not ApiError): the terminal handler below must
          // render THIS text verbatim, not classify it as offline/5xx.
          throw new Error(t("measures.walkLimit"));
        }
      }
      if (generation.current !== run) return;
      decoded.sort((a, b) => a.date.localeCompare(b.date));
      setHistory(decoded);
    } catch (err) {
      if (generation.current !== run) return;
      // M-W1 (audit 2026-09-26): EVERY terminal failure leaves the screen
      // honest — history becomes [] with the error, never a permanent
      // "Loading…" (a 500/429/409 used to wedge the view; mirrors
      // History.tsx's terminal-failure handling).
      setHistory([]);
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
      } else if (err instanceof ApiError && err.status === 0) {
        setError(t("measures.loadOffline"));
      } else {
        setError(err instanceof Error ? err.message : t("measures.loadFailed"));
      }
    }
  }, []);

  useEffect(() => {
    // Skip the form reset exactly once when the restore path just seeded
    // this instrument's answers (audit 2026-09-26 LOW) — otherwise the
    // restored questionnaire would render blank one commit later.
    const seeded = restoreSeedRef.current === active;
    restoreSeedRef.current = null;
    if (seeded) return;
    setResponses(new Array(instrument.items).fill(null));
    setItem9(false);
    setSavedNote(null);
  }, [active, instrument.items]);

  useEffect(() => {
    void load();
  }, [load]);

  // The cadence preference is account-local non-content state (see
  // measureCadence.ts) — read once per mount, best-effort.
  useEffect(() => {
    const owner = vault.ownerUserId();
    if (!owner) return;
    void readMeasureCadence(owner).then(setCadence).catch(() => undefined);
  }, []);

  /** "Not now": a three-day snooze, persisted in the same slot so it
   *  survives remounts. The in-memory state hides the banner immediately;
   *  a failed persist merely re-shows it on the next mount (fail toward
   *  showing, like the crisis throttle). */
  const dismissCadence = async (): Promise<void> => {
    if (cadence === null) return;
    const owner = vault.ownerUserId();
    const snoozed = snoozeCadence(cadence);
    setCadence(snoozed);
    if (owner) await writeMeasureCadence(owner, snoozed).catch(() => undefined);
  };

  const answer = (index: number, value: number): void => {
    setResponses((current) => current.map((existing, i) => (i === index ? value : existing)));
  };

  const answeredCount = responses.filter((value) => value !== null).length;

  /** Record the completed questionnaire. `retryOf` (the mount-retry path)
   *  sends a specific persisted record; a plain tap reuses the pending
   *  record when the on-screen answers still match it, so the SAME
   *  client_measure_id rides every attempt of one questionnaire (the
   *  server is idempotent by that id). */
  const save = async (retryOf?: PendingMeasure): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    const reusable =
      retryOf ??
      (pendingRef.current !== null && pendingRef.current.kind === active && samePicks(pendingRef.current.picks, responses)
        ? pendingRef.current
        : undefined);
    if (reusable === undefined && !measureComplete(active, responses)) {
      setError(t("measures.incomplete"));
      return;
    }
    setBusy(true);
    setError("");
    // Hoisted for the catch paths (try and catch are separate scopes): the
    // 409 branch must clear the very pending record this send used.
    const record: PendingMeasure =
      reusable ?? {
        kind: active,
        clientMeasureId: `m-${localDateISO()}-${toBase64(randomBytes(6)).replace(/[^a-zA-Z0-9]/g, "").slice(0, 8)}`,
        picks: responses as number[],
        date: localDateISO(),
      };
    let writePermit:WritePermit|undefined;
    try {
      // independent audit 2026-09-27 (P1): snapshot the data key BEFORE the
      // awaits — vault.get()'s buffers are SHARED, and a lock landing during
      // the persist await zeroizes them, which used to encrypt the
      // questionnaire under 32 zero bytes, POST it, and then destroy the
      // pending retry record. The snapshot (plus the re-check below) closes
      // both halves; the copy is zeroized in the inner finally.
      const keys = vault.get();
      const dataKey = new Uint8Array(new ArrayBuffer(keys.dataKey.length));
      dataKey.set(keys.dataKey);
      try {
        writePermit=await kv.captureWritePermit(owner,dataKey);
        // Persist BEFORE the send (a status-0 failure can be a timeout AFTER
        // the server committed; the stable id is what makes every retry
        // idempotent). A persistence failure never blocks the send — the
        // answers are also still on screen.
        pendingRef.current = record;
        await savePendingMeasure(dataKey, owner, record).catch(() => undefined);
        // A lock during the persist: KEEP the pending record, skip the send,
        // and say so honestly — never a POST under a dead key.
        if (!vault.isUnlocked()) {
          setError(t("measures.saveLockedNote"));
          return;
        }
        // measurePayload returns the canonical JSON string itself:
        const encoded = new TextEncoder().encode(measurePayload(record.kind, record.picks, new Date().toISOString()));
        try {
          const blob = await encrypt(dataKey, encoded, buildAad("measure", owner, record.clientMeasureId));
          await api.createMeasure(record.clientMeasureId, toBase64(blob), record.date);
        } finally {
          zeroize(encoded);
        }
        await clearPendingMeasure(owner,writePermit).catch(() => undefined);
        pendingRef.current = null;
        // Item 9 (self-harm) endorsement: point at support AFTER the save.
        if (safetyItemEndorsed(record.kind, record.picks)) setItem9(true);
        setSavedNote(t("measures.savedNote"));
        await load();
      } finally {
        zeroize(dataKey);
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Idempotent retry of a send that already landed: the record dies
        // here too, or every mount would retry it forever.
        await clearPendingMeasure(owner,writePermit).catch(() => undefined);
        pendingRef.current = null;
        setSavedNote(t("measures.alreadyToday"));
        await load();
        return;
      }
      if (err instanceof ApiError && err.status === 0) {
        // Offline submit failure: a quiet inline status, never a dead end.
        // The picks stay selected and the pending record stays persisted —
        // the next mount restores and retries them under the same id
        // (audit 2026-09-26 LOW; mobile parity).
        // 2026-10-01 audit M4: the answers ARE safely stored (the encrypted
        // pending record above), so an item-9 endorsement shows the support
        // card NOW — offline must not delay the pointer indefinitely.
        if (safetyItemEndorsed(record.kind, record.picks)) setItem9(true);
        setSavedNote(t("measures.pendingOfflineNote"));
        return;
      }
      setError(err instanceof Error ? err.message : t("measures.saveFailed"));
    } finally {
      setBusy(false);
    }
  };

  // 2026-09-26 audit LOW: restore + retry a persisted pending questionnaire
  // once per mount. The answers come back on screen (the honest restore)
  // and the send uses the SAME client_measure_id (idempotent by contract).
  // Offline again → the record simply stays for the next mount; the
  // restored picks keep the flow resumable either way.
  useEffect(() => {
    if (retriedRef.current) return;
    retriedRef.current = true;
    void (async () => {
      try {
        const owner = vault.ownerUserId();
        if (!owner || !vault.isUnlocked()) return;
        const pending = await loadPendingMeasure(vault.get().dataKey, owner);
        if (pending === null) return;
        restoreSeedRef.current = pending.kind;
        setActive(pending.kind);
        setResponses(pending.picks);
        await save(pending);
      } catch {
        // Locked vault / dead storage: the record stays; nothing to show.
      }
    })();
    // Stryker disable next-line ArrayDeclaration: a mount-once flow guarded by retriedRef — the effect body is idempotent under a double fire
  }, []);

  const trend = (id: MeasureId): TrendPoint[] | null => {
    if (!history) return null;
    return history.filter((row) => row.measureId === id).map((row) => ({ score: row.score, max: INSTRUMENTS[id].maxScore, date: row.date.slice(0, 10) }));
  };

  // The cadence fact: the LAST completed measure (any instrument), taken
  // from the already-decrypted history. undefined = history not loaded (a
  // banner must never render over an unknown); null = none completed yet
  // (the first check-in is available).
  const lastCompletedDate =
    history === null ? undefined : history.length > 0 ? history[history.length - 1]!.date.slice(0, 10) : null;
  const showCadenceBanner = cadence !== null && !error && cadenceDue(cadence, lastCompletedDate);

  return (
    <>
      {item9 && (
        <Card title={t("measures.item9Title")} tone="sensitive">
          <Note tone="warn">{t("measures.item9Body")}</Note>
          <Button label={t("measures.getSupport")} onPress={props.onCrisis} small />
        </Card>
      )}
      {showCadenceBanner && (
        <Card title={t("measures.cadenceTitle")}>
          <Note>{t("measures.cadenceBody")}</Note>
          <Button label={t("common.notNow")} onPress={() => void dismissCadence()} small variant="ghost" />
        </Card>
      )}
      <Card title={t("settings.measures")}>
        <SegmentedControl
          options={MEASURE_IDS.map((id) => ({ id, label: MEASURE_NAMES[id] }))}
          activeId={active}
          onSelect={(id) => setActive(id as MeasureId)}
          a11yLabel={t("settings.measures")}
        />
        <Note tone="muted">{t("measures.introWeb")}</Note>
        {Array.from({ length: instrument.items }, (_, index) => (
          <div key={index} className="stack" style={{ gap: "var(--space-2)" }}>
            <Note>{itemText(index)}</Note>
            <div className="row row--wrap">
              {instrument.options.map((option) => (
                <Chip
                  key={option}
                  label={optionLabel(option)}
                  selected={optionSelected(responses, index, option)}
                  onPress={() => answer(index, option)}
                />
              ))}
            </div>
          </div>
        ))}
        <ProgressTrack
          progress={instrument.items > 0 ? answeredCount / instrument.items : 0}
          label={t("measures.progressA11y", { answered: answeredCount, total: instrument.items })}
        />
        <span className="note note--muted">{t("measures.progressNote", { answered: answeredCount, total: instrument.items })}</span>
        <ErrorBanner message={error} />
        {savedNote && <Note role="status" tone="ok">{savedNote}</Note>}
        <Button label={busy ? t("entry.saving") : t("measures.save")} onPress={() => void save()} disabled={busy} block />
      </Card>

      <Card title={t("measures.trendTitle")}>
        {history === null && (
          <>
            <Note role="status">{t("common.loading")}</Note>
            <Skeleton lines={3} title />
          </>
        )}
        {history?.length === 0 && <Note>{t("measures.emptyNote")}</Note>}
        {MEASURE_IDS.map((id) => {
          const rows = trend(id);
          if (!rows || rows.length === 0) return null;
          return (
            <div key={id} className="stack" style={{ gap: "var(--space-2)" }}>
              <Note tone="muted">{t(rows.length === 1 ? "measures.trendOne" : "measures.trendMany", { name: MEASURE_NAMES[id], count: rows.length })}</Note>
              <TrendChart points={rows} />
            </div>
          );
        })}
        <Note tone="muted">{t("measures.interpretationNote")}</Note>
      </Card>
    </>
  );
}
