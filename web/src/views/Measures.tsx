/**
 * Measures (WEB_PLAN P7.1): PHQ-9 / GAD-7 / PHQ-2 questionnaires. The app
 * never interprets a score — no severity bands, no advice (the charter);
 * the trend is the patient's own data. Item 9 (self-harm) endorsement
 * gently points at the offline crisis resources AFTER the response is
 * safely saved. Scores travel encrypted under AAD "measure".
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "../crypto/core";
import { buildAad } from "../crypto/aad";
import { INSTRUMENTS, MEASURE_IDS, maxScoreForMeasure, measureComplete, measurePayload, safetyItemEndorsed, type MeasureId } from "../measures";
import { t } from "../strings";

const MEASURE_NAMES: Record<MeasureId, string> = {
  phq9: "PHQ-9",
  gad7: "GAD-7",
  phq2: "PHQ-2",
};
import { localDateISO } from "../dates";
import { randomBytes } from "../platform";
import { vault } from "../vault";
import { theme, Button, Card, ErrorBanner, Note } from "../ui";

interface DecodedMeasure {
  id: string;
  measureId: MeasureId;
  score: number;
  date: string;
}

interface InstrumentScores {
  score: number;
  max: number;
}

/** The safe walk cap for the history download (LOW a, audit 2026-09-26):
 *  20 pages of up to 100 rows each — beyond this a hostile server feeding
 *  endless continuations must hit a terminal probe, not a silent stop. */
const MAX_MEASURE_PAGES = 20;

export function MeasuresView(props: { onCrisis: () => void }): React.JSX.Element {
  const [active, setActive] = useState<MeasureId>("phq9");
  const [responses, setResponses] = useState<(number | null)[]>([]);
  const [history, setHistory] = useState<DecodedMeasure[] | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);
  const [item9, setItem9] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);

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
    setResponses(new Array(instrument.items).fill(null));
    setItem9(false);
    setSavedNote(null);
  }, [active, instrument.items]);

  useEffect(() => {
    void load();
  }, [load]);

  const answer = (index: number, value: number): void => {
    setResponses((current) => current.map((existing, i) => (i === index ? value : existing)));
  };

  const save = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    if (!measureComplete(active, responses)) {
      setError(t("measures.incomplete"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const keys = vault.get();
      const clientMeasureId = `m-${localDateISO()}-${toBase64(randomBytes(6)).replace(/[^a-zA-Z0-9]/g, "").slice(0, 8)}`;
      // measurePayload returns the canonical JSON string itself:
      const encoded = new TextEncoder().encode(measurePayload(active, responses, new Date().toISOString()));
      try {
        const blob = await encrypt(keys.dataKey, encoded, buildAad("measure", owner, clientMeasureId));
        await api.createMeasure(clientMeasureId, toBase64(blob), localDateISO());
      } finally {
        zeroize(encoded);
      }
      // Item 9 (self-harm) endorsement: point at support AFTER the save.
      if (safetyItemEndorsed(active, responses)) setItem9(true);
      setSavedNote(t("measures.savedNote"));
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setSavedNote(t("measures.alreadyToday"));
      } else {
        setError(err instanceof Error ? err.message : t("measures.saveFailed"));
      }
    } finally {
      setBusy(false);
    }
  };

  const trend = (id: MeasureId): InstrumentScores[] | null => {
    if (!history) return null;
    return history.filter((row) => row.measureId === id).map((row) => ({ score: row.score, max: INSTRUMENTS[id].maxScore }));
  };

  return (
    <>
      {item9 && (
        <Card title={t("measures.item9Title")}>
          <Note tone="warn">{t("measures.item9Body")}</Note>
          <Button label={t("measures.getSupport")} onPress={props.onCrisis} small />
        </Card>
      )}
      <Card title={t("settings.measures")}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {MEASURE_IDS.map((id) => (
            <Button key={id} label={MEASURE_NAMES[id]} onPress={() => setActive(id)} small disabled={active === id} />
          ))}
        </div>
        <Note tone="muted">{t("measures.introWeb")}</Note>
        {Array.from({ length: instrument.items }, (_, index) => (
          <div key={index} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Note>{itemText(index)}</Note>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {instrument.options.map((option, optionIndex) => (
                <Button
                  key={option}
                  label={optionLabel(option)}
                  small
                  danger={responses[index] === optionIndex}
                  onPress={() => answer(index, optionIndex)}
                />
              ))}
            </div>
          </div>
        ))}
        <ErrorBanner message={error} />
        {savedNote && <Note role="status" tone="ok">{savedNote}</Note>}
        <Button label={busy ? t("entry.saving") : t("measures.save")} onPress={() => void save()} disabled={busy} />
      </Card>

      <Card title={t("measures.trendTitle")}>
        {history === null && <Note role="status">{t("common.loading")}</Note>}
        {history?.length === 0 && <Note>{t("measures.emptyNote")}</Note>}
        {MEASURE_IDS.map((id) => {
          const rows = trend(id);
          if (!rows || rows.length === 0) return null;
          return (
            <div key={id} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <Note tone="muted">{t(rows.length === 1 ? "measures.trendOne" : "measures.trendMany", { name: MEASURE_NAMES[id], count: rows.length })}</Note>
              <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 48 }}>
                {rows.map((row, index) => (
                  <div
                    key={index}
                    title={`${row.score}/${row.max}`}
                    style={{
                      width: 14,
                      height: `${Math.max(8, Math.round((row.score / row.max) * 100))}%`,
                      backgroundColor: theme.accentBright,
                      borderRadius: 3,
                    }}
                  />
                ))}
              </div>
            </div>
          );
        })}
        <Note tone="muted">{t("measures.interpretationNote")}</Note>
      </Card>
    </>
  );
}
