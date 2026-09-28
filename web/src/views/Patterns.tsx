/**
 * Patterns (WEB_PLAN P6.1–6.3): the analysis surface. Baseline phase shows
 * the honest 30-day ring + the device-local mood trend (never synced);
 * post-threshold, every surfaced pattern renders as a card with its
 * lifecycle evidence label, a "Why am I seeing this?" panel (window, n,
 * effect size, confidence, method in plain language), per-pattern mute
 * (coarse pattern ids only, local), and the sensitive non-quoting
 * contract: a crisis-adjacent pattern NEVER echoes its text — it says so
 * calmly and links to support.
 *
 * M-W4 (audit 2026-09-26): the muted pid set is CONTENT-DERIVED
 * ("topic:divorce") and used to sit in plaintext localStorage — it now
 * lives in the encrypted kv seam (patternMutes.ts, data-key sealed). The
 * server-side mute sync (recordPatternMute → recompute blob) is unchanged.
 *
 * Redesign 2026-09-26: baseline progress renders as a calm progress track
 * with an SVG diverging-bar mood trend (dates + per-bar titles); the
 * disclosure is styled; sensitive patterns render on a soft lavender card
 * — the non-quoting contract is untouched.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import { decryptInsights } from "../crypto/patient";
import { matchesCrisisSuppress } from "../crisisDetect";
import { recentMoods } from "../moodLog";
import { recordPatternMute } from "../questionFeedback";
import { adoptLegacyPlaintextMutes, writeMutedPids } from "../patternMutes";
import { reconcile, type ReconcileOutcome } from "../sync";
import { recordThresholdNotice, thresholdNoticeShown } from "../thresholdNotice";
import { t } from "../strings";
import { vault } from "../vault";
import { moodFill, usePaletteVersion } from "../tokens";
import { Button, Card, ErrorBanner, Icon, Note, ProgressTrack, Skeleton } from "../ui";

/** One surfaced pattern, as the brain's encrypted payload carries it. */
export interface PatternPayload {
  kind: string;
  label: string;
  occurrences: number;
  confidence: number;
  detail: {
    pattern_pid?: string;
    pattern_state?: string;
    strength?: number;
    first_seen?: string;
    last_seen?: string;
    is_new?: boolean;
    sample_days?: number;
    evidence_dates?: string[];
    sensitive?: boolean;
    [key: string]: unknown;
  };
}

/** Lifecycle label per declared state, as CATALOG KEYS (M-W5): the copy
 *  resolves through t() so a Spanish device reads Spanish evidence
 *  labels. Unknown states fall back to the raw wire token below. */
const LIFECYCLE_KEY: Record<string, string> = {
  candidate: "insights.state.emerging",
  emerging: "insights.state.emerging",
  confirmed: "insights.stateWeb.confirmed",
  fading: "insights.state.fading",
  archived: "insights.state.fading",
};

/** Plain-language method copy per pattern kind, as catalog keys (M-W5). */
const METHOD_KEY: Record<string, string> = {
  temporal: "insights.webmethod.temporal",
  mood_correlation: "insights.webmethod.mood_correlation",
  link: "insights.webmethod.link",
  inertia: "insights.webmethod.inertia",
  energy_inertia: "insights.webmethod.energy_inertia",
  pa_inertia: "insights.webmethod.pa_inertia",
  na_inertia: "insights.webmethod.na_inertia",
  energy_mood_coupling: "insights.webmethod.energy_mood_coupling",
  sense_making: "insights.webmethod.sense_making",
  activity_diversity: "insights.webmethod.activity_diversity",
  instability: "insights.webmethod.instability",
  mood_shift: "insights.webmethod.mood_shift",
  rumination: "insights.webmethod.rumination",
  topic: "insights.webmethod.topic",
  recurring_phrase: "insights.webmethod.recurring_phrase",
  avoidance: "insights.webmethod.avoidance",
  cadence: "insights.webmethod.cadence",
};

function methodText(kind: string): string {
  const key = METHOD_KEY[kind];
  return key === undefined ? t("insights.methodFallbackWeb") : t(key);
}

/** Belt-and-braces with mobile and the backend (audit 2026-09-25): trust
 *  the payload's `sensitive` flag, but ALSO run the suppress-tier matcher on
 *  the label — an insights blob that carries a crisis-adjacent phrase
 *  without the flag (legacy payload, LLM extra, upstream regression) must
 *  still never have its text echoed by this view. */
function isSensitivePattern(pattern: PatternPayload): boolean {
  return pattern.detail.sensitive === true || matchesCrisisSuppress(pattern.label);
}

/** Diverging bar chart of the device-local mood trend (never synced):
 *  bars grow up/down from the zero baseline, colored by the mood scale. */
function MoodTrendChart({ days }: { days: { date: string; value: number }[] }): React.JSX.Element {
  const barWidth = 10;
  const gap = 4;
  const width = days.length * (barWidth + gap);
  const height = 88;
  const mid = height / 2;
  const scale = 34; // |value| ≤ 1 → max 34px of bar
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${Math.max(width, 120)} ${height + 16}`}
      role="img"
      aria-label={t("insights.localTrendA11y")}
      style={{ maxWidth: 520 }}
    >
      <line x1={0} y1={mid} x2={Math.max(width, 120)} y2={mid} className="chart__baseline" />
      {days.map((day, index) => {
        const magnitude = Math.max(2, Math.abs(day.value) * scale);
        const x = index * (barWidth + gap);
        const y = day.value >= 0 ? mid - magnitude : mid;
        return (
          <rect key={day.date} x={x} y={y} width={barWidth} height={magnitude} rx={2.5} className="chart__bar" style={{ fill: moodFill(day.value) }}>
            <title>{`${day.date}: ${day.value.toFixed(2)}`}</title>
          </rect>
        );
      })}
      <text x={0} y={height + 12} className="chart__axis">{days[0]!.date.slice(5)}</text>
      <text x={Math.max(width, 120)} y={height + 12} textAnchor="end" className="chart__axis">{days[days.length - 1]!.date.slice(5)}</text>
    </svg>
  );
}

export function PatternsView(props: { onCrisis: () => void }): React.JSX.Element {
  // The trend bars draw with JS-side palette values — re-render on theme
  // flips (auto mode included; audit 2026-09-26 fix).
  usePaletteVersion();
  const [phase, setPhase] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ activeDays: number; remaining: number } | null>(null);
  const [patterns, setPatterns] = useState<PatternPayload[] | null>(null);
  const [muted, setMuted] = useState<Set<string>>(new Set());
  const [localTrend, setLocalTrend] = useState<{ date: string; value: number }[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState("");
  const generation = useRef(0);

  const userId = vault.ownerUserId();

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    setError("");
    const outcome: ReconcileOutcome = await reconcile().catch((err: unknown) => ({
      kind: "error",
      message: err instanceof Error ? err.message : "failed",
    }) as ReconcileOutcome);
    if (generation.current !== run) return;
    if (outcome.kind === "credentialRotated" || outcome.kind === "locked") {
      setError(t("errors.sessionEndedWeb"));
      return;
    }
    if (outcome.kind === "freshness") {
      setError(t("insights.freshnessWeb"));
      return;
    }
    if (outcome.kind === "error") {
      setError(outcome.message);
      return;
    }
    if (outcome.kind === "offline") {
      setError(t("insights.offlineWeb"));
      return;
    }
    // ok: pull the decrypted summary directly for the richer fields.
    // Immediate re-check after the awaits above (audit 2026-09-26 LOW): a
    // lock that landed mid-reconcile is a quiet no-op, never
    // vault.get()'s throw as an unhandled rejection.
    if (!vault.isUnlocked()) return;
    const keys = vault.get();
    const summary = await api.insights().catch(() => null);
    if (!summary || generation.current !== run) {
      if (!summary) setError(t("insights.summaryFailedWeb"));
      return;
    }
    setPhase(summary.phase);
    setProgress({ activeDays: summary.active_days, remaining: summary.days_remaining });
    if (summary.blob) {
      try {
        const payload = await decryptInsights(keys.dataKey, owner, summary.blob);
        const stats = payload.stats as { patterns?: PatternPayload[] } | undefined;
        setPatterns(Array.isArray(stats?.patterns) ? stats!.patterns! : []);
        // The one-time threshold-crossing notice (P6.5).
        if (summary.phase !== "baseline" && !(await thresholdNoticeShown(owner))) {
          await recordThresholdNotice(owner);
          setNotice(t("insights.thresholdNotice"));
        }
      } catch {
        setError(t("insights.decryptFailedWeb"));
      }
    } else {
      setPatterns([]);
    }
    void recentMoods(keys.dataKey, owner, 30)
      .then((days) => {
        if (generation.current !== run) return;
        setLocalTrend(days.map((d) => ({ date: d.date, value: d.value })));
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const owner = vault.ownerUserId();
    // M-W4 (audit 2026-09-26): the mute set loads through the ENCRYPTED kv
    // seam (adopting any pre-fix plaintext list once, then removing it).
    if (owner && vault.isUnlocked()) {
      void adoptLegacyPlaintextMutes(vault.get().dataKey, owner).then(setMuted).catch(() => undefined);
    }
    void load();
  }, [load]);

  const toggleMute = useCallback(async (pid: string | undefined): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!pid || !owner || !vault.isUnlocked()) return;
    // independent audit 2026-09-27 (P2): fetch the keys ONCE, before any
    // await — the second vault.get() used to sit AFTER the local-persist
    // await, so a lock mid-write threw inside this void callback as an
    // unhandled rejection.
    const keys = vault.get();
    const next = new Set(muted);
    const muting = !next.has(pid);
    if (muting) next.add(pid);
    else next.delete(pid);
    setMuted(next);
    // M-W4: the local set persists as ONE data-key-encrypted blob — never
    // plaintext localStorage (the pids are content-derived theme words).
    await writeMutedPids(keys.dataKey, owner, next).catch(() => undefined);
    // A lock during that write: the UI state above stays, the server-side
    // sync is quietly skipped (the mute re-rides on the next toggle) —
    // never a throw, never a write under the zeroized shared buffer.
    if (!vault.isUnlocked()) return;
    // The mute also rides the next recompute (server-side suppression):
    await recordPatternMute(keys.dataKey, owner, pid, muting).catch(() => undefined);
  }, [muted]);

  const visible = useMemo(() => {
    if (!patterns) return null;
    return patterns.filter((pattern) => !pattern.detail.pattern_pid || !muted.has(pattern.detail.pattern_pid));
  }, [patterns, muted]);

  const mutedCount = (patterns?.length ?? 0) - (visible?.length ?? 0);

  return (
    <>
      {notice && <Note role="status" tone="ok">{notice}</Note>}
      <Card title={t("insights.titleWeb")}>
        {phase === "baseline" || phase === null ? (
          <>
            <Note role="status">{progress ? t("insights.baselineProgress", { active: progress.activeDays, remaining: progress.remaining, activeUnit: progress.activeDays === 1 ? "" : "s" }) : t("insights.baselineReading")}</Note>
            {progress && (
              <ProgressTrack
                progress={progress.activeDays + progress.remaining > 0 ? progress.activeDays / (progress.activeDays + progress.remaining) : 0}
                label={t("insights.baselineProgressA11y", { active: progress.activeDays, remaining: progress.remaining })}
              />
            )}
            {localTrend.length > 1 && <MoodTrendChart days={localTrend} />}
            {(patterns === null || localTrend.length === 0) && <Skeleton lines={2} />}
            <Note tone="muted">{t("insights.baselineNote")}</Note>
          </>
        ) : (
          <Note>{t("insights.activeIntro")}</Note>
        )}
        {mutedCount > 0 && (
          <>
            <Note tone="muted">{t(mutedCount === 1 ? "insights.mutedCountOne" : "insights.mutedCountMany", { count: mutedCount })}</Note>
            {patterns
              ?.filter((pattern) => pattern.detail.pattern_pid && muted.has(pattern.detail.pattern_pid))
              .map((pattern) => (
                <Button
                  key={pattern.detail.pattern_pid}
                  label={t("insights.unmuteLabel", { label: isSensitivePattern(pattern) ? t("insights.privatePattern") : pattern.label })}
                  onPress={() => void toggleMute(pattern.detail.pattern_pid)}
                  small
                  variant="ghost"
                />
              ))}
          </>
        )}
        <ErrorBanner message={error} />
      </Card>

      {visible?.map((pattern, index) => {
        const pid = pattern.detail.pattern_pid ?? `#${index}`;
        const stateKey = LIFECYCLE_KEY[pattern.detail.pattern_state ?? ""];
        const state = stateKey === undefined ? (pattern.detail.pattern_state ?? "") : t(stateKey);
        const method = methodText(pattern.kind);
        const sensitive = isSensitivePattern(pattern);
        return (
          <Card key={pid} title={sensitive ? t("insights.sensitiveTitle") : pattern.label} tone={sensitive ? "sensitive" : undefined}>
            {sensitive ? (
              <>
                <Note tone="warn">{t("insights.sensitiveBodyWeb")}</Note>
                <Button label={t("measures.getSupport")} onPress={props.onCrisis} small variant="ghost" />
              </>
            ) : (
              <Note>{pattern.label}</Note>
            )}
            <div className="row row--wrap">
              {state && <Note tone="muted">{`${t("insights.evidencePrefix")}: ${state}${pattern.detail.is_new ? ` · ${t("insights.newFlag").trim()}` : ""}`}</Note>}
              <Note tone="muted">{t(pattern.occurrences === 1 ? "insights.seenOne" : "insights.seenMany", { count: pattern.occurrences })}</Note>
              {pattern.detail.last_seen && <Note tone="muted">{t("insights.lastSeen", { date: pattern.detail.last_seen })}</Note>}
            </div>
            <details className="disclosure">
              <summary>
                <Icon name="chevron-down" size={14} />
                {t("insights.whySeeing")}
              </summary>
              <div className="disclosure__body">
                <Note tone="muted">{t("insights.evidenceLine", { days: pattern.detail.sample_days ?? 180, count: pattern.occurrences, confidence: (pattern.confidence * 100).toFixed(0), method, firstSeen: pattern.detail.first_seen ?? "—" })}</Note>
                <Note tone="muted">{t("insights.evidenceFootnoteWeb")}</Note>
              </div>
            </details>
            <div className="row">
              <Button label={muted.has(pattern.detail.pattern_pid ?? "") ? t("insights.unmute") : t("insights.muteVerbWeb")} onPress={() => void toggleMute(pattern.detail.pattern_pid)} small variant="ghost" />
            </div>
          </Card>
        );
      })}
      {visible !== null && visible.length === 0 && phase !== "baseline" && (
        <Card>
          <Note>{t("insights.noneYetWeb")}</Note>
        </Card>
      )}
    </>
  );
}
