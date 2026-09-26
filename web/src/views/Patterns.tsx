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
import { theme, Button, Card, ErrorBanner, Note } from "../ui";

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
 * the payload's `sensitive` flag, but ALSO run the suppress-tier matcher on
 * the label — an insights blob that carries a crisis-adjacent phrase
 * without the flag (legacy payload, LLM extra, upstream regression) must
 * still never have its text echoed by this view. */
function isSensitivePattern(pattern: PatternPayload): boolean {
  return pattern.detail.sensitive === true || matchesCrisisSuppress(pattern.label);
}

export function PatternsView(props: { onCrisis: () => void }): React.JSX.Element {
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
    const next = new Set(muted);
    const muting = !next.has(pid);
    if (muting) next.add(pid);
    else next.delete(pid);
    setMuted(next);
    // M-W4: the local set persists as ONE data-key-encrypted blob — never
    // plaintext localStorage (the pids are content-derived theme words).
    await writeMutedPids(vault.get().dataKey, owner, next).catch(() => undefined);
    // The mute also rides the next recompute (server-side suppression):
    await recordPatternMute(vault.get().dataKey, owner, pid, muting).catch(() => undefined);
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
            {localTrend.length > 1 && (
              <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 48 }} aria-label={t("insights.localTrendA11y")}>
                {localTrend.map((day) => (
                  <div
                    key={day.date}
                    title={`${day.date}: ${day.value.toFixed(2)}`}
                    style={{
                      width: 10,
                      height: `${Math.max(8, Math.round(50 + day.value * 50))}%`,
                      backgroundColor: day.value >= 0 ? "#8fc7a8" : "#dba89c",
                      borderRadius: 3,
                    }}
                  />
                ))}
              </div>
            )}
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
          <Card key={pid} title={sensitive ? t("insights.sensitiveTitle") : pattern.label}>
            {sensitive ? (
              <>
                <Note tone="warn">{t("insights.sensitiveBodyWeb")}</Note>
                <Button label={t("measures.getSupport")} onPress={props.onCrisis} small />
              </>
            ) : (
              <Note>{pattern.label}</Note>
            )}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {state && <Note tone="muted">{`${t("insights.evidencePrefix")}: ${state}${pattern.detail.is_new ? ` · ${t("insights.newFlag").trim()}` : ""}`}</Note>}
              <Note tone="muted">{t(pattern.occurrences === 1 ? "insights.seenOne" : "insights.seenMany", { count: pattern.occurrences })}</Note>
              {pattern.detail.last_seen && <Note tone="muted">{t("insights.lastSeen", { date: pattern.detail.last_seen })}</Note>}
            </div>
            <details style={{ color: theme.muted, fontSize: 13 }}>
              <summary style={{ cursor: "pointer" }}>{t("insights.whySeeing")}</summary>
              <Note tone="muted">{t("insights.evidenceLine", { days: pattern.detail.sample_days ?? 180, count: pattern.occurrences, confidence: (pattern.confidence * 100).toFixed(0), method, firstSeen: pattern.detail.first_seen ?? "—" })}</Note>
              <Note tone="muted">{t("insights.evidenceFootnoteWeb")}</Note>
            </details>
            <div style={{ display: "flex", gap: 8 }}>
              <Button label={muted.has(pattern.detail.pattern_pid ?? "") ? t("insights.unmute") : t("insights.muteVerbWeb")} onPress={() => void toggleMute(pattern.detail.pattern_pid)} small />
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
