/**
 * Patterns (WEB_PLAN P6.1–6.3): the analysis surface. Baseline phase shows
 * the honest 30-day ring + the device-local mood trend (never synced);
 * post-threshold, every surfaced pattern renders as a card with its
 * lifecycle evidence label, a "Why am I seeing this?" panel (window, n,
 * effect size, confidence, method in plain language), per-pattern mute
 * (coarse pattern ids only, local), and the sensitive non-quoting
 * contract: a crisis-adjacent pattern NEVER echoes its text — it says so
 * calmly and links to support.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { decryptInsights, type InsightsPayload } from "../crypto/patient";
import { recentMoods } from "../moodLog";
import { recordPatternMute } from "../questionFeedback";
import { reconcile, type ReconcileOutcome } from "../sync";
import { recordThresholdNotice, thresholdNoticeShown } from "../thresholdNotice";
import { localStore } from "../platform";
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

const LIFECYCLE_LABEL: Record<string, string> = {
  candidate: "early evidence",
  emerging: "early evidence",
  confirmed: "established",
  fading: "fading",
  archived: "fading",
};

const METHOD_PLAIN: Record<string, string> = {
  temporal: "Compared how often this word appears on each weekday against your own writing schedule, with multiple-testing correction across every claim.",
  mood_correlation: "Compared your mood on days this appears versus days it doesn't — always against your own baseline, never anyone else's.",
  link: "Compared how you write the DAY AFTER this appears against your own baseline days.",
  inertia: "Measured how strongly your mood carries over from one day to the next, compared with your own earlier norm.",
  energy_inertia: "Measured how strongly your energy carries over day to day, compared with your own earlier norm.",
  pa_inertia: "Measured how strongly your positive feelings carry over day to day, compared with your own earlier norm.",
  na_inertia: "Measured how strongly your negative feelings carry over day to day, compared with your own earlier norm.",
  energy_mood_coupling: "Measured how much your energy and mood move together, compared with your own earlier norm.",
  sense_making: "Measured how much your writing leans on cause-and-effect and insight words, compared with your own earlier norm.",
  activity_diversity: "Measured the variety of your tagged activities per week, compared with your own earlier weeks.",
  instability: "Measured the size of your day-to-day mood swings, compared with your own earlier norm.",
  mood_shift: "Watched your mood against your personal baseline with a control chart that flags sustained shifts.",
  rumination: "Found a negative thought-phrase that keeps returning in near-identical form.",
  topic: "Found a word or phrase taking up more space in your writing than it used to.",
  recurring_phrase: "Found a phrase that keeps returning in near-identical form.",
  avoidance: "Noticed you tend to go quiet the day after this comes up, compared with your own usual rhythm.",
  cadence: "Compared how regular your writing rhythm is against your own earlier norm.",
};

function muteKey(userId: string): string {
  return `mindpattern.mutedPids.v1.${userId}`;
}

function readMuted(userId: string): Set<string> {
  try {
    const raw = localStore.get(muteKey(userId));
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? new Set(parsed.filter((x): x is string => typeof x === "string")) : new Set();
  } catch {
    return new Set();
  }
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
      setError("Your session locked — sign in again.");
      return;
    }
    setError("");
    const outcome: ReconcileOutcome = await reconcile().catch((err: unknown) => ({
      kind: "error",
      message: err instanceof Error ? err.message : "failed",
    }) as ReconcileOutcome);
    if (generation.current !== run) return;
    if (outcome.kind === "credentialRotated" || outcome.kind === "locked") {
      setError("Your session ended — sign in again.");
      return;
    }
    if (outcome.kind === "freshness") {
      setError("Your pattern data failed its freshness check — it may have been replayed. Try again in a moment.");
      return;
    }
    if (outcome.kind === "error") {
      setError(outcome.message);
      return;
    }
    if (outcome.kind === "offline") {
      setError("Offline — patterns need a connection to refresh.");
      return;
    }
    // ok: pull the decrypted summary directly for the richer fields.
    const keys = vault.get();
    const summary = await api.insights().catch(() => null);
    if (!summary || generation.current !== run) {
      if (!summary) setError("Could not read your pattern summary.");
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
          setNotice("Your patterns are live — thirty honest days of data, computed only from your own writing. Every card shows its evidence.");
        }
      } catch {
        setError("Your pattern data could not be decrypted.");
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
    if (owner) setMuted(readMuted(owner));
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
    localStore.set(muteKey(owner), JSON.stringify([...next]));
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
      <Card title="Patterns">
        {phase === "baseline" || phase === null ? (
          <>
            <Note role="status">{progress ? `Building your baseline: ${progress.activeDays} active day${progress.activeDays === 1 ? "" : "s"}, ${progress.remaining} to go before patterns surface.` : "Reading your baseline…"}</Note>
            {localTrend.length > 1 && (
              <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 48 }} aria-label="Your local mood trend">
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
            <Note tone="muted">This trend is computed on this device from your entries and is never synced. Patterns need 30 active days — honest data takes time.</Note>
          </>
        ) : (
          <Note>{"Observations, not verdicts — computed only from your own writing. Every card shows its evidence."}</Note>
        )}
        {mutedCount > 0 && (
          <>
            <Note tone="muted">{`${mutedCount} pattern${mutedCount === 1 ? "" : "s"} muted — they stay muted on this browser and in future analyses after your next refresh.`}</Note>
            {patterns
              ?.filter((pattern) => pattern.detail.pattern_pid && muted.has(pattern.detail.pattern_pid))
              .map((pattern) => (
                <Button
                  key={pattern.detail.pattern_pid}
                  label={`Unmute: ${pattern.detail.sensitive === true ? "a private pattern" : pattern.label}`}
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
        const state = LIFECYCLE_LABEL[pattern.detail.pattern_state ?? ""] ?? pattern.detail.pattern_state ?? "";
        const method = METHOD_PLAIN[pattern.kind] ?? "Computed within your own journal, against your own baseline.";
        const sensitive = pattern.detail.sensitive === true;
        return (
          <Card key={pid} title={sensitive ? "A difficult thought has been returning" : pattern.label}>
            {sensitive ? (
              <>
                <Note tone="warn">{"Something heavy shows up repeatedly in your writing. It is not quoted here — you deserve to decide when to look at it."}</Note>
                <Button label="Get support" onPress={props.onCrisis} small />
              </>
            ) : (
              <Note>{pattern.label}</Note>
            )}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {state && <Note tone="muted">{`evidence: ${state}${pattern.detail.is_new ? " · new" : ""}`}</Note>}
              <Note tone="muted">{`seen ${pattern.occurrences} time${pattern.occurrences === 1 ? "" : "s"}`}</Note>
              {pattern.detail.last_seen && <Note tone="muted">{`last: ${pattern.detail.last_seen}`}</Note>}
            </div>
            <details style={{ color: theme.muted, fontSize: 13 }}>
              <summary style={{ cursor: "pointer" }}>Why am I seeing this?</summary>
              <Note tone="muted">{`Window: the last ${pattern.detail.sample_days ?? 180} days of your journal. Sample: ${pattern.occurrences} occurrences. Confidence: ${(pattern.confidence * 100).toFixed(0)}%. Method: ${method} First seen: ${pattern.detail.first_seen ?? "—"}.`}</Note>
              <Note tone="muted">{"No advice, no diagnosis, no prediction — an observation with its evidence. Mute it below if it is not useful."}</Note>
            </details>
            <div style={{ display: "flex", gap: 8 }}>
              <Button label={muted.has(pattern.detail.pattern_pid ?? "") ? "Unmute" : "Mute"} onPress={() => void toggleMute(pattern.detail.pattern_pid)} small />
            </div>
          </Card>
        );
      })}
      {visible !== null && visible.length === 0 && phase !== "baseline" && (
        <Card>
          <Note>No patterns surfaced yet — the engine only speaks when the evidence clears its statistical bars.</Note>
        </Card>
      )}
    </>
  );
}
