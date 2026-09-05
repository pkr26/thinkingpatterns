/**
 * Patterns view. Pulls the encrypted insight blob, decrypts on-device with
 * the session data key, and renders "pattern linking" cards — no advice,
 * no diagnosis, just the observation, plus the evidence behind it.
 *
 * Every card carries an evidence panel ("Why this?"): the lifecycle state
 * as a trust label (early evidence / established / fading — the industry
 * norm for correlation confidence, cf. Daylio's Low/Med/High), the
 * observation window, the sample size, the statistics behind the claim,
 * and a plain-language note on the method with its scientific grounding.
 */
import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, RefreshControl, ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { api } from "../api/client";
import { decryptInsights } from "../crypto/MindPatternCrypto";
import { vault } from "../vault";
import { useSession } from "../store";
import { MoodDay, localStreak, recentMoods } from "../moodLog";

interface PatternDetail {
  day?: string;
  day_fraction?: number;
  base_rate?: number;
  p_value?: number;
  mood_delta?: number;
  cohens_d?: number;
  direction?: string;
  lag_days?: number;
  n_after?: number;
  n_other?: number;
  span_days?: number;
  distinct_days?: number;
  negativity?: number;
  absolutist_per_100?: number;
  mean_negators?: number;
  shift?: number;
  baseline?: number;
  current?: number;
  carryover_recent?: number;
  carryover_earlier?: number;
  spread_recent?: number;
  spread_earlier?: number;
  pattern_state?: string;
  strength?: number;
  first_seen?: string;
  last_seen?: string;
  is_new?: boolean;
  sample_days?: number;
  trend?: string;
  share?: number;
  share_earlier?: number;
  share_recent?: number;
  entries?: number;
}

interface PatternCard {
  kind: string;
  label: string;
  occurrences: number;
  confidence: number;
  detail?: PatternDetail;
  describe?: string;
}

// Plain-language method notes — the science is cited in RESEARCH.md.
const METHOD_NOTES: Record<string, string> = {
  temporal:
    "Weekday concentration tested against your own writing schedule (exact binomial, corrected for multiple comparisons).",
  mood_correlation:
    "Within-person: days with this theme vs your own mood baseline in the same weeks (Welch's t + effect-size gate).",
  link: "Day-after association vs your own baseline — the shape of the best-replicated daily-diary link (e.g. sleep → next-day mood).",
  inertia:
    "Day-to-day mood carryover (autocorrelation) compared with your own earlier norm — a dynamic tied to wellbeing in meta-analyses.",
  instability: "The spread of your daily mood compared with your own earlier norm.",
  mood_shift: "A control chart over your daily mood vs your personal baseline — built for exactly this use.",
  recurring_phrase: "Near-duplicate sentence clustering across separated days.",
  rumination:
    "A returning negative thought. Repetitive negative thinking is a well-studied pattern; this clusters near-identical negative sentences.",
  topic:
    "A recurring theme discovered from your own words — not from any fixed list. Rising topics are tested against your own earlier entries (exact binomial).",
};

const STATE_LABELS: Record<string, string> = {
  emerging: "early evidence",
  confirmed: "established",
  fading: "fading",
};

function kindLabel(kind: string): string {
  if (kind === "temporal") return "TIMING";
  if (kind === "mood_correlation") return "MOOD LINK";
  if (kind === "link") return "DAY-AFTER LINK";
  if (kind === "inertia") return "CARRYOVER";
  if (kind === "instability") return "SWINGS";
  if (kind === "recurring_phrase") return "REPEATED PHRASE";
  if (kind === "rumination") return "REPEATED WORRY";
  if (kind === "topic") return "THEME";
  if (kind === "mood_shift") return "MOOD TREND";
  return "PATTERN";
}

function fmt(n: number | undefined, digits = 2): string {
  return typeof n === "number" && Number.isFinite(n) ? n.toFixed(digits) : "—";
}

/** The rows of the evidence panel for one pattern, in reading order. */
function evidenceRows(p: PatternCard): [string, string][] {  const d = p.detail ?? {};
  const rows: [string, string][] = [];
  rows.push(["Evidence window", `${d.first_seen ?? "?"} → ${d.last_seen ?? "?"}`]);
  if (typeof d.sample_days === "number") rows.push(["Based on", `${d.sample_days} entries in your analysis window`]);
  if (typeof d.day === "string" && typeof d.day_fraction === "number") {
    const base = typeof d.base_rate === "number" ? d.base_rate : 0;
    rows.push(["Concentration", `${fmt(d.day_fraction * 100, 0)}% on ${d.day}s (your baseline: ${fmt(base * 100, 0)}%)`]);
  }
  if (typeof d.mood_delta === "number") {
    rows.push(["Mood difference", `${d.direction === "lower" ? "lower" : "higher"} by ${fmt(Math.abs(d.mood_delta))} vs your own norm`]);
  }
  if (typeof d.cohens_d === "number") rows.push(["Effect size", `Cohen's d = ${fmt(d.cohens_d)}`]);
  if (typeof d.lag_days === "number") {
    rows.push(["Lag", `~${d.lag_days} day later (${d.n_after ?? "?"} such days vs ${d.n_other ?? "?"} others)`]);
  }
  if (typeof d.carryover_recent === "number") {
    rows.push(["Day-to-day carryover", `recent ${fmt(d.carryover_recent)} vs earlier ${fmt(d.carryover_earlier)}`]);
  }
  if (typeof d.spread_recent === "number") {
    rows.push(["Mood spread", `recent ${fmt(d.spread_recent)} vs earlier ${fmt(d.spread_earlier)}`]);
  }
  if (typeof d.share === "number") {
    rows.push(["Share of entries", `${fmt(d.share * 100, 0)}% (${d.entries ?? "?"} entries, ${p.occurrences} mentions)`]);
  }
  if (typeof d.share_recent === "number" && typeof d.share_earlier === "number") {
    rows.push(["Earlier → recent", `${fmt(d.share_earlier * 100, 0)}% → ${fmt(d.share_recent * 100, 0)}%`]);
  }
  if (d.trend === "rising" && typeof d.p_value === "number") {
    rows.push(["Significance", `p = ${d.p_value.toExponential(1)} (FDR-corrected)`]);
  }
  if (typeof d.span_days === "number") {
    rows.push(["Recurring over", `${d.span_days} days (${d.distinct_days ?? "?"} distinct days)`]);
  }
  if (typeof d.negativity === "number") {
    rows.push(["Tone", `reads negative (${fmt(d.negativity)}); absolutist words ${fmt(d.absolutist_per_100, 1)}/100`]);
  }
  if (typeof d.shift === "number") {
    rows.push(["Shift", `${d.direction === "lower" ? "−" : "+"}${fmt(Math.abs(d.shift))} vs baseline ${fmt(d.baseline)}`]);
  }
  if (typeof d.p_value === "number") rows.push(["Significance", `p = ${d.p_value.toExponential(1)} (FDR-corrected)`]);
  const note = METHOD_NOTES[p.kind];
  if (note) rows.push(["Method", note]);
  return rows;
}

function describe(p: PatternCard): string {
  if (p.kind === "temporal") {
    const day = p.detail?.day ?? "the same day";
    return `You've mentioned '${p.label}' ${p.occurrences} times, most often on ${day}s.`;
  }
  if (p.kind === "mood_correlation") {
    const delta = p.detail?.mood_delta ?? 0;
    const direction = p.detail?.direction ?? (delta < 0 ? "higher" : "lower");
    return `Your entries read ${direction} on days when '${p.label}' comes up (mood shift of ${Math.abs(delta).toFixed(1)}).`;
  }
  if (p.kind === "link") {
    const direction = p.detail?.direction === "higher" ? "higher" : "lower";
    return `The day after '${p.label}' comes up, your entries read ${direction} than usual for you.`;
  }
  if (p.kind === "inertia") {
    return "Your mood has been carrying over from day to day more than usual for you.";
  }
  if (p.kind === "instability") {
    return "Your daily mood has swung more widely than usual for you these past weeks.";
  }
  if (p.kind === "recurring_phrase") {
    return `The phrase "${p.label}" keeps returning — ${p.occurrences} times so far.`;
  }
  if (p.kind === "rumination") {
    return `The thought "${p.label}" keeps returning across different days — ${p.occurrences} times so far.`;
  }
  if (p.kind === "topic") {
    const share = p.detail?.share;
    const shareTxt = typeof share === "number" ? ` (${Math.round(share * 100)}% of entries)` : "";
    if (p.detail?.trend === "rising") {
      return `'${p.label}' has been taking up more space in your writing lately${shareTxt}.`;
    }
    return `'${p.label}' is a steady presence in your writing${shareTxt}.`;
  }
  if (p.kind === "mood_shift") {
    const direction = p.detail?.direction === "higher" ? "higher" : "lower";
    const shift = Math.abs(p.detail?.shift ?? 0);
    return `Your entries have read ${direction} than your usual baseline lately (a shift of ${shift.toFixed(1)}).`;
  }
  return `'${p.label}' appeared ${p.occurrences} times.`;
}

/** Device-local mood trend: one thin bar per day, midline at zero. */
function MoodSparkline({ days }: { days: MoodDay[] }) {
  if (days.length === 0) return null;
  const height = 44;
  return (
    <View style={styles.sparkRow}>
      {days.map((d) => {
        const barHeight = Math.max(3, Math.abs(d.value) * (height / 2 - 2));
        return (
          <View key={d.date} style={styles.sparkCol}>
            <View style={{ height: height / 2, justifyContent: "flex-end" }}>
              {d.value >= 0 && <View style={[styles.sparkBarUp, { height: barHeight }]} />}
            </View>
            <View style={{ height: height / 2, justifyContent: "flex-start" }}>
              {d.value < 0 && <View style={[styles.sparkBarDown, { height: barHeight }]} />}
            </View>
          </View>
        );
      })}
    </View>
  );
}

/** The decrypted blob is a TRUST BOUNDARY: the server (which once held the
 *  data key in a processing session) could have crafted it. Every field
 *  rendered to a vulnerable user is type- and range-checked here; garbage
 *  degrades to a dropped card, never a crash or a rendered injection. */
const MAX_LABEL_CHARS = 500;

function sanitizePatterns(raw: unknown): PatternCard[] {
  if (!Array.isArray(raw)) return [];
  const cards: PatternCard[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) continue;
    const p = item as Record<string, unknown>;
    if (typeof p.kind !== "string" || typeof p.label !== "string") continue;
    const occurrences = typeof p.occurrences === "number" && Number.isFinite(p.occurrences)
      ? Math.max(0, Math.floor(p.occurrences))
      : 0;
    const confidence = typeof p.confidence === "number" && Number.isFinite(p.confidence)
      ? Math.min(1, Math.max(0, p.confidence))
      : 0;
    cards.push({
      kind: p.kind.slice(0, 64),
      label: p.label.slice(0, MAX_LABEL_CHARS),
      occurrences,
      confidence,
      detail: (p.detail ?? undefined) as PatternDetail | undefined,
      describe: undefined,
    });
  }
  return cards;
}

export function InsightsScreen(): React.JSX.Element {
  const { refreshActiveDays, unlockDays } = useSession();
  const [phase, setPhase] = useState<string>("loading");
  const [remaining, setRemaining] = useState(0);
  const [patterns, setPatterns] = useState<PatternCard[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [streak, setStreak] = useState(0);
  const [moods, setMoods] = useState<MoodDay[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const summary = await api.insights();
      // A hostile server must not be able to drive the UI into an unknown
      // branch: only the two real phases are accepted.
      if (summary.phase !== "baseline" && summary.phase !== "insight") {
        throw new Error("server reported an unknown insights phase");
      }
      setPhase(summary.phase);
      setRemaining(typeof summary.days_remaining === "number" && Number.isFinite(summary.days_remaining) ? summary.days_remaining : 0);
      await refreshActiveDays();
      // Baseline-phase value is device-local: streak + mood trend, no
      // server involvement. The log is encrypted under the data key —
      // only reachable on this screen while the vault is unlocked.
      const userId = await api.getUserId();
      if (userId && vault.get().dataKey) {
        const dataKey = vault.get().dataKey;
        localStreak(dataKey, userId).then(setStreak).catch(() => {});
        recentMoods(dataKey, userId, 30).then(setMoods).catch(() => {});
      }
      if (summary.blob) {
        const userId = (await api.getUserId()) ?? "";
        const payload = decryptInsights(vault.get(), userId, summary.blob);
        const list = sanitizePatterns(payload.stats?.patterns);
        for (const p of list) {
          p.describe = describe(p);
        }
        setPatterns(list);
      } else {
        setPatterns([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load insights");
    } finally {
      setBusy(false);
    }
  }, [refreshActiveDays]);

  React.useEffect(() => {
    load();
  }, [load]);

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={{ padding: 20, gap: 14 }}
      refreshControl={<RefreshControl refreshing={busy} onRefresh={load} tintColor="#4f7cff" />}
    >
      {error && <Text style={styles.error}>{error}</Text>}
      {phase === "loading" && <ActivityIndicator color="#4f7cff" />}
      {phase === "baseline" && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Keep writing — {remaining} {remaining === 1 ? "day" : "days"} to your patterns</Text>
          <Text style={styles.cardBody}>
            The wait is deliberate: with less than {unlockDays} days of entries, any "insight" would
            be a guess dressed up as a finding. Real patterns need real history.
          </Text>
          {streak > 0 && (
            <Text style={styles.meta}>
              Writing streak: {streak} {streak === 1 ? "day" : "days"}
            </Text>
          )}
          {moods.length > 2 && (
            <>
              <Text style={styles.meta}>Your mood, this month (stays on this device):</Text>
              <MoodSparkline days={moods} />
            </>
          )}
        </View>
      )}
      {phase === "insight" && patterns.length === 0 && !busy && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Nothing solid yet</Text>
          <Text style={styles.cardBody}>No recurring pattern has enough evidence. Keep writing.</Text>
        </View>
      )}
      {patterns.map((p, i) => {
        const key = `${p.kind}-${p.label}-${i}`;
        const stateLabel = STATE_LABELS[p.detail?.pattern_state ?? ""] ?? "observed";
        const isOpen = expanded === key;
        return (
          <View key={key} style={styles.card}>
            <View style={styles.cardHeader}>
              <Text style={styles.kind}>{kindLabel(p.kind)}</Text>
              <Text style={stateLabel === "established" ? styles.stateStrong : styles.stateEarly}>
                {stateLabel}
                {p.detail?.is_new ? " · new" : ""}
              </Text>
            </View>
            <Text style={styles.cardBody}>{p.describe}</Text>
            <Text style={styles.meta}>
              {p.occurrences} mentions · strength {(p.confidence * 100).toFixed(0)}%
            </Text>
            <TouchableOpacity
              onPress={() => setExpanded(isOpen ? null : key)}
              accessibilityRole="button"
              style={styles.whyToggle}
            >
              <Text style={styles.whyText}>{isOpen ? "Hide the evidence" : "Why am I seeing this?"}</Text>
            </TouchableOpacity>
            {isOpen && (
              <View style={styles.evidencePanel}>
                {evidenceRows(p).map(([k, v]) => (
                  <View key={k} style={styles.evidenceRow}>
                    <Text style={styles.evidenceKey}>{k}</Text>
                    <Text style={styles.evidenceValue}>{v}</Text>
                  </View>
                ))}
                <Text style={styles.evidenceFootnote}>
                  An observation about your own data — not a diagnosis or advice.
                </Text>
              </View>
            )}
          </View>
        );
      })}
      {phase === "insight" && (
        <Text style={styles.footnote}>
          These are observations, not advice or diagnosis. You decide what they mean.
        </Text>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f1115" },
  card: { backgroundColor: "#1a1e26", borderRadius: 12, padding: 16, gap: 6 },
  cardHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  cardTitle: { color: "#e8eaf0", fontSize: 17, fontWeight: "700" },
  cardBody: { color: "#b6bdc9", fontSize: 15, lineHeight: 21 },
  kind: { color: "#7f9bff", fontSize: 11, fontWeight: "700", letterSpacing: 1 },
  stateEarly: { color: "#8a91a3", fontSize: 11, fontWeight: "600" },
  stateStrong: { color: "#59c98a", fontSize: 11, fontWeight: "700" },
  meta: { color: "#5c6370", fontSize: 12 },
  whyToggle: { paddingVertical: 6 },
  whyText: { color: "#7f9bff", fontSize: 13, fontWeight: "600" },
  evidencePanel: { backgroundColor: "#141821", borderRadius: 10, padding: 12, gap: 8, marginTop: 2 },
  evidenceRow: { flexDirection: "row", gap: 10 },
  evidenceKey: { color: "#8a91a3", fontSize: 12, width: 128, flexShrink: 0 },
  evidenceValue: { color: "#c7cdd8", fontSize: 12, flex: 1, lineHeight: 16 },
  evidenceFootnote: { color: "#5c6370", fontSize: 11, marginTop: 2 },
  footnote: { color: "#5c6370", fontSize: 12, textAlign: "center", marginTop: 8 },
  error: { color: "#ff6b6b", fontSize: 13 },
  sparkRow: { flexDirection: "row", alignItems: "flex-end", height: 48, gap: 2, marginTop: 4 },
  sparkCol: { flex: 1, height: 48 },
  sparkBarUp: { backgroundColor: "#59c98a", borderRadius: 1 },
  sparkBarDown: { backgroundColor: "#e06c75", borderRadius: 1 },
});
