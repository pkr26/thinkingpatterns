/**
 * Patterns view. Pulls the encrypted insight blob, decrypts on-device with
 * the session data key, and renders "pattern linking" cards — no advice,
 * no diagnosis, just the observation, plus the evidence behind it.
 *
 * Every ordinary card carries an evidence panel ("Why this?"): the
 * lifecycle state as a trust label (early evidence / seen consistently /
 * fading), the observation window, the sample size, and one plain-language
 * sentence per stat. Raw statistics (p-values, Cohen's d, absolutist-word
 * density) live behind a second "Technical details" expander, and every
 * panel ends with an honest-uncertainty sentence.
 *
 * SENSITIVE CARDS: a pattern flagged `detail.sensitive` by the server, or
 * whose label matches the on-device crisis-suppression tier, never renders
 * its label, counts, or tone stats — a crisis-adjacent thought quoted back
 * by an algorithm can read as confirmation. The card acknowledges the
 * pattern without quoting it and points at human support.
 */
import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, RefreshControl, ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { api } from "../api/client";
import { decryptInsights } from "../crypto/MindPatternCrypto";
import { checkAnalysisGeneration } from "../stateSeqGuard";
import { vault } from "../vault";
import { useSession } from "../store";
import { MoodDay, localStreak, recentMoods } from "../moodLog";
import { matchesCrisisSuppress } from "../crisisDetect";
import { useTheme, Theme } from "../theme";
import { CrisisHelpButton, GhostButton } from "../components/buttons";
import { requestFailureCopy } from "../components/errors";

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
  /** Server flag: crisis-adjacent — NEVER quote the label back. */
  sensitive?: boolean;
  /** Server flag: low-confidence presence topic — down-rank visually. */
  presence?: boolean;
  /** Link-card spacing metadata (available for future rendering). */
  gap1_days?: number;
  gap2_days?: number;
  /** Avoidance (silence-after) detector. */
  silences?: number;
  observed?: number;
  /** Cadence (rhythm) detector. */
  gap_spread_recent?: number;
  gap_spread_earlier?: number;
  median_gap_recent?: number;
  /** Structured-channel origin (2026-09-17): user tags / sleep ratings. */
  source?: string;
  channel?: string;
  /** Consent-gated LLM narrative (2026-09-17): one calm sentence the model
   *  reframed for a deterministic finding — sanitized server-side. */
  narrative?: string;
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
  avoidance:
    "Days with this theme are more often followed by a silent day than your own usual pattern (exact binomial against your base rate, corrected for multiple comparisons).",
  cadence:
    "The regularity of your writing rhythm compared with your own earlier norm (spread of gaps between writing days).",
};

/** Lifecycle states rendered as evidence labels. "Seen consistently" is
 *  deliberately softer than the old "established" next to low-mood cards. */
const STATE_LABELS: Record<string, string> = {
  emerging: "early evidence",
  confirmed: "seen consistently",
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
  if (kind === "avoidance") return "SILENCE AFTER";
  if (kind === "cadence") return "RHYTHM";
  return "PATTERN";
}

function fmt(n: number | undefined, digits = 2): string {
  // Stryker disable next-line ConditionalExpression, LogicalOperator: Number.isFinite implies typeof "number" and every value here is JSON-parsed, so the typeof arm is redundant for every reachable input.
  return typeof n === "number" && Number.isFinite(n) ? n.toFixed(digits) : "—";
}

/** |d| in plain words (Cohen's conventions, softened: these are observations). */
export function effectSizeWords(d: number): string {
  const size = Math.abs(d);
  if (size < 0.2) return "a very small difference";
  if (size < 0.5) return "a small difference";
  if (size < 0.8) return "a medium-sized difference";
  return "a large difference";
}

/** The plain-language rows of the evidence panel, in reading order. One
 *  sentence per stat; the raw numbers live in technicalRows(). */
function evidenceRows(p: PatternCard): [string, string][] {
  const d = p.detail ?? {};
  const rows: [string, string][] = [];
  rows.push(["Evidence window", `${d.first_seen ?? "?"} → ${d.last_seen ?? "?"}`]);
  if (typeof d.sample_days === "number") rows.push(["Based on", `${d.sample_days} entries in your analysis window`]);
  if (typeof d.day === "string" && typeof d.day_fraction === "number") {
    const base = typeof d.base_rate === "number" ? d.base_rate : 0;
    rows.push([
      "Concentration",
      `${fmt(d.day_fraction * 100, 0)}% of these mentions fell on ${d.day}s — your baseline for ${d.day}s is ${fmt(base * 100, 0)}%`,
    ]);
  }
  if (typeof d.mood_delta === "number") {
    rows.push(["Mood difference", `entries read ${d.direction === "lower" ? "lower" : "higher"} by ${fmt(Math.abs(d.mood_delta))} than your own norm`]);
  }
  if (typeof d.cohens_d === "number") {
    rows.push(["Size of the difference", effectSizeWords(d.cohens_d)]);
  }
  if (typeof d.lag_days === "number") {
    rows.push(["Day-after", `~${d.lag_days} day later — seen on ${d.n_after ?? "?"} such days vs ${d.n_other ?? "?"} others`]);
  }
  if (typeof d.carryover_recent === "number") {
    rows.push(["Carryover", "mood has been carrying over more strongly than it used to for you"]);
  }
  if (typeof d.spread_recent === "number") {
    rows.push(["Swings", "your daily mood has been spread over a wider range than it used to"]);
  }
  if (typeof d.share === "number") {
    rows.push(["Share of entries", `${fmt(d.share * 100, 0)}% (${d.entries ?? "?"} entries, ${p.occurrences} mentions)`]);
  }
  if (typeof d.share_recent === "number" && typeof d.share_earlier === "number") {
    rows.push(["Earlier → recent", `${fmt(d.share_earlier * 100, 0)}% → ${fmt(d.share_recent * 100, 0)}%`]);
  }
  if (typeof d.span_days === "number") {
    rows.push(["Returning for", `seen on ${d.distinct_days ?? "?"} distinct days across ${d.span_days} days`]);
  }
  if (typeof d.negativity === "number") {
    rows.push(["Tone", "the thought reads negative"]);
  }
  if (typeof d.shift === "number") {
    rows.push(["Shift", `${d.direction === "lower" ? "−" : "+"}${fmt(Math.abs(d.shift))} against your baseline of ${fmt(d.baseline)}`]);
  }
  if (typeof d.silences === "number") {
    rows.push(["Silent days after", `${d.silences} of ${d.observed ?? "?"} such days (your usual silent-day rate is ${fmt((d.base_rate ?? 0) * 100, 0)}%)`]);
  }
  if (typeof d.gap_spread_recent === "number") {
    rows.push(["Rhythm", `gap spread ${fmt(d.gap_spread_recent, 1)} vs your earlier ${fmt(d.gap_spread_earlier, 1)} days`]);
  }
  const note = METHOD_NOTES[p.kind];
  if (note) rows.push(["Method", note]);
  return rows;
}

/** The raw statistics, gated behind "Technical details". Exactly one row
 *  per stat — the old panel pushed the p-value row twice for rising topics
 *  (a duplicate-React-key bug). */
function technicalRows(p: PatternCard): [string, string][] {
  const d = p.detail ?? {};
  const rows: [string, string][] = [];
  if (typeof d.p_value === "number") rows.push(["Significance", `p = ${d.p_value.toExponential(1)} (corrected for running many tests)`]);
  if (typeof d.cohens_d === "number") rows.push(["Cohen's d", fmt(d.cohens_d)]);
  if (typeof d.negativity === "number") rows.push(["Negativity score", fmt(d.negativity)]);
  if (typeof d.absolutist_per_100 === "number") rows.push(["Absolutist-word density", `${fmt(d.absolutist_per_100, 1)} per 100 words`]);
  if (typeof d.carryover_recent === "number") rows.push(["Carryover, recent vs earlier", `${fmt(d.carryover_recent)} vs ${fmt(d.carryover_earlier)}`]);
  if (typeof d.spread_recent === "number") rows.push(["Spread, recent vs earlier", `${fmt(d.spread_recent)} vs ${fmt(d.spread_earlier)}`]);
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
  if (p.detail?.channel === "sleep_quality") {
    if (p.kind === "link") {
      const direction = p.detail?.direction === "higher" ? "higher" : "lower";
      return `The day after a night you rated as rougher than your own usual, your entries read ${direction} than usual for you.`;
    }
    if (p.kind === "mood_correlation") {
      const direction = p.detail?.direction === "higher" ? "higher" : "lower";
      return `On nights you rated as rougher than your own usual, your entries read ${direction} the same day.`;
    }
    if (p.kind === "temporal") {
      return `Your rougher nights (by your own ratings) fall most often on ${p.detail?.day ?? "certain"}s.`;
    }
  }
  if (p.kind === "avoidance") {
    const silences = p.detail?.silences ?? p.occurrences;
    const share = typeof p.detail?.share === "number" ? Math.round(p.detail.share * 100) : null;
    return `The day after '${p.label}' comes up, you tend not to write${share !== null ? ` (${share}% of such days)` : ""}.`;
  }
  if (p.kind === "cadence") {
    return "Your writing rhythm has been less regular than it used to be for you — longer stretches of silence between writing days.";
  }
  if (p.detail?.source === "tag") {
    if (p.kind === "mood_correlation") {
      return `Your entries read ${p.detail?.direction === "higher" ? "higher" : "lower"} on days you tag '${p.label}'.`;
    }
    if (p.kind === "link") {
      const direction = p.detail?.direction === "higher" ? "higher" : "lower";
      return `The day after you tag '${p.label}', your entries read ${direction} than usual for you.`;
    }
    if (p.kind === "temporal") {
      return `You tag '${p.label}' most often on ${p.detail?.day ?? "certain"}s.`;
    }
  }
  return `'${p.label}' appeared ${p.occurrences} times.`;
}

/** One-line VoiceOver summary for the sparkline: the bars themselves are
 *  decorative Views, invisible to screen readers without this. */
export function sparklineSummary(days: MoodDay[]): string {
  const n = days.length;
  const half = Math.floor(n / 2);
  const avg = (slice: MoodDay[]): number =>
    // Stryker disable next-line ConditionalExpression: an empty half only occurs at n < 2, where the trend word is forced to steady before diff is read.
    slice.length === 0 ? 0 : slice.reduce((sum, d) => sum + d.value, 0) / slice.length;
  const diff = avg(days.slice(half)) - avg(days.slice(0, half));
  // One day is a point, not a trend.
  const trend = n < 2 ? "steady" : diff > 0.15 ? "rising" : diff < -0.15 ? "falling" : "steady";
  const latest = days[n - 1]?.value ?? 0;
  const latestWord = latest > 0 ? "positive" : latest < 0 ? "negative" : "neutral";
  return `Mood trend: ${trend} over ${n} ${n === 1 ? "day" : "days"}, latest ${latestWord}`;
}

/** Device-local mood trend: one thin bar per day, midline at zero. The
 *  container is the accessible element (summary label); the bars are
 *  presentation only. */
function MoodSparkline({ days }: { days: MoodDay[] }) {
  const t = useTheme();
  // Stryker disable next-line ConditionalExpression: the only call site renders behind moods.length > 2; empty days cannot reach this component.
  if (days.length === 0) return null;
  const height = 44;
  return (
    <View
      style={styles.sparkRow}
      accessible
      accessibilityRole="image"
      accessibilityLabel={sparklineSummary(days)}
    >
      {days.map((d) => {
        const barHeight = Math.max(3, Math.abs(d.value) * (height / 2 - 2));
        return (
          <View key={d.date} style={styles.sparkCol}>
            <View style={{ height: height / 2, justifyContent: "flex-end" }}>
              {d.value >= 0 && (
                <View style={[styles.sparkBarUp, { backgroundColor: t.colors.success, height: barHeight }]} />
              )}
            </View>
            <View style={{ height: height / 2, justifyContent: "flex-start" }}>
              {d.value < 0 && (
                <View style={[styles.sparkBarDown, { backgroundColor: t.colors.sparkDown, height: barHeight }]} />
              )}
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
    // Stryker disable next-line ConditionalExpression: JSON primitives have no .kind/.label so the checks below drop them; null stays caught by the second clause.
    if (typeof item !== "object" || item === null) continue;
    const p = item as Record<string, unknown>;
    if (typeof p.kind !== "string" || typeof p.label !== "string") continue;
    // Stryker disable next-line ConditionalExpression, LogicalOperator: Number.isFinite implies typeof number; occurrences arrives via JSON, never NaN/Infinity.
    const occurrences = typeof p.occurrences === "number" && Number.isFinite(p.occurrences)
      ? Math.max(0, Math.floor(p.occurrences))
      : 0;
    // Stryker disable next-line ConditionalExpression, LogicalOperator: Number.isFinite implies typeof number; confidence arrives via JSON, never NaN/Infinity.
    const confidence = typeof p.confidence === "number" && Number.isFinite(p.confidence)
      ? Math.min(1, Math.max(0, p.confidence))
      : 0;
    const detail = (p.detail ?? undefined) as PatternDetail | undefined;
    // Same render cap as the label: the narrative is one calm sentence —
    // a hostile blob must not push unbounded text into the card.
    if (typeof detail?.narrative === "string") detail.narrative = detail.narrative.slice(0, MAX_LABEL_CHARS);
    cards.push({
      // Stryker disable next-line MethodExpression: kind is only compared for equality against known kinds far below 64 chars; truncation cannot change an outcome.
      kind: p.kind.slice(0, 64),
      label: p.label.slice(0, MAX_LABEL_CHARS),
      occurrences,
      confidence,
      detail,
      describe: undefined,
    });
  }
  return cards;
}

/** Crisis-adjacent patterns (server-flagged or suppress-tier label) get a
 *  non-quoting card: acknowledge, point at humans, quote nothing. */
function isSensitive(p: PatternCard): boolean {
  return p.detail?.sensitive === true || matchesCrisisSuppress(p.label);
}

export function InsightsScreen({ navigation }: { navigation?: any }): React.JSX.Element {
  const t = useTheme();
  const { refreshActiveDays, unlockDays, touchActivity } = useSession();
  const [phase, setPhase] = useState<string>("loading");
  const [remaining, setRemaining] = useState(0);
  const [patterns, setPatterns] = useState<PatternCard[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [techExpanded, setTechExpanded] = useState<string | null>(null);
  const [streak, setStreak] = useState(0);
  // Stryker disable next-line ArrayDeclaration: moods is only read behind moods.length > 2; a 1-element poisoned initial cannot pass that gate before setMoods replaces it.
  const [moods, setMoods] = useState<MoodDay[]>([]);
  // Stryker disable next-line BooleanLiteral: busy is set by the load effect before any observable read; the initial value is never observably rendered.
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
      // Stryker disable next-line ConditionalExpression, LogicalOperator: Number.isFinite implies typeof number; days_remaining arrives via JSON and the non-numeric case is pinned by test.
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
        // Rollback guard (2026-09-19): the payload's embedded analysis
        // generation must equal the plaintext echo and never move below
        // this device's pinned high-water mark — a silent replay of an
        // older valid-GCM blob otherwise renders as today's truth.
        await checkAnalysisGeneration(userId, payload.state_seq, summary.state_seq);
        const list = sanitizePatterns(payload.stats?.patterns);
        for (const p of list) {
          p.describe = describe(p);
        }
        setPatterns(list);
      } else {
        setPatterns([]);
      }
    } catch (err) {
      // Calm copy for server failures; our own local Error text passes.
      setError(requestFailureCopy(err));
    } finally {
      setBusy(false);
    }
  }, // Stryker disable next-line ArrayDeclaration: constant deps are equivalent under the test seam (the mocked refreshActiveDays has a stable identity); in production the dependency keeps the callback honest.
     [refreshActiveDays]);

  React.useEffect(() => {
    load();
  }, // Stryker disable next-line ArrayDeclaration: constant deps under the stable test seam described above.
     [load]);

  const cardStyles = makeCardStyles(t);

  return (
    // Any touch on this screen is real interaction: restart the inactivity
    // countdown so the auto-lock only fires on a genuinely idle session.
    <ScrollView
      style={[styles.container, { backgroundColor: t.colors.bg }]}
      contentContainerStyle={{ padding: t.spacing.xl, gap: 14 }}
      onTouchStart={touchActivity}
      refreshControl={
        <RefreshControl refreshing={busy} onRefresh={load} tintColor={t.colors.primaryBright} colors={[t.colors.primaryBright]} />
      }
    >
      {error && (
        <View style={cardStyles.card}>
          <Text style={{ color: t.colors.error, fontSize: t.type.bodySmall.fontSize }} accessibilityRole="alert">
            {error}
          </Text>
          <GhostButton label="Try again" onPress={load} accessibilityLabel="Try loading your patterns again" />
        </View>
      )}
      {phase === "loading" && <ActivityIndicator color={t.colors.primaryBright} />}
      {phase === "baseline" && (
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>Keep writing — {remaining} {remaining === 1 ? "day" : "days"} to your patterns</Text>
          <Text style={cardStyles.cardBody}>
            The wait is deliberate: with less than {unlockDays} days of entries, any "insight" would
            be a guess dressed up as a finding. Real patterns need real history.
          </Text>
          {streak > 0 && (
            <Text style={cardStyles.meta}>
              Writing streak: {streak} {streak === 1 ? "day" : "days"}
            </Text>
          )}
          {moods.length > 2 && (
            <>
              <Text style={cardStyles.meta}>Your mood, this month (stays on this device):</Text>
              <MoodSparkline days={moods} />
            </>
          )}
        </View>
      )}
      {phase === "insight" && patterns.length === 0 && !busy && (
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>Nothing solid yet</Text>
          <Text style={cardStyles.cardBody}>No recurring pattern has enough evidence. Keep writing.</Text>
        </View>
      )}
      {phase === "insight" && moods.length > 2 && (
        // The mood check-in keeps paying off after the threshold: the
        // trend it fed during baseline stays visible beside the pattern
        // cards (device-local, never synced — same data, same rules).
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>Your mood, this month</Text>
          <MoodSparkline days={moods} />
          <Text style={cardStyles.meta}>Recorded on this device with your daily check-in.</Text>
        </View>
      )}
      {patterns.map((p, i) => {
        const key = `${p.kind}-${p.label}-${i}`;
        if (isSensitive(p)) {
          // Non-quoting variant: no label, no counts, no stats, no expander.
          return (
            <View key={key} style={cardStyles.card}>
              <Text style={cardStyles.cardBody}>
                A difficult thought has been returning across different days.
              </Text>
              <Text style={cardStyles.meta}>
                Talking to a professional is never a wrong move.
              </Text>
              <GhostButton
                label="Support resources"
                center={false}
                onPress={() => navigation?.navigate("Crisis")}
                accessibilityLabel="Support resources — crisis help"
              />
            </View>
          );
        }
        // Stryker disable next-line StringLiteral: the fallback key hits no STATE_LABELS entry for every possible value; any replacement key still lands on observed.
        const stateLabel = STATE_LABELS[p.detail?.pattern_state ?? ""] ?? "observed";
        const isOpen = expanded === key;
        const techOpen = techExpanded === key;
        const presence = p.detail?.presence === true; // low-confidence: down-ranked visually
        return (
          <View key={key} style={cardStyles.card}>
            <View style={styles.cardHeader}>
              <Text style={[cardStyles.kind, presence && { color: t.colors.muted }]}>{kindLabel(p.kind)}</Text>
              <Text style={stateLabel === "seen consistently" ? cardStyles.stateStrong : cardStyles.stateEarly}>
                {stateLabel}
                {p.detail?.is_new ? " · new" : ""}
              </Text>
            </View>
            <Text style={[cardStyles.cardBody, presence && { color: t.colors.muted }]}>{p.describe}</Text>
            {typeof p.detail?.narrative === "string" && p.detail.narrative.length > 0 && (
              <Text style={[styles.narrative, { color: t.colors.muted }]}>{p.detail.narrative}</Text>
            )}
            <Text style={cardStyles.meta}>
              {p.occurrences} mentions · evidence density {(p.confidence * 100).toFixed(0)}%
            </Text>
            <TouchableOpacity
              onPress={() => setExpanded(isOpen ? null : key)}
              accessibilityRole="button"
              accessibilityLabel={isOpen ? "Hide the evidence" : `Why am I seeing this? Evidence for this pattern`}
              accessibilityState={{ expanded: isOpen }}
              hitSlop={t.touchSlop}
              style={styles.whyToggle}
            >
              <Text style={[styles.whyText, { color: t.colors.accent }]}>{isOpen ? "Hide the evidence" : "Why am I seeing this?"}</Text>
            </TouchableOpacity>
            {isOpen && (
              <View style={[styles.evidencePanel, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.md }]}>
                {evidenceRows(p).map(([k, v]) => (
                  <View key={k} style={styles.evidenceRow}>
                    <Text style={[styles.evidenceKey, { color: t.colors.muted }]}>{k}</Text>
                    <Text style={[styles.evidenceValue, { color: t.colors.body }]}>{v}</Text>
                  </View>
                ))}
                {technicalRows(p).length > 0 && (
                  <>
                    <TouchableOpacity
                      onPress={() => setTechExpanded(techOpen ? null : key)}
                      accessibilityRole="button"
                      accessibilityLabel={techOpen ? "Hide technical details" : "Technical details — the raw statistics"}
                      accessibilityState={{ expanded: techOpen }}
                      hitSlop={t.touchSlop}
                      style={styles.whyToggle}
                    >
                      <Text style={[styles.techText, { color: t.colors.muted }]}>
                        {techOpen ? "Hide technical details" : "Technical details"}
                      </Text>
                    </TouchableOpacity>
                    {techOpen &&
                      technicalRows(p).map(([k, v]) => (
                        <View key={k} style={styles.evidenceRow}>
                          <Text style={[styles.evidenceKey, { color: t.colors.muted }]}>{k}</Text>
                          <Text style={[styles.evidenceValue, { color: t.colors.body }]}>{v}</Text>
                        </View>
                      ))}
                  </>
                )}
                <Text style={[styles.evidenceFootnote, { color: t.colors.muted }]}>
                  Patterns like this can occasionally appear by chance — that's why we show the evidence.
                </Text>
                <Text style={[styles.evidenceFootnote, { color: t.colors.muted }]}>
                  An observation about your own data — not a diagnosis or advice.
                </Text>
              </View>
            )}
          </View>
        );
      })}
      {phase === "insight" && (
        <Text style={[styles.footnote, { color: t.colors.muted }]}>
          These are observations, not advice or diagnosis. You decide what they mean.
        </Text>
      )}
      {/* The one screen the audit found without a path to help: fixed. */}
      <CrisisHelpButton onPress={() => navigation?.navigate("Crisis")} />
    </ScrollView>
  );
}

function makeCardStyles(t: Theme) {
  return {
    card: { backgroundColor: t.colors.card, borderRadius: t.radius.lg, padding: t.spacing.lg, gap: 6 },
    cardTitle: { color: t.colors.text, fontSize: t.type.title.fontSize, fontWeight: "700" as const },
    cardBody: { color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: t.type.body.lineHeight },
    kind: { color: t.colors.accent, fontSize: t.type.caption.fontSize, fontWeight: "700" as const, letterSpacing: 1 },
    stateEarly: { color: t.colors.muted, fontSize: 11, fontWeight: "600" as const },
    stateStrong: { color: t.colors.success, fontSize: 11, fontWeight: "700" as const },
    meta: { color: t.colors.muted, fontSize: t.type.meta.fontSize },
  };
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  cardHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  whyToggle: { paddingVertical: 6 },
  whyText: { fontSize: 13, fontWeight: "600" },
  techText: { fontSize: 12, fontWeight: "600" },
  evidencePanel: { padding: 12, gap: 8, marginTop: 2 },
  evidenceRow: { flexDirection: "row", gap: 10 },
  evidenceKey: { fontSize: 12, width: 128, flexShrink: 0 },
  evidenceValue: { fontSize: 12, flex: 1, lineHeight: 16 },
  evidenceFootnote: { fontSize: 11, marginTop: 2, lineHeight: 15 },
  narrative: { fontSize: 13, lineHeight: 18, fontStyle: "italic" },
  footnote: { fontSize: 12, textAlign: "center", marginTop: 8 },
  sparkRow: { flexDirection: "row", alignItems: "flex-end", height: 48, gap: 2, marginTop: 4 },
  sparkCol: { flex: 1, height: 48 },
  sparkBarUp: { borderRadius: 1 },
  sparkBarDown: { borderRadius: 1 },
});
