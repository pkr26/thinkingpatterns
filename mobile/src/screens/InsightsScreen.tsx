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
import React, { useCallback, useEffect, useRef, useState } from "react";
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
import { recordPatternMute } from "../questionFeedback";
import { t as tr, dateLocaleTag } from "../strings";

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
  coupling_recent?: number;
  coupling_earlier?: number;
  density_recent?: number;
  density_earlier?: number;
  entropy_recent?: number;
  entropy_earlier?: number;
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
  /** Stable pattern id (2026-09-19): routes mute/unmute and feedback taps. */
  pattern_pid?: string;
  /** Server flag: the patient muted this pattern — collapsed section. */
  muted?: boolean;
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
// Catalog keys per pattern kind (insights.method.*); an unknown kind has
// no note, exactly as before.
const METHOD_NOTE_KEYS: Record<string, string> = {
  temporal: "insights.method.temporal",
  mood_correlation: "insights.method.mood_correlation",
  link: "insights.method.link",
  inertia: "insights.method.inertia",
  energy_inertia: "insights.method.energy_inertia",
  pa_inertia: "insights.method.pa_inertia",
  na_inertia: "insights.method.na_inertia",
  energy_mood_coupling: "insights.method.energy_mood_coupling",
  sense_making: "insights.method.sense_making",
  activity_diversity: "insights.method.activity_diversity",
  instability: "insights.method.instability",
  mood_shift: "insights.method.mood_shift",
  recurring_phrase: "insights.method.recurring_phrase",
  rumination: "insights.method.rumination",
  topic: "insights.method.topic",
  avoidance: "insights.method.avoidance",
  cadence: "insights.method.cadence",
};

/** Lifecycle states rendered as evidence labels. "Seen consistently" is
 *  deliberately softer than the old "established" next to low-mood cards. */
const STATE_LABEL_KEYS: Record<string, string> = {
  emerging: "insights.state.emerging",
  confirmed: "insights.state.confirmed",
  fading: "insights.state.fading",
};

const KIND_LABEL_KEYS: Record<string, string> = {
  temporal: "insights.kind.temporal",
  mood_correlation: "insights.kind.mood_correlation",
  link: "insights.kind.link",
  inertia: "insights.kind.inertia",
  energy_inertia: "insights.kind.energy_inertia",
  pa_inertia: "insights.kind.pa_inertia",
  na_inertia: "insights.kind.na_inertia",
  energy_mood_coupling: "insights.kind.energy_mood_coupling",
  sense_making: "insights.kind.sense_making",
  activity_diversity: "insights.kind.activity_diversity",
  instability: "insights.kind.instability",
  recurring_phrase: "insights.kind.recurring_phrase",
  rumination: "insights.kind.rumination",
  topic: "insights.kind.topic",
  mood_shift: "insights.kind.mood_shift",
  avoidance: "insights.kind.avoidance",
  cadence: "insights.kind.cadence",
};

function kindLabel(kind: string): string {
  const key = KIND_LABEL_KEYS[kind];
  return key ? tr(key) : tr("insights.kind.fallback");
}

function fmt(n: number | undefined, digits = 2): string {
  // Stryker disable next-line ConditionalExpression, LogicalOperator: Number.isFinite implies typeof "number" and every value here is JSON-parsed, so the typeof arm is redundant for every reachable input.
  return typeof n === "number" && Number.isFinite(n) ? n.toFixed(digits) : "—";
}

// M-36 (2026-09-20 audit): the backend's DAY_NAMES (services/patterns.py)
// emits ENGLISH weekday words in every locale — "la mayoría de las veces en
// Monday" was the shipped Spanish sentence. The weekday is localized at
// RENDER time: the English word is mapped onto the app locale's weekday via
// Intl with the strings.ts locale tag (2024-01-01 was a Monday, so the
// array index IS the weekday). Trust-boundary safe: detail.day is
// attacker-controllable text, and anything that is not exactly one of the
// seven English names passes through unchanged (never crashes, never
// invents a date).
const ENGLISH_WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"] as const;

/** The locale's long weekday for a backend English weekday name. */
export function localWeekday(day: string): string {
  const index = ENGLISH_WEEKDAYS.indexOf(day as (typeof ENGLISH_WEEKDAYS)[number]);
  if (index < 0) return day;
  const anchor = new Date(Date.UTC(2024, 0, 1 + index));
  try {
    return anchor.toLocaleDateString(dateLocaleTag(), { weekday: "long", timeZone: "UTC" });
  } catch {
    return day; // an exotic locale tag degrades to the raw server word
  }
}

/** |d| in plain words (Cohen's conventions, softened: these are observations). */
export function effectSizeWords(d: number): string {
  const size = Math.abs(d);
  if (size < 0.2) return tr("insights.effect.verySmall");
  if (size < 0.5) return tr("insights.effect.small");
  if (size < 0.8) return tr("insights.effect.medium");
  return tr("insights.effect.large");
}

/** The plain-language rows of the evidence panel, in reading order. One
 *  sentence per stat; the raw numbers live in technicalRows(). */
function evidenceRows(p: PatternCard): [string, string][] {
  const d = p.detail ?? {};
  const rows: [string, string][] = [];
  rows.push([tr("insights.ev.window"), tr("insights.ev.windowValue", { from: d.first_seen ?? "?", to: d.last_seen ?? "?" })]);
  if (typeof d.sample_days === "number") {
    rows.push([tr("insights.ev.basedOn"), tr("insights.ev.basedOnValue", { count: d.sample_days })]);
  }
  if (typeof d.day === "string" && typeof d.day_fraction === "number") {
    const base = typeof d.base_rate === "number" ? d.base_rate : 0;
    rows.push([
      tr("insights.ev.concentration"),
      tr("insights.ev.concentrationValue", {
        share: fmt(d.day_fraction * 100, 0),
        day: localWeekday(d.day),
        baseline: fmt(base * 100, 0),
      }),
    ]);
  }
  if (typeof d.mood_delta === "number") {
    rows.push([
      tr("insights.ev.moodDiff"),
      tr("insights.ev.moodDiffValue", {
        direction: tr(d.direction === "lower" ? "insights.words.lower" : "insights.words.higher"),
        amount: fmt(Math.abs(d.mood_delta)),
      }),
    ]);
  }
  if (typeof d.cohens_d === "number") {
    rows.push([tr("insights.ev.size"), effectSizeWords(d.cohens_d)]);
  }
  if (typeof d.lag_days === "number") {
    rows.push([
      tr("insights.ev.dayAfter"),
      tr("insights.ev.dayAfterValue", { lag: d.lag_days, after: d.n_after ?? "?", other: d.n_other ?? "?" }),
    ]);
  }
  if (typeof d.carryover_recent === "number") {
    const valueKey =
      d.channel === "energy" ? "insights.ev.carryoverEnergy"
      : d.channel === "positive_affect" ? "insights.ev.carryoverPositive"
      : d.channel === "negative_affect" ? "insights.ev.carryoverNegative"
      : "insights.ev.carryoverMood";
    rows.push([tr("insights.ev.carryover"), tr(valueKey)]);
  }
  if (typeof d.coupling_recent === "number") {
    rows.push([tr("insights.ev.tracking"), tr("insights.ev.trackingValue")]);
  }
  if (typeof d.density_recent === "number") {
    rows.push([
      tr("insights.ev.senseWords"),
      tr("insights.ev.senseWordsValue", { recent: fmt(d.density_recent, 1), earlier: fmt(d.density_earlier, 1) }),
    ]);
  }
  if (typeof d.entropy_recent === "number") {
    rows.push([
      tr("insights.ev.activityVariety"),
      tr("insights.ev.activityVarietyValue", {
        direction: tr(d.direction === "narrowed" ? "insights.words.narrowed" : "insights.words.widened"),
        recent: fmt(d.entropy_recent, 1),
        earlier: fmt(d.entropy_earlier, 1),
      }),
    ]);
  }
  if (typeof d.spread_recent === "number") {
    rows.push([tr("insights.ev.swings"), tr("insights.ev.swingsValue")]);
  }
  if (typeof d.share === "number") {
    rows.push([
      tr("insights.ev.share"),
      tr("insights.ev.shareValue", { share: fmt(d.share * 100, 0), entries: d.entries ?? "?", mentions: p.occurrences }),
    ]);
  }
  if (typeof d.share_recent === "number" && typeof d.share_earlier === "number") {
    rows.push([
      tr("insights.ev.earlierRecent"),
      tr("insights.ev.earlierRecentValue", { earlier: fmt(d.share_earlier * 100, 0), recent: fmt(d.share_recent * 100, 0) }),
    ]);
  }
  if (typeof d.span_days === "number") {
    rows.push([
      tr("insights.ev.returning"),
      tr("insights.ev.returningValue", { days: d.distinct_days ?? "?", span: d.span_days }),
    ]);
  }
  if (typeof d.negativity === "number") {
    rows.push([tr("insights.ev.tone"), tr("insights.ev.toneValue")]);
  }
  if (typeof d.shift === "number") {
    rows.push([
      tr("insights.ev.shift"),
      tr("insights.ev.shiftValue", { sign: d.direction === "lower" ? "−" : "+", amount: fmt(Math.abs(d.shift)), baseline: fmt(d.baseline) }),
    ]);
  }
  if (typeof d.silences === "number") {
    rows.push([
      tr("insights.ev.silentDays"),
      tr("insights.ev.silentDaysValue", {
        silences: d.silences,
        observed: d.observed ?? "?",
        rate: fmt((d.base_rate ?? 0) * 100, 0),
      }),
    ]);
  }
  if (typeof d.gap_spread_recent === "number") {
    rows.push([
      tr("insights.ev.rhythm"),
      tr("insights.ev.rhythmValue", { recent: fmt(d.gap_spread_recent, 1), earlier: fmt(d.gap_spread_earlier, 1) }),
    ]);
  }
  const noteKey = METHOD_NOTE_KEYS[p.kind];
  if (noteKey) rows.push([tr("insights.ev.method"), tr(noteKey)]);
  return rows;
}

/** The raw statistics, gated behind "Technical details". Exactly one row
 *  per stat — the old panel pushed the p-value row twice for rising topics
 *  (a duplicate-React-key bug). */
function technicalRows(p: PatternCard): [string, string][] {
  const d = p.detail ?? {};
  const rows: [string, string][] = [];
  if (typeof d.p_value === "number") {
    rows.push([tr("insights.tech.significance"), tr("insights.tech.significanceValue", { value: d.p_value.toExponential(1) })]);
  }
  if (typeof d.cohens_d === "number") rows.push([tr("insights.tech.cohensD"), fmt(d.cohens_d)]);
  if (typeof d.negativity === "number") rows.push([tr("insights.tech.negativity"), fmt(d.negativity)]);
  if (typeof d.absolutist_per_100 === "number") {
    rows.push([tr("insights.tech.absolutist"), tr("insights.tech.absolutistValue", { value: fmt(d.absolutist_per_100, 1) })]);
  }
  if (typeof d.carryover_recent === "number") {
    rows.push([
      tr("insights.tech.carryover"),
      tr("insights.tech.pairValue", { recent: fmt(d.carryover_recent), earlier: fmt(d.carryover_earlier) }),
    ]);
  }
  if (typeof d.coupling_recent === "number") {
    rows.push([
      tr("insights.tech.coupling"),
      tr("insights.tech.pairValue", { recent: fmt(d.coupling_recent), earlier: fmt(d.coupling_earlier) }),
    ]);
  }
  if (typeof d.spread_recent === "number") {
    rows.push([
      tr("insights.tech.spread"),
      tr("insights.tech.pairValue", { recent: fmt(d.spread_recent), earlier: fmt(d.spread_earlier) }),
    ]);
  }
  return rows;
}

function describe(p: PatternCard): string {
  if (p.kind === "temporal") {
    const day = p.detail?.day !== undefined ? localWeekday(p.detail.day) : tr("insights.desc.sameDay");
    return tr("insights.desc.temporal", { label: p.label, count: p.occurrences, day });
  }
  if (p.kind === "mood_correlation") {
    const delta = p.detail?.mood_delta ?? 0;
    const direction = tr(p.detail?.direction ?? (delta < 0 ? "insights.words.higher" : "insights.words.lower"));
    return tr("insights.desc.moodCorrelation", {
      label: p.label,
      direction,
      shift: Math.abs(delta).toFixed(1),
    });
  }
  if (p.kind === "link") {
    const direction = tr(p.detail?.direction === "higher" ? "insights.words.higher" : "insights.words.lower");
    return tr("insights.desc.link", { label: p.label, direction });
  }
  if (p.kind === "inertia") {
    return tr("insights.desc.inertia");
  }
  if (p.kind === "energy_inertia") {
    return tr("insights.desc.energyInertia");
  }
  if (p.kind === "pa_inertia") {
    return tr("insights.desc.paInertia");
  }
  if (p.kind === "na_inertia") {
    return tr("insights.desc.naInertia");
  }
  if (p.kind === "energy_mood_coupling") {
    return tr("insights.desc.coupling");
  }
  if (p.kind === "sense_making") {
    return tr("insights.desc.senseMaking");
  }
  if (p.kind === "activity_diversity") {
    return tr(
      p.detail?.direction === "narrowed" ? "insights.desc.activityNarrowed" : "insights.desc.activityWidened",
    );
  }
  if (p.kind === "instability") {
    return tr("insights.desc.instability");
  }
  if (p.kind === "recurring_phrase") {
    return tr("insights.desc.recurringPhrase", { label: p.label, count: p.occurrences });
  }
  if (p.kind === "rumination") {
    return tr("insights.desc.rumination", { label: p.label, count: p.occurrences });
  }
  if (p.kind === "topic") {
    const share = p.detail?.share;
    const shareTxt = typeof share === "number"
      ? tr("insights.desc.topicShare", { share: Math.round(share * 100) })
      : "";
    if (p.detail?.trend === "rising") {
      return tr("insights.desc.topicRising", { label: p.label, share: shareTxt });
    }
    return tr("insights.desc.topicSteady", { label: p.label, share: shareTxt });
  }
  if (p.kind === "mood_shift") {
    const direction = tr(p.detail?.direction === "higher" ? "insights.words.higher" : "insights.words.lower");
    const shift = Math.abs(p.detail?.shift ?? 0);
    return tr("insights.desc.moodShift", { direction, shift: shift.toFixed(1) });
  }
  if (p.detail?.channel === "sleep_quality") {
    if (p.kind === "link") {
      const direction = tr(p.detail?.direction === "higher" ? "insights.words.higher" : "insights.words.lower");
      return tr("insights.desc.sleepLink", { direction });
    }
    if (p.kind === "mood_correlation") {
      const direction = tr(p.detail?.direction === "higher" ? "insights.words.higher" : "insights.words.lower");
      return tr("insights.desc.sleepCorrelation", { direction });
    }
    if (p.kind === "temporal") {
      return tr("insights.desc.sleepTemporal", {
        day: p.detail?.day !== undefined ? localWeekday(p.detail.day) : tr("insights.desc.certainDay"),
      });
    }
  }
  if (p.kind === "avoidance") {
    const share = typeof p.detail?.share === "number" ? Math.round(p.detail.share * 100) : null;
    const shareTxt = share !== null ? tr("insights.desc.avoidanceShare", { share }) : "";
    return tr("insights.desc.avoidance", { label: p.label, share: shareTxt });
  }
  if (p.kind === "cadence") {
    return tr("insights.desc.cadence");
  }
  if (p.detail?.source === "tag") {
    if (p.kind === "mood_correlation") {
      const direction = tr(p.detail?.direction === "higher" ? "insights.words.higher" : "insights.words.lower");
      return tr("insights.desc.tagCorrelation", { label: p.label, direction });
    }
    if (p.kind === "link") {
      const direction = tr(p.detail?.direction === "higher" ? "insights.words.higher" : "insights.words.lower");
      return tr("insights.desc.tagLink", { label: p.label, direction });
    }
    if (p.kind === "temporal") {
      return tr("insights.desc.tagTemporal", {
        label: p.label,
        day: p.detail?.day !== undefined ? localWeekday(p.detail.day) : tr("insights.desc.certainDay"),
      });
    }
  }
  return tr("insights.desc.fallback", { label: p.label, count: p.occurrences });
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
  const trend = n < 2 ? "insights.spark.steady" : diff > 0.15 ? "insights.spark.rising" : diff < -0.15 ? "insights.spark.falling" : "insights.spark.steady";
  const latest = days[n - 1]?.value ?? 0;
  const latestKey = latest > 0 ? "insights.spark.positive" : latest < 0 ? "insights.spark.negative" : "insights.spark.neutral";
  return tr("insights.spark.summary", {
    trend: tr(trend),
    count: n,
    unit: tr(n === 1 ? "common.day" : "common.days"),
    latest: tr(latestKey),
  });
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

/** How long the transient mute/unmute status note stays on screen — the
 *  same lifetime EntryScreen gives its save confirmations. */
const MUTE_NOTE_MS = 2_600;

export function InsightsScreen({ navigation }: { navigation?: any }): React.JSX.Element {
  const t = useTheme();
  const { applyActiveDays, unlockDays, touchActivity } = useSession();
  const [phase, setPhase] = useState<string>("loading");
  const [remaining, setRemaining] = useState(0);
  const [patterns, setPatterns] = useState<PatternCard[]>([]);
  /** Honesty signal (2026-09-19): "other" = the engine stepped aside for
   *  text-derived claims in this journal's language — say so instead of
   *  rendering an unexplained quiet analysis. */
  const [languageNote, setLanguageNote] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [techExpanded, setTechExpanded] = useState<string | null>(null);
  const [streak, setStreak] = useState(0);
  // Stryker disable next-line ArrayDeclaration: moods is only read behind moods.length > 2; a 1-element poisoned initial cannot pass that gate before setMoods replaces it.
  const [moods, setMoods] = useState<MoodDay[]>([]);
  // Stryker disable next-line BooleanLiteral: busy is set by the load effect before any observable read; the initial value is never observably rendered.
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** Optimistic per-pattern mutes (2026-09-19): the card hides immediately;
   *  the encrypted event queues for the next recompute, which is when the
   *  server's muted set (and question generation) catches up. Keyed by
   *  pattern_pid; a lost queue just means the pattern reappears. */
  const [mutedLocal, setMutedLocal] = useState<Record<string, boolean>>({});
  const [mutedOpen, setMutedOpen] = useState(false);
  const [muteNote, setMuteNote] = useState<string | null>(null);

  const pidOf = (p: PatternCard): string => (typeof p.detail?.pattern_pid === "string" ? p.detail.pattern_pid : "");
  const isMuted = (p: PatternCard): boolean =>
    p.detail?.muted === true || mutedLocal[pidOf(p)] === true;

  /** Audit fix 24 (2026-09-21): the mute status note is transient like
   *  every other inline confirmation — EntryScreen's showStatus idiom
   *  (clear-on-replace, clear-on-unmount) instead of staying on screen
   *  for the rest of the session. */
  const muteNoteTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showMuteNote = (message: string) => {
    if (muteNoteTimer.current) clearTimeout(muteNoteTimer.current);
    setMuteNote(message);
    muteNoteTimer.current = setTimeout(() => setMuteNote(null), MUTE_NOTE_MS);
  };
  useEffect(
    () => () => {
      if (muteNoteTimer.current) clearTimeout(muteNoteTimer.current);
    },
    [],
  );

  /** A pattern renders in the main list when it is not muted — EXCEPT a
   *  sensitive one (audit L-61): its non-quoting support card must stay up
   *  even when the server's muted set contains it. The UI never offers a
   *  mute on a sensitive card; if one arrives muted anyway (a mute that
   *  predates the sensitive flag, or the LLM merge), dropping it would
   *  remove the support pointer — the one thing this screen must never
   *  do. Sensitive cards quote nothing, so keeping them up leaks nothing. */
  const rendersInList = (p: PatternCard): boolean => isSensitive(p) || !isMuted(p);

  /** Queue mute/unmute and apply it optimistically. The vault must be
   *  unlocked (it always is on this screen — the shell swaps it out on
   *  lock), and a queue failure only costs the optimistic state: the
   *  pattern returns on the next load, which is the honest direction. */
  const mutePattern = (p: PatternCard, mute: boolean) => {
    const pid = pidOf(p);
    if (!pid) return;
    touchActivity();
    setMutedLocal((prev) => ({ ...prev, [pid]: mute }));
    showMuteNote(mute ? tr("insights.mutedNote") : tr("insights.unmutedNote"));
    void (async () => {
      try {
        const userId = await api.getUserId();
        if (userId) await recordPatternMute(vault.get().dataKey, userId, pid, mute);
      } catch {
        // The optimistic state stands for this session; nothing to alert.
      }
    })();
  };

  /** Request sequencing (audit L-60, 2026-09-20): pull-to-refresh and the
   *  Retry button can overlap a slow in-flight load, and the OLDER
   *  response used to land last and briefly replace the newer one's
   *  patterns with stale cards. Every await point re-checks the epoch; a
   *  superseded load stops writing state entirely (its finally must not
   *  clear the newer load's busy flag either). Same idiom as
   *  HistoryScreen's historyLoadEpochRef. */
  const loadEpochRef = useRef(0);

  const load = useCallback(async () => {
    const epoch = ++loadEpochRef.current;
    setBusy(true);
    setError(null);
    try {
      const summary = await api.insights();
      if (epoch !== loadEpochRef.current) return;
      // A hostile server must not be able to drive the UI into an unknown
      // branch: only the two real phases are accepted.
      if (summary.phase !== "baseline" && summary.phase !== "insight") {
        throw new Error(tr("insights.unknownPhase"));
      }
      setPhase(summary.phase);
      // Stryker disable next-line ConditionalExpression, LogicalOperator: Number.isFinite implies typeof number; days_remaining arrives via JSON and the non-numeric case is pinned by test.
      setRemaining(typeof summary.days_remaining === "number" && Number.isFinite(summary.days_remaining) ? summary.days_remaining : 0);
      // The active-days counter applies from THIS response (audit L-59):
      // refreshActiveDays() here issued a second GET /insights per load —
      // double latency and double rate budget for data already in hand.
      applyActiveDays(summary.active_days);
      // Baseline-phase value is device-local: streak + mood trend, no
      // server involvement. The log is encrypted under the data key —
      // only reachable on this screen while the vault is unlocked.
      const userId = await api.getUserId();
      if (epoch !== loadEpochRef.current) return;
      if (userId && vault.get().dataKey) {
        const dataKey = vault.get().dataKey;
        localStreak(dataKey, userId)
          .then((streak) => {
            if (epoch === loadEpochRef.current) setStreak(streak);
          })
          .catch(() => {});
        recentMoods(dataKey, userId, 30)
          .then((days) => {
            if (epoch === loadEpochRef.current) setMoods(days);
          })
          .catch(() => {});
      }
      if (summary.blob) {
        const userId = (await api.getUserId()) ?? "";
        if (epoch !== loadEpochRef.current) return;
        const payload = decryptInsights(vault.get(), userId, summary.blob);
        // Rollback guard (2026-09-19): the payload's embedded analysis
        // generation must equal the plaintext echo and never move below
        // this device's pinned high-water mark — a silent replay of an
        // older valid-GCM blob otherwise renders as today's truth.
        await checkAnalysisGeneration(userId, payload.state_seq, summary.state_seq);
        if (epoch !== loadEpochRef.current) return;
        setLanguageNote(payload.stats?.language === "other");
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
      // A superseded load's failure is not the screen's failure.
      if (epoch === loadEpochRef.current) setError(requestFailureCopy(err));
    } finally {
      if (epoch === loadEpochRef.current) setBusy(false);
    }
  }, // Stryker disable next-line ArrayDeclaration: constant deps are equivalent under the test seam (the mocked applyActiveDays has a stable identity); in production the dependency keeps the callback honest.
     [applyActiveDays]);

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
          <GhostButton label={tr("common.tryAgain")} onPress={load} accessibilityLabel={tr("insights.tryAgainA11y")} />
        </View>
      )}
      {phase === "loading" && <ActivityIndicator color={t.colors.primaryBright} />}
      {phase === "baseline" && (
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>
            {tr("insights.baselineTitle", {
              count: remaining,
              unit: tr(remaining === 1 ? "common.day" : "common.days"),
            })}
          </Text>
          <Text style={cardStyles.cardBody}>{tr("insights.baselineBody", { days: unlockDays })}</Text>
          {streak > 0 && (
            <Text style={cardStyles.meta}>
              {streak === 1 ? tr("common.streakOne", { count: streak }) : tr("common.streakMany", { count: streak })}
            </Text>
          )}
          {moods.length > 2 && (
            <>
              <Text style={cardStyles.meta}>{tr("insights.moodMonthDevice")}</Text>
              <MoodSparkline days={moods} />
            </>
          )}
        </View>
      )}
      {phase === "insight" && languageNote && (
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>{tr("insights.languageTitle")}</Text>
          <Text style={cardStyles.cardBody}>{tr("insights.languageBody")}</Text>
        </View>
      )}
      {phase === "insight" && patterns.filter(rendersInList).length === 0 && !busy && (
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>{tr("insights.nothingSolidTitle")}</Text>
          <Text style={cardStyles.cardBody}>
            {patterns.some((p) => isMuted(p) && !isSensitive(p))
              ? tr("insights.allMutedBody")
              : tr("insights.noEvidenceBody")}
          </Text>
        </View>
      )}
      {phase === "insight" && moods.length > 2 && (
        // The mood check-in keeps paying off after the threshold: the
        // trend it fed during baseline stays visible beside the pattern
        // cards (device-local, never synced — same data, same rules).
        <View style={cardStyles.card}>
          <Text style={cardStyles.cardTitle}>{tr("insights.moodMonth")}</Text>
          <MoodSparkline days={moods} />
          <Text style={cardStyles.meta}>{tr("insights.moodMonthNote")}</Text>
        </View>
      )}
      {muteNote && <Text style={[styles.footnote, { color: t.colors.muted }]}>{muteNote}</Text>}
      {/* L-58: the MAIN card list now carries the same phase gate every
          sibling section enforces — "baseline" renders no pattern cards
          even if a hostile/legacy response shipped a blob alongside the
          baseline phase (the server-trust-boundary display rule). */}
      {phase === "insight" && patterns.filter(rendersInList).map((p, i) => {
        const key = `${p.kind}-${p.label}-${i}`;
        if (isSensitive(p)) {
          // Non-quoting variant: no label, no counts, no stats, no expander.
          return (
            <View key={key} style={cardStyles.card}>
              <Text style={cardStyles.cardBody}>{tr("insights.sensitiveBody")}</Text>
              <Text style={cardStyles.meta}>{tr("common.neverWrongMove")}</Text>
              <GhostButton
                label={tr("insights.supportResources")}
                center={false}
                onPress={() => navigation?.navigate("Crisis")}
                accessibilityLabel={tr("insights.supportResourcesA11y")}
              />
            </View>
          );
        }
        // Stryker disable next-line StringLiteral: the fallback key hits no STATE_LABELS entry for every possible value; any replacement key still lands on observed.
        const stateKey = STATE_LABEL_KEYS[p.detail?.pattern_state ?? ""];
        const stateLabel = stateKey ? tr(stateKey) : tr("insights.state.observed");
        const isOpen = expanded === key;
        const techOpen = techExpanded === key;
        const presence = p.detail?.presence === true; // low-confidence: down-ranked visually
        return (
          <View key={key} style={cardStyles.card}>
            <View style={styles.cardHeader}>
              <Text style={[cardStyles.kind, presence && { color: t.colors.muted }]}>{kindLabel(p.kind)}</Text>
              <Text style={stateLabel === tr("insights.state.confirmed") ? cardStyles.stateStrong : cardStyles.stateEarly}>
                {stateLabel}
                {p.detail?.is_new ? tr("insights.newFlag") : ""}
              </Text>
            </View>
            <Text style={[cardStyles.cardBody, presence && { color: t.colors.muted }]}>{p.describe}</Text>
            {typeof p.detail?.narrative === "string" && p.detail.narrative.length > 0 && (
              <Text style={[styles.narrative, { color: t.colors.muted }]}>{p.detail.narrative}</Text>
            )}
            <Text style={cardStyles.meta}>
              {tr("insights.meta", { count: p.occurrences, density: (p.confidence * 100).toFixed(0) })}
            </Text>
            <TouchableOpacity
              onPress={() => setExpanded(isOpen ? null : key)}
              accessibilityRole="button"
              accessibilityLabel={isOpen ? tr("insights.hideEvidence") : tr("insights.whySeeingA11y")}
              accessibilityState={{ expanded: isOpen }}
              hitSlop={t.touchSlop}
              style={styles.whyToggle}
            >
              <Text style={[styles.whyText, { color: t.colors.accent }]}>
                {isOpen ? tr("insights.hideEvidence") : tr("insights.whySeeing")}
              </Text>
            </TouchableOpacity>
            {/* Per-pattern mute (2026-09-19): quiet, never offered on
                sensitive cards (their support pointer must stay put), and
                reversible from the muted section below. */}
            <TouchableOpacity
              onPress={() => mutePattern(p, true)}
              accessibilityRole="button"
              accessibilityLabel={tr("insights.muteA11y", { label: p.label })}
              hitSlop={t.touchSlop}
              style={styles.whyToggle}
            >
              <Text style={[styles.muteText, { color: t.colors.muted }]}>{tr("insights.muteLabel")}</Text>
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
                      accessibilityLabel={techOpen ? tr("insights.hideTech") : tr("insights.techDetailsA11y")}
                      accessibilityState={{ expanded: techOpen }}
                      hitSlop={t.touchSlop}
                      style={styles.whyToggle}
                    >
                      <Text style={[styles.techText, { color: t.colors.muted }]}>
                        {techOpen ? tr("insights.hideTech") : tr("insights.techDetails")}
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
                  {tr("insights.evidenceFootnote1")}
                </Text>
                <Text style={[styles.evidenceFootnote, { color: t.colors.muted }]}>
                  {tr("insights.evidenceFootnote2")}
                </Text>
              </View>
            )}
          </View>
        );
      })}
      {phase === "insight" && patterns.some((p) => isMuted(p) && !isSensitive(p)) && (
        <View style={cardStyles.card}>
          <TouchableOpacity
            onPress={() => setMutedOpen(!mutedOpen)}
            accessibilityRole="button"
            accessibilityLabel={
              mutedOpen
                ? tr("insights.hideMutedA11y")
                : tr("insights.showMutedA11y", {
                    count: patterns.filter((p) => isMuted(p) && !isSensitive(p)).length,
                  })
            }
            accessibilityState={{ expanded: mutedOpen }}
            hitSlop={t.touchSlop}
            style={styles.whyToggle}
          >
            <Text style={[styles.whyText, { color: t.colors.muted }]}>
              {mutedOpen
                ? tr("insights.mutedCountHide", { count: patterns.filter((p) => isMuted(p) && !isSensitive(p)).length })
                : tr("insights.mutedCountShow", { count: patterns.filter((p) => isMuted(p) && !isSensitive(p)).length })}
            </Text>
          </TouchableOpacity>
          <Text style={cardStyles.meta}>{tr("insights.mutedNoteBody")}</Text>
          {mutedOpen &&
            patterns.filter((p) => isMuted(p) && !isSensitive(p)).map((p, i) => (
              <View key={`muted-${p.kind}-${p.label}-${i}`} style={styles.mutedRow}>
                <Text style={cardStyles.meta}>
                  {kindLabel(p.kind)} · {p.label}
                </Text>
                <TouchableOpacity
                  onPress={() => mutePattern(p, false)}
                  accessibilityRole="button"
                  accessibilityLabel={tr("insights.unmuteA11y", { label: p.label })}
                  hitSlop={t.touchSlop}
                >
                  <Text style={[styles.muteText, { color: t.colors.accent }]}>{tr("insights.unmute")}</Text>
                </TouchableOpacity>
              </View>
            ))}
        </View>
      )}
      {phase === "insight" && (
        <Text style={[styles.footnote, { color: t.colors.muted }]}>{tr("insights.footnote")}</Text>
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
  muteText: { fontSize: 12, fontWeight: "600" },
  mutedRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 10 },
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
