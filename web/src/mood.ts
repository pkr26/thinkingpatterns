/**
 * The mood vocabulary: the explicit check-in scale plus the quick
 * text-derived estimate. Shared by the Entry screen (the one-tap mood row
 * and the device-local mood log write) and the History screen (per-entry
 * mood badge).
 *
 * Values live in [-1, 1] — the range the mood log and the entry payload's
 * sentiment field already use. The labels deliberately avoid clinical and
 * judgmental language: Heavy and Light are states of the day, not verdicts
 * about the person.
 *
 * LOCALIZATION (audit fix 21, 2026-09-21): the VALUES are the wire
 * contract — numbers for mood/energy/sleep and English tag tokens — and
 * are never localized. Display labels resolve through the i18n catalog by
 * value (`labelKey`, plus activityTagLabel for the tags), so the check-in
 * speaks the app locale while the payload the server's engine reads stays
 * byte-identical across locales.
 */
import { detectLanguage, sentimentScore } from "./brain/sentiment";
import { t } from "./strings";

export interface MoodOption {
  value: number;
  /** The English fallback label — also the stable React key. */
  label: string;
  /** Catalog key of the localized display label. */
  labelKey: string;
}

/** The five check-in picks, Heavy → Light. An explicit tap always wins over
 *  the text estimate; never tapping is fine and never blocks saving. */
export const MOOD_OPTIONS: readonly MoodOption[] = [
  { value: -1, label: "Heavy", labelKey: "mood.option.heavy" },
  { value: -0.5, label: "Low", labelKey: "mood.option.low" },
  { value: 0, label: "Okay", labelKey: "mood.option.okay" },
  { value: 0.5, label: "Good", labelKey: "mood.option.good" },
  { value: 1, label: "Light", labelKey: "mood.option.light" },
];

/** The optional energy dimension (2026-09-17): a second, orthogonal
 *  check-in — mood and energy dissociate (low mood with high energy,
 *  flat mood with drain), and the structured-channel analysis reads the
 *  same [-1, 1] range. Three picks keep it one-tap light. */
export const ENERGY_OPTIONS: readonly MoodOption[] = [
  { value: -1, label: "Drained", labelKey: "energy.option.drained" },
  { value: 0, label: "Steady", labelKey: "energy.option.steady" },
  { value: 1, label: "Energized", labelKey: "energy.option.energized" },
];

/** The optional sleep-quality picks (2026-09-17, payload v2): 1..5 as the
 *  server channel expects. Five words keep it one-tap; the labels describe
 *  the NIGHT, not the person. */
export const SLEEP_OPTIONS: readonly { value: number; label: string; labelKey: string }[] = [
  { value: 1, label: "Rough", labelKey: "sleep.option.1" },
  { value: 2, label: "Poor", labelKey: "sleep.option.2" },
  { value: 3, label: "Okay", labelKey: "sleep.option.3" },
  { value: 4, label: "Good", labelKey: "sleep.option.4" },
  { value: 5, label: "Rested", labelKey: "sleep.option.5" },
];

/** The day-shaping activity tags (2026-09-17, payload v2): deliberately
 *  few, plain, and non-clinical — the engine correlates them with mood as
 *  within-person binary day channels. Users can also skip them entirely.
 *  The tokens ARE the wire values (never translated); render them through
 *  activityTagLabel. */
export const ACTIVITY_TAGS: readonly string[] = [
  "work", "family", "friends", "exercise", "outdoors", "rest",
  "creative", "health", "money", "travel",
];

/** Localized display label for a check-in option (by its catalog key). */
export function optionLabel(option: { labelKey: string }): string {
  return t(option.labelKey);
}

/** Localized display label for an activity tag. An unknown tag (another
 *  client's vocabulary riding in a decrypted payload) renders as its raw
 *  wire value — never a raw catalog key. */
export function activityTagLabel(tag: string): string {
  return ACTIVITY_TAGS.includes(tag) ? t(`activityTag.${tag}`) : tag;
}

/** The closest scale label for any value in [-1, 1] — badges render the
 *  stored quick score, which is rarely one of the five exact picks. */
export function moodLabel(value: number): string {
  let best = MOOD_OPTIONS[0]!;
  for (const option of MOOD_OPTIONS) {
    if (Math.abs(option.value - value) < Math.abs(best.value - value)) best = option;
  }
  return t(best.labelKey);
}

/** The device-local mood estimate (2026-09-19): the REAL graded engine —
 *  the on-device brain's port of the server's deterministic sentiment
 *  walk (mobile/src/brain/sentiment.ts), vector-pinned to the Python
 *  engine via shared/brain_vectors.json. The old 20-word ratio hack is
 *  retired: the local trend, History badges and fallback mood-log values
 *  now score exactly as the server would. Never sent as plaintext
 *  metadata; in the entry payload only a deliberate check-in pick rides
 *  along. */
export function localSentiment(text: string): number {
  // L-3 (2026-09-26): the on-device estimate scores Spanish text with
  // the ES-winning merge, mirroring the server's language-gated walk.
  return sentimentScore(text, detectLanguage(text));
}
