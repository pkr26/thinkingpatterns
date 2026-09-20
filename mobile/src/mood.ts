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
 */
import { sentimentScore } from "./brain/sentiment";

export interface MoodOption {
  value: number;
  label: string;
}

/** The five check-in picks, Heavy → Light. An explicit tap always wins over
 *  the text estimate; never tapping is fine and never blocks saving. */
export const MOOD_OPTIONS: readonly MoodOption[] = [
  { value: -1, label: "Heavy" },
  { value: -0.5, label: "Low" },
  { value: 0, label: "Okay" },
  { value: 0.5, label: "Good" },
  { value: 1, label: "Light" },
];

/** The optional energy dimension (2026-09-17): a second, orthogonal
 *  check-in — mood and energy dissociate (low mood with high energy,
 *  flat mood with drain), and the structured-channel analysis reads the
 *  same [-1, 1] range. Three picks keep it one-tap light. */
export const ENERGY_OPTIONS: readonly MoodOption[] = [
  { value: -1, label: "Drained" },
  { value: 0, label: "Steady" },
  { value: 1, label: "Energized" },
];

/** The optional sleep-quality picks (2026-09-17, payload v2): 1..5 as the
 *  server channel expects. Five words keep it one-tap; the labels describe
 *  the NIGHT, not the person. */
export const SLEEP_OPTIONS: readonly { value: number; label: string }[] = [
  { value: 1, label: "Rough" },
  { value: 2, label: "Poor" },
  { value: 3, label: "Okay" },
  { value: 4, label: "Good" },
  { value: 5, label: "Rested" },
];

/** The day-shaping activity tags (2026-09-17, payload v2): deliberately
 *  few, plain, and non-clinical — the engine correlates them with mood as
 *  within-person binary day channels. Users can also skip them entirely. */
export const ACTIVITY_TAGS: readonly string[] = [
  "work", "family", "friends", "exercise", "outdoors", "rest",
  "creative", "health", "money", "travel",
];

/** The closest scale label for any value in [-1, 1] — badges render the
 *  stored quick score, which is rarely one of the five exact picks. */
export function moodLabel(value: number): string {
  let best = MOOD_OPTIONS[0]!;
  for (const option of MOOD_OPTIONS) {
    if (Math.abs(option.value - value) < Math.abs(best.value - value)) best = option;
  }
  return best.label;
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
  return sentimentScore(text);
}
