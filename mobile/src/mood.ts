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

/** The closest scale label for any value in [-1, 1] — badges render the
 *  stored quick score, which is rarely one of the five exact picks. */
export function moodLabel(value: number): string {
  let best = MOOD_OPTIONS[0]!;
  for (const option of MOOD_OPTIONS) {
    if (Math.abs(option.value - value) < Math.abs(best.value - value)) best = option;
  }
  return best.label;
}

/** Quick client-side mood estimate: drives the local (device-only) trend
 *  view before patterns unlock. Never sent as plaintext metadata and, in
 *  the entry payload, only a deliberate check-in pick rides along — the
 *  server's graded engine re-scores the text at analysis time. */
export function localSentiment(text: string): number {
  const positive = (text.toLowerCase().match(/\b(good|great|happy|calm|grateful|relaxed|excited|proud|hopeful)\b/g) ?? []).length;
  const negative = (text.toLowerCase().match(/\b(bad|sad|anxious|anxiety|stressed|angry|worried|tired|lonely|overwhelmed)\b/g) ?? []).length;
  // When positive == negative the ratio below already evaluates to 0, so
  // `-` and `+` agree on every reachable input.
  // Stryker disable ArithmeticOperator
  if (positive + negative === 0) return 0;
  // Stryker restore ArithmeticOperator
  return Number(((positive - negative) / (positive + negative)).toFixed(2));
}
