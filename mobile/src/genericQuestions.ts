/**
 * The generic reflective question pool — EMBEDDED COPY of
 * shared/generic_questions.json (the cross-platform source of truth).
 *
 * Why embed instead of import: Metro cannot resolve modules outside the
 * project root, so the shared JSON cannot be imported at runtime (the same
 * reason shared/vectors.json is verified by a node tool). Sync is enforced
 * by tests/genericQuestions.test.ts, which reads the shared file from disk
 * and pins array parity plus the content invariants (every entry is a
 * question, none contains advice language).
 *
 * Scope: this pool serves PRE-THRESHOLD users only (a day-1 question while
 * the account is below the pattern threshold; the server-side engine takes
 * over after it). The rotation below is device-local and deterministic —
 * the same question all day, a different one tomorrow — but it is NOT
 * stable across platforms and does not need to be: the backend derives its
 * own daily question, and nothing compares the two.
 */
import { localDateISO } from "./moodLog";

export const GENERIC_QUESTIONS: readonly string[] = [
  "What took up most space in your mind today?",
  "What felt different today compared to yesterday?",
  "When did you feel most like yourself today?",
  "What's one small thing that went right today?",
  "What thought repeated itself today?",
  "If today had a title, what would it be?",
  "What are you carrying into tomorrow?",
  "What did you notice today that you usually overlook?",
];

/** djb2 over the date string: a pure function of the local calendar day,
 *  so the pick is stable within the day and rotates as the date changes.
 *  (Day-to-day rotation is not a uniform shuffle — consecutive dates land
 *  on adjacent pool slots — which is exactly the desired behavior.) */
function seedFromDate(date: string): number {
  let hash = 5381;
  // Stryker disable next-line EqualityOperator: the extra iteration multiplies the final seed by 33 (charCodeAt past the end is NaN, an XOR no-op) and 33 ≡ 1 (mod 8) — with the 8-item pool, seed % 8 picks the same index for every date
  for (let i = 0; i < date.length; i++) {
    hash = ((hash * 33) ^ date.charCodeAt(i)) >>> 0;
  }
  return hash;
}

/** The day's question for the given LOCAL calendar date (YYYY-MM-DD);
 *  defaults to today. */
export function genericQuestionForDate(date: string = localDateISO()): string {
  return GENERIC_QUESTIONS[seedFromDate(date) % GENERIC_QUESTIONS.length]!;
}
