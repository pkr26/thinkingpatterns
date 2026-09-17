/**
 * GENERIC_QUESTIONS — EMBEDDED COPY of shared/generic_questions.json
 * (the cross-platform source of truth; Metro cannot import outside the
 * project root). Sync is enforced by tests/genericQuestions.test.ts,
 * which reads the shared file from disk and pins array-for-array parity.
 *
 * Invariants (pinned on BOTH platforms by test):
 *  - every entry ends with "?" (questions, never instructions)
 *  - the word "should" never appears (no advice language)
 *
 * 2026-09-17: expanded 8 -> 60 across evidence-informed reflective
 * families — noticing, self-compassion, gratitude, meaning, emotion
 * granularity, connection, energy, honest difficulty, curiosity. Every
 * phrasing stays observational, never prescriptive.
 */

import { localDateISO } from "./moodLog";

/** One reflective question per baseline day (deterministic rotation). */
export const GENERIC_QUESTIONS: readonly string[] = [
  "What took up most space in your mind today?",
  "What felt different today compared to yesterday?",
  "When did you feel most like yourself today?",
  "What's one small thing that went right today?",
  "What thought repeated itself today?",
  "If today had a title, what would it be?",
  "What are you carrying into tomorrow?",
  "What did you notice today that you usually overlook?",
  "What did your body notice before your mind did today?",
  "What was the quietest moment of your day?",
  "What sound do you remember from today?",
  "What did you see today that you'd want to see again?",
  "What would you say to a friend who had your day?",
  "What's something you did today that took effort?",
  "What did you forgive yourself for today?",
  "What would make tomorrow 1% kinder to you?",
  "What are three things that went okay today?",
  "Who made your day a little lighter today?",
  "What's something you're looking forward to?",
  "What comforted you today?",
  "What's one thing worth keeping from today?",
  "What mattered most to you today?",
  "When did today feel meaningful?",
  "What value showed up in something you did today?",
  "What would you like more of in your life?",
  "If your mood today had a texture, what would it feel like?",
  "What emotion visited you most today?",
  "What emotion surprised you today?",
  "Where in your body did today's strongest feeling live?",
  "Who did you think about today?",
  "What conversation stayed with you today?",
  "When did you feel understood today?",
  "When did you feel alone today, and what was that like?",
  "What gave you energy today?",
  "What drained you today?",
  "What did you say no to today?",
  "What did you let go of today?",
  "What part of the day felt longest?",
  "When were you most absorbed in something today?",
  "What did today's pace feel like?",
  "What was the hardest part of today?",
  "What did you get through today that felt heavy?",
  "What are you avoiding, gently speaking?",
  "What worry got smaller once you wrote it down?",
  "What are you curious about right now?",
  "What's a question you're sitting with lately?",
  "What would you like to remember about this time?",
  "What's one small thing you're curious to attempt tomorrow?",
  "What did you taste today that you remember?",
  "Where did you feel most at ease today?",
  "What's a place you'd rather have been today?",
  "What feels most like 'you' these days?",
  "What's changing in you lately, slowly?",
  "What has stayed steady in you lately?",
  "If today were weather, what was it?",
  "What would tomorrow look like in an ideal world?",
  "If you could send yourself a note this morning, what would it say?",
  "What did you do today purely because you wanted to?",
  "What did today ask of you?",
  "What are you grateful to past-you for today?",
];

/** djb2 over the date string: a pure function of the local calendar day,
 *  so the pick is stable within the day and rotates as the date changes.
 *  (Day-to-day rotation is not a uniform shuffle — consecutive dates land
 *  on adjacent pool slots — which is exactly the desired behavior.) */
function seedFromDate(date: string): number {
  let hash = 5381;
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
