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
import type { Locale } from "./strings";

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
 *  defaults to today. E-3 (2026-09-21 audit): the pre-threshold baseline
 *  loop is localized — the Spanish pool (below) is position-parity with
 *  the English one, so the same rotation picks the equivalent question. */
export function genericQuestionForDate(
  date: string = localDateISO(),
  locale: Locale = "en",
): string {
  const pool = locale === "es" ? GENERIC_QUESTIONS_ES : GENERIC_QUESTIONS;
  return pool[seedFromDate(date) % pool.length]!;
}

/** GENERIC_QUESTIONS_ES — embedded copy of shared/generic_questions_es.json
 *  (E-3, 2026-09-21 audit: the entire 30-day baseline question loop used
 *  to be English-only). Position-parity with the English pool: index i in
 *  each pool is the same question. Invariants (pinned by test, including
 *  the shared-file sync and the parity itself): every entry ends with "?",
 *  and "debería" (advice language) never appears — the Spanish mirror of
 *  the English "should" rule. Usted register, matching the app's Spanish
 *  catalog. */
export const GENERIC_QUESTIONS_ES: readonly string[] = [
  "¿Qué ocupó la mayor parte de su mente hoy?",
  "¿Qué se sintió diferente hoy en comparación con ayer?",
  "¿Cuándo se sintió más usted mismo o usted misma hoy?",
  "¿Qué pequeña cosa salió bien hoy?",
  "¿Qué pensamiento se repitió hoy?",
  "Si hoy tuviera un título, ¿cuál sería?",
  "¿Qué se lleva consigo hacia mañana?",
  "¿Qué notó hoy que suele pasar por alto?",
  "¿Qué notó su cuerpo antes que su mente hoy?",
  "¿Cuál fue el momento más tranquilo de su día?",
  "¿Qué sonido recuerda de hoy?",
  "¿Qué vio hoy que le gustaría volver a ver?",
  "¿Qué le diría a un amigo que hubiera tenido su día?",
  "¿Qué hizo hoy que le exigió esfuerzo?",
  "¿Qué se perdonó hoy?",
  "¿Qué haría que mañana fuera un 1% más amable con usted?",
  "¿Qué tres cosas salieron más o menos bien hoy?",
  "¿Quién hizo su día un poco más ligero hoy?",
  "¿Hay algo que espera con ilusión?",
  "¿Qué la confortó hoy?",
  "¿Qué vale la pena conservar de hoy?",
  "¿Qué fue lo que más le importó hoy?",
  "¿Cuándo sintió que hoy tenía sentido?",
  "¿Qué valor suyo apareció en algo que hizo hoy?",
  "¿Qué le gustaría tener más en su vida?",
  "Si el estado de ánimo de hoy tuviera una textura, ¿cómo se sentiría?",
  "¿Qué emoción lo visitó más hoy?",
  "¿Qué emoción lo sorprendió hoy?",
  "¿En qué parte del cuerpo vivió hoy el sentimiento más fuerte?",
  "¿En quién pensó hoy?",
  "¿Qué conversación se quedó con usted hoy?",
  "¿Cuándo se sintió comprendido o comprendida hoy?",
  "¿Cuándo se sintió solo o sola hoy, y cómo fue eso?",
  "¿Qué le dio energía hoy?",
  "¿Qué lo agotó hoy?",
  "¿A qué dijo no hoy?",
  "¿Qué dejó ir hoy?",
  "¿Qué parte del día se sintió más larga?",
  "¿Cuándo estuvo más absorbido o absorbida en algo hoy?",
  "¿Cómo sintió el ritmo de hoy?",
  "¿Cuál fue la parte más difícil de hoy?",
  "¿Qué atravesó hoy que se sintió pesado?",
  "¿Qué está evitando, dicho con gentileza?",
  "¿Qué preocupación se hizo más pequeña al escribirla?",
  "¿Sobre qué tiene curiosidad ahora mismo?",
  "¿Qué pregunta lleva rondándole últimamente?",
  "¿Qué le gustaría recordar de esta época?",
  "¿Qué pequeña cosa tiene curiosidad por intentar mañana?",
  "¿Qué saboreó hoy y recuerda?",
  "¿Dónde se sintió más a gusto hoy?",
  "¿En qué lugar habría preferido estar hoy?",
  "¿Qué se siente más como 'usted' en estos días?",
  "¿Qué está cambiando en usted lenta y lentamente?",
  "¿Qué se ha mantenido estable en usted últimamente?",
  "Si hoy fuera un clima, ¿cuál habría sido?",
  "¿Cómo sería mañana en un mundo ideal?",
  "Si pudiera enviarse una nota esta mañana, ¿qué diría?",
  "¿Qué hizo hoy puramente porque quería?",
  "¿Qué le pidió hoy el día?",
  "¿Por qué le agradece hoy a su yo del pasado?",
];
