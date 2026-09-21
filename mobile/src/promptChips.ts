/**
 * Gentle writing starters for blank-page days (2026-09-17).
 *
 * Depression's blank-page paralysis is a documented journaling barrier;
 * three rotating starters above an empty editor give the first words
 * without steering content. The pool is deliberately non-clinical — no
 * CBT scaffolding, no "should" — matching the app's observation-only
 * voice. Selection is DETERMINISTIC per day (a seeded shuffle over the
 * date ordinal): no RNG, testable, and the same chips stay put within a
 * day so they don't visually flicker on re-renders.
 *
 * E-3 (2026-09-21 audit): the chips are LOCALIZED. Chips are seed text
 * for the user's own journal, not UI chrome — a Spanish speaker should
 * seed Spanish text — so the pools are parallel arrays (position-parity:
 * index i is the same starter) and `promptChipsFor` picks by locale.
 */

import type { Locale } from "./strings";

export const PROMPT_CHIPS: readonly string[] = [
  "Today I noticed…",
  "One small thing that happened…",
  "On my mind right now…",
  "Something I want to remember…",
  "Today felt…",
  "A moment worth keeping…",
  "I didn't expect…",
  "Someone I thought of today…",
  "The best part of today…",
  "The hardest part of today…",
  "Something I'm looking forward to…",
  "If today had a title…",
  "My body feels…",
  "The weather matched my mood when…",
  "One thing I did for myself…",
  "Something I keep putting off…",
  "A sound I heard today…",
  "Somewhere I went today…",
  "I felt most like myself when…",
  "Something that surprised me…",
] as const;

/** E-3 (2026-09-21): the Spanish starters, position-parity with the
 *  English pool (index i = the same chip). Usted register. */
export const PROMPT_CHIPS_ES: readonly string[] = [
  "Hoy noté…",
  "Una pequeña cosa que pasó…",
  "En mi mente ahora…",
  "Algo que quiero recordar…",
  "Hoy se sintió…",
  "Un momento que vale la pena guardar…",
  "No esperaba…",
  "Alguien en quien pensé hoy…",
  "Lo mejor de hoy…",
  "Lo más difícil de hoy…",
  "Algo que espero con ilusión…",
  "Si hoy tuviera un título…",
  "Mi cuerpo siente…",
  "El clima acompañó mi estado de ánimo cuando…",
  "Una cosa que hice por mí…",
  "Algo que sigo postergando…",
  "Un sonido que escuché hoy…",
  "Un lugar al que fui hoy…",
  "Me sentí más yo cuando…",
  "Algo que me sorprendió…",
] as const;

/** Deterministic per-day selection: a multiplicative hash of the date
 *  ordinal picks the rotation offset, then the first `count` pool entries
 *  (wrapping) come out in pool order. Same day → same chips, forever.
 *
 *  L-70 (2026-09-20 audit): the ordinal is the LOCAL CALENDAR day
 *  (Date.UTC over the local y/m/d fields), not the UTC day a raw
 *  getTime()/86_400_000 division yields — chips used to rotate mid-evening
 *  for everyone outside UTC, "today's" starters changing under the user
 *  while they wrote. Date.UTC keeps the ordinal an exact integer per local
 *  day regardless of timezone or DST. */
export function promptChipsFor(day: Date, count = 3, locale: Locale = "en"): string[] {
  const pool = locale === "es" ? PROMPT_CHIPS_ES : PROMPT_CHIPS;
  const ordinal = Math.floor(Date.UTC(day.getFullYear(), day.getMonth(), day.getDate()) / 86_400_000);
  // A small odd multiplier spreads consecutive days across the pool.
  const offset = ((ordinal * 7) % pool.length + pool.length) % pool.length;
  const chips: string[] = [];
  const total = Math.min(count, pool.length);
  for (let i = 0; i < total; i++) {
    const chip = pool[(offset + i) % pool.length];
    if (chip !== undefined) chips.push(chip);
  }
  return chips;
}
