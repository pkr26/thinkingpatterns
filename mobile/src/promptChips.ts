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
 */

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

/** Deterministic per-day selection: a multiplicative hash of the date
 *  ordinal picks the rotation offset, then the first `count` pool entries
 *  (wrapping) come out in pool order. Same day → same chips, forever. */
export function promptChipsFor(day: Date, count = 3): string[] {
  const ordinal = Math.floor(day.getTime() / 86_400_000);
  // A small odd multiplier spreads consecutive days across the pool.
  const offset = ((ordinal * 7) % PROMPT_CHIPS.length + PROMPT_CHIPS.length) % PROMPT_CHIPS.length;
  const chips: string[] = [];
  const total = Math.min(count, PROMPT_CHIPS.length);
  for (let i = 0; i < total; i++) {
    const chip = PROMPT_CHIPS[(offset + i) % PROMPT_CHIPS.length];
    if (chip !== undefined) chips.push(chip);
  }
  return chips;
}
