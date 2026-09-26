/**
 * L-3 (2026-09-26 audit) parity pins: the on-device engine's
 * language-gated scoring mirrors brain.py's SENTIMENT_LEXICON_ES /
 * _negators_for / detection heuristic. The DEFAULT (no language) stays
 * byte-identical to the pre-change walk — that is separately pinned by
 * the shared brain vectors; these pins cover the new surface.
 */
import { describe, expect, it } from "vitest";

import { detectLanguage, sentimentScore } from "../src/brain/sentiment";

const SPANISH_PARAGRAPH =
  "hoy me siento muy bien porque mi familia vino a verme y comimos juntos " +
  "una comida muy rica, después dimos un largo paseo por el parque y " +
  "hablamos de todo un poco, la verdad es que era perfecto y estoy feliz " +
  "de haber pasado el día con ellos aunque estaba un poco cansada al final, " +
  "pero valió la pena porque estas cosas son las que recuerdas cuando la " +
  "semana ha sido difícil y el trabajo te deja sin energía";

const ENGLISH_PARAGRAPH =
  "today was a good day because my family came over and we cooked a big " +
  "lunch together, then we took a long walk in the park and talked about " +
  "everything, it was perfect and I am glad I spent the day with them " +
  "even though I was a bit tired at the end, but it was worth it because " +
  "these are the moments you remember when the week has been hard and " +
  "work leaves you with no energy at all";

describe("language detection (brain heuristic port)", () => {
  it("classifies a Spanish paragraph as es", () => {
    expect(detectLanguage(SPANISH_PARAGRAPH)).toBe("es");
  });

  it("classifies an English paragraph as en", () => {
    expect(detectLanguage(ENGLISH_PARAGRAPH)).toBe("en");
  });

  it("keeps the historical English default below the min-token floor", () => {
    expect(detectLanguage("me siento fatal hoy")).toBe("en");
    expect(detectLanguage("feeling great today")).toBe("en");
  });
});

describe("language-gated sentiment scoring (L-3)", () => {
  it("scores Spanish text with the ES-winning merge (perfecto unmuted)", () => {
    // "perfecto" carries 2.8 in the ES merge vs 1.3 in the EN-winning
    // default — the shared word the audit found muted for ES writers.
    const es = sentimentScore("el día fue perfecto", "es");
    const def = sentimentScore("el día fue perfecto");
    expect(es).toBeGreaterThan(def);
  });

  it("keeps the no-language default byte-identical (vector contract)", () => {
    // Same input, no language vs "en"/"other" must agree with the
    // historical default walk for text without ES-only negators.
    expect(sentimentScore(ENGLISH_PARAGRAPH)).toBe(sentimentScore(ENGLISH_PARAGRAPH, "other"));
  });

  it("scopes the ES negator 'sin' out of English scoring", () => {
    // "sin" (ES "without") must not negate English valences.
    const en = sentimentScore("washed away my sin and guilt", "en");
    const legacy = sentimentScore("washed away my sin and guilt");
    expect(en).not.toBe(legacy);
  });
});
