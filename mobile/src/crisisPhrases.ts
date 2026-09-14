/**
 * Canonical crisis-language phrase lists — EMBEDDED COPY of
 * shared/crisis_phrases.json (the cross-platform source of truth).
 *
 * Why embed instead of import: Metro cannot resolve modules outside the
 * project root, so the shared JSON cannot be imported at runtime (the same
 * reason shared/vectors.json is verified by a node tool instead). Sync is
 * enforced by tests/crisisPhrases.test.ts, which reads the shared file
 * from disk (vitest runs in node, fs is fine) and pins array-for-array
 * parity plus every fixture in the contract. If you change these lists,
 * change shared/crisis_phrases.json first and let the parity test pull
 * this file along.
 *
 * Two tiers:
 *  - dialog (CRISIS_DIALOG_PATTERNS): client-side, pre-encryption
 *    detection that triggers the gentle support dialog. Conservative —
 *    a false positive costs one gentle dialog, a miss costs a life.
 *  - suppress (dialog + CRISIS_SUPPRESS_EXTRA_PATTERNS): deliberately
 *    broader — a false positive here only means a pattern is not quoted
 *    back as a card or question (the UI renders a non-quoting card for
 *    crisis-adjacent patterns instead).
 *
 * Pattern rules (from the shared contract): every pattern must compile
 * under BOTH Python re and ECMAScript RegExp — no lookahead/lookbehind;
 * consumers apply case-insensitive matching; \s+ for whitespace;
 * ['’]? for optional ASCII/curly apostrophes (iOS Smart
 * Punctuation, stored as the escape sequence); \b word boundaries.
 */

/** The dialog tier: high-signal phrases that surface support resources. */
export const CRISIS_DIALOG_PATTERNS: readonly string[] = [
  "\\bsuicid(?:e|al)\\b",
  "\\bkill(?:ing)?\\s+myself\\b",
  "\\b(?:wants?|wanted|wanting)\\s+to\\s+die\\b",
  "\\bwanna\\s+(?:to\\s+)?die\\b",
  "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+dead\\b",
  "\\bwish\\s+(?:i\\s+)?could\\s+die\\b",
  "\\bfeel(?:s|ing)?\\s+like\\s+dying\\b",
  "\\bend(?:ing)?\\s+it\\s+all\\b",
  "\\b(?:end|ending|take|taking)\\s+my\\s+(?:own\\s+)?life\\b",
  "\\bself[-\\s]?harm(?:ing)?\\b",
  "\\bhurt(?:ing)?\\s+myself\\b",
  "\\bharm(?:ing)?\\s+myself\\b",
  "\\bcut(?:ting)?\\s+myself\\b",
  "\\bno\\s+reason\\s+to\\s+(?:live|go\\s+on)\\b",
  "\\bnothing\\s+to\\s+live\\s+for\\b",
  "\\b(?:can['\\u2019]?t|cannot)\\s+go\\s+on\\b",
  "\\bbetter\\s+off\\s+without\\s+me\\b",
  "\\b(?:don['\\u2019]?t|do\\s+not)\\s+want\\s+to\\s+(?:be\\s+here|live|exist|be\\s+alive|wake\\s+up)\\b",
  "\\bwant(?:s|ed|ing)?\\s+to\\s+disappear\\b",
  "\\bend(?:ing)?\\s+everything\\b",
  "\\bno\\s+point\\s+(?:in\\s+)?going\\s+on\\b",
  "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+never\\s+born\\b",
  "\\bunalive\\b",
  "\\bkys\\b",
  "\\bno\\s+way\\s+out\\b",
  "\\bsleep\\s+forever\\b",
  "\\b(?:can['\\u2019]?t|cannot)\\s+do\\s+this\\s+anymore\\b",
];

/** The broader suppression tier's EXTRA patterns (the effective suppress
 *  list is dialog + these). Used for non-quoting cards / question
 *  suppression — never for the support dialog. */
export const CRISIS_SUPPRESS_EXTRA_PATTERNS: readonly string[] = [
  "\\bsuicid\\w+",
  "\\bkill(?:ing)?\\s+me\\b",
  "\\bwant(?:s|ed|ing)?\\s+to\\s+be\\s+dead\\b",
  "\\brather\\s+be\\s+dead\\b",
  "\\bbetter\\s+off\\s+dead\\b",
  "\\boverdose(?:d)?\\b",
  "\\beveryone\\s+would\\s+be\\s+better\\s+off\\b",
  "\\bnot\\s+want(?:ing)?\\s+to\\s+(?:live|be\\s+here)\\b",
  // Bare self-harm / ED topic words and non-first-person-anchored ideation:
  // suppress-tier ONLY (a false positive costs one gentle non-quoting card,
  // never a dialog — the dialog tier stays conservative). "\\bcutting\\b"
  // closes the re-audit's quoted-topic hole ("the urge for cutting was
  // loud" surfaced as a quoted rising topic).
  "\\bcutting\\b",
  "\\bself[-\\s]?loathing\\b",
  "\\bburn(?:ing|ed)?\\s+myself\\b",
  "\\bstarv(?:e|ing|ed)\\s+myself\\b",
  "\\bmake\\s+myself\\s+(?:throw\\s+up|puke|vomit)\\b",
  "\\b(?:made|making)\\s+myself\\s+(?:throw\\s+up|puke|vomit)\\b",
];
