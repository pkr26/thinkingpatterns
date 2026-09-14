/**
 * On-device crisis-language detection.
 *
 * Entries are encrypted before anything leaves the phone, so the server
 * CANNOT notice a crisis — detection has to happen here, client-side and
 * pre-encryption, or it does not happen at all. This matcher runs in
 * memory over the plaintext the user just typed. Nothing is sent, stored,
 * or logged: the caller shows support resources and forgets the result.
 *
 * The phrase lists come from src/crisisPhrases.ts, the embedded copy of
 * shared/crisis_phrases.json (the cross-platform source of truth — see
 * that file's header for the embed + parity-test pattern). Two tiers:
 *
 *  - detectCrisisLanguage (the DIALOG tier) is deliberately conservative:
 *    it fires on high-signal phrases and errs toward false positives over
 *    misses (a false positive costs one gentle dialog; a miss costs a
 *    life). It stays phrase-based — not single common words — so everyday
 *    journaling ("the assessment was brutal", "that killed my mood") does
 *    not trip it.
 *
 *  - matchesCrisisSuppress (the SUPPRESS tier = dialog + suppress_extra)
 *    is deliberately broader: it powers non-quoting rendering for
 *    crisis-adjacent patterns (a card that acknowledges the pattern
 *    without quoting the phrase back) and question suppression. A false
 *    positive there only means a pattern is not quoted.
 *
 * Accepted false positives of the dialog tier (documented, not shipped as
 * sloppy regexes):
 *  - Any use of the word "suicide"/"suicidal", even in a prevention or
 *    academic context ("we discussed suicide prevention in class").
 *  - "cut myself" / "cutting myself" fires even in benign grooming or
 *    kitchen contexts ("I cut myself shaving"). Enumerating benign
 *    follow-up contexts with a lookahead would be an incomplete blocklist
 *    pretending to be precision; in a private journal the bare statement
 *    is high-signal, and the cost is one gentle dialog.
 *  - "feel like dying" fires on "dying of embarrassment/laughter"-style
 *    hyperbole when written with "feel like" ("I feel like dying after
 *    that workout"). Without the "feel like" anchor, "dying of laughter"
 *    does NOT fire.
 *
 * iOS Smart Punctuation note: iOS keyboards substitute the curly
 * apostrophe U+2019 for ASCII ' by default, so every apostrophe-tolerant
 * pattern accepts BOTH characters (the ['’]? classes in the shared
 * list) — otherwise "I can't go on" typed on an iPhone silently missed
 * detection.
 */
import { CRISIS_DIALOG_PATTERNS, CRISIS_SUPPRESS_EXTRA_PATTERNS } from "./crisisPhrases";

/** Compiled once at module load; every pattern in the shared contract is
 *  guaranteed lookahead-free and dual-engine (Python re + ECMAScript). */
const DIALOG_PATTERNS: readonly RegExp[] = CRISIS_DIALOG_PATTERNS.map((pattern) => new RegExp(pattern, "i"));

/** The suppress tier is dialog + suppress_extra — one compiled list. */
const SUPPRESS_PATTERNS: readonly RegExp[] = [
  ...CRISIS_DIALOG_PATTERNS,
  ...CRISIS_SUPPRESS_EXTRA_PATTERNS,
].map((pattern) => new RegExp(pattern, "i"));

/** True when `text` contains crisis language (dialog tier — fire the
 *  gentle support dialog). Pure: no I/O, no state. */
export function detectCrisisLanguage(text: string): boolean {
  return DIALOG_PATTERNS.some((pattern) => pattern.test(text));
}

/** True when `text` belongs to the broader suppression tier — the caller
 *  renders a NON-QUOTING card (or suppresses a generated question) for
 *  crisis-adjacent patterns. Pure: no I/O, no state. */
export function matchesCrisisSuppress(text: string): boolean {
  return SUPPRESS_PATTERNS.some((pattern) => pattern.test(text));
}
