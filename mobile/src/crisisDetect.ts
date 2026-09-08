/**
 * On-device crisis-language detection.
 *
 * Entries are encrypted before anything leaves the phone, so the server
 * CANNOT notice a crisis — detection has to happen here, client-side and
 * pre-encryption, or it does not happen at all. This matcher runs in
 * memory over the plaintext the user just typed. Nothing is sent, stored,
 * or logged: the caller shows support resources and forgets the result.
 *
 * The phrase list is deliberately conservative: it fires on high-signal
 * phrases and errs toward false positives over misses (a false positive
 * costs one gentle dialog; a miss costs a life). It stays phrase-based —
 * not single common words — so everyday journaling ("the assessment was
 * brutal", "that killed my mood") does not trip it.
 *
 * Accepted false positives (documented, not shipped as sloppy regexes):
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
 * pattern accepts BOTH characters — otherwise "I can't go on" typed on
 * an iPhone silently missed detection.
 */

/** One entry per phrase family; `\s+` tolerates odd spacing/newlines and
 *  the `['\u2019]?` classes the dropped or curly apostrophe of quick
 *  typing. Case-insensitive. */
const CRISIS_PATTERNS: readonly RegExp[] = [
  // "suicide" / "suicidal" — unambiguous even as single words.
  /\bsuicid(?:e|al)\b/i,
  // "kill myself" / "killing myself"
  /\bkill(?:ing)?\s+myself\b/i,
  // "want to die" / "wanted to die" / "wanting to die"; "wanna die";
  // "wish I was dead"; "wish I could die"; "feel like dying"
  /\b(?:wants?|wanted|wanting)\s+to\s+die\b/i,
  /\bwanna\s+(?:to\s+)?die\b/i,
  /\bwish\s+(?:i\s+)?(?:was|were)\s+dead\b/i,
  /\bwish\s+(?:i\s+)?could\s+die\b/i,
  /\bfeel(?:s|ing)?\s+like\s+dying\b/i,
  // "end it all" / "ending it all"
  /\bend(?:ing)?\s+it\s+all\b/i,
  // "end my life" / "ending my life" / "take my (own) life" / "taking my life"
  /\b(?:end|ending|take|taking)\s+my\s+(?:own\s+)?life\b/i,
  // "self harm" / "self-harm" / "self harming"
  /\bself[-\s]?harm(?:ing)?\b/i,
  // "hurt myself" / "hurting myself"
  /\bhurt(?:ing)?\s+myself\b/i,
  // "cut myself" / "cutting myself" (accepted FP: shaving/kitchen — see header)
  /\bcut(?:ting)?\s+myself\b/i,
  // "no reason to live" / "no reason to go on" / "nothing to live for"
  /\bno\s+reason\s+to\s+(?:live|go\s+on)\b/i,
  /\bnothing\s+to\s+live\s+for\b/i,
  // "can't go on" / "cant go on" / "cannot go on" (ASCII or curly apostrophe)
  /\b(?:can['\u2019]?t|cannot)\s+go\s+on\b/i,
  // "better off without me"
  /\bbetter\s+off\s+without\s+me\b/i,
  // "don't want to be here / live / exist / be alive" (and "do not" spellings)
  /\b(?:don['\u2019]?t|do\s+not)\s+want\s+to\s+(?:be\s+here|live|exist|be\s+alive)\b/i,
];

/** True when `text` contains crisis language. Pure: no I/O, no state. */
export function detectCrisisLanguage(text: string): boolean {
  return CRISIS_PATTERNS.some((pattern) => pattern.test(text));
}
