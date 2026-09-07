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
 */

/** One entry per phrase family; `\s+` tolerates odd spacing/newlines and
 *  `'?` the dropped apostrophe of quick typing. Case-insensitive. */
const CRISIS_PATTERNS: readonly RegExp[] = [
  // "suicide" / "suicidal" — unambiguous even as single words.
  /\bsuicid(?:e|al)\b/i,
  // "kill myself" / "killing myself"
  /\bkill(?:ing)?\s+myself\b/i,
  // "want to die" / "wanted to die" / "wanna die"; "wish I was dead"
  /\b(?:wants?|wanted)\s+to\s+die\b/i,
  /\bwanna\s+(?:to\s+)?die\b/i,
  /\bwish\s+(?:i\s+)?(?:was|were)\s+dead\b/i,
  // "end it all" / "ending it all"
  /\bend(?:ing)?\s+it\s+all\b/i,
  // "end my life" / "ending my life" / "take my (own) life" / "taking my life"
  /\b(?:end|ending|take|taking)\s+my\s+(?:own\s+)?life\b/i,
  // "self harm" / "self-harm" / "self harming"
  /\bself[-\s]?harm(?:ing)?\b/i,
  // "hurt myself" / "hurting myself"
  /\bhurt(?:ing)?\s+myself\b/i,
  // "no reason to live" / "no reason to go on"
  /\bno\s+reason\s+to\s+(?:live|go\s+on)\b/i,
  // "can't go on" / "cant go on" / "cannot go on"
  /\b(?:can'?t|cannot)\s+go\s+on\b/i,
  // "better off without me"
  /\bbetter\s+off\s+without\s+me\b/i,
  // "don't want to be here / live / exist" (and "do not" spellings)
  /\b(?:don'?t|do\s+not)\s+want\s+to\s+(?:be\s+here|live|exist)\b/i,
];

/** True when `text` contains crisis language. Pure: no I/O, no state. */
export function detectCrisisLanguage(text: string): boolean {
  return CRISIS_PATTERNS.some((pattern) => pattern.test(text));
}
