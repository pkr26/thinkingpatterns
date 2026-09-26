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
  "\\bkill(?:ed|ing)?\\s+myself\\b",
  "\\b(?:wants?|wanted|wanting)\\s+to\\s+die\\b",
  "\\bwanna\\s+(?:to\\s+)?die\\b",
  "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+dead\\b",
  "\\bwish\\s+(?:i\\s+)?could\\s+die\\b",
  "\\bfeel(?:s|ing)?\\s+like\\s+dying\\b",
  "\\bend(?:ing)?\\s+it\\s+all\\b",
  "\\b(?:end|ended|ending|take|took|taking)\\s+my\\s+(?:own\\s+)?life\\b",
  "\\bself[-\\s]?harm(?:ing)?\\b",
  "\\bhurt(?:ing)?\\s+myself\\b",
  "\\bharm(?:ing)?\\s+myself\\b",
  "\\bcut(?:ting)?\\s+myself\\b",
  "\\bno\\s+reason\\s+to\\s+(?:live|go\\s+on)\\b",
  "\\bnothing\\s+to\\s+live\\s+for\\b",
  "\\b(?:can[\'\\u2019]?t|cannot)\\s+go\\s+on\\b",
  "\\bbetter\\s+off\\s+without\\s+me\\b",
  "\\b(?:don[\'\\u2019]?t|do\\s+not)\\s+want\\s+to\\s+(?:be\\s+here|live|exist|be\\s+alive|wake\\s+up)\\b",
  "\\bwant(?:s|ed|ing)?\\s+to\\s+disappear\\b",
  "\\bend(?:ing)?\\s+everything\\b",
  "\\bno\\s+point\\s+(?:in\\s+)?going\\s+on\\b",
  "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+never\\s+born\\b",
  "\\bunalive\\b",
  "\\bkys\\b",
  "\\bno\\s+way\\s+out\\b",
  "\\bsleep\\s+forever\\b",
  "\\b(?:can[\'\\u2019]?t|cannot)\\s+do\\s+this\\s+anymore\\b",
  "\\boff(?:ing)?\\s+myself\\b",
  "\\bput\\s+me\\s+out\\s+of\\s+my\\s+misery\\b",
  "\\b(?:life|living)(?:[\'\\u2019]?s)?\\s+(?:(?:is|was|feels?|seems?|sounds?)\\s*)?(?:n[\'\\u2019]?t|not)\\s+worth\\s+(?:living|it)\\b",
  "\\b(?:life|living)(?:[\'\\u2019]?s)?\\s+(?:do(?:es)?|did)n[\'\\u2019]?t\\s+(?:feel|seem|sound)\\s+worth\\s+(?:living|it)\\b",
  "\\bno\\s+longer\\s+want(?:s|ed|ing)?\\s+to\\s+(?:live|be\\s+here|be\\s+alive|exist|wake\\s+up)\\b",
  "\\btired\\s+of\\s+(?:living|life)\\b",
  "\\bwant(?:s|ed|ing)?\\s+to\\s+overdose\\b",
  "\\bsuicidality\\b",
  "\\bquiero\\s+morir\\b",
  "\\bme\\s+quiero\\s+matar\\b",
  "\\bquitarme\\s+la\\s+vida\\b",
  "\\bje\\s+veux\\s+mourir\\b",
  "\\bme\\s+suicider\\b",
  "\\bsuizid\\w*",
  "\\bich\\s+will\\s+sterben\\b",
  "\\bbringe\\s+mich\\s+um\\b",
  "\\bvoglio\\s+morire\\b",
  "\\bquero\\s+morrer\\b",
  "\\bme\\s+matar\\b",
  "\\bsuicid(?:io|ios|arme|armi)\\b",
  "\\bno\\s+quiero\\s+vivir\\b",
  "\\bcansad[oa]s?\\s+de\\s+vivir\\b",
  "\\bno\\s+vale\\s+la\\s+pena\\s+(?:vivir|seguir)\\b",
  "\\bla\\s+vida\\s+no\\s+vale\\s+la\\s+pena\\b",
  "\\b(?:me\\s+)?(?:quiero|quisiera|deberia|podria)\\s+quitar(?:me)?\\s+la\\s+vida\\b",
  "\\bme\\s+voy\\s+a\\s+quitar\\s+la\\s+vida\\b",
  "\\bme\\s+quiero\\s+(?:cortar|lastimar|quemar|ahogar)\\b",
  "\\bquiero\\s+(?:matarme|cortarme|lastimarme|quemarme|ahogarme)\\b",
  "\\bme\\s+(?:lastimo|hago\\s+da[nñ]o|corto\\s+la\\s+piel|quemo\\s+la\\s+piel)\\b",
  "\\b(?:quiero|quisiera)\\s+hacerme\\s+da[nñ]o\\b",
  "\\bno\\s+hay\\s+salida\\b",
  "\\b(?:quiero|quisiera)\\s+desaparecer\\b",
  "\\b(?:todos|el\\s+mundo)\\s+estarian\\s+mejor\\s+sin\\s+mi\\b",
  "\\bno\\s+tengo\\s+ganas\\s+de\\s+vivir\\b",
  "\\bhart[oa]s?\\s+de\\s+(?:la\\s+)?vida\\b",
  "\\b(?:solo\\s+)?quiero\\s+dormir\\s+para\\s+siempre\\b",
  "\\bno\\s+(?:puedo|aguanto)\\s+mas\\b",
  "\\bno\\s+quiero\\s+(?:despertar|despertarme|seguir\\s+viviendo)\\b",
  "我想死",
  "我想去死",
  "自杀",
  "死にたい",
  "自殺",
  "자살하고 싶다",
  "죽고 싶다",
  "أريد أن أموت",
  "أريد أن أنتحر",
  "मरना चाहता",
  "मरना चाहती",
  "\\bintihar\\s+etmek\\s+istiyorum\\b",
  "\\bcanını\\s+almak\\s+istiyorum\\b",
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
  "\\bcutting\\b",
  "\\bself[-\\s]?loathing\\b",
  "\\bburn(?:ing|ed)?\\s+myself\\b",
  "\\bstarv(?:e|ing|ed)\\s+myself\\b",
  "\\bmake\\s+myself\\s+(?:throw\\s+up|puke|vomit)\\b",
  "\\b(?:made|making)\\s+myself\\s+(?:throw\\s+up|puke|vomit)\\b",
  "\\bdon[\'\\u2019]?t\\s+see\\s+(?:a\\s+|any\\s+)?future\\b",
  "\\bno\\s+future\\s+for\\s+me\\b",
  "\\bhappier\\s+(?:if|when)\\s+(?:i[\'\\u2019]?m|i\\s+am|i\\s+was)\\s+gone\\b",
  "\\bhappier\\s+without\\s+me\\b",
  "\\beveryone\\s+would\\s+be\\s+happier\\b",
  "\\bnot\\s+worth\\s+living\\b",
  "\\bno\\s+vale\\s+la\\s+pena\\b",
  "\\bquitar(?:le|me|se)?\\s+la\\s+vida\\b",
  "\\bhacer(?:le|me|se)\\s+da[nñ]o\\b",
];

/**
 * Multiword titles/causes masked from BOTH tiers before matching
 * (2026-09-17): the bare topic word inside them is not first-person
 * ideation — "that movie was suicide squad" must not fire the dialog
 * tier, and "we discussed suicide prevention in class" neither. Any
 * genuine crisis phrasing around them still matches on its own words.
 */
export const CRISIS_BENIGN_COMPOUNDS: readonly string[] = [
  "suicide squad",
  "suicide silence",
  "suicideboys",
  "suicide prevention",
  "suicide awareness",
  // 2026-09-20 audit L-23: prevention-campaign masking beyond English —
  // CJK and Spanish classroom mentions. Post-fold spellings (masking runs
  // after Latin-mark folding).
  "自杀预防",
  "prevencion del suicidio",
  "prevencion de suicidio",
  // 2026-09-26 audit follow-up (corpus false positives): the H-1
  // additions fired the dialog tier on everyday Spanish — grooming
  // ("me quiero cortar el pelo" = I want a haircut), building navigation
  // ("no hay salida de emergencia" = no emergency exit), common sports
  // injuries ("me lastimo la rodilla"), and colloquial slipping-away
  // ("desaparecer de la fiesta"). Benign-compound masking is the
  // engine's designed mechanism for this class ("suicide squad" has the
  // same standing); enumerated body-part masks keep the recall of the
  // bare self-harm phrasings. Post-fold spellings.
  "cortar el pelo",
  "cortarme el pelo",
  "cortar la barba",
  "cortarme la barba",
  "cortar las unas",
  "cortarme las unas",
  "no hay salida de emergencia",
  "salida de emergencia",
  "no hay salida hacia el mar",
  "desaparecer de la fiesta",
  "desaparecer de las redes",
  "me lastimo el dedo",
  "me lastimo la rodilla",
  "me lastimo el tobillo",
  "me lastimo el pie",
  "me lastimo la mano",
  "me lastimo el brazo",
  "me lastimo la cabeza",
  "me lastimo la espalda",
  "me lastimo la pierna",
];
