"""The v3 mini-brain: a stateful, evidence-anchored pattern engine.

v3 keeps everything v2 stood for (persistent encrypted memory, pattern
lifecycle, decayed evidence, deterministic purity) and rebuilds the
*analysis* on the methodological standards of intensive-longitudinal
clinical research. Every detector below maps to a citable source; see
RESEARCH.md for the full bibliography. The changes that matter:

  * **Within-person analysis** (Bolger & Laurenceau 2013, *Intensive
    Longitudinal Methods*): every mood association is computed on
    residuals against the user's own rolling baseline, not on raw pooled
    scores. Raw pooling confounds slow mood trends with day-level
    associations — v2 manufactured false "your mood is higher when X
    comes up" claims whenever the user's mood trended (proven by
    probe_brain.py: five false correlations at p <= 1e-6). Residuals kill
    that class of false positives.
  * **Graded sentiment** (VADER-style, Hutto & Gilbert 2014): a graded
    lexicon with intensifier boosters, downtoners, damped negation
    (x-0.74 scalar) and "but" re-weighting replaces the binary word
    lists. Still pure and deterministic.
  * **Lagged day-after links** (Bourke et al. 2026 meta-analysis of 118
    daily-diary studies; Bolger et al. 1989 spillover): "the day after
    'sleep' comes up, your entries read lower" — the literal pattern
    *linking* the product is named for. Welch's t + Cohen's d on
    residuals, gated like every statistical claim.
  * **Mood dynamics**: inertia (lag-1 autocorrelation; Kuppens, Allen &
    Sheeber 2010; Houben et al. 2015 meta-analysis) and instability
    (rolling spread) are meta-analytically tied to lower wellbeing and
    are surfaced only as *changes from the user's own norm*.
  * **Rumination framing** (Ehring & Watkins 2008, transdiagnostic
    repetitive negative thinking; Al-Mosaiwi & Johnstone 2018 for
    absolutist language): a recurring near-duplicate phrase cluster
    whose members read negative is surfaced as a repeated *worry*, with
    absolutist-word density in the detail — not as a neutral "phrase".
  * **Emergent topic discovery**: the fixed lexicon covers nine universal
    themes; everything else a life revolves around — a new relationship, a
    startup, grief, guitar — is found by deterministic n-gram mining of
    recurring content phrases, surfaced when RISING against the user's own
    earlier-window base rate (exact binomial, BH-corrected) or a persistent
    presence. The audit's "topic blindness" finding, closed.
  * **Honest multiple testing**: the weekday-concentration test now
    tests every candidate weekday (not the argmax alone) and puts all
    of them into the Benjamini-Hochberg family — selecting the best of
    7 days and testing it once understated p-values ~7x.
  * **EWMA tuning** (Smit, Schat & Ceulemans 2023 methods paper):
    lambda 0.18 inside their validated 0.05-0.25 band, baseline over
    the first quarter of the window (min 10 days).

Determinism is absolute: ``update(state, entries, today)`` is a pure
function of its arguments. No wall clock, no RNG, no network. The store
is a JSON payload the caller encrypts under the user's data key.

Scope guardrails (deliberate, see RESEARCH.md "never do"): no
critical-slowing-down claims (mixed replications), no bipolar language,
no relapse *prediction* claims (FDA wellness boundary) — observations of
the user's own data, always phrased within-person ("than usual for
you"), never diagnoses.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from . import phrases as phrase_miner
from . import statsig
from .patterns import DAY_NAMES, SENTENCE_RE, WORD_RE, JournalEntry, Pattern

STATE_VERSION = 2

# --- analysis window ---------------------------------------------------------
WINDOW_DAYS = 180
MAX_WINDOW_ENTRIES = 4_000
MAX_SENTENCES_PER_ENTRY = 40
MAX_WINDOW_SENTENCES = 4_000
MIN_SENTENCE_TOKENS = 4

# --- evidence model ----------------------------------------------------------
HALF_LIFE_DAYS = 45.0  # recent mentions outweigh old ones; the brain forgets
EVIDENCE_FULL = 8.0    # decayed mentions that saturate strength
STRONG_EVIDENCE = 10   # occurrences that may surface on first qualification

# --- statistical gates -------------------------------------------------------
ALPHA = 0.05
TEMPORAL_MIN_N = 8
TEMPORAL_MIN_DAY_K = 4      # per-weekday floor before a weekday is tested at all
TEMPORAL_MIN_FRACTION = 0.35
# A word in ~every entry is journaling boilerplate ("unique day", "ordinary
# notes"), not a life topic — presence claims are capped from above too.
TOPIC_PRESENCE_MAX_SHARE = 0.95
MOOD_MIN_PER_SIDE = 8
MOOD_MIN_DELTA = 0.2
MOOD_MIN_EFFECT = 0.5  # Cohen's d
MOOD_SD_FLOOR = 0.05   # lexicon mood always carries at least this measurement noise
LINK_MIN_PER_SIDE = 8   # lagged day-after links: transitions per side
LINK_MAX_GAP_DAYS = 2   # "next day" survives a one-day skip in journaling
PHRASE_MIN_OCCURRENCES = 3
PHRASE_MIN_SPAN_DAYS = 7
PHRASE_MIN_DISTINCT_DAYS = 3

# --- within-person baseline (Bolger & Laurenceau 2013) -------------------------
BASELINE_HALF_WINDOW = 7   # personal baseline = +/- this many days around a day
BASELINE_MIN_NEIGHBORS = 4  # neighbors required before the day itself is excluded

# --- mood dynamics (Kuppens 2010; Houben 2015) ---------------------------------
INERTIA_MIN_PAIRS = 10       # consecutive-day pairs per window to trust r1
INERTIA_RECENT_MIN = 0.45    # recent carryover correlation strong enough to mention
INERTIA_DELTA = 0.25         # ... and risen by this much vs the earlier window
INERTIA_RECENT_DAYS = 28
INSTABILITY_MIN_DAYS = 10
INSTABILITY_RECENT_DAYS = 28
INSTABILITY_SD_FLOOR = 0.12
INSTABILITY_RATIO = 1.6      # recent spread vs earlier spread

# --- rumination (Ehring & Watkins 2008; Al-Mosaiwi & Johnstone 2018) -----------
RUMINATION_NEGATIVITY_MAX = -0.30  # cluster mean sentiment at or below → a worry
RUMINATION_MIN_NEGATORS = 2        # ... or non-positive + negation-heavy phrasing

# --- mood trajectory (EWMA control chart, Smit/Schat/Ceulemans 2023) -----------
MOOD_SHIFT_MIN_DAYS = 21
MOOD_SHIFT_BASELINE_MIN = 10
MOOD_SHIFT_LAMBDA = 0.18   # inside the validated 0.05–0.25 band
MOOD_SHIFT_LIMIT = 2.7     # control-limit multiplier (standard ARL choice)
MOOD_SHIFT_TAIL = 5        # most recent EWMA points inspected
MOOD_SHIFT_RUN = 3         # beyond-limit points required in the tail
MOOD_SHIFT_MIN_SHIFT = 0.15
MOOD_SHIFT_SIGMA_FLOOR = 0.05

# --- lifecycle ---------------------------------------------------------------
GRACE_DAYS = 7     # unqualified days before active → fading
ARCHIVE_DAYS = 45  # unqualified days before fading → archived
DROP_DAYS = 90     # archived patterns are dropped after this
PROMOTE_AGE_DAYS = 7   # candidate → emerging by age without re-qualification
CONFIRM_AGE_DAYS = 21  # emerging → confirmed by age

# --- store bounds --------------------------------------------------------------
HISTORY_DAYS = 90
EVIDENCE_DATES_CAP = 60
QUALIFICATION_DAYS_CAP = 60
MAX_STORED_PATTERNS = 200
MAX_SURFACED = 20
NEW_PATTERN_WINDOW_DAYS = 7

ACTIVE_STATES = ("candidate", "emerging", "confirmed")
SURFACED_STATES = ("emerging", "confirmed", "fading")
STATE_RANK = {"confirmed": 0, "emerging": 1, "fading": 2}

# --- lexicon (superset of v1: explicit variants + light stemming) ---------------
THEME_LEXICON: dict[str, tuple[str, ...]] = {
    "work": ("work", "job", "boss", "deadline", "meeting", "office", "project",
             "client", "interview", "presentation", "colleague", "shift",
             "overtime", "career", "manager", "commute", "workload", "email",
             "promotion", "layoff", "understaffed", "burnout"),
    "sleep": ("sleep", "insomnia", "tired", "exhausted", "nightmare", "restless",
              "fatigue", "nap", "awake", "bed", "sleepy", "asleep", "wake",
              "bedtime", "dream", "sleepless"),
    "social": ("friend", "party", "social", "lonely", "alone", "gathered",
               "hangout", "hang", "gather", "isolated", "isolation", "company",
               "meetup", "connected", "connection"),
    "family": ("family", "mom", "dad", "mother", "father", "sister", "brother",
               "parents", "partner", "wife", "husband", "kids", "home", "son",
               "daughter", "grandma", "grandpa", "grandmother", "grandfather",
               "uncle", "aunt", "cousin", "marriage", "divorce", "baby",
               "toddler"),
    "health": ("health", "gym", "exercise", "workout", "run", "sick", "ill",
               "doctor", "headache", "pain", "walk", "yoga", "stretch",
               "medicine", "meds", "migraine", "injury", "dentist", "therapy"),
    "money": ("money", "bills", "rent", "debt", "salary", "budget", "expensive",
              "broke", "afford", "save", "loan", "credit", "paycheck", "tax",
              "overdraft", "insurance", "cheap"),
    "study": ("school", "exam", "study", "class", "college", "university",
              "homework", "assignment", "test", "quiz", "lecture", "semester",
              "thesis", "dissertation", "revision", "teacher", "professor",
              "grade", "fail"),
    "food": ("eat", "food", "meal", "cook", "appetite", "hungry", "breakfast",
             "lunch", "dinner", "snack", "coffee", "tea", "sugar", "junk",
             "takeaway", "restaurant"),
    "weather": ("rain", "rainy", "cold", "grey", "gray", "sunny", "storm",
                "winter", "summer", "weather", "fog", "foggy", "heat", "humid",
                "wind", "windy", "snow", "snowy", "drizzle", "freezing",
                "cloud", "cloudy", "autumn"),
}
THEME_WORDS: dict[str, str] = {
    word: theme for theme, words in THEME_LEXICON.items() for word in words
}

# --- graded sentiment lexicon (VADER-inspired; Hutto & Gilbert 2014) ------------
# Valences in [-4, 4]; magnitudes follow the VADER convention (a "terrible"
# outweighs a "bad"). Curated for journal register; superset of the v2 word
# lists so historical corpora score consistently.
SENTIMENT_LEXICON: dict[str, float] = {
    # positive — mild
    "okay": 0.9, "ok": 0.9, "alright": 0.9, "fine": 0.8, "decent": 1.1,
    "calm": 1.5, "quiet": 0.6, "settled": 1.2, "steady": 1.0, "neutral": 0.0,
    "pleasant": 1.9, "mild": 0.4, "gentle": 1.1, "easy": 1.0, "simple": 0.6,
    "comfortable": 1.6, "content": 1.9, "peaceful": 2.2, "relieved": 1.9,
    "rested": 1.8, "refreshed": 2.0, "grounded": 1.6, "balanced": 1.3,
    "accepted": 1.2, "safe": 1.6, "secure": 1.5, "warm": 1.4, "cozy": 1.8,
    "soft": 0.7, "lighter": 1.4, "bright": 1.5, "clear": 0.9, "present": 0.8,
    # positive — moderate
    "good": 1.9, "nice": 1.5, "better": 1.7, "improved": 1.6, "happy": 3.0,
    "glad": 2.2, "joy": 2.8, "joyful": 2.9, "cheerful": 2.4, "smiled": 2.3,
    "smile": 2.3, "laugh": 2.4, "laughed": 2.4, "fun": 2.3, "playful": 2.0,
    "enjoy": 2.1, "enjoyed": 2.2, "love": 3.2, "loved": 2.9, "liked": 1.8,
    "hope": 2.0, "hopeful": 2.3, "optimistic": 2.2, "excited": 2.8,
    "eager": 2.0, "curious": 1.5, "interested": 1.2, "engaged": 1.5,
    "motivated": 2.3, "productive": 1.9, "proud": 2.6, "accomplished": 2.3,
    "confident": 2.4, "capable": 1.9, "strong": 1.8, "energetic": 2.4,
    "active": 1.3, "alive": 1.9, "grateful": 2.8, "thankful": 2.8,
    "appreciate": 2.2, "blessed": 2.5, "lucky": 1.8, "amused": 1.8,
    "connected": 1.8, "supported": 2.0, "understood": 1.8, "heard": 1.4,
    "kind": 1.9, "helpful": 1.6, "generous": 1.8, "creative": 1.7,
    "progress": 1.5, "win": 1.9, "won": 1.9,
    # positive — strong
    "great": 3.1, "wonderful": 3.2, "amazing": 3.3, "awesome": 3.3,
    "fantastic": 3.4, "excellent": 3.1, "beautiful": 2.9, "delight": 2.8,
    "delighted": 2.9, "thrilled": 3.1, "ecstatic": 3.5, "bliss": 3.2,
    "perfect": 2.9, "incredible": 2.9, "phenomenal": 3.0,
    # negative — mild
    "bad": -1.9, "meh": -0.9, "off": -0.8, "down": -1.3, "low": -1.2,
    "flat": -0.8, "dull": -1.1, "bored": -1.2, "tired": -1.7, "sleepy": -1.0,
    "slow": -0.7, "heavy": -1.3, "grey": -0.6, "gray": -0.6, "bleak": -1.9,
    "gloomy": -1.8, "mehh": -1.0, "awkward": -1.3, "annoyed": -1.7,
    "irritated": -1.8, "frustrated": -2.0, "uneasy": -1.6, "tense": -1.7,
    "restless": -1.5, "unsettled": -1.6, "wary": -1.4, "skeptical": -1.0,
    "disappointed": -2.1, "underwhelmed": -1.4, "inconvenient": -1.2,
    "guilty": -2.1, "ashamed": -2.5, "embarrassed": -2.0, "regret": -2.0,
    "lonely": -2.4, "alone": -1.4, "isolated": -2.2, "disconnected": -1.8,
    "unhappy": -2.2, "dissatisfied": -1.8, "stuck": -2.0, "trapped": -2.4,
    "hollow": -2.0, "empty": -2.1, "numb": -2.3, "distant": -1.4,
    "withdrawn": -1.9,
    # negative — moderate
    "sad": -2.5, "downcast": -2.3, "sorrow": -2.6, "grief": -2.9,
    "grieving": -2.9, "hurt": -2.3, "aching": -2.0, "cry": -2.2,
    "cried": -2.4, "crying": -2.4, "tears": -2.2, "weep": -2.4,
    "miss": -1.5, "loss": -2.2, "anxious": -2.7, "anxiety": -2.6,
    "nervous": -2.0, "worry": -2.1, "worried": -2.3, "stress": -2.0,
    "stressed": -2.4, "pressured": -2.1, "overloaded": -2.3,
    "overwhelmed": -2.9, "swamped": -2.1, "angry": -2.7, "anger": -2.6,
    "mad": -2.2, "upset": -2.3, "fed": -1.5, "bitter": -2.1,
    "resentment": -2.3, "resentful": -2.2, "hate": -2.8, "dislike": -1.7,
    "afraid": -2.5, "scared": -2.5, "fear": -2.5, "fearful": -2.4,
    "dread": -2.6, "panic": -3.0, "panicky": -2.9, "hopeless": -3.3,
    "helpless": -3.0, "worthless": -3.4, "useless": -3.1, "failure": -2.9,
    "failed": -2.6, "failing": -2.7, "miserable": -2.9, "awful": -3.0,
    "terrible": -3.1, "horrible": -3.1, "worse": -2.3, "worst": -3.0,
    "exhausted": -2.8, "drained": -2.7, "burnt": -2.4, "burnout": -2.6,
    "fatigue": -2.2, "insomnia": -2.6, "nightmare": -2.8, "draining": -2.0,
    "hazy": -1.1, "foggy": -1.2, "scattered": -1.5, "distracted": -1.4,
    "overthinking": -2.1, "spiraling": -2.7, "ruminate": -1.9,
    "ruminating": -2.0, "migraine": -2.2, "headache": -1.9, "sick": -1.9,
    "ill": -1.9, "pain": -2.1, "unwell": -2.0,
    # negative — strong
    "depressed": -3.4, "depression": -3.2, "despair": -3.4,
    "devastated": -3.4, "heartbroken": -3.2, "anguish": -3.3,
    "tormented": -3.2, "unbearable": -3.3, "intolerable": -3.2,
    "disgusted": -2.6, "disgust": -2.5, "contempt": -2.4, "furious": -3.1,
    "rage": -3.0, "livid": -3.0, "terrified": -3.1, "petrified": -3.0,
    "suicidal": -3.8, "unreal": -1.6, "impossible": -2.1,
}

# Intensifiers/downtoners (VADER booster conventions, multiplicative).
INTENSIFIERS: dict[str, float] = {
    "very": 1.4, "so": 1.2, "really": 1.25, "extremely": 1.6,
    "incredibly": 1.6, "absolutely": 1.6, "completely": 1.55,
    "totally": 1.5, "utterly": 1.6, "deeply": 1.45, "truly": 1.3,
    "quite": 1.15, "pretty": 1.15, "super": 1.4, "highly": 1.4,
    "insanely": 1.5, "unbelievably": 1.55,
    "slightly": 0.75, "somewhat": 0.8, "mildly": 0.75, "barely": 0.7,
    "hardly": 0.7, "almost": 0.85, "little": 0.9,
}
NEGATION_SCALAR = -0.74  # VADER's damped flip: "not good" < "bad"
BUT_WORDS = frozenset({"but", "however", "although", "though", "yet"})
SENTIMENT_SCALE = 4.0  # max lexicon magnitude maps onto [-1, 1]

NEGATORS = frozenset({
    "not", "no", "never", "nothing", "none", "nobody", "nowhere", "cannot",
    "can't", "won't", "don't", "doesn't", "didn't", "isn't", "aren't",
    "wasn't", "weren't", "haven't", "hasn't", "hadn't", "wouldn't",
    "couldn't", "shouldn't", "hardly", "barely", "rarely",
})

# Absolutist language (Al-Mosaiwi & Johnstone 2018): elevated in
# anxiety/depression and suicidal-ideation text; reported to the user as a
# self-reflection observation only — never as a risk score.
ABSOLUTIST_WORDS = frozenset({
    "always", "never", "nothing", "everything", "everyone", "nobody",
    "none", "every", "must", "completely", "totally", "absolutely",
    "entirely", "constantly", "forever", "unbearable", "impossible",
    "unreal", "wholly", "undeniably",
})

# --- emergent topic discovery (beyond the fixed theme lexicon) --------------------
# The lexicon covers nine universal themes; everything else a user's life
# revolves around — a new relationship, a startup, grief, guitar — must be
# DISCOVERED. Deterministic n-gram mining: content n-grams (never function
# words, never words the lexicon/sentiment layers already own) that recur
# across enough distinct days, surfaced either because they are RISING
# (share of entries vs the user's own earlier-window base rate, exact
# binomial into the BH family) or a PERSISTENT presence (a direct
# measurement — share of entries — so no significance test applies).
TOPIC_MIN_ENTRIES = 6       # entries mentioning it before it can be tested
TOPIC_MIN_DISTINCT_DAYS = 4
TOPIC_RISING_MIN_RECENT = 5     # recent-half mentions for a rising claim
TOPIC_RISING_MIN_SHARE = 0.18   # share of recent entries it must reach
TOPIC_RISING_MIN_GAIN = 0.12    # ... above the earlier-half base rate
TOPIC_MIN_PER_HALF = 10         # entries per half before a trend is claimable
TOPIC_PRESENCE_MIN_ENTRIES = 20
TOPIC_PRESENCE_MIN_SHARE = 0.30
TOPIC_PRESENCE_MIN_DAYS = 10
TOPIC_MAX_CANDIDATES = 12       # tested per run (by document frequency)
TOPIC_MAX_SIGNALS = 6           # surfaced per run, rising first

# Function words, auxiliaries, time/filler boilerplate and mood carriers —
# none of them can be a life topic. Deliberately broad: a false negative
# (a real topic skipped) costs little, a false positive costs trust.
TOPIC_STOPWORDS = frozenset({
    # pronouns / determiners / auxiliaries / prepositions / conjunctions
    "about", "after", "again", "all", "also", "although", "always", "another",
    "any", "anyone", "anything", "are", "around", "back", "because", "been",
    "before", "being", "both", "but", "came", "can", "cannot", "come",
    "could", "did", "didn", "does", "doesn", "doing", "done", "down", "else",
    "even", "every", "everyone", "everything", "few", "for", "from", "get",
    "gets", "getting", "give", "gives", "go", "goes", "going", "gone", "got",
    "had", "has", "hasn", "have", "haven", "having", "her", "here", "hers",
    "herself", "him", "himself", "his", "how", "into", "isn", "itself",
    "just", "keep", "keeps", "kept", "know", "known", "knows", "least",
    "less", "let", "like", "made", "make", "makes", "making", "many", "more",
    "most", "much", "must", "myself", "never", "next", "none", "nothing",
    "now", "off", "once", "one", "only", "other", "others", "our", "ours",
    "ourselves", "out", "over", "own", "put", "really", "said", "same",
    "say", "saying", "says", "see", "seem", "seemed", "seems", "seen",
    "several", "shall", "she", "should", "since", "some", "someone",
    "something", "still", "such", "take", "takes", "taking", "tell", "tells",
    "than", "that", "their", "theirs", "them", "themselves", "then", "there",
    "these", "they", "thing", "things", "think", "thinking", "this", "those",
    "though", "through", "thus", "too", "took", "under", "until", "upon",
    "very", "want", "wanted", "wants", "was", "wasn", "way", "well", "went",
    "were", "weren", "what", "when", "where", "whether", "which", "while",
    "who", "whom", "whose", "why", "will", "with", "within", "without",
    "won", "would", "yeah", "yes", "yet", "you", "your", "yours", "yourself",
    # time / journal boilerplate
    "today", "yesterday", "tomorrow", "morning", "afternoon", "evening",
    "night", "day", "days", "week", "weeks", "month", "months", "year",
    "years", "hour", "hours", "minute", "minutes", "time", "times", "moment",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
    "sunday", "january", "february", "march", "april", "june", "july",
    "august", "september", "october", "november", "december", "weekend",
    "tonight", "lately", "recently", "maybe", "kind", "sort", "stuff",
    "little", "bit", "pretty", "quite", "somewhat", "actually", "maybe",
    # mood/feeling carriers (the sentiment layer owns them)
    "feel", "feels", "felt", "feeling", "feelings", "emotion", "emotions",
    "mood", "mind", "head", "heart", "soul", "life", "living", "live",
    "love", "hate", "okay", "ok", "fine", "good", "bad", "better", "worse",
    "best", "worst", "great", "nice", "hard", "easy", "weird", "strange",
    # high-frequency journal verbs/nouns that are never life topics
    "people", "person", "told", "ask", "asked", "asking", "call", "called",
    "calling", "talk", "talked", "talking", "spend", "spent", "spending",
    "watch", "watched", "watching", "happen", "happened", "happening",
    "remember", "remembered", "start", "started", "starting", "stop",
    "stopped", "stopping", "thought", "thoughts", "wonder", "wondered",
    "wondering", "wait", "waited", "waiting", "try", "tried", "trying",
    "turn", "turned", "turning", "find", "found", "finding", "lot", "lots",
    "whole", "part", "kinda", "sorta", "someone's", "everyone's",
})

IRREGULAR_FORMS: dict[str, str] = {
    "slept": "sleep", "overslept": "sleep", "ate": "eat", "overate": "eat",
    "ran": "run", "cried": "cry", "woke": "wake", "awoke": "wake",
    "met": "meet", "paid": "pay", "said": "say", "felt": "feel",
    "grieved": "grieve", "missed": "miss", "loathed": "loathe",
}

BOOSTER_SCOPE = 3       # tokens before a sentiment word that may boost or negate it


# --- NLP primitives -------------------------------------------------------------

def word_forms(token: str) -> list[str]:
    """Deterministic morphological candidates for one token.

    Order matters only for determinism: theme/sentiment lookups accept
    the FIRST form present in the lexicon. The rules are deliberately
    light ("working"→"work", "studies"→"study", "running"→"run",
    "slept"→"sleep"); a real lemmatizer is not worth its weight here
    because lookups fall back to exact match anyway.
    """
    forms = [token]
    if token in IRREGULAR_FORMS:
        forms.append(IRREGULAR_FORMS[token])
    t = token
    if len(t) > 4 and t.endswith("ies"):
        forms.append(t[:-3] + "y")
    if len(t) > 3 and t.endswith("es"):
        forms.append(t[:-2])
    if len(t) > 3 and t.endswith("s") and not t.endswith("ss"):
        forms.append(t[:-1])
    if len(t) > 5 and t.endswith("ing"):
        base = t[:-3]
        forms.append(base)
        if len(base) > 3 and base[-1] == base[-2] and base[-1] not in "aeiouy":
            forms.append(base[:-1])
        forms.append(base + "e")
    if len(t) > 4 and t.endswith("ed"):
        base = t[:-2]
        forms.append(base)
        if len(base) > 3 and base[-1] == base[-2] and base[-1] not in "aeiouy":
            forms.append(base[:-1])
        forms.append(base + "e")
    seen: set[str] = set()
    return [f for f in forms if not (f in seen or seen.add(f))]


def theme_for(token: str) -> str | None:
    for form in word_forms(token):
        theme = THEME_WORDS.get(form)
        if theme is not None:
            return theme
    return None


def _word_valence(token: str) -> float:
    for form in word_forms(token):
        valence = SENTIMENT_LEXICON.get(form)
        if valence is not None:
            return valence
    return 0.0


def sentiment_score(tokens: list[str]) -> float:
    """Graded lexicon sentiment in [-1, 1] (VADER-style, deterministic).

    Intensifiers scale the next sentiment word; negation flips it with
    damping ("not good" is mildly negative, not catastrophic — the
    VADER x-0.74 scalar); "but" re-weights the sentence so the clause
    after the contrast carries the meaning.
    """
    sentiments: list[float] = []
    # "but" re-weighting: find the LAST contrastive; damp before, boost after.
    split = max((i for i, t in enumerate(tokens) if t in BUT_WORDS), default=-1)
    segments: list[tuple[list[float], float]] = []
    if split >= 0:
        segments = [
            (tokens[: split], 0.5),
            (tokens[split + 1:], 1.5),
        ]
    else:
        segments = [(tokens, 1.0)]

    for seg, seg_weight in segments:
        for i, token in enumerate(seg):
            valence = _word_valence(token)
            if valence == 0.0:
                continue
            window = seg[max(0, i - BOOSTER_SCOPE): i]
            # Boosters compound; a negator in scope flips the valence ONCE
            # with damping (VADER's x-0.74: "not good" is mildly negative).
            boost = 1.0
            negated = False
            for prev in window:
                if prev in INTENSIFIERS:
                    boost *= INTENSIFIERS[prev]
                if prev in NEGATORS:
                    negated = True
            valence *= boost
            if negated:
                valence *= NEGATION_SCALAR
            valence = max(-4.0, min(4.0, valence)) * seg_weight
            sentiments.append(valence)

    if not sentiments:
        return 0.0
    total = sum(sentiments)
    return max(-1.0, min(1.0, total / SENTIMENT_SCALE))


def absolutist_density(tokens: list[str]) -> float:
    """Absolutist words per 100 tokens (Al-Mosaiwi & Johnstone 2018)."""
    if not tokens:
        return 0.0
    hits = sum(1 for t in tokens if t in ABSOLUTIST_WORDS)
    return round(100.0 * hits / len(tokens), 2)


def extract_themes(tokens: list[str]) -> set[str]:
    return {theme for theme in (theme_for(t) for t in tokens) if theme is not None}


def sentences_of(text: str) -> list[str]:
    """Normalized sentences of at least MIN_SENTENCE_TOKENS tokens."""
    out: list[str] = []
    for raw in SENTENCE_RE.findall(text):
        tokens = WORD_RE.findall(raw.lower())
        if len(tokens) >= MIN_SENTENCE_TOKENS:
            out.append(" ".join(tokens))
        if len(out) >= MAX_SENTENCES_PER_ENTRY:
            break
    return out


# --- within-person baseline (Bolger & Laurenceau 2013) ---------------------------

def _personal_baselines(day_sentiments: list[tuple[date, float]]) -> dict[date, float]:
    """Each day's personal mood baseline: mean of neighbouring days.

    A ±7-day window around each day (excluding the day itself once
    enough neighbours exist) absorbs slow trends — the confound that
    made v2 report spurious mood correlations during any sustained dip
    or climb. Group means never enter: this is the user's own norm.
    """
    moods = dict(day_sentiments)
    days = sorted(moods)
    if not days:
        return {}
    global_mean = sum(moods.values()) / len(moods)
    out: dict[date, float] = {}
    for day in days:
        neighbours = [
            moods[other]
            for other in days
            if other != day and abs((other - day).days) <= BASELINE_HALF_WINDOW
        ]
        if len(neighbours) >= BASELINE_MIN_NEIGHBORS:
            out[day] = sum(neighbours) / len(neighbours)
        else:
            window = [
                moods[other]
                for other in days
                if abs((other - day).days) <= BASELINE_HALF_WINDOW
            ]
            out[day] = (sum(window) / len(window)) if window else global_mean
    return out


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 3:
        return None
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    sxx = sum(v * v for v in dx)
    syy = sum(v * v for v in dy)
    if sxx <= 0.0 or syy <= 0.0:
        return None
    return sum(a * b for a, b in zip(dx, dy)) / math.sqrt(sxx * syy)


def _lag1_autocorr(values: list[float]) -> float | None:
    """Lag-1 autocorrelation of a value sequence; None when unmeasurable.

    Used to inflate the EWMA control limits for autocorrelated mood (the
    iid variance formula understates the run-to-run spread); needs enough
    consecutive pairs and actual variance to mean anything.
    """
    if len(values) < 8:
        return None
    return _pearson(values[:-1], values[1:])


def _sd(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = sum(values) / len(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / (len(values) - 1))


# --- pattern store ----------------------------------------------------------------

@dataclass
class StoredPattern:
    """The persistent, per-pattern memory (serialized into the encrypted store)."""

    pid: str
    kind: str
    label: str
    first_seen: str
    last_seen: str
    first_qualified: str
    last_qualified: str
    occurrences: int
    state: str
    qualification_days: list[str]
    evidence_dates: list[str]
    feedback: dict
    detail: dict

    def to_dict(self) -> dict:
        return {
            "pid": self.pid, "kind": self.kind, "label": self.label,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "first_qualified": self.first_qualified,
            "last_qualified": self.last_qualified,
            "occurrences": self.occurrences, "state": self.state,
            "qualification_days": self.qualification_days,
            "evidence_dates": self.evidence_dates,
            "feedback": self.feedback, "detail": self.detail,
        }


def fresh_state() -> dict:
    return {"v": STATE_VERSION, "patterns": {}, "history": []}


def _parse_iso(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        date.fromisoformat(value)
    except ValueError:
        return None
    return value


def _stored_from_dict(raw: Any, pid: str) -> StoredPattern | None:
    if not isinstance(raw, dict):
        return None
    kind = raw.get("kind")
    label = raw.get("label")
    if not isinstance(kind, str) or not isinstance(label, str):
        return None
    iso_or_none = lambda v: _parse_iso(v)  # noqa: E731
    qualification_days = sorted({
        d for d in raw.get("qualification_days", []) if _parse_iso(d)
    }) if isinstance(raw.get("qualification_days"), list) else []
    evidence_dates = sorted({
        d for d in raw.get("evidence_dates", []) if _parse_iso(d)
    }) if isinstance(raw.get("evidence_dates"), list) else []
    detail = raw.get("detail") if isinstance(raw.get("detail"), dict) else {}
    feedback = raw.get("feedback") if isinstance(raw.get("feedback"), dict) else {}
    try:
        occurrences = int(raw.get("occurrences", 0) or 0)
        if occurrences < 0:
            occurrences = 0
    except (TypeError, ValueError):
        return None  # a corrupt record must degrade to amnesia, not a 500
    return StoredPattern(
        pid=pid,
        kind=kind,
        label=label[:200],
        first_seen=iso_or_none(raw.get("first_seen")) or "1970-01-01",
        last_seen=iso_or_none(raw.get("last_seen")) or "1970-01-01",
        first_qualified=iso_or_none(raw.get("first_qualified")) or "",
        last_qualified=iso_or_none(raw.get("last_qualified")) or "",
        occurrences=occurrences,
        state=raw.get("state") if raw.get("state") in SURFACED_STATES + ("candidate", "archived") else "candidate",
        qualification_days=qualification_days[:QUALIFICATION_DAYS_CAP],
        evidence_dates=evidence_dates[:EVIDENCE_DATES_CAP],
        feedback=feedback,
        detail=detail,
    )


def load_state(raw: bytes | None) -> dict:
    """Parse the encrypted-store plaintext; any defect means a fresh brain.

    The store is our own ciphertext, but it crossed a JSON boundary and
    years of schema evolution — a corrupt store must degrade to amnesia,
    never to a crash or a fabricated pattern.
    """
    if raw is None:
        return fresh_state()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return fresh_state()
    if not isinstance(parsed, dict):
        return fresh_state()
    if not isinstance(parsed.get("v"), int) or parsed["v"] > STATE_VERSION:
        return fresh_state()
    patterns_raw = parsed.get("patterns")
    patterns: dict[str, StoredPattern] = {}
    if isinstance(patterns_raw, dict):
        for pid, record in patterns_raw.items():
            stored = _stored_from_dict(record, str(pid))
            if stored is not None:
                patterns[stored.pid] = stored
    history = parsed.get("history") if isinstance(parsed.get("history"), list) else []
    clean_history = [h for h in history if isinstance(h, list) and len(h) == 2
                     and isinstance(h[0], str) and isinstance(h[1], list)][:HISTORY_DAYS]
    return {"v": STATE_VERSION, "patterns": patterns, "history": clean_history}


def dump_state(state: dict) -> bytes:
    """Byte-stable serialization (sort_keys) so identical brains dump identically."""
    payload = {
        "v": state["v"],
        "patterns": {pid: rec.to_dict() for pid, rec in state["patterns"].items()},
        "history": state["history"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --- detectors ----------------------------------------------------------------------

@dataclass
class _Signal:
    pid: str
    kind: str
    label: str
    occurrences: int
    pvalue: float | None  # None = qualifies on its own (non-statistical family)
    detail: dict
    evidence_days: list[date]


def _decay_strength(evidence: list[date], today: date) -> float:
    """Decayed evidence density: mentions with a 45-day half-life, saturating at 1."""
    # Each day's weight is capped at 1.0: a future-dated evidence day (which
    # entry-date validation should already prevent) must not push the
    # exponent positive — 2.0 ** +7900 is an OverflowError that would escape
    # as a 500 on every future recompute. Past days keep exact half-life.
    weight = sum(
        2.0 ** min(0.0, -((today - day).days) / HALF_LIFE_DAYS) for day in evidence
    )
    return min(1.0, weight / EVIDENCE_FULL)


def _detect_themes(
    per_entry: list[tuple[JournalEntry, list[str], set[str], float]],
    weekday_total: dict[int, int],
    total_entries: int,
) -> list[_Signal]:
    """Base-rate-corrected weekday concentration + within-person mood ties.

    Two v2 flaws fixed here:

      * the weekday test asked only about the argmax day — selecting the
        best of 7 and testing it once understated the p-value ~7x. Every
        weekday that clears the fraction/sample floors is now tested and
        ALL of the tests enter the Benjamini-Hochberg family; the best
        surviving day becomes the pattern.
      * mood correlations ran on raw sentiment, so any slow mood trend
        manufactured spurious ties (probe_brain.py: five false claims at
        p <= 1e-6). They now run on residuals against the user's own
        rolling baseline (Bolger & Laurenceau 2013, within-person
        centering) — a theme only ties to mood if its days read
        different from the user's norm AT THAT MOMENT.
    """
    signals: list[_Signal] = []
    themes = sorted({theme for _, _, themes, _ in per_entry for theme in themes})
    for theme in themes:
        with_theme = [(e, s) for e, _, themes, s in per_entry if theme in themes]
        without_theme = [(e, s) for e, _, themes, s in per_entry if theme not in themes]
        count = len(with_theme)
        if count < TEMPORAL_MIN_N:
            continue
        days = [e.entry_date for e, _ in with_theme]

        # Weekday concentration: test EVERY candidate day, not just the max.
        weekday_counts: dict[int, int] = {}
        for e, _ in with_theme:
            weekday_counts[e.entry_date.weekday()] = weekday_counts.get(e.entry_date.weekday(), 0) + 1
        candidates: list[tuple[int, int, float, float]] = []  # (weekday, k, fraction, pvalue)
        for weekday in sorted(weekday_counts):
            k = weekday_counts[weekday]
            fraction = k / count
            if k < TEMPORAL_MIN_DAY_K or fraction < TEMPORAL_MIN_FRACTION:
                continue
            base_rate = weekday_total.get(weekday, 0) / total_entries
            if not 0.0 < base_rate < 1.0:
                continue
            candidates.append((weekday, k, fraction, statsig.binomial_sf(k, count, base_rate)))
        # EVERY candidate weekday enters the significance family (selecting
        # the argmax first and testing it alone understated p-values by up
        # to the number of weekdays). update() keeps, per theme, only the
        # best SURVIVOR after correction.
        for weekday, k, fraction, pvalue in candidates:
            signals.append(_Signal(
                pid=f"temporal:{theme}",
                kind="temporal",
                label=theme,
                occurrences=count,
                pvalue=pvalue,
                detail={
                    "day": DAY_NAMES[weekday],
                    "day_count": k,
                    "day_fraction": round(fraction, 3),
                    "base_rate": round(weekday_total.get(weekday, 0) / total_entries, 3),
                    "p_value": round(pvalue, 6),
                    "days_tested": len(candidates),
                },
                evidence_days=days,
            ))

        if len(without_theme) >= MOOD_MIN_PER_SIDE:
            moods_with = [s for _, s in with_theme]
            moods_without = [s for _, s in without_theme]
            delta = sum(moods_without) / len(moods_without) - sum(moods_with) / len(moods_with)
            effect = statsig.cohens_d(moods_with, moods_without, variance_floor=MOOD_SD_FLOOR)
            if abs(delta) >= MOOD_MIN_DELTA and abs(effect) >= MOOD_MIN_EFFECT:
                _, pvalue = statsig.welch_test(moods_with, moods_without, variance_floor=MOOD_SD_FLOOR)
                signals.append(_Signal(
                    pid=f"mood_correlation:{theme}",
                    kind="mood_correlation",
                    label=theme,
                    occurrences=count,
                    pvalue=pvalue,
                    detail={
                        "mood_delta": round(delta, 3),
                        "direction": "lower" if delta > 0 else "higher",
                        "cohens_d": round(effect, 3),
                        "p_value": round(pvalue, 6),
                    },
                    evidence_days=days,
                ))
    return signals


def _detect_links(
    day_themes: dict[date, set[str]],
    day_residuals: dict[date, float],
    today: date,
) -> list[_Signal]:
    """Lagged day-after links: theme today → mood deviation tomorrow.

    The best-validated lagged association in the daily-diary literature
    is sleep → next-day affect (Bourke et al. 2026, meta-analysis of 118
    studies); stress spillover (Bolger et al. 1989) has the same shape.
    We test every theme's next-day residual mood against the user's own
    baseline — the literal "pattern linking" the product promises.
    Only lag-1 is tested: it is the interpretable, best-replicated lag,
    and each extra lag doubles the multiple-testing burden.
    """
    days = sorted(day_themes)
    transitions: list[tuple[date, date]] = []
    for prev, cur in zip(days, days[1:]):
        gap = (cur - prev).days
        if 1 <= gap <= LINK_MAX_GAP_DAYS:
            transitions.append((prev, cur))
    if len(transitions) < 2 * LINK_MIN_PER_SIDE:
        return []

    signals: list[_Signal] = []
    themes = sorted({t for theme_set in day_themes.values() for t in theme_set})
    for theme in themes:
        exposed = [day_residuals[cur] for prev, cur in transitions if theme in day_themes[prev]]
        unexposed = [day_residuals[cur] for prev, cur in transitions if theme not in day_themes[prev]]
        if len(exposed) < LINK_MIN_PER_SIDE or len(unexposed) < LINK_MIN_PER_SIDE:
            continue
        delta = sum(unexposed) / len(unexposed) - sum(exposed) / len(exposed)
        effect = statsig.cohens_d(exposed, unexposed, variance_floor=MOOD_SD_FLOOR)
        if abs(delta) < MOOD_MIN_DELTA or abs(effect) < MOOD_MIN_EFFECT:
            continue
        _, pvalue = statsig.welch_test(exposed, unexposed, variance_floor=MOOD_SD_FLOOR)
        outcome_days = [cur for prev, cur in transitions if theme in day_themes[prev]]
        signals.append(_Signal(
            pid=f"link:{theme}",
            kind="link",
            label=theme,
            occurrences=len(exposed),
            pvalue=pvalue,
            detail={
                "lag_days": 1,
                "mood_delta": round(delta, 3),
                "direction": "lower" if delta > 0 else "higher",
                "cohens_d": round(effect, 3),
                "p_value": round(pvalue, 6),
                "n_after": len(exposed),
                "n_other": len(unexposed),
            },
            evidence_days=outcome_days,
        ))
    return signals


def _detect_mood_dynamics(
    day_sentiments: list[tuple[date, float]],
    day_residuals: dict[date, float],
    today: date,
) -> list[_Signal]:
    """Within-person mood dynamics: inertia and instability (Houben 2015).

    Emotional inertia — how strongly today's mood predicts tomorrow's —
    and affective instability are meta-analytically tied to lower
    wellbeing (Kuppens 2010; Houben et al. 2015). Both are surfaced only
    as a CHANGE from the user's own earlier norm ("more than usual for
    you"), never as an absolute verdict; individual cutoffs are not
    validated and we do not pretend otherwise.
    """
    signals: list[_Signal] = []
    recent_cutoff = today - timedelta(days=INERTIA_RECENT_DAYS)

    # --- inertia: lag-1 autocorrelation of daily mood, recent vs earlier.
    consecutive: list[tuple[date, float, float]] = []
    for (d1, s1), (d2, s2) in zip(day_sentiments, day_sentiments[1:]):
        if 1 <= (d2 - d1).days <= 2:
            consecutive.append((d2, s1, s2))
    recent = [(s1, s2) for d, s1, s2 in consecutive if d > recent_cutoff]
    earlier = [(s1, s2) for d, s1, s2 in consecutive if d <= recent_cutoff]
    if len(recent) >= INERTIA_MIN_PAIRS and len(earlier) >= INERTIA_MIN_PAIRS:
        r_recent = _pearson([a for a, _ in recent], [b for _, b in recent])
        r_earlier = _pearson([a for a, _ in earlier], [b for _, b in earlier])
        if (r_recent is not None and r_earlier is not None
                and r_recent >= INERTIA_RECENT_MIN
                and r_recent - r_earlier >= INERTIA_DELTA):
            # An autocorrelation IS a statistical claim: r = 0.46 on 10
            # pairs is p ~ 0.18 noise. The p-value enters the same
            # Benjamini-Hochberg family as every other claim this run.
            pvalue = statsig.correlation_p(r_recent, len(recent))
            signals.append(_Signal(
                pid="inertia:mood",
                kind="inertia",
                label="day-to-day mood",
                occurrences=len(recent),
                pvalue=pvalue,
                detail={
                    "carryover_recent": round(r_recent, 3),
                    "carryover_earlier": round(r_earlier, 3),
                    "window_days": INERTIA_RECENT_DAYS,
                    "p_value": round(pvalue, 6),
                },
                evidence_days=[d for d, _, _ in consecutive if d > recent_cutoff],
            ))

    # --- instability: spread of within-person residuals, recent vs earlier.
    residual_days = sorted(day_residuals)
    recent_vals = [day_residuals[d] for d in residual_days if d > recent_cutoff]
    earlier_vals = [day_residuals[d] for d in residual_days if d <= recent_cutoff]
    if len(recent_vals) >= INSTABILITY_MIN_DAYS and len(earlier_vals) >= INSTABILITY_MIN_DAYS:
        sd_recent = _sd(recent_vals)
        sd_earlier = _sd(earlier_vals)
        if sd_recent >= INSTABILITY_SD_FLOOR and sd_recent >= INSTABILITY_RATIO * max(sd_earlier, 0.0):
            # Variance-ratio claim → F-test p-value, in the BH family.
            v_r, v_e = sd_recent**2, max(sd_earlier, 1e-12) ** 2
            f_stat = v_r / v_e
            pvalue = min(
                1.0,
                2.0 * min(
                    statsig.f_sf(f_stat, len(recent_vals) - 1, len(earlier_vals) - 1),
                    statsig.f_sf(1.0 / f_stat, len(earlier_vals) - 1, len(recent_vals) - 1),
                ),
            )
            signals.append(_Signal(
                pid="instability:mood",
                kind="instability",
                label="daily mood",
                occurrences=len(recent_vals),
                pvalue=pvalue,
                detail={
                    "spread_recent": round(sd_recent, 3),
                    "spread_earlier": round(sd_earlier, 3),
                    "window_days": INSTABILITY_RECENT_DAYS,
                    "p_value": round(pvalue, 6),
                },
                evidence_days=[d for d in residual_days if d > recent_cutoff],
            ))
    return signals


def _phrase_pid(kind: str, cluster_members: list[phrase_miner.SentenceRef]) -> str:
    """Stable pattern id for a phrase cluster: anchored on its earliest member.

    Anchoring on the representative sentence made the pid flip whenever
    the most-frequent variant changed between runs, fragmenting the
    pattern's lifecycle. The earliest member persists as the cluster
    gains members, so the identity is stable within the analysis window.
    """
    anchor = min(cluster_members, key=lambda r: (r.day, r.text))
    digest = hashlib.blake2b(anchor.text.encode("utf-8"), digest_size=6).hexdigest()
    return f"{kind}:{digest}"


def _detect_phrases(window: list[JournalEntry]) -> list[_Signal]:
    """Near-duplicate clusters; negative ones surface as rumination.

    A recurring near-duplicate cluster is surfaced as a repeated *worry*
    when it reads negative (repetitive negative thinking, a transdiagnostic
    process — Ehring & Watkins 2008) or when it is non-positive and
    negation-heavy ("can't sleep, mind won't stop" — perseverative negative
    phrasing). Absolutist-word density (Al-Mosaiwi & Johnstone 2018) rides
    along in the detail. Non-negative repeats stay the neutral
    "recurring_phrase".
    """
    sentences: list[phrase_miner.SentenceRef] = []
    for entry in window:
        for sentence in sentences_of(entry.text):
            sentences.append(phrase_miner.SentenceRef(text=sentence, day=entry.entry_date))
            if len(sentences) >= MAX_WINDOW_SENTENCES:
                break
        if len(sentences) >= MAX_WINDOW_SENTENCES:
            break
    signals: list[_Signal] = []
    for cluster in phrase_miner.near_duplicate_clusters(
        sentences,
        min_size=PHRASE_MIN_OCCURRENCES,
        min_span_days=PHRASE_MIN_SPAN_DAYS,
        min_distinct_days=PHRASE_MIN_DISTINCT_DAYS,
    ):
        days = sorted({ref.day for ref in cluster.members})
        variants = sorted({ref.text for ref in cluster.members})
        member_sentiments = [sentiment_score(ref.text.split()) for ref in cluster.members]
        member_negators = [sum(1 for t in ref.text.split() if t in NEGATORS) for ref in cluster.members]
        negativity = sum(member_sentiments) / len(member_sentiments)
        negators = sum(member_negators) / len(member_negators)
        is_rumination = (
            negativity <= RUMINATION_NEGATIVITY_MAX
            or (negativity <= 0.0 and negators >= RUMINATION_MIN_NEGATORS)
        )
        kind = "rumination" if is_rumination else "recurring_phrase"
        tokens = " ".join(variants).split()
        detail: dict[str, Any] = {
            "span_days": cluster.span_days,
            "distinct_days": cluster.distinct_days,
            "first": days[0].isoformat(),
            "last": days[-1].isoformat(),
            "variants": variants[:3],
        }
        if is_rumination:
            detail["negativity"] = round(negativity, 3)
            detail["mean_negators"] = round(negators, 2)
            detail["absolutist_per_100"] = absolutist_density(tokens)
        signals.append(_Signal(
            pid=_phrase_pid(kind, cluster.members),
            kind=kind,
            label=cluster.representative,
            occurrences=len(cluster.members),
            pvalue=None,
            detail=detail,
            evidence_days=days,
        ))
    return signals


def _detect_mood_shift(day_sentiments: list[tuple[date, float]]) -> list[_Signal]:
    """EWMA control chart over daily mood: sustained shifts vs personal baseline.

    The chart estimates the user's own in-control mood (mean and spread
    over the first quarter of the window, min 10 days), then tracks an
    exponentially weighted moving average (lambda 0.18, inside the
    0.05-0.25 band validated by Smit, Schat & Ceulemans 2023); a run of
    points beyond +/-2.7 sigma_ewma in the recent tail reports a
    trajectory shift (Snippe et al. 2023 used this exact family of
    charts on EMA mood series).
    """
    n = len(day_sentiments)
    if n < MOOD_SHIFT_MIN_DAYS:
        return []
    baseline = day_sentiments[: max(MOOD_SHIFT_BASELINE_MIN, n // 4)]
    values = [s for _, s in baseline]
    mu = sum(values) / len(values)
    sigma = statsig._variance(values) if len(values) > 1 else 0.0  # noqa: SLF001
    sigma = math.sqrt(max(sigma, MOOD_SHIFT_SIGMA_FLOOR**2))
    sigma_ewma = sigma * math.sqrt(MOOD_SHIFT_LAMBDA / (2 - MOOD_SHIFT_LAMBDA))
    # The textbook EWMA variance assumes iid observations. Daily mood is
    # precisely the autocorrelated series this engine's own inertia
    # detector exists to find: for AR(1) with lag-1 correlation phi the
    # long-run variance inflates by ~ (1+phi)/(1-phi) (phi = 0.5 → ~2.4x),
    # and unadjusted ±2.7 "sigma" limits are effectively ±1.75 — measured
    # false-alarm rates of ~19% on stationary autocorrelated mood. Only a
    # STRONG baseline phi estimate triggers inflation: with the ~15-point
    # baselines this chart gets, the standard error of r is ~0.27, so
    # weak estimates are indistinguishable from iid and inflating on them
    # would smother real shifts.
    phi = _lag1_autocorr(values)
    if phi is not None and phi >= 0.35:
        inflation = (1.0 + phi) / (1.0 - phi)
        sigma_ewma *= math.sqrt(min(max(inflation, 1.0), 16.0))
    upper = mu + MOOD_SHIFT_LIMIT * sigma_ewma
    lower = mu - MOOD_SHIFT_LIMIT * sigma_ewma

    ewma = mu
    signs: list[tuple[date, int]] = []
    last_ewma = mu
    for day, s in day_sentiments[len(baseline):]:
        ewma = MOOD_SHIFT_LAMBDA * s + (1 - MOOD_SHIFT_LAMBDA) * ewma
        last_ewma = ewma
        sign = 1 if ewma > upper else (-1 if ewma < lower else 0)
        signs.append((day, sign))

    if not signs or signs[-1][1] == 0:
        return []
    tail = signs[-MOOD_SHIFT_TAIL:]
    last_sign = tail[-1][1]
    beyond = [day for day, sign in tail if sign == last_sign]
    if len(beyond) < MOOD_SHIFT_RUN:
        return []
    shift = last_ewma - mu
    if abs(shift) < MOOD_SHIFT_MIN_SHIFT:
        return []
    direction = "lower" if last_sign < 0 else "higher"
    # The excursion IS a statistical claim (a control chart is a repeated
    # test): attach its p-value so it enters the BH family with everything
    # else instead of bypassing multiple-testing correction.
    z_last = (last_ewma - mu) / sigma_ewma if sigma_ewma > 0 else 0.0
    pvalue = statsig.normal_two_sided_sf(z_last)
    return [_Signal(
        pid=f"mood_shift:{direction}",
        kind="mood_shift",
        label="recent mood",
        occurrences=len(beyond),
        pvalue=pvalue,
        detail={
            "direction": direction,
            "shift": round(shift, 3),
            "baseline": round(mu, 3),
            "current": round(last_ewma, 3),
            "beyond_limit_days": len(beyond),
            "p_value": round(pvalue, 6),
        },
        evidence_days=beyond,
    )]


# --- emergent topic discovery -------------------------------------------------------

def _detect_topics(
    per_entry: list[tuple[JournalEntry, list[str], set[str], float]],
) -> list[_Signal]:
    """Discover recurring content n-grams the fixed lexicon does not cover.

    The theme lexicon knows nine universal themes; everything else a life
    revolves around — a new relationship, a startup, grief, guitar — must be
    found in the text itself. Candidates are unigrams and adjacent bigrams
    of content tokens (function words, theme words, sentiment carriers and
    absolutist markers are all excluded — those layers own them), recurring
    across enough entries and distinct days. A candidate surfaces either as
    RISING (recent-half share vs the user's own earlier-half base rate,
    exact binomial, into the Benjamini-Hochberg family — "X is taking up
    more space in your writing") or as a PERSISTENT presence (a direct
    measurement of share, ≥30% of entries — no null hypothesis applies).
    """
    n = len(per_entry)
    if n < TOPIC_MIN_PER_HALF * 2:
        return []
    # Halves are split at the median entry DATE, not a fixed calendar offset:
    # a two-month journal has "earlier vs recent" just like an eight-month
    # one, and the comparison must work for both.
    split = per_entry[n // 2][0].entry_date

    doc_tokens: list[tuple[date, list[str]]] = []
    for entry, tokens, _, _ in per_entry:
        norm = [t[:-2] if t.endswith("'s") else t for t in tokens]
        doc_tokens.append((entry.entry_date, norm))
    recent_idx = {i for i, (d, _) in enumerate(doc_tokens) if d >= split}
    earlier_n = n - len(recent_idx)

    def eligible(token: str) -> bool:
        if token in TOPIC_STOPWORDS or token in NEGATORS or token in BUT_WORDS:
            return False
        if token in ABSOLUTIST_WORDS or token in INTENSIFIERS:
            return False
        if theme_for(token) is not None:  # also catches theme inflections
            return False
        if any(f in SENTIMENT_LEXICON for f in word_forms(token)):
            return False
        return len(token) >= 4

    df_docs: dict[str, set[int]] = {}
    df_days: dict[str, set[date]] = {}
    for i, (day, tokens) in enumerate(doc_tokens):
        prev = None
        for tok in tokens:
            if not eligible(tok):
                prev = None
                continue
            for cand in (tok, f"{prev} {tok}") if prev else (tok,):
                df_docs.setdefault(cand, set()).add(i)
                df_days.setdefault(cand, set()).add(day)
            prev = tok

    candidates: list[tuple[str, int, int, int]] = []  # label, total, days, recent_df
    for label, docs_hit in df_docs.items():
        total = len(docs_hit)
        days_n = len(df_days[label])
        if total < TOPIC_MIN_ENTRIES or days_n < TOPIC_MIN_DISTINCT_DAYS:
            continue
        recent_df = sum(1 for i in docs_hit if i in recent_idx)
        candidates.append((label, total, days_n, recent_df))
    # Highest-document-frequency first: when "guitar" and "guitar practice"
    # both qualify, the broader one wins and nested labels are dropped.
    candidates.sort(key=lambda c: (-c[1], c[0]))
    candidates = candidates[:TOPIC_MAX_CANDIDATES]

    recent_n = len(recent_idx)
    kept_tokens: set[str] = set()
    ranked: list[tuple[int, _Signal]] = []
    for label, total, days_n, recent_df in candidates:
        toks = label.split()
        if any(t in kept_tokens for t in toks):
            continue
        share = total / n
        pvalue: float | None = None
        trend = "steady"
        share_recent = recent_df / recent_n if recent_n else 0.0
        share_earlier = (total - recent_df) / earlier_n if earlier_n else 0.0
        if recent_n >= TOPIC_MIN_PER_HALF and earlier_n >= TOPIC_MIN_PER_HALF:
            base = ((total - recent_df) + 0.5) / (earlier_n + 1)
            if (recent_df >= TOPIC_RISING_MIN_RECENT
                    and share_recent >= TOPIC_RISING_MIN_SHARE
                    and share_recent >= base + TOPIC_RISING_MIN_GAIN
                    # AND a substantial RELATIVE gain: the binomial p-value
                    # conditions on a base estimated from the same window's
                    # earlier half, so a chance-low earlier half makes an
                    # ordinary recent half look "rising". Demanding the
                    # recent rate roughly double the base keeps chance-low
                    # baselines from manufacturing claims.
                    and share_recent >= 2.0 * base + 0.05):
                pvalue = statsig.binomial_sf(recent_df, recent_n, base)
                # The effect gates pre-select for extremeness, so the BH
                # family downstream only ever sees gate survivors and
                # cannot correct the multiplicity that matters. Correct
                # here for the REAL family: every candidate topic that
                # was tested (Bonferroni on len(candidates)).
                if pvalue > ALPHA / max(1, len(candidates)):
                    pvalue = None
                else:
                    trend = "rising"
        is_presence = (total >= TOPIC_PRESENCE_MIN_ENTRIES
                       and share >= TOPIC_PRESENCE_MIN_SHARE
                       and share <= TOPIC_PRESENCE_MAX_SHARE
                       and days_n >= TOPIC_PRESENCE_MIN_DAYS)
        if pvalue is None and not is_presence:
            continue
        detail: dict[str, Any] = {
            "trend": trend,
            "entries": total,
            "distinct_days": days_n,
            "share": round(share, 3),
            "share_earlier": round(share_earlier, 3),
            "share_recent": round(share_recent, 3),
        }
        if pvalue is not None:
            detail["p_value"] = round(pvalue, 6)
        kept_tokens.update(toks)
        ranked.append((total, _Signal(
            pid=f"topic:{label}",
            kind="topic",
            label=label,
            occurrences=total,
            pvalue=pvalue,
            detail=detail,
            evidence_days=sorted(df_days[label]),
        )))

    # Rising claims first (they carry the news), then presence.
    ranked.sort(key=lambda item: (item[1].pvalue is None, -item[0], item[1].pid))
    return [signal for _, signal in ranked[:TOPIC_MAX_SIGNALS]]


# --- lifecycle merge ------------------------------------------------------------------

def _iso(day: date) -> str:
    return day.isoformat()


def _merge_lifecycle(store: dict, qualified: list[_Signal], today: date) -> None:
    patterns: dict[str, StoredPattern] = store["patterns"]
    today_iso = _iso(today)
    qualified_pids = set()

    for signal in qualified:
        qualified_pids.add(signal.pid)
        record = patterns.get(signal.pid)
        if record is None:
            record = StoredPattern(
                pid=signal.pid, kind=signal.kind, label=signal.label,
                first_seen=_iso(min(signal.evidence_days)),
                last_seen=_iso(max(signal.evidence_days)),
                first_qualified=today_iso, last_qualified=today_iso,
                occurrences=signal.occurrences, state="candidate",
                qualification_days=[], evidence_dates=[], feedback={},
                detail={},
            )
            patterns[signal.pid] = record
        record.kind = signal.kind
        # Cap at write time too (load caps at 200): a pattern label comes
        # from journal text and a 1 MiB single-sentence entry must not
        # become a 1 MiB stored label rendered on cards.
        record.label = signal.label[:200]
        record.occurrences = signal.occurrences
        record.detail = signal.detail
        record.first_seen = min(record.first_seen, _iso(min(signal.evidence_days)))
        record.last_seen = max(record.last_seen, _iso(max(signal.evidence_days)))
        record.last_qualified = today_iso
        record.first_qualified = record.first_qualified or today_iso
        days = sorted(set(record.qualification_days) | {today_iso})
        record.qualification_days = days[-QUALIFICATION_DAYS_CAP:]
        evidence = sorted(set(record.evidence_dates)
                          | {_iso(d) for d in signal.evidence_days})
        record.evidence_dates = evidence[-EVIDENCE_DATES_CAP:]

        # Lifecycle promotion: strong evidence surfaces immediately; weaker
        # signals must re-qualify on another day (or age a week) first.
        if record.state == "candidate":
            spread = (date.fromisoformat(record.qualification_days[-1])
                      - date.fromisoformat(record.qualification_days[0])).days
            if (record.occurrences >= STRONG_EVIDENCE
                    or len(record.qualification_days) >= 2
                    or (today - date.fromisoformat(record.first_qualified)).days >= PROMOTE_AGE_DAYS
                    or spread >= PROMOTE_AGE_DAYS):
                record.state = "emerging"
        if record.state == "emerging":
            if (today - date.fromisoformat(record.first_qualified)).days >= CONFIRM_AGE_DAYS:
                record.state = "confirmed"
        elif record.state in ("fading", "archived"):
            record.state = "emerging"  # re-qualified: back in play

    # Aging: patterns that stopped qualifying fade, archive, then are dropped.
    for pid in sorted(patterns):
        record = patterns[pid]
        if pid in qualified_pids or not record.last_qualified:
            continue
        stale_days = (today - date.fromisoformat(record.last_qualified)).days
        if record.state in ACTIVE_STATES and stale_days > GRACE_DAYS:
            record.state = "fading"
        if record.state == "fading" and stale_days > ARCHIVE_DAYS:
            record.state = "archived"
        if record.state == "archived" and stale_days > DROP_DAYS:
            del patterns[pid]

    # Bounded store: evict archived-oldest first, then weakest.
    if len(patterns) > MAX_STORED_PATTERNS:
        ranked = sorted(
            patterns.items(),
            key=lambda kv: (
                kv[1].state != "archived",
                kv[1].last_qualified,
                kv[1].occurrences,
            ),
        )
        for pid, _ in ranked[: len(patterns) - MAX_STORED_PATTERNS]:
            del patterns[pid]


# --- the update entry point -------------------------------------------------------------

@dataclass
class BrainUpdate:
    new_state: dict
    surfaced: list[Pattern]
    stats: dict
    patterns_new: int
    patterns_fading: int


def update(state: dict, entries: list[JournalEntry], today: date) -> BrainUpdate:
    """Fold the corpus into the persistent store; surface what earned it."""
    store = state if isinstance(state, dict) and isinstance(state.get("patterns"), dict) else fresh_state()

    cutoff = today - timedelta(days=WINDOW_DAYS)
    ordered = sorted(entries, key=lambda e: e.entry_date)
    window = [e for e in ordered if e.entry_date >= cutoff][-MAX_WINDOW_ENTRIES:]

    per_entry: list[tuple[JournalEntry, list[str], set[str], float]] = []
    for entry in window:
        tokens = WORD_RE.findall(entry.text.lower())
        if entry.sentiment is not None and math.isfinite(entry.sentiment):
            # Client-supplied mood tag: clamped to the engine's scale. A
            # non-finite value (NaN poisons every average downstream) falls
            # back to scoring the text.
            sentiment = max(-1.0, min(1.0, entry.sentiment))
        else:
            sentiment = sentiment_score(tokens)
        per_entry.append((entry, tokens, extract_themes(tokens), sentiment))

    weekday_total: dict[int, int] = {}
    for entry, _, _, _ in per_entry:
        weekday_total[entry.entry_date.weekday()] = weekday_total.get(entry.entry_date.weekday(), 0) + 1

    day_buckets: dict[date, list[float]] = {}
    for entry, _, _, sentiment in per_entry:
        day_buckets.setdefault(entry.entry_date, []).append(sentiment)
    day_sentiments = sorted((day, sum(v) / len(v)) for day, v in day_buckets.items())

    # Within-person residuals: each entry's mood minus the user's own rolling
    # baseline for that day. All mood ASSOCIATIONS run on these; level claims
    # (the EWMA chart) keep raw values, because "lower than your usual" is a
    # statement about levels, not deviations.
    baselines = _personal_baselines(day_sentiments)
    day_residuals = {day: mood - baselines.get(day, mood) for day, mood in day_sentiments}
    residual_per_entry: list[tuple[JournalEntry, list[str], set[str], float]] = [
        (entry, tokens, themes, sentiment - baselines.get(entry.entry_date, sentiment))
        for entry, tokens, themes, sentiment in per_entry
    ]
    day_themes: dict[date, set[str]] = {}
    for entry, _, themes, _ in per_entry:
        day_themes.setdefault(entry.entry_date, set()).update(themes)

    signals: list[_Signal] = []
    if per_entry:
        signals.extend(_detect_themes(residual_per_entry, weekday_total, len(per_entry)))
        signals.extend(_detect_phrases(window))
        signals.extend(_detect_mood_shift(day_sentiments))
        signals.extend(_detect_links(day_themes, day_residuals, today))
        signals.extend(_detect_mood_dynamics(day_sentiments, day_residuals, today))
        signals.extend(_detect_topics(per_entry))

    # Multiple-testing correction across every statistical claim this run.
    tested = [s for s in signals if s.pvalue is not None]
    rejected = statsig.benjamini_hochberg([s.pvalue for s in tested], q=ALPHA)
    qualified = [s for s in signals if s.pvalue is None] + [
        s for s, keep in zip(tested, rejected) if keep
    ]
    # A theme may field several weekday candidates (all tested, all in the
    # family); only the best survivor becomes this run's pattern, and a
    # theme whose every candidate failed correction makes no claim.
    best_temporal: dict[str, _Signal] = {}
    for signal in qualified:
        if signal.kind != "temporal":
            continue
        current = best_temporal.get(signal.label)
        if current is None or signal.detail.get("day_count", 0) > current.detail.get("day_count", 0):
            best_temporal[signal.label] = signal
    if best_temporal:
        qualified = [s for s in qualified if s.kind != "temporal"]
        qualified.extend(best_temporal.values())
    qualified.sort(key=lambda s: s.pid)

    _merge_lifecycle(store, qualified, today)

    surfaced_records: list[tuple[StoredPattern, float]] = []
    for pid in sorted(store["patterns"]):
        record = store["patterns"][pid]
        if record.state not in SURFACED_STATES:
            continue
        evidence = [date.fromisoformat(d) for d in record.evidence_dates]
        surfaced_records.append((record, _decay_strength(evidence, today)))
    surfaced_records.sort(key=lambda item: (
        STATE_RANK.get(item[0].state, 3),
        -item[1],
        -item[0].occurrences,
        item[0].pid,
    ))
    surfaced_records = surfaced_records[:MAX_SURFACED]

    n_window_entries = len(per_entry)
    surfaced: list[Pattern] = []
    patterns_new = 0
    patterns_fading = 0
    for record, strength in surfaced_records:
        is_new = bool(
            record.first_qualified
            and (today - date.fromisoformat(record.first_qualified)).days <= NEW_PATTERN_WINDOW_DAYS
        )
        if is_new:
            patterns_new += 1
        if record.state == "fading":
            patterns_fading += 1
        surfaced.append(Pattern(
            kind=record.kind,
            label=record.label,
            occurrences=record.occurrences,
            confidence=round(strength, 3),
            detail={
                **record.detail,
                "pattern_state": record.state,
                "strength": round(strength, 3),
                "first_seen": record.first_seen,
                "last_seen": record.last_seen,
                "is_new": is_new,
                "sample_days": n_window_entries,
            },
        ))

    history = store["history"]
    surfaced_pids = [r.pid for r, _ in surfaced_records]
    if not history or history[-1][0] != _iso(today):
        history.append([_iso(today), surfaced_pids])
        del history[:-HISTORY_DAYS]
    else:
        history[-1] = [_iso(today), surfaced_pids]

    sentiments = [s for _, _, _, s in per_entry]
    stats = {
        "total_entries": len(per_entry),
        "active_days": len(day_buckets),
        "avg_sentiment": round(sum(sentiments) / len(sentiments), 3) if sentiments else 0.0,
        "first_date": _iso(window[0].entry_date) if window else None,
        "last_date": _iso(window[-1].entry_date) if window else None,
    }
    return BrainUpdate(
        new_state=store,
        surfaced=surfaced,
        stats=stats,
        patterns_new=patterns_new,
        patterns_fading=patterns_fading,
    )
