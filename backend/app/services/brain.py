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
  * **Lagged day-after links** (Konjarski et al. 2018, *Sleep Medicine
    Reviews* meta-analysis of daily-diary sleep→affect studies; Bolger et
    al. 1989 spillover): "the day after 'sleep' comes up, your entries
    read lower" — the literal pattern *linking* the product is named for.
    Welch's t + Cohen's d on residuals, gated like every statistical
    claim.
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
    presence. Presence claims clear two anti-boilerplate bars (distinct
    followers, and NOT covered by the run's own recurring-phrase clusters
    — a repeated sentence is a phrase card, not a topic). The audit's
    "topic blindness" finding, closed.
  * **Honest multiple testing**: every significance test that runs —
    weekday concentrations (every candidate weekday, not the argmax
    alone), mood ties, links, dynamics, shifts, rising topics — enters
    one Benjamini-Hochberg family for the run, computed BEFORE any
    effect-size gate is applied; the gates then filter the corrected
    survivors. Selecting on extremeness first and correcting only the
    survivors is selection-then-test and voids FDR control (measured:
    ~half of pure-noise corpora surfaced a false statistical card).
  * **Replication before surfacing**: statistical claims must re-qualify
    on >= 2 distinct recompute days before they earn a card, and the
    second qualification must bring INDEPENDENT evidence — consecutive
    recomputes share ~179 of 180 window days, so "qualified twice" on
    consecutive days is the same data scored twice (see
    STATISTICAL_KINDS). Direct measurements (a literally repeated
    sentence, a persistent topic presence) may surface at once.
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
import re
import unicodedata
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from . import crisis
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
EVIDENCE_FULL = 8.0  # decayed mentions that saturate strength
STRONG_EVIDENCE = 10  # occurrences that may surface on first qualification

# Statistical claim kinds vs direct-measurement kinds. A statistical claim
# ("work days read lower", "mood carries over more than usual") can fluke
# through the gates on pure noise — measured: ~half of pure-noise corpora
# surfaced at least one such card when a single strong qualification was
# enough. These kinds therefore surface only after re-qualifying on >= 2
# DISTINCT recompute days (the replication gate, enforced in
# _merge_lifecycle). Direct-measurement kinds (recurring_phrase, rumination,
# topic presence) REPORT what is literally in the text — a repeated sentence
# is there or it isn't, no null hypothesis to fluke past — so they keep
# first-qualification surfacing at STRONG_EVIDENCE. The asymmetry is
# deliberate: replication discipline applies to inference, not to counting.
STATISTICAL_KINDS = frozenset(
    {
        "temporal",
        "mood_correlation",
        "link",
        "inertia",
        "instability",
        "mood_shift",
        # 2026-09-20 audit H-9: the newer statistical kinds were missing —
        # they took the direct-measurement promotion path and surfaced on
        # their FIRST qualification (their sample floors are >=
        # STRONG_EVIDENCE by construction, so the direct paths were always
        # satisfied). That is exactly the single-run-fluke surfacing the
        # replication gate exists to stop (A/B-proven: gated `inertia`
        # stayed candidate while ungated `energy_inertia` surfaced on
        # identical machinery; `cadence` surfaced first-run).
        "cadence",
        "avoidance",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
        "sense_making",
        "activity_diversity",
    }
)

# The two flavors of statistical claim, replicated differently (the "2
# distinct recompute days" bar alone was measured at ~17% false-card rate
# on daily-cadence pure noise: consecutive recomputes share ~179/180 window
# days, so day N+1 is not an independent replication of day N).
#   * EVIDENCE_DATE_KINDS anchor on concrete days (theme days, outcome
#     days): the second qualification must add at least one NEW evidence
#     day the record did not already hold — the claim re-derived on data
#     that did not produce the first one.
#   * WINDOW_STAT_KINDS are computed on the sliding window itself (an
#     ~11-day EWMA memory re-qualifies one fluke for days running): the
#     two qualification days must be >= REPLICATION_MIN_SPREAD_DAYS apart,
#     so the window has genuinely moved between observations.
# Flavor assignments for the 2026-09-20 additions (audit H-9): the inertia
# family and energy_mood_coupling ride EWMA/window machinery → WINDOW_STAT;
# sense_making/activity_diversity/avoidance anchor on concrete high-density
# or silent days → EVIDENCE_DATE. "topic" appears in EVIDENCE_DATE_KINDS
# only for its RISING form (see _is_statistical_kind): a steady-presence
# topic is a direct measurement, but "taking up more space lately" is a
# p-value-tested inference the same gate must cover.
EVIDENCE_DATE_KINDS = frozenset(
    {
        "temporal",
        "mood_correlation",
        "link",
        "avoidance",
        "sense_making",
        "activity_diversity",
        "topic",
    }
)
WINDOW_STAT_KINDS = frozenset(
    {
        "inertia",
        "instability",
        "mood_shift",
        "cadence",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
    }
)
REPLICATION_MIN_SPREAD_DAYS = 2


def _is_statistical(kind: str, detail: dict[str, Any]) -> bool:
    """The replication gate's kind test: STATISTICAL_KINDS membership, plus
    the topic RISING trend (audit H-9) — a rising-trend claim carries a
    p-value and can fluke past it once, exactly like every other inference
    kind, while a steady-presence topic merely reports what is literally in
    the text and keeps direct-measurement surfacing."""
    if kind in STATISTICAL_KINDS:
        return True
    return kind == "topic" and detail.get("trend") == "rising"


# --- statistical gates -------------------------------------------------------
ALPHA = 0.05
TEMPORAL_MIN_N = 8
TEMPORAL_MIN_DAY_K = 4  # per-weekday floor before a weekday is tested at all
TEMPORAL_MIN_FRACTION = 0.35
# P3 (2026-09-21): the temporal card's optional time-of-day narrowing
# — at least this many tod-bearing entries on the weekday, with this
# dominant fraction, before "Sunday" may become "Sunday evening".
TEMPORAL_MIN_TOD_N = 3
TEMPORAL_MIN_TOD_FRACTION = 0.7
# A word in ~every entry is journaling boilerplate ("unique day", "ordinary
# notes"), not a life topic — presence claims are capped from above too.
TOPIC_PRESENCE_MAX_SHARE = 0.95
MOOD_MIN_PER_SIDE = 8
MOOD_MIN_DELTA = 0.2
MOOD_MIN_EFFECT = 0.5  # Cohen's d
MOOD_SD_FLOOR = 0.05  # lexicon mood always carries at least this measurement noise
LINK_MIN_PER_SIDE = 8  # lagged day-after links: transitions per side
LINK_MAX_GAP_DAYS = 2  # "next day" survives a one-day skip in journaling
PHRASE_MIN_OCCURRENCES = 3
PHRASE_MIN_SPAN_DAYS = 7
PHRASE_MIN_DISTINCT_DAYS = 3

# --- within-person baseline (Bolger & Laurenceau 2013) -------------------------
BASELINE_HALF_WINDOW = 7  # personal baseline = +/- this many days around a day
BASELINE_MIN_NEIGHBORS = 4  # neighbors required before the day itself is excluded

# --- mood dynamics (Kuppens 2010; Houben 2015) ---------------------------------
INERTIA_MIN_PAIRS = 10  # consecutive-day pairs per window to trust r1
INERTIA_RECENT_MIN = 0.45  # recent carryover correlation strong enough to mention
INERTIA_DELTA = 0.25  # ... and risen by this much vs the earlier window
INERTIA_RECENT_DAYS = 28
INSTABILITY_MIN_DAYS = 10
INSTABILITY_RECENT_DAYS = 28
INSTABILITY_SD_FLOOR = 0.12
INSTABILITY_RATIO = 1.6  # recent spread vs earlier spread

# --- rumination (Ehring & Watkins 2008; Al-Mosaiwi & Johnstone 2018) -----------
RUMINATION_NEGATIVITY_MAX = -0.30  # cluster mean sentiment at or below → a worry
RUMINATION_MIN_NEGATORS = 2  # ... or non-positive + negation-heavy phrasing

# --- mood trajectory (EWMA control chart, Smit/Schat/Ceulemans 2023) -----------
MOOD_SHIFT_MIN_DAYS = 21
MOOD_SHIFT_BASELINE_MIN = 10
MOOD_SHIFT_LAMBDA = 0.18  # inside the validated 0.05–0.25 band
MOOD_SHIFT_LIMIT = 2.7  # control-limit multiplier (standard ARL choice)
MOOD_SHIFT_TAIL = 5  # most recent EWMA points inspected
MOOD_SHIFT_RUN = 3  # beyond-limit points required in the tail
MOOD_SHIFT_MIN_SHIFT = 0.15
MOOD_SHIFT_SIGMA_FLOOR = 0.05

# Once a stored mood shift's evidence is this many days old, the EWMA
# baseline re-anchors PAST it (see _mood_reanchor_day): a stable,
# months-old improvement must not keep qualifying cards whose copy says
# "lately" — statistically true, conversationally false.
MOOD_SHIFT_REANCHOR_DAYS = 21

# --- lifecycle ---------------------------------------------------------------
GRACE_DAYS = 7  # unqualified days before active → fading
ARCHIVE_DAYS = 45  # unqualified days before fading → archived
DROP_DAYS = 90  # archived patterns are dropped after this
PROMOTE_AGE_DAYS = 7  # candidate → emerging by age without re-qualification
CONFIRM_AGE_DAYS = 21  # emerging → confirmed by age

# --- language gate (2026-09-17) ----------------------------------------------------
# The lexicons are English. Non-Latin journals already read as "honest
# nothing" (WORD_RE strips them); LATIN-script non-English is the dangerous
# case: German/French/Spanish function words ("nicht", "mais", "para") are
# not in TOPIC_STOPWORDS, pass topic eligibility, and can surface as
# garbage topic cards ("'nicht' is a steady presence in your writing"),
# while lexicon collisions ("Bad" German=bath, English=bad) score mood
# from noise. Gate: the share of window tokens the engine actually
# recognizes; below the floor, topic mining is suppressed, text-derived
# sentiment stops feeding the mood detectors (explicit client mood tags
# still count — they are the user's own report, never a translation
# guess), and rumination's English negativity classifier steps aside
# (recurring phrases still surface for the TOKENIZABLE scripts — the
# [a-z']+ tokenizer reads Latin-script text only; Cyrillic/Greek/etc.
# journals yield no sentence tokens, so phrase repetition itself steps
# aside for them too, audit M-10).
LANGUAGE_MIN_TOKENS = 50  # too little text to judge a language honestly
LANGUAGE_HIT_FLOOR = 0.10  # ~10% recognized = English with names/slang;
# Latin-script non-English prose lands ~2-5%

# --- store bounds --------------------------------------------------------------
HISTORY_DAYS = 90
EVIDENCE_DATES_CAP = 60
QUALIFICATION_DAYS_CAP = 60
MAX_STORED_PATTERNS = 200
MAX_SURFACED = 20
NEW_PATTERN_WINDOW_DAYS = 7
# Per-pattern mutes (2026-09-19): muted patterns surface with
# detail.muted=true (after the unmuted top-N, so they never displace live
# cards) and never feed question generation. The store cap bounds the
# payload; the surfaced cap bounds the client's muted section.
MUTED_STORED_CAP = 100
MUTED_SURFACED_CAP = 10

ACTIVE_STATES = ("candidate", "emerging", "confirmed")
SURFACED_STATES = ("emerging", "confirmed", "fading")
STATE_RANK = {"confirmed": 0, "emerging": 1, "fading": 2}

# --- lexicon (superset of v1: explicit variants + light stemming) ---------------
THEME_LEXICON: dict[str, tuple[str, ...]] = {
    "work": (
        "work",
        "job",
        "boss",
        "deadline",
        "meeting",
        "office",
        "project",
        "client",
        "interview",
        "presentation",
        "colleague",
        "shift",
        "overtime",
        "career",
        "manager",
        "commute",
        "workload",
        "email",
        "promotion",
        "layoff",
        "understaffed",
        "burnout",
    ),
    "sleep": (
        "sleep",
        "insomnia",
        "tired",
        "exhausted",
        "nightmare",
        "restless",
        "fatigue",
        "nap",
        "awake",
        "bed",
        "sleepy",
        "asleep",
        "wake",
        "bedtime",
        "dream",
        "sleepless",
    ),
    "social": (
        "friend",
        "party",
        "social",
        "lonely",
        "alone",
        "gathered",
        "hangout",
        "hang",
        "gather",
        "isolated",
        "isolation",
        "company",
        "meetup",
        "connected",
        "connection",
    ),
    "family": (
        "family",
        "mom",
        "dad",
        "mother",
        "father",
        "sister",
        "brother",
        "parents",
        "partner",
        "wife",
        "husband",
        "kids",
        "home",
        "son",
        "daughter",
        "grandma",
        "grandpa",
        "grandmother",
        "grandfather",
        "uncle",
        "aunt",
        "cousin",
        "marriage",
        "divorce",
        "baby",
        "toddler",
    ),
    "health": (
        "health",
        "gym",
        "exercise",
        "workout",
        "run",
        "sick",
        "ill",
        "doctor",
        "headache",
        "pain",
        "walk",
        "yoga",
        "stretch",
        "medicine",
        "meds",
        "migraine",
        "injury",
        "dentist",
        "therapy",
    ),
    "money": (
        "money",
        "bills",
        "rent",
        "debt",
        "salary",
        "budget",
        "expensive",
        "broke",
        "afford",
        "save",
        "loan",
        "credit",
        "paycheck",
        "tax",
        "overdraft",
        "insurance",
        "cheap",
    ),
    "study": (
        "school",
        "exam",
        "study",
        "class",
        "college",
        "university",
        "homework",
        "assignment",
        "test",
        "quiz",
        "lecture",
        "semester",
        "thesis",
        "dissertation",
        "revision",
        "teacher",
        "professor",
        "grade",
        "fail",
    ),
    "food": (
        "eat",
        "food",
        "meal",
        "cook",
        "appetite",
        "hungry",
        "breakfast",
        "lunch",
        "dinner",
        "snack",
        "coffee",
        "tea",
        "sugar",
        "junk",
        "takeaway",
        "restaurant",
    ),
    "weather": (
        "rain",
        "rainy",
        "cold",
        "grey",
        "gray",
        "sunny",
        "storm",
        "winter",
        "summer",
        "weather",
        "fog",
        "foggy",
        "heat",
        "humid",
        "wind",
        "windy",
        "snow",
        "snowy",
        "drizzle",
        "freezing",
        "cloud",
        "cloudy",
        "autumn",
    ),
}
THEME_WORDS: dict[str, str] = {
    word: theme for theme, words in THEME_LEXICON.items() for word in words
}

# Spanish theme set (2026-09-21 audit Phase 2 workstream 1, delivered by the
# independent verification follow-up): the same nine canonical themes with
# journal-common Spanish words so temporal/mood_correlation/link cards fire
# for Spanish corpora. Lookups are LANGUAGE-GATED (theme_for/extract_themes
# select the map by the detected language): a union would let English theme
# words misread Spanish text ("son las cinco" -> family "son"), and ES words
# never fire on English corpora. Spellings are PRE-FOLDED (no diacritics,
# n-tilde as "n") because tokenization folds before [a-z']+ matching
# (audit H-8) — "sueño" must be stored as "sueno" to ever match. Spanish
# plurals need no separate entries: word_forms' final-s strip already maps
# "trabajos" -> "trabajo". High-precision by design — ambiguous everyday
# words ("solo", "te", "noche") are deliberately absent; a missed synonym
# only costs sensitivity, a false member costs card honesty.
THEME_LEXICON_ES: dict[str, tuple[str, ...]] = {
    "work": (
        "trabajo",
        "trabajos",
        "empleo",
        "jefe",
        "jefa",
        "oficina",
        "reunion",
        "reuniones",
        "proyecto",
        "proyectos",
        "cliente",
        "clientes",
        "entrevista",
        "presentacion",
        "colega",
        "turno",
        "jornada",
        "gerente",
        "correo",
        "ascenso",
        "despido",
        "nomina",
        "curro",
        "sobrecarga",
    ),
    "sleep": (
        "sueno",
        "suenos",
        "dormir",
        "duermo",
        "dormi",
        "insomnio",
        "desvelo",
        "desvelado",
        "pesadilla",
        "pesadillas",
        "cama",
        "siesta",
        "descanso",
        "descansar",
        "despertar",
        "desperte",
        "cansancio",
        "cansado",
        "cansada",
        "agotado",
        "agotada",
        "fatiga",
    ),
    "social": (
        "amigo",
        "amiga",
        "amigos",
        "amigas",
        "fiesta",
        "fiestas",
        "social",
        "soledad",
        "aislado",
        "aislamiento",
        "compania",
        "companero",
        "conocer",
        "conocidos",
    ),
    "family": (
        "familia",
        "mama",
        "papa",
        "madre",
        "padre",
        "hermano",
        "hermana",
        "padres",
        "pareja",
        "esposa",
        "marido",
        "esposo",
        "hijo",
        "hija",
        "hijos",
        "hijas",
        "casa",
        "abuela",
        "abuelo",
        "tio",
        "tia",
        "primo",
        "prima",
        "boda",
        "divorcio",
        "bebe",
        "nino",
        "nina",
    ),
    "health": (
        "salud",
        "gimnasio",
        "ejercicio",
        "entrenamiento",
        "entrenar",
        "correr",
        "enfermo",
        "enferma",
        "enfermedad",
        "medico",
        "doctor",
        "doctora",
        "dolor",
        "dolores",
        "caminar",
        "paseo",
        "yoga",
        "medicina",
        "medicamento",
        "migrana",
        "lesion",
        "dentista",
        "terapia",
        "terapeuta",
        "gripe",
        "resfriado",
    ),
    "money": (
        "dinero",
        "factura",
        "facturas",
        "alquiler",
        "deuda",
        "deudas",
        "sueldo",
        "salario",
        "presupuesto",
        "caro",
        "caros",
        "carisimo",
        "carisima",
        "arruinado",
        "ahorro",
        "ahorros",
        "hipoteca",
        "prestamo",
        "banco",
        "gasto",
        "gastos",
        "impuesto",
        "impuestos",
        "bancarrota",
    ),
    "study": (
        "estudio",
        "estudios",
        "estudiar",
        "examen",
        "examenes",
        "clase",
        "clases",
        "universidad",
        "escuela",
        "colegio",
        "instituto",
        "deberes",
        "tarea",
        "tareas",
        "apuntes",
        "profesor",
        "profesora",
        "estudiante",
        "lectura",
        "leer",
        "aprender",
        "tesis",
        "master",
        "doctorado",
        "repaso",
        "repasar",
        "biblioteca",
    ),
    "food": (
        "comida",
        "comidas",
        "comer",
        "comi",
        "cena",
        "cenar",
        "desayuno",
        "almuerzo",
        "merienda",
        "hambre",
        "apetito",
        "antojo",
        "antojos",
        "cocinar",
        "receta",
        "recetas",
        "restaurante",
        "dieta",
        "azucar",
        "cafe",
        "postre",
        "postres",
        "dulce",
        "dulces",
        "chocolate",
        "pizza",
        "verduras",
        "fruta",
        "frutas",
        "carne",
        "pescado",
        "pan",
        "alcohol",
        "cerveza",
        "vino",
    ),
    "weather": (
        "lluvia",
        "llueve",
        "llovio",
        "soleado",
        "sol",
        "calor",
        "frio",
        "fria",
        "nieve",
        "nevar",
        "nevando",
        "viento",
        "ventoso",
        "tormenta",
        "tormentas",
        "humedo",
        "humedad",
        "nublado",
        "nube",
        "nubes",
        "niebla",
        "llovizna",
        "primavera",
        "verano",
        "otono",
        "invierno",
    ),
}
THEME_WORDS_ES: dict[str, str] = {
    word: theme for theme, words in THEME_LEXICON_ES.items() for word in words
}

# --- graded sentiment lexicon (VADER-inspired; Hutto & Gilbert 2014) ------------
# Valences in [-4, 4]; magnitudes follow the VADER convention (a "terrible"
# outweighs a "bad"). Curated for journal register; superset of the v2 word
# lists so historical corpora score consistently ("relaxed" kept from v2).
# Curation rule: a word whose DOMINANT journal sense is not sentiment is
# dropped, whatever its dictionary valence — a false valence costs trust.
# Removed on that rule: "kind" (+1.9 — the hedge "kind of <adj>" is far more
# common than the compliment and flipped hedged negatives positive), "fed"
# (-1.5 — "fed up" is rare next to "i fed the cat"), "present" (0.8 — gift /
# attendance / "presented" via -ed stemming outnumber the mindful sense).
# "miss" stays: in first-person journal text the longing sense dominates and
# the collision senses ("missed the bus") read mildly negative anyway.
# 2026-09-17: the graded lexicon is now CURATED-OVER-VADER. The VADER
# base (7,200+ words, MIT) ships in services/sentiment_lexicon.py; every
# value curated HERE wins word-for-word (the curation rules documented
# above stay authoritative), and the emoji map scores alongside WORD_RE.
from .sentiment_lexicon import EMOJI_VALENCES, VADER_BASE  # noqa: E402

# 2026-09-19: the first non-English lexicon. Spanish assets merge with
# ENGLISH WINS on collision (see SENTIMENT_LEXICON below): shared short
# words union in the grammatical sets, graded entries never silently
# override an English reading.
from .sentiment_lexicon_es import (  # noqa: E402
    ABSOLUTIST_WORDS_ES,
    BUT_WORDS_ES,
    INTENSIFIERS_ES,
    LANGUAGE_FUNCTION_WORDS_ES,
    NEGATORS_ES,
    SENSE_WORDS_ES,
    VADER_BASE_ES,
)

CURATED_SENTIMENT: dict[str, float] = {
    # positive — mild
    "okay": 0.9,
    "ok": 0.9,
    "alright": 0.9,
    "fine": 0.8,
    "decent": 1.1,
    "calm": 1.5,
    "quiet": 0.6,
    "settled": 1.2,
    "steady": 1.0,
    "neutral": 0.0,
    "pleasant": 1.9,
    "mild": 0.4,
    "gentle": 1.1,
    "easy": 1.0,
    "simple": 0.6,
    "comfortable": 1.6,
    "content": 1.9,
    "peaceful": 2.2,
    "relieved": 1.9,
    "rested": 1.8,
    "refreshed": 2.0,
    "grounded": 1.6,
    "balanced": 1.3,
    "accepted": 1.2,
    "safe": 1.6,
    "secure": 1.5,
    "warm": 1.4,
    "cozy": 1.8,
    "soft": 0.7,
    "lighter": 1.4,
    "bright": 1.5,
    "clear": 0.9,
    # positive — moderate
    "good": 1.9,
    "nice": 1.5,
    "better": 1.7,
    "improved": 1.6,
    "happy": 3.0,
    "glad": 2.2,
    "joy": 2.8,
    "joyful": 2.9,
    "cheerful": 2.4,
    "smiled": 2.3,
    "smile": 2.3,
    "laugh": 2.4,
    "laughed": 2.4,
    "fun": 2.3,
    "playful": 2.0,
    "enjoy": 2.1,
    "enjoyed": 2.2,
    "love": 3.2,
    "loved": 2.9,
    "liked": 1.8,
    "hope": 2.0,
    "hopeful": 2.3,
    "optimistic": 2.2,
    "excited": 2.8,
    "eager": 2.0,
    "curious": 1.5,
    "interested": 1.2,
    "engaged": 1.5,
    "motivated": 2.3,
    "productive": 1.9,
    "proud": 2.6,
    "accomplished": 2.3,
    "confident": 2.4,
    "capable": 1.9,
    "strong": 1.8,
    "energetic": 2.4,
    "active": 1.3,
    "alive": 1.9,
    "grateful": 2.8,
    "thankful": 2.8,
    "appreciate": 2.2,
    "blessed": 2.5,
    "lucky": 1.8,
    "amused": 1.8,
    "connected": 1.8,
    "supported": 2.0,
    "understood": 1.8,
    "heard": 1.4,
    "relaxed": 1.9,
    "helpful": 1.6,
    "generous": 1.8,
    "creative": 1.7,
    "progress": 1.5,
    "win": 1.9,
    "won": 1.9,
    # positive — strong
    "great": 3.1,
    "wonderful": 3.2,
    "amazing": 3.3,
    "awesome": 3.3,
    "fantastic": 3.4,
    "excellent": 3.1,
    "beautiful": 2.9,
    "delight": 2.8,
    "delighted": 2.9,
    "thrilled": 3.1,
    "ecstatic": 3.5,
    "bliss": 3.2,
    "perfect": 2.9,
    "incredible": 2.9,
    "phenomenal": 3.0,
    # negative — mild
    "bad": -1.9,
    "meh": -0.9,
    "off": -0.8,
    "down": -1.3,
    "low": -1.2,
    "flat": -0.8,
    "dull": -1.1,
    "bored": -1.2,
    "tired": -1.7,
    "sleepy": -1.0,
    "slow": -0.7,
    "heavy": -1.3,
    "grey": -0.6,
    "gray": -0.6,
    "bleak": -1.9,
    "gloomy": -1.8,
    "mehh": -1.0,
    "awkward": -1.3,
    "annoyed": -1.7,
    "irritated": -1.8,
    "frustrated": -2.0,
    "uneasy": -1.6,
    "tense": -1.7,
    "restless": -1.5,
    "unsettled": -1.6,
    "wary": -1.4,
    "skeptical": -1.0,
    "disappointed": -2.1,
    "underwhelmed": -1.4,
    "inconvenient": -1.2,
    "guilty": -2.1,
    "ashamed": -2.5,
    "embarrassed": -2.0,
    "regret": -2.0,
    "lonely": -2.4,
    "alone": -1.4,
    "isolated": -2.2,
    "disconnected": -1.8,
    "unhappy": -2.2,
    "dissatisfied": -1.8,
    "stuck": -2.0,
    "trapped": -2.4,
    "hollow": -2.0,
    "empty": -2.1,
    "numb": -2.3,
    "distant": -1.4,
    "withdrawn": -1.9,
    # negative — moderate
    "sad": -2.5,
    "downcast": -2.3,
    "sorrow": -2.6,
    "grief": -2.9,
    "grieving": -2.9,
    "hurt": -2.3,
    "aching": -2.0,
    "cry": -2.2,
    "cried": -2.4,
    "crying": -2.4,
    "tears": -2.2,
    "weep": -2.4,
    "miss": -1.5,
    "loss": -2.2,
    "anxious": -2.7,
    "anxiety": -2.6,
    "nervous": -2.0,
    "worry": -2.1,
    "worried": -2.3,
    "stress": -2.0,
    "stressed": -2.4,
    "pressured": -2.1,
    "overloaded": -2.3,
    "overwhelmed": -2.9,
    "swamped": -2.1,
    "angry": -2.7,
    "anger": -2.6,
    "mad": -2.2,
    "upset": -2.3,
    "bitter": -2.1,
    "resentment": -2.3,
    "resentful": -2.2,
    "hate": -2.8,
    "dislike": -1.7,
    "afraid": -2.5,
    "scared": -2.5,
    "fear": -2.5,
    "fearful": -2.4,
    "dread": -2.6,
    "panic": -3.0,
    "panicky": -2.9,
    "hopeless": -3.3,
    "helpless": -3.0,
    "worthless": -3.4,
    "useless": -3.1,
    "failure": -2.9,
    "failed": -2.6,
    "failing": -2.7,
    "miserable": -2.9,
    "awful": -3.0,
    "terrible": -3.1,
    "horrible": -3.1,
    "worse": -2.3,
    "worst": -3.0,
    "exhausted": -2.8,
    "drained": -2.7,
    "burnt": -2.4,
    "burnout": -2.6,
    "fatigue": -2.2,
    "insomnia": -2.6,
    "nightmare": -2.8,
    "draining": -2.0,
    "hazy": -1.1,
    "foggy": -1.2,
    "scattered": -1.5,
    "distracted": -1.4,
    "overthinking": -2.1,
    "spiraling": -2.7,
    "ruminate": -1.9,
    "ruminating": -2.0,
    "migraine": -2.2,
    "headache": -1.9,
    "sick": -1.9,
    "ill": -1.9,
    "pain": -2.1,
    "unwell": -2.0,
    # negative — strong
    "depressed": -3.4,
    "depression": -3.2,
    "despair": -3.4,
    "devastated": -3.4,
    "heartbroken": -3.2,
    "anguish": -3.3,
    "tormented": -3.2,
    "unbearable": -3.3,
    "intolerable": -3.2,
    "disgusted": -2.6,
    "disgust": -2.5,
    "contempt": -2.4,
    "furious": -3.1,
    "rage": -3.0,
    "livid": -3.0,
    "terrified": -3.1,
    "petrified": -3.0,
    "suicidal": -3.8,
    "unreal": -1.6,
    "impossible": -2.1,
}

# The active graded lexicon: VADER breadth + curated authority.
# The ENGLISH-only lexicon: the language-DETECTION set is built from it
# (not the merged lookup), so Spanish prose cannot inflate English hits.
SENTIMENT_LEXICON_EN: dict[str, float] = {**VADER_BASE, **CURATED_SENTIMENT}
# The runtime lookup: English wins every collision by merge order.
SENTIMENT_LEXICON: dict[str, float] = {**VADER_BASE_ES, **SENTIMENT_LEXICON_EN}

# Intensifiers/downtoners (VADER booster conventions, multiplicative).
# "hardly"/"barely" are NOT downtoners: VADER treats them as negations
# ("hardly good" ≈ "not good"). Listing them here AND in NEGATORS applied
# both rules at once (0.7x booster times the -0.74 flip) — negation-only.
INTENSIFIERS: dict[str, float] = {
    "very": 1.4,
    "so": 1.2,
    "really": 1.25,
    "extremely": 1.6,
    "incredibly": 1.6,
    "absolutely": 1.6,
    "completely": 1.55,
    "totally": 1.5,
    "utterly": 1.6,
    "deeply": 1.45,
    "truly": 1.3,
    "quite": 1.15,
    "pretty": 1.15,
    "super": 1.4,
    "highly": 1.4,
    "insanely": 1.5,
    "unbelievably": 1.55,
    "slightly": 0.75,
    "somewhat": 0.8,
    "mildly": 0.75,
    "almost": 0.85,
    "little": 0.9,
}
NEGATION_SCALAR = -0.74  # VADER's damped flip: "not good" < "bad"
BUT_WORDS_EN = frozenset({"but", "however", "although", "though", "yet"})
BUT_WORDS = BUT_WORDS_EN | BUT_WORDS_ES
INTENSIFIERS = {**INTENSIFIERS_ES, **INTENSIFIERS}

SENTIMENT_SCALE = 4.0  # max lexicon magnitude maps onto [-1, 1]

NEGATORS = frozenset(
    {
        "not",
        "no",
        "never",
        "nothing",
        "none",
        "nobody",
        "nowhere",
        "cannot",
        "can't",
        "won't",
        "don't",
        "doesn't",
        "didn't",
        "isn't",
        "aren't",
        "wasn't",
        "weren't",
        "haven't",
        "hasn't",
        "hadn't",
        "wouldn't",
        "couldn't",
        "shouldn't",
        "hardly",
        "barely",
        "rarely",
    }
)
NEGATORS_EN = NEGATORS
NEGATORS = NEGATORS_EN | NEGATORS_ES

# Absolutist language (Al-Mosaiwi & Johnstone 2018): elevated in
# anxiety/depression and suicidal-ideation text; reported to the user as a
# self-reflection observation only — never as a risk score.
ABSOLUTIST_WORDS = frozenset(
    {
        "always",
        "never",
        "nothing",
        "everything",
        "everyone",
        "nobody",
        "none",
        "every",
        "must",
        "completely",
        "totally",
        "absolutely",
        "entirely",
        "constantly",
        "forever",
        "unbearable",
        "impossible",
        "unreal",
        "wholly",
        "undeniably",
    }
)
ABSOLUTIST_WORDS_EN = ABSOLUTIST_WORDS
ABSOLUTIST_WORDS = ABSOLUTIST_WORDS_EN | ABSOLUTIST_WORDS_ES

# --- emergent topic discovery (beyond the fixed theme lexicon) --------------------
# The lexicon covers nine universal themes; everything else a user's life
# revolves around — a new relationship, a startup, grief, guitar — must be
# DISCOVERED. Deterministic n-gram mining: content n-grams (never function
# words, never words the lexicon/sentiment layers already own) that recur
# across enough distinct days, surfaced either because they are RISING
# (share of entries vs the user's own earlier-window base rate, exact
# binomial into the BH family) or a PERSISTENT presence (a direct
# measurement — share of entries — so no significance test applies).
# --- structured channels (entry payload v2, 2026-09-17) ------------------------
# Sleep quality is the best-validated lagged daily-diary channel (Konjarski
# 2018 meta-analysis: sleep QUALITY → next-day affect). The user's 1-5
# rating becomes a within-person binary: nights rated strictly below the
# user's OWN median are "poor sleep" days (a 3 means something different
# for someone who averages 4 than for someone averaging 2 — never pooled).
# The synthetic theme rides the SAME detector machinery as every lexicon
# theme: weekday concentration, same-day mood correlation, and the day-after
# link, all gated and multiple-comparison-corrected identically. Activity
# tags merge into the theme set directly — a tagged day is by definition a
# themed day, and "your mood on days you tag 'family'" is exactly the
# Daylio-style question asked with real statistics instead of a bar chart.
SLEEP_CHANNEL_THEME = "poor sleep"
SLEEP_MIN_RATED_NIGHTS = 10  # distinct rated nights before the split is claimable

# --- cadence signals (2026-09-17) ------------------------------------------------
# The server already holds the writing CALENDAR (metadata, no decryption
# beyond what recompute already does): two honest signals live there.
# AVOIDANCE: theme-days followed by SILENCE (no entry the next calendar
# day, with later writing proving the silence was a choice, not an end) —
# "the day after conflict comes up, you go quiet". Exact binomial against
# the user's own base skip rate, one-sided (more silence than usual), in
# the BH family like every other claim.
AVOIDANCE_MIN_OBSERVED = 10  # theme-days with an observable next-day outcome
AVOIDANCE_MIN_SKIPS = 5
AVOIDANCE_MIN_LIFT = 0.20  # skips share must exceed base rate by this
# RHYTHM: the regularity of the journaling rhythm itself (gap spread,
# recent vs the user's earlier norm) — the same comparative shape as the
# instability detector, applied to gaps between writing days.
CADENCE_MIN_DAYS = 12  # journaling days per window half

# --- person anchoring (2026-09-17) ------------------------------------------------
# "My mood dips after seeing my mom, not my dad" is the most-requested
# real-world insight. Deterministic extraction: mid-sentence CAPITALIZED
# tokens (proper names survive the lowercase tokenizer's fold only by
# re-reading the raw text) and "my <relation>" bigrams, recurring on
# enough distinct days. Strict bars — a false person theme costs trust —
# and the candidates ride the SAME detector machinery as every theme
# (weekday concentration, mood ties, day-after links), so no new claims
# are possible without the usual gating and correction.
PERSON_MIN_DISTINCT_DAYS = 6
PERSON_MIN_TOTAL_MENTIONS = 8
# Hard ceiling on how many person candidates ride the theme machinery per
# run (2026-09-19 DoS remediation). The corpus budgets bound chars and
# entries but never distinct-name cardinality: a 30-day-old account can
# pack tens of thousands of qualifying names into the 2M-char analysis
# budget, and the per-name corpus rescan made ONE recompute cost minutes
# of CPU on the single-process deployment. Real journals name a handful
# of people; the most-established names win, selected deterministically
# (mentions, then distinct days, then name) — the same contract as
# TOPIC_MAX_CANDIDATES.
PERSON_MAX_CANDIDATES = 24

TOPIC_MIN_ENTRIES = 6  # entries mentioning it before it can be tested
TOPIC_MIN_DISTINCT_DAYS = 4
TOPIC_RISING_MIN_RECENT = 5  # recent-half mentions for a rising claim
TOPIC_RISING_MIN_SHARE = 0.18  # share of recent entries it must reach
TOPIC_RISING_MIN_GAIN = 0.12  # ... above the earlier-half base rate
TOPIC_MIN_PER_HALF = 10  # entries per half before a trend is claimable
TOPIC_PRESENCE_MIN_ENTRIES = 20
TOPIC_PRESENCE_MIN_SHARE = 0.30
TOPIC_PRESENCE_MIN_DAYS = 10
# A presence claim must recur in varied context: the token FOLLOWING each
# occurrence differs across occurrences. Templated boilerplate ("another
# ordinary journal scribble…") has one follower per slot and is filtered;
# a real topic ("guitar") attaches to whatever the day contained.
TOPIC_PRESENCE_MIN_CONTEXTS = 4
# Second anti-boilerplate bar (small-vocab corpora defeat the follower bar:
# a 40-word vocabulary hands every content word enough distinct followers).
# When the run's OWN recurring-phrase clusters already cover this share of
# a candidate's evidence days, the occurrences are a repeated SENTENCE —
# the phrase detector surfaces that sentence as recurring_phrase, and a
# presence card on top would be the same measurement wearing a second hat.
TOPIC_PRESENCE_CLUSTER_COVER = 0.8
TOPIC_MAX_CANDIDATES = 12  # tested per run (by document frequency)
# Same cardinality bound for the client-controlled tag vocabulary (2026-09-19
# DoS remediation): tags are capped per entry (<=8) but unbounded across a
# corpus, and every distinct tag rides the same O(entries) theme machinery
# a hostile corpus can drive to tens of thousands. Top tags by (distinct
# days, mentions, tag) — deterministic; origin marking still reports
# source="tag" for any survivor.
TAG_MAX_THEMES = 24
TOPIC_MAX_SIGNALS = 6  # surfaced per run, rising first

# Function words, auxiliaries, time/filler boilerplate and mood carriers —
# none of them can be a life topic. Deliberately broad: a false negative
# (a real topic skipped) costs little, a false positive costs trust.
TOPIC_STOPWORDS = frozenset(
    {
        # pronouns / determiners / auxiliaries / prepositions / conjunctions
        "about",
        "after",
        "again",
        "all",
        "also",
        "although",
        "always",
        "another",
        "any",
        "anyone",
        "anything",
        "are",
        "around",
        "back",
        "because",
        "been",
        "before",
        "being",
        "both",
        "but",
        "came",
        "can",
        "cannot",
        "come",
        "could",
        "did",
        "didn",
        "does",
        "doesn",
        "doing",
        "done",
        "down",
        "else",
        "even",
        "every",
        "everyone",
        "everything",
        "few",
        "for",
        "from",
        "get",
        "gets",
        "getting",
        "give",
        "gives",
        "go",
        "goes",
        "going",
        "gone",
        "got",
        "had",
        "has",
        "hasn",
        "have",
        "haven",
        "having",
        "her",
        "here",
        "hers",
        "herself",
        "him",
        "himself",
        "his",
        "how",
        "into",
        "isn",
        "itself",
        "just",
        "keep",
        "keeps",
        "kept",
        "know",
        "known",
        "knows",
        "least",
        "less",
        "let",
        "like",
        "made",
        "make",
        "makes",
        "making",
        "many",
        "more",
        "most",
        "much",
        "must",
        "myself",
        "never",
        "next",
        "none",
        "nothing",
        "now",
        "off",
        "once",
        "one",
        "only",
        "other",
        "others",
        "our",
        "ours",
        "ourselves",
        "out",
        "over",
        "own",
        "put",
        "really",
        "said",
        "same",
        "say",
        "saying",
        "says",
        "see",
        "seem",
        "seemed",
        "seems",
        "seen",
        "several",
        "shall",
        "she",
        "should",
        "since",
        "some",
        "someone",
        "something",
        "still",
        "such",
        "take",
        "takes",
        "taking",
        "tell",
        "tells",
        "than",
        "that",
        "their",
        "theirs",
        "them",
        "themselves",
        "then",
        "there",
        "these",
        "they",
        "thing",
        "things",
        "think",
        "thinking",
        "this",
        "those",
        "though",
        "through",
        "thus",
        "too",
        "took",
        "under",
        "until",
        "upon",
        "very",
        "want",
        "wanted",
        "wants",
        "was",
        "wasn",
        "way",
        "well",
        "went",
        "were",
        "weren",
        "what",
        "when",
        "where",
        "whether",
        "which",
        "while",
        "who",
        "whom",
        "whose",
        "why",
        "will",
        "with",
        "within",
        "without",
        "won",
        "would",
        "yeah",
        "yes",
        "yet",
        "you",
        "your",
        "yours",
        "yourself",
        # time / journal boilerplate
        "today",
        "yesterday",
        "tomorrow",
        "morning",
        "afternoon",
        "evening",
        "night",
        "day",
        "days",
        "week",
        "weeks",
        "month",
        "months",
        "year",
        "years",
        "hour",
        "hours",
        "minute",
        "minutes",
        "time",
        "times",
        "moment",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
        "january",
        "february",
        "march",
        "april",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
        "weekend",
        "tonight",
        "lately",
        "recently",
        "maybe",
        "kind",
        "sort",
        "stuff",
        "little",
        "bit",
        "pretty",
        "quite",
        "somewhat",
        "actually",
        "maybe",
        # mood/feeling carriers (the sentiment layer owns them)
        "feel",
        "feels",
        "felt",
        "feeling",
        "feelings",
        "emotion",
        "emotions",
        "mood",
        "mind",
        "head",
        "heart",
        "soul",
        "life",
        "living",
        "live",
        "love",
        "hate",
        "okay",
        "ok",
        "fine",
        "good",
        "bad",
        "better",
        "worse",
        "best",
        "worst",
        "great",
        "nice",
        "hard",
        "easy",
        "weird",
        "strange",
        # dropped from the sentiment lexicon for context-dependence; still never
        # a life topic ("stayed present", "a present for mom")
        "present",
        # high-frequency journal verbs/nouns that are never life topics
        "people",
        "person",
        "told",
        "ask",
        "asked",
        "asking",
        "call",
        "called",
        "calling",
        "talk",
        "talked",
        "talking",
        "spend",
        "spent",
        "spending",
        "watch",
        "watched",
        "watching",
        "happen",
        "happened",
        "happening",
        "remember",
        "remembered",
        "start",
        "started",
        "starting",
        "stop",
        "stopped",
        "stopping",
        "thought",
        "thoughts",
        "wonder",
        "wondered",
        "wondering",
        "wait",
        "waited",
        "waiting",
        "try",
        "tried",
        "trying",
        "turn",
        "turned",
        "turning",
        "find",
        "found",
        "finding",
        "lot",
        "lots",
        "whole",
        "part",
        "kinda",
        "sorta",
        "someone's",
        "everyone's",
    }
)

IRREGULAR_FORMS: dict[str, str] = {
    "slept": "sleep",
    "overslept": "sleep",
    "ate": "eat",
    "overate": "eat",
    "ran": "run",
    "cried": "cry",
    "woke": "wake",
    "awoke": "wake",
    "met": "meet",
    "paid": "pay",
    "said": "say",
    "felt": "feel",
    "grieved": "grieve",
    "missed": "miss",
    "loathed": "loathe",
}

BOOSTER_SCOPE = 3  # tokens before a sentiment word that may boost or negate it


# The high-frequency English function-word core. TOPIC_STOPWORDS
# deliberately omits the shortest words (its eligibility rule already
# filters len < 4), so the language gate carries its own frequency list —
# these are the words that make English prose READ as English (~40-50% of
# tokens in any English sentence) regardless of content.
_LANGUAGE_FUNCTION_WORDS: frozenset[str] = frozenset(
    {
        "a",
        "am",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "been",
        "being",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "doing",
        "for",
        "from",
        "had",
        "has",
        "have",
        "he",
        "her",
        "here",
        "hers",
        "him",
        "his",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "me",
        "much",
        "must",
        "my",
        "no",
        "not",
        "of",
        "on",
        "or",
        "our",
        "out",
        "over",
        "she",
        "so",
        "some",
        "such",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "to",
        "up",
        "us",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
    }
)

# Every token the engine has an opinion about (function words, sentiment,
# themes, negators, absolutists, irregulars). The language gate asks: of
# the window's tokens, what share are these? English prose runs ~35-55%
# (function-word density); Latin-script non-English prose ~2-8% even with
# the handful of shared short words ("in", "a", "so").
_KNOWN_TOKENS: frozenset[str] = (
    frozenset(TOPIC_STOPWORDS)
    | _LANGUAGE_FUNCTION_WORDS
    | frozenset(SENTIMENT_LEXICON_EN)
    | frozenset(NEGATORS_EN)
    | frozenset(ABSOLUTIST_WORDS_EN)
    | frozenset(IRREGULAR_FORMS)
    | {word for words in THEME_LEXICON.values() for word in words}
)
# The Spanish twin (2026-09-19): function words + the ES lexicon's own
# grammatical sets. Detection compares the two shares — Spanish prose
# lands ~35-55% here and ~2-8% on the English side, and vice versa.
_KNOWN_TOKENS_ES: frozenset[str] = (
    LANGUAGE_FUNCTION_WORDS_ES
    | frozenset(VADER_BASE_ES)
    | frozenset(NEGATORS_ES)
    | frozenset(ABSOLUTIST_WORDS_ES)
    | frozenset(SENSE_WORDS_ES)
)

# --- NLP primitives -------------------------------------------------------------

# Per-character fold cache for _fold_sentiment_text: journals repeat the
# same accented characters thousands of times, and NFKD per call would
# otherwise be the recompute's hottest loop after the regex itself.
# 2026-09-21 audit D-8: single-character KEYS kept growth slow in
# practice, but nothing ENFORCED it — a process fed adversarial Unicode
# grew the map for its lifetime. Hard cap + clear: the working set of any
# real journal corpus is a few dozen characters, 4096 distinct codepoints
# is two orders of magnitude beyond that, and the rare clear is one cheap
# pass that cannot change behavior (the cache is a pure memo).
_FOLD_CACHE: dict[str, str] = {}
_FOLD_CACHE_LIMIT = 4096


def _fold_sentiment_text(text: str) -> str:
    """Fold Latin diacritics to base letters and U+2019 to ASCII ' BEFORE
    [a-z']+ tokenization (2026-09-20 audit H-8).

    Without the fold the tokenizer mangles every accented word
    ("depresión" -> "depresi" + "n"), scoring accented Spanish 0.0 while
    an unaccented typo of the same word scored normally — 70 of the ES
    lexicon's keys were structurally unreachable. And iOS Smart
    Punctuation substitutes U+2019 for ', defeating every contraction
    negator ("don’t feel good" read POSITIVE). Both spellings of every ES
    key live in the lexicon, so folding cannot drift lookup values.

    Same Latin-only rule as the crisis engine's _fold_latin_marks: only a
    decomposable char whose BASE is Latin (below U+0250) with pure
    combining marks reduces, so Devanagari/Arabic vowel marks survive.
    MUST stay behavior-identical to mobile's foldSentimentText (the
    brain-vector fixtures pin both engines).
    """
    if text.isascii():
        return text  # fast path: pure-ASCII English needs no folding
    text = text.replace("\u2019", "'")
    # Compose FIRST: a decomposed (NFD) accent is a BARE combining mark,
    # which per-char folding cannot see — "depresió n" (NFD) must fold
    # exactly like the precomposed "depresión" (the crisis engine's
    # pipeline composes for the same reason).
    text = unicodedata.normalize("NFKC", text)
    out: list[str] = []
    for ch in text:
        folded = _FOLD_CACHE.get(ch)
        if folded is None:
            decomposed = unicodedata.normalize("NFKD", ch)
            base = decomposed[0]
            if (
                len(decomposed) > 1
                and ord(base) < 0x0250
                and all("\u0300" <= c <= "\u036f" for c in decomposed[1:])
            ):
                folded = base
            else:
                folded = ch
            if len(_FOLD_CACHE) >= _FOLD_CACHE_LIMIT:
                _FOLD_CACHE.clear()
            _FOLD_CACHE[ch] = folded
        out.append(folded)
    return "".join(out)


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
    deduplicated: list[str] = []
    for form in forms:
        if form not in seen:
            seen.add(form)
            deduplicated.append(form)
    return deduplicated


def theme_for(token: str, language: str = "en") -> str | None:
    """Theme of a token under the corpus language's lexicon.

    Language-gated (2026-09-21 audit Phase 2, ES theme set): "es" corpora
    read the Spanish map only — a union would let English theme words
    misread Spanish text ("son las cinco" -> family "son") — and English
    corpora are untouched. "other" keeps the historical English-map
    behavior (themes were never language-gated before and detector output
    for non-en/es corpora must not change).
    """
    lexicon = THEME_WORDS_ES if language == "es" else THEME_WORDS
    for form in word_forms(token):
        theme = lexicon.get(form)
        if theme is not None:
            return theme
    return None


def _word_valence(token: str) -> float:
    # Emoji are their own tokens (extracted alongside WORD_RE); they have
    # no word forms and live in their own graded map.
    emoji = EMOJI_VALENCES.get(token)
    if emoji is not None:
        return emoji
    for form in word_forms(token):
        valence = SENTIMENT_LEXICON.get(form)
        if valence is not None:
            return valence
    return 0.0


def _valence_walk(tokens: list[str]) -> list[float]:
    """The per-word graded valences of the sentiment walk (deterministic).

    This is the exact accumulation ``sentiment_score`` nets into its
    compound; extracted so the PA/NA components reader can sum the same
    numbers by sign. Behavior must stay byte-identical to the pre-2026-09-19
    inline loop — sentiment outputs are pinned by vectors and regression
    suites.
    """
    sentiments: list[float] = []
    # "but" re-weighting: find the LAST contrastive; damp before, boost after.
    split = max((i for i, t in enumerate(tokens) if t in BUT_WORDS), default=-1)
    segments: list[tuple[list[str], float]] = []
    if split >= 0:
        segments = [
            (tokens[:split], 0.5),
            (tokens[split + 1 :], 1.5),
        ]
    else:
        segments = [(tokens, 1.0)]

    for seg, seg_weight in segments:
        for i, token in enumerate(seg):
            valence = _word_valence(token)
            if valence == 0.0:
                continue
            window = seg[max(0, i - BOOSTER_SCOPE) : i]
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
    return sentiments


def sentiment_score(tokens: list[str]) -> float:
    """Graded lexicon sentiment in [-1, 1] (VADER-style, deterministic).

    Intensifiers scale the next sentiment word; negation flips it with
    damping ("not good" is mildly negative, not catastrophic — the
    VADER x-0.74 scalar); "but" re-weights the sentence so the clause
    after the contrast carries the meaning.
    """
    sentiments = _valence_walk(tokens)
    if not sentiments:
        return 0.0
    total = sum(sentiments)
    return max(-1.0, min(1.0, total / SENTIMENT_SCALE))


def sentiment_components(tokens: list[str]) -> tuple[float, float]:
    """(positive, negative) affect magnitudes, each in [0, 1].

    Same deterministic walk as sentiment_score, summed by SIGN instead of
    netted. Positive and negative affect are separable constructs, not two
    ends of one scale (Emmons & Diener 1985; differential dynamics: Abitante
    et al. 2024) — the PA/NA inertia detectors need each stream. Computed
    from TEXT-SCORED entries only: an explicit mood check-in is a single
    valence judgment and cannot be honestly split.
    """
    sentiments = _valence_walk(tokens)
    if not sentiments:
        return (0.0, 0.0)
    positive = sum(v for v in sentiments if v > 0) / SENTIMENT_SCALE
    negative = -sum(v for v in sentiments if v < 0) / SENTIMENT_SCALE
    return (max(0.0, min(1.0, positive)), max(0.0, min(1.0, negative)))


def absolutist_density(tokens: list[str]) -> float:
    """Absolutist words per 100 tokens (Al-Mosaiwi & Johnstone 2018)."""
    if not tokens:
        return 0.0
    hits = sum(1 for t in tokens if t in ABSOLUTIST_WORDS)
    return round(100.0 * hits / len(tokens), 2)


def extract_themes(tokens: list[str], language: str = "en") -> set[str]:
    return {
        theme
        for theme in (theme_for(t, language) for t in tokens)
        if theme is not None
    }


def sentences_of(text: str) -> list[str]:
    """Normalized sentences of at least MIN_SENTENCE_TOKENS tokens."""
    out: list[str] = []
    for raw in SENTENCE_RE.findall(text):
        # Folded before tokenization (audit H-8): accented words must
        # survive as whole tokens, and iOS U+2019 must not split "don't".
        tokens = WORD_RE.findall(_fold_sentiment_text(raw.lower()))
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
                moods[other] for other in days if abs((other - day).days) <= BASELINE_HALF_WINDOW
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


def _daily_lag1_autocorr(day_values: dict[date, float]) -> float | None:
    """Lag-1 autocorrelation over CONSECUTIVE calendar days only.

    The deflation heuristic behind the link/mood tests' effective sample
    size. Unlike _lag1_autocorr (positional, EWMA-tuned), only true
    next-day pairs count — a 5-day gap is not lag-1 dependence. An
    approximation either way: one shared nuisance estimate for every
    theme's test, computed once per run.
    """
    days = sorted(day_values)
    pairs = [
        (day_values[d1], day_values[d2]) for d1, d2 in zip(days, days[1:]) if (d2 - d1).days == 1
    ]
    if len(pairs) < 8:
        return None
    return _pearson([a for a, _ in pairs], [b for _, b in pairs])


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
            "pid": self.pid,
            "kind": self.kind,
            "label": self.label,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_qualified": self.first_qualified,
            "last_qualified": self.last_qualified,
            "occurrences": self.occurrences,
            "state": self.state,
            "qualification_days": self.qualification_days,
            "evidence_dates": self.evidence_dates,
            "feedback": self.feedback,
            "detail": self.detail,
        }


def fresh_state() -> dict:
    return {"v": STATE_VERSION, "patterns": {}, "history": [], "muted": {}}


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
    qualification_days = (
        sorted({d for d in raw.get("qualification_days", []) if _parse_iso(d)})
        if isinstance(raw.get("qualification_days"), list)
        else []
    )
    evidence_dates = (
        sorted({d for d in raw.get("evidence_dates", []) if _parse_iso(d)})
        if isinstance(raw.get("evidence_dates"), list)
        else []
    )
    detail_raw = raw.get("detail")
    feedback_raw = raw.get("feedback")
    detail: dict[Any, Any] = dict(detail_raw) if isinstance(detail_raw, dict) else {}
    feedback: dict[Any, Any] = dict(feedback_raw) if isinstance(feedback_raw, dict) else {}
    state = raw.get("state")
    if not isinstance(state, str) or state not in SURFACED_STATES + ("candidate", "archived"):
        state = "candidate"
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
        state=state,
        qualification_days=qualification_days[-QUALIFICATION_DAYS_CAP:],
        evidence_dates=evidence_dates[-EVIDENCE_DATES_CAP:],
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
    history_raw = parsed.get("history")
    history: list[Any] = history_raw if isinstance(history_raw, list) else []
    clean_history = [
        h
        for h in history
        if isinstance(h, list) and len(h) == 2 and isinstance(h[0], str) and isinstance(h[1], list)
    ][:HISTORY_DAYS]
    # Per-pattern mutes (2026-09-19): hostile-shape rules like everywhere —
    # a corrupt entry is dropped, never a crash. Only well-formed pids with
    # a truthy flag survive; the cap bounds the store's size.
    muted_raw = parsed.get("muted")
    muted: dict[str, bool] = {}
    if isinstance(muted_raw, dict):
        for pid, flag in list(muted_raw.items())[:MUTED_STORED_CAP]:
            if isinstance(pid, str) and 1 <= len(pid) <= 128 and flag is True:
                muted[pid] = True
    return {"v": STATE_VERSION, "patterns": patterns, "history": clean_history, "muted": muted}


def dump_state(state: dict) -> bytes:
    """Byte-stable serialization (sort_keys) so identical brains dump identically.

    Pattern records may arrive as plain dicts — direct callers holding
    JSON-shaped state (audit L-16). They are re-validated through
    _stored_from_dict instead of crashing on the StoredPattern attribute
    seam, degrading to amnesia for records that fail validation, exactly
    like load_state; the docstring's "whatever the caller held is
    re-validated" promise now holds on both legs of the roundtrip."""
    patterns: dict[str, StoredPattern] = {}
    for pid, rec in state.get("patterns", {}).items():
        if isinstance(rec, StoredPattern):
            patterns[pid] = rec
            continue
        if isinstance(pid, str):
            normalized = _stored_from_dict(rec, pid)
            if normalized is not None:
                patterns[pid] = normalized
    payload = {
        "v": state.get("v", STATE_VERSION),
        "patterns": {pid: rec.to_dict() for pid, rec in patterns.items()},
        "history": state.get("history") or [],
        # Per-pattern mutes (2026-09-19): a patient-side presentation
        # preference. Must survive the update() copy-on-entry roundtrip
        # (dump_state → load_state) or every recompute would forget it.
        "muted": state.get("muted") or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --- detectors ----------------------------------------------------------------------


@dataclass
class _Signal:
    """One detector's claim this run.

    ``pvalue`` is set whenever a significance test RAN — including for
    candidates whose effect-size gates fail. Selection-then-test (running
    BH only over gate survivors) invalidates FDR control: the gates select
    FOR extremeness, so the family must count every test, and the gates
    apply to the corrected survivors (``gate_ok``). ``fallback`` carries
    the direct-measurement variant of a topic signal (a persistent
    presence) for when its tested rising claim does not survive.
    """

    pid: str
    kind: str
    label: str
    occurrences: int
    pvalue: float | None  # None = qualifies on its own (non-statistical family)
    detail: dict
    evidence_days: list[date]
    gate_ok: bool = True
    fallback: _Signal | None = None


def _decay_strength(evidence: list[date], today: date) -> float:
    """Decayed evidence density: mentions with a 45-day half-life, saturating at 1."""
    # Each day's weight is capped at 1.0: a future-dated evidence day (which
    # entry-date validation should already prevent) must not push the
    # exponent positive — 2.0 ** +7900 is an OverflowError that would escape
    # as a 500 on every future recompute. Past days keep exact half-life.
    weight = sum(2.0 ** min(0.0, -((today - day).days) / HALF_LIFE_DAYS) for day in evidence)
    return min(1.0, weight / EVIDENCE_FULL)


# Common-word homographs that are also given/month names ("I may go",
# "the bill arrived", "sue the clinic", "in June"). They stay ELIGIBLE as
# candidates (a journal can genuinely be about Bill or May), but their
# mentions must be CAPITALIZED — case-insensitive matching counted every
# modal verb and invoice as a person-day.
_NAME_HOMOGRAPHS = frozenset(
    {
        "may",
        "bill",
        "sue",
        "rob",
        "pat",
        "mark",
        "frank",
        "grace",
        "rose",
        "jack",
        "reed",
        "miles",
        "art",
        "will",
        "ray",
        "vic",
        "dan",
        "jan",
        "june",
        "april",
        "august",
    }
)


def _mentions_name(text: str, name: str) -> bool:
    """Word-boundary mention of a person candidate. Case-insensitive for
    real names; homograph names ("may", "bill") match only their
    CAPITALIZED form, so "I may go tomorrow" is not a May mention."""
    if name in _NAME_HOMOGRAPHS:
        capital = name[0].upper() + name[1:]
        return re.search(rf"\b{re.escape(capital)}\b", text) is not None
    return re.search(rf"\b{re.escape(name)}\b", text, re.IGNORECASE) is not None


def _select_tag_themes(
    tag_entries_count: dict[str, int], tag_distinct_days: dict[str, set[date]]
) -> set[str]:
    """The tag vocabulary that rides the theme machinery this run.

    Tags are client-controlled (<=8 per entry, unbounded across a corpus),
    and every distinct tag costs the per-theme O(entries) detectors a full
    pass — so the tested set is capped (TAG_MAX_THEMES) exactly like topic
    and person candidates. Most distinct days first, then mentions, then
    tag: a total, deterministic order for any corpus size.
    """
    if len(tag_distinct_days) <= TAG_MAX_THEMES:
        return set(tag_distinct_days)
    ranked = sorted(
        tag_distinct_days,
        key=lambda tag: (-len(tag_distinct_days[tag]), -tag_entries_count[tag], tag),
    )
    return set(ranked[:TAG_MAX_THEMES])


def _person_candidates(window: list[JournalEntry]) -> set[str]:
    """Recurring proper-name/possessive candidates, deterministically.

    A candidate is either a mid-sentence capitalized token (sentence
    initials are excluded — first token of the entry AND the first token
    after a . ! ? terminator — they are just ordinary sentence starts)
    whose lowercase form the engine does not already know (not a
    lexicon/theme/stopword word), or the word after "my" when that bigram
    recurs. Both must clear PERSON_MIN_DISTINCT_DAYS across
    PERSON_MIN_TOTAL_MENTIONS.
    """
    counts: dict[str, int] = {}
    days: dict[str, set[date]] = {}
    for entry in window:
        raw = entry.text.split()
        found: set[str] = set()
        for i, token in enumerate(raw):
            clean = token.strip(".,!?:;()\"'")
            low = clean.lower()
            if not clean or not clean[0].isupper() or not low.isalpha():
                continue
            # Sentence initials carry no signal: the entry's first token,
            # and the first token after a . ! ? terminator (Telegram-style
            # journals make every fragment start look like a name).
            if i == 0 or raw[i - 1].endswith((".", "!", "?")):
                continue
            if low in _KNOWN_TOKENS or theme_for(low) is not None:
                continue
            # A mid-sentence capitalized alpha token is a plausible person
            # mention; "my <relation>" is only one of its spellings, so the
            # unigram alone records it (a set makes a bigram re-add a no-op).
            found.add(low)
        for name in found:
            counts[name] = counts.get(name, 0) + 1
            days.setdefault(name, set()).add(entry.entry_date)
    qualified = {
        name
        for name, n in counts.items()
        if n >= PERSON_MIN_TOTAL_MENTIONS and len(days.get(name, set())) >= PERSON_MIN_DISTINCT_DAYS
    }
    if len(qualified) <= PERSON_MAX_CANDIDATES:
        return qualified
    # Cardinality ceiling (see PERSON_MAX_CANDIDATES): the theme machinery
    # rescans the corpus once per surviving name, so the qualified set must
    # be bounded no matter how the corpus was constructed. Most-mentioned
    # first, then most distinct days, then name — a total, deterministic
    # order, mirroring the topic candidate cap.
    ranked = sorted(qualified, key=lambda name: (-counts[name], -len(days[name]), name))
    return set(ranked[:PERSON_MAX_CANDIDATES])


def _detect_themes(
    per_entry: list[tuple[JournalEntry, list[str], set[str], float]],
    weekday_days: dict[int, int],
    total_days: int,
    lag1: float | None = None,
) -> list[_Signal]:
    """Base-rate-corrected weekday concentration + within-person mood ties.

    Two v2 flaws fixed here:

      * the weekday test asked only about the argmax day — selecting the
        best of 7 and testing it once understated the p-value ~7x. Every
        weekday with a testable base rate is now tested and ALL of the
        tests enter the Benjamini-Hochberg family — including the ones
        whose effect gates fail (selecting on the statistic before
        correcting is selection-then-test and voids FDR control; the
        gates filter the corrected survivors instead).
      * mood correlations ran on raw sentiment, so any slow mood trend
        manufactured spurious ties (probe_brain.py: five false claims at
        p <= 1e-6). They now run on residuals against the user's own
        rolling baseline (Bolger & Laurenceau 2013, within-person
        centering) — a theme only ties to mood if its days read
        different from the user's norm AT THAT MOMENT.

    ``lag1``: autocorrelation of the daily residual series, used to
    deflate per-group n in the mood Welch test — day residuals are not
    independent observations when mood carries over day to day.
    """
    signals: list[_Signal] = []
    themes = sorted({theme for _, _, themes, _ in per_entry for theme in themes})
    for theme in themes:
        with_theme = [(e, s) for e, _, themes, s in per_entry if theme in themes]
        without_theme = [(e, s) for e, _, themes, s in per_entry if theme not in themes]
        # Day-level Bernoulli (2026-09-17): a user who writes 4 entries
        # every Sunday contributes 4 CORRELATED trials to one weekday —
        # one calendar day, one observation. The entry-level version
        # over-counted clustered journals and inflated significance;
        # TEMPORAL_MIN_N now reads in theme-DAYS, honestly.
        days = sorted({e.entry_date for e, _ in with_theme})
        count = len(days)
        if count < TEMPORAL_MIN_N:
            continue

        # Weekday concentration: test EVERY candidate day, not just the max.
        weekday_counts: dict[int, int] = {}
        for day in days:
            weekday_counts[day.weekday()] = weekday_counts.get(day.weekday(), 0) + 1
        candidates: list[
            tuple[int, int, float, float, bool]
        ] = []  # (weekday, k, fraction, pvalue, gate_ok)
        for weekday in sorted(weekday_counts):
            base_rate = weekday_days.get(weekday, 0) / total_days
            if not 0.0 < base_rate < 1.0:
                continue  # the test itself is undefined here
            k = weekday_counts[weekday]
            fraction = k / count
            pvalue = statsig.binomial_sf(k, count, base_rate)
            gate_ok = k >= TEMPORAL_MIN_DAY_K and fraction >= TEMPORAL_MIN_FRACTION
            candidates.append((weekday, k, fraction, pvalue, gate_ok))
        # EVERY tested weekday enters the significance family, gate-passing
        # or not (selecting the argmax first and testing it alone understated
        # p-values by up to the number of weekdays). update() keeps, per
        # theme, only the best SURVIVOR after correction.
        for weekday, k, fraction, pvalue, gate_ok in candidates:
            # P3 (2026-09-21): the "Sunday EVENING" refinement. When the
            # weekday's theme-entries carry the optional coarse
            # writing-window bucket and one bucket dominates strongly, it
            # rides the detail — a temporal card may say "Sunday evenings"
            # instead of the flat weekday. Absent on v1 corpora (no tod
            # channel) and when the writing times are genuinely mixed:
            # the claim only narrows when the data actually supports it.
            tod_detail: dict[str, str] = {}
            tod_seen = [
                e.tod
                for e, _ in with_theme
                if e.entry_date.weekday() == weekday and e.tod is not None
            ]
            if len(tod_seen) >= TEMPORAL_MIN_TOD_N:
                dominant, dominant_k = max(
                    ((bucket, tod_seen.count(bucket)) for bucket in set(tod_seen)),
                    key=lambda pair: pair[1],
                )
                if dominant_k / len(tod_seen) >= TEMPORAL_MIN_TOD_FRACTION:
                    tod_detail = {"time_of_day": dominant}
            signals.append(
                _Signal(
                    pid=f"temporal:{theme}",
                    kind="temporal",
                    label=theme,
                    occurrences=count,
                    pvalue=pvalue,
                    detail={
                        "day": DAY_NAMES[weekday],
                        **tod_detail,
                        "day_count": k,
                        "day_fraction": round(fraction, 3),
                        "base_rate": round(weekday_days.get(weekday, 0) / total_days, 3),
                        "p_value": round(pvalue, 6),
                        "days_tested": len(candidates),
                    },
                    evidence_days=days,
                    gate_ok=gate_ok,
                )
            )

        # Day-level mood groups (2026-09-20 audit M-8): clustered same-day
        # entries are not independent observations — a user who journals
        # five times on a theme-day contributed five trials to the Welch
        # test (10 theme-days x 5 entries measured n=50 on 10 independent
        # days, p=2.4e-46, d=4.8). One calendar day, one mean residual —
        # exactly the correction the weekday Bernoulli above already has.
        def _day_means(pairs: list[tuple[JournalEntry, float]]) -> list[float]:
            buckets: dict[date, list[float]] = {}
            for e, s in pairs:
                buckets.setdefault(e.entry_date, []).append(s)
            return [sum(v) / len(v) for _, v in sorted(buckets.items())]

        # Audit round 2 (2026-09-21) F-3: the D-3 rule on the association
        # side. Budget truncation blanks text but keeps client tags, so a
        # blanked entry still joins its theme group above (the tag is a
        # real activity signal for prevalence/cadence) — but with no text
        # and no explicit mood tag it carries zero mood evidence, and its
        # fabricated 0.0 residual must stay out of the mood groups. A
        # blanked entry WITH a mood tag is the user's own report and stays.
        mood_with_theme = [(e, s) for e, s in with_theme if e.text or e.sentiment is not None]
        mood_without_theme = [
            (e, s) for e, s in without_theme if e.text or e.sentiment is not None
        ]
        moods_with = _day_means(mood_with_theme)
        moods_without = _day_means(mood_without_theme)
        if len(moods_without) >= MOOD_MIN_PER_SIDE:
            delta = sum(moods_without) / len(moods_without) - sum(moods_with) / len(moods_with)
            effect = statsig.cohens_d(moods_with, moods_without, variance_floor=MOOD_SD_FLOOR)
            _, pvalue = statsig.welch_test(
                moods_with, moods_without, variance_floor=MOOD_SD_FLOOR, lag1=lag1
            )
            signals.append(
                _Signal(
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
                    gate_ok=abs(delta) >= MOOD_MIN_DELTA and abs(effect) >= MOOD_MIN_EFFECT,
                )
            )
    return signals


def _detect_links(
    day_themes: dict[date, set[str]],
    day_residuals: dict[date, float],
    today: date,
    lag1: float | None = None,
) -> list[_Signal]:
    """Lagged day-after links: theme today → mood deviation tomorrow.

    The best-validated lagged association in the daily-diary literature
    is sleep → next-day affect (Konjarski et al. 2018, *Sleep Medicine
    Reviews* meta-analysis); stress spillover (Bolger et al. 1989) has the
    same shape. We test every theme's next-day residual mood against the
    user's own baseline — the literal "pattern linking" the product
    promises. Only lag-1/lag-2 are tested: they are the interpretable,
    best-replicated lags, and each extra lag doubles the multiple-testing
    burden.

    Two honesty details:

      * GAP LABELING: a one-day journaling skip must not erase the link
        (a skip-day pair still measures "the day after the theme came
        up" for the WRITER — they just didn't write that day), so
        transitions with gap <= LINK_MAX_GAP_DAYS are admitted. The
        label then reports the MODAL exposed gap (detail.lag_days, with
        per-gap counts): "the day after" is said only when the data
        actually says it. Restricting to gap == 1 was tried and
        rejected: for anyone who skips a weekday the exposed group
        collapses below the sample floor and true links vanish.
      * EFFECTIVE SAMPLE SIZE: consecutive-day residuals are
        autocorrelated (that carryover is the inertia detector's whole
        subject), so the per-side n is deflated by the series' lag-1
        autocorrelation before the Welch test — treating them as
        independent made every link p-value anti-conservative.
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
        exposed_pairs = [(prev, cur) for prev, cur in transitions if theme in day_themes[prev]]
        # Audit round 2 (2026-09-21) F-3: a theme day conferred by TAGS on
        # blank truncated entries has no mood residual to read (D-3 kept
        # those days out of the mood series). The exposure stays real, but
        # an outcome day without mood evidence measures nothing — skip it
        # rather than KeyError (or fabricate a value) for an unmeasured day.
        exposed = [day_residuals[cur] for _, cur in exposed_pairs if cur in day_residuals]
        unexposed = [
            day_residuals[cur]
            for prev, cur in transitions
            if theme not in day_themes[prev] and cur in day_residuals
        ]
        if len(exposed) < LINK_MIN_PER_SIDE or len(unexposed) < LINK_MIN_PER_SIDE:
            continue
        delta = sum(unexposed) / len(unexposed) - sum(exposed) / len(exposed)
        effect = statsig.cohens_d(exposed, unexposed, variance_floor=MOOD_SD_FLOOR)
        _, pvalue = statsig.welch_test(exposed, unexposed, variance_floor=MOOD_SD_FLOOR, lag1=lag1)
        gap1 = sum(1 for prev, cur in exposed_pairs if (cur - prev).days == 1)
        gap2 = len(exposed_pairs) - gap1
        # Evidence follows what was MEASURED (see the F-3 filter above):
        # unmeasured outcome days back no part of the claim.
        outcome_days = [cur for _, cur in exposed_pairs if cur in day_residuals]
        signals.append(
            _Signal(
                pid=f"link:{theme}",
                kind="link",
                label=theme,
                occurrences=len(exposed),
                pvalue=pvalue,
                detail={
                    # The MODAL exposed gap (ties break to 1, the stricter
                    # reading): the card copy keys off this.
                    "lag_days": 1 if gap1 >= gap2 else 2,
                    "gap1_days": gap1,
                    "gap2_days": gap2,
                    "mood_delta": round(delta, 3),
                    "direction": "lower" if delta > 0 else "higher",
                    "cohens_d": round(effect, 3),
                    "p_value": round(pvalue, 6),
                    "n_after": len(exposed),
                    "n_other": len(unexposed),
                },
                evidence_days=outcome_days,
                gate_ok=abs(delta) >= MOOD_MIN_DELTA and abs(effect) >= MOOD_MIN_EFFECT,
            )
        )
    return signals


def _inertia_signal(
    series: list[tuple[date, float]],
    pid: str,
    kind: str,
    label: str,
    today: date,
    channel: str | None = None,
) -> _Signal | None:
    """Lag-1 autocorrelation of a daily channel, recent vs the user's own
    earlier norm (Fisher z difference test). Shared by the mood and energy
    channels (2026-09-19): the payload-v2 energy pick is a client-reported
    channel like the mood tag, so it rides the identical machinery — same
    evidence bars, same BH family, same lifecycle. Returns None when either
    window lacks the minimum consecutive-day pairs."""
    recent_cutoff = today - timedelta(days=INERTIA_RECENT_DAYS)
    consecutive: list[tuple[date, float, float]] = []
    for (d1, s1), (d2, s2) in zip(series, series[1:]):
        if 1 <= (d2 - d1).days <= 2:
            consecutive.append((d2, s1, s2))
    recent = [(s1, s2) for d, s1, s2 in consecutive if d > recent_cutoff]
    earlier = [(s1, s2) for d, s1, s2 in consecutive if d <= recent_cutoff]
    if len(recent) < INERTIA_MIN_PAIRS or len(earlier) < INERTIA_MIN_PAIRS:
        return None
    r_recent = _pearson([a for a, _ in recent], [b for _, b in recent])
    r_earlier = _pearson([a for a, _ in earlier], [b for _, b in earlier])
    if r_recent is None or r_earlier is None:
        return None
    # The claim is COMPARATIVE ("carrying over more than usual"), so its
    # p-value must test the difference of the two windows' correlations
    # (Fisher z), not the weaker null r_recent = 0 — a user whose carryover
    # was always high has "inertia" under the old test even with no change
    # at all. The p enters the same Benjamini-Hochberg family as every
    # other claim this run, whether or not the effect gates pass.
    pvalue = statsig.fisher_z_difference_p(r_recent, len(recent), r_earlier, len(earlier))
    detail: dict[str, Any] = {
        "carryover_recent": round(r_recent, 3),
        "carryover_earlier": round(r_earlier, 3),
        "window_days": INERTIA_RECENT_DAYS,
        "p_value": round(pvalue, 6),
    }
    if channel:
        detail["channel"] = channel
    return _Signal(
        pid=pid,
        kind=kind,
        label=label,
        occurrences=len(recent),
        pvalue=pvalue,
        detail=detail,
        evidence_days=[d for d, _, _ in consecutive if d > recent_cutoff],
        gate_ok=(r_recent >= INERTIA_RECENT_MIN and r_recent - r_earlier >= INERTIA_DELTA),
    )


def _coupling_signal(
    a_residuals: dict[date, float],
    b_residuals: dict[date, float],
    today: date,
) -> _Signal | None:
    """Within-person COUPLING of two daily channels (energy ↔ mood): the
    Pearson correlation of their within-person residuals, recent vs the
    user's own earlier norm (Fisher z difference) — the same comparative
    machinery as inertia, applied across channels instead of across days.
    Surfaced only as a RISE ("moving together more than usual"), never as
    an absolute verdict; the evidence bar reuses the inertia constants
    deliberately (a cross-channel claim deserves at least as much proof).
    Returns None when either window lacks the minimum shared days."""
    recent_cutoff = today - timedelta(days=INERTIA_RECENT_DAYS)
    shared = sorted(set(a_residuals) & set(b_residuals))
    recent_days = [d for d in shared if d > recent_cutoff]
    earlier_days = [d for d in shared if d <= recent_cutoff]
    if len(recent_days) < INERTIA_MIN_PAIRS or len(earlier_days) < INERTIA_MIN_PAIRS:
        return None
    r_recent = _pearson(
        [a_residuals[d] for d in recent_days], [b_residuals[d] for d in recent_days]
    )
    r_earlier = _pearson(
        [a_residuals[d] for d in earlier_days], [b_residuals[d] for d in earlier_days]
    )
    if r_recent is None or r_earlier is None:
        return None
    pvalue = statsig.fisher_z_difference_p(r_recent, len(recent_days), r_earlier, len(earlier_days))
    return _Signal(
        pid="coupling:energy_mood",
        kind="energy_mood_coupling",
        label="energy and mood",
        occurrences=len(recent_days),
        pvalue=pvalue,
        detail={
            "coupling_recent": round(r_recent, 3),
            "coupling_earlier": round(r_earlier, 3),
            "window_days": INERTIA_RECENT_DAYS,
            "p_value": round(pvalue, 6),
            "channel": "energy_mood",
        },
        evidence_days=recent_days,
        gate_ok=(r_recent >= INERTIA_RECENT_MIN and r_recent - r_earlier >= INERTIA_DELTA),
    )


# --- sense-making trajectory + activity diversity (2026-09-19 wave 3) ------------

# LIWC-style causal+insight dictionary (deterministic, hand-curated to
# unambiguous forms — no stemming adventures). The evidence anchor: people
# whose writing INCREASES its use of causal ("because", "reason") and
# insight ("realize", "understand") words across sessions show the
# greatest health improvements — language moving from describing toward
# making sense (Pennebaker & Francis 1996; Campbell & Pennebaker 2003;
# Hevey 2014). Surfaced only as a within-person RISE, never a verdict.
SENSE_WORDS: frozenset[str] = frozenset(
    {
        # causal conjunction/nouns
        "because",
        "since",
        "reason",
        "reasons",
        "why",
        "cause",
        "causes",
        "caused",
        "effect",
        "effects",
        "therefore",
        "thus",
        "hence",
        "consequently",
        "result",
        "results",
        "resulted",
        "leads",
        "led",
        # insight/cognitive-processing verbs
        "realize",
        "realized",
        "realise",
        "realised",
        "understand",
        "understood",
        "consider",
        "considered",
        "recognize",
        "recognized",
        "recognise",
        "recognised",
        "learn",
        "learned",
        "learnt",
        "notice",
        "noticed",
        "insight",
        "perspective",
        "meaning",
        "explain",
        "explained",
        "figure",
        "figured",
        "reflect",
        "reflected",
    }
    | SENSE_WORDS_ES
)
SENSEMAKING_RECENT_DAYS = 28
SENSEMAKING_MIN_DAYS = 8  # density observations per window to trust a t-test
SENSEMAKING_RECENT_FLOOR = 0.8  # per-100-token density before any claim
SENSEMAKING_DELTA = 0.5  # ... and risen by this much vs the earlier window
SENSEMAKING_VARIANCE_FLOOR = 0.35  # measurement-noise floor for sparse text days


def _sense_density(tokens: list[str]) -> float | None:
    """Causal+insight words per 100 tokens. None when the entry is too
    short to measure honestly (fewer than 10 tokens)."""
    if len(tokens) < 10:
        return None
    hits = sum(1 for t in tokens if t in SENSE_WORDS)
    return 100.0 * hits / len(tokens)


def _detect_sense_making(day_densities: list[tuple[date, float]], today: date) -> _Signal | None:
    """The sense-making trajectory: per-day causal+insight word density,
    recent window vs the user's own earlier norm (Welch's t on per-day
    densities with a measurement-noise variance floor — the same shape as
    the mood-association tests). A comparative claim, never an absolute
    one: "leaning more on sense-making words than YOU used to"."""
    recent_cutoff = today - timedelta(days=SENSEMAKING_RECENT_DAYS)
    recent = [v for d, v in day_densities if d > recent_cutoff]
    earlier = [v for d, v in day_densities if d <= recent_cutoff]
    if len(recent) < SENSEMAKING_MIN_DAYS or len(earlier) < SENSEMAKING_MIN_DAYS:
        return None
    _, pvalue = statsig.welch_test(recent, earlier, variance_floor=SENSEMAKING_VARIANCE_FLOOR)
    mean_recent = sum(recent) / len(recent)
    mean_earlier = sum(earlier) / len(earlier)
    return _Signal(
        pid="sensemaking:causal_insight",
        kind="sense_making",
        label="sense-making words",
        occurrences=len(recent),
        pvalue=pvalue,
        detail={
            "density_recent": round(mean_recent, 2),
            "density_earlier": round(mean_earlier, 2),
            "window_days": SENSEMAKING_RECENT_DAYS,
            "p_value": round(pvalue, 6),
            "direction": "higher",
            "channel": "text",
        },
        evidence_days=[d for d, _ in day_densities if d > recent_cutoff],
        gate_ok=(
            mean_recent >= SENSEMAKING_RECENT_FLOOR
            and mean_recent - mean_earlier >= SENSEMAKING_DELTA
        ),
    )


# Activity variety: Shannon entropy (bits) over the week's activity-tag
# frequencies. Greater VARIETY of pleasant activities tracks fewer
# depressive symptoms (Ong et al. 2023) — surfaced as BOTH directions
# ("narrowed" / "widened"), each an honest observation about the person's
# own tagging, never a symptom claim. Needs real variety to exist: a
# person who ever used fewer than two distinct tags has no variety to
# lose or gain, and no claim is made for them.
DIVERSITY_RECENT_WEEKS = 4
DIVERSITY_MIN_WEEKS = 3  # weekly entropy observations per window
DIVERSITY_DELTA = 0.35  # bits of entropy change vs the earlier window
DIVERSITY_VARIANCE_FLOOR = 0.25


def _weekly_tag_entropies(tag_days: dict[str, set[date]]) -> list[tuple[date, float]]:
    """(week-start-monday, Shannon entropy in bits) for every week with at
    least one tag, chronological."""
    weeks: dict[date, dict[str, int]] = {}
    for tag, days in tag_days.items():
        for d in days:
            week = d - timedelta(days=d.weekday())
            weeks.setdefault(week, {})
            weeks[week][tag] = weeks[week].get(tag, 0) + 1
    out: list[tuple[date, float]] = []
    for week in sorted(weeks):
        counts = weeks[week]
        total = sum(counts.values())
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
        out.append((week, entropy))
    return out


def _detect_activity_diversity(tag_days: dict[str, set[date]], today: date) -> _Signal | None:
    """The activity-diversity trajectory: weekly tag entropy, recent weeks
    vs the user's own earlier weeks (Welch's t with a noise floor). Both
    directions surface — narrowing and widening are different, equally
    honest observations."""
    distinct_tags = len(tag_days)
    if distinct_tags < 2:
        return None  # no variety to measure
    entropies = _weekly_tag_entropies(tag_days)
    cutoff = today - timedelta(days=7 * DIVERSITY_RECENT_WEEKS)
    recent = [v for d, v in entropies if d > cutoff]
    earlier = [v for d, v in entropies if d <= cutoff]
    if len(recent) < DIVERSITY_MIN_WEEKS or len(earlier) < DIVERSITY_MIN_WEEKS:
        return None
    _, pvalue = statsig.welch_test(recent, earlier, variance_floor=DIVERSITY_VARIANCE_FLOOR)
    mean_recent = sum(recent) / len(recent)
    mean_earlier = sum(earlier) / len(earlier)
    direction = "narrowed" if mean_recent < mean_earlier else "widened"
    return _Signal(
        pid="diversity:activity_tags",
        kind="activity_diversity",
        label="activity variety",
        occurrences=len(recent),
        pvalue=pvalue,
        detail={
            "entropy_recent": round(mean_recent, 2),
            "entropy_earlier": round(mean_earlier, 2),
            "window_weeks": DIVERSITY_RECENT_WEEKS,
            "p_value": round(pvalue, 6),
            "direction": direction,
            "channel": "activity_tags",
        },
        evidence_days=[d for d, _ in entropies if d > cutoff],
        gate_ok=abs(mean_recent - mean_earlier) >= DIVERSITY_DELTA,
    )


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
    inertia = _inertia_signal(day_sentiments, "inertia:mood", "inertia", "day-to-day mood", today)
    if inertia is not None:
        signals.append(inertia)

    # --- instability: spread of within-person residuals, recent vs earlier.
    residual_days = sorted(day_residuals)
    recent_vals = [day_residuals[d] for d in residual_days if d > recent_cutoff]
    earlier_vals = [day_residuals[d] for d in residual_days if d <= recent_cutoff]
    if len(recent_vals) >= INSTABILITY_MIN_DAYS and len(earlier_vals) >= INSTABILITY_MIN_DAYS:
        sd_recent = statsig.sample_sd(recent_vals)
        sd_earlier = statsig.sample_sd(earlier_vals)
        # Spread claim → Brown-Forsythe (median-centered Levene) p-value
        # (2026-09-17), in the BH family whether or not the effect gates
        # (spread floor, ratio) pass. The variance-ratio F-test it replaced
        # assumed iid normal observations and was notoriously kurtosis-
        # sensitive — the input is bounded, platykurtic residual sentiment,
        # often literally discrete 5-point mood tags — and unlike its
        # sibling detectors it carried NO autocorrelation deflation. The
        # spread ratio stays the reported EFFECT (gates below); the TEST
        # now deflates df by the residual series' own lag-1 autocorrelation
        # (the same Bartlett deflation Welch applies). Degenerate inputs
        # fail closed to p=1: "no evidence", never a crash.
        resid_phi = _daily_lag1_autocorr(day_residuals)
        pvalue = statsig.brown_forsythe_two_sided_p(
            recent_vals,
            earlier_vals,
            n_eff_x=statsig.effective_sample_size(len(recent_vals), resid_phi),
            n_eff_y=statsig.effective_sample_size(len(earlier_vals), resid_phi),
        )
        signals.append(
            _Signal(
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
                gate_ok=(
                    sd_recent >= INSTABILITY_SD_FLOOR
                    and sd_recent >= INSTABILITY_RATIO * max(sd_earlier, 0.0)
                ),
            )
        )
    return signals


def _phrase_pid(kind: str, cluster_members: list[phrase_miner.SentenceRef]) -> str:
    """Stable pattern id for a phrase cluster: anchored on its earliest member.

    Anchoring on the representative sentence made the pid flip whenever
    the most-frequent variant changed between runs, fragmenting the
    pattern's lifecycle. The earliest member persists as the cluster
    gains members, so the identity is stable within the analysis window.

    The CLASSIFICATION does not participate in the id (2026-09-20 audit
    L-17): a cluster whose mean negativity oscillates across the
    rumination bar used to flip between "rumination:<digest>" and
    "recurring_phrase:<digest>" — two pids for one underlying pattern,
    churning the lifecycle and double-carding it outside the
    semantic-flip machinery. ``kind`` stays in the signature so callers
    keep naming the classification; the identity is the cluster alone.
    """
    anchor = min(cluster_members, key=lambda r: (r.day, r.text))
    digest = hashlib.blake2b(anchor.text.encode("utf-8"), digest_size=6).hexdigest()
    return f"phrase:{digest}"


def _window_sentences(window: list[JournalEntry]) -> list[phrase_miner.SentenceRef]:
    """The window's clusterable sentences, budgeted newest-first.

    Fill the sentence budget NEWEST-first: when the cap bites, the
    sentences dropped are the oldest in the window — the same recency
    bias the window itself applies to entries. The final reverse keeps
    clustering input in chronological order, so results stay
    deterministic (and identical to before whenever the cap never hits).
    """
    sentences: list[phrase_miner.SentenceRef] = []
    for entry in reversed(window):
        for sentence in sentences_of(entry.text):
            sentences.append(phrase_miner.SentenceRef(text=sentence, day=entry.entry_date))
            if len(sentences) >= MAX_WINDOW_SENTENCES:
                break
        if len(sentences) >= MAX_WINDOW_SENTENCES:
            break
    sentences.reverse()
    return sentences


def _phrase_clusters(window: list[JournalEntry]) -> list[phrase_miner.PhraseCluster]:
    """The run's recurring-phrase clusters, computed ONCE per update.

    Both the phrase detector and the topic presence gate consume the same
    clustering — a word whose occurrences are all inside one repeated
    sentence is that sentence's story, not a topic (see _detect_topics).
    """
    return phrase_miner.near_duplicate_clusters(
        _window_sentences(window),
        min_size=PHRASE_MIN_OCCURRENCES,
        min_span_days=PHRASE_MIN_SPAN_DAYS,
        min_distinct_days=PHRASE_MIN_DISTINCT_DAYS,
    )


def _detect_phrases(
    clusters: list[phrase_miner.PhraseCluster], allow_rumination: bool = True
) -> list[_Signal]:
    """Near-duplicate clusters; negative ones surface as rumination.

    A recurring near-duplicate cluster is surfaced as a repeated *worry*
    when it reads negative (repetitive negative thinking, a transdiagnostic
    process — Ehring & Watkins 2008) or when it is non-positive and
    negation-heavy ("can't sleep, mind won't stop" — perseverative negative
    phrasing). Absolutist-word density (Al-Mosaiwi & Johnstone 2018) rides
    along in the detail. Non-negative repeats stay the neutral
    "recurring_phrase".

    ``allow_rumination=False`` (language gate): the negativity/negation
    classifiers are English, and scoring a language the lexicons do not
    know produces noise dressed as a worry. Repetition itself needs no
    lexicon, so clusters still surface for the tokenizable (Latin-script)
    languages — always as the neutral recurring_phrase kind.
    """
    signals: list[_Signal] = []
    for cluster in clusters:
        days = sorted({ref.day for ref in cluster.members})
        variants = sorted({ref.text for ref in cluster.members})
        member_sentiments = [sentiment_score(ref.text.split()) for ref in cluster.members]
        member_negators = [
            sum(1 for t in ref.text.split() if t in NEGATORS) for ref in cluster.members
        ]
        negativity = sum(member_sentiments) / len(member_sentiments)
        negators = sum(member_negators) / len(member_negators)
        is_rumination = allow_rumination and (
            negativity <= RUMINATION_NEGATIVITY_MAX
            or (negativity <= 0.0 and negators >= RUMINATION_MIN_NEGATORS)
        )
        kind = "rumination" if is_rumination else "recurring_phrase"
        tokens = " ".join(variants).split()
        anchor = min(cluster.members, key=lambda r: (r.day, r.text))
        detail: dict[str, Any] = {
            "span_days": cluster.span_days,
            "distinct_days": cluster.distinct_days,
            "first": days[0].isoformat(),
            "last": days[-1].isoformat(),
            "variants": variants[:3],
            # 2026-09-21 audit D-6: the pid below is anchored on this
            # sentence's TEXT. Persisting the anchor (variants above
            # persist alongside) lets a later recompute re-link a cluster
            # to this record after window/budget rotation evicts the
            # anchor itself and the pid derivation moves to a newer
            # member — see _phrase_alias_pid in the lifecycle merge.
            "phrase_anchor": anchor.text[:200],
        }
        # Suppress-tier tripwire over EVERY variant (2026-09-20 audit
        # L-18): the stored display list is trimmed to three, but a
        # suppress-tier variant sorted 4th+ must still flag the record at
        # surfacing. Detection-time bit, stored only when true; it can
        # only ever err conservative (a stored True may over-suppress if
        # the phrase contract later narrows — it can never under-suppress,
        # and the label/variants checks stay recomputed live).
        if any(crisis.matches_suppress(variant) for variant in variants):
            detail["suppress_variant_seen"] = True
        if is_rumination:
            detail["negativity"] = round(negativity, 3)
            detail["mean_negators"] = round(negators, 2)
            detail["absolutist_per_100"] = absolutist_density(tokens)
        signals.append(
            _Signal(
                pid=_phrase_pid(kind, cluster.members),
                kind=kind,
                label=cluster.representative,
                occurrences=len(cluster.members),
                pvalue=None,
                detail=detail,
                evidence_days=days,
            )
        )
    return signals


def _detect_avoidance(
    day_themes: dict[date, set[str]],
    entry_days: set[date],
    today: date,
) -> list[_Signal]:
    """Theme-days followed by journaling SILENCE vs the user's own rhythm.

    The observation is the writing calendar alone (metadata the server
    already holds). For a theme-day d the next-day outcome is observable
    when journaling continued afterwards: wrote on d+1, or skipped d+1 but
    wrote later — a corpus that simply ENDS after d carries no evidence.
    Censoring-honest, base-rate-corrected, one-sided into the BH family.

    The null is PER WEEKDAY of the theme-day (2026-09-17 audit): the skip
    rate after the theme-day's own weekday, pooled only when that weekday
    has fewer than three observable transitions. A weekly writing calendar
    is not avoidance — the Mon-Fri writer's Friday->Saturday silence has
    p=1 under their own rhythm and must not print a card. The tail is the
    exact Poisson-binomial over the per-day probabilities.
    """
    days_sorted = sorted(entry_days)
    if len(days_sorted) < 2:
        return []
    last_day = days_sorted[-1]
    # Observable next-day transitions, bucketed by the FROM-day's weekday.
    weekday_skips: dict[int, int] = {}
    weekday_total: dict[int, int] = {}
    base_skips = 0
    base_total = 0
    for idx, d in enumerate(days_sorted):
        next_day = d + timedelta(days=1)
        if next_day in entry_days:
            weekday_total[d.weekday()] = weekday_total.get(d.weekday(), 0) + 1
            base_total += 1
            continue  # wrote tomorrow: observable, not a skip
        if idx == len(days_sorted) - 1:
            continue  # corpus ends here: censored
        weekday_skips[d.weekday()] = weekday_skips.get(d.weekday(), 0) + 1
        weekday_total[d.weekday()] = weekday_total.get(d.weekday(), 0) + 1
        base_total += 1
        base_skips += 1
    if base_total < 2 or not 0.0 < base_skips / base_total < 1.0:
        return []

    base_rate = base_skips / base_total

    def day_rate(d: date) -> float:
        total = weekday_total.get(d.weekday(), 0)
        if total < 3:
            return base_rate  # too few same-weekday references: the pooled rate
        return weekday_skips.get(d.weekday(), 0) / total

    signals: list[_Signal] = []
    themes = sorted({t for theme_set in day_themes.values() for t in theme_set})
    for theme in themes:
        observed = 0
        skips = 0
        skip_days: list[date] = []
        probs: list[float] = []
        for d in sorted(day_themes):
            if theme not in day_themes[d]:
                continue
            next_day = d + timedelta(days=1)
            if next_day in entry_days:
                observed += 1
                probs.append(day_rate(d))
                continue
            # The last observed day's absence is not evidence of avoidance:
            # the journal may simply have continued past the window (the
            # day is censored). days_sorted is ascending, so d == last_day
            # IS the max — no further scan needed.
            if d == last_day:
                continue  # censored tail
            observed += 1
            skips += 1
            skip_days.append(d)
            probs.append(day_rate(d))
        if observed < AVOIDANCE_MIN_OBSERVED or skips < AVOIDANCE_MIN_SKIPS:
            continue
        share = skips / observed
        expected_rate = sum(probs) / observed
        pvalue = statsig.poisson_binomial_sf(skips, probs)
        signals.append(
            _Signal(
                pid=f"avoidance:{theme}",
                kind="avoidance",
                label=theme,
                occurrences=skips,
                pvalue=pvalue,
                detail={
                    "silences": skips,
                    "observed": observed,
                    "base_rate": round(base_rate, 3),
                    "expected_silences": round(sum(probs), 2),
                    "share": round(share, 3),
                    "p_value": round(pvalue, 6),
                },
                evidence_days=skip_days,
                gate_ok=share >= expected_rate + AVOIDANCE_MIN_LIFT,
            )
        )
    return signals


def _detect_cadence(entry_days: set[date], today: date) -> list[_Signal]:
    """Journaling-rhythm regularity, recent vs the user's earlier norm.

    Same comparative shape as instability — never an absolute verdict —
    applied to the gaps between writing days. Brown-Forsythe on the gap
    deviations (gaps are counts; the median-centered test is robust to
    their skew), failing closed on degenerate windows.
    """
    days_sorted = sorted(entry_days)
    recent_cutoff = today - timedelta(days=INERTIA_RECENT_DAYS)
    recent_days = [d for d in days_sorted if d > recent_cutoff]
    earlier_days = [d for d in days_sorted if d <= recent_cutoff]
    if len(recent_days) < CADENCE_MIN_DAYS or len(earlier_days) < CADENCE_MIN_DAYS:
        return []

    def gaps(day_list: list[date]) -> list[float]:
        return [float((b - a).days) for a, b in zip(day_list, day_list[1:])]

    recent_gaps = gaps(recent_days)
    earlier_gaps = gaps(earlier_days)
    if len(recent_gaps) < 3 or len(earlier_gaps) < 3:
        return []
    sd_recent = statsig.sample_sd(recent_gaps)
    sd_earlier = statsig.sample_sd(earlier_gaps)
    pvalue = statsig.brown_forsythe_two_sided_p(recent_gaps, earlier_gaps)
    return [
        _Signal(
            pid="cadence:rhythm",
            kind="cadence",
            label="writing rhythm",
            occurrences=len(recent_days),
            pvalue=pvalue,
            detail={
                "gap_spread_recent": round(sd_recent, 3),
                "gap_spread_earlier": round(sd_earlier, 3),
                "median_gap_recent": round(sorted(recent_gaps)[len(recent_gaps) // 2], 1),
                "p_value": round(pvalue, 6),
            },
            evidence_days=recent_days,
            gate_ok=(sd_recent >= 0.5 and sd_recent >= 1.5 * max(sd_earlier, 1e-9)),
        )
    ]


def _mood_reanchor_day(store: dict, today: date) -> date | None:
    """Latest ESTABLISHED mood-shift evidence start; None = no re-anchor.

    The EWMA chart's baseline is the first quarter of the window — without
    this hook, a genuine shift that happened months ago keeps re-qualifying
    on every run as the window slides past it, and the card keeps saying
    your mood is lower/higher "lately" when it has been the new normal for
    a season. Once a stored shift's ``first_seen`` (the day the chart first
    flagged it — at or shortly after the true onset) is
    MOOD_SHIFT_REANCHOR_DAYS in the past, the chart restarts its baseline
    AFTER that day: it re-learns the user's new normal from post-shift data
    (silently, until enough of it exists). Idempotent and state-driven —
    the same store + corpus always anchors the same way.
    """
    anchor: date | None = None
    for record in store["patterns"].values():
        if record.kind != "mood_shift":
            continue
        parsed = _parse_iso(record.first_seen)
        if parsed is None:
            continue
        start = date.fromisoformat(parsed)
        if today - start >= timedelta(days=MOOD_SHIFT_REANCHOR_DAYS):
            if anchor is None or start > anchor:
                anchor = start
    return anchor


def _detect_mood_shift(day_sentiments: list[tuple[date, float]]) -> list[_Signal]:
    """EWMA control chart over daily mood: sustained shifts vs personal baseline.

    The chart estimates the user's own in-control mood (mean and spread
    over the first quarter of the window, min 10 days), then tracks an
    exponentially weighted moving average (lambda 0.18, inside the
    0.05-0.25 band validated by Smit, Schat & Ceulemans 2023); a run of
    points beyond +/-2.7 sigma_ewma in the recent tail reports a
    trajectory shift (Snippe et al. 2024 used this exact family of
    charts on EMA mood series).
    """
    n = len(day_sentiments)
    if n < MOOD_SHIFT_MIN_DAYS:
        return []
    baseline = day_sentiments[: max(MOOD_SHIFT_BASELINE_MIN, n // 4)]
    values = [s for _, s in baseline]
    mu = sum(values) / len(values)
    sigma = max(statsig.sample_sd(values), MOOD_SHIFT_SIGMA_FLOOR)
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
    # Clamp before the division: a constant-within-float-noise baseline
    # computes r == 1.0 exactly and (1+phi)/(1-phi) divides by zero — the
    # 2026-09-16 red-team corpus (35 near-identical daily entries) bricked
    # every future recompute for such accounts. phi = 0.99 already
    # saturates the inflation cap below, so the clamp changes no honest
    # statistical outcome.
    if phi is not None:
        phi = min(phi, 0.99)
    if phi is not None and phi >= 0.35:
        inflation = (1.0 + phi) / (1.0 - phi)
        sigma_ewma *= math.sqrt(min(max(inflation, 1.0), 16.0))
    upper = mu + MOOD_SHIFT_LIMIT * sigma_ewma
    lower = mu - MOOD_SHIFT_LIMIT * sigma_ewma

    ewma = mu
    signs: list[tuple[date, int]] = []
    last_ewma = mu
    for day, s in day_sentiments[len(baseline) :]:
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
    direction = "lower" if last_sign < 0 else "higher"
    # The excursion IS a statistical claim (a control chart is a repeated
    # test): attach its p-value so it enters the BH family with everything
    # else instead of bypassing multiple-testing correction. The minimum
    # meaningful shift is an effect gate and filters the SURVIVORS — the
    # test ran, so the family counts it.
    z_last = (last_ewma - mu) / sigma_ewma if sigma_ewma > 0 else 0.0
    pvalue = statsig.normal_two_sided_sf(z_last)
    return [
        _Signal(
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
            gate_ok=abs(shift) >= MOOD_SHIFT_MIN_SHIFT,
        )
    ]


# --- emergent topic discovery -------------------------------------------------------


def _cluster_covered_days(clusters: list[phrase_miner.PhraseCluster], label: str) -> set[date]:
    """Days on which a recurring-phrase cluster member contains *label*.

    Unigrams match on tokens; bigrams on ADJACENT token pairs (the label
    was mined from adjacent tokens, so the same adjacency is required here
    — a substring test would credit "xa b" with the bigram "a b").
    """
    covered: set[date] = set()
    for cluster in clusters:
        for ref in cluster.members:
            toks = ref.text.split()
            if " " in label:
                if any(f"{a} {b}" == label for a, b in zip(toks, toks[1:])):
                    covered.add(ref.day)
            elif label in toks:
                covered.add(ref.day)
    return covered


def _detect_topics(
    per_entry: list[tuple[JournalEntry, list[str], set[str], float]],
    phrase_clusters: list[phrase_miner.PhraseCluster],
    language: str = "en",
) -> list[_Signal]:
    """Discover recurring content n-grams the fixed lexicon does not cover.

    The theme lexicon knows nine universal themes; everything else a life
    revolves around — a new relationship, a startup, grief, guitar — must be
    found in the text itself. Candidates are unigrams and adjacent bigrams
    of content tokens (function words, theme words, sentiment carriers and
    absolutist markers are all excluded — those layers own them), recurring
    across enough entries and distinct days. A candidate surfaces either as
    RISING (recent-half share vs the user's own earlier-half base rate,
    exact binomial, into the run-wide Benjamini-Hochberg family — "X is
    taking up more space in your writing") or as a PERSISTENT presence (a
    direct measurement of share, ≥30% of entries — no null hypothesis
    applies).

    Three honesty rules worth calling out:

      * Every TESTABLE candidate's p-value is emitted pre-gate (the local
        Bonferroni this detector used to apply is subsumed by the
        run-wide family); the rising effect gates filter the corrected
        survivors downstream. A failing rising claim with a persistent
        presence still surfaces — as the presence variant (``fallback``).
      * Presence claims must clear a distinct-context bar: the same word
        followed by the same word every time ("another ordinary journal
        scribble…") is boilerplate, not a topic — measured: presence
        topics flooded pure-noise corpora (~5 cards/run) before the bar.
        Presence cards carry ``presence: true`` so the client can
        down-rank a measurement against tested claims.
      * …and a cluster-coverage bar on top of it (the follower bar is
        beatable: small-vocab noise hands every frequent word enough
        distinct followers — measured: 40/40 such runs surfaced 3–6
        presence cards, "'blanket' is a steady presence"). A candidate
        whose evidence days are ≥ TOPIC_PRESENCE_CLUSTER_COVER covered by
        the run's own recurring-phrase clusters has its occurrences
        explained by a repeated SENTENCE; the phrase detector already
        surfaces that sentence, so the presence claim is suppressed as
        the same measurement in a second hat. Rising (tested) claims are
        unaffected — a word can genuinely rise inside varied phrasing
        while a boilerplate sentence also repeats.
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

    # 2026-09-21 audit D-2: TOPIC_STOPWORDS is English-only, so on a
    # Spanish corpus the eligibility filter let every function word
    # through ("para", "cuando", "porque", "ahora" …) and presence cards
    # surfaced for filler. Under language "es" the Spanish function-word
    # set joins the exclusions — same rule the English side always had.
    # (The grammatical sets below — NEGATORS, BUT_WORDS, ABSOLUTIST_WORDS,
    # INTENSIFIERS, SENTIMENT_LEXICON — are already EN+ES unions.)
    eligibility_stopwords: frozenset[str] = (
        TOPIC_STOPWORDS | LANGUAGE_FUNCTION_WORDS_ES if language == "es" else TOPIC_STOPWORDS
    )

    def eligible(token: str) -> bool:
        if token in eligibility_stopwords or token in NEGATORS or token in BUT_WORDS:
            return False
        if token in ABSOLUTIST_WORDS or token in INTENSIFIERS:
            return False
        if theme_for(token, language) is not None:  # also catches theme inflections
            return False
        if any(f in SENTIMENT_LEXICON for f in word_forms(token)):
            return False
        return len(token) >= 4

    df_docs: dict[str, set[int]] = {}
    df_days: dict[str, set[date]] = {}
    followers: dict[str, set[str]] = {}
    for i, (day, tokens) in enumerate(doc_tokens):
        prev = None
        for j, tok in enumerate(tokens):
            if not eligible(tok):
                prev = None
                continue
            following = tokens[j + 1] if j + 1 < len(tokens) else None
            for cand in (tok, f"{prev} {tok}") if prev else (tok,):
                df_docs.setdefault(cand, set()).add(i)
                df_days.setdefault(cand, set()).add(day)
                if following is not None:
                    followers.setdefault(cand, set()).add(following)
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
    # both qualify downstream, the broader one wins and nested labels are
    # dropped (the dedupe itself happens post-correction in update()).
    candidates.sort(key=lambda c: (-c[1], c[0]))
    candidates = candidates[:TOPIC_MAX_CANDIDATES]

    recent_n = len(recent_idx)
    signals: list[_Signal] = []
    for label, total, days_n, recent_df in candidates:
        share = total / n
        share_recent = recent_df / recent_n if recent_n else 0.0
        share_earlier = (total - recent_df) / earlier_n if earlier_n else 0.0
        pvalue: float | None = None
        gate_ok = False
        if recent_n >= TOPIC_MIN_PER_HALF and earlier_n >= TOPIC_MIN_PER_HALF:
            base = ((total - recent_df) + 0.5) / (earlier_n + 1)
            pvalue = statsig.binomial_sf(recent_df, recent_n, base)
            gate_ok = (
                recent_df >= TOPIC_RISING_MIN_RECENT
                and share_recent >= TOPIC_RISING_MIN_SHARE
                and share_recent >= base + TOPIC_RISING_MIN_GAIN
                # AND a substantial RELATIVE gain: the binomial p-value
                # conditions on a base estimated from the same window's
                # earlier half, so a chance-low earlier half makes an
                # ordinary recent half look "rising". Demanding the
                # recent rate roughly double the base keeps chance-low
                # baselines from manufacturing claims.
                and share_recent >= 2.0 * base + 0.05
            )
        is_presence = (
            total >= TOPIC_PRESENCE_MIN_ENTRIES
            and share >= TOPIC_PRESENCE_MIN_SHARE
            and share <= TOPIC_PRESENCE_MAX_SHARE
            and days_n >= TOPIC_PRESENCE_MIN_DAYS
            and len(followers.get(label, ())) >= TOPIC_PRESENCE_MIN_CONTEXTS
        )
        if is_presence:
            # Cluster-coverage bar: occurrences a repeated sentence already
            # explains (the engine surfaces that sentence as a phrase card)
            # must not double as a "steady presence" measurement.
            covered = _cluster_covered_days(phrase_clusters, label)
            if len(df_days[label] & covered) >= TOPIC_PRESENCE_CLUSTER_COVER * days_n:
                is_presence = False
        if pvalue is None and not is_presence:
            continue
        shared_detail: dict[str, Any] = {
            "entries": total,
            "distinct_days": days_n,
            "share": round(share, 3),
            "share_earlier": round(share_earlier, 3),
            "share_recent": round(share_recent, 3),
        }
        fallback: _Signal | None = None
        if is_presence:
            fallback = _Signal(
                pid=f"topic:{label}",
                kind="topic",
                label=label,
                occurrences=total,
                pvalue=None,
                detail={**shared_detail, "trend": "steady", "presence": True},
                evidence_days=sorted(df_days[label]),
            )
        if pvalue is None:
            # Untestable trend (thin halves): the presence variant, or
            # nothing, IS the signal.
            if fallback is not None:
                signals.append(fallback)
            continue
        signals.append(
            _Signal(
                pid=f"topic:{label}",
                kind="topic",
                label=label,
                occurrences=total,
                pvalue=pvalue,
                detail={**shared_detail, "trend": "rising", "p_value": round(pvalue, 6)},
                evidence_days=sorted(df_days[label]),
                gate_ok=gate_ok,
                fallback=fallback,
            )
        )
    return signals


# --- lifecycle merge ------------------------------------------------------------------

# The detail field that carries a claim's CORE semantics, per kind: when a
# re-qualification rewrites it, the claim itself has changed.
_SEMANTIC_DETAIL_KEYS = {
    "temporal": "day",  # the dominant weekday
    "mood_correlation": "direction",
    "link": "direction",
    "mood_shift": "direction",
}

# The near-duplicate family: pid anchored on an earliest member's text
# (see _phrase_pid), therefore exposed to anchor churn at the window and
# sentence-budget edges.
PHRASE_KINDS = frozenset({"rumination", "recurring_phrase"})


def _phrase_alias_pid(signal: _Signal, patterns: dict[str, StoredPattern]) -> str:
    """The stored pid for a phrase signal whose anchor rotated out of the
    window (2026-09-21 audit D-6), or its own pid when nothing matches.

    Cluster membership churns at the 180-day window and sentence-budget
    edges; the recurring thought itself does not. A stored record's
    anchor sentence and top variants carry that identity across the
    rotation. Match at the clusterer's own DEFAULT_JACCARD bar — two
    texts the miner would have merged ARE one pattern — keeping the
    highest-similarity record (insertion order wins ties, so the result
    is deterministic). Without this bridge, a chronic rumination's pid
    re-derived from a newer member minted a fresh candidate and restarted
    the lifecycle the day the original anchor left the window.
    """
    incoming = [
        phrase_miner.shingles(text.split())
        for text in [
            signal.detail.get("phrase_anchor", ""),
            *signal.detail.get("variants", []),
        ]
        if text
    ]
    if not incoming:
        return signal.pid
    best_pid: str | None = None
    best_score = phrase_miner.DEFAULT_JACCARD
    for record in patterns.values():
        if record.kind not in PHRASE_KINDS:
            continue
        stored = [
            phrase_miner.shingles(text.split())
            for text in [
                record.detail.get("phrase_anchor", ""),
                *record.detail.get("variants", []),
            ]
            if text
        ]
        for left in incoming:
            for right in stored:
                if not left or not right:
                    continue
                score = len(left & right) / len(left | right)
                if score > best_score:
                    best_pid = record.pid
                    best_score = score
    return best_pid if best_pid is not None else signal.pid


def _semantic_flip(record: StoredPattern, signal: _Signal) -> bool:
    """True when a re-qualification rewrites the claim's core semantics
    (the dominant weekday flipped, a mood direction reversed)."""
    key = _SEMANTIC_DETAIL_KEYS.get(signal.kind)
    if key is None:
        return False
    old = record.detail.get(key)
    new = signal.detail.get(key)
    return old is not None and new is not None and old != new


def _iso(day: date) -> str:
    return day.isoformat()


def _replication_satisfied(
    record: StoredPattern, signal: _Signal, prior_evidence: set[str]
) -> bool:
    """True when a statistical claim has an INDEPENDENT second observation.

    Two distinct qualification days are necessary but not sufficient:
    consecutive recomputes share ~179 of 180 window days, so "qualified
    again tomorrow" used to mean "the same fluke, scored twice" — measured:
    ~17% of daily-cadence pure-noise runs surfaced at least one false
    statistical card (mostly mood_shift's ~11-day EWMA memory re-qualifying
    a single excursion). What counts as independent depends on the claim
    (see EVIDENCE_DATE_KINDS / WINDOW_STAT_KINDS above):

      * evidence-date kinds: this run's signal must contribute at least
        one evidence day the record did not already hold — the claim
        re-derived on data that did not produce the first qualification.
      * window-stat kinds: the first and latest qualification days must
        be >= REPLICATION_MIN_SPREAD_DAYS calendar days apart, so the
        window itself has moved between the two observations.

    Sensitivity cost, honestly stated: a real claim now surfaces a day or
    two later than the bare 2-day gate allowed (it still surfaces on the
    first recompute after genuinely new corroborating data exists).
    """
    if len(record.qualification_days) < 2:
        return False
    if record.kind in EVIDENCE_DATE_KINDS:
        # 2026-09-21 audit D-1: set membership against the stored list was
        # defeated by the EVIDENCE_DATES_CAP. The cap keeps the NEWEST
        # EVIDENCE_DATES_CAP days, so for a well-evidenced pattern (>60
        # evidence days) an evicted older day counted as "new" — a
        # same-corpus, zero-new-data recompute satisfied "independent
        # replication" (verified: mood_correlation:work, 73 evidence days,
        # surfaced on a second identical run). Genuinely new evidence must
        # postdate everything any earlier run held, and the newest stored
        # day survives every cap — compare against it, not membership.
        newest_prior = max(prior_evidence) if prior_evidence else ""
        return any(_iso(day) > newest_prior for day in signal.evidence_days)
    spread = (
        date.fromisoformat(record.qualification_days[-1])
        - date.fromisoformat(record.qualification_days[0])
    ).days
    return spread >= REPLICATION_MIN_SPREAD_DAYS


def _merge_lifecycle(store: dict, qualified: list[_Signal], today: date) -> None:
    patterns: dict[str, StoredPattern] = store["patterns"]
    today_iso = _iso(today)
    qualified_pids = set()

    for signal in qualified:
        if signal.pid not in patterns and signal.kind in PHRASE_KINDS:
            # 2026-09-21 audit D-6: window/budget rotation can evict the
            # sentence a phrase pid was anchored on, so the re-derived pid
            # misses its own record and a chronic pattern restarts as a
            # fresh candidate. Re-link first: a cluster whose text is
            # near-duplicate (the clusterer's own bar) of a stored phrase
            # record's anchor/variants IS that pattern — continue its
            # lifecycle under the stored pid.
            signal.pid = _phrase_alias_pid(signal, patterns)
        record = patterns.get(signal.pid)
        if record is not None and _semantic_flip(record, signal):
            # Semantic flip: the re-qualified claim contradicts the stored
            # one ("mostly on Sundays" → "mostly on Wednesdays"). Keeping
            # the pid would let the retired claim's evidence, age and
            # confirmation status prop up a claim that never earned them —
            # the label would silently change under an intact history. The
            # old record retires instead (a surfaced claim fades honestly;
            # a never-surfaced candidate archives quietly) and the flipped
            # signal continues under a fork pid: new candidate clock, and
            # for statistical kinds the replication gate re-applies.
            if record.state in ("emerging", "confirmed"):
                record.state = "fading"
            elif record.state == "candidate":
                record.state = "archived"
            base_pid = signal.pid
            # REUSE before minting (2026-09-20 audit H-11): detectors
            # always emit the base pid, and the base record's semantic
            # detail froze at this flip — every later run re-flips against
            # it. Without reuse each run minted ~3, ~4, … each holding one
            # qualification day, so the genuinely-supported flipped claim
            # could never re-establish itself (and the store churned one
            # record per recompute). A fork whose STORED semantic detail
            # equals the incoming signal's IS that claim — continue it.
            semantic_key = _SEMANTIC_DETAIL_KEYS.get(signal.kind)
            reuse: StoredPattern | None = None
            if semantic_key is not None:
                target = signal.detail.get(semantic_key)
                suffix = 2
                while (candidate := patterns.get(f"{base_pid}~{suffix}")) is not None:
                    if (
                        candidate.kind == signal.kind
                        and candidate.detail.get(semantic_key) == target
                    ):
                        reuse = candidate
                        break
                    suffix += 1
            if reuse is not None:
                signal.pid = reuse.pid
                record = reuse
            else:
                suffix = 2
                while (
                    f"{base_pid}~{suffix}" in patterns or f"{base_pid}~{suffix}" in qualified_pids
                ):
                    suffix += 1
                signal.pid = f"{base_pid}~{suffix}"
                record = None
        qualified_pids.add(signal.pid)
        if record is None:
            record = StoredPattern(
                pid=signal.pid,
                kind=signal.kind,
                label=signal.label,
                first_seen=_iso(min(signal.evidence_days)),
                last_seen=_iso(max(signal.evidence_days)),
                first_qualified=today_iso,
                last_qualified=today_iso,
                occurrences=signal.occurrences,
                state="candidate",
                qualification_days=[],
                evidence_dates=[],
                feedback={},
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
        # The replication gate compares this run's signal against the
        # evidence recorded BEFORE this merge — a "new evidence day" is new
        # relative to everything earlier runs already counted.
        prior_evidence = set(record.evidence_dates)
        evidence = sorted(set(record.evidence_dates) | {_iso(d) for d in signal.evidence_days})
        record.evidence_dates = evidence[-EVIDENCE_DATES_CAP:]

        # Lifecycle promotion. DIRECT-measurement kinds: strong evidence
        # surfaces immediately; weaker signals must re-qualify on another
        # day (or age a week) first. STATISTICAL kinds get no instant or
        # age-based path: an inference from noisy data must replicate
        # before it earns a card — >= 2 distinct recompute days AND an
        # independent second observation (_replication_satisfied). A single
        # lucky p-value stays a candidate forever.
        if record.state == "candidate":
            spread = (
                date.fromisoformat(record.qualification_days[-1])
                - date.fromisoformat(record.qualification_days[0])
            ).days
            promoted = False
            if _is_statistical(record.kind, record.detail):
                if _replication_satisfied(record, signal, prior_evidence):
                    promoted = True
            elif (
                record.occurrences >= STRONG_EVIDENCE
                or len(record.qualification_days) >= 2
                or (today - date.fromisoformat(record.first_qualified)).days >= PROMOTE_AGE_DAYS
                or spread >= PROMOTE_AGE_DAYS
            ):
                promoted = True
            if promoted:
                # 2026-09-21 audit D-5: the confirm clock starts at the
                # EMERGING transition, not at first candidate qualification.
                # first_qualified used to stay at the day the pattern first
                # qualified as a candidate, so a claim that sat as candidate
                # >= CONFIRM_AGE_DAYS (e.g. waiting on replication) jumped
                # candidate -> confirmed in one run and the first card the
                # user ever saw carried the highest-confidence label.
                record.state = "emerging"
                record.first_qualified = today_iso
        if record.state == "emerging":
            if (today - date.fromisoformat(record.first_qualified)).days >= CONFIRM_AGE_DAYS:
                record.state = "confirmed"
        elif record.state in ("fading", "archived"):
            # Re-qualified: back in play, but as a fresh qualification —
            # the confirmation clock restarts here, or the next run's age
            # check would read the stale first_qualified and promote the
            # pattern straight to "confirmed" without re-proving itself.
            # Statistical kinds must additionally replicate (the same
            # independent-second-observation bar as first promotion) — one
            # lucky re-qualification after months of silence is the same
            # single-run fluke the promotion gate exists to stop.
            if not _is_statistical(record.kind, record.detail) or _replication_satisfied(
                record, signal, prior_evidence
            ):
                record.state = "emerging"
                record.first_qualified = today_iso

    # Aging: patterns that stopped qualifying fade, archive, then are dropped.
    # A candidate NEVER surfaced — promoting it to "fading" would surface a
    # card the user has never seen, for a claim that never earned one
    # (audit M-9: a 4-occurrence phrase with one qualification day showed
    # up as a "fading" card nine days after it left the corpus). Statistical
    # candidates skip fading for the same reason plus the replication
    # verdict; every candidate therefore archives quietly. Only patterns
    # that actually surfaced (emerging/confirmed) fade visibly.
    for pid in sorted(patterns):
        record = patterns[pid]
        if pid in qualified_pids:
            continue
        if not record.last_qualified:
            # Corrupt store (audit L-14): an empty timestamp used to skip
            # aging entirely — the record surfaced forever and never
            # dropped. Treat it as maximally stale so this run archives
            # (and, on a later run, drops) it.
            record.state = "archived"
            if (today - date.fromisoformat(record.first_seen or "1970-01-01")).days > DROP_DAYS:
                del patterns[pid]
            continue
        stale_days = (today - date.fromisoformat(record.last_qualified)).days
        if record.state == "candidate" and stale_days > GRACE_DAYS:
            record.state = "archived"
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


def _record_is_sensitive(record: StoredPattern) -> bool:
    """True when a surfaced pattern's own wording is suppress-tier crisis
    content (label, or any stored phrase variant — the representative is
    often the mildest phrasing of a darker cluster)."""
    if crisis.matches_suppress(record.label):
        return True
    # Detection-time bit set when ANY cluster variant tripped the suppress
    # tier (audit L-18) — the stored display list is trimmed to three.
    if record.detail.get("suppress_variant_seen") is True:
        return True
    variants = record.detail.get("variants")
    if isinstance(variants, list):
        return any(
            isinstance(variant, str) and crisis.matches_suppress(variant) for variant in variants
        )
    return False


@dataclass
class BrainUpdate:
    new_state: dict
    surfaced: list[Pattern]
    stats: dict
    patterns_new: int
    patterns_fading: int


def update(
    state: dict,
    entries: list[JournalEntry],
    today: date,
    feedback: list[tuple[str, bool]] | None = None,
    muted: list[str] | None = None,
    unmuted: list[str] | None = None,
) -> BrainUpdate:
    """Fold the corpus into the persistent store; surface what earned it.

    Pure: the caller's ``state`` is never mutated. Copy-on-entry via a
    dump/load roundtrip — cheap (the store is capped at MAX_STORED_PATTERNS
    small records), and it doubles as normalization: whatever the caller
    held is re-validated exactly as if it had crossed the encrypted-store
    boundary. The recompute path reloads state from bytes each run anyway,
    so this changes nothing observable there.
    """
    if isinstance(state, dict) and isinstance(state.get("patterns"), dict):
        store = load_state(dump_state(state))
    else:
        store = fresh_state()

    cutoff = today - timedelta(days=WINDOW_DAYS)
    ordered = sorted(entries, key=lambda e: e.entry_date)
    window = [e for e in ordered if e.entry_date >= cutoff][-MAX_WINDOW_ENTRIES:]

    # Structured channels (2026-09-17): the sleep-quality split is decided
    # BEFORE the per-entry pass so every entry on a poor night carries the
    # synthetic theme; tags merge into the theme set as-is.
    day_sleep_vals: dict[date, list[float]] = {}
    for entry in window:
        if entry.sleep_quality is not None:
            day_sleep_vals.setdefault(entry.entry_date, []).append(float(entry.sleep_quality))
    day_sleep_mean = {day: sum(v) / len(v) for day, v in day_sleep_vals.items()}
    poor_sleep_days: set[date] = set()
    if len(day_sleep_mean) >= SLEEP_MIN_RATED_NIGHTS:
        ordered_ratings = sorted(day_sleep_mean.values())
        mid = len(ordered_ratings) // 2
        median = (
            ordered_ratings[mid]
            if len(ordered_ratings) % 2 == 1
            else (ordered_ratings[mid - 1] + ordered_ratings[mid]) / 2
        )
        # Strictly below the user's own median = a rough night FOR THEM.
        poor_sleep_days = {day for day, q in day_sleep_mean.items() if q < median}
    tag_vocab: set[str] = set()
    tag_entries_count: dict[str, int] = {}
    tag_distinct_days: dict[str, set[date]] = {}
    for entry in window:
        tag_vocab.update(entry.tags)
        for tag in entry.tags:
            tag_entries_count[tag] = tag_entries_count.get(tag, 0) + 1
            tag_distinct_days.setdefault(tag, set()).add(entry.entry_date)
    # Cardinality ceiling for tag-derived themes (see TAG_MAX_THEMES):
    # ``tag_vocab`` stays complete for origin marking, but only the kept
    # tags ride the per-theme O(entries) detectors.
    kept_tags = _select_tag_themes(tag_entries_count, tag_distinct_days)

    # Tokens first (two passes): language DETECTION must run before themes
    # are extracted, because the theme lexicon is language-gated (2026-09-21
    # audit Phase 2, ES theme set) — the same folded tokenization as always
    # (audit H-8: every accented word must survive [a-z']+ as one whole
    # token, and iOS U+2019 must read as ' so contraction negators fire).
    entry_tokens: list[list[str]] = []
    for entry in window:
        tokens = WORD_RE.findall(_fold_sentiment_text(entry.text.lower()))
        # Emoji ride along as their own tokens: they score mood through
        # EMOJI_VALENCES but never become themes or phrase shingles (the
        # theme/phrase lookups simply never match them). Counted per
        # OCCURRENCE: an entry of five sobs carries five sob tokens, not
        # one (a repeated word is counted five times too).
        tokens.extend(e for e in EMOJI_VALENCES for _ in range(entry.text.count(e)))
        entry_tokens.append(tokens)

    # Language gate (2026-09-17): see the LANGUAGE_* constants. When the
    # window's text is not something the lexicons know, mood analyses keep
    # only explicitly tagged entries (the user's own report) and topic
    # mining / rumination classification step aside. Scored over tokens of
    # >= 3 letters only (2026-09-17 audit): Spanish function words ("no",
    # "me", "a", "y") are English tokens too, and counting them let
    # negation-dense Spanish through at ~25% "known" — enough to mint
    # English-lexicon rumination cards on Spanish prose.
    scored = [t for tokens in entry_tokens for t in tokens if len(t) >= 3]
    # Language DETECTION (2026-09-19): English and Spanish each score a
    # share of the window's tokens against their own detection sets; the
    # higher share wins if it clears the floor, otherwise the language is
    # "other" and the historical suppressions apply (topics, text
    # sentiment, rumination classification step aside; client mood tags
    # still count). Phrase repetition needs WORD_RE tokenization, so it
    # steps aside for non-Latin scripts too (M-10, 2026-09-20: the README
    # promise was corrected to match). Too little text keeps the
    # historical English default.
    language = "en"
    if len(scored) >= LANGUAGE_MIN_TOKENS:
        en_hits = sum(1 for t in scored if t in _KNOWN_TOKENS)
        es_hits = sum(1 for t in scored if t in _KNOWN_TOKENS_ES)
        en_share = en_hits / len(scored)
        es_share = es_hits / len(scored)
        if es_share >= LANGUAGE_HIT_FLOOR and es_share > en_share:
            language = "es"
        elif en_share >= LANGUAGE_HIT_FLOOR:
            language = "en"
        else:
            language = "other"
    language_ok = language != "other"

    per_entry: list[tuple[JournalEntry, list[str], set[str], float]] = []
    for entry, tokens in zip(window, entry_tokens):
        if entry.sentiment is not None and math.isfinite(entry.sentiment):
            # Client-supplied mood tag: clamped to the engine's scale. A
            # non-finite value (NaN poisons every average downstream) falls
            # back to scoring the text.
            sentiment = max(-1.0, min(1.0, entry.sentiment))
        else:
            sentiment = sentiment_score(tokens)
        # Themes under the DETECTED language's lexicon (Phase 2 ES theme
        # set): Spanish corpora read Spanish words, English corpora English
        # ones; client tags (English wire values) join unchanged.
        themes = extract_themes(tokens, language) | (set(entry.tags) & kept_tags)
        if entry.entry_date in poor_sleep_days:
            themes.add(SLEEP_CHANNEL_THEME)
        per_entry.append((entry, tokens, themes, sentiment))

    # Person anchoring: computed once per run over the raw window — but
    # only for English (2026-09-21 audit D-4). The heuristic reads "a
    # recurring MID-SENTENCE capitalized token" as a name; German-style
    # orthography capitalizes every noun, so under language "other" (or
    # Spanish sentence starts) common nouns masquerade as people and a
    # mood-tagging user gets source="person" cards for ordinary words.
    # English is the only orthography where the signal means what it says.
    person_names = _person_candidates(window) if language == "en" else set()
    if person_names:
        per_entry = [
            (
                entry,
                tokens,
                themes | {n for n in person_names if _mentions_name(entry.text, n)},
                sentiment,
            )
            for entry, tokens, themes, sentiment in per_entry
        ]

    mood_entries = (
        per_entry
        if language_ok
        # `isfinite`, not just `is not None` (audit L-15): a NaN tag would
        # pass the filter and slip a fabricated text-score into the
        # "explicitly tagged" series. (The API rejects non-finite tags, so
        # this is the hostile-store belt-and-braces.)
        else [
            (e, t, th, m)
            for (e, t, th, m) in per_entry
            if e.sentiment is not None and math.isfinite(e.sentiment)
        ]
    )

    day_buckets: dict[date, list[float]] = {}
    for entry, _, _, sentiment in mood_entries:
        # 2026-09-21 audit D-3: an entry with NO text and NO explicit mood
        # tag carries zero mood evidence — it is a corpus-budget truncation
        # (the API layer blanks the oldest over-budget entries) or an empty
        # submit, and scoring it injected a fabricated neutral 0.0 day into
        # means/baselines/EWMA for prolific long-term users. The day still
        # counts for cadence/calendar below (entry_day_set comes from
        # `window`, untouched); only the mood series drops it.
        if not entry.text and entry.sentiment is None:
            continue
        day_buckets.setdefault(entry.entry_date, []).append(sentiment)
    day_sentiments = sorted((day, sum(v) / len(v)) for day, v in day_buckets.items())

    # Energy channel (2026-09-19): the payload-v2 energy pick is a
    # client-reported daily channel like the mood tag — it is NOT language
    # gated (the user's own report, not scored text) and rides the inertia
    # machinery unchanged: same evidence bars, same BH family, surfaced
    # only as a within-person CHANGE ("more than usual for you").
    day_energy_buckets: dict[date, list[float]] = {}
    for entry in window:
        if entry.energy is not None and math.isfinite(entry.energy):
            day_energy_buckets.setdefault(entry.entry_date, []).append(
                max(-1.0, min(1.0, entry.energy))
            )
    day_energies = sorted((day, sum(v) / len(v)) for day, v in day_energy_buckets.items())

    # PA/NA split (2026-09-19): positive and negative affect are separable
    # streams, not ends of one scale (Emmons & Diener 1985; differential
    # dynamics — Abitante et al. 2024). Computed from TEXT-SCORED entries
    # only and only when the language gate passed: an explicit mood
    # check-in is a single valence judgment that cannot be honestly split,
    # and a lexicon that doesn't know the language cannot split anything.
    day_pa_buckets: dict[date, list[float]] = {}
    day_na_buckets: dict[date, list[float]] = {}
    if language_ok:
        for entry, tokens, _, _ in per_entry:
            if entry.sentiment is not None:
                continue
            if not entry.text:
                # Budget-truncated/empty entry (audit D-3): no text means no
                # affect components either — (0.0, 0.0) would be fabricated
                # neutral PA/NA days, the same lie as the mood series.
                continue
            pa, na = sentiment_components(tokens)
            day_pa_buckets.setdefault(entry.entry_date, []).append(pa)
            day_na_buckets.setdefault(entry.entry_date, []).append(na)
    day_pa = sorted((day, sum(v) / len(v)) for day, v in day_pa_buckets.items())
    day_na = sorted((day, sum(v) / len(v)) for day, v in day_na_buckets.items())

    # Sense-making densities (2026-09-19): per-day causal+insight word
    # density over EVERY entry's text (a mood-tag override says nothing
    # about the text's cognitive organization, so — unlike PA/NA — the
    # override does not exclude the entry), language-gated like every
    # lexicon measurement.
    day_sense_buckets: dict[date, list[float]] = {}
    if language_ok:
        for entry, tokens, _, _ in per_entry:
            density = _sense_density(tokens)
            if density is not None:
                day_sense_buckets.setdefault(entry.entry_date, []).append(density)
    day_sense = sorted((day, sum(v) / len(v)) for day, v in day_sense_buckets.items())

    # Day-level writing calendar: one calendar day, one Bernoulli (see
    # _detect_themes) — the BASE RATE counts distinct journaling days per
    # weekday too, so clustered journals cannot inflate their own
    # reference rate. Built from the mood-relevant entries so a language-
    # gated corpus cannot manufacture weekday claims from noise moods.
    weekday_days: dict[int, int] = {}
    for entry_day in day_buckets:
        weekday_days[entry_day.weekday()] = weekday_days.get(entry_day.weekday(), 0) + 1

    # Within-person residuals: each entry's mood minus the user's own rolling
    # baseline for that day. All mood ASSOCIATIONS run on these; level claims
    # (the EWMA chart) keep raw values, because "lower than your usual" is a
    # statement about levels, not deviations.
    baselines = _personal_baselines(day_sentiments)
    day_residuals = {day: mood - baselines.get(day, mood) for day, mood in day_sentiments}
    residual_per_entry: list[tuple[JournalEntry, list[str], set[str], float]] = [
        (entry, tokens, themes, sentiment - baselines.get(entry.entry_date, sentiment))
        for entry, tokens, themes, sentiment in mood_entries
    ]
    day_themes: dict[date, set[str]] = {}
    for entry, _, themes, _ in mood_entries:
        day_themes.setdefault(entry.entry_date, set()).update(themes)

    signals: list[_Signal] = []
    if per_entry:
        # One nuisance estimate per run: lag-1 autocorrelation of the daily
        # residual series, deflating per-group n in the link/mood Welch
        # tests (consecutive-day residuals are not independent evidence).
        resid_lag1 = _daily_lag1_autocorr(day_residuals)
        # The recurring-phrase clusters feed BOTH the phrase detector and
        # the topic presence gate (a presence a repeated sentence already
        # explains is the same measurement twice) — computed once per run.
        clusters = _phrase_clusters(window)
        signals.extend(
            _detect_themes(residual_per_entry, weekday_days, len(day_buckets), resid_lag1)
        )
        signals.extend(_detect_phrases(clusters, allow_rumination=language_ok))
        # EWMA baseline re-anchor: once a stored shift is established, the
        # chart re-learns the new normal from post-shift data only.
        anchor = _mood_reanchor_day(store, today)
        shift_series = (
            day_sentiments
            if anchor is None
            else [(day, mood) for day, mood in day_sentiments if day > anchor]
        )
        signals.extend(_detect_mood_shift(shift_series))
        signals.extend(_detect_links(day_themes, day_residuals, today, resid_lag1))
        # Writing calendar from ALL window entry dates (2026-09-20 audit
        # H-10): avoidance and cadence observe WHEN the user journaled —
        # pure writing-metadata, not something the lexicon scored. Under
        # language "other" the mood-day calendar held only mood-TAGGED
        # days, so a daily journal without tags manufactured silence that
        # never happened (probe: a 30/30-day German journal surfaced an
        # "avoidance" card for a user with zero silent days). Mood-day
        # censoring stays where it belongs: the mood series and the
        # weekday mood base rate above.
        entry_day_set = {entry.entry_date for entry in window}
        signals.extend(_detect_avoidance(day_themes, entry_day_set, today))
        signals.extend(_detect_cadence(entry_day_set, today))
        signals.extend(_detect_mood_dynamics(day_sentiments, day_residuals, today))
        energy_inertia = _inertia_signal(
            day_energies,
            "inertia:energy",
            "energy_inertia",
            "day-to-day energy",
            today,
            channel="energy",
        )
        if energy_inertia is not None:
            signals.append(energy_inertia)
        # PA/NA inertia: each affect stream gets its own carryover claim —
        # "your negative feelings have been carrying over" and "your
        # positive feelings have been carrying over" are different
        # observations, and neither is implied by the compound alone.
        pa_inertia = _inertia_signal(
            day_pa,
            "inertia:pa",
            "pa_inertia",
            "day-to-day positive feelings",
            today,
            channel="positive_affect",
        )
        if pa_inertia is not None:
            signals.append(pa_inertia)
        na_inertia = _inertia_signal(
            day_na,
            "inertia:na",
            "na_inertia",
            "day-to-day negative feelings",
            today,
            channel="negative_affect",
        )
        if na_inertia is not None:
            signals.append(na_inertia)
        # Energy ↔ mood coupling: cross-channel concordance on within-person
        # residuals, recent vs the user's own earlier norm. Needs both
        # channels present on enough shared days.
        energy_baselines = _personal_baselines(day_energies)
        energy_residuals = {
            day: value - energy_baselines.get(day, value) for day, value in day_energies
        }
        coupling = _coupling_signal(energy_residuals, day_residuals, today)
        if coupling is not None:
            signals.append(coupling)
        # Sense-making trajectory and activity variety (2026-09-19): the
        # two Pennebaker-lineage / behavioral-activation-adjacent kinds.
        # Both are comparative within-person claims in the same BH family.
        if language_ok:
            sense_making = _detect_sense_making(day_sense, today)
            if sense_making is not None:
                signals.append(sense_making)
        diversity = _detect_activity_diversity(tag_distinct_days, today)
        if diversity is not None:
            signals.append(diversity)
        if language_ok:
            signals.extend(_detect_topics(per_entry, clusters, language))

    # Origin marking (2026-09-17): patterns fed by the user's own tags or
    # structured ratings say so — "you tagged it" is a different evidence
    # statement than "your words mentioned it", and the card copy can be
    # honest about which.
    for signal in signals:
        if signal.label in tag_vocab:
            signal.detail["source"] = "tag"
        if signal.label in person_names:
            signal.detail["source"] = "person"
        if signal.label == SLEEP_CHANNEL_THEME:
            signal.detail["channel"] = "sleep_quality"

    # Multiple-testing correction over the FULL family: every test that ran
    # this run, whether or not its effect gates passed. Correcting only the
    # gate survivors would be selection-then-test — the gates select for
    # extremeness, so the family must count every test and the gates filter
    # the corrected survivors instead.
    tested = [s for s in signals if s.pvalue is not None]
    pvalues: list[float] = []
    for signal in tested:
        # `tested` was filtered above; the explicit assertion lets the static
        # type retain the same invariant without weakening the runtime guard.
        assert signal.pvalue is not None
        pvalues.append(signal.pvalue)
    survivors = statsig.benjamini_hochberg(pvalues, q=ALPHA)
    surviving = {id(s) for s, keep in zip(tested, survivors) if keep}
    qualified: list[_Signal] = []
    for signal in signals:
        if signal.pvalue is None:
            qualified.append(signal)  # direct-measurement family
        elif id(signal) in surviving and signal.gate_ok:
            qualified.append(signal)  # tested claim survives correction
        elif signal.fallback is not None:
            qualified.append(signal.fallback)  # measured presence stands
    # Topic housekeeping happens post-correction: nested labels collapse
    # into the broader kept topic, rising claims outrank presence
    # measurements, and the per-run cap bounds what QUALIFIED — never the
    # family itself.
    ranked_topics = sorted(
        (s for s in qualified if s.kind == "topic"),
        key=lambda s: (s.pvalue is None, -s.occurrences, s.pid),
    )
    kept_tokens: set[str] = set()
    kept_topic_pids: set[str] = set()
    for topic in ranked_topics:
        toks = topic.label.split()
        if any(t in kept_tokens for t in toks) or len(kept_topic_pids) >= TOPIC_MAX_SIGNALS:
            continue
        kept_tokens.update(toks)
        kept_topic_pids.add(topic.pid)
    qualified = [s for s in qualified if s.kind != "topic" or s.pid in kept_topic_pids]
    # A theme may field several weekday candidates (all tested, all in the
    # family); only the best survivor becomes this run's pattern, and a
    # theme whose every candidate failed correction makes no claim.
    best_temporal: dict[str, _Signal] = {}
    for signal in qualified:
        if signal.kind != "temporal":
            continue
        current = best_temporal.get(signal.label)
        if current is None or signal.detail.get("day_count", 0) > current.detail.get(
            "day_count", 0
        ):
            best_temporal[signal.label] = signal
    if best_temporal:
        qualified = [s for s in qualified if s.kind != "temporal"]
        qualified.extend(best_temporal.values())
    qualified.sort(key=lambda s: s.pid)

    _merge_lifecycle(store, qualified, today)

    # Question feedback (2026-09-17): "this resonated / not me" taps ride
    # with the next recompute (encrypted like everything else) and land in
    # the pattern's stored memory — question selection reads them below.
    # Unknown pids are ignored (patterns retire); the counts are capped so
    # a stuck button cannot dominate forever.
    if feedback:
        for pid, resonated in feedback[:100]:
            record = store["patterns"].get(pid)
            if record is None:
                continue
            key = "resonated" if resonated else "not_me"
            counts = dict(record.feedback)
            counts[key] = min(99, counts.get(key, 0) + 1)
            record.feedback = counts

    # Per-pattern mutes (2026-09-19): "stop showing me this" rides the same
    # encrypted feedback channel as the resonated/not_me taps. A mute is a
    # presentation preference, not evidence removal: the pattern's lifecycle
    # keeps evolving underneath, question generation skips it, and the card
    # surfaces with detail.muted=true so the client can offer the unmute.
    # Unknown pids are ignored (patterns retire); the store is capped so a
    # stuck button cannot grow it forever.
    if muted or unmuted:
        muted_store = dict(store.get("muted") or {})
        for pid in (muted or [])[:100]:
            if isinstance(pid, str) and 1 <= len(pid) <= 128 and pid in store["patterns"]:
                muted_store[pid] = True
        for pid in (unmuted or [])[:100]:
            muted_store.pop(pid, None)
        while len(muted_store) > MUTED_STORED_CAP:
            muted_store.pop(next(iter(muted_store)))
        store["muted"] = muted_store

    surfaced_records: list[tuple[StoredPattern, float]] = []
    muted_records: list[tuple[StoredPattern, float]] = []
    for pid in sorted(store["patterns"]):
        record = store["patterns"][pid]
        if record.state not in SURFACED_STATES:
            continue
        evidence = [date.fromisoformat(d) for d in record.evidence_dates]
        surfaced_entry = (record, _decay_strength(evidence, today))
        if pid in (store.get("muted") or {}):
            muted_records.append(surfaced_entry)
        else:
            surfaced_records.append(surfaced_entry)
    for records in (surfaced_records, muted_records):
        records.sort(
            key=lambda item: (
                STATE_RANK.get(item[0].state, 3),
                -item[1],
                -item[0].occurrences,
                item[0].pid,
            )
        )
    surfaced_records = surfaced_records[:MAX_SURFACED]
    muted_records = muted_records[:MUTED_SURFACED_CAP]

    n_window_entries = len(per_entry)
    surfaced: list[Pattern] = []
    patterns_new = 0
    patterns_fading = 0
    for record, strength in surfaced_records + muted_records:
        is_muted = record.pid in (store.get("muted") or {})
        # A muted card is never "new" either: the flag exists to draw the
        # eye, and the eye is deliberately elsewhere.
        is_new = (
            bool(
                record.first_qualified
                and (today - date.fromisoformat(record.first_qualified)).days
                <= NEW_PATTERN_WINDOW_DAYS
            )
            and not is_muted
        )
        if is_new:
            patterns_new += 1
        if record.state == "fading":
            patterns_fading += 1
        surfaced.append(
            Pattern(
                kind=record.kind,
                label=record.label,
                occurrences=record.occurrences,
                confidence=round(strength, 3),
                detail={
                    **record.detail,
                    # Stable identity for external attachment (therapist notes):
                    # phrase-cluster pids are anchored on internal sentence
                    # refs, so kind+label alone cannot reconstruct them.
                    "pattern_pid": record.pid,
                    "pattern_state": record.state,
                    "strength": round(strength, 3),
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "is_new": is_new,
                    "sample_days": n_window_entries,
                    # The days whose entries fed this pattern (capped at
                    # EVIDENCE_DATES_CAP). Powers the evidence drill-down: the
                    # patient's app and the therapist portal fetch the entries
                    # for exactly these dates. Dates only — never quotes text.
                    "evidence_dates": list(record.evidence_dates),
                    # Question-feedback taps (encrypted at rest with the rest
                    # of the state): powers feedback-aware question ranking.
                    "feedback": dict(record.feedback),
                    # Patient-side mute (2026-09-19): the client collapses
                    # these cards and the question engine skips them; the
                    # flag rides the payload so the unmute has something to
                    # act on. Computed at surfacing time from the muted set.
                    **({"muted": True} if is_muted else {}),
                    # Crisis interlock: when the wording itself is suppress-tier,
                    # the card is marked so the client renders the NON-QUOTING
                    # variant (and the question engine never touches it —
                    # enforced again there). Computed at surfacing time, never
                    # stored: the flag follows the current phrase contract.
                    **({"sensitive": True} if _record_is_sensitive(record) else {}),
                },
            )
        )

    history = store["history"]
    surfaced_pids = [r.pid for r, _ in surfaced_records]
    if not history or history[-1][0] != _iso(today):
        history.append([_iso(today), surfaced_pids])
        del history[:-HISTORY_DAYS]
    else:
        history[-1] = [_iso(today), surfaced_pids]

    # Audit round 2 (2026-09-21) F-2: the D-3 rule for the reported average
    # — an entry with NO text and NO explicit mood tag is a corpus-budget
    # truncation or empty submit carrying zero mood evidence, and averaging
    # its fabricated neutral 0.0 pulled "average reading" (portal) toward
    # the middle. Tagged entries keep counting: the user's own report.
    sentiments = [
        s for entry, _, _, s in per_entry if entry.text or entry.sentiment is not None
    ]
    stats = {
        "total_entries": len(per_entry),
        # Honesty signal (2026-09-19): the detected analysis language;
        # "other" means the engine stepped aside for text-derived claims
        # (clients render an honest note instead of silence).
        "language": language,
        # Distinct WRITING days (audit H-10): under language "other" the
        # mood-bucket calendar counted only mood-tagged days and understated
        # the user's actual journaling cadence.
        "active_days": len({entry.entry_date for entry in window}),
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
