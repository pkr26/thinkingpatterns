"""Daily reflective question generation.

Philosophy invariants, enforced by tests:
  * every question is a question (ends with "?"),
  * no advice language (the word "should" never appears),
  * one deterministic question per user per day (stable within the day).
"""

from __future__ import annotations

import math
import zlib
from datetime import date
from typing import Sequence

from . import crisis
from .patterns import Pattern

# Crisis interlock: when a recurring thought is crisis-adjacent (suicidal
# ideation, self-harm), reflecting it back as an engaging question ("what
# would you say to it if you could?") is the wrong move for a journaling
# tool — such patterns are skipped for question generation entirely and the
# pool falls through to neutral generic questions. The client's offline
# crisis-resources screen is the supported path for this content. The
# phrase contract lives in services/crisis.py (embedded from
# shared/crisis_phrases.json); questions consume the broad SUPPRESS tier.

GENERIC_QUESTIONS: tuple[str, ...] = (
    "What took up most space in your mind today?",
    "What felt different today compared to yesterday?",
    "When did you feel most like yourself today?",
    "What's one small thing that went right today?",
    "What thought repeated itself today?",
    "If today had a title, what would it be?",
    "What are you carrying into tomorrow?",
    "What did you notice today that you usually overlook?",
    "What did your body notice before your mind did today?",
    "What was the quietest moment of your day?",
    "What sound do you remember from today?",
    "What did you see today that you'd want to see again?",
    "What would you say to a friend who had your day?",
    "What's something you did today that took effort?",
    "What did you forgive yourself for today?",
    "What would make tomorrow 1% kinder to you?",
    "What are three things that went okay today?",
    "Who made your day a little lighter today?",
    "What's something you're looking forward to?",
    "What comforted you today?",
    "What's one thing worth keeping from today?",
    "What mattered most to you today?",
    "When did today feel meaningful?",
    "What value showed up in something you did today?",
    "What would you like more of in your life?",
    "If your mood today had a texture, what would it feel like?",
    "What emotion visited you most today?",
    "What emotion surprised you today?",
    "Where in your body did today's strongest feeling live?",
    "Who did you think about today?",
    "What conversation stayed with you today?",
    "When did you feel understood today?",
    "When did you feel alone today, and what was that like?",
    "What gave you energy today?",
    "What drained you today?",
    "What did you say no to today?",
    "What did you let go of today?",
    "What part of the day felt longest?",
    "When were you most absorbed in something today?",
    "What did today's pace feel like?",
    "What was the hardest part of today?",
    "What did you get through today that felt heavy?",
    "What are you avoiding, gently speaking?",
    "What worry got smaller once you wrote it down?",
    "What are you curious about right now?",
    "What's a question you're sitting with lately?",
    "What would you like to remember about this time?",
    "What's one small thing you're curious to attempt tomorrow?",
    "What did you taste today that you remember?",
    "Where did you feel most at ease today?",
    "What's a place you'd rather have been today?",
    "What feels most like 'you' these days?",
    "What's changing in you lately, slowly?",
    "What has stayed steady in you lately?",
    "If today were weather, what was it?",
    "What would tomorrow look like in an ideal world?",
    "If you could send yourself a note this morning, what would it say?",
    "What did you do today purely because you wanted to?",
    "What did today ask of you?",
    "What are you grateful to past-you for today?",
)

# 2026-09-26 audit M-B3: the Spanish generic pool — the position-by-position
# counterpart of GENERIC_QUESTIONS (shared/generic_questions_es.json, E-3
# 2026-09-21; the mobile client already rotates its day-1 questions over
# it). Post-threshold question generation now selects it when the brain's
# detected language is "es", so Spanish users no longer receive English
# templates around Spanish pattern labels. Positional parity with the EN
# pool is pinned by test (same length, same rotation index → the
# equivalent question in either language).
GENERIC_QUESTIONS_ES: tuple[str, ...] = (
    '¿Qué ocupó la mayor parte de su mente hoy?',
    '¿Qué se sintió diferente hoy en comparación con ayer?',
    '¿Cuándo se sintió más usted mismo o usted misma hoy?',
    '¿Qué pequeña cosa salió bien hoy?',
    '¿Qué pensamiento se repitió hoy?',
    'Si hoy tuviera un título, ¿cuál sería?',
    '¿Qué se lleva consigo hacia mañana?',
    '¿Qué notó hoy que suele pasar por alto?',
    '¿Qué notó su cuerpo antes que su mente hoy?',
    '¿Cuál fue el momento más tranquilo de su día?',
    '¿Qué sonido recuerda de hoy?',
    '¿Qué vio hoy que le gustaría volver a ver?',
    '¿Qué le diría a un amigo que hubiera tenido su día?',
    '¿Qué hizo hoy que le exigió esfuerzo?',
    '¿Qué se perdonó hoy?',
    '¿Qué haría que mañana fuera un 1% más amable con usted?',
    '¿Qué tres cosas salieron más o menos bien hoy?',
    '¿Quién hizo su día un poco más ligero hoy?',
    '¿Hay algo que espera con ilusión?',
    '¿Qué la confortó hoy?',
    '¿Qué vale la pena conservar de hoy?',
    '¿Qué fue lo que más le importó hoy?',
    '¿Cuándo sintió que hoy tenía sentido?',
    '¿Qué valor suyo apareció en algo que hizo hoy?',
    '¿Qué le gustaría tener más en su vida?',
    'Si el estado de ánimo de hoy tuviera una textura, ¿cómo se sentiría?',
    '¿Qué emoción lo visitó más hoy?',
    '¿Qué emoción lo sorprendió hoy?',
    '¿En qué parte del cuerpo vivió hoy el sentimiento más fuerte?',
    '¿En quién pensó hoy?',
    '¿Qué conversación se quedó con usted hoy?',
    '¿Cuándo se sintió comprendido o comprendida hoy?',
    '¿Cuándo se sintió solo o sola hoy, y cómo fue eso?',
    '¿Qué le dio energía hoy?',
    '¿Qué lo agotó hoy?',
    '¿A qué dijo no hoy?',
    '¿Qué dejó ir hoy?',
    '¿Qué parte del día se sintió más larga?',
    '¿Cuándo estuvo más absorbido o absorbida en algo hoy?',
    '¿Cómo sintió el ritmo de hoy?',
    '¿Cuál fue la parte más difícil de hoy?',
    '¿Qué atravesó hoy que se sintió pesado?',
    '¿Qué está evitando, dicho con gentileza?',
    '¿Qué preocupación se hizo más pequeña al escribirla?',
    '¿Sobre qué tiene curiosidad ahora mismo?',
    '¿Qué pregunta lleva rondándole últimamente?',
    '¿Qué le gustaría recordar de esta época?',
    '¿Qué pequeña cosa tiene curiosidad por intentar mañana?',
    '¿Qué saboreó hoy y recuerda?',
    '¿Dónde se sintió más a gusto hoy?',
    '¿En qué lugar habría preferido estar hoy?',
    "¿Qué se siente más como 'usted' en estos días?",
    '¿Qué está cambiando en usted lenta y lentamente?',
    '¿Qué se ha mantenido estable en usted últimamente?',
    'Si hoy fuera un clima, ¿cuál habría sido?',
    '¿Cómo sería mañana en un mundo ideal?',
    'Si pudiera enviarse una nota esta mañana, ¿qué diría?',
    '¿Qué hizo hoy puramente porque quería?',
    '¿Qué le pidió hoy el día?',
    '¿Por qué le agradece hoy a su yo del pasado?',
)

TEMPLATE_BY_KIND: dict[str, tuple[str, ...]] = {
    "temporal": (
        "'{label}' shows up mostly on {day}s — what do those days have in common?",
        "You often write about '{label}' on {day}s. What usually happens right before?",
        "When {day} comes around and '{label}' is on your mind, where do you notice it first?",
    ),
    "mood_correlation": (
        # Direction-aware: the brain reports both "lower" and "higher"
        # (protective factors); the question must not contradict the data.
        "Your entries read {direction} on days '{label}' appears — what does that day usually look like?",
        "When '{label}' is present, how does your body usually respond?",
        "What's one difference between days with '{label}' and days without?",
    ),
    "recurring_phrase": (
        'The phrase "{label}" keeps returning in your writing — what does it mean to you?',
        'You\'ve written "{label}" several times now. When did you first notice it?',
        'When "{label}" shows up in an entry, what usually preceded it?',
    ),
    "avoidance": (
        "The day after '{label}' comes up, you often don't write — what do those quieter days hold?",
        "You tend to go quiet after '{label}' days ({share}% of them). What is the day after like when it happens?",
    ),
    "cadence": (
        "Your writing rhythm has been less regular than it used to be — what has been shaping the gaps?",
        "There have been longer silences between writing days lately. What happens in those stretches?",
    ),
    "mood_shift": (
        "Your entries have read {direction} than your usual baseline lately — what has been going on around that?",
        "Your mood baseline has shifted {direction} these past weeks — when do you first remember noticing it?",
        "Things have read {direction} than your baseline recently — what do the days on either side of that change look like?",
    ),
    "link": (
        # Lagged day-after links (Konjarski et al. 2018 sleep→next-day
        # mood): the question points at the day(s) in between, never at a
        # cause. Wording is lag-neutral — the claim's modal lag lives in
        # the pattern detail.
        "'{label}' days are often followed by {direction} days — what do the in-between days usually contain?",
        "You've noticed '{label}' days are followed by {direction} days. What do you do differently on the days between?",
        "When '{label}' was on your mind recently, how did the following day start?",
    ),
    "inertia": (
        "Your mood has been carrying over from day to day more than usual — what does a stuck stretch feel like from the inside?",
        "Lately one day's mood leans on the next more than it used to. When did that rhythm start?",
        "Some weeks drag their mood from day to day. What tends to break the pattern for you?",
    ),
    "energy_inertia": (
        "Your energy has been carrying over from day to day more than usual — what does a drained stretch look like from the inside?",
        "Lately one day's energy leans on the next more than it used to. When did that start?",
        "Some weeks drag their energy from day to day. What tends to lift yours?",
    ),
    "pa_inertia": (
        "Your positive feelings have been carrying over from day to day more than usual — what does a good stretch feel like from the inside?",
        "Lately one good day seems to lean on the next. When did that rhythm start?",
        "Some weeks carry their brightness from day to day. What feeds yours?",
    ),
    "na_inertia": (
        "Your negative feelings have been carrying over from day to day more than usual — what does a hard stretch feel like from the inside?",
        "Lately one hard day seems to lean on the next. When did that start?",
        "Some weeks drag their weight from day to day. What tends to interrupt it for you?",
    ),
    "energy_mood_coupling": (
        "Your energy and mood have been tracking each other more closely than usual — what do those days look like together?",
        "Lately when your energy shifts, your mood tends to move with it. What sits in the middle of that for you?",
        "Your energy and mood have been moving in step lately. When do you first notice them linking up?",
    ),
    "sense_making": (
        "Your writing has joined events to reasons more than it used to — what were you working out?",
        "You've leaned on words like 'because' and 'realize' more lately. What clicked into place?",
        "Your entries have moved from describing toward understanding. What changed to make that possible?",
    ),
    "activity_diversity": (
        "The variety of things you tag has {direction} compared with your usual — what has that been like?",
        "Compared with your own usual weeks, your activity variety has {direction} — what fills the difference for you?",
        "Your activity variety has {direction} these past weeks — what does a usual week hold for you now?",
    ),
    "instability": (
        "Your daily mood has swung more than usual these past weeks — what do the peaks and dips have in common?",
        "The distance between your good days and hard days has grown lately. What sits at either end?",
        "When your mood moves quickly day to day, what helps you steady it?",
    ),
    "rumination": (
        'The thought "{label}" has returned several times now — what does it ask of you when it visits?',
        'You\'ve written "{label}" more than once across different weeks. What usually triggers its return?',
        'When "{label}" shows up again, what would you say to it if you could?',
    ),
    # Trend-aware (2026-09-20 audit fix M-24): the DEFAULT tuple is the
    # rising-trend set — "taking up more space lately" is a claim only a
    # rising share can back. A steady-presence topic renders the steady
    # set below, mirroring Pattern.describe()'s trend branch exactly
    # (services/patterns.py); the two neutral templates are shared so the
    # pool size is stable either way.
    "topic": (
        "'{label}' has been taking up more space in your writing lately — what is that about for you?",
        "You keep returning to '{label}' across different days. What does it mean right now?",
        "When did '{label}' first start mattering to you in this stretch of your life?",
    ),
}

TOPIC_TEMPLATES_STEADY: tuple[str, ...] = (
    "'{label}' is a steady presence in your writing — what is it holding for you these days?",
    "You keep returning to '{label}' across different days. What does it mean right now?",
    "When did '{label}' first start mattering to you in this stretch of your life?",
)

# 2026-09-26 audit M-B3: the Spanish template set — every EN kind has an ES
# counterpart tuple (rendered only when the brain's detected language is
# "es"), so a Spanish corpus never mints English post-threshold questions.
# The {label} placeholder carries the user's OWN words (already Spanish);
# {day} and {direction} arrive as English engine values and are translated
# at render time via the maps below.
TEMPLATE_BY_KIND_ES: dict[str, tuple[str, ...]] = {
    "temporal": (
        "'{label}' aparece sobre todo los {day}s — ¿qué tienen en común esos días?",
        "Suele escribir sobre '{label}' los {day}s. ¿Qué suele pasar justo antes?",
        "Cuando llega el {day} y '{label}' está en su mente, ¿dónde lo nota primero?",
    ),
    "mood_correlation": (
        # Direction-aware like the EN set: the brain reports both "lower"
        # and "higher" (protective factors); the question must not
        # contradict the data.
        "Sus entradas suenan con un ánimo {direction} los días en que aparece "
        "'{label}' — ¿cómo es normalmente ese día?",
        "Cuando '{label}' está presente, ¿cómo responde normalmente su cuerpo?",
        "¿Cuál es una diferencia entre los días con '{label}' y los días sin él?",
    ),
    "recurring_phrase": (
        'La frase "{label}" sigue volviendo en lo que escribe — ¿qué significa para usted?',
        'Ha escrito "{label}" varias veces ya. ¿Cuándo la notó por primera vez?',
        'Cuando "{label}" aparece en una entrada, ¿qué lo precedió normalmente?',
    ),
    "avoidance": (
        "Al día siguiente de que sale '{label}', muchas veces no escribe — "
        "¿qué contienen esos días más callados?",
        "Suele quedarse en silencio después de los días de '{label}' ({share}% de "
        "ellos). ¿Cómo es el día siguiente cuando eso pasa?",
    ),
    "cadence": (
        "Su ritmo de escritura ha sido menos regular que antes — ¿qué ha ido "
        "moldeando los huecos?",
        "Ha habido silencios más largos entre días de escritura últimamente. "
        "¿Qué pasa en esos tramos?",
    ),
    "mood_shift": (
        "Últimamente sus entradas han sonado con un ánimo {direction} que su "
        "línea base habitual — ¿qué ha estado pasando alrededor de eso?",
        "Su línea base de ánimo ha estado {direction} estas últimas semanas — "
        "¿cuándo lo recuerda haber notado por primera vez?",
        "Las cosas han sonado {direction} que su línea base últimamente — ¿cómo "
        "se ven los días a cada lado de ese cambio?",
    ),
    "link": (
        # Lag-neutral wording like the EN set: the claim points at the
        # day(s) in between, never at a cause.
        "Los días de '{label}' suelen ir seguidos de días con un ánimo "
        "{direction} — ¿qué contienen normalmente los días intermedios?",
        "Ha notado que los días de '{label}' van seguidos de días con un ánimo "
        "{direction}. ¿Qué hace distinto en los días entre medias?",
        "Cuando '{label}' estuvo en su mente últimamente, ¿cómo empezó el día siguiente?",
    ),
    "inertia": (
        "Su ánimo se ha venido arrastrando de un día al otro más de lo habitual — "
        "¿cómo se siente por dentro un tramo atascado?",
        "Últimamente el ánimo de un día se apoya más que antes en el siguiente. "
        "¿Cuándo empezó ese ritmo?",
        "Hay semanas que arrastran su ánimo de día en día. ¿Qué suele romper el patrón para usted?",
    ),
    "energy_inertia": (
        "Su energía se ha venido arrastrando de un día al otro más de lo habitual — "
        "¿cómo se ve por dentro un tramo agotado?",
        "Últimamente la energía de un día se apoya más que antes en el siguiente. "
        "¿Cuándo empezó eso?",
        "Hay semanas que arrastran su energía de día en día. ¿Qué suele levantar la suya?",
    ),
    "pa_inertia": (
        "Sus sentimientos positivos se han venido arrastrando de un día al otro "
        "más de lo habitual — ¿cómo se siente por dentro un buen tramo?",
        "Últimamente un buen día parece apoyarse en el siguiente. ¿Cuándo empezó ese ritmo?",
        "Hay semanas que llevan su brillo de día en día. ¿Qué alimenta el suyo?",
    ),
    "na_inertia": (
        "Sus sentimientos difíciles se han venido arrastrando de un día al otro "
        "más de lo habitual — ¿cómo se siente por dentro un tramo duro?",
        "Últimamente un día duro parece apoyarse en el siguiente. ¿Cuándo empezó eso?",
        "Hay semanas que arrastran su peso de día en día. ¿Qué suele interrumpirlo para usted?",
    ),
    "energy_mood_coupling": (
        "Su energía y su ánimo han estado siguiéndose más de lo habitual — ¿cómo "
        "se ven juntos esos días?",
        "Últimamente, cuando su energía cambia, su ánimo tiende a moverse con "
        "ella. ¿Qué se pone en medio de eso para usted?",
        "Su energía y su ánimo han ido al paso últimamente. ¿Cuándo los nota engancharse por primera vez?",
    ),
    "sense_making": (
        "Lo que escribe ha estado uniendo hechos con razones más que antes — "
        "¿qué estaba resolviendo?",
        "Se ha apoyado más en palabras como 'porque' y 'darme cuenta' "
        "últimamente. ¿Qué encajó en su lugar?",
        "Sus entradas han ido de describir hacia comprender. ¿Qué cambió para que eso fuera posible?",
    ),
    "activity_diversity": (
        "La variedad de lo que etiqueta se ha {direction} comparada con su "
        "costumbre — ¿cómo ha sido eso para usted?",
        "Comparado con sus semanas habituales, su variedad de actividades se ha "
        "{direction} — ¿qué llena la diferencia para usted?",
        "Su variedad de actividades se ha {direction} estas últimas semanas — "
        "¿cómo es ahora una semana normal para usted?",
    ),
    "instability": (
        "Su ánimo diario ha oscilado más de lo habitual estas últimas semanas — "
        "¿qué tienen en común los picos y las caídas?",
        "La distancia entre sus buenos días y sus días duros ha crecido "
        "últimamente. ¿Qué hay en cada extremo?",
        "Cuando su ánimo se mueve rápido de un día a otro, ¿qué le ayuda a estabilizarlo?",
    ),
    "rumination": (
        'El pensamiento "{label}" ha vuelto varias veces ya — ¿qué le pide cuando lo visita?',
        'Ha escrito "{label}" más de una vez en semanas distintas. ¿Qué suele provocar su regreso?',
        'Cuando "{label}" vuelve a aparecer, ¿qué le diría si pudiera?',
    ),
    # Trend-aware like the EN set: rising-trend templates by default, the
    # steady-presence set below for non-rising trends — mirroring the EN
    # detail.trend branch exactly.
    "topic": (
        "'{label}' ha estado ocupando más espacio en lo que escribe "
        "últimamente — ¿qué es eso para usted?",
        "Sigue volviendo a '{label}' en días distintos. ¿Qué significa para usted ahora mismo?",
        "¿Cuándo empezó '{label}' a importarle en esta etapa de su vida?",
    ),
}

TOPIC_TEMPLATES_STEADY_ES: tuple[str, ...] = (
    "'{label}' es una presencia constante en lo que escribe — ¿qué le está guardando estos días?",
    "Sigue volviendo a '{label}' en días distintos. ¿Qué significa para usted ahora mismo?",
    "¿Cuándo empezó '{label}' a importarle en esta etapa de su vida?",
)

# Engine detail values are English wire values (DAY_NAMES / the detectors'
# "lower"/"higher"/"narrowed"/"widened"); the ES templates phrase around
# the translated forms. Unknown values pass through unchanged (a client
# tag or a future detector value is still the user's own content).
_WEEKDAYS_ES: dict[str, str] = {
    "Monday": "lunes",
    "Tuesday": "martes",
    "Wednesday": "miércoles",
    "Thursday": "jueves",
    "Friday": "viernes",
    "Saturday": "sábado",
    "Sunday": "domingo",
    "that day": "ese día",
}
_DIRECTION_ES: dict[str, str] = {
    "lower": "más bajo",
    "higher": "más alto",
    "narrowed": "reducido",
    "widened": "ampliado",
}

MAX_PATTERN_QUESTIONS = 5


def _percent(value: object) -> str:
    """0.31 -> "31"; "—" for anything non-numeric (templates render it)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return str(int(round(float(value) * 100)))
    return "—"


def render_pattern_questions(pattern: Pattern, language: str = "en") -> list[str]:
    """Render the question variants for one pattern.

    2026-09-26 audit M-B3: ``language`` selects the template set — "es"
    renders the Spanish templates (with the engine's English weekday/
    direction detail values translated), every other value renders the
    historical English set byte-identically to the pre-localization
    behavior. "other" (a detected language the engine cannot classify)
    keeps English: the generic pool is the fallback there anyway.
    """
    spanish = language == "es"
    templates = (TEMPLATE_BY_KIND_ES if spanish else TEMPLATE_BY_KIND).get(pattern.kind)
    if pattern.kind == "topic":
        # Steady-presence topics must not render the rising-trend claim
        # ("taking up more space lately") — the template is selected by
        # the pattern's own detail.trend, exactly like Pattern.describe().
        if pattern.detail.get("trend", "steady") != "rising":
            templates = TOPIC_TEMPLATES_STEADY_ES if spanish else TOPIC_TEMPLATES_STEADY
    if not templates:
        return []
    if spanish:
        # Translate the engine's English detail values for the ES templates
        # only — the EN path renders raw values exactly as before.
        day = _WEEKDAYS_ES.get(pattern.detail.get("day", "that day"), pattern.detail.get("day"))
        direction = _DIRECTION_ES.get(
            pattern.detail.get("direction", "lower"), pattern.detail.get("direction")
        )
    else:
        day = pattern.detail.get("day", "that day")
        direction = pattern.detail.get("direction", "lower")
    rendered = []
    for template in templates:
        # Extra kwargs are ignored by templates that don't reference them,
        # so legacy kinds render byte-identically to their pinned strings.
        rendered.append(
            template.format(
                label=pattern.label,
                day=day,
                direction=direction,
                # Evidence anchoring (2026-09-17): percentages computed from the
                # pattern's own numbers, so questions feel grounded ("31% of
                # them") instead of templated. Ints only — no p-values, no
                # statistics lecture in a daily question.
                share=_percent(pattern.detail.get("share")),
                mentions=pattern.occurrences,
            )
        )
    return rendered


def pattern_is_sensitive(pattern: Pattern) -> bool:
    """True when a pattern must never be quoted back as a question.

    Three independent tripwires, cheapest last:
      * the brain marked the surfaced card ``sensitive`` (its label or a
        stored variant matched the suppress tier at surfacing time);
      * the label itself matches the suppress tier (patterns that arrived
        without the flag — LLM extras, legacy payloads);
      * any stored variant string matches (the representative may be the
        mildest phrasing of a cluster whose other members are not).
    """
    if pattern.detail.get("sensitive"):
        return True
    if crisis.matches_suppress(pattern.label):
        return True
    variants = pattern.detail.get("variants")
    if isinstance(variants, list):
        if any(isinstance(v, str) and crisis.matches_suppress(v) for v in variants):
            return True
    return False


def pattern_is_muted(pattern: Pattern) -> bool:
    """True when the patient muted this pattern (2026-09-19): the card
    surfaces in the client's collapsed "muted" section, and question
    generation skips it entirely — a muted topic must not come back as a
    reflective question. Module-level so the insights API re-derives the
    SAME pool when routing feedback taps back to pattern ids."""
    return bool(pattern.detail.get("muted")) is True


def feedback_rank(p: Pattern) -> tuple[int, int, int, str]:
    """Feedback-aware ordering (2026-09-17): patterns the user said "this
    resonated" about float up, "not me" sinks — the question learns from
    its reader without ever tracking WHAT was answered (only the taps on
    the pattern itself, stored encrypted in the brain state). Module-level
    so the insights API re-derives the SAME ordering when routing feedback
    taps back to pattern ids."""
    fb = p.detail.get("feedback") if isinstance(p.detail, dict) else None
    resonated = fb.get("resonated", 0) if isinstance(fb, dict) else 0
    not_me = fb.get("not_me", 0) if isinstance(fb, dict) else 0
    return (min(not_me, 3), -min(resonated, 3), -p.occurrences, p.label)


def build_pool(patterns: Sequence[Pattern], language: str = "en") -> list[str]:
    """Question pool: rendered variants for top patterns first, then generic.

    Crisis-adjacent patterns are excluded — their reflective templates
    would ask the user to engage with a suicidal or self-harm thought; the
    neutral generic pool serves instead.

    2026-09-26 audit M-B3: ``language`` selects the generic pool (the ES
    counterpart is positionally parallel to the EN list), and the same
    value reaches render_pattern_questions for the pattern templates.
    """
    generic = GENERIC_QUESTIONS_ES if language == "es" else GENERIC_QUESTIONS
    pool: list[str] = []
    for pattern in sorted(patterns, key=feedback_rank)[:MAX_PATTERN_QUESTIONS]:
        if pattern_is_muted(pattern):
            continue
        if pattern_is_sensitive(pattern):
            continue
        pool.extend(render_pattern_questions(pattern, language))
    pool.extend(generic)
    # Belt and braces: no rendered question may quote crisis content even
    # if a label slipped past the pattern-side filter some other way.
    pool = [q for q in pool if not crisis.matches_suppress(q)]
    unique: list[str] = []
    seen: set[str] = set()
    for q in pool:
        if q in seen:
            continue
        seen.add(q)
        unique.append(q)
    return unique


def user_rotation_offset(user_id: str) -> int:
    """Stable per-user rotation offset (hash() is process-randomized; never use it)."""
    return zlib.crc32(user_id.encode("utf-8"))


def question_for_today(
    user_id: str, patterns: Sequence[Pattern], today: date, language: str = "en"
) -> str:
    """One deterministic question per user per day.

    2026-09-26 audit M-B3: the language selects the whole pool (templates
    and generics together), so the same corpus still yields the same
    question — determinism is per-language, and the ES pool is
    positionally parallel to the EN one."""
    pool = build_pool(patterns, language) or list(
        GENERIC_QUESTIONS_ES if language == "es" else GENERIC_QUESTIONS
    )
    index = (today.toordinal() + user_rotation_offset(user_id)) % len(pool)
    return pool[index]
