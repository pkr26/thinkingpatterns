"""Daily reflective question generation.

Philosophy invariants, enforced by tests:
  * every question is a question (ends with "?"),
  * no advice language (the word "should" never appears),
  * one deterministic question per user per day (stable within the day).
"""

from __future__ import annotations

import re
import zlib
from datetime import date
from typing import Sequence

from .patterns import Pattern

# Crisis interlock: when a recurring thought is crisis-adjacent (suicidal
# ideation, self-harm), reflecting it back as an engaging question ("what
# would you say to it if you could?") is the wrong move for a journaling
# tool — such patterns are skipped for question generation entirely and the
# pool falls through to neutral generic questions. The client's offline
# crisis-resources screen is the supported path for this content.
CRISIS_LABEL_RE = re.compile(
    r"suicid\w*|kill(?:ing)? (?:myself|me)|want(?:ed)? to (?:die|be dead|disappear)"
    r"|end(?:ing)? (?:my life|it all)|self[- ]?harm(?:ing)?|hurt(?:ing)? (?:myself|me)"
    r"|no reason to live|better off dead|don'?t want to (?:live|be here|wake up)"
    r"|not want(?:ing)? to (?:live|be here)",
    re.IGNORECASE,
)

GENERIC_QUESTIONS: tuple[str, ...] = (
    "What took up most space in your mind today?",
    "What felt different today compared to yesterday?",
    "When did you feel most like yourself today?",
    "What's one small thing that went right today?",
    "What thought repeated itself today?",
    "If today had a title, what would it be?",
    "What are you carrying into tomorrow?",
    "What did you notice today that you usually overlook?",
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
    "mood_shift": (
        "Your entries have read {direction} than your usual baseline lately — what has been going on around that?",
        "Your mood baseline has shifted {direction} these past weeks — when do you first remember noticing it?",
        "Things have read {direction} than your baseline recently — what do the days on either side of that change look like?",
    ),
    "link": (
        # Lagged day-after links (Bourke et al. 2026 sleep→next-day mood):
        # the question points at the day in between, not a cause.
        "The day after '{label}' comes up, your entries read {direction} — what do those in-between days usually contain?",
        "You've noticed '{label}' days are followed by {direction} days. What do you do differently on the days between?",
        "When '{label}' was on your mind yesterday, how did today start?",
    ),
    "inertia": (
        "Your mood has been carrying over from day to day more than usual — what does a stuck stretch feel like from the inside?",
        "Lately one day's mood leans on the next more than it used to. When did that rhythm start?",
        "Some weeks drag their mood from day to day. What tends to break the pattern for you?",
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
    "topic": (
        "'{label}' has been taking up more space in your writing lately — what is that about for you?",
        "You keep returning to '{label}' across different days. What does it mean right now?",
        "When did '{label}' first start mattering to you in this stretch of your life?",
    ),
}

MAX_PATTERN_QUESTIONS = 5


def render_pattern_questions(pattern: Pattern) -> list[str]:
    templates = TEMPLATE_BY_KIND.get(pattern.kind)
    if not templates:
        return []
    rendered = []
    for template in templates:
        # Extra kwargs are ignored by templates that don't reference them,
        # so legacy kinds render byte-identically to their pinned strings.
        rendered.append(template.format(
            label=pattern.label,
            day=pattern.detail.get("day", "that day"),
            direction=pattern.detail.get("direction", "lower"),
        ))
    return rendered


def build_pool(patterns: Sequence[Pattern]) -> list[str]:
    """Question pool: rendered variants for top patterns first, then generic.

    Crisis-adjacent pattern labels are excluded — their reflective
    templates would ask the user to engage with a suicidal or self-harm
    thought; the neutral generic pool serves instead.
    """
    pool: list[str] = []
    for pattern in sorted(patterns, key=lambda p: (-p.confidence, -p.occurrences, p.label))[:MAX_PATTERN_QUESTIONS]:
        if CRISIS_LABEL_RE.search(pattern.label):
            continue
        pool.extend(render_pattern_questions(pattern))
    pool.extend(GENERIC_QUESTIONS)
    # Belt and braces: no rendered question may quote crisis content even
    # if a label slipped past the pattern-side filter some other way.
    pool = [q for q in pool if not CRISIS_LABEL_RE.search(q)]
    seen: set[str] = set()
    unique = [q for q in pool if not (q in seen or seen.add(q))]
    return unique


def user_rotation_offset(user_id: str) -> int:
    """Stable per-user rotation offset (hash() is process-randomized; never use it)."""
    return zlib.crc32(user_id.encode("utf-8"))


def question_for_today(user_id: str, patterns: Sequence[Pattern], today: date) -> str:
    pool = build_pool(patterns) or list(GENERIC_QUESTIONS)
    index = (today.toordinal() + user_rotation_offset(user_id)) % len(pool)
    return pool[index]
