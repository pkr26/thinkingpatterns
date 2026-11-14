"""Native default-language snapshot and nonempty question pool interfaces."""

from datetime import date

from app.services import questions
from app.services.patterns import Pattern


def test_default_english_and_explicit_english_share_the_same_daily_pool_snapshot(
    monkeypatch,
):
    monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
    today = date(2026, 10, 22)
    patterns = [Pattern("temporal", "guitar", 5, 0.5, {"day": "Monday"})]
    patterned = questions.build_pool(patterns)
    generic = questions.build_pool([], "en")
    owner = next(
        f"english-default-{i}"
        for i in range(1000)
        if patterned[
            (today.toordinal() + questions.user_rotation_offset(f"english-default-{i}"))
            % len(patterned)
        ]
        not in generic
    )
    first = questions.question_for_today(owner, patterns, today)
    assert first not in generic
    assert questions.question_for_today(owner, [], today, "en") == first


def test_native_language_pools_always_supply_a_real_generic_question(monkeypatch):
    monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
    today = date(2026, 10, 22)
    for language in ("en", "es", "other"):
        pool = questions.build_pool([], language)
        assert pool and all(isinstance(question, str) and question for question in pool)
        question = questions.question_for_today("native-pool", [], today, language)
        assert question in pool
