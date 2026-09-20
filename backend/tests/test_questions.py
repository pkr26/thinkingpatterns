"""Daily question engine: determinism, rotation, and the no-advice philosophy."""

from __future__ import annotations

from datetime import date, timedelta

from app.services import questions
from app.services.patterns import Pattern

TODAY = date(2026, 9, 3)

PATTERNS = [
    Pattern("temporal", "work", 12, 0.9, {"day": "Sunday"}),
    Pattern("mood_correlation", "sleep", 8, 0.6, {"mood_delta": 0.5}),
    Pattern("recurring_phrase", "want to disappear", 4, 0.4, {}),
]


class TestPhilosophyInvariants:
    def test_every_template_is_a_question(self):
        candidates = list(questions.GENERIC_QUESTIONS)
        for templates in questions.TEMPLATE_BY_KIND.values():
            candidates.extend(templates)
        for question in candidates:
            assert question.rstrip().endswith("?"), f"not a question: {question!r}"

    def test_no_advice_language(self):
        candidates = list(questions.GENERIC_QUESTIONS)
        for templates in questions.TEMPLATE_BY_KIND.values():
            candidates.extend(templates)
        for question in candidates:
            lowered = question.lower()
            assert "should" not in lowered, f"advice language detected: {question!r}"
            assert "you must" not in lowered
            assert "try to" not in lowered

    def test_rendered_pattern_questions(self):
        rendered = questions.render_pattern_questions(PATTERNS[0])
        assert len(rendered) == 3
        assert all("work" in q and "?" in q for q in rendered)
        assert any("Sunday" in q for q in rendered)

    def test_mood_correlation_question_follows_direction(self):
        lower = questions.render_pattern_questions(
            Pattern("mood_correlation", "work", 8, 0.6, {"direction": "lower"})
        )
        higher = questions.render_pattern_questions(
            Pattern("mood_correlation", "friends", 8, 0.6, {"direction": "higher"})
        )
        assert lower[0].startswith("Your entries read lower")
        assert higher[0].startswith("Your entries read higher")
        # Missing direction (old blobs): safe default, never contradicts.
        default = questions.render_pattern_questions(
            Pattern("mood_correlation", "sleep", 8, 0.6, {})
        )
        assert default[0].startswith("Your entries read lower")


class TestDeterminism:
    def test_same_user_same_day_same_question(self):
        a = questions.question_for_today("user-a", PATTERNS, TODAY)
        b = questions.question_for_today("user-a", PATTERNS, TODAY)
        assert a == b

    def test_rotation_moves_across_days(self):
        seen = {
            questions.question_for_today("user-a", PATTERNS, TODAY + timedelta(days=i))
            for i in range(14)
        }
        assert len(seen) > 1, "question never rotates across days"

    def test_question_always_comes_from_pool(self):
        pool = questions.build_pool(PATTERNS)
        for i in range(30):
            assert (
                questions.question_for_today("user-a", PATTERNS, TODAY + timedelta(days=i)) in pool
            )

    def test_no_patterns_falls_back_to_generic(self):
        q = questions.question_for_today("user-a", [], TODAY)
        assert q in questions.GENERIC_QUESTIONS

    def test_rotation_offset_stable_and_user_varying(self):
        assert questions.user_rotation_offset("user-a") == questions.user_rotation_offset("user-a")
        assert questions.user_rotation_offset("user-a") != questions.user_rotation_offset("user-b")


class TestPool:
    def test_pool_orders_patterns_first(self):
        pool = questions.build_pool(PATTERNS)
        assert "work" in pool[0]  # highest-confidence pattern question leads

    def test_pool_deduplicates(self):
        pool = questions.build_pool(PATTERNS)
        assert len(pool) == len(set(pool))

    def test_pool_includes_generic_fallbacks(self):
        pool = questions.build_pool(PATTERNS)
        assert any(q in questions.GENERIC_QUESTIONS for q in pool)

    def test_unknown_pattern_kind_skipped(self):
        pool = questions.build_pool([Pattern("mystery", "x", 3, 0.5, {})])
        assert pool == list(dict.fromkeys(list(questions.GENERIC_QUESTIONS)))

    def test_max_pattern_questions_respected(self):
        many = [Pattern("temporal", f"t{i}", 5, 0.9, {"day": "Monday"}) for i in range(10)]
        pool = questions.build_pool(many)
        pattern_questions = [q for q in pool if "t0" in q or "t4" in q]
        assert pattern_questions  # top-5 patterns render
        assert not any("t5" in q for q in pool)  # beyond the cap: generic only


class TestTopicTrendTemplates2026_09_20:
    """Audit M-24: topic templates must select by detail.trend, mirroring
    Pattern.describe() — a steady-presence topic never renders the rising
    'taking up more space' claim."""

    def test_rising_topic_renders_the_rising_template(self):
        from app.services.patterns import Pattern

        rendered = questions.render_pattern_questions(
            Pattern("topic", "work", 9, 0.8, {"trend": "rising", "share": 0.31})
        )
        assert any("taking up more space" in q for q in rendered)

    def test_steady_topic_renders_the_steady_template(self):
        from app.services.patterns import Pattern

        rendered = questions.render_pattern_questions(
            Pattern("topic", "work", 9, 0.8, {"trend": "steady", "share": 0.31})
        )
        assert rendered
        assert not any("taking up more space" in q for q in rendered)
        assert any("steady presence" in q for q in rendered)

    def test_missing_trend_defaults_to_steady(self):
        # Old/foreign blobs without detail.trend must not fabricate a rise.
        from app.services.patterns import Pattern

        rendered = questions.render_pattern_questions(Pattern("topic", "work", 9, 0.8, {}))
        assert not any("taking up more space" in q for q in rendered)
