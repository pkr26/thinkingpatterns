"""Native public question calls exercise the current bounded FIFO policy."""

from datetime import date

from app.services import questions
from app.services.patterns import Pattern


def test_native_question_calls_evict_the_first_snapshot_at_current_fifo_capacity(
    monkeypatch,
):
    # Establish isolated initial state; all population and observations
    # below use actual public calls, with native rendering and rotation.
    monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
    today = date(2026, 10, 22)
    patterns = [Pattern("temporal", "guitar", 5, 0.5, {"day": "Monday"})]
    rendered = questions.build_pool(patterns)
    generic = questions.build_pool([])
    owner = next(
        f"fifo-owner-{i}"
        for i in range(1000)
        if rendered[
            (today.toordinal() + questions.user_rotation_offset(f"fifo-owner-{i}")) % len(rendered)
        ]
        not in generic
    )
    first = questions.question_for_today(owner, patterns, today)
    assert first not in generic
    for index in range(4096):
        questions.question_for_today(f"fifo-peer-{index}", [], today)
    expected = generic[(today.toordinal() + questions.user_rotation_offset(owner)) % len(generic)]
    assert questions.question_for_today(owner, [], today) == expected
