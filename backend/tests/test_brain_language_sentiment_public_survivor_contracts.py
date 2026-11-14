"""Actual public language coverage and graded sentiment from native text inputs."""

from datetime import date

import pytest

from app.services import brain
from app.services.patterns import JournalEntry


@pytest.mark.parametrize(
    "word, language",
    [
        ("a", "other"),
        ("aas", "en"),
        ("abatida", "es"),
        ("absolutamente", "es"),
        ("absolutely", "en"),
        ("adorable", "en"),
        ("afford", "en"),
        ("and", "en"),
        ("its", "en"),
        ("the", "en"),
    ],
)
def test_native_ten_token_text_reports_released_scoring_coverage(word, language):
    # All tokens are real input text. Nine unknown Latin words put one
    # recognized word at the declared ten-percent coverage boundary.
    today = date(2026, 10, 22)
    text = " ".join([word] + ["qzxunknown"] * 9)
    result = brain.update(brain.fresh_state(), [JournalEntry(text, today)], today)
    assert result.stats["language"] == language
    if language == "other":
        assert result.stats["avg_sentiment"] is None


def test_native_graded_spanish_and_english_merges_keep_their_public_scores():
    # Released graded lexicon weights for amor are3.0 under the historical
    # English-winning merge and3.2 under the Spanish-winning merge, scaled
    # to the public [-1,1] interval by4. No native scalar output is supplied.
    assert brain.sentiment_score(["amor"], "en") == 0.75
    assert brain.sentiment_score(["amor"], "es") == 0.8
    assert brain.sentiment_score(["amor"]) == 0.75


def test_native_negation_and_contrast_keep_the_public_affect_measurements():
    # The released ordinary walk for this actual phrase is[-.703,-2.85].
    # Check the public net/positive/negative measurements, not that private
    # walk or any replaced negation/contrast/estimator return value.
    for language in (None, "en", "es"):
        assert brain.sentiment_score("no good but bad".split(), language) == pytest.approx(
            -0.88825, abs=1e-12
        )
        assert brain.sentiment_components("no good but bad".split(), language) == pytest.approx(
            (0.0, 0.88825), abs=1e-12
        )
