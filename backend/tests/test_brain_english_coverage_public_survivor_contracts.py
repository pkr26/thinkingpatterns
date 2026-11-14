"""Public English coverage from actual input words and native tokenization."""

from datetime import date

import pytest

from app.services import brain
from app.services.patterns import JournalEntry


@pytest.mark.parametrize(
    "word",
    [
        "all",
        "although",
        "few",
        "get",
        "got",
        "how",
        "isn",
        "let",
        "now",
        "one",
        "own",
        "put",
        "really",
        "say",
        "see",
        "though",
        "too",
        "very",
        "wanted",
        "wants",
        "way",
        "yet",
        "day",
        "little",
        "bit",
        "quite",
        "somewhat",
        "feelings",
        "ask",
        "try",
        "lot",
        "someone's",
        "everyone's",
    ],
)
def test_released_english_words_keep_the_native_ten_percent_coverage(word):
    # The one recognized word and nine unknown Latin words are all actual
    # text. update computes the tokens, letter counts and hit fraction.
    today = date(2026, 10, 22)
    text = " ".join([word] + ["qzxunknown"] * 9)
    result = brain.update(brain.fresh_state(), [JournalEntry(text, today)], today)
    assert result.stats["language"] == "en"
    assert result.stats["avg_sentiment"] is not None
