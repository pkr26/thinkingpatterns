"""Public reference sanitizer rejects grounded contact-shaped labels."""

import pytest

from app.services.llm import sanitize_pattern


@pytest.mark.parametrize(
    "label",
    [
        "dot com",
        "at gmail",
        "text me at",
        *[
            f"{word} {word} {word}"
            for word in ("zero", "four", "five", "six", "seven", "eight", "nine", "oh")
        ],
    ],
)
def test_grounded_contact_shaped_labels_are_refused_by_public_sanitizer(label):
    # Corpus grounding is deliberately satisfied: contact shape itself is
    # the refusal contract of this exported reference helper.
    item = {"kind": "recurring_phrase", "label": label, "occurrences": 3}
    assert sanitize_pattern(item, [label] * 3) is None


def test_grounded_ordinary_phrase_survives_public_sanitizer():
    label = "ordinary quiet walk"
    item = {"kind": "recurring_phrase", "label": label, "occurrences": 3}
    result = sanitize_pattern(item, [label] * 3)
    assert result is not None
    assert (result.kind, result.label, result.occurrences) == ("recurring_phrase", label, 3)
