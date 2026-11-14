"""Public clustering of actual recurring sentences across calendar days."""

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from app.services.phrases import SentenceRef, near_duplicate_clusters


@pytest.mark.parametrize("span", [6, 7])
def test_default_recurring_thought_cluster_requires_one_separated_week(span):
    start = date(2026, 10, 1)
    text = "i kept the blue notebook beside the kitchen window"
    references = [SentenceRef(text, start + timedelta(days=offset)) for offset in (0, 3, span)]
    clusters = near_duplicate_clusters(references)
    if span == 6:
        assert clusters == []
    else:
        assert len(clusters) == 1
        assert clusters[0].representative == text
        assert clusters[0].span_days == 7
        assert clusters[0].distinct_days == 3
        assert [ref.text for ref in clusters[0].members] == [text] * 3


def _letters(number, width):
    """Expand a compact corpus word index without consulting the clusterer."""
    chars = []
    for _ in range(width):
        chars.append(chr(97 + number % 26))
        number //= 26
    assert number == 0
    return "".join(reversed(chars))


PHRASE_CORPORA = json.loads(
    (Path(__file__).parent / "fixtures" / "phrase_budget_corpora.json").read_text()
)


@pytest.mark.parametrize("case", PHRASE_CORPORA["cases"], ids=lambda case: case["name"])
def test_default_cluster_work_limits_have_deterministic_public_recall(case):
    """Crafted word corpora exercise real default MinHash and banding.

    The public library accepts normalized words. These cases preserve its
    documented deterministic degradation after the default work ceilings;
    they do not assert internal counters or a wall-clock performance limit.
    """
    today = date(2026, 10, 5)
    references = []
    for group_index, group in enumerate(case["groups"]):
        for candidate in group["wordVariants"]:
            words = group["core"] + [
                "v" + _letters(group_index, 2) + _letters(candidate, 4) + _letters(k, 2) + "v"
                for k in range(36)
            ]
            # Each crowded prefix occurs on one date only; it cannot itself
            # qualify as a thought recurring on three separated days.
            references.append(SentenceRef(" ".join(words), today))
    base, variant = case["target"]
    target = [
        SentenceRef(base, today - timedelta(days=8)),
        SentenceRef(base, today - timedelta(days=4)),
        SentenceRef(variant, today),
    ]
    clusters = near_duplicate_clusters(references + target)
    if case["expectedCluster"]:
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.members == target
        assert cluster.representative == base
        assert cluster.distinct_days == 3
        assert cluster.span_days == 8
    else:
        assert clusters == []


@pytest.mark.parametrize("case", PHRASE_CORPORA["bucketCases"], ids=lambda case: case["name"])
def test_default_cluster_crowding_preserves_the_public_bucket_boundary(case):
    today = date(2026, 10, 5)
    texts = [
        " ".join(
            case["core"]
            + [
                "v" + _letters(0, 2) + _letters(candidate, 4) + _letters(k, 2) + "v"
                for k in range(36)
            ]
        )
        for candidate in case["wordVariants"]
    ]
    references = [SentenceRef(text, today) for text in texts[:-2]] + [
        SentenceRef(texts[-2], today - timedelta(days=8)),
        SentenceRef(texts[-2], today - timedelta(days=4)),
        SentenceRef(texts[-1], today),
    ]
    clusters = near_duplicate_clusters(references)
    if case["expectedCluster"]:
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.members == references
        assert cluster.representative == texts[-2]
        assert cluster.distinct_days == 3
        assert cluster.span_days == 8
    else:
        assert clusters == []


@pytest.mark.parametrize("case", PHRASE_CORPORA["edgeCases"], ids=lambda case: case["name"])
def test_default_cluster_preserves_the_last_allowed_near_pair(case):
    today = date(2026, 10, 5)
    prefix = []
    for group in case["groups"]:
        for candidate in group["wordVariants"]:
            text = " ".join(
                group["core"]
                + [
                    "v"
                    + _letters(group["groupIndex"], 2)
                    + _letters(candidate, 4)
                    + _letters(k, 2)
                    + "v"
                    for k in range(36)
                ]
            )
            prefix.append(SentenceRef(text, today))
    base, unrelated, variant = case["tail"]
    earlier = SentenceRef(base, today - timedelta(days=8))
    middle = SentenceRef(base, today - timedelta(days=4))
    later = SentenceRef(variant, today)
    tail = (
        [earlier, middle, later, SentenceRef(unrelated, today)]
        if case.get("nearPairFirst", False)
        else [earlier, middle, SentenceRef(unrelated, today), later]
    )
    clusters = near_duplicate_clusters(prefix + tail)
    if case["expectedCluster"]:
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.members == [earlier, middle, later]
        assert cluster.representative == base
        assert cluster.distinct_days == 3
        assert cluster.span_days == 8
    else:
        assert clusters == []
