"""MinHash/LSH near-duplicate clustering — the fix for verbatim matching.

People do not repeat themselves verbatim; recurring thoughts arrive as
near-duplicates. These tests pin the property that matters product-wise:
paraphrased repetitions cluster, unrelated sentences do not, and the
whole thing is deterministic byte-for-byte.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import phrases

BASE = date(2026, 8, 1)


def near_duplicates(n: int) -> list[str]:
    return [
        "i am so tired of everything",
        "i am so tired of this",
        "i am just so tired of everything today",
        "i am so very tired of it all",
        "again i am so tired of everything here",
    ][:n]


def test_signature_shape_and_determinism():
    sig1 = phrases.signature("i am so tired of everything".split())
    sig2 = phrases.signature("i am so tired of everything".split())
    assert len(sig1) == phrases.NUM_PERM
    assert sig1 == sig2


def test_estimated_jaccard_bounds():
    tokens = near_duplicates(2)
    sig1 = phrases.signature(tokens[0].split())
    sig2 = phrases.signature(tokens[1].split())
    disjoint = phrases.signature("completely unrelated words appear here now".split())
    assert 0.0 <= phrases.estimated_jaccard(sig1, sig2) <= 1.0
    assert phrases.estimated_jaccard(sig1, sig1) == 1.0
    assert phrases.estimated_jaccard(sig1, disjoint) < 0.2


def test_near_duplicates_cluster_across_days():
    refs = [
        phrases.SentenceRef(text=near_duplicates(1)[0], day=BASE),
        phrases.SentenceRef(text=near_duplicates(2)[1], day=BASE + timedelta(days=10)),
        phrases.SentenceRef(text=near_duplicates(3)[2], day=BASE + timedelta(days=20)),
    ]
    clusters = phrases.near_duplicate_clusters(refs)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert len(cluster.members) == 3
    assert cluster.span_days == 20
    assert cluster.distinct_days == 3


def test_unrelated_sentences_do_not_cluster():
    refs = [
        phrases.SentenceRef(text="went for a long walk by the river", day=BASE),
        phrases.SentenceRef(
            text="meeting with the boss went fine today", day=BASE + timedelta(days=10)
        ),
        phrases.SentenceRef(text="cooked dinner and watched a film", day=BASE + timedelta(days=20)),
    ]
    assert phrases.near_duplicate_clusters(refs) == []


def test_min_size_filters_small_groups():
    refs = [
        phrases.SentenceRef(text=near_duplicates(1)[0], day=BASE),
        phrases.SentenceRef(text=near_duplicates(2)[1], day=BASE + timedelta(days=10)),
    ]
    assert phrases.near_duplicate_clusters(refs) == []


def test_span_filter_requires_separated_days():
    refs = [
        phrases.SentenceRef(text=near_duplicates(1)[0], day=BASE),
        phrases.SentenceRef(text=near_duplicates(2)[1], day=BASE + timedelta(days=1)),
        phrases.SentenceRef(text=near_duplicates(3)[2], day=BASE + timedelta(days=2)),
    ]
    assert phrases.near_duplicate_clusters(refs) == []


def test_representative_is_most_common_variant():
    variants = near_duplicates(3)
    refs = [
        phrases.SentenceRef(text=variants[0], day=BASE),
        phrases.SentenceRef(text=variants[1], day=BASE + timedelta(days=10)),
        phrases.SentenceRef(text=variants[0], day=BASE + timedelta(days=20)),
        phrases.SentenceRef(text=variants[2], day=BASE + timedelta(days=30)),
    ]
    clusters = phrases.near_duplicate_clusters(refs)
    assert len(clusters) == 1
    assert clusters[0].representative == variants[0]


def test_large_cluster_orders_first():
    a = [
        phrases.SentenceRef(text=near_duplicates(1)[0], day=BASE + timedelta(days=d))
        for d in (0, 8, 16, 24)
    ]
    b = [
        phrases.SentenceRef(text="the commute home was awful again", day=BASE + timedelta(days=d))
        for d in (1, 9, 17)
    ]
    clusters = phrases.near_duplicate_clusters(a + b)
    assert len(clusters) == 2
    assert len(clusters[0].members) == 4


def test_bucket_pairs_beyond_the_first_member_are_compared(monkeypatch):
    """Regression: bucket pairing used to compare only members[0] vs the rest.

    With every sentence forced into one bucket, a linking pair that does
    not involve the first member must still merge. Here D (unrelated)
    lands first; A-B and A-C qualify; the old code unioned nothing and
    returned no cluster at all.
    """
    from datetime import timedelta  # noqa: F401 — used via BASE arithmetic below

    a = "i am so tired of everything"
    b = "i am so tired of this"
    c = "again i am so tired of everything here"
    d = "went for a long walk by the river"
    refs = [
        phrases.SentenceRef(text=d, day=BASE),
        phrases.SentenceRef(text=b, day=BASE),
        phrases.SentenceRef(text=a, day=BASE + timedelta(days=10)),
        phrases.SentenceRef(text=c, day=BASE + timedelta(days=20)),
    ]
    monkeypatch.setattr(phrases, "_band_keys", lambda sig: [(0, "forced")])
    clusters = phrases.near_duplicate_clusters(refs)
    assert len(clusters) == 1
    assert len(clusters[0].members) == 3
    assert {ref.text for ref in clusters[0].members} == {a, b, c}


def test_full_pipeline_is_deterministic():
    refs = [
        phrases.SentenceRef(text=t, day=BASE + timedelta(days=7 * i))
        for i, t in enumerate(near_duplicates(5))
    ]
    first = phrases.near_duplicate_clusters(refs)
    second = phrases.near_duplicate_clusters(refs)
    assert first == second


def test_short_sentences_still_hash():
    # Short sentences degrade gracefully: identical shorts match exactly,
    # different shorts do not.
    sig = phrases.signature("so tired".split())
    assert phrases.estimated_jaccard(sig, phrases.signature("so tired".split())) == 1.0
    assert phrases.estimated_jaccard(sig, phrases.signature("wide awake".split())) < 0.5
