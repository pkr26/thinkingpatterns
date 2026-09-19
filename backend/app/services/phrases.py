"""Near-duplicate sentence clustering: MinHash + LSH banding.

v1 matched recurring phrases by exact normalized-sentence equality, so
"I'm so tired of this" and "so tired of everything" never linked. People
do not repeat themselves verbatim; recurring thoughts show up as
near-duplicates. This module clusters sentences whose estimated Jaccard
similarity over word shingles clears a threshold, in (near-)linear time
via locality-sensitive hashing.

Determinism is a hard requirement (same corpus → same clusters, on every
platform, forever): hash parameters come from a fixed splitmix64 stream
and shingle hashing uses blake2b — no Python ``hash()``, no seeded
``random`` module, no wall clock.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date

NUM_PERM = 64
BANDS = 16
ROWS = 4  # BANDS * ROWS == NUM_PERM
# Accepted recall: 16 bands x 4 rows proposes a candidate pair with
# probability 1 - (1 - s^4)^16 ≈ 0.64 at the s = 0.5 confirmation
# threshold (and ≈ 0.995 at s = 0.8). Clustering is a recall device for
# recurring-thought hints, not an exact index: a missed pair delays a
# pattern, it never invents one — and tighter banding would cost the
# (near-)linear runtime that keeps recompute cheap.
MERSENNE = (1 << 61) - 1
DEFAULT_JACCARD = 0.5
DEFAULT_MIN_SIZE = 3
DEFAULT_MIN_SPAN_DAYS = 7
DEFAULT_MIN_DISTINCT_DAYS = 3
# Cost ceilings: a "sentence" longer than this is a paragraph (not a
# recurring *phrase*), and a single band bucket holding more distinct
# signatures than this is a hash collision pile, not a cluster — the
# pairwise confirmation loop is O(bucket^2) and without these caps a few
# hundred KB of crafted near-identical text costs minutes of CPU.
MAX_SENTENCE_TOKENS = 120
MAX_BUCKET_SIGNATURES = 256
# Two further ceilings from the 2026-09-19 pen-test round, closing the
# quadratic-work gap the caps above left open.  A candidate pair sharing
# all 16 band buckets used to be confirmed 16 times — the SAME union,
# purchased 16 times.  And the per-bucket cap alone bounds one bucket, not
# the sum: ~14 disjoint near-identical clusters, each just under the cap,
# drove ~4.3M pair comparisons (~11s CPU) per recompute while respecting
# every per-bucket limit.  A pair is now compared at most once per RUN
# (union is idempotent, so cluster output is unchanged), and the run may
# spend at most this many signature comparisons in total.  Past the
# budget, later candidates are simply not confirmed — an adversarial
# corpus degrades to fewer links, never to unbounded CPU.  Degradation is
# deterministic: buckets are visited in insertion order and the budget
# decrements identically on every platform, so the same corpus always
# yields the same clusters.
MAX_PAIRWISE_COMPARISONS = 200_000
# The dedupe set lookup happens once per PROPOSAL, and a crafted corpus
# proposes the same pairs from all 16 bands: ~4.3M proposals walked ~3s of
# pure set traffic even after comparisons were capped. Proposals are
# bounded separately: past this many candidates walked in one run, the
# pairwise loops of remaining buckets are skipped (identical-signature
# unions still run). Real journals sit orders of magnitude below (a
# pathological 4000-sentence corpus of 200 recurring thoughts proposes
# ~600k); the ceiling only clips adversarial bucket crowding.
MAX_PAIRWISE_PROPOSALS = 1_000_000


@dataclass(frozen=True)
class SentenceRef:
    """One normalized sentence occurrence, pinned to its entry date."""

    text: str
    day: date


@dataclass(frozen=True)
class PhraseCluster:
    """A group of near-duplicate sentences (one recurring thought)."""

    members: list[SentenceRef]
    representative: str
    span_days: int
    distinct_days: int


def _splitmix64(seed: int):
    """Deterministic 64-bit pseudo-random stream (no stdlib RNG involved)."""
    state = seed & 0xFFFFFFFFFFFFFFFF
    while True:
        state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        yield z ^ (z >> 31)


_HASH_PARAMS: list[tuple[int, int]] = []
_gen = _splitmix64(0x4D696E64506174)  # "MindPat"
for _ in range(NUM_PERM):
    a = (next(_gen) | 1) % MERSENNE  # odd, non-degenerate multipliers
    b = next(_gen) % MERSENNE
    _HASH_PARAMS.append((a, b))
del _gen


def shingles(tokens: list[str]) -> set[str]:
    """Unigrams + bigrams: the shingle set for one sentence.

    Word-order-preserving k-shingles (k=3) punish insertions hard —
    "i am so tired of everything" vs "i am just so tired of everything
    today" share almost no 3-grams. Unigrams tolerate insertions,
    bigrams keep enough order sensitivity to separate unrelated
    thoughts (measured margin on journal-like pairs: related ≥0.6,
    unrelated ≤0.1 estimated Jaccard).
    """
    out: set[str] = set(tokens)
    for i in range(len(tokens) - 1):
        out.add(f"{tokens[i]} {tokens[i + 1]}")
    return out


def _shingle_hash(shingle: str) -> int:
    digest = hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def signature(tokens: list[str]) -> list[int]:
    """NUM_PERM-component MinHash signature of a token list."""
    # No shingle ordering needed: each component is a MIN over all shingle
    # hashes, and min is order-independent (a wasted sorted() used to run
    # here). The set dedupes; the generator consumes it in any order.
    hashes = [_shingle_hash(s) for s in shingles(tokens)]
    if not hashes:
        return [0] * NUM_PERM
    return [min(((a * h + b) % MERSENNE) for h in hashes) for a, b in _HASH_PARAMS]


def estimated_jaccard(sig1: list[int], sig2: list[int]) -> float:
    """Jaccard similarity estimated from two equal-length signatures."""
    if len(sig1) != len(sig2) or not sig1:
        return 0.0
    equal = sum(1 for x, y in zip(sig1, sig2) if x == y)
    return equal / len(sig1)


def _band_keys(sig: list[int]) -> list[tuple[int, str]]:
    """LSH band bucket keys: one per band, over consecutive row slices."""
    keys: list[tuple[int, str]] = []
    for band in range(BANDS):
        row = sig[band * ROWS : (band + 1) * ROWS]
        digest = hashlib.blake2b(
            ",".join(str(v) for v in row).encode("ascii"), digest_size=8
        ).hexdigest()
        keys.append((band, digest))
    return keys


def near_duplicate_clusters(
    sentences: list[SentenceRef],
    jaccard: float = DEFAULT_JACCARD,
    min_size: int = DEFAULT_MIN_SIZE,
    min_span_days: int = DEFAULT_MIN_SPAN_DAYS,
    min_distinct_days: int = DEFAULT_MIN_DISTINCT_DAYS,
) -> list[PhraseCluster]:
    """Cluster near-duplicate sentences that recur across separated days.

    LSH banding proposes candidate pairs (sentences sharing at least one
    band bucket); exact signature comparison confirms them; union-find
    merges them; filters demand enough members spread across enough
    distinct days — a sentence repeated five times in one afternoon is
    a writing tic, not a pattern.
    """
    n = len(sentences)
    if n < min_size:
        return []
    # Overlong "sentences" are excluded before signing: MinHash cost scales
    # with shingle count, and a punctuation-free megabyte entry would
    # otherwise arrive as one ~100k-token sentence.
    sentences = [s for s in sentences if len(s.text.split()) <= MAX_SENTENCE_TOKENS]
    n = len(sentences)
    if n < min_size:
        return []
    signatures: list[list[int]] = []
    # Verbatim repeats share a signature: signing is the dominant linear
    # cost of this pass, and recurring journals repeat sentences word for
    # word far more often than they vary them.
    sig_cache: dict[str, list[int]] = {}
    for s in sentences:
        cached = sig_cache.get(s.text)
        if cached is None:
            cached = signature(s.text.split())
            sig_cache[s.text] = cached
        signatures.append(cached)

    buckets: dict[tuple[int, str], list[int]] = {}
    for idx, sig in enumerate(signatures):
        for key in _band_keys(sig):
            buckets.setdefault(key, []).append(idx)

    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[max(rx, ry)] = min(rx, ry)

    compared_pairs: set[tuple[int, int]] = set()
    comparisons_left = MAX_PAIRWISE_COMPARISONS
    proposals_left = MAX_PAIRWISE_PROPOSALS
    for members in buckets.values():
        if len(members) < 2:
            continue
        # Exact duplicates union in O(n) per bucket (identical signatures
        # share every key); only DISTINCT signatures need pairwise
        # comparison. Comparing just members[0] against the rest would
        # silently miss links between later members — the qualifying pair
        # does not have to involve the first index that landed in the
        # bucket.
        by_sig: dict[tuple[int, ...], int] = {}
        for idx in members:
            sig_key = tuple(signatures[idx])
            anchor = by_sig.get(sig_key)
            if anchor is None:
                by_sig[sig_key] = idx
            else:
                union(anchor, idx)
        distinct = list(by_sig.values())
        if len(distinct) > MAX_BUCKET_SIGNATURES:
            # A bucket this crowded is adversarial noise (every near-variant
            # of one sentence): confirming pairs inside it is quadratic. The
            # identical-signature unions above already ran; skip the rest.
            continue
        for i in range(len(distinct)):
            if comparisons_left <= 0 or proposals_left <= 0:
                break
            for j in range(i + 1, len(distinct)):
                lo, hi = distinct[i], distinct[j]
                if lo > hi:
                    lo, hi = hi, lo
                if proposals_left <= 0:
                    break
                proposals_left -= 1
                # One confirmation per pair per RUN: a pair sharing several
                # band buckets is proposed once per bucket, but the second
                # comparison could only repeat the first union.
                if (lo, hi) in compared_pairs:
                    continue
                if comparisons_left <= 0:
                    break
                compared_pairs.add((lo, hi))
                comparisons_left -= 1
                if estimated_jaccard(signatures[lo], signatures[hi]) >= jaccard:
                    union(lo, hi)

    groups: dict[int, list[int]] = {}
    for idx in range(n):
        groups.setdefault(find(idx), []).append(idx)

    clusters: list[PhraseCluster] = []
    for indices in groups.values():
        if len(indices) < min_size:
            continue
        refs = [sentences[i] for i in indices]
        days = sorted({r.day for r in refs})
        span = (days[-1] - days[0]).days
        if len(days) < min_distinct_days or span < min_span_days:
            continue
        clusters.append(
            PhraseCluster(
                members=refs,
                representative=_representative(refs),
                span_days=span,
                distinct_days=len(days),
            )
        )
    clusters.sort(key=lambda c: (-len(c.members), c.representative))
    return clusters


def _representative(refs: list[SentenceRef]) -> str:
    """Most frequent variant; ties break lexicographically (determinism)."""
    counts: dict[str, int] = {}
    for ref in refs:
        counts[ref.text] = counts.get(ref.text, 0) + 1
    return max(sorted(counts), key=lambda t: counts[t])
