"""Scratch measurement for items 4/5 (not part of the suite).

Item 4: daily-cadence pure-noise false-statistical-card rate.
Item 5: small-vocab noise presence-card flood + cluster structure.
"""

from __future__ import annotations

import random
import sys
from datetime import date, timedelta

from app.services import brain
from app.services import phrases as phrase_miner
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 4)

FILLER = (
    "walked home past the library and the old mill afterwards",
    "washed the dishes and folded the laundry slowly",
    "watered the balcony plants and trimmed the basil",
    "sorted the mail and paid the utility bill",
    "swept the hallway and shook out the rug",
)
THEME_WORDS = (
    "work boss deadline",
    "sleep tired bed",
    "friend party lonely",
    "family mom dad",
    "gym doctor headache",
    "money rent salary",
    "school exam homework",
    "food dinner cook",
    "rain sunny storm",
)


def noise_corpus(rng: random.Random, days: int, start: date) -> list[JournalEntry]:
    entries = []
    for i in range(days):
        if rng.random() < 0.85:
            parts = [rng.choice(FILLER)]
            parts.extend(rng.choice(THEME_WORDS).split()[0] for _ in range(2))
            rng.shuffle(parts)
            entries.append(
                JournalEntry(
                    ". ".join(parts),
                    start + timedelta(days=i),
                    sentiment=round(rng.uniform(-0.6, 0.6), 3),
                )
            )
    return entries


def daily_cadence_stat_cards(seed: int, corpus_days: int = 98, recompute_days: int = 14):
    """One run: grow the corpus one day at a time, recompute daily, count
    distinct statistical cards EVER surfaced."""
    rng = random.Random(seed)
    start = T0 - timedelta(days=corpus_days - 1)
    entries = noise_corpus(rng, corpus_days, start)
    state = brain.load_state(None)
    ever: set[str] = set()
    for k in range(recompute_days):
        today = start + timedelta(days=corpus_days - recompute_days + k)
        known = [e for e in entries if e.entry_date <= today]
        result = brain.update(state, known, today)
        state = result.new_state
        ever |= {
            f"{p.kind}:{p.label}:{p.detail.get('direction', '')}"
            for p in result.surfaced
            if p.kind in brain.STATISTICAL_KINDS
        }
    return ever


def measure_item4(runs: int = 30):
    hits = 0
    detail: dict[str, int] = {}
    for seed in range(1000, 1000 + runs):
        cards = daily_cadence_stat_cards(seed)
        if cards:
            hits += 1
            for pid in cards:
                detail[pid] = detail.get(pid, 0) + 1
    print(f"item4 daily-cadence false-stat-card runs: {hits}/{runs}")
    for pid, n in sorted(detail.items(), key=lambda kv: -kv[1]):
        print(f"   {pid}: {n} runs")


VOCAB = (
    "blanket ladder kettle lantern pillow candle basket hammer needle ribbon "
    "button mirror carpet drawer closet broom bucket candle2 spoon fork plate "
    "window garden garage attic porch cellar fence gate roof chimney stairs "
    "hallway curtain cushion blanket2 toaster kettle2 wardrobe dresser shelf rug"
).split()


def small_vocab_corpus(rng: random.Random, days: int, start: date) -> list[JournalEntry]:
    entries = []
    for i in range(days):
        n = rng.randint(6, 10)
        words = [rng.choice(VOCAB) for _ in range(n)]
        entries.append(
            JournalEntry(
                " ".join(words),
                start + timedelta(days=i),
                sentiment=round(rng.uniform(-0.4, 0.4), 3),
            )
        )
    return entries


TEMPLATES = (
    "another ordinary day with {a} and {b} and {c}",
    "wrote about {a} and {b} and {c} again",
    "spent the evening near the {a} and the {b} and the {c}",
    "thought about the {a}, then the {b}, then the {c}",
)


def templated_vocab_corpus(rng: random.Random, days: int, start: date) -> list[JournalEntry]:
    entries = []
    for i in range(days):
        s1 = rng.choice(TEMPLATES).format(
            a=rng.choice(VOCAB), b=rng.choice(VOCAB), c=rng.choice(VOCAB)
        )
        s2 = rng.choice(TEMPLATES).format(
            a=rng.choice(VOCAB), b=rng.choice(VOCAB), c=rng.choice(VOCAB)
        )
        entries.append(
            JournalEntry(
                f"{s1}. {s2}", start + timedelta(days=i), sentiment=round(rng.uniform(-0.4, 0.4), 3)
            )
        )
    return entries


def measure_item5(runs: int = 8):
    corpus_fn = templated_vocab_corpus if "templated" in sys.argv else small_vocab_corpus
    for seed in range(2000, 2000 + runs):
        rng = random.Random(seed)
        start = T0 - timedelta(days=83)
        entries = corpus_fn(rng, 84, start)
        state = brain.load_state(None)
        # two consecutive recompute days so anything gated can surface
        r1 = brain.update(state, entries, T0)
        r2 = brain.update(r1.new_state, entries, T0 + timedelta(days=1))
        presence = [p for p in r2.surfaced if p.kind == "topic" and p.detail.get("presence")]
        topics_all = [p for p in r2.surfaced if p.kind == "topic"]
        phrases = [p for p in r2.surfaced if p.kind in ("recurring_phrase", "rumination")]
        print(
            f"seed {seed}: presence={[p.label for p in presence]} "
            f"topics={[p.label for p in topics_all]} phrases={len(phrases)}"
        )
        # cluster structure for the first seed
        if seed == 2000 or True:
            sentences = []
            for e in entries:
                for s in brain.sentences_of(e.text):
                    sentences.append(phrase_miner.SentenceRef(text=s, day=e.entry_date))
            clusters = phrase_miner.near_duplicate_clusters(sentences)
            clustered_texts = {m.text for c in clusters for m in c.members}
            for p in presence:
                word = p.label
                in_cluster = 0
                total = 0
                for e in entries:
                    toks = brain.WORD_RE.findall(e.text.lower())
                    if word in toks:
                        total += 1
                        for s in brain.sentences_of(e.text):
                            if s in clustered_texts and word in s.split():
                                in_cluster += 1
                                break
                print(
                    f"   presence {word!r}: occurrences={total} in_cluster={in_cluster} "
                    f"clusters={len(clusters)}"
                )


if __name__ == "__main__":
    if "item4" in sys.argv:
        measure_item4()
    if "item5" in sys.argv:
        measure_item5()
