#!/usr/bin/env python3
"""Offline check: does the E2E corpus clear the brain's day-1 surfacing bars?"""
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.services import brain
from campaign import structured_corpus, plain_mood_corpus

for label, corpus in [
    ("structured 48d", structured_corpus(date.today(), 48, seed=11)),
    ("structured 84d", structured_corpus(date.today(), 84, seed=11)),
    ("structured 84d s7", structured_corpus(date.today(), 84, seed=7)),
    ("plain-mood 35d crisis", plain_mood_corpus(date.today(), 35, crisis=True)),
]:
    entries = [
        brain.JournalEntry(text=e["text"], entry_date=e["date"], sentiment=e["sentiment"])
        for e in corpus
    ]
    result = brain.update(brain.load_state(None), entries, date.today())
    kinds = [p.kind for p in result.surfaced]
    print(f"{label:24} entries={len(entries):3} surfaced={len(kinds):2} {sorted(set(kinds))}")
    for p in result.surfaced:
        print(f"    [{p.detail.get('pattern_state', '?'):9}] {p.kind:16} {p.label[:64]}")
