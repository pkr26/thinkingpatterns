#!/usr/bin/env python3
"""Offline tuning probe: which effect sizes make the dynamics/link detectors
fire within 60 days? (No server — pure brain replay.)"""
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.services import brain
from app.services.patterns import JournalEntry
from simulate import DAYS, TODAY, FILLERS, Persona, replay
import random


def probe(name, seed, build):
    p = Persona(name, "x", seed, "")
    build(p)
    final, timeline, first = replay(p)
    kinds = sorted({x["kind"] for x in final})
    print(f"{name:34} entries={len(p.entries):3} patterns={len(final):2} kinds={kinds}")
    for x in final:
        if x["kind"] in ("temporal", "mood_correlation", "link", "inertia",
                         "instability", "mood_shift", "topic"):
            print(f"      [{x['state']:9}] {x['kind']:17} {x['label'][:52]} n={x['occurrences']}")
    return final


def priya_strong(p):
    used = {}
    rng = p.rng
    carry = 0.0
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        late = i >= DAYS - 25
        phi, amp = (0.72, 0.85) if late else (0.1, 0.12)
        carry = phi * carry + (1 - phi) * rng.uniform(-amp, amp)
        s = 0.05 + carry - (0.75 if late else 0.0)
        scroll = (not late) and rng.random() < 0.42
        if scroll:
            s = rng.uniform(-0.7, -0.45)
        p.add(d, p.filler(used), s)
        ev = p.filler(used)
        if scroll:
            ev += ". wasted the whole evening scrolling, eyes tired"
        p.add(d, ev, s)


def maya_strong(p):
    used = {}
    rng = p.rng
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        base = rng.uniform(-0.15, 0.15)
        p.add(d, p.filler(used), base)
        ev, sent = p.filler(used), base
        if d.weekday() == 6:
            ev = "the week is looming, big deadline pressure at work again"
            sent = rng.uniform(-0.75, -0.55)
        elif d.weekday() in (0, 2, 4) and rng.random() < 0.85:
            ev = "went to bed late. i can't sleep, my mind won't stop"
            sent = rng.uniform(-0.5, -0.3)
            p._low = getattr(p, "_low", set())
            p._low.add(d + timedelta(days=1))
        p.add(d, ev, sent)
    for e in p.entries:
        if e["date"] in getattr(p, "_low", set()):
            e["sentiment"] = round(min(e["sentiment"], p.rng.uniform(-0.75, -0.55)), 3)


def lena_strong(p):
    used = {}
    rng = p.rng
    family = set()
    i = 3
    while i < DAYS - 3:
        family.add(i)
        i += 7 + rng.randrange(2)
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = rng.uniform(-0.05, 0.25)
        if i and (i - 1) in family:
            s = rng.uniform(-0.8, -0.6)
        p.add(d, p.filler(used), s)
        ev = p.filler(used)
        if i in family:
            ev += ". visited the family, mom and dad were there"
        if d.weekday() == 6:
            ev += ". called grandma like every sunday"
        p.add(d, ev, s + rng.uniform(-0.05, 0.05))


probe("priya strong-decline", 31, priya_strong)
probe("priya strong-decline (s2)", 32, priya_strong)
probe("maya strong-link", 33, maya_strong)
probe("maya strong-link (s2)", 34, maya_strong)
probe("lena strong-link", 35, lena_strong)
probe("lena strong-link (s2)", 36, lena_strong)
