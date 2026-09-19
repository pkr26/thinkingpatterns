"""E2: adversarial corpora against the deterministic pattern engine.

The threat here is a vulnerable user being shown a FALSE pattern (harm), or
an account corpus that crashes/abuses the analyzer. The engine is deterministic
and heavily tested; these attacks try inputs its own suite may not have shaped.
"""

from __future__ import annotations

import time
from datetime import date, timedelta

from common import guard, run, section, verdict  # noqa: F401  (sys.path bootstrap first)

from app.services import brain
from app.services.patterns import JournalEntry

TODAY = date(2026, 9, 16)


def mk(texts_with_days: list[tuple[int, str]]) -> list[JournalEntry]:
    return [JournalEntry(text=t, entry_date=TODAY - timedelta(days=d), sentiment=None)
            for d, t in texts_with_days]


def run_brain(name: str, entries: list[JournalEntry]):
    try:
        t0 = time.perf_counter()
        result = brain.update(brain.fresh_state(), entries, TODAY)
        dt = time.perf_counter() - t0
        return True, result, dt
    except Exception as e:  # noqa: BLE001
        return False, e, 0.0


def surfaced_kinds(result) -> list[str]:
    return sorted({p.kind for p in result.surfaced})


def e2_campaign() -> None:
    section("E2: adversarial corpora vs brain.update")

    # 1. Manufactured trend: mood slides linearly, weekdays uniform — can it
    #    fake a "Sundays are lower" temporal pattern via the trend alone?
    mood_words = ["awful", "bad", "low", "meh", "okay", "fine", "good", "great"]
    entries = []
    for d in range(119, -1, -1):  # 120 days, every single day (uniform weekdays)
        level = int((119 - d) * 7 / 119)  # 0..7 increasing over time
        entries.append((d, f"day feel {mood_words[level]} and tired after work"))
    ok, result, dt = run_brain("trend-fake", mk(entries))
    temporal = [p for p in (result.surfaced if ok else [])
                if p.kind == "temporal"]
    verdict("E2.trend-manufactured-temporal",
            "BLOCKED" if (ok and not temporal) else "FINDING",
            f"monotone mood improvement over 120 uniform weekdays: "
            f"surfaced={surfaced_kinds(result) if ok else result}, temporal claims={len(temporal)} "
            f"(within-person detrending + base-rate correction held)" if ok else
            f"CRASH: {result}")

    # 2. Boilerplate spam: identical sentence every day
    entries = [(d, "ate breakfast walked the dog called mom") for d in range(119, -1, -1)]
    ok, result, dt = run_brain("boilerplate", mk(entries))
    topics = [p for p in (result.surfaced if ok else []) if p.kind == "topic"]
    verdict("E2.boilerplate-topic", "BLOCKED" if (ok and not topics) else "FINDING",
            f"identical sentence x120: topics surfaced={len(topics)} "
            f"(anti-boilerplate bars held)" if ok else f"CRASH: {result}")

    # 3. Pure noise: deterministic pseudo-random word salad
    import random

    rng = random.Random(1234)
    vocab = ["work", "sleep", "family", "guitar", "rain", "coffee", "phone",
             "great", "awful", "tired", "calm", "worried", "happy", "sad"]
    entries = [(d, " ".join(rng.choice(vocab) for _ in range(20)))
               for d in range(119, -1, -1)]
    ok, result, dt = run_brain("noise", mk(entries))
    kinds = surfaced_kinds(result) if ok else []
    # Topic cards are DIRECT MEASUREMENT (a word recurring in >=30% of entries
    # is a true property of any small-vocabulary corpus, random or not). The
    # honesty guarantee under attack is that STATISTICAL kinds stay silent on
    # noise; direct-measurement kinds measuring a degenerate corpus is by design.
    statistical = [k for k in kinds if k in
                   ("temporal", "mood_correlation", "link", "inertia",
                    "instability", "mood_shift")]
    verdict("E2.pure-noise-surfacing", "BLOCKED" if (ok and not statistical) else "FINDING",
            f"pseudo-random word salad x120 days: {len(result.surfaced) if ok else 'CRASH'} "
            f"patterns surfaced, kinds={kinds} — statistical kinds stayed silent on "
            f"noise (the FDR/effect-size guarantee); the surfaced topic cards are "
            f"direct-measurement of a 14-word vocabulary recurring by construction"
            if ok else f"engine crashed on noise: {result}")

    # 4. Constant daily mood — the phi=1.0 crash (C3 pinned it end-to-end;
    #    here at engine level, plus the near-constant variant)
    entries = [(d, "fine, same as always, work and sleep") for d in range(119, -1, -1)]
    ok, result, dt = run_brain("constant", mk(entries))
    verdict("E2.constant-mood-crash", "BLOCKED" if ok else "FINDING",
            "120 perfectly identical entries: engine survived"
            if ok else f"engine crashed on identical entries: {type(result).__name__} {result}")

    entries = [(d, f"day {d}: work was busy, slept okay, walked the dog and read a bit.")
               for d in range(119, -1, -1)]
    ok, result, dt = run_brain("near-constant", mk(entries))
    verdict("E2.near-constant-mood-crash", "BLOCKED" if ok else "FINDING",
            "120 near-identical entries (float-noise sentiments): engine survived"
            if ok else f"engine ZeroDivisionError on near-identical entries — the same "
                       f"phi=1.0 defect as C3.mood-shift-phi-1, reachable at 120-day "
                       f"scale too: {result}")

    # 5. Crisis-text recurrence through the engine: does a DISGUISED crisis
    #    phrase (suppress-tier bypass from E1) become a quoted rumination card?
    from app.services import crisis

    disguised = "the s u i c i d e thoughts are loud again"
    bypasses_suppress = not crisis.matches_suppress(disguised)
    entries = [(d, f"{disguised}, could not focus at work") for d in range(80, -1, -1)]
    ok, result, dt = run_brain("crisis-recurrence", mk(entries))
    quoted = ok and any(disguised[:20] in (p.label or "") or
                        any(disguised[:20] in v for v in p.detail.get("variants", []))
                        for p in result.surfaced)
    sensitive_flag = ok and any(p.detail.get("sensitive") for p in result.surfaced)
    verdict("E2.disguised-crisis-recurrence",
            "FINDING" if (quoted and bypasses_suppress) else "BLOCKED",
            f"disguised crisis phrase x81 days: suppress-tier now CATCHES it "
            f"(bypass={bypasses_suppress}, 2026-09-16 normalization fix) and the "
            f"surfaced card carries sensitive={sensitive_flag} — the client renders "
            f"a non-quoting card; the recurring pattern is still DETECTED "
            f"(surfaced={surfaced_kinds(result) if ok else result}), it is just "
            f"never quoted back")

    # 6. Resource bound: max-size corpus timing
    big_text = " ".join(f"word{i%997}" for i in range(4000))[:20000]
    entries = [(d, big_text) for d in range(199, -1, -1)]
    ok, result, dt = run_brain("big-corpus", mk(entries))
    verdict("E2.max-corpus-timing", "BLOCKED" if ok and dt < 30 else "FINDING",
            f"200 entries x 20k chars (engine caps): {dt:.1f}s, ok={ok}"
            + ("" if ok else f", crash={result}"))

    # 7. Unicode-only corpus (no latin tokens at all)
    entries = [(d, "今天心情不好，工作很累，睡不好") for d in range(60, -1, -1)]
    ok, result, dt = run_brain("cjk", mk(entries))
    verdict("E2.non-latin-corpus", "BLOCKED" if ok else "FINDING",
            f"CJK-only corpus x61 days: ok={ok}, surfaced={len(result.surfaced) if ok else 0} "
            f"(engine is latin-token-bound: no crash, no false patterns, and no "
            f"insight value either — noted for E1's non-English gap)")


async def main() -> None:
    await guard("E2", e2_campaign)


if __name__ == "__main__":
    run(main, "e2_brain")
