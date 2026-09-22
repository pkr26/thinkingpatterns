"""Generate cross-platform brain vectors (shared/brain_vectors.json).

The on-device brain (mobile/src/brain/) must be byte-faithful to the
Python engine for the pieces it runs locally. This script emits golden
inputs and outputs — sentiment scores/components over a diverse text
corpus (negation, intensifiers, "but" re-weighting, stemming, emoji,
PA/NA splits) plus the statistics core (erfc tails, Fisher-z difference
p-values, Pearson r) — consumed by tests on BOTH platforms:
  - mobile: tests/brainVectors.test.ts runs the TS port against every
    vector (float equality for sentiment; 1e-9 for statistics),
  - backend: tests/test_brain_vectors.py regenerates and compares, so a
    Python-side engine change that breaks parity fails on the server too.

The same standing as shared/vectors.json for the crypto: regenerate after
any engine change,
    cd backend && ../.venv/bin/python scripts/gen_brain_vectors.py
"""

from __future__ import annotations

import json
import math
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import brain, statsig  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "shared" / "brain_vectors.json"

TEXT_CASES: list[str] = [
    "quiet day, some work in the afternoon",
    "felt calm and grateful today",
    "i am happy today",
    "i am not happy today",
    "no stress at all today",
    "felt happy and calm but tired",
    "extremely bad no good very anxious",
    "it was very very good but honestly kind of awful afterwards",
    "working late on the presentations again, dreading tomorrow",
    "i slept terribly and cant stop thinking about the deadline",
    "cried all evening for no reason i can name",
    "proud of what we finished, relieved it shipped, exhausted though",
    "the interview went badly i suppose, but i realize now the reason i "
    "was nervous was because i cared about it",
    "walking home noticing the light, thinking about my sister, feeling okay",
    "absolutely wonderful 🎉 sunshine and coffee ☕ and no meetings",
    "terrible awful day 😞 but the dog 🐕 helped",
    "hardly slept, barely ate, somehow still standing",
    "not bad, not great, just a day",
    "so so so tired of everything",
    "understood why she said it, and knowing that helped more than i expected",
    "worried about mom again, the tests are friday",
    "running helped, outdoors helped, the run in the park always helps",
    "i don't know how i feel about the move yet",
    "because you asked, i will consider it",
    "",
    "🙂",
    "good good good good good",
    "sad sad happy",
    # Regression inputs from the TS-port debugging session: negation via
    # "nothing", morphological identity ("goodness" is not "good"), and
    # case handling all live here so both platforms stay pinned on them.
    "nothing emotional here",
    "goodness gracious",
    "GOOD day",
    "i realize now the reason was because i cared",
    # Spanish (2026-09-19): the merged-lexicon engine must score Spanish
    # identically on both platforms — negation, "pero" re-weighting,
    # intensifiers and pure valence all exercised.
    "hoy me siento muy feliz y tranquilo",
    "me siento triste y cansado con mucha ansiedad",
    "estoy cansado pero feliz",
    "no estoy bien",
    "nunca estoy tranquilo los domingos",
    "estoy muy muy agradecido por mi familia",
    "que dia tan horrible, todo salio mal",
    # 2026-09-20 audit H-8/H-18 pins: diacritic folding (the NFC and NFD
    # spellings of the same word must score IDENTICALLY), iOS U+2019
    # contraction negation, the ES death-word class, "quiero" no longer
    # reading positive, and the prototype-chain token "constructor"
    # scoring exactly 0.0 on-device (null-prototype lookup tables).
    "quiero morir",
    "me quiero morir",
    "pienso en el suicidio",
    "no quiero vivir",
    "estoy muy cansado de vivir",
    "tengo depresión y ansiedad",
    "tengo depresio\u0301n y ansiedad",
    "don\u2019t feel good",
    "constructor constructor constructor",
]

STAT_CASES = {
    "erfc": [0.05, 0.467, 1.0, 1.5, 2.0, 2.5, 3.5, 5.0, 7.0],
    "pearson": [
        [[0.1, 0.4, -0.2, 0.5, 0.3], [0.2, 0.35, -0.1, 0.55, 0.25]],
        [[1, 2, 3, 4], [4, 3, 2, 1]],
        [[0.5, 0.5, 0.5, 0.5], [0.1, -0.3, 0.2, 0.0]],
    ],
    "fisher_z": [
        [0.44, 28, -0.1, 40],
        [0.7, 15, 0.5, 20],
        [0.9, 12, -0.8, 30],
        [0.05, 50, 0.02, 60],
    ],
}


def build_update_cases() -> list[dict]:
    """The three FULL-ENGINE golden cases (Phase 3, 2026-09-21) — the
    contract the on-device port must satisfy (mobile/src/brain/PORT.md).

    Each case is a deterministic corpus; the expected output serializes
    the surfaced cards AND the complete new state (patterns sorted by
    pid, floats rounded to 9 decimals so JSON comparison is exact on both
    platforms). Importable so the backend parity test can re-run the
    exact generation path in-process (audit round 2, 2026-09-21, F-1).
    """
    from app.services.patterns import JournalEntry

    def _serialize_pattern(record) -> dict:
        out = {
            "pid": record.pid,
            "kind": record.kind,
            "label": record.label,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "first_qualified": record.first_qualified,
            "last_qualified": record.last_qualified,
            "occurrences": record.occurrences,
            "state": record.state,
            "qualification_days": record.qualification_days,
            "evidence_dates": record.evidence_dates,
        }
        detail = {}
        for key in sorted(record.detail):
            value = record.detail[key]
            if isinstance(value, float):
                value = round(value, 9)
            detail[key] = value
        out["detail"] = detail
        return out

    def _update_case(corpus, today) -> dict:
        result = brain.update(brain.load_state(None), corpus, today)
        return {
            "surfaced": [
                {
                    "kind": p.kind,
                    "label": p.label,
                    "occurrences": p.occurrences,
                    "detail": {
                        k: (round(v, 9) if isinstance(v, float) else v)
                        for k, v in sorted(p.detail.items())
                    },
                }
                for p in result.surfaced
            ],
            "state": [
                _serialize_pattern(record)
                for pid, record in sorted(result.new_state["patterns"].items())
            ],
        }

    t0 = date(2026, 8, 2)
    calm_corpus = [
        JournalEntry("felt calm and grateful today", t0 + timedelta(days=i)) for i in range(30)
    ]
    work_corpus = []
    for week in range(6):
        work_corpus.append(JournalEntry("anxious about work", t0 + timedelta(weeks=week)))
        for d in range(1, 7):
            work_corpus.append(JournalEntry("felt calm and grateful today", t0 + timedelta(weeks=week, days=d)))
    # Spanish twin of the work corpus (70 days / 10 work weekdays): the
    # ES theme lexicon must drive the same candidate machinery from Spanish
    # text — this case is the golden pin for the on-device port's Spanish
    # theme handling (audit Phase 2 workstream 1).
    spanish_corpus = []
    for week in range(10):
        spanish_corpus.append(
            JournalEntry("muy ansioso por el trabajo otra vez", t0 + timedelta(weeks=week))
        )
        for d in range(1, 7):
            spanish_corpus.append(
                JournalEntry("me sentí tranquilo y agradecido", t0 + timedelta(weeks=week, days=d))
            )
    return [
        {"name": "calm-30d", "case": _update_case(calm_corpus, t0 + timedelta(days=30))},
        {"name": "weekly-work-anxiety", "case": _update_case(work_corpus, t0 + timedelta(weeks=6))},
        {"name": "spanish-mixed", "case": _update_case(spanish_corpus, t0 + timedelta(weeks=10))},
    ]


def build_payload() -> dict:
    """The complete brain_vectors.json payload, in-memory."""
    sentiment_vectors = []
    # Tokenized EXACTLY as the engine does (2026-09-20 audit): the
    # engine's own fold + WORD_RE, imported — not hand-copied. A hand copy
    # silently drifts the day one side changes tokenization, and every
    # vector would then pin the drift instead of catching it.
    from app.services.patterns import WORD_RE  # noqa: PLC0415 — engine seam

    for text in TEXT_CASES:
        tokens = WORD_RE.findall(brain._fold_sentiment_text(text.lower()))
        tokens.extend(e for e in brain.EMOJI_VALENCES for _ in range(text.count(e)))
        pa, na = brain.sentiment_components(tokens)
        sentiment_vectors.append(
            {
                "text": text,
                "score": brain.sentiment_score(tokens),
                "pa": round(pa, 6),
                "na": round(na, 6),
            }
        )

    return {
        "v": 2,
        "note": "generated by backend/scripts/gen_brain_vectors.py — regenerate on engine change",
        "sentiment": sentiment_vectors,
        "updates": build_update_cases(),
        "stats": {
            "erfc": [[z, math.erfc(z)] for z in STAT_CASES["erfc"]],
            "pearson": [[xs, ys, brain._pearson(xs, ys)] for xs, ys in STAT_CASES["pearson"]],
            "fisher_z": [
                [r1, n1, r2, n2, statsig.fisher_z_difference_p(r1, n1, r2, n2)]
                for r1, n1, r2, n2 in STAT_CASES["fisher_z"]
            ],
        },
    }


def main() -> None:
    payload = build_payload()
    OUT.write_text(json.dumps(payload, indent=1) + "\n")
    print(
        f"wrote {OUT}: {len(payload['sentiment'])} sentiment vectors, "
        f"{len(payload['updates'])} full-engine update cases, "
        f"{len(payload['stats']['erfc'])} erfc, "
        f"{len(payload['stats']['pearson'])} pearson, "
        f"{len(payload['stats']['fisher_z'])} fisher-z"
    )


if __name__ == "__main__":
    main()
