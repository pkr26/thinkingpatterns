"""Deterministic analysis behavior and bounded scanner progress contracts.

Imports occur inside calls so broken analysis code fails the oracle itself.
"""

from __future__ import annotations

import builtins
import dataclasses
import gzip
import json
import math
import random
from datetime import date, timedelta
from pathlib import Path

import pytest

TODAY = date(2026, 10, 5)
ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "tools/tests/fixtures/analysis_runtime_contract.json.gz"


def runtime_contract():
    with gzip.open(CONTRACT, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def normalized(value):
    if dataclasses.is_dataclass(value):
        return normalized(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): normalized(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(normalized(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [normalized(item) for item in value]
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


class BoundedPatterns(dict):
    """A genuine mapping whose small-store scans must make finite progress."""

    reads = 0

    def _read(self):
        self.reads += 1
        assert self.reads <= 65536, "small semantic-fork store stopped making progress"

    def get(self, *args):
        self._read()
        return super().get(*args)

    def __contains__(self, item):
        self._read()
        return super().__contains__(item)

    def __getitem__(self, item):
        self._read()
        return super().__getitem__(item)


def bound_crisis_substitutions(monkeypatch, budget=100000):
    from app.services import crisis

    class Substitution:
        def __init__(self, expression):
            self.expression, self.calls = expression, 0

        def sub(self, replacement, text):
            self.calls += 1
            assert self.calls <= budget, (
                "finite crisis input exhausted its normalization budget"
            )
            return self.expression.sub(replacement, text)

    for name in ("_LEET_RE", "_LEET_EDGE_RE", "_LEET_TRAIL_RE"):
        monkeypatch.setattr(crisis, name, Substitution(getattr(crisis, name)))


def bound_phrase_walks(monkeypatch):
    from app.services import phrases

    class Parents(list):
        reads = 0

        def __getitem__(self, index):
            self.reads += 1
            assert self.reads <= 100000, (
                "small corpus exhausted its disjoint-set progress budget"
            )
            return super().__getitem__(index)

    def lists(values=()):
        return Parents(values) if isinstance(values, range) else builtins.list(values)

    monkeypatch.setattr(phrases, "list", lists, raising=False)


def threshold_cases():
    from app.services import threshold

    output = {}
    for offsets in (
        [],
        [0],
        [1],
        [-1],
        [0, -1],
        [1, 0, -1, -2],
        [0, 0, -1, -7],
        [-2, -3],
        [1, 2],
        list(range(-35, 1)),
    ):
        dates = [TODAY + timedelta(days=offset) for offset in offsets] + [None]
        for floor in (1, 2, 29, 30, 31):
            key = str((offsets, floor))
            output[key] = {
                "active": threshold.count_active_days(dates),
                "streak": threshold.current_streak(dates, TODAY),
                "state": threshold.evaluate(dates, threshold=floor, today=TODAY),
                "unlocked": threshold.is_unlocked(dates, floor),
            }
    output["defaults"] = threshold.evaluate([TODAY], today=TODAY)
    return normalized(output)


def pattern_examples():
    from app.services.patterns import Pattern

    kinds = [
        "temporal",
        "mood_correlation",
        "link",
        "avoidance",
        "cadence",
        "recurring_phrase",
        "mood_shift",
        "inertia",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
        "sense_making",
        "activity_diversity",
        "instability",
        "rumination",
        "topic",
        "unknown",
    ]
    details = [
        {},
        {"day": "Monday"},
        {"day": "Sunday", "source": "tag"},
        {"channel": "sleep_quality", "day": "Tuesday", "lag_days": 1},
        {
            "channel": "sleep_quality",
            "day": "Friday",
            "lag_days": 2,
            "direction": "higher",
        },
        {"source": "tag", "lag_days": 2, "direction": "higher", "mood_delta": -0.34567},
        {
            "direction": "lower",
            "mood_delta": 0.34567,
            "share": 0.315,
            "base_rate": 0.27,
            "silences": 2,
        },
        {"mood_delta": -0.15, "shift": -0.41, "trend": "rising", "share": 0.54},
        {"direction": "narrowed", "lag_days": 3, "share": 0.2},
        {"direction": "widened", "lag_days": 3, "share": 0.2},
    ]
    details.extend(
        {"day": day}
        for day in (
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        )
    )
    return [
        (f"{kind}:{index}", Pattern(kind, "guitar", 5, 0.987654321, detail))
        for kind in kinds
        for index, detail in enumerate(details)
    ]


def pattern_cases():
    from app.services import patterns

    output = {
        key: {"dict": pattern.to_dict(), "description": pattern.describe()}
        for key, pattern in pattern_examples()
    }
    for text in (
        "",
        "GOOD!! bad, work and sleep",
        "café — running with friends",
        "i keep thinking about the same work deadline. i keep thinking about the same work deadline!",
        "calm grateful happy exhausted anxious",
        "it's good, isn't it?",
    ):
        output[text] = {
            "normalize": patterns.normalize(text),
            "tokens": patterns.tokenize(text),
            "sentiment": patterns.sentiment_score(text),
            "themes": patterns.extract_themes(text),
            "sentences": patterns._sentences(text),
        }
    text = "i keep worrying about the same work deadline"
    for size in (0, 1, 3, 4, 5, 8):
        entries = [
            patterns.JournalEntry(
                text, TODAY - timedelta(days=index * 3), -0.6 if index % 2 else 0.4
            )
            for index in range(size)
        ]
        entries += [
            patterns.JournalEntry(
                "happy calm walking with friends",
                TODAY - timedelta(days=30 + index),
                0.7,
            )
            for index in range(size)
        ]
        result = patterns.analyze(entries)
        output[f"analysis:{size}"] = {
            "result": result.to_dict(),
            "private": result.to_dict(False),
            "phrases": patterns.recurring_phrases(entries),
            "custom_phrases": patterns.recurring_phrases(
                entries, min_count=3, min_span_days=6
            ),
        }
    output["weekday"] = [
        patterns._dominant_weekday(
            [TODAY - timedelta(days=offset) for offset in offsets]
        )
        for offsets in ([0], [0, 1], [0, 7, 1], [0, 1, 2, 3, 4, 5, 6])
    ]
    return normalized(output)


def question_cases(monkeypatch):
    from app.services import questions
    from app.services.patterns import Pattern

    monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
    output = {
        f"{key}:{language}": questions.render_pattern_questions(pattern, language)
        for key, pattern in pattern_examples()
        for language in ("en", "es", "other")
    }
    output["percentages"] = [
        questions._percent(value)
        for value in (
            None,
            False,
            True,
            "0.2",
            0,
            0.005,
            0.315,
            -1.2,
            float("nan"),
            float("inf"),
        )
    ]
    for index, detail in enumerate(
        (
            {},
            {"muted": True},
            {"muted": 1},
            {"sensitive": True},
            {"variants": [None, 1, "i want to kill myself"]},
            {"variants": "i want to kill myself"},
            {"feedback": {"resonated": 2, "not_me": 4}},
            {"feedback": {"resonated": 9, "not_me": 0}},
        )
    ):
        pattern = Pattern("topic", "guitar", 5, 0.6, detail)
        output[f"eligibility:{index}"] = [
            questions.pattern_is_muted(pattern),
            questions.pattern_is_sensitive(pattern),
            questions.feedback_rank(pattern),
        ]
    all_patterns = [
        pattern for key, pattern in pattern_examples() if key.endswith(":0")
    ]
    all_patterns += [
        Pattern("rumination", "i want to kill myself", 12, 0.9),
        Pattern("topic", "muted instrument", 10, 0.8, {"muted": True}),
    ]
    for language in ("en", "es", "other"):
        output["sensitive_first_pool:" + language] = questions.build_pool(
            [
                Pattern("rumination", "i want to kill myself", 12, 0.9),
                Pattern("topic", "guitar", 10, 0.8),
            ],
            language,
        )
        repeated = Pattern("topic", "guitar", 10, 0.8)
        output["duplicate_middle_pool:" + language] = questions.build_pool(
            [repeated, repeated, Pattern("topic", "mandolin", 10, 0.8)], language
        )
        output["pool:" + language] = questions.build_pool(all_patterns, language)
        for user in ("", "synthetic-user", "usuario-ñ"):
            for offset in (0, 1, 7, 30):
                key = f"rotation:{language}:{user}:{offset}"
                day = TODAY + timedelta(days=offset)
                first = questions.question_for_today(user, all_patterns, day, language)
                second = questions.question_for_today(user, [], day, language)
                output[key] = [questions.user_rotation_offset(user), first, second]
    return normalized(output)


def brain_primitive_cases():
    from app.services import brain

    output = {}
    texts = (
        "",
        "good work but not happy",
        "I don’t feel good, never really relaxed",
        "muy feliz tranquilo con trabajo y familia",
        "no estoy feliz ni tranquilo",
        "depresión depresio\u0301n café नमस्ते",
        "ά έ Ώ ḁ",
        "❤️❤ 😊😢 😌",
        "Bad un jour très triste",
        "because i realized why this happened i now understand what it meant",
    )
    for text in texts:
        folded = brain._fold_sentiment_text(text)
        tokens = brain.WORD_RE.findall(folded.lower()) + brain._emoji_tokens(text)
        output[text] = {
            "folded": folded,
            "emoji": brain._emoji_tokens(text),
            "sentences": brain.sentences_of(text),
            "density": brain.absolutist_density(tokens),
            "sense": brain._sense_density(tokens),
        }
        for language in (None, "en", "es", "other"):
            output[text][str(language)] = {
                "score": brain.sentiment_score(tokens, language),
                "components": brain.sentiment_components(tokens, language),
                "walk": brain._valence_walk(tokens, language),
                "themes": brain.extract_themes(tokens, language or "en"),
            }
    for token in (
        "hi",
        "is",
        "boss",
        "ties",
        "tries",
        "studies",
        "buses",
        "running",
        "stopped",
        "worked",
        "slept",
        "working",
        "happily",
        "tired",
        "depresion",
        "abbing",
        "abbed",
        "abXXing",
        "abXXed",
    ):
        output["forms:" + token] = brain.word_forms(token)
    for size in (0, 1, 3, 4, 5, 6, 7, 8, 9, 15, 30):
        series = [
            (TODAY - timedelta(days=size - index), math.sin(index * 1.7) * 0.6)
            for index in range(size)
        ]
        output[f"numeric:{size}"] = {
            "baseline": brain._personal_baselines(series),
            "weekday": brain._strip_weekday_effects(dict(series)),
            "lag": brain._lag1_autocorr([value for _, value in series]),
            "daily_lag": brain._daily_lag1_autocorr(dict(series)),
            "decay": brain._decay_strength([day for day, _ in series], TODAY),
        }
    output["pearson"] = [
        brain._pearson(left, right)
        for left, right in [
            ([], []),
            ([1, 2], [3, 4]),
            ([1, 1, 1], [1, 2, 3]),
            ([1, 2, 3], [1, 1, 1]),
            ([1, 2, 3], [3, 2, 1]),
            ([0, 1, 3, 2], [1, 3, 2, 4]),
            ([1, 2, 3], [1, 2]),
        ]
    ]
    output["sparse_baselines"] = [
        brain._personal_baselines(
            [(TODAY - timedelta(days=offset), value) for offset, value in rows]
        )
        for rows in ([(0, 1.0), (7, 0.0)], [(0, 1.0), (1, 0.8), (30, 0.2), (31, 0.0)])
    ]
    output["interpolation"] = [
        brain._interp_fraction(*values)
        for values in [(0, 1, 0.25), (1, 1, 1), (2, 1, 1), (-1, 1, 0), (0, 1, 2)]
    ]
    output["tod"] = [
        brain._dominant_tod(values)
        for values in [
            ["morning"],
            ["night", "morning"],
            ["afternoon", "night", "night"],
        ]
    ]
    output["names"] = [
        brain._mentions_name(text, name)
        for text, name in [
            ("I may go tomorrow", "may"),
            ("I saw May today", "may"),
            ("I saw ann", "ann"),
            ("I saw joanne", "ann"),
        ]
    ]
    output["lexicon_fold"] = [
        brain._fold_canonicalize_lexicon(dict(mapping))
        for mapping in (
            {"café": 1, "cafe": 2, "naïve": 3, "unique": 4, "été": -1},
            {"café": 2, "cafe": 2},
            {"cafe": 1},
            {"é": 1, "e": 0},
        )
    ]
    output["decay_edges"] = [
        brain._decay_strength([TODAY + timedelta(days=d) for d in offsets], TODAY)
        for offsets in ([], [0], [1], [45], [-45], [-90], [0] * 8, [0] * 9, [-45] * 16)
    ]
    output["signal_defaults"] = brain._Signal(
        "pid", "topic", "label", 4, None, {}, [TODAY]
    )
    for text in (
        "not good",
        "never really ever very happy",
        "not suicidal",
        "not sad",
        "can't stop crying",
        "can't quit smiling",
        "no puedo dejar de llorar",
        "good but bad",
        "bad but good",
        "good however happy",
        "not x x x good",
        "not x x good",
        "really x x happy",
        "really x x x happy",
        "depressed and depressed",
    ):
        tokens = text.split()
        output["scope:" + text] = [
            brain._valence_walk(tokens, language) for language in (None, "en", "es")
        ]
    return normalized(output)


def crisis_cases():
    from app.services import crisis

    contract = json.loads((ROOT / "shared/crisis_phrases.json").read_text())
    texts = sorted(
        {text for values in contract["fixtures"].values() for text in values}
        | {row["sample"] for row in contract["redteam_corpus"]}
        | {
            "ordinary journal",
            "I w a nt to die",
            "life i s n't worth living",
            "su1c1de",
            "suicide awareness",
            "weekend it all",
            "k😊ll myself",
            "killmyself",
            "नमस्ते suicideम",
        }
    )
    return {
        text: normalized(
            {
                "normal": crisis.normalize_crisis_text(text),
                "variants": crisis._match_variants(text),
                "folded": crisis._folded_variants(text),
                "dialog": crisis.matches_dialog(text),
                "suppress": crisis.matches_suppress(text),
            }
        )
        for text in texts
    }


def phrase_cases():
    from app.services import phrases

    output = {}
    texts = [
        "",
        "one",
        "one two",
        "one one two",
        "i keep worrying about work every night",
        "i keep worrying about work every evening",
        "i keep worrying about work each night",
        "happy calm walking with friends",
        "mañana con mi familia café",
    ]
    for text in texts:
        tokens = text.split()
        sig = phrases.signature(tokens)
        output[text] = {
            "shingles": phrases.shingles(tokens),
            "signature": sig,
            "bands": phrases._band_keys(sig),
            "hash": phrases._shingle_hash(text),
        }
    output["jaccard"] = [
        phrases.estimated_jaccard(a, b)
        for a, b in [
            ([], []),
            ([1], []),
            ([1], [1]),
            ([1, 2, 3, 4], [1, 0, 3, 0]),
            ([1, 2], [2, 1]),
        ]
    ]
    for seed in (0, 1, -1, 0xFFFFFFFFFFFFFFFF, 0x4D696E64506174):
        stream = phrases._splitmix64(seed)
        output[f"stream:{seed}"] = [next(stream) for _ in range(5)]
    for size in (0, 1, 2, 3, 4, 6):
        for spread in (0, 3, 7, 8):
            refs = [
                phrases.SentenceRef(
                    texts[4 + index % 3], TODAY - timedelta(days=index * spread)
                )
                for index in range(size)
            ]
            output[f"cluster:{size}:{spread}"] = phrases.near_duplicate_clusters(refs)
    for length in (119, 120, 121):
        refs = [
            phrases.SentenceRef(
                " ".join(["repeat"] * length), TODAY - timedelta(days=offset)
            )
            for offset in (0, 4, 8)
        ]
        output[f"long:{length}"] = phrases.near_duplicate_clusters(refs)
    refs = [
        phrases.SentenceRef(text, TODAY - timedelta(days=index * 4))
        for index, text in enumerate(texts[4:7] * 2)
    ]
    output["representative"] = phrases._representative(refs)
    output["custom"] = phrases.near_duplicate_clusters(
        refs, jaccard=0.7, min_size=2, min_span_days=4, min_distinct_days=2
    )
    return normalized(output)


def stored_record(
    brain,
    pid="topic:guitar",
    kind="topic",
    state="candidate",
    age=0,
    stale=0,
    occurrences=4,
    detail=None,
):
    return brain.StoredPattern(
        pid,
        kind,
        "guitar",
        (TODAY - timedelta(days=age)).isoformat(),
        (TODAY - timedelta(days=stale)).isoformat(),
        (TODAY - timedelta(days=age)).isoformat(),
        (TODAY - timedelta(days=stale)).isoformat(),
        occurrences,
        state,
        [(TODAY - timedelta(days=age)).isoformat()],
        [(TODAY - timedelta(days=age)).isoformat()],
        {},
        detail or {},
    )


def brain_state_cases():
    from app.services import brain

    output = {}
    raw_base = stored_record(brain).to_dict()
    output["missing_occurrences"] = brain._stored_from_dict(
        {k: v for k, v in raw_base.items() if k != "occurrences"}, "missing-count"
    )
    output["legacy_version_dump"] = [
        brain.dump_state({"v": version, "patterns": {}}).decode()
        for version in (0, 1, 2)
    ]
    for index, changes in enumerate(
        (
            {},
            {"kind": "foreign", "state": "confirmed"},
            {"label": "x" * 205},
            {"kind": None},
            {"label": None},
            {"state": "broken"},
            {"state": "XXcandidateXX"},
            {"state": "XXarchivedXX"},
            {"state": "archived"},
            {"occurrences": -1},
            {"occurrences": "12"},
            {"occurrences": "not numeric"},
            {"occurrences": None},
            {"occurrences": []},
            {
                "first_seen": "invalid",
                "last_seen": None,
                "first_qualified": 1,
                "last_qualified": "",
            },
            {
                "qualification_days": ["bad", None, 1]
                + [(TODAY - timedelta(days=i)).isoformat() for i in range(65)],
                "evidence_dates": [
                    (TODAY - timedelta(days=i)).isoformat() for i in range(65)
                ]
                + ["bad", None],
            },
            {"feedback": [], "detail": []},
            {"qualification_days": {}, "evidence_dates": "bad"},
        )
    ):
        raw = {**raw_base, **changes}
        output[f"record:{index}"] = brain._stored_from_dict(raw, "input-pid")
    output["record_shapes"] = [
        brain._stored_from_dict(raw, "x") for raw in (None, [], 1, "string")
    ]
    output["iso"] = [
        brain._parse_iso(value) for value in (None, 1, "", "2026-10-05", "2026-02-30")
    ]
    for index, raw in enumerate(
        (
            None,
            b"",
            b"\xff",
            b"{",
            b"null",
            b"[]",
            b"1",
            b"{}",
            b'{"v":3}',
            b'{"v":"2"}',
            b'{"v":1,"patterns":[]}',
            json.dumps(
                {
                    "v": 2,
                    "patterns": {"valid": raw_base, "invalid": None},
                    "history": [
                        None,
                        ["day"],
                        [1, []],
                        ["day", 1],
                        ["day", []],
                        ["day", [], 1],
                    ]
                    + [[str(i), []] for i in range(95)],
                    "muted": {
                        "": True,
                        "a": True,
                        "x" * 128: True,
                        "x" * 129: True,
                        "one": 1,
                        "false": False,
                        "yes": True,
                    },
                }
            ).encode(),
        )
    ):
        output[f"load:{index}"] = brain.load_state(raw)
    state = {
        "v": 2,
        "patterns": {
            "one": raw_base,
            "two": None,
            "three": stored_record(brain, "three"),
        },
        "history": None,
        "muted": None,
    }
    dumped = brain.dump_state(state)
    output["dump"] = [
        dumped.decode(),
        brain.load_state(dumped),
        brain.dump_state(brain.fresh_state()).decode(),
    ]
    return normalized(output)


def brain_lifecycle_cases():
    from app.services import brain

    output = {}
    for state in ("candidate", "emerging", "confirmed", "fading", "archived"):
        for stale in (0, 7, 8, 45, 46, 90, 91):
            record = stored_record(brain, state=state, age=100, stale=stale)
            store = brain.fresh_state()
            store["patterns"] = BoundedPatterns({record.pid: record})
            brain._merge_lifecycle(store, [], TODAY)
            output[f"aging:{state}:{stale}"] = store
    for kind in (
        "topic",
        "temporal",
        "mood_correlation",
        "recurring_phrase",
        "mood_shift",
        "inertia",
        "avoidance",
    ):
        for state in ("candidate", "emerging", "confirmed", "fading", "archived"):
            for age in (0, 7, 21):
                record = stored_record(
                    brain,
                    kind=kind,
                    state=state,
                    age=age,
                    detail={"day": "Monday", "direction": "lower"},
                )
                for new in (0, 1, 2):
                    record_copy = brain._stored_from_dict(record.to_dict(), record.pid)
                    record_copy.qualification_days += [TODAY.isoformat()]
                    signal = brain._Signal(
                        record.pid,
                        kind,
                        "guitar",
                        10 if age == 21 else 4,
                        0.01,
                        {"day": "Monday", "direction": "lower"},
                        [TODAY - timedelta(days=age)]
                        + [TODAY + timedelta(days=i + 1) for i in range(new)],
                    )
                    store = brain.fresh_state()
                    store["patterns"] = BoundedPatterns({record.pid: record_copy})
                    replication = brain._replication_satisfied(record_copy, signal)
                    brain._merge_lifecycle(store, [signal], TODAY)
                    output[f"promotion:{kind}:{state}:{age}:{new}"] = [
                        replication,
                        store,
                    ]
    for kind in ("temporal", "link", "mood_correlation", "mood_shift", "topic"):
        for old, new in (
            (None, None),
            (None, "higher"),
            ("lower", None),
            ("lower", "lower"),
            ("lower", "higher"),
        ):
            record = stored_record(
                brain, kind=kind, detail={"day": old, "direction": old}
            )
            signal = brain._Signal(
                record.pid,
                kind,
                "guitar",
                4,
                0.01,
                {"day": new, "direction": new},
                [TODAY],
            )
            output[f"flip:{kind}:{old}:{new}"] = brain._semantic_flip(record, signal)
    records = {
        str(index): stored_record(
            brain,
            str(index),
            state="archived" if index < 3 else "candidate",
            age=index,
            stale=index % 6,
            occurrences=index % 10,
        )
        for index in range(202)
    }
    store = brain.fresh_state()
    store["patterns"] = BoundedPatterns(records)
    brain._merge_lifecycle(store, [], TODAY)
    output["eviction"] = sorted(store["patterns"])
    for age in (20, 21, 22):
        store = brain.fresh_state()
        store["patterns"] = {
            "shift": stored_record(brain, "shift", "mood_shift", age=age)
        }
        output[f"anchor:{age}"] = brain._mood_reanchor_day(store, TODAY)
    record = stored_record(
        brain, detail={"phrase_anchor": "i keep worrying about work every night"}
    )
    record.kind = "recurring_phrase"
    for text in (
        "",
        "i keep worrying about work every night",
        "i keep worrying about work every evening",
        "a completely different sentence with other thoughts",
    ):
        signal = brain._Signal(
            "new", "recurring_phrase", text, 4, None, {"phrase_anchor": text}, [TODAY]
        )
        output["alias:" + text] = brain._phrase_alias_pid(signal, {"old": record})
    return normalized(output)


def brain_detector_cases():
    from app.services import brain

    output = {}
    for size in (0, 7, 8, 10, 12, 20, 21, 28, 40, 60, 90):
        for mode in ("noise", "shift", "smooth", "constant"):
            series = []
            for index in range(size):
                value = (
                    math.sin(index * 1.71) * 0.25
                    if mode == "noise"
                    else (
                        (-0.6 if index >= size // 2 else 0.5)
                        + math.sin(index * 1.71) * 0.07
                    )
                    if mode == "shift"
                    else math.sin(index * 0.19) * 0.7
                    if mode == "smooth"
                    else 0.2
                )
                series.append((TODAY - timedelta(days=size - 1 - index), value))
            residuals = dict(series)
            alternate = {
                day: math.cos(index * 0.83) * 0.5 if index < size // 2 else value
                for index, (day, value) in enumerate(series)
            }
            densities = [
                (day, 0.1 if index < size // 2 else 1.2 + abs(value))
                for index, (day, value) in enumerate(series)
            ]
            tags = {
                "walking": {
                    day for index, (day, _) in enumerate(series) if index % 2 == 0
                },
                "reading": {
                    day for index, (day, _) in enumerate(series) if index % 3 == 0
                },
                "friends": {
                    day
                    for index, (day, _) in enumerate(series)
                    if index % 5 == 0 and index < size // 2
                },
            }
            themes = {
                day: ({"work"} if index % 3 == 0 else {"family"})
                for index, (day, _) in enumerate(series)
            }
            output[f"detector:{size}:{mode}"] = {
                "inertia": brain._inertia_signal(
                    series, "inertia:mood", "inertia", "daily mood", TODAY
                ),
                "energy": brain._inertia_signal(
                    series,
                    "inertia:energy",
                    "energy_inertia",
                    "energy",
                    TODAY,
                    "energy",
                ),
                "coupling": brain._coupling_signal(residuals, alternate, TODAY),
                "mood": brain._detect_mood_dynamics(series, residuals, TODAY),
                "shift": brain._detect_mood_shift(series),
                "sense": brain._detect_sense_making(densities, TODAY),
                "entropy": brain._weekly_tag_entropies(tags),
                "diversity": brain._detect_activity_diversity(tags, TODAY),
                "cadence": brain._detect_cadence(set(residuals), TODAY),
                "avoidance": brain._detect_avoidance(themes, set(residuals), TODAY),
                "links": brain._detect_links(themes, residuals, TODAY),
            }
    for phi in (0, 0.1, 0.2, 0.5, 0.8, 0.99):
        for size in (20, 21, 30, 40, 60, 90, 180, 200):
            for z in (3, 3.1, 3.4, 4.5, 6, 7):
                output[f"alarm:{phi}:{size}:{z}"] = brain._ewma_alarm_probability(
                    phi, size, z
                )
    return normalized(output)


def brain_corpus_cases():
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    corpora = {
        "empty": [],
        "empty_text": [JournalEntry("", TODAY)],
        "emoji": [JournalEntry("😢❤😊", TODAY)],
        "unsupported": [
            JournalEntry("Сегодня было хорошо 日本語", TODAY - timedelta(days=i))
            for i in range(8)
        ],
        "explicit_unsupported": [
            JournalEntry(
                "日本語",
                TODAY - timedelta(days=i),
                (-1) ** i * 0.6,
                (-1) ** i * 0.4,
                1 + i % 5,
                ("walking",),
                "night",
            )
            for i in range(12)
        ],
        "calendar_edges": [
            JournalEntry("happy work", TODAY + timedelta(days=i), 0.5)
            for i in (-181, -180, -179, 0, 1)
        ],
        "nonfinite": [
            JournalEntry(
                "happy calm but tired", TODAY - timedelta(days=i), value, value
            )
            for i, value in enumerate(
                (None, float("nan"), float("inf"), float("-inf"), -2, 2)
            )
        ],
    }
    rng = random.Random(72105)
    for language in ("en", "es", "mixed"):
        entries = []
        for index in range(70):
            day = TODAY - timedelta(days=69 - index)
            if language == "es":
                text = (
                    "mi madre dijo que estoy triste preocupado con trabajo"
                    if index % 3 == 0
                    else "feliz tranquilo con mi familia porque ahora entiendo la razón"
                )
            else:
                text = (
                    "i keep worrying about the same work deadline every night"
                    if index % 3 == 0
                    else "i met Alice and felt happy calm because i realized why my friends helped"
                )
                if language == "mixed" and index % 5 == 0:
                    text = "日本語 Это дневник"
            entries.append(
                JournalEntry(
                    text,
                    day,
                    (-0.65 if day.weekday() == 0 else 0.4) + rng.uniform(-0.08, 0.08)
                    if index % 2 == 0
                    else None,
                    math.sin(index * 0.21),
                    1 + index % 5,
                    ("work",) if day.weekday() == 0 else ("walking", "family"),
                    "night" if index % 3 == 0 else "morning",
                )
            )
        corpora[language] = entries
    for name, entries in corpora.items():
        state = brain.fresh_state()
        first = brain.update(state, entries, TODAY)
        assert state == brain.fresh_state(), "analysis mutated its caller's state"
        second = brain.update(
            first.new_state,
            list(reversed(entries)),
            TODAY + timedelta(days=8),
            feedback=[(pid, False) for pid in sorted(first.new_state["patterns"])[:2]],
            muted=sorted(first.new_state["patterns"])[:1],
        )
        output[name] = [first, second]
    output["foreign_state"] = [
        brain.update(state, [], TODAY) for state in (None, [], {"patterns": []}, {})
    ]
    store = brain.fresh_state()
    for index in range(48):
        record = stored_record(
            brain,
            f"stored:{index:02}",
            "topic",
            ("confirmed", "emerging", "fading")[index % 3],
            age=index % 25,
            stale=0,
            occurrences=index % 15 + 2,
            detail={"share": 0.2, "sensitive": index % 11 == 0},
        )
        record.feedback = {"resonated": 98, "not_me": 98}
        record.evidence_dates = [
            (TODAY - timedelta(days=i)).isoformat() for i in range(index % 9 + 1)
        ]
        if index % 13 == 0:
            record.label = "i want to kill myself"
        store["patterns"][record.pid] = record
    store["muted"] = {f"stored:{index:02}": True for index in range(15)}
    store["history"] = [
        [(TODAY - timedelta(days=i)).isoformat(), ["stored:00"]] for i in range(92)
    ]
    output["stored_surface"] = brain.update(
        store,
        [],
        TODAY,
        feedback=[("missing", True), ("stored:00", True), ("stored:01", False)] * 35,
        muted=["", "missing", "x" * 129, *[f"stored:{i:02}" for i in range(15, 28)]],
        unmuted=["stored:00", "stored:02", "missing"],
    )
    return normalized(output)


def brain_measurement_cases(monkeypatch):
    """Record real measurement inputs while still running every detector."""
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    names = (
        "_analysis_language",
        "sentiment_components",
        "_sense_density",
        "_select_tag_themes",
        "_detect_themes",
        "_detect_links",
        "_detect_mood_shift",
        "_detect_mood_dynamics",
        "_inertia_signal",
        "_coupling_signal",
        "_detect_sense_making",
        "_detect_activity_diversity",
        "_detect_avoidance",
        "_detect_cadence",
        "_detect_topics",
        "_detect_phrases",
    )
    current = []
    id_entries = {}
    for name in names:
        original = getattr(brain, name)

        def traced(*args, _name=name, _original=original, **kwargs):
            cleaned = []
            for arg in args:
                if (
                    isinstance(arg, dict)
                    and arg
                    and all(isinstance(k, int) for k in arg)
                ):
                    arg = {str(id_entries.get(k, k)): v for k, v in arg.items()}
                cleaned.append(arg)
            result = _original(*args, **kwargs)
            current.append(
                [_name, normalized(cleaned), normalized(kwargs), normalized(result)]
            )
            return result

        monkeypatch.setattr(brain, name, traced)
    for size in (9, 10, 11, 12):
        entries = []
        for index in range(size):
            day = TODAY - timedelta(days=index)
            entries.append(
                JournalEntry(
                    "happy work because i understand my friends and the reason",
                    day,
                    (-1) ** index * 0.6,
                    (-1) ** index * 0.4,
                    1 + index % 5,
                    ("tag" + str(index % 4),),
                    "night",
                )
            )
            if index % 3 == 0:
                entries.append(
                    JournalEntry("sad family", day, None, 0.3, 5, ("tag0",), "morning")
                )
        current = []
        id_entries = {id(e): (e.entry_date.isoformat(), e.text) for e in entries}
        result = brain.update(brain.fresh_state(), entries, TODAY)
        output[f"structured:{size}"] = [result, current]
    for majority in ("en", "es", "other"):
        for explicit in (False, True):
            entries = []
            texts = {
                "en": "i met Alice and felt happy because i understood why my work was hard "
                * 8,
                "es": "mi madre dijo que estoy feliz porque entiendo cómo ocurrió el trabajo "
                * 8,
                "other": "日本語 Это дневник " * 40
                + "happy work family because i understand",
            }
            for i in range(20):
                text = (
                    texts[majority]
                    if i % 3
                    else texts["other" if majority != "other" else "en"]
                )
                if i in (1, 4):
                    text = ""
                entries.append(
                    JournalEntry(
                        text,
                        TODAY - timedelta(days=20 - i),
                        0.4 if explicit else None,
                        math.sin(i * 0.73) * 0.6,
                        tags=("guitar",),
                    )
                )
            current = []
            id_entries = {id(e): (e.entry_date.isoformat(), e.text) for e in entries}
            result = brain.update(brain.fresh_state(), entries, TODAY)
            output[f"mixed_measurement:{majority}:{explicit}"] = [result, current]
    for case in (
        "duplicates",
        "energy_clamp",
        "sleep_median",
        "punctuation_ratio",
        "reanchor",
    ):
        entries = []
        for i in range(20):
            text = "i am happy and worried because i realized why my work matters"
            if case == "punctuation_ratio":
                text = "`^_[ ] " + text
            energy = (-1 if i % 2 else 1) * (1.5 if case == "energy_clamp" else 0.4)
            sleep = (
                ([1, 1, 1, 2, 2, 2, 3, 3, 3, 4] + [5] * 10)[i]
                if case == "sleep_median"
                else None
            )
            day = TODAY - timedelta(days=i // 2 if case == "duplicates" else i)
            entries.append(JournalEntry(text, day, energy=energy, sleep_quality=sleep))
        current = []
        id_entries = {id(e): (e.entry_date.isoformat(), e.text) for e in entries}
        state = brain.fresh_state()
        if case == "reanchor":
            state["patterns"]["mood_shift:higher"] = stored_record(
                brain, "mood_shift:higher", "mood_shift", "confirmed", age=21
            )
            entries.extend(
                JournalEntry(
                    "happy work because i understand my friends",
                    TODAY - timedelta(days=i),
                    math.sin(i * 0.71) * 0.4,
                )
                for i in range(20, 60)
            )
            id_entries = {id(e): (e.entry_date.isoformat(), e.text) for e in entries}
        result = brain.update(state, entries, TODAY)
        output["specific_measurement:" + case] = [result, current]
    for size in (23, 24, 25, 30):
        days = {
            "tag" + str(i): {TODAY - timedelta(days=d) for d in range(i % 4 + 1)}
            for i in range(size)
        }
        counts = {k: len(v) + int(k[3:]) % 3 for k, v in days.items()}
        output[f"tags:{size}"] = brain._select_tag_themes(counts, days)
    entries = [
        JournalEntry("", TODAY - timedelta(days=i // 30), 0.2, 0.3) for i in range(4002)
    ]
    current = []
    id_entries = {id(e): (e.entry_date.isoformat(), e.text) for e in entries}
    result = brain.update(brain.fresh_state(), entries, TODAY)
    output["window_entry_cap"] = [result, current]
    entries = []
    common = "not never celadon amber ivory linen granite marble. "
    for i in range(8):
        day = TODAY - timedelta(days=i)
        entries.append(
            JournalEntry(
                ("i felt happy because i understood why my friends came today. " * 4)
                + common,
                day,
            )
        )
        entries.append(
            JournalEntry(
                (
                    "mi madre dijo que estoy feliz porque entiendo cómo ocurrió el trabajo. "
                    * 4
                )
                + common,
                day,
            )
        )
    current = []
    id_entries = {id(e): (e.entry_date.isoformat(), e.text) for e in entries}
    result = brain.update(brain.fresh_state(), entries, TODAY)
    output["same_sentence_mixed_entry_languages"] = [result, current]
    texts = [
        "one two three",
        "one two three four",
        " ".join(["word"] * 121),
        ". ".join(["i write another ordinary sentence"] * 42),
    ]
    output["sentence_limits"] = [brain.sentences_of(text) for text in texts]
    sentences = [
        JournalEntry(
            ". ".join([f"i write journal word number {i}"] * 41),
            TODAY - timedelta(days=i),
        )
        for i in range(103)
    ]
    output["window_sentence_cap"] = brain._window_sentences(sentences)
    return normalized(output)


def brain_dictionary_cases():
    from app.services import brain
    from app.services.patterns import JournalEntry

    inputs = runtime_contract()["vocabulary_inputs"]
    output = {}
    for token in inputs["words"]:
        output[token] = {
            "forms": brain.word_forms(token),
            "valence": [
                brain._word_valence(token, language) for language in (None, "en", "es")
            ],
            "theme": [
                brain.theme_for(token, language) for language in ("en", "es", "other")
            ],
            "absolutist": brain.absolutist_density([token]),
            "sense": brain._sense_density([token] * 10),
            "language": brain._analysis_language(
                [token] + ["qzxunknown"] * 9, 100, 100, True
            ),
        }
    for token in inputs["modifiers"]:
        for language in (None, "en", "es"):
            output[f"modifier:{token}:{language}"] = brain._valence_walk(
                [token, "good", "but", "bad"], language
            )
    for token in inputs["topic_filters"]:
        per_entry = []
        for index in range(30):
            tokens = [token, "nimbus" + str(index % 5), "aurora" + str(index % 7)]
            entry = JournalEntry(
                " ".join(tokens), TODAY - timedelta(days=30 - index), 0.3
            )
            per_entry.append((entry, tokens, set(), 0.3))
        output["topic_filter:" + token] = brain._detect_topics(per_entry, [], "en")
    for token in inputs["names"]:
        entries = [
            JournalEntry(
                f"I met {token.title()} near home and felt happy",
                TODAY - timedelta(days=i),
            )
            for i in range(8)
        ]
        output["name:" + token] = [
            brain._mentions_name(f"I saw {token.title()} yesterday", token),
            brain._mentions_name(f"i saw {token} yesterday", token),
            brain._person_candidates(entries),
        ]
    return normalized(output)


def pattern_boundary_cases():
    from app.services import patterns

    output = {
        "defaults": [
            patterns.JournalEntry("", TODAY),
            patterns.Pattern("topic", "guitar", 1, 0.5),
        ]
    }
    for word in sorted(
        set(patterns.POSITIVE_WORDS)
        | set(patterns.NEGATIVE_WORDS)
        | set(patterns.THEME_WORDS)
    ):
        output[word] = [patterns.sentiment_score(word), patterns.extract_themes(word)]
    for size in (3, 4, 5, 8, 12, 16, 24):
        for delta in (0.299, 0.3, 0.301, 0.34567, 0.7):
            entries = [
                patterns.JournalEntry(
                    "work deadline", TODAY - timedelta(days=i * 7), 0.0
                )
                for i in range(size)
            ]
            entries += [
                patterns.JournalEntry(
                    "quiet journal", TODAY - timedelta(days=i * 7 + 1), delta
                )
                for i in range(size)
            ]
            output[f"analysis:{size}:{delta}"] = patterns.analyze(entries)
    entries = [
        patterns.JournalEntry(
            "happy work", TODAY - timedelta(days=i * 7 + (i % 3 == 0)), 0.25
        )
        for i in range(9)
    ]
    entries += [
        patterns.JournalEntry("calm family", TODAY - timedelta(days=i * 7 + 3), 0.6)
        for i in range(4)
    ]
    output["mixed_weekday_strength_order"] = patterns.analyze(entries)
    output["weekday_tie"] = patterns._dominant_weekday(
        [TODAY + timedelta(days=i) for i in (5, 2)]
    )
    output["balanced_words"] = patterns.sentiment_score("happy sad")
    for weekday in range(7):
        base = TODAY - timedelta(days=(TODAY.weekday() - weekday) % 7)
        output[f"all_weekdays:{weekday}"] = patterns.analyze(
            [
                patterns.JournalEntry("work", base - timedelta(days=7 * i), 0.0)
                for i in range(8)
            ]
        )
    entries = [
        patterns.JournalEntry(
            " ".join(
                word + chr(97 + n // 26) + chr(97 + n % 26)
                for word in ("phrase", "alpha", "beta", "gamma", "delta")
            ),
            TODAY - timedelta(days=3 * i),
        )
        for n in range(32)
        for i in range(4)
    ]
    output["full_card_capacity"] = patterns.analyze(entries)
    for rate in (0.315, 0.515, 0.025):
        output[f"avoidance_rounding:{rate}"] = patterns.Pattern(
            "avoidance", "work", 7, 0.5, {"base_rate": rate, "share": rate}
        ).describe()
    entries = [
        patterns.JournalEntry("first short phrase", TODAY),
        *[
            patterns.JournalEntry("second narrow phrase", TODAY - timedelta(days=i))
            for i in range(3)
        ],
        *[
            patterns.JournalEntry("third wide phrase", TODAY - timedelta(days=i * 4))
            for i in range(3)
        ],
    ]
    output["phrase_skip_order"] = patterns.recurring_phrases(entries)
    output["blank_and_tagged"] = patterns.analyze(
        [
            patterns.JournalEntry("", TODAY),
            patterns.JournalEntry("", TODAY, 0.6),
            patterns.JournalEntry("happy calm", TODAY),
        ]
    )
    for detail in (
        {"channel": "sleep_quality"},
        {"source": "tag", "lag_days": 1},
        {"direction": "widened"},
        {"trend": "steady", "share": "unknown"},
    ):
        for kind in ("temporal", "link", "activity_diversity", "topic"):
            output[f"copy:{kind}:{detail}"] = patterns.Pattern(
                kind, "guitar", 3, 0.7, detail
            ).describe()
    return normalized(output)


def brain_positive_cases(monkeypatch):
    from app.services import brain, phrases
    from app.services.patterns import JournalEntry

    output = {}
    for size in (16, 32, 80):
        for tagged in (False, True):
            for language in ("en", "es"):
                for lag in (None, 0.7):
                    per_entry = []
                    weekdays = {}
                    languages = {}
                    for i in range(size):
                        day = TODAY - timedelta(days=size - i)
                        has_theme = i % 3 != 1
                        text = (
                            (
                                "insomnia anxious"
                                if language == "en"
                                else "insomnio preocupado"
                            )
                            if has_theme
                            else "happy calm"
                        )
                        if i == 1:
                            text = ""
                        tokens = text.split()
                        themes = {"sleep"} if has_theme else set()
                        raw = brain.sentiment_score(tokens, language)
                        residual = (-0.31 if has_theme else 0.41) + math.sin(
                            i * 1.37
                        ) * 0.07
                        entry = JournalEntry(
                            text,
                            day,
                            residual if tagged else None,
                            tod="night" if i % 4 else "morning",
                        )
                        languages[id(entry)] = language if i % 5 else "other"
                        weekdays[day.weekday()] = weekdays.get(day.weekday(), 0) + 1
                        per_entry.append((entry, tokens, themes, residual, raw, tagged))
                        if i % 7 == 0:
                            per_entry.append(
                                (entry, tokens, themes, residual + 0.03, raw, tagged)
                            )
                    output[f"theme:{size}:{tagged}:{language}:{lag}"] = (
                        brain._detect_themes(
                            per_entry, weekdays, size, lag, language, languages
                        )
                    )
                    output[f"theme_nomap:{size}:{tagged}:{language}:{lag}"] = (
                        brain._detect_themes(per_entry, weekdays, size, lag, language)
                    )
    for size in (14, 16, 18, 30, 60):
        for gap in (1, 2, 3):
            days = [TODAY - timedelta(days=(size - i) * gap) for i in range(size)]
            themes = {
                day: ({"work"} if i % 2 == 0 else {"family"})
                for i, day in enumerate(days)
            }
            moods = {
                day: (0.37 if i % 2 == 0 else -0.27) + math.sin(i * 1.7) * 0.07
                for i, day in enumerate(days)
            }
            output[f"link:{size}:{gap}"] = brain._detect_links(
                themes, moods, TODAY, 0.25
            )
    for size in (20, 30, 45, 90, 120):
        days = {TODAY - timedelta(days=size - i) for i in range(size) if i % 3 != 1}
        themes = {
            day: ({"work"} if i % 3 == 0 else {"family"})
            for i, day in enumerate(sorted(days))
        }
        # Follow an observed work day by a silence while keeping later writing.
        themes = {
            TODAY - timedelta(days=size - i): {"work" if i % 3 == 0 else "family"}
            for i in range(size)
            if i % 3 != 1
        }
        output[f"avoidance:{size}"] = brain._detect_avoidance(themes, days, TODAY)
    for weeks in (7, 8, 9, 10, 12):
        for widened in (False, True):
            tags = {}
            for w in range(weeks):
                wide = (w >= weeks - 4) == widened
                for d in range(6):
                    day = TODAY - timedelta(days=(weeks - w) * 7 - d)
                    for tag in range(8 if wide else 2):
                        if d % 3 == 0 and tag > 0 and tag % 3 == 0:
                            continue
                        tags.setdefault("tag" + str(tag), set()).add(day)
            output[f"diversity:{weeks}:{widened}"] = [
                brain._weekly_tag_entropies(tags),
                brain._detect_activity_diversity(tags, TODAY),
            ]
    for recent in (0.799, 0.8, 0.801, 1.299, 1.3, 1.301):
        for earlier in (0.299, 0.3, 0.301, 0.8):
            densities = [(TODAY - timedelta(days=40 - i), earlier) for i in range(12)]
            densities += [(TODAY - timedelta(days=12 - i), recent) for i in range(12)]
            output[f"sense:{recent}:{earlier}"] = brain._detect_sense_making(
                densities, TODAY
            )
    series = [(TODAY - timedelta(days=50 - i), math.sin(i * 1.73)) for i in range(50)]
    for r_recent, r_earlier in (
        (None, 0.2),
        (0.5, None),
        (0.449, 0.19),
        (0.45, 0.2),
        (0.451, 0.201),
        (0.7, 0.45),
        (0.701, 0.45),
        (0.1, 0.2),
    ):
        for kind in ("inertia", "coupling"):
            readings = iter((r_recent, r_earlier))
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(
                    brain, "_pearson", lambda a, b, readings=readings: next(readings)
                )
                result = (
                    brain._inertia_signal(series, "pid", "inertia", "label", TODAY)
                    if kind == "inertia"
                    else brain._coupling_signal(dict(series), dict(series), TODAY)
                )
            output[f"effect:{kind}:{r_recent}:{r_earlier}"] = result
    recent_gaps = [1, 1, 3, 1, 2, 1, 1, 3, 1, 1, 2, 1, 1, 1]
    for count in (11, 12, 13):
        days = {TODAY - timedelta(days=29 + i * 2) for i in range(count)}
        offset = 0
        for gap in recent_gaps[:count]:
            days.add(TODAY - timedelta(days=offset))
            offset += gap
        output[f"cadence_gap:{count}"] = brain._detect_cadence(days, TODAY)
    for size in (20, 40, 60):
        for share in (0.25, 0.3, 0.5, 0.8, 0.95, 1):
            for language in ("en", "es"):
                rows = []
                language_map = {}
                contexts = [
                    "luminous",
                    "nebula",
                    "harbor",
                    "lantern",
                    "orchard",
                    "marble",
                ]
                for i in range(size):
                    tokens = (
                        ["guitar's", "practice", contexts[i % 6]]
                        if i >= size - int(size * share)
                        else ["quiet", "ordinary", "journal"]
                    )
                    if language == "es":
                        tokens += ["porque", "ahora", "cuando"]
                    entry = JournalEntry(
                        " ".join(tokens), TODAY - timedelta(days=size - i), 0.2
                    )
                    rows.append((entry, tokens, set(), 0.2))
                    language_map[id(entry)] = language
                output[f"topic:{size}:{share}:{language}"] = brain._detect_topics(
                    rows, [], language, language_map
                )
                if share == 0.8:
                    refs = [
                        phrases.SentenceRef(e.text, e.entry_date) for e, _, _, _ in rows
                    ]
                    clusters = [
                        phrases.PhraseCluster(refs, refs[0].text, size - 1, size)
                    ]
                    output[f"covered_topic:{size}:{language}"] = brain._detect_topics(
                        rows, clusters, language, language_map
                    )
    for label in ("guitar", "guitar practice", "practice", "", "instrument"):
        refs = [
            phrases.SentenceRef(text, TODAY - timedelta(days=i))
            for i, text in enumerate(
                (
                    "i play guitar practice today",
                    "guitar practice sounds nice",
                    "guitars are fun",
                    "an instrument",
                )
            )
        ]
        cluster = phrases.PhraseCluster(refs, refs[0].text, 3, 4)
        output["covered:" + label] = brain._cluster_covered_days([cluster], label)
    for label in ("ordinary thought", "i want to kill myself"):
        for variants in (
            None,
            [],
            ["ordinary thought"],
            ["i want to kill myself"],
            "i want to kill myself",
        ):
            for seen in (False, True, 1):
                record = stored_record(
                    brain, detail={"variants": variants, "suppress_variant_seen": seen}
                )
                record.label = label
                output[f"sensitive:{label}:{variants}:{seen}"] = (
                    brain._record_is_sensitive(record)
                )
    for first_seen in (
        "",
        "bad",
        TODAY.isoformat(),
        (TODAY - timedelta(days=100)).isoformat(),
    ):
        record = stored_record(brain, age=100)
        record.first_seen = first_seen
        record.last_qualified = ""
        store = brain.fresh_state()
        store["patterns"] = {record.pid: record}
        # Invalid first_seen is removed by the real load boundary before merge.
        store = brain.load_state(brain.dump_state(store))
        brain._merge_lifecycle(store, [], TODAY)
        output["no_qualification:" + first_seen] = store
    return normalized(output)


def brain_deeper_cases(monkeypatch):
    from app.services import brain, phrases
    from app.services.patterns import JournalEntry

    output = {}
    for capacity in (4095, 4096, 4097):
        cache = {chr(0x5000 + i): chr(0x5000 + i) for i in range(capacity)}
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(brain, "_FOLD_CACHE", cache)
            folded = brain._fold_sentiment_text("é")
            output[f"fold_cache:{capacity}"] = [
                folded,
                len(cache),
                "é" in cache,
                chr(0x5000) in cache,
            ]
    for text in (
        "not bad",
        "extremely ecstatic",
        "extremely devastated",
        "not tired",
        "extremely happy and very wonderful",
        "❤❤❤",
        "not not happy",
        "no nunca triste",
        "i can't never really stop crying",
        "nothing",
        "good but extremely bad",
    ):
        tokens = brain.WORD_RE.findall(
            brain._fold_sentiment_text(text.lower())
        ) + brain._emoji_tokens(text)
        output["sentiment_edge:" + text] = [
            brain.sentiment_score(tokens, language) for language in (None, "en", "es")
        ]
        output["components_edge:" + text] = [
            brain.sentiment_components(tokens, language)
            for language in (None, "en", "es")
        ]
    for size in (20, 21, 22, 39, 40, 41, 89, 90, 91, 179, 180):
        for tail in (0, 1, 2, 3, 4, 5, 6, 7, 10):
            for direction in (-1, 1):
                series = [
                    (
                        TODAY - timedelta(days=size - 1 - i),
                        direction * 0.7 if i >= size - tail else 0.0,
                    )
                    for i in range(size)
                ]
                output[f"chart:{size}:{tail}:{direction}"] = brain._detect_mood_shift(
                    series
                )
    for phi in (-1, 0, 0.2, 0.4, 0.6, 0.8, 1, 2):
        for size in (1, 20, 21, 22, 40, 90, 180, 181):
            for z in (0, 3.1, 3.3, 3.5, 4, 5, 6, 20):
                output[f"table:{phi}:{size}:{z}"] = brain._ewma_alarm_probability(
                    phi, size, z
                )
    for token in (
        "pies",
        "ties",
        "mies",
        "mis",
        "kiss",
        "kisses",
        "talks",
        "ing",
        "being",
        "singing",
        "ringing",
        "runnning",
        "seeeing",
        "played",
        "tired",
        "cooked",
        "passed",
        "bossed",
        "worked",
    ):
        output["form_edge:" + token] = brain.word_forms(token)
    for ratio in (0, 0.499, 0.5, 0.501, 1):
        for size in (0, 1, 9, 10, 49, 50, 51):
            for text in (False, True):
                tokens = ["happy"] + ["unrecognized"] * max(0, size - 1) if size else []
                output[f"language:{ratio}:{size}:{text}"] = brain._analysis_language(
                    tokens, int(ratio * 1000), 1000, text
                )
    for count in (5, 6, 7, 8, 9):
        for dates in (1, 5, 6, 7):
            en = [
                JournalEntry(
                    "Alice. I met Alice and Bob today near Cafe. Bob starts again",
                    TODAY - timedelta(days=i % dates),
                )
                for i in range(count)
            ]
            es = [
                JournalEntry(
                    "mi tío habló con mi madre y mi jefa",
                    TODAY - timedelta(days=i % dates),
                )
                for i in range(count)
            ]
            output[f"person:{count}:{dates}"] = [
                brain._person_candidates(en),
                brain._person_candidates_es(es),
            ]
    names = [
        "Alden",
        "Brenna",
        "Cade",
        "Della",
        "Ewan",
        "Fara",
        "Garen",
        "Hela",
        "Iven",
        "Jora",
        "Kellan",
        "Lena",
        "Maren",
        "Nella",
        "Oren",
        "Petra",
        "Quinn",
        "Rella",
        "Soren",
        "Tara",
        "Ulla",
        "Varen",
        "Willa",
        "Xara",
        "Yoren",
        "Zella",
        "Arel",
    ]
    for count in (23, 24, 25, 27):
        entries = [
            JournalEntry(
                "I met " + " and ".join(names[:count]), TODAY - timedelta(days=i % 9)
            )
            for i in range(10)
        ]
        output[f"person_cap:{count}"] = brain._person_candidates(entries)
    for text in (
        "mi madre",
        "mi madresa",
        "mi tío",
        "mmi madre",
        "mi madre!",
        "MADRE",
        "mi padre",
    ):
        output["relation:" + text] = [
            brain._mentions_es_relation(text, "mi madre"),
            brain._person_mention(text, "mi madre", "es"),
            brain._person_mention(text, "madre", "en"),
        ]
    for age in (1, 6, 7, 8, 20, 21, 22):
        for qdays in ([TODAY], [TODAY - timedelta(days=1), TODAY]):
            record = stored_record(brain, age=age)
            record.qualification_days = [d.isoformat() for d in qdays]
            store = brain.fresh_state()
            store["patterns"] = BoundedPatterns({record.pid: record})
            sig = brain._Signal(record.pid, "topic", "guitar", 4, None, {}, [TODAY])
            brain._merge_lifecycle(store, [sig], TODAY)
            output[f"candidate_age:{age}:{qdays}"] = store
    for empty in (False, True):
        first = stored_record(brain, "aaa", state="confirmed", age=0)
        first.last_qualified = "" if empty else TODAY.isoformat()
        later = stored_record(brain, "zzz", state="confirmed", age=30, stale=8)
        store = brain.fresh_state()
        store["patterns"] = BoundedPatterns({first.pid: first, later.pid: later})
        signals = (
            []
            if empty
            else [brain._Signal(first.pid, "topic", "guitar", 4, None, {}, [TODAY])]
        )
        brain._merge_lifecycle(store, signals, TODAY)
        output[f"aging_progress:{empty}"] = store
    record = stored_record(brain, age=100)
    record.qualification_days = [
        (TODAY - timedelta(days=i)).isoformat() for i in range(1, 66)
    ]
    record.evidence_dates = list(record.qualification_days)
    store = brain.fresh_state()
    store["patterns"] = BoundedPatterns({record.pid: record})
    sig = brain._Signal(record.pid, "topic", "x" * 205, 4, None, {}, [TODAY])
    brain._merge_lifecycle(store, [sig], TODAY)
    output["lifecycle_caps"] = store
    for incoming in ("alpha alpha beta", "alpha alpha", "different thought"):
        record = stored_record(
            brain, kind="recurring_phrase", detail={"phrase_anchor": "alpha alpha"}
        )
        sig = brain._Signal(
            "new",
            "recurring_phrase",
            incoming,
            4,
            None,
            {"phrase_anchor": incoming},
            [TODAY],
        )
        output["alias_exact:" + incoming] = brain._phrase_alias_pid(
            sig, {"old": record}
        )
    for negative in (False, True):
        text = (
            "i never can't escape this painful awful thought"
            if negative
            else "i always love this happy peaceful thought"
        )
        refs = [
            phrases.SentenceRef(text, TODAY - timedelta(days=i * 4)) for i in range(4)
        ]
        cluster = phrases.PhraseCluster(refs, text, 12, 4)
        for language in (None, "en", "es", "other"):
            for allow in (False, True):
                langs = {
                    (r.day, r.text): ("other" if i == 0 else language)
                    for i, r in enumerate(refs)
                }
                output[f"phrase_signal:{negative}:{language}:{allow}"] = (
                    brain._detect_phrases([cluster], allow, language)
                )
                output[f"phrase_signal_map:{negative}:{language}:{allow}"] = (
                    brain._detect_phrases([cluster], allow, language, langs)
                )
    return normalized(output)


def brain_final_cases(monkeypatch):
    from app.services import brain, phrases
    from app.services.patterns import JournalEntry

    output = {}
    for token in (
        "but good",
        "however bad",
        "very no",
        "no but calm",
        "calm but no",
        "extremely very extremely no",
        "not suicidal good",
        "not suicidal but happy",
        "not x good happy",
        "extremely extremely extremely no",
    ):
        output["valence:" + token] = [
            brain._valence_walk(token.split(), lang) for lang in (None, "en", "es")
        ]
    for noun in (
        "madre",
        "padre",
        "hermano",
        "hermana",
        "hijo",
        "hija",
        "abuelo",
        "abuela",
        "tio",
        "tia",
        "primo",
        "prima",
        "jefe",
        "jefa",
        "esposa",
        "esposo",
        "marido",
        "suegra",
        "suegro",
    ):
        entries = [
            JournalEntry("ayer hablé con mi " + noun, TODAY - timedelta(days=i))
            for i in range(8)
        ]
        output["relation_all:" + noun] = [
            brain._person_candidates_es(entries),
            brain._person_mention(entries[0].text, "mi " + noun, "es"),
        ]
    for terminator in (".", "!", "?", "", "word"):
        text = f"I saw May{terminator} Alice Bob and met Zora"
        entries = [JournalEntry(text, TODAY - timedelta(days=i)) for i in range(8)]
        output["sentence_initial:" + terminator] = brain._person_candidates(entries)
    for weeks in (7, 8, 9):
        for wide_recent in (False, True):
            tags = {}
            for w in range(weeks + 1):
                wide = (w > weeks - 4) == wide_recent
                for d in range(6):
                    day = TODAY - timedelta(days=(weeks - w) * 7 - d)
                    for tag in range(8 if wide else 2):
                        if tag > 0 and (tag + d) % 4 == 0:
                            continue
                        tags.setdefault("tag" + str(tag), set()).add(day)
            output[f"complete_weeks:{weeks}:{wide_recent}"] = (
                brain._detect_activity_diversity(tags, TODAY + timedelta(days=5))
            )
    for count in (7, 8, 9):
        for level in (0.799, 0.8, 0.801):
            earlier = [
                (TODAY - timedelta(days=40 - i), 0.3 * count if i == count - 1 else 0)
                for i in range(count)
            ]
            recent = [
                (
                    TODAY - timedelta(days=count - i),
                    level * count if i == count - 1 else 0,
                )
                for i in range(count)
            ]
            output[f"sense_exact:{count}:{level}"] = brain._detect_sense_making(
                earlier + recent, TODAY
            )
    rng = random.Random(168492)
    for n in (30, 60, 90, 180):
        for phi in (0, 0.25, 0.5, 0.75, 0.9):
            for sigma in (0.03, 0.08, 0.15, 0.3):
                for delta in (-0.6, -0.3, -0.15, 0.15, 0.3, 0.6):
                    series = []
                    value = 0
                    for i in range(n):
                        value = phi * value + rng.gauss(0, sigma)
                        mood = max(-1, min(1, value + (delta if i > n * 0.55 else 0)))
                        series.append((TODAY - timedelta(days=n - 1 - i), mood))
                    output[f"moderate_chart:{n}:{phi}:{sigma}:{delta}"] = (
                        brain._detect_mood_shift(series)
                    )
    for label in (
        "first worried phrase",
        "i want to kill myself",
        "never not bad",
        "happy calm thought",
    ):
        variants = [
            label,
            "another ordinary thought",
            "a calm alternative",
            "zzz i want to kill myself",
        ]
        refs = [
            phrases.SentenceRef(text, TODAY - timedelta(days=i * 4))
            for i, text in enumerate(variants)
        ]
        cluster = phrases.PhraseCluster(refs, label, 12, 4)
        output["phrase_variant:" + label] = brain._detect_phrases([cluster], True, "en")
    for count in (9, 10, 11, 12):
        themed = []
        plain = []
        weekdays = {}
        for i in range(count * 2):
            day = TODAY - timedelta(days=count * 2 - i)
            theme = i < count
            entry = JournalEntry(
                "work" if theme else "quiet", day, 0.2 if theme else 0.4, tod="night"
            )
            weekdays[day.weekday()] = weekdays.get(day.weekday(), 0) + 1
            (themed if theme else plain).append(
                (
                    entry,
                    entry.text.split(),
                    {"work"} if theme else set(),
                    0.2 if theme else 0.4,
                    0.2 if theme else 0.4,
                    True,
                )
            )
        output[f"theme_exact_counts:{count}"] = brain._detect_themes(
            themed + plain, weekdays, count * 2
        )
    return normalized(output)


def test_brain_remaining_numeric_phrase_and_calendar_boundaries(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    bound_phrase_walks(monkeypatch)
    assert brain_final_cases(monkeypatch) == runtime_contract()["brain_final"]


def brain_floor_cases():
    from app.services import brain

    output = {}
    for theme_days in (7, 8, 9, 10, 11, 12, 20):
        for other_days in (7, 8, 9, 12):
            for delta in (0.0, 0.199, 0.2, 0.201, 0.6):
                rows = []
                for index in range(theme_days + other_days):
                    themed = index < theme_days
                    day = TODAY - timedelta(days=index * 7 + (0 if themed else 1))
                    mood = 0.0 if themed else delta
                    entry = brain.JournalEntry(
                        "" if index == 0 else "calm",
                        day,
                        sentiment=mood,
                        tod="night" if index % 10 < 7 else "morning",
                    )
                    rows.append(
                        (entry, [], {"work"} if themed else set(), mood, mood, True)
                    )
                days = {row[0].entry_date for row in rows}
                weekday_days = {
                    weekday: sum(d.weekday() == weekday for d in days)
                    for weekday in range(7)
                }
                output[f"theme:{theme_days}:{other_days}:{delta}"] = (
                    brain._detect_themes(rows, weekday_days, len(days), language="en")
                )

    for earlier_n in (9, 10, 11, 12):
        for recent_n in (9, 10, 11, 12):
            for gap in (1, 2, 3):
                series = [
                    (TODAY - timedelta(days=29 + i * gap), math.sin(i * 2.1) * 0.15)
                    for i in range(earlier_n + 1)
                ]
                series += [
                    (TODAY - timedelta(days=i * gap), math.sin(i * 0.25) * 0.4)
                    for i in range(recent_n + 1)
                ]
                series.sort()
                key = f"dynamics:{earlier_n}:{recent_n}:{gap}"
                output[key] = {
                    "inertia": brain._inertia_signal(
                        series, "test", "inertia", "daily mood", TODAY
                    ),
                    "coupling": brain._coupling_signal(
                        dict(series),
                        {
                            day: -value + math.sin(i) * 0.1
                            for i, (day, value) in enumerate(series)
                        },
                        TODAY,
                    ),
                    "instability": brain._detect_mood_dynamics(
                        series, dict(series), TODAY
                    ),
                }

    for size in (2, 3, 4, 5, 10, 30, 60):
        for mask in (1, 2, 3, 5, 7, 11):
            days = {
                TODAY - timedelta(days=i) for i in range(size) if (i * mask) % 7 < 4
            }
            themes = {
                day: ({"work"} if i % 3 == 0 else {"play"})
                for i, day in enumerate(sorted(days))
            }
            output[f"avoidance:{size}:{mask}"] = brain._detect_avoidance(
                themes, days, TODAY
            )
    for recent_n in (5, 6, 7, 8, 10):
        for earlier_n in (5, 6, 7, 8, 10):
            days = {TODAY - timedelta(days=1 + i * 2 + i % 2) for i in range(recent_n)}
            days |= {TODAY - timedelta(days=30 + i * 3) for i in range(earlier_n)}
            output[f"cadence:{recent_n}:{earlier_n}"] = brain._detect_cadence(
                days, TODAY
            )

    for language in ("en", "es", "other"):
        for token in (
            "guit",
            "guitar",
            "only",
            "now",
            "porque",
            "para",
            "about",
            "always",
            "really",
            "never",
            "teaching",
            "happiness",
            "sleep",
            "anything",
        ):
            for size in (15, 16, 17, 20, 32):
                rows = []
                for index in range(size):
                    tokens = (
                        [token, "celadon", "amber", f"context{index % 8}"]
                        if index >= size // 4
                        else ["ordinary", "journal"]
                    )
                    day = TODAY - timedelta(days=size - index)
                    entry = brain.JournalEntry(" ".join(tokens), day)
                    rows.append((entry, tokens, set(), 0.0))
                output[f"topic:{language}:{token}:{size}"] = brain._detect_topics(
                    rows, [], language=language
                )
    return normalized(output)


def test_brain_exact_statistical_sample_and_calendar_floors():
    assert brain_floor_cases() == runtime_contract()["brain_floors"]


def brain_stemming_contract_cases():
    from app.services import brain

    words = runtime_contract()["theme_stemming_inputs"]
    return {
        f"{language}:{word}": [brain.word_forms(word), brain.theme_for(word, language)]
        for language, word in words
    }


def test_theme_aliases_are_consumed_through_the_supported_single_pass_stemmer():
    assert (
        normalized(brain_stemming_contract_cases())
        == runtime_contract()["theme_stemming"]
    )


def brain_gap_cases(monkeypatch):
    """Actual detector outputs for clustered days and unequal statistical windows."""
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    for language in (None, "en", "es"):
        for word in ("good", "bad"):
            output[f"booster_cap:{language}:{word}"] = brain._valence_walk(
                ["extremely", "very", "extremely", word], language
            )
    output["sentence_initial_person"] = brain._person_candidates(
        [
            JournalEntry("Alice met another ordinary person", TODAY - timedelta(days=i))
            for i in range(8)
        ]
    )
    for day_k, tod_k in ((4, 3), (4, 4), (5, 3), (8, 3)):
        rows = []
        for i in range(8):
            weekday = 0 if i < day_k else 1
            day = TODAY - timedelta(days=7 * i + (TODAY.weekday() - weekday) % 7)
            entry = JournalEntry(
                "ordinary", day, 0.0, tod="night" if i < tod_k else None
            )
            rows.append((entry, [], {"work"}, 0.0, 0.0, True))
        days = {r[0].entry_date for r in rows}
        ref = {i: sum(d.weekday() == i for d in days) for i in range(7)}
        for name, reference in (
            ("full", ref),
            ("missing", {}),
            ("first_zero", {**ref, 0: 0}),
        ):
            output[f"temporal:{day_k}:{tod_k}:{name}"] = brain._detect_themes(
                rows, reference, len(days)
            )
    for n in (8, 9, 10):
        for gap1 in (5, 6, 7, 8):
            for delta in (0.199, 0.2, 0.201, 0.25):
                day = TODAY - timedelta(days=80)
                days, themes, moods = [day], {}, {}
                for i in range(2 * n):
                    themed = i < n
                    themes[day] = {"work"} if themed else set()
                    day += timedelta(days=1 if not themed or i < gap1 else 2)
                    days.append(day)
                    moods[day] = 0.0 if themed else delta
                themes[day] = set()
                output[f"link_mix:{n}:{gap1}:{delta}"] = brain._detect_links(
                    themes, moods, TODAY
                )
    for recent_n in (8, 9, 10, 11, 12):
        for earlier_n in (8, 10, 12):
            series = [
                (TODAY - timedelta(days=30 + i), math.sin(i * 0.8) * 0.2)
                for i in range(earlier_n)
            ]
            series += [
                (
                    TODAY - timedelta(days=i + (2 if i > 5 else 0)),
                    math.sin(i * 0.17) * 0.4,
                )
                for i in range(recent_n)
            ]
            series.sort()
            output[f"mixed_gap:{recent_n}:{earlier_n}"] = [
                brain._inertia_signal(series, "test", "inertia", "daily mood", TODAY),
                brain._coupling_signal(
                    dict(series),
                    {
                        d: -v + math.sin(i * 0.3) * 0.1
                        for i, (d, v) in enumerate(series)
                    },
                    TODAY,
                ),
            ]
    saturday = TODAY + timedelta(days=5)
    for weeks in (8, 9, 10, 12):
        for mode in ("constant", "varied", "wider"):
            tags = {}
            for w in range(weeks):
                week = saturday - timedelta(days=5 + 7 * w)
                for tag_i in range(3 if mode == "wider" else 2):
                    count = (
                        6
                        if tag_i == 0
                        else 2
                        if mode == "constant"
                        else 1 + (w * 3 + tag_i) % 6
                    )
                    tags.setdefault(str(tag_i), set()).update(
                        week + timedelta(days=d) for d in range(count)
                    )
            output[f"diversity:{weeks}:{mode}"] = brain._detect_activity_diversity(
                tags, saturday
            )
    for earlier_n in (11, 12, 13, 16):
        for recent_n in (11, 12, 13, 16):
            for mode in ("uniform", "varied", "zero_earlier"):
                days = {TODAY, TODAY - timedelta(days=30)}
                day = TODAY
                for i in range(recent_n - 1):
                    day -= timedelta(
                        days=1 if mode == "uniform" else 1 + int(i % 3 != 0)
                    )
                    days.add(day)
                day = TODAY - timedelta(days=30)
                for i in range(earlier_n - 1):
                    day -= timedelta(
                        days=1 if mode == "zero_earlier" else 1 + (i * 5) % 4
                    )
                    days.add(day)
                output[f"cadence_window:{earlier_n}:{recent_n}:{mode}"] = (
                    brain._detect_cadence(days, TODAY)
                )
    for text in (
        "not never celadon amber ivory linen granite marble",
        "not never not celadon amber ivory linen granite marble",
        "never not ordinary journal prose remains quiet " + "alpha " * 45,
    ):
        for days in ((0, 3, 7), (0, 3, 8), (0, 3, 7, 8)):
            refs = [JournalEntry(text.strip(), TODAY - timedelta(days=d)) for d in days]
            clusters = brain._phrase_clusters(refs)
            output[f"phrase_exact:{text}:{days}"] = [
                clusters,
                brain._detect_phrases(clusters, language="en"),
                brain._detect_phrases(clusters, language="en", sentence_languages={}),
            ]
    for size in (20, 21, 24, 30, 40, 60):
        for mode in ("thin_earlier", "thin_recent", "clustered", "daily"):
            for language in ("en", "es", "other"):
                for token in ("guitar", "porque", "never", "really"):
                    rows = []
                    for i in range(size):
                        offset = (
                            size - i
                            if mode == "daily"
                            else size - i // 3
                            if mode == "clustered"
                            else size
                            if mode == "thin_earlier" and i < size * 2 // 3
                            else 0
                            if mode == "thin_recent" and i >= size // 3
                            else size - i
                        )
                        words = (
                            [token, "context" + str(i % 4), "ordinary", "journal"]
                            if i % 5
                            else ["ordinary", "journal"]
                        )
                        entry = JournalEntry(
                            " ".join(words), TODAY - timedelta(days=offset)
                        )
                        rows.append((entry, words, set(), 0.0))
                    rows.sort(key=lambda r: r[0].entry_date)
                    output[f"topic_calendar:{size}:{mode}:{language}:{token}"] = (
                        brain._detect_topics(rows, [], language=language)
                    )
    rng = random.Random(619)
    for trial in range(80):
        size = rng.choice((24, 30, 40, 60))
        rows = []
        for i in range(size):
            day = TODAY - timedelta(days=(size - i) // rng.choice((1, 2, 3)))
            words = [
                rng.choice(("guitar", "mandolin", "porque", "never")),
                "context" + str(rng.randrange(5)),
                rng.choice(("celadon", "amber", "ivory")),
            ]
            entry = JournalEntry(" ".join(words), day)
            rows.append((entry, words, set(), 0.0))
        rows.sort(key=lambda r: r[0].entry_date)
        output[f"topic_clustered_random:{trial}"] = brain._detect_topics(
            rows, [], language="es" if trial % 2 else "en"
        )
    for language in ("en", "es"):
        for token in (
            "para",
            "cuando",
            "porque",
            "siempre",
            "always",
            "very",
            "completely",
            "really",
        ):
            rows = []
            mapping = {}
            for i in range(40):
                words = (
                    [token, "context" + str(i % 5), "guitar"]
                    if i >= 8
                    else ["ordinary", "journal"]
                )
                entry = JournalEntry(" ".join(words), TODAY - timedelta(days=40 - i))
                rows.append((entry, words, set(), 0.0))
                mapping[id(entry)] = "en" if i >= 20 else "es"
            output[f"topic_minority:{language}:{token}"] = brain._detect_topics(
                rows, [], language=language, entry_languages=mapping
            )
    output["bad_store_recovers"] = brain.update(None, [], TODAY)
    for weekday in range(7):
        tags = {"one": set(), "two": set()}
        current = TODAY + timedelta(days=weekday)
        for w in range(9):
            monday = current - timedelta(days=current.weekday() + 7 * w)
            for d in (0, 1):
                for tag in tags:
                    tags[tag].add(monday + timedelta(days=d))
        output[f"diversity_calendar_grace:{weekday}"] = (
            brain._detect_activity_diversity(tags, current)
        )
    texts = [
        "never not celadon amber ivory linen granite marble " + suffix
        for suffix in ("jasper quartz", "jasper onyx", "not jasper quartz")
    ]
    clusters = brain._phrase_clusters(
        [
            JournalEntry(text, TODAY - timedelta(days=4 * i))
            for i, text in enumerate(texts)
        ]
    )
    output["rumination_varied_counts"] = brain._detect_phrases(clusters, language="en")
    for size in (2, 3, 4, 20):
        for stride in (1, 2, 3):
            days = {TODAY - timedelta(days=i * stride) for i in range(size)}
            output[f"avoidance_empty_reference:{size}:{stride}"] = (
                brain._detect_avoidance({d: {"work"} for d in days}, days, TODAY)
            )
    return normalized(output)


def test_brain_clustered_topic_phrase_and_unequal_window_contracts(monkeypatch):
    assert brain_gap_cases(monkeypatch) == runtime_contract()["brain_gap"]


def brain_exact_effect_cases():
    from app.services import brain

    output = {}
    values = (
        [0.001, -0.001] * 5 + [0.5, -0.5] * 13 + [0.5, 0.9, 0.9, -0.6620147608675602]
    )
    output["ewma_exact_shift"] = brain._detect_mood_shift(
        [
            (TODAY - timedelta(days=len(values) - i), value)
            for i, value in enumerate(values)
        ]
    )
    # These binary floats produce actual sample SDs exactly on the released bars.
    for recent_a, earlier_a in (
        (0.11489125293076057, 0.07115124735378853),
        (0.22978250586152113, 0.14230249470757705),
    ):
        recent = [recent_a, -recent_a] * 6
        earlier = [earlier_a, -earlier_a] * 5
        series = [(TODAY - timedelta(days=i), v) for i, v in enumerate(recent)] + [
            (TODAY - timedelta(days=30 + i), v) for i, v in enumerate(earlier)
        ]
        output[f"spread:{recent_a}:{earlier_a}"] = brain._detect_mood_dynamics(
            sorted(series), dict(series), TODAY
        )
    for n, a in ((8, 0.37416573867739417), (10, 0.4743416490252569)):
        left, right = (
            [a, -a] * (n // 2),
            [a + 0.5 * (0.4 if n == 8 else 0.5), -a + 0.5 * (0.4 if n == 8 else 0.5)]
            * (n // 2),
        )
        rows = []
        day_themes, residuals = {}, {}
        for i, value in enumerate(left + right):
            day = TODAY - timedelta(days=2 * n - i)
            entry = brain.JournalEntry("ordinary", day, value)
            rows.append((entry, [], {"work"} if i < n else set(), value, value, True))
            day_themes[day] = {"work"} if i < n else set()
            residuals[day + timedelta(days=1)] = value
        counts = {
            i: sum(r[0].entry_date.weekday() == i for r in rows) for i in range(7)
        }
        output[f"cohens_theme:{n}"] = brain._detect_themes(rows, counts, 2 * n)
        day_themes[max(day_themes) + timedelta(days=1)] = set()
        output[f"cohens_link:{n}"] = brain._detect_links(day_themes, residuals, TODAY)
    for count in (20, 40):
        rows = []
        for i in range(count):
            themed = i < 7 * count // 20
            day = TODAY - timedelta(days=7 * i + (0 if themed else 1))
            entry = brain.JournalEntry("ordinary", day, 0.1)
            rows.append((entry, [], {"work"}, 0.1, 0.1, True))
        counts = {
            i: sum(r[0].entry_date.weekday() == i for r in rows) for i in range(7)
        }
        output[f"fraction_boundary:{count}"] = brain._detect_themes(rows, counts, count)
    return normalized(output)


def test_real_statistical_effects_include_the_exact_released_thresholds():
    assert brain_exact_effect_cases() == runtime_contract()["brain_exact_effects"]


def brain_precision_cases(monkeypatch):
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    output["person_known_before_name"] = brain._person_candidates(
        [
            JournalEntry("i felt Happy then saw Alice", TODAY - timedelta(days=i))
            for i in range(8)
        ]
    )
    for mode in ("contaminated_blocks", "default_language", "tiny_difference"):
        rows = []
        for i in range(80):
            themed = i % 2 == 0
            token = "good" if (i // 8) % 2 else "bad"
            words = ["insomnia", token] if themed else [token]
            if mode == "default_language":
                words = ["work", "sin", token] if themed else [token]
            raw = brain.sentiment_score(words, "en")
            if mode == "tiny_difference":
                words, raw = (
                    (["work", "happy"] if themed else ["happy"]),
                    brain.sentiment_score(["happy"], "en") + (1e-12 if themed else 0),
                )
            entry = JournalEntry(" ".join(words), TODAY - timedelta(days=80 - i))
            rows.append(
                (
                    entry,
                    words,
                    {"work" if mode != "contaminated_blocks" else "sleep"}
                    if themed
                    else set(),
                    raw,
                    raw,
                    False,
                )
            )
        counts = {
            day: sum(r[0].entry_date.weekday() == day for r in rows) for day in range(7)
        }
        output["theme_precision:" + mode] = brain._detect_themes(rows, counts, 80)
    for earlier_n, recent_n, earlier_hits, recent_hits in (
        (24, 100, 1, 18),
        (38, 100, 2, 18),
        (24, 100, 2, 25),
        (49, 100, 1, 18),
        (10, 70, 1, 13),
        (10, 10, 5, 1),
    ):
        rows = []
        for i in range(100):
            day_index = i * earlier_n // 100
            words = (
                ["guitar", "context" + str(i % 5)]
                if day_index < earlier_hits
                else ["ordinary", "journal"]
            )
            rows.append(
                (
                    JournalEntry(
                        " ".join(words),
                        TODAY - timedelta(days=earlier_n + recent_n - day_index),
                    ),
                    words,
                    set(),
                    0.0,
                )
            )
        for i in range(recent_n):
            words = (
                ["guitar", "context" + str(i % 5)]
                if i < recent_hits
                else ["ordinary", "journal"]
            )
            rows.append(
                (
                    JournalEntry(" ".join(words), TODAY - timedelta(days=recent_n - i)),
                    words,
                    set(),
                    0.0,
                )
            )
        rows.sort(key=lambda r: r[0].entry_date)
        output[
            f"topic_rate_boundary:{earlier_n}:{recent_n}:{earlier_hits}:{recent_hits}"
        ] = brain._detect_topics(rows, [])
    rows = []
    for i in range(70):
        words = (
            ["guitar", "context" + str(i % 5)] if i < 21 else ["ordinary", "journal"]
        )
        rows.append(
            (
                JournalEntry(" ".join(words), TODAY - timedelta(days=70 - i)),
                words,
                set(),
                0.0,
            )
        )
    output["presence_share_exact"] = brain._detect_topics(rows, [])
    rows = []
    for i in range(60):
        words = (
            [
                "guitar",
                "celadon",
                "amber",
                "ivory",
                "linen",
                "granite",
                "marble",
                "quartz",
                "jasper",
                "opal",
                "cobalt",
                "slate",
            ]
            if i < 24
            else ["guitar", "context" + str(i)]
            if i < 30
            else ["ordinary", "journal"]
        )
        rows.append(
            (
                JournalEntry(" ".join(words), TODAY - timedelta(days=60 - i)),
                words,
                set(),
                0.0,
            )
        )
    clusters = brain._phrase_clusters([r[0] for r in rows])
    output["cluster_coverage_exact"] = brain._detect_topics(rows, clusters)
    rows = []
    for i in range(80):
        words = (
            ["guitar", "context" + str(i % 5), "mandolin", "context" + str((i + 2) % 5)]
            if i % 5
            else ["ordinary", "journal"]
        )
        day = TODAY - timedelta(days=31 if i < 50 else 80 - i)
        rows.append((JournalEntry(" ".join(words), day), words, set(), 0.0))
    output["multiple_thin_presence"] = brain._detect_topics(rows, [])
    record = stored_record(
        brain,
        "phrase:old",
        "rumination",
        "confirmed",
        detail={
            "phrase_anchor": "not never celadon amber ivory linen granite marble",
            "variants": [],
        },
    )
    incoming = brain._Signal(
        "phrase:new",
        "rumination",
        "claim",
        4,
        None,
        {"phrase_anchor": record.detail["phrase_anchor"], "variants": []},
        [TODAY],
    )
    output["rumination_alias"] = brain._phrase_alias_pid(incoming, {record.pid: record})
    tags = {"one": set(), "two": set()}
    saturday = TODAY + timedelta(days=5)
    for w in range(9):
        monday = saturday - timedelta(days=5 + 7 * w)
        tags["one"].update(monday + timedelta(days=d) for d in range(6))
        tags["two"].update(monday + timedelta(days=d) for d in range(6 if w < 4 else 1))
    output["diversity_moderate_shift"] = brain._detect_activity_diversity(
        tags, saturday
    )
    tags = {"one": set(), "two": set()}
    for w in range(9):
        monday = TODAY - timedelta(days=7 * w)
        tags["one"].update(monday + timedelta(days=d) for d in range(2))
        tags["two"].update(
            monday + timedelta(days=d) for d in range(1 if w in (0, 4, 8) else 2)
        )
    output["diversity_unequal_cutoff_week"] = brain._detect_activity_diversity(
        tags, TODAY
    )
    calendar = {TODAY - timedelta(days=146 - i) for i in range(147) if i % 3 != 2}
    last = max(calendar)
    null_excluded_weekday = last.weekday()
    eligible = sorted(
        d for d in calendar if d != last and d.weekday() != null_excluded_weekday
    )
    skipped = [d for d in eligible if d + timedelta(days=1) not in calendar][:14]
    wrote = [d for d in eligible if d + timedelta(days=1) in calendar][:6]
    output["avoidance_exact_lift"] = brain._detect_avoidance(
        {d: {"work"} for d in skipped + wrote}, calendar, TODAY
    )
    for name, recent_gaps, earlier_gaps in (
        ("sd_floor", [2] * 6 + [1] * 10, [1] * 16),
        ("sd_ratio", [4] * 2 + [1] * 9, [3] * 2 + [1] * 9),
        ("sd_ratio_larger", [3] * 5 + [1] * 11, [2] * 6 + [1] * 10),
    ):
        days = {TODAY, TODAY - timedelta(days=40)}
        for start, gaps in (
            (TODAY, recent_gaps),
            (TODAY - timedelta(days=40), earlier_gaps),
        ):
            d = start
            for gap in gaps:
                d -= timedelta(days=gap)
                days.add(d)
        output["cadence_exact:" + name] = brain._detect_cadence(days, TODAY)
    rows = []
    for i in range(60):
        words = (
            [
                "guitar",
                "celadon",
                "amber",
                "ivory",
                "linen",
                "granite",
                "marble",
                "quartz",
                "jasper",
                "opal",
                "cobalt",
                "slate",
            ]
            if i < 23
            else ["guitar", "context" + str(i)]
            if i < 30
            else ["ordinary", "journal"]
        )
        rows.append(
            (
                JournalEntry(" ".join(words), TODAY - timedelta(days=60 - i)),
                words,
                set(),
                0.0,
            )
        )
    output["cluster_coverage_below_bar"] = brain._detect_topics(
        rows, brain._phrase_clusters([r[0] for r in rows])
    )
    return normalized(output)


def test_theme_topic_alias_and_calendar_boundary_outputs(monkeypatch):
    assert brain_precision_cases(monkeypatch) == runtime_contract()["brain_precision"]


def numerical_interface_cases(monkeypatch):
    """Isolate declared precision/effect bars from nuisance estimator variation."""
    from app.services import brain

    output = {}
    for difference in (1e-12, 1.5e-12, 2e-12):
        rows = []
        for i in range(40):
            themed = i % 2 == 0
            raw = difference if themed else math.sin(i * 0.4) * 0.3
            residual = 0.0 if themed else math.sin(i * 0.8) * 0.2
            words = ["work", "celadon"] if themed else ["celadon"]
            entry = brain.JournalEntry(" ".join(words), TODAY - timedelta(days=40 - i))
            rows.append(
                (entry, words, {"work"} if themed else set(), residual, raw, False)
            )
        counts = {
            i: sum(r[0].entry_date.weekday() == i for r in rows) for i in range(7)
        }
        output["precision:" + str(difference)] = brain._detect_themes(rows, counts, 40)
    # A valid entropy estimate can lie exactly at an effect bar. The Welch
    # test still runs normally; this unit contract checks how its measured
    # effect enters the family, separately from the entropy estimator.
    entropies = [
        (TODAY - timedelta(days=7 * i), 1.0 if i < 4 else 0.65) for i in range(8)
    ]
    monkeypatch.setattr(brain, "_weekly_tag_entropies", lambda tags: sorted(entropies))
    output["entropy_exact_effect"] = brain._detect_activity_diversity(
        {"one": {TODAY}, "two": {TODAY}}, TODAY + timedelta(days=1)
    )
    return normalized(output)


def test_numerical_preprocessing_and_measured_entropy_effect_boundaries(monkeypatch):
    assert (
        numerical_interface_cases(monkeypatch)
        == runtime_contract()["numerical_interfaces"]
    )


@pytest.mark.parametrize("reuse", [False, True])
def test_semantic_reuse_walk_advances_through_two_existing_forks(reuse):
    from app.services import brain

    base = stored_record(
        brain, "temporal:work", "temporal", "confirmed", detail={"day": "Sunday"}
    )
    second = stored_record(
        brain, "temporal:work~2", "temporal", detail={"day": "Wednesday"}
    )
    third = stored_record(
        brain,
        "temporal:work~3",
        "temporal",
        detail={"day": "Tuesday" if reuse else "Thursday"},
    )
    state = brain.fresh_state()
    state["patterns"] = BoundedPatterns({rec.pid: rec for rec in (base, second, third)})
    signal = brain._Signal(
        base.pid, "temporal", "work", 12, 0.01, {"day": "Tuesday"}, [TODAY]
    )
    brain._merge_lifecycle(state, [signal], TODAY)
    assert signal.pid == ("temporal:work~3" if reuse else "temporal:work~4")
    assert len(state["patterns"]) == (3 if reuse else 4)


@pytest.mark.parametrize(
    "budget", ["MAX_PAIRWISE_COMPARISONS", "MAX_PAIRWISE_PROPOSALS"]
)
def test_phrase_scanner_uses_the_last_available_comparison_or_proposal(
    monkeypatch, budget
):
    from app.services import phrases

    refs = [
        phrases.SentenceRef(text, day)
        for text, day in [
            ("one two three four", TODAY),
            ("one two three five", TODAY - timedelta(days=8)),
        ]
    ]
    monkeypatch.setattr(phrases, budget, 1)
    monkeypatch.setattr(
        phrases, "signature", lambda tokens: [1, 2, 3, 4 if tokens[-1] == "four" else 5]
    )
    monkeypatch.setattr(phrases, "_band_keys", lambda signature: [(0, (1, 2, 3))])
    clusters = phrases.near_duplicate_clusters(refs, min_size=2, min_distinct_days=2)
    assert len(clusters) == 1
    assert len(clusters[0].members) == 2


def test_reference_phrase_confidence_saturates_and_tied_cards_sort_by_occurrences():
    from app.services import patterns

    entries = [
        patterns.JournalEntry(
            "zebra ritual alpha beta gamma", TODAY - timedelta(days=i)
        )
        for i in range(10)
    ]
    entries += [
        patterns.JournalEntry(
            "amber ritual delta epsilon zeta", TODAY - timedelta(days=i)
        )
        for i in range(8)
    ]
    phrases = patterns.recurring_phrases(entries)
    assert [p.confidence for p in phrases] == [1.0, 1.0]
    cards = [
        p for p in patterns.analyze(entries).patterns if p.kind == "recurring_phrase"
    ]
    assert [(p.occurrences, p.label) for p in cards] == [
        (10, "zebra ritual alpha beta gamma"),
        (8, "amber ritual delta epsilon zeta"),
    ]


def brain_persistence_edge_cases():
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    kinds = [
        "temporal",
        "mood_correlation",
        "link",
        "avoidance",
        "sense_making",
        "activity_diversity",
        "topic",
        "inertia",
        "instability",
        "mood_shift",
        "cadence",
        "energy_inertia",
        "pa_inertia",
        "na_inertia",
        "energy_mood_coupling",
        "rumination",
        "recurring_phrase",
    ]
    for kind in kinds:
        raw = stored_record(brain, kind=kind, state="confirmed").to_dict()
        for candidate in (kind, "XX" + kind + "XX"):
            output["kind_normalization:" + candidate] = brain._stored_from_dict(
                {**raw, "kind": candidate}, "test"
            )
        for trend in ("rising", "steady"):
            output[f"inference_kind:{kind}:{trend}"] = brain._is_statistical(
                kind, {"trend": trend}
            )
        state = brain.fresh_state()
        signal = brain._Signal(
            "kind-test",
            kind,
            "claim",
            12,
            0.01,
            {"trend": "rising" if kind == "topic" else "steady"},
            [TODAY],
        )
        brain._merge_lifecycle(state, [signal], TODAY)
        output["first_qualification:" + kind] = state
    a = "alpha beta gamma delta epsilon zeta eta theta iota kappa"
    b = a + " lambda mu nu"
    c = b + " xi omicron pi rho sigma tau upsilon phi"
    for case in (
        "incoming_variants",
        "stored_variants",
        "foreign_first",
        "empty_first",
        "existing_identity",
    ):
        incoming = {
            "phrase_anchor": c if case == "incoming_variants" else a,
            "variants": [b, c],
        }
        stored = {
            "phrase_anchor": a if case != "stored_variants" else c,
            "variants": [b, c] if case == "stored_variants" else [],
        }
        if case == "empty_first":
            stored["phrase_anchor"] = " "
            stored["variants"] = [b]
        record = stored_record(
            brain, "phrase:old", "recurring_phrase", "confirmed", detail=stored
        )
        patterns = {record.pid: record}
        if case == "foreign_first":
            patterns = {"foreign": stored_record(brain, "foreign", "topic"), **patterns}
        signal = brain._Signal(
            "phrase:new", "recurring_phrase", "claim", 4, None, incoming, [TODAY]
        )
        if case == "existing_identity":
            patterns[signal.pid] = stored_record(
                brain, signal.pid, "recurring_phrase", detail={"phrase_anchor": c}
            )
        output["phrase_alias:" + case] = brain._phrase_alias_pid(signal, patterns)
        state = brain.fresh_state()
        state["patterns"] = BoundedPatterns(patterns)
        brain._merge_lifecycle(state, [signal], TODAY)
        output["phrase_alias_lifecycle:" + case] = [signal, state]
    for language in (None, "en", "es"):
        output["compound_boosters:" + str(language)] = brain._valence_walk(
            ["extremely", "very", "extremely", "good"], language
        )
    output["accented_person"] = brain._person_mention("Hoy vi a mi tía", "mi tia", "es")
    names = ["Name" + chr(97 + i // 26) + chr(97 + i % 26) for i in range(27)]
    for varied in ("counts", "days"):
        entries = []
        for i, name in enumerate(names):
            for j in range(20 if varied == "days" or i < 5 else 12):
                span = 6 if i < 5 and varied == "days" else 10
                entries.append(
                    JournalEntry("I met " + name, TODAY - timedelta(days=j % span))
                )
        output["person_ranking:" + varied] = brain._person_candidates(entries)
    for kind in ("inertia", "instability", "temporal", "topic", "recurring_phrase"):
        for spread in (1, 2, 6, 7, 8):
            record = stored_record(brain, "record", kind)
            record.qualification_days = [
                (TODAY - timedelta(days=spread)).isoformat(),
                (TODAY - timedelta(days=spread - 1)).isoformat(),
                TODAY.isoformat(),
            ]
            for first in ("", (TODAY - timedelta(days=3)).isoformat()):
                record.first_qualified = first
                signal = brain._Signal(
                    "record",
                    kind,
                    "claim",
                    4,
                    0.01,
                    {},
                    [TODAY - timedelta(days=1), TODAY],
                )
                output[f"replication:{kind}:{spread}:{first}"] = (
                    brain._replication_satisfied(record, signal)
                )
    for history in (
        [],
        [[TODAY.isoformat(), ["stale"]]],
        [[(TODAY - timedelta(days=1)).isoformat(), []], [TODAY.isoformat(), ["stale"]]],
    ):
        state = brain.fresh_state()
        state["history"] = history
        output["history:" + str(history)] = brain.update(state, [], TODAY)
    for action in ("feedback", "muted", "unmuted"):
        state = brain.fresh_state()
        pids = ["a", "ab", "c" * 128, "d" * 129]
        for pid in pids:
            state["patterns"][pid] = stored_record(
                brain, pid, state="confirmed", occurrences=12
            )
        if action == "unmuted":
            state["muted"] = {pid: True for pid in pids}
        kwargs = {
            action: [(pids[0], True), (pids[1], False)]
            if action == "feedback"
            else pids
        }
        output["preference:" + action] = brain.update(state, [], TODAY, **kwargs)
    for action in ("feedback", "muted", "unmuted"):
        state = brain.fresh_state()
        pids = ["preference-" + str(i) for i in range(111)]
        for pid in pids:
            state["patterns"][pid] = stored_record(
                brain, pid, state="confirmed", occurrences=12
            )
        if action == "unmuted":
            state["muted"] = dict.fromkeys(pids, True)
        output["preference_capacity:" + action] = brain.update(
            state,
            [],
            TODAY,
            **{action: [(pid, True) for pid in pids] if action == "feedback" else pids},
        )
    for first_seen in (
        "",
        (TODAY - timedelta(days=90)).isoformat(),
        (TODAY - timedelta(days=91)).isoformat(),
    ):
        state = brain.fresh_state()
        record = stored_record(brain, state="confirmed")
        record.first_seen = first_seen
        record.last_qualified = ""
        state["patterns"][record.pid] = record
        brain._merge_lifecycle(state, [], TODAY)
        output["damaged_first_seen:" + first_seen] = state
    for first in (
        None,
        "invalid",
        (TODAY - timedelta(days=21)).isoformat(),
        (TODAY - timedelta(days=30)).isoformat(),
    ):
        state = brain.fresh_state()
        record = stored_record(brain, "shift", "mood_shift", "confirmed")
        record.first_seen = first
        state["patterns"] = {
            "other": stored_record(brain),
            "shift": record,
            "later": stored_record(brain, "later", "mood_shift", "confirmed", age=22),
        }
        output["reanchor:" + str(first)] = brain._mood_reanchor_day(state, TODAY)
    return normalized(output)


def test_brain_replication_preference_history_and_person_ranking_edges():
    assert (
        brain_persistence_edge_cases() == runtime_contract()["brain_persistence_edges"]
    )


def test_sentiment_character_cache_reuses_actual_unicode_decompositions(monkeypatch):
    from app.services import brain

    original = brain.unicodedata.normalize
    calls = []

    def normalize(form, text):
        if form == "NFKD":
            calls.append(text)
        return original(form, text)

    monkeypatch.setattr(brain.unicodedata, "normalize", normalize)
    monkeypatch.setattr(brain, "_FOLD_CACHE", {})
    assert brain._fold_sentiment_text("ééé") == "eee"
    assert brain._fold_sentiment_text("ééé") == "eee"
    assert calls == ["é"]


@pytest.mark.parametrize("direction", [-1, 1])
def test_mood_chart_points_on_the_control_limit_do_not_enter_the_fdr_family(direction):
    from app.services import brain

    values = runtime_contract()["boundary_chart_values"]
    series = [
        (TODAY - timedelta(days=len(values) - 1 - i), direction * value)
        for i, value in enumerate(values)
    ]
    assert brain._detect_mood_shift(series) == []


def test_sentence_budget_stops_inside_an_entry_and_retains_the_newest_sentences():
    from app.services import brain
    from app.services.patterns import JournalEntry

    entries = [
        JournalEntry(
            ". ".join(
                ["i write another ordinary journal sentence"] * (39 if i == 100 else 40)
            ),
            TODAY - timedelta(days=100 - i),
        )
        for i in range(101)
    ]
    refs = brain._window_sentences(entries)
    assert len(refs) == 4000
    assert refs[0].day == TODAY - timedelta(days=100)
    assert refs[-1].day == TODAY


def test_brain_chart_language_person_phrase_and_lifecycle_edge_outputs(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    bound_phrase_walks(monkeypatch)
    assert brain_deeper_cases(monkeypatch) == runtime_contract()["brain_deeper"]


def brain_selection_cases(monkeypatch):
    """Exercise the real FDR, evidence marking and display selection stage."""
    from app.services import brain
    from app.services.patterns import JournalEntry

    output = {}
    entries = [
        JournalEntry(
            "i met Alice and felt happy with work because i understand my friends",
            TODAY - timedelta(days=i),
            0.4,
            tags=("work",) if i % 2 == 0 else (),
        )
        for i in range(20)
    ]
    for n in (
        "_detect_links",
        "_detect_mood_shift",
        "_detect_mood_dynamics",
        "_detect_phrases",
        "_detect_avoidance",
        "_detect_cadence",
        "_detect_topics",
    ):
        monkeypatch.setattr(brain, n, lambda *args, **kwargs: [])
    for n in (
        "_inertia_signal",
        "_coupling_signal",
        "_detect_sense_making",
        "_detect_activity_diversity",
    ):
        monkeypatch.setattr(brain, n, lambda *args, **kwargs: None)

    def signal(pid, kind, label, count, p=None, detail=None, gate=True, fallback=None):
        return brain._Signal(
            pid,
            kind,
            label,
            count,
            p,
            detail or {},
            [TODAY - timedelta(days=1), TODAY],
            gate,
            fallback,
        )

    qualified = []
    merge = brain._merge_lifecycle

    def merge_capture(store, signals, today):
        qualified.append(normalized(signals))
        merge(store, signals, today)

    monkeypatch.setattr(brain, "_merge_lifecycle", merge_capture)
    for mode in ("mixed", "fallback", "tie", "all_tag_evidence", "no_tag_evidence"):
        candidates = [
            signal(
                "temporal:work",
                "temporal",
                "work",
                14,
                0.0001,
                {"day": "Sunday", "day_count": 5},
            ),
            signal(
                "temporal:work",
                "temporal",
                "work",
                14,
                0.0002,
                {"day": "Monday", "day_count": 5 if mode == "tie" else 8},
            ),
            signal(
                "mood_correlation:alice",
                "mood_correlation",
                "alice",
                10,
                0.001,
                {"direction": "lower"},
            ),
            signal(
                "temporal:poor sleep",
                "temporal",
                "poor sleep",
                12,
                0.001,
                {"day": "Tuesday", "day_count": 8},
            ),
            signal(
                "topic:work",
                "topic",
                "work",
                25,
                None,
                {"presence": True, "trend": "steady"},
            ),
            signal("topic:guitar", "topic", "guitar", 24, 0.0005, {"trend": "rising"}),
            signal(
                "topic:guitar practice",
                "topic",
                "guitar practice",
                22,
                0.0007,
                {"trend": "rising"},
            ),
            signal("rejected", "link", "noise", 14, 0.95, gate=True),
            signal("effect_rejected", "link", "noise2", 14, 0.00001, gate=False),
        ]
        candidates += [
            signal(
                "topic:instrument" + str(i),
                "topic",
                "instrument" + str(i),
                20 - i,
                0.001 + i * 0.0001,
                {"trend": "rising"},
            )
            for i in range(8)
        ]
        if mode == "fallback":
            candidates += [
                signal(
                    "topic:steady",
                    "topic",
                    "steady",
                    21,
                    0.9,
                    {"trend": "rising"},
                    False,
                    signal(
                        "topic:steady",
                        "topic",
                        "steady",
                        21,
                        None,
                        {"trend": "steady", "presence": True},
                    ),
                )
            ]
        if mode in ("all_tag_evidence", "no_tag_evidence"):
            for candidate in candidates:
                candidate.evidence_days = [
                    TODAY if mode == "all_tag_evidence" else TODAY - timedelta(days=1)
                ]
        monkeypatch.setattr(
            brain,
            "_detect_themes",
            lambda *args, candidates=candidates, **kwargs: candidates,
        )
        qualified = []
        result = brain.update(brain.fresh_state(), entries, TODAY)
        output[mode] = [result, qualified]
    monkeypatch.setattr(brain, "_detect_themes", lambda *args, **kwargs: [])
    store = brain.fresh_state()
    store["patterns"] = {
        f"memo:{i:03}": stored_record(brain, f"memo:{i:03}", state="confirmed", age=30)
        for i in range(120)
    }
    store["muted"] = {f"memo:{i:03}": True for i in range(100)}
    output["mute_fifo_cap"] = brain.update(
        store, [], TODAY, muted=[f"memo:{i:03}" for i in range(100, 110)]
    )
    return normalized(output)


def question_boundary_cases(monkeypatch):
    from app.services import questions
    from app.services.patterns import Pattern

    output = {}
    pattern = Pattern("temporal", "guitar", 5, 0.5, {"day": "Monday"})
    output["default_template"] = questions.render_pattern_questions(pattern)
    output["default_pool"] = questions.build_pool([pattern])
    for direction in ("sideways", "", None, "higher"):
        p = Pattern("mood_correlation", "guitar", 5, 0.5, {"direction": direction})
        output["direction:" + str(direction)] = questions.render_pattern_questions(
            p, "es"
        )
    for detail in (
        {},
        {"feedback": {}},
        {"feedback": {"resonated": 1}},
        {"feedback": {"not_me": 1}},
    ):
        p = Pattern("topic", "guitar", 5, 0.5, detail)
        output["feedback:" + str(detail)] = questions.feedback_rank(p)
    for capacity in (4095, 4096, 4097):
        pins = {
            (str(i), TODAY.toordinal(), "en"): f"original {i}" for i in range(capacity)
        }
        monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", pins)
        q = questions.question_for_today("new", [], TODAY)
        output[f"memo:{capacity}"] = [q, len(pins), list(pins)[:2], list(pins)[-2:]]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(questions, "build_pool", lambda *args: [])
        for language in ("en", "es", "other"):
            patch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
            output["empty_pool:" + language] = questions.question_for_today(
                "new", [], TODAY, language
            )
    return normalized(output)


def test_brain_real_fdr_family_fallback_topic_selection_and_mute_memory(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    assert brain_selection_cases(monkeypatch) == runtime_contract()["brain_selection"]


def test_question_legacy_detail_fallback_and_actual_memo_capacity(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    assert (
        question_boundary_cases(monkeypatch)
        == runtime_contract()["question_boundaries"]
    )


def test_brain_positive_detector_effects_and_topic_eligibility_boundaries(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    bound_phrase_walks(monkeypatch)
    assert brain_positive_cases(monkeypatch) == runtime_contract()["brain_positive"]


def crisis_edge_cases():
    from app.services import crisis

    output = {}
    output["latin_characters"] = [
        crisis._fold_latin_marks(chr(i)) for i in range(0x80, 0x250)
    ]
    output["ascii_singles"] = [crisis._is_ascii_single(chr(i)) for i in range(128)]
    output["multi_punct"] = crisis._punct_variants("a😊😊b!!c😊😊😊d")
    output["compatibility_nonmarks"] = crisis._fold_latin_marks("№㎧")
    output["nonascii_compound_mask"] = crisis._benign_mask("自杀 小队").pattern
    for text in (
        "",
        "😊",
        "😊a",
        "a😊",
        "a😊b",
        "a😊b😊c😊d",
        "é e\u0301",
        "ā ž ȳ ɐ",
        "α ά आ क़",
        "\u02ff\u0300\u036f\u0370",
        "0म9 aमz",
        "म0 म9 मa मz",
        "0म 9म aम zम",
        "Aम Zम :म ?म",
        "\u0250\u0251",
        "𝔞Åﬃ",
        "the end😊of😊it😊all",
    ):
        output[text] = {
            "latin": crisis._fold_latin_marks(text),
            "script": crisis._insert_script_boundaries(text),
            "punct": crisis._punct_variants(text),
            "pre": crisis._normalize_pre_punct(text),
            "tokens": crisis._tokens_from_folded(text),
            "variants": crisis._variant_token_sets(text),
        }
    output["single"] = [
        crisis._is_ascii_single(token)
        for token in ("", "a", "z", "A", "0", "9", "é", "中", "aa")
    ]
    for count in (0, 1, 2, 3, 4, 5):
        for lead in ([], ["i"], ["hello"]):
            for tail in ([], ["word"], ["a"]):
                tokens = lead + ["x"] * count + tail
                output[f"join:{tokens}"] = [
                    crisis._primary_join(tokens),
                    crisis._orphan_glue(tokens),
                    crisis._orphan_glue(tokens, preserve_first_person=True),
                    crisis._concat_join(tokens),
                ]
        joined = ["before"]
        crisis._emit_run(["x"] * count, joined)
        output[f"emit:{count}"] = joined
    for pattern in (
        "",
        "a",
        "z",
        "abcd",
        "abcde",
        "ab(cd)ef",
        "a[bc]de",
        "(ab)c(de)f",
        ")a",
        "[a-z]abc",
        r"ab\scd",
        "自杀",
        r"\bkill\s+myself\b",
        r"\bdie\b",
        "Xabc",
        "abcdXef",
        "ab)cdef",
        "abc[X]def",
        "abc(abX)de",
        "ABCxyz",
        "é中文Xabc",
        "[Xabc]def",
        "abc?def",
        "abc\\ndef",
        "(ab)中",
        "(ab)😊",
        "abc😊def",
        "XYZabc",
        "ab😊",
        "a[bc]😊",
    ):
        output["regex:" + pattern] = [
            crisis._interleave_optional_marks(pattern),
            crisis._toplevel_literal_letters(pattern),
            crisis._concat_pattern(pattern),
        ]
    return normalized(output)


def phrase_cost_cases(monkeypatch):
    from app.services import phrases

    output = {}
    for label, groups, width, bands in (
        ("bucket_floor", 1, 256, 1),
        ("bucket_over", 1, 257, 1),
        ("comparison_ceiling", 14, 200, 1),
        ("proposal_ceiling", 9, 128, 16),
    ):
        signatures = 0
        comparisons = 0
        proposals = 0
        iterations = 0
        real_estimate = phrases.estimated_jaccard

        class Pairs(set):
            def __contains__(self, pair):
                nonlocal proposals
                proposals += 1
                return super().__contains__(pair)

        def signature(tokens):
            nonlocal signatures
            signatures += 1
            return [int(tokens[0][1:]), int(tokens[1][1:])]

        def ranges(*args):
            nonlocal iterations
            for value in builtins.range(*args):
                iterations += 1
                yield value

        def keys(sig, bands=bands):
            return [(band, str(sig[0])) for band in range(bands)]

        def estimate(left, right, real_estimate=real_estimate):
            nonlocal comparisons
            comparisons += 1
            assert comparisons <= 300000, (
                "finite confirmation scan exhausted its independent work budget"
            )
            return real_estimate(left, right)

        refs = [
            phrases.SentenceRef(f"g{g} v{v}", TODAY - timedelta(days=v % 10))
            for g in range(groups)
            for v in range(width)
        ]
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(phrases, "signature", signature)
            patch.setattr(phrases, "_band_keys", keys)
            patch.setattr(phrases, "estimated_jaccard", estimate)
            patch.setattr(phrases, "set", Pairs, raising=False)
            patch.setattr(phrases, "range", ranges, raising=False)
            result = phrases.near_duplicate_clusters(refs, jaccard=1)
        output[label] = [signatures, comparisons, proposals, iterations, result]
    real_signature = phrases.signature
    calls = 0

    def counted_signature(tokens):
        nonlocal calls
        calls += 1
        return real_signature(tokens)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(phrases, "signature", counted_signature)
        refs = [
            phrases.SentenceRef(
                "i keep repeating this ordinary sentence", TODAY - timedelta(days=i)
            )
            for i in range(8)
        ]
        result = phrases.near_duplicate_clusters(refs)
    output["verbatim_signature_cache"] = [calls, result]
    return normalized(output)


def phrase_selection_cases(monkeypatch):
    from app.services import phrases

    output = {}

    def signature(tokens):
        return [int(tokens[0][1:]), int(tokens[1][1:])]

    def keys(sig):
        return [(0, str(sig[0]))]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(phrases, "signature", signature)
        patch.setattr(phrases, "_band_keys", keys)
        for label, rows in (
            ("undersized_then_valid", [(0, 1, [0]), (1, 1, [0, 4, 8])]),
            ("narrow_then_wide", [(0, 1, [0, 1, 2]), (1, 1, [0, 4, 8])]),
            ("sort_two_clusters", [(0, 1, [0, 4, 8]), (1, 1, [0, 2, 4, 6, 8])]),
            ("crowded_then_valid", [(0, None, list(range(257))), (1, 1, [0, 4, 8])]),
        ):
            refs = []
            for group, variant, offsets in rows:
                refs += [
                    phrases.SentenceRef(
                        f"g{group} v{index if variant is None else variant}",
                        TODAY - timedelta(days=offset),
                    )
                    for index, offset in enumerate(offsets)
                ]
            output[label] = phrases.near_duplicate_clusters(refs, jaccard=1)
        patch.setattr(
            phrases,
            "_band_keys",
            lambda sig: (
                [(0, "left")]
                if sig[1] == 0
                else [(0, "left"), (0, "right")]
                if sig[1] == 1
                else [(0, "right")]
            ),
        )
        refs = [
            phrases.SentenceRef(f"g0 v{i}", TODAY - timedelta(days=i * 4))
            for i in range(3)
        ]
        output["two_node_buckets_transitive_chain"] = phrases.near_duplicate_clusters(
            refs, jaccard=0.5
        )
    return normalized(output)


def test_phrase_bucket_rejection_transitive_pairs_and_result_selection(monkeypatch):
    bound_phrase_walks(monkeypatch)
    assert phrase_selection_cases(monkeypatch) == runtime_contract()["phrase_selection"]


def test_immutable_analysis_records_and_constructor_defaults():
    from app.services import patterns, phrases, threshold

    records = [
        patterns.JournalEntry("", TODAY),
        patterns.Pattern("topic", "guitar", 1, 0.5),
        patterns.Analysis(0, 0, 0, None, None, []),
        phrases.SentenceRef("phrase", TODAY),
        phrases.PhraseCluster([], "phrase", 7, 3),
        threshold.evaluate([], today=TODAY),
    ]
    for record in records:
        field = dataclasses.fields(record)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, field, getattr(record, field))
    assert (
        normalized(records[:2]) == runtime_contract()["pattern_boundaries"]["defaults"]
    )


def test_reference_pattern_analysis_effect_size_and_description_boundaries():
    assert pattern_boundary_cases() == runtime_contract()["pattern_boundaries"]
    from app.services import patterns

    with pytest.raises(ValueError, match="^no dates to analyze$"):
        patterns._dominant_weekday([])


def test_crisis_unicode_token_and_regex_transform_boundaries(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    assert crisis_edge_cases() == runtime_contract()["crisis_edges"]


def test_phrase_real_scan_cost_ceilings_and_verbatim_signature_cache(monkeypatch):
    bound_phrase_walks(monkeypatch)
    assert phrase_cost_cases(monkeypatch) == runtime_contract()["phrase_costs"]


def test_threshold_calendar_and_unlock_boundaries():
    assert threshold_cases() == runtime_contract()["threshold"]
    from app.services import threshold

    for invalid in (0, -1):
        with pytest.raises(ValueError) as caught:
            threshold.evaluate([], threshold=invalid, today=TODAY)
        assert str(caught.value) == "threshold must be at least 1 day"


def test_pattern_descriptions_and_reference_analysis_outputs():
    assert pattern_cases() == runtime_contract()["patterns"]


def reference_pattern_vocabulary_cases():
    from app.services import patterns

    inputs = runtime_contract()["pattern_runtime_tokens"]
    return {
        token: [patterns.sentiment_score(token), sorted(patterns.extract_themes(token))]
        for token in inputs
    }


def test_reference_analyzer_consumed_released_vocabulary_values():
    assert (
        reference_pattern_vocabulary_cases() == runtime_contract()["pattern_vocabulary"]
    )


def test_question_templates_safety_ranking_and_calendar_rotation(monkeypatch):
    assert question_cases(monkeypatch) == runtime_contract()["questions"]


def test_question_first_real_request_populates_the_actual_day_memo():
    from app.services import questions

    key = ("analysis-memo-first-request", TODAY.toordinal(), "en")
    result = questions.question_for_today(key[0], [], TODAY, "en")
    assert isinstance(result, str) and result
    assert questions._DAY_PINNED_QUESTIONS[key] == result


def test_brain_language_valence_morphology_and_numeric_outputs():
    assert brain_primitive_cases() == runtime_contract()["brain_primitives"]


def test_crisis_normalized_variants_and_released_verdicts(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    assert crisis_cases() == runtime_contract()["crisis"]


def test_crisis_consumed_catalog_matches_the_released_cross_platform_contract():
    from app.services import crisis

    contract = json.loads((ROOT / "shared/crisis_phrases.json").read_text())
    assert list(crisis.DIALOG_PATTERNS) == contract["dialog"]
    assert list(crisis.SUPPRESS_EXTRA_PATTERNS) == contract["suppress_extra"]
    assert (
        list(crisis.SUPPRESS_PATTERNS)
        == contract["dialog"] + contract["suppress_extra"]
    )
    assert list(crisis.BENIGN_COMPOUNDS) == contract["benign_compounds"]


def crisis_character_cases():
    import re

    from app.services import crisis

    output = {}
    inputs = runtime_contract()["crisis_character_inputs"]
    for text in inputs:
        output["normalization:" + text] = [
            crisis._normalize_pre_punct(text),
            crisis.normalize_crisis_text(text),
            crisis._match_variants(text),
            crisis._folded_variants(text),
        ]
    for compound in json.loads((ROOT / "shared/crisis_phrases.json").read_text())[
        "benign_compounds"
    ]:
        output["benign_fold:" + compound] = crisis._folded_variants(
            "i watched " + compound + " today"
        )
        stretched = "".join(ch * 2 if "a" <= ch <= "z" else ch for ch in compound)
        output["benign_stretched_fold:" + compound] = crisis._folded_variants(
            "i watched " + stretched + " today"
        )
    for pattern in (
        "((ab))cd",
        "(?:a(?:b)c)d",
        "[a(b)]cd",
        "a([bc])def",
        "[(a)]bc",
        "(a)(b)cd",
        "((a))((b))c",
    ):
        output["nested_regex:" + pattern] = [
            crisis._interleave_optional_marks(pattern),
            crisis._toplevel_literal_letters(pattern),
        ]
    for ending in ("die", "dead", "cutting", "gone", "on", "up", "out"):
        pattern = r"\bprefix\s+" + ending + r"\b"
        compiled = re.compile(crisis._concat_pattern(pattern))
        output["anchored_ending:" + ending] = [
            bool(compiled.search(text))
            for text in (
                "prefix" + ending,
                "prefix" + ending + "field",
                "prefix|" + ending,
                "prefix|" + ending + "field",
            )
        ]
    return normalized(output)


def test_crisis_each_confusable_invisible_leet_and_concat_boundary(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    assert crisis_character_cases() == runtime_contract()["crisis_characters"]


def test_phrase_hash_similarity_and_calendar_cluster_outputs(monkeypatch):
    bound_phrase_walks(monkeypatch)
    assert phrase_cases() == runtime_contract()["phrases"]


def test_brain_store_normalization_and_stable_serialization():
    assert brain_state_cases() == runtime_contract()["brain_state"]


def test_brain_lifecycle_replication_aging_alias_and_eviction_outputs():
    assert brain_lifecycle_cases() == runtime_contract()["brain_lifecycle"]


def test_brain_statistical_detector_and_calibrated_alarm_outputs():
    assert brain_detector_cases() == runtime_contract()["brain_detectors"]


def test_brain_complete_multilingual_structured_corpus_outputs(monkeypatch):
    from app.services import brain

    bound_crisis_substitutions(monkeypatch)
    bound_phrase_walks(monkeypatch)
    load = brain.load_state

    def bounded_load(raw):
        state = load(raw)
        state["patterns"] = BoundedPatterns(state["patterns"])
        return state

    monkeypatch.setattr(brain, "load_state", bounded_load)
    assert brain_corpus_cases() == runtime_contract()["brain_corpora"]


def test_brain_actual_measurements_structured_channels_and_cost_bounds(monkeypatch):
    bound_crisis_substitutions(monkeypatch)
    bound_phrase_walks(monkeypatch)
    assert (
        brain_measurement_cases(monkeypatch) == runtime_contract()["brain_measurements"]
    )


def test_brain_released_vocabulary_scoring_and_topic_eligibility_outputs():
    assert brain_dictionary_cases() == runtime_contract()["brain_dictionary"]


def test_phrase_union_find_terminates_for_three_repeated_sentences(monkeypatch):
    from app.services import phrases

    class BoundedParents(list):
        reads = 0

        def __getitem__(self, index):
            self.reads += 1
            assert self.reads <= 4096, (
                "three-node disjoint-set walk stopped making progress"
            )
            return super().__getitem__(index)

    def lists(values=()):
        return (
            BoundedParents(values)
            if isinstance(values, range)
            else builtins.list(values)
        )

    monkeypatch.setattr(phrases, "list", lists, raising=False)
    text = "i keep worrying about the same deadline every night"
    sentences = [
        phrases.SentenceRef(text, TODAY - timedelta(days=offset))
        for offset in (0, 4, 8)
    ]
    clusters = phrases.near_duplicate_clusters(sentences)
    assert len(clusters) == 1
    assert clusters[0].representative == text
    assert clusters[0].members == sentences
    assert (clusters[0].span_days, clusters[0].distinct_days) == (8, 3)


def test_crisis_leet_normalization_reaches_its_fixed_point(monkeypatch):
    from app.services import crisis

    class BoundedSubstitution:
        def __init__(self, expression):
            self.expression = expression
            self.calls = 0

        def sub(self, replacement, text):
            self.calls += 1
            assert self.calls <= 32, (
                "short leet input did not converge to a fixed point"
            )
            return self.expression.sub(replacement, text)

    for name in ("_LEET_RE", "_LEET_EDGE_RE", "_LEET_TRAIL_RE"):
        monkeypatch.setattr(crisis, name, BoundedSubstitution(getattr(crisis, name)))
    for text, expected in (
        ("ordinary journal", "ordinary journal"),
        ("su1c1de", "suicide"),
        ("k1ll myse1f", "kill myself"),
        ("1 am tired", "1 am tired"),
        ("1am tired", "iam tired"),
        ("suic1d3", "suicide"),
    ):
        assert crisis._leet_fold(text) == expected


@pytest.mark.parametrize("reuse", [False, True])
def test_semantic_fork_lookup_terminates_and_reuses_the_matching_claim(reuse):
    from app.services import brain

    class BoundedPatterns(dict):
        reads = 0

        def _read(self):
            self.reads += 1
            assert self.reads <= 128, (
                "small semantic-fork store stopped making progress"
            )

        def get(self, *args):
            self._read()
            return super().get(*args)

        def __contains__(self, item):
            self._read()
            return super().__contains__(item)

        def __getitem__(self, item):
            self._read()
            return super().__getitem__(item)

    def record(pid, day, state):
        return brain.StoredPattern(
            pid=pid,
            kind="temporal",
            label="work",
            first_seen=TODAY.isoformat(),
            last_seen=TODAY.isoformat(),
            first_qualified=TODAY.isoformat(),
            last_qualified=TODAY.isoformat(),
            occurrences=12,
            state=state,
            qualification_days=[TODAY.isoformat()],
            evidence_dates=[TODAY.isoformat()],
            feedback={},
            detail={"day": day},
        )

    original = record("temporal:work", "Sunday", "confirmed")
    fork = record("temporal:work~2", "Tuesday" if reuse else "Wednesday", "candidate")
    patterns = BoundedPatterns({original.pid: original, fork.pid: fork})
    store = brain.fresh_state()
    store["patterns"] = patterns
    signal = brain._Signal(
        pid=original.pid,
        kind="temporal",
        label="work",
        occurrences=12,
        pvalue=0.01,
        detail={"day": "Tuesday"},
        evidence_days=[TODAY - timedelta(days=7), TODAY],
    )
    brain._merge_lifecycle(store, [signal], TODAY)
    assert original.state == "fading"
    expected = "temporal:work~2" if reuse else "temporal:work~3"
    assert signal.pid == expected
    assert patterns[expected].detail["day"] == "Tuesday"
    assert len(patterns) == (2 if reuse else 3)
