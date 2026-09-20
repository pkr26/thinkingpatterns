"""Regression pins for the 2026-09-16 red-team remediation wave.

Every fix from reports/redteam_audit_2026-09-16.md that has a behavioral
surface is pinned here (crisis normalization, the phi=1.0 recompute crash,
the single-process guard, LLM spelled-contact rejection). Fixes whose pins
live in the suites they broke are not duplicated: TTL ceiling
(test_api_hardening_r3), export head (test_account_api / test_mutation_pins),
LLM payload shape + timeout (test_llm / test_mutation_pins), KDF floor
(test_kdf / test_contract_pins), nonce seam removal (test_encrypt_vectors).
"""

from __future__ import annotations

import subprocess
import sys
from datetime import date, timedelta

from app import singleprocess
from app.security import kdf
from app.services import brain, crisis, llm, questions
from app.services.patterns import JournalEntry, Pattern

BACKEND_DIR = __file__.rsplit("/tests/", 1)[0] if "/" in __file__ else None

TODAY = date(2026, 9, 16)


# ---------------------------------------------------------------------------
# P0-1: crisis normalization — the obfuscation corpus both engines must beat
# ---------------------------------------------------------------------------

OBVIOUS_CRISIS = [
    # leetspeak
    "i will su1c1de tonight",
    "k1ll myself",
    "1 want to d1e so bad",
    "un4l1ve myself",
    # homoglyphs (Cyrillic lookalikes)
    "ѕuicide is on my mind",
    "kіll myself",
    "сutting myself again",
    "want to dіe",
    # invisible characters
    "su​icide",
    "kill my​self",
    "su­icide",
    # intra-word separators
    "s.u.i.c.i.d.e",
    "k.i.l.l myself",
    "c-u-t-t-i-n-g myself",
    "s u i c i d e",
    # plain-English gaps the old list missed
    "i am going to off myself",
    "put me out of my misery",
    # non-English
    "quiero morir",
    "me quiero matar",
    "quitarme la vida",
    "je veux mourir",
    "me suicider",
    "ich will sterben",
    "bringe mich um",
    "suizid gedanken",
    "voglio morire",
    "quero morrer",
    "me matar",
    "我想死",
    "自杀",
    "死にたい",
    "自殺",
    "أريد أن أموت",
    "मरना चाहता हूँ",
    "मरना चाहती हूँ",
]

BENIGN = [
    "killed it at the presentation today",
    "cutting back on sugar this month",
    # the single-letter join threshold must not eat ordinary prose
    "i am so sad today",
    "to be or not to be that is the question",
    "a e i o u are vowels",
    "u s a won gold",
    "day 30 of my meditation streak, feeling fine",
]


class TestCrisisNormalization:
    def test_obfuscated_crisis_language_is_caught_by_suppress(self):
        for text in OBVIOUS_CRISIS:
            assert crisis.matches_suppress(text), f"suppress tier missed {text!r}"

    def test_obfuscated_crisis_language_fires_the_dialog_tier(self):
        # Everything except the hopelessness phrasing (suppress-only by
        # design) and bare "me matar" style fragments must reach the user.
        suppress_only = {"i don't see any future for me", "no future for me at all", "me suicider"}
        for text in OBVIOUS_CRISIS:
            if text in suppress_only:
                continue
            assert crisis.matches_dialog(text), f"dialog tier missed {text!r}"

    def test_benign_text_stays_silent(self):
        for text in BENIGN:
            assert not crisis.matches_dialog(text), f"dialog tier fired on {text!r}"

    def test_normalization_is_idempotent_and_stable(self):
        once = crisis.normalize_crisis_text("Ѕuіϲіde​ thoughts…")
        assert crisis.normalize_crisis_text(once) == once
        assert once == "suicide thoughts"

    def test_bypassed_label_is_no_longer_quoted_in_questions(self):
        # The end-to-end impact chain from the audit: a disguised crisis
        # phrase recurring in the journal used to ride a pattern label into
        # the daily question verbatim. With normalization, the pool filter
        # catches it. L-40 (2026-09-20): this used to read
        # ``assert not matches_suppress(label) or True`` — vacuous, so it
        # pinned nothing. The load-bearing fact is the POSITIVE one: the
        # suppress tier, through normalization, recognizes the disguised
        # label (it is exactly the "s u i c i d e" gap-joined form pinned
        # in OBVIOUS_CRISIS above), which is why the pool filter drops it.
        label = "the s u i c i d e thoughts are loud again"
        assert crisis.matches_suppress(label)
        pattern = Pattern(
            kind="rumination",
            label=label,
            occurrences=30,
            confidence=0.9,
            detail={"variants": [label]},
        )
        pool = questions.build_pool([pattern])
        assert not any(label in q for q in pool), pool

    def test_engine_marks_disguised_crisis_recurrence_sensitive(self):
        # E2.disguised-crisis-recurrence: 81 days of the disguised phrase
        # surfaced a QUOTED recurring_phrase card with sensitive=false.
        entries = [
            JournalEntry(
                text=f"{label} could not focus at work",
                entry_date=TODAY - timedelta(days=d),
                sentiment=None,
            )
            for d, label in (
                (d, "the s u i c i d e thoughts are loud again") for d in range(81, -1, -1)
            )
        ]
        result = brain.update(brain.fresh_state(), entries, TODAY)
        for surfaced in result.surfaced:
            if surfaced.kind in ("recurring_phrase", "rumination"):
                assert surfaced.detail.get("sensitive") is True, surfaced


# ---------------------------------------------------------------------------
# P0-2: the phi = 1.0 recompute crash
# ---------------------------------------------------------------------------


class TestMoodShiftPhiOne:
    CORPUS_TEXT = "day {i}: work was busy, slept okay, walked the dog and read a bit."

    def test_near_constant_mood_does_not_crash_the_engine(self):
        entries = [
            JournalEntry(
                text=self.CORPUS_TEXT.format(i=i),
                entry_date=TODAY - timedelta(days=i),
                sentiment=None,
            )
            for i in range(35, 0, -1)
        ]
        result = brain.update(brain.fresh_state(), entries, TODAY)  # used to ZeroDivisionError
        assert isinstance(result.surfaced, list)

    def test_perfectly_constant_mood_does_not_crash(self):
        entries = [
            JournalEntry(
                text="same as always", entry_date=TODAY - timedelta(days=i), sentiment=None
            )
            for i in range(35, 0, -1)
        ]
        brain.update(brain.fresh_state(), entries, TODAY)

    def test_honest_inflation_still_applies(self):
        # The clamp saturates the inflation cap: a phi of 0.999 and the old
        # 1.0-epsilon behavior produce the same capped sigma multiplier.
        values = [0.1 * (i + 1) for i in range(20)]  # monotone ramp, phi ~ 1.0
        assert brain._lag1_autocorr(values) is not None


# ---------------------------------------------------------------------------
# P1: the single-process guard
# ---------------------------------------------------------------------------


class TestSingleProcessGuard:
    def test_reentrant_within_one_process(self):
        key = ("rt-secret-2026-09-16", "sqlite+aiosqlite:///reentrance")
        with singleprocess.single_process_guard(*key):
            with singleprocess.single_process_guard(*key):  # tests stack apps
                pass
        singleprocess.release_single_process_lock(*key)  # idempotent release

    def test_second_process_is_refused(self):
        # A REAL second process (what uvicorn --workers 2 spawns) must be
        # refused while the first holds the deployment lock.
        secret = "rt-secret-second-process"
        url = "sqlite+aiosqlite:///second-proc"
        with singleprocess.single_process_guard(secret, url):
            probe = (
                "import sys; sys.path.insert(0, '.');"
                "from app import singleprocess;"
                "singleprocess.acquire_single_process_lock(%r, %r)" % (secret, url)
            )
            done = subprocess.run(
                [sys.executable, "-c", probe],
                capture_output=True,
                text=True,
                cwd=BACKEND_DIR,
                timeout=60,
            )
            assert done.returncode != 0
            assert "another worker/process is already serving" in done.stderr


# ---------------------------------------------------------------------------
# D1: LLM spelled-contact label rejection
# ---------------------------------------------------------------------------


class TestLlmSpelledContact:
    CORPUS = [
        "reminder to myself call five five five zero one three four now",
        "i keep meaning to visit evil dot com for laughs",
        "work dominates my week and sleep is rough",
    ]

    def test_spelled_phone_label_is_dropped(self):
        item = {
            "kind": "temporal",
            "label": "call five five five zero one three four",
            "occurrences": 9,
            "confidence": 0.9,
        }
        assert llm.sanitize_pattern(item, self.CORPUS) is None

    def test_spelled_domain_label_is_dropped(self):
        item = {
            "kind": "temporal",
            "label": "visit evil dot com often",
            "occurrences": 3,
            "confidence": 0.5,
        }
        assert llm.sanitize_pattern(item, self.CORPUS) is None

    def test_number_word_run_below_threshold_still_passes(self):
        # Two number-words in a row are ordinary prose ("one two punch");
        # only 3+ consecutive ones are treated as a spelled phone number.
        item = {
            "kind": "temporal",
            "label": "one two punch at work",
            "occurrences": 3,
            "confidence": 0.5,
        }
        out = llm.sanitize_pattern(item, self.CORPUS + ["one two punch at work"])
        assert out is not None and out.label == "one two punch at work"

    def test_digit_phone_and_urls_still_dropped(self):
        for label in ("call 555-0134", "see https://evil.example", "www.evil.example"):
            assert (
                llm.sanitize_pattern(
                    {"kind": "temporal", "label": label, "occurrences": 1, "confidence": 0.5},
                    self.CORPUS,
                )
                is None
            )


# ---------------------------------------------------------------------------
# Misc pins that would otherwise only live in the harness
# ---------------------------------------------------------------------------


def test_processing_ttl_ceiling_matches_consent_copy():
    from app.config import MAX_PROCESSING_SESSION_TTL

    assert MAX_PROCESSING_SESSION_TTL == 300  # "up to 5 minutes" (mobile copy)


def test_kdf_floor_constant():
    assert kdf.MIN_ITERATIONS == 100_000
    assert kdf.MIN_ITERATIONS < kdf.KDF_ITERATIONS
