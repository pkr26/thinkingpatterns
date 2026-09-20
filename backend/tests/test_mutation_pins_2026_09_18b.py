"""Round-2 mutation campaign pins (2026-09-18, reports/mutation_campaign_2026-09-18_round2.md).

Eight survivors of the FULL fast suite, each pinned here and re-verified
killed by hand-applying the exact mutant. Two further full-suite survivors
are documented, not pinned:

  * I4 (pairing-burn expiry condition): the grant path already rejects
    expired codes in _live_code; the burn's WHERE clause only closes the
    milliseconds-wide lookup->burn race. Defense in depth.
  * J1 (question-pool belt-and-braces filter): every current template
    path is already subsumed by the three upstream tripwires (sensitive
    flag, label check, variants check); the filter guards future
    templates. Redundant by construction today.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.config import Settings
from app.main import create_app
from app.services import brain, crisis
from app.services.brain import JournalEntry, load_state, dump_state, StoredPattern
from app.services.patterns import Pattern
from app.services import questions

T0 = date(2026, 6, 1)


def _days(n: int, start: date = T0) -> list[date]:
    return [start + timedelta(days=i) for i in range(n)]


# ---------------------------------------------------------------------------
# G4/G5: the EWMA control chart's honesty parameters
# ---------------------------------------------------------------------------


class TestEwmaChartPins:
    def _update_twice(self, sentiments: list[float], start: date = T0):
        """mood_shift is a WINDOW_STAT kind: it surfaces only after a second
        qualification day >= 2 calendar days out (the replication gate), so
        every chart pin recomputes twice."""
        first = [
            JournalEntry("ordinary day notes", d, sentiment=s)
            for d, s in zip(_days(len(sentiments), start), sentiments)
        ]
        res1 = brain.update(brain.fresh_state(), first, start + timedelta(days=len(sentiments)))
        tail_days = _days(2, start + timedelta(days=len(sentiments) + 1))
        second = first + [
            JournalEntry("ordinary day notes", d, sentiment=sentiments[-1]) for d in tail_days
        ]
        res2 = brain.update(res1.new_state, second, tail_days[-1] + timedelta(days=1))
        return res2

    def test_autocorrelated_stationary_series_does_not_fire(self):
        """G4 pin: a stationary AR-like series with strong carryover must not
        fire the chart — the limits are inflated by (1+phi)/(1-phi) precisely
        so ordinary autocorrelated mood is not a 'shift'.

        Corpus (tuned and verified discriminating): a single smooth hump
        baseline (lag-1 phi ~= 0.81, well above the 0.35 inflation trigger,
        sigma ~= 0.26), a quiet continuation, then a moderate elevated run
        (+0.5, ~1.6 sigma). Without the inflation the run clears the limits
        at p ~= 1e-6 and surfaces; the honest chart must stay silent.
        """
        hump = [0.10, 0.25, 0.40, 0.30, 0.15, -0.05, -0.25, -0.40, -0.25, -0.05]
        continuation = [0.05, 0.20, 0.05, -0.15, 0.05]
        elevated = [0.5] * 8
        result = self._update_twice(hump + continuation + elevated)
        shifts = [p for p in result.surfaced if p.kind == "mood_shift"]
        assert shifts == [], [s.detail for s in shifts]

    def test_single_beyond_limit_spike_is_not_a_shift(self):
        """G5 pin: MOOD_SHIFT_RUN is 3 — one beyond-limit point in the recent
        tail (a transient spike at the very end) must not surface a card.

        Corpus: flat baseline (sigma from mild variation), quiet run, one
        large spike on the final day. The spike's EWMA crosses the limit for
        exactly one point; the spike is repeated on the replication days so
        the second qualification is not what silences it — the run rule is.
        """
        baseline = [
            0.1,
            -0.1,
            0.2,
            -0.2,
            0.05,
            -0.05,
            0.15,
            -0.15,
            0.1,
            -0.1,
            0.2,
            -0.2,
            0.0,
            0.1,
            -0.1,
        ] + [0.0] * 8
        result = self._update_twice(baseline + [2.5])
        shifts = [p for p in result.surfaced if p.kind == "mood_shift"]
        assert shifts == [], [s.detail for s in shifts]


# ---------------------------------------------------------------------------
# G14/G15: lifecycle boundaries are exact
# ---------------------------------------------------------------------------


def _store_with_pattern(last_qualified: str, state_name: str) -> dict:
    store = brain.fresh_state()
    record = StoredPattern(
        pid="temporal:work",
        kind="temporal",
        label="work",
        first_seen=last_qualified,
        last_seen=last_qualified,
        first_qualified=last_qualified,
        last_qualified=last_qualified,
        occurrences=12,
        state=state_name,
        qualification_days=[last_qualified],
        evidence_dates=[last_qualified],
        feedback={},
        detail={"day": "Sunday"},
    )
    store["patterns"][record.pid] = record
    # Round-trip so _merge_lifecycle sees a normalized store, exactly as a
    # recompute would after loading the encrypted blob.
    return load_state(dump_state(store))


class TestLifecycleBoundaries:
    def test_active_pattern_survives_exactly_seven_stale_days(self):
        """G14 pin: GRACE_DAYS is 7 — at exactly 7 stale days the pattern is
        still active; fading starts only past 7 (a ->6 mutant fades early)."""
        last = "2026-08-01"
        for stale, expect_fading in ((7, False), (8, True)):
            store = _store_with_pattern(last, "confirmed")
            brain._merge_lifecycle(store, [], date.fromisoformat(last) + timedelta(days=stale))
            assert store["patterns"]["temporal:work"].state == (
                "fading" if expect_fading else "confirmed"
            ), f"stale={stale}"

    def test_fading_pattern_archives_only_past_forty_five_days(self):
        """G15 pin: ARCHIVE_DAYS is 45 — at exactly 45 stale days the pattern
        is still fading; archival starts only past 45 (a ->44 mutant
        archives a day early)."""
        last = "2026-08-01"
        for stale, expect_archived in ((45, False), (46, True)):
            store = _store_with_pattern(last, "fading")
            brain._merge_lifecycle(store, [], date.fromisoformat(last) + timedelta(days=stale))
            assert store["patterns"]["temporal:work"].state == (
                "archived" if expect_archived else "fading"
            ), f"stale={stale}"


# ---------------------------------------------------------------------------
# J2: crisis-adjacent surfaced cards carry detail.sensitive
# ---------------------------------------------------------------------------


class TestSensitiveFlagPin:
    def test_suppress_tier_rumination_surfaces_non_quoting(self):
        """J2 pin: a recurring negative cluster whose label is suppress-tier
        crisis language must surface with detail.sensitive — the mobile app
        and portal render the non-quoting card keyed off this flag."""
        phrase = "i can't go on anymore"  # dialog tier (therefore suppress tier)
        assert crisis.matches_suppress(phrase)
        days = _days(12)  # direct-measurement kinds surface at STRONG_EVIDENCE=10 occurrences
        entries = [
            JournalEntry(
                f"{phrase} and everything feels heavy and hopeless and unbearable",
                d,
                sentiment=-0.8,
            )
            for d in days
        ]
        result = brain.update(brain.fresh_state(), entries, days[-1] + timedelta(days=1))
        surfaced = [p for p in result.surfaced if p.kind in ("rumination", "recurring_phrase")]
        assert surfaced, "corpus must surface the recurring cluster"
        flagged = [p for p in surfaced if p.detail.get("sensitive")]
        assert flagged, [(p.kind, p.label, p.detail.get("sensitive")) for p in surfaced]

    def test_label_branch_of_sensitivity_flag(self):
        """J2 pin (the label branch): a record whose LABEL is suppress-tier
        is sensitive even when the stored variant list cannot catch it —
        the representative must not be the only unchecked copy. The variants
        check subsumes the label check whenever the representative survives
        the variants[:3] cap; this is the record shape where only the label
        branch sees it."""
        record = StoredPattern(
            pid="rumination:x",
            kind="rumination",
            label="i can't go on anymore",
            first_seen="2026-08-01",
            last_seen="2026-08-12",
            first_qualified="2026-08-12",
            last_qualified="2026-08-12",
            occurrences=12,
            state="emerging",
            qualification_days=["2026-08-12"],
            evidence_dates=["2026-08-01"],
            feedback={},
            # Benign variants only: the variants branch cannot fire here.
            detail={"variants": ["everything feels heavy and slow", "so tired of everything"]},
        )
        assert crisis.matches_suppress(record.label)
        assert not any(crisis.matches_suppress(v) for v in record.detail["variants"])
        assert brain._record_is_sensitive(record) is True


# ---------------------------------------------------------------------------
# K1/K4: fail-closed boot gates
# ---------------------------------------------------------------------------


class TestBootGates:
    def test_uppercase_environment_hits_production_gates(self):
        """K1 pin: environment values normalize before any comparison. The
        security direction is the DEV side — 'DEVELOPMENT'/' Development '
        are the developer's OPT-IN to dev gates; without normalization a
        case typo silently hits the production gates instead (fail-closed,
        but it means normalization is dead code and the next check built on
        the comparison inherits the typo)."""
        for env in ("DEVELOPMENT", " Development ", "development"):
            s = Settings(environment=env)  # dev secret allowed exactly here
            assert s.environment == "development", env
        # ...and no production-adjacent spelling may reach the dev gates.
        for env in ("PRODUCTION", " Production ", "prod", "staging"):
            with pytest.raises(RuntimeError, match="MINDPATTERN_TOKEN_SECRET"):
                Settings(environment=env)

    def test_production_app_mounts_no_docs(self):
        """K4 pin: /docs and /openapi.json exist only in development. The
        FastAPI attributes are set at construction, before any lifespan
        work, so construction alone is the honest pin."""
        settings = Settings(
            environment="production",
            token_secret="x" * 48,
            database_url="postgresql+asyncpg://u:p@localhost:5432/mindpattern_test",
        )
        app = create_app(settings)  # no lifespan: construction must not touch the DB
        assert app.docs_url is None
        assert app.openapi_url is None


# ---------------------------------------------------------------------------
# L2: the poor-sleep split is against the user's OWN median
# ---------------------------------------------------------------------------


class TestOwnMedianSleepSplit:
    def test_split_is_strictly_below_the_users_own_median(self):
        """L2 pin: a user rating every night 1 or 2 (median 1.5) has poor
        nights ONLY on the 1s. A fixed 3.0 population norm would mark every
        night poor — the within-person promise, pinned at the theme-day set
        (the candidate mood-correlation record's evidence dates)."""
        days = _days(20)  # the mood tie needs >=8 entries per side (poor vs not)
        entries = []
        for i, d in enumerate(days):
            rating = 1 if i % 2 == 0 else 2
            # Poor nights read lower, decent nights fine — the mood tie the
            # channel exists to find (and the reason the record lands in the
            # store at all: unqualified candidates are never merged).
            mood = -0.8 if rating == 1 else 0.5
            entries.append(
                JournalEntry("quiet notes and tea", d, sentiment=mood, sleep_quality=rating)
            )
        result = brain.update(brain.fresh_state(), entries, days[-1] + timedelta(days=1))
        record = result.new_state["patterns"].get("mood_correlation:poor sleep")
        assert record is not None, "the poor-sleep theme must be analyzed"
        expected = {d.isoformat() for d in days[0::2]}  # the rating-1 nights
        assert set(record.evidence_dates) == expected, (
            "poor-sleep days must be exactly the nights rated strictly below "
            "THIS user's median (1.5), not below any population norm"
        )
