"""Focused regression tests for analytics-service defensive paths.

These cases exercise the less common inputs that are still important to the
product's safety contract: hostile encrypted payload shapes, statistical
boundary values, deterministic question-pool filtering, and a deletion race
during recompute.  They deliberately test public behavior or small pure
helpers; production configuration and coverage thresholds stay untouched.
"""

from __future__ import annotations

import json
import math
from contextlib import asynccontextmanager
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.api import insights
from app.deps import ApiError
from app.security import crypto
from app.services import questions, statsig
from app.services.patterns import Pattern


def test_pattern_descriptions_cover_structured_and_extended_kinds():
    """Every surfaced kind has copy that matches its evidence source."""
    cases = [
        (
            Pattern("link", "sleep", 4, 0.5, {"channel": "sleep_quality", "direction": "higher"}),
            "rated as rougher",
        ),
        (
            Pattern(
                "mood_correlation",
                "sleep",
                4,
                0.5,
                {"channel": "sleep_quality", "direction": "lower"},
            ),
            "same day",
        ),
        (
            Pattern("temporal", "sleep", 4, 0.5, {"channel": "sleep_quality", "day": "Monday"}),
            "rougher nights",
        ),
        (
            Pattern("temporal", "run", 4, 0.5, {"source": "tag", "day": "Tuesday"}),
            "tagged 'run'",
        ),
        (
            Pattern(
                "mood_correlation",
                "family",
                4,
                0.5,
                {"source": "tag", "direction": "higher", "mood_delta": -0.4},
            ),
            "days you tag 'family'",
        ),
        (
            Pattern("avoidance", "work", 2, 0.5, {"silences": 2, "share": 0.5, "base_rate": 0.2}),
            "versus your usual 20% silent days",
        ),
        (Pattern("cadence", "", 1, 0.5), "less regular"),
        (Pattern("mood_shift", "", 1, 0.5, {"direction": "higher", "shift": 0.4}), "higher"),
        (
            Pattern("link", "family", 4, 0.5, {"source": "tag", "direction": "lower"}),
            "you tag 'family'",
        ),
        (Pattern("link", "work", 4, 0.5, {"direction": "lower", "lag_days": 1}), "day after"),
        (
            Pattern("link", "work", 4, 0.5, {"direction": "higher", "lag_days": 3}),
            "about 3 days later",
        ),
        (Pattern("inertia", "", 1, 0.5), "carrying over"),
        (Pattern("instability", "", 1, 0.5), "swung more widely"),
        (Pattern("rumination", "I failed", 3, 0.5), "across different days"),
        (Pattern("topic", "work", 5, 0.5, {"trend": "rising", "share": 0.4}), "40% of entries"),
        (Pattern("topic", "music", 5, 0.5, {"trend": "steady"}), "steady presence"),
    ]

    for pattern, expected in cases:
        assert expected in pattern.describe()


def test_statsig_boundary_and_degenerate_inputs_fail_closed():
    """Tail helpers keep exact edge semantics and reject impossible claims."""
    assert statsig.poisson_binomial_sf(0, []) == 1.0
    assert statsig.poisson_binomial_sf(1, []) == 0.0
    assert statsig.poisson_binomial_sf(0, [0.2, 0.8]) == 1.0
    assert statsig.poisson_binomial_sf(3, [0.2, 0.8]) == 0.0
    with pytest.raises(ValueError, match="every p"):
        statsig.poisson_binomial_sf(1, [1.01])

    assert statsig._betainc(2.0, 3.0, 0.0) == 0.0
    assert statsig._betainc(2.0, 3.0, 1.0) == 1.0
    assert statsig.f_sf(3.0, 0, 5) == 1.0
    assert statsig.f_sf(0.0, 1, 5) == 1.0
    assert statsig.correlation_p(1.0, 10) == 1.0
    assert 0.0 < statsig.correlation_p(0.5, 10) < 1.0
    assert statsig.effective_sample_size(0, 0.5) == 0.0
    # The function is defensive even if an untyped caller supplies an
    # infinite sample count: the zero standard error is no evidence.
    assert statsig.fisher_z_difference_p(0.2, math.inf, 0.1, math.inf) == 1.0


def test_statsig_continued_fraction_underflow_guards_are_finite(monkeypatch):
    """The Lentz denominator floors prevent numerical zero divisions."""
    # A deliberately enlarged floor reaches each defensive branch without
    # relying on platform-specific subnormal floating-point behavior.
    monkeypatch.setattr(statsig, "_BETACF_FPMIN", 2.0)
    assert math.isfinite(statsig._betacf(1.0, 1.0, 0.5))


def test_statsig_welch_fails_closed_if_effective_count_is_nonfinite(monkeypatch):
    """An impossible dependency result must not manufacture significance."""
    monkeypatch.setattr(statsig, "effective_sample_size", lambda *_: math.inf)
    assert statsig.welch_test([0.0, 1.0], [0.0, 2.0], lag1=0.5) == (0.0, 1.0)


def _entry_payload(**changes: object) -> bytearray:
    outer = date(2026, 9, 18)
    payload: dict[str, object] = {"text": "ordinary day", "created_at": outer.isoformat()}
    payload.update(changes)
    return bytearray(json.dumps(payload).encode("utf-8"))


def test_parse_entries_normalizes_structured_channels_and_rejects_hostile_shapes():
    """Structured fields are normalized only after their strict validation."""
    outer = date(2026, 9, 18)
    (entry,) = insights._parse_entries(
        [_entry_payload(energy=4.0, sleep=5, tags=[" Run ", "run", "", "Tea", "tea"])],
        [outer],
    )
    assert entry.energy == 1.0
    assert entry.sleep_quality == 5
    assert entry.tags == ("run", "tea")

    invalid_cases = [
        ({"energy": True}, "energy must be a finite number"),
        ({"sleep": True}, "sleep must be an integer 1..5"),
        ({"tags": "run"}, "tags must be a list of at most 8 strings"),
        ({"tags": ["run", 3]}, "tags must be strings"),
    ]
    for changes, message in invalid_cases:
        with pytest.raises(ValueError, match=f"^{message}$"):
            insights._parse_entries([_entry_payload(**changes)], [outer])


def test_parse_feedback_rejects_malformed_items_and_returns_stable_api_errors():
    """Only bounded, typed feedback taps enter the encrypted brain state —
    and a malformed item is a 400 for the WHOLE blob (audit L-11,
    2026-09-20): the old silent per-item filtering drifted from the
    docstring's "never a silent skip" contract and half-applied corrupt
    queues invisibly. The pre-flight shape check on the recompute path
    turns this into a quarantineable client error before any corpus work."""
    for raw in (b"{", b"\xff", b"[]", b'{"feedback": {}}'):
        with pytest.raises(ApiError) as excinfo:
            insights._parse_feedback(raw)
        assert excinfo.value.status_code == 400
        assert excinfo.value.code == "entry_payload_malformed"

    accepted = json.dumps({"feedback": [{"pid": "accepted", "resonated": True}]}).encode("utf-8")
    events = insights._parse_feedback(accepted)
    assert events.taps == [("accepted", True)]
    assert events.muted == []
    assert events.unmuted == []

    malformed_payloads = [
        {"feedback": ["not-an-object"]},
        {"feedback": [{"pid": "", "resonated": True}]},
        {"feedback": [{"pid": "wrong-type", "resonated": 1}]},
        {"feedback": [{"pid": "x" * 129, "resonated": False}]},
        {"feedback": [{"pid": "ok", "resonated": True}], "muted": ["ok", 7]},
        {"feedback": [{"pid": "ok", "resonated": True}], "unmuted": [""]},
    ]
    for payload in malformed_payloads:
        with pytest.raises(ApiError) as excinfo:
            insights._parse_feedback(json.dumps(payload).encode("utf-8"))
        assert excinfo.value.status_code == 400
        assert excinfo.value.code == "entry_payload_malformed"


def test_chosen_pattern_pid_filters_suppressed_and_duplicate_questions(monkeypatch):
    """Feedback ownership follows the exact de-duplicated question pool."""
    pattern = Pattern("topic", "focus", 3, 0.5, {"pattern_pid": "pid-focus"})
    monkeypatch.setattr(questions, "feedback_rank", lambda _: (0,))
    monkeypatch.setattr(questions, "pattern_is_sensitive", lambda _: False)
    monkeypatch.setattr(
        questions,
        "render_pattern_questions",
        lambda _: ["suppressed?", "same?", "same?"],
    )
    monkeypatch.setattr(questions, "GENERIC_QUESTIONS", ("same?", "generic?"))
    monkeypatch.setattr(questions, "user_rotation_offset", lambda _: 0)
    monkeypatch.setattr(questions.crisis, "matches_suppress", lambda text: text == "suppressed?")

    start = date(2026, 9, 18)
    chosen_day = next(day for day in (start, start + timedelta(days=1)) if day.toordinal() % 2 == 0)
    assert insights._chosen_pattern_pid(chosen_day, [pattern], "user") == "pid-focus"


def test_fk_classifier_handles_an_integrity_error_without_an_original_exception():
    assert insights._is_fk_violation(IntegrityError("INSERT", {}, None)) is False


async def test_load_rows_avoids_fetching_an_entry_that_exceeds_the_byte_budget():
    """The metadata pass stops before an oversized blob query is built."""

    class _MetadataResult:
        def all(self):
            return [("newest-entry", 2)]

    class _Session:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        def __init__(self):
            self.calls = 0

        async def execute(self, _statement):
            self.calls += 1
            return _MetadataResult()

    session = _Session()
    assert await insights._load_rows(session, "user", limit=10, blob_budget=1) == []
    assert session.calls == 1


async def test_recompute_reports_deleted_account_after_the_lifecycle_fence(monkeypatch):
    """A user deleted after threshold evaluation never reaches analysis."""
    popped_key = bytearray(b"k" * crypto.KEY_SIZE)

    class _MissingUserSession:
        async def get(self, *_args, **_kwargs):
            return None

    @asynccontextmanager
    async def sessionmaker():
        yield _MissingUserSession()

    async def active_dates(*_args, **_kwargs):
        return [date(2026, 9, 18)]

    monkeypatch.setattr(insights, "_entry_dates", active_dates)
    state = SimpleNamespace(
        settings=SimpleNamespace(unlock_threshold_days=1),
        key_store=SimpleNamespace(pop=lambda *_args, **_kwargs: popped_key),
        sessionmaker=sessionmaker,
    )
    request = SimpleNamespace(app=SimpleNamespace(state=state))

    with pytest.raises(ApiError) as excinfo:
        # token_epoch rides the fake user because the handler captures the
        # authenticated epoch before its lock waits (audit M-2, 2026-09-20);
        # the account delete still wins inside the fence (410 below).
        await insights.recompute(
            request, SimpleNamespace(id="deleted-user", token_epoch=1), "session-token"
        )

    assert excinfo.value.status_code == 410
    assert excinfo.value.code == "account_deleted"
    assert popped_key == bytearray(crypto.KEY_SIZE)
