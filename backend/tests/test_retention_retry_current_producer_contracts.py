"""Real retry-state evolution reaches the current sleep/callback interface."""

import asyncio
from types import SimpleNamespace

import pytest

from app import main


@pytest.mark.asyncio
@pytest.mark.parametrize("random_value", [0.0, 0.5])
async def test_current_retention_retry_producer_reaches_its_native_thirty_two_second_base(
    monkeypatch, random_value
):
    # These initial fields are the current failed-maintenance state with
    # the constructor's1-second delay. The native loop produces all later
    # 2/4/8/16/32 states; no fabricated30-second base or elapsed-time claim.
    app = SimpleNamespace(
        state=SimpleNamespace(
            audit_maintenance_retry_needed=True,
            audit_maintenance_retry_delay_seconds=main.AUDIT_MAINTENANCE_CATCHUP_SECONDS,
        )
    )
    delays, calls = [], []

    async def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 6:
            raise asyncio.CancelledError

    async def failed_audit(actual_app):
        assert actual_app is app
        calls.append("audit")
        raise RuntimeError("declared maintenance-provider outage")

    async def questions(actual_app):
        calls.append("questions")

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(main.random, "random", lambda: random_value)
    monkeypatch.setattr(main, "_prune_access_log_once", failed_audit)
    monkeypatch.setattr(main, "_prune_expired_questions_once", questions)
    with pytest.raises(asyncio.CancelledError):
        await main._access_log_retention_sweep(app)
    multiplier = 0.8 + 0.4 * random_value
    assert delays == pytest.approx([base * multiplier for base in [1, 2, 4, 8, 16, 32]])
    assert calls == ["audit"] * 5
    assert app.state.audit_maintenance_retry_delay_seconds == 32
