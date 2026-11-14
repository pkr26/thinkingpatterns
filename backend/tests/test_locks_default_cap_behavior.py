"""Behavioral default-cap oracle candidate; private evidence only."""

import pytest

from app.locks import UserLocks


@pytest.mark.asyncio
async def test_default_user_locks_recycle_the_first_idle_key_at_the_ten_thousand_cap():
    locks = UserLocks()
    for index in range(10_001):
        async with locks.hold(f"default-cap-{index}"):
            pass

    assert len(locks._locks) == 10_000
    assert "default-cap-0" not in locks._locks
    assert "default-cap-1" in locks._locks
    assert "default-cap-10000" in locks._locks
