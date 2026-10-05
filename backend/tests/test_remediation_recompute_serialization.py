"""Real HTTP recomputes serialize one account while other accounts can progress."""

import asyncio
import threading
from contextlib import asynccontextmanager
from datetime import date

import pytest

from app.services import brain
from tests.helpers import ClientEmulator, daterange


@pytest.mark.parametrize("same_owner", [True, False])
async def test_overlapping_recomputes_preserve_account_serialization(
    client, monkeypatch, same_owner
):
    from app.locks import lifecycle_locks

    alice = ClientEmulator("serialization-alice", "synthetic-serialization-password")
    await alice.register(client)
    await alice.backdate_account(client, days=40)
    for day in daterange(32, date.today()):
        await alice.create_entry(
            client,
            "I wrote about the day in my journal.",
            day,
            client_entry_id=f"alice-{day.isoformat()}",
        )
    bob = alice
    if not same_owner:
        bob = ClientEmulator("serialization-bob", "synthetic-independent-password")
        await bob.register(client)
        await bob.backdate_account(client, days=40)
        for day in daterange(32, date.today()):
            await bob.create_entry(
                client,
                "I wrote about the day in my journal.",
                day,
                client_entry_id=f"bob-{day.isoformat()}",
            )
    first_token = await alice.open_processing_session(client)
    second_token = await bob.open_processing_session(client)

    # Instrument arrival only, preserving actual guards and their opaque keys.
    # A waiting request has reached the endpoint fence before overlap is tested.
    second_attempted = asyncio.Event()
    attempts = 0
    original_hold = lifecycle_locks.hold

    @asynccontextmanager
    async def observed_hold(key):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            second_attempted.set()
        async with original_hold(key):
            yield

    monkeypatch.setattr(lifecycle_locks, "hold", observed_hold)
    loop = asyncio.get_running_loop()
    first_started = asyncio.Event()
    second_started = asyncio.Event()
    release = threading.Event()
    counts_lock = threading.Lock()
    active = 0
    peak = 0
    calls = 0
    original_update = brain.update

    def blocked_analysis(*args, **kwargs):
        nonlocal active, peak, calls
        with counts_lock:
            calls += 1
            number = calls
            active += 1
            peak = max(peak, active)
        try:
            if number == 1:
                loop.call_soon_threadsafe(first_started.set)
                assert release.wait(10), "The owned analysis barrier was not released"
            else:
                loop.call_soon_threadsafe(second_started.set)
            return original_update(*args, **kwargs)
        finally:
            with counts_lock:
                active -= 1

    monkeypatch.setattr(brain, "update", blocked_analysis)

    async def request(emu, token):
        return await client.post(
            "/api/v1/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
        )

    first = asyncio.create_task(request(alice, first_token))
    second = None
    try:
        await asyncio.wait_for(first_started.wait(), 5)
        second = asyncio.create_task(request(bob, second_token))
        await asyncio.wait_for(second_attempted.wait(), 5)
        if same_owner:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(second_started.wait(), 2)
        else:
            await asyncio.wait_for(second_started.wait(), 5)
    finally:
        release.set()
        pending = [first] + ([second] if second is not None else [])
        responses = await asyncio.wait_for(asyncio.gather(*pending), 10)
    assert all(response.status_code == 200 for response in responses), [
        (response.status_code, response.text) for response in responses
    ]
    assert calls == 2
    assert peak == (1 if same_owner else 2)
