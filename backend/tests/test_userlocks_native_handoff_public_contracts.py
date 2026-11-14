"""Configured native lock registry keeps waiter custody and clears completed task state."""

import asyncio

import pytest

from app.deps import ApiError
from app.locks import UserLocks


@pytest.mark.asyncio
async def test_native_waiter_reference_blocks_a_nested_dedicated_reacquire_after_release():
    registry = UserLocks(max_keys=1)
    dedicated, overflow = registry.hold("dedicated"), registry.hold("overflow")
    await dedicated.__aenter__()
    await overflow.__aenter__()
    started, entered, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def waiter():
        started.set()
        async with registry.hold("dedicated"):
            entered.set()
            await release.wait()

    async def release_after_native_handoff():
        await entered.wait()
        release.set()

    tasks = [asyncio.create_task(waiter()), asyncio.create_task(release_after_native_handoff())]
    try:
        await started.wait()
        # The waiter runs to its real asyncio.Lock acquisition wait before
        # this task resumes. Context exit releases without yielding; this
        # task still owns overflow during the genuine queued handoff gap.
        await dedicated.__aexit__(None, None, None)
        with pytest.raises(ApiError) as refusal:
            async with registry.hold("dedicated"):
                pass
        assert refusal.value.status_code == 503
        assert refusal.value.code == "service_unavailable"
    finally:
        release.set()
        await overflow.__aexit__(None, None, None)
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_completed_native_dedicated_scope_does_not_turn_a_later_wait_into_a_nested_refusal():
    registry = UserLocks(max_keys=1)
    async with registry.hold("dedicated"):
        pass
    dedicated_ready, overflow_ready = asyncio.Event(), asyncio.Event()
    release_dedicated, release_overflow, attempted = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )

    async def dedicated_holder():
        async with registry.hold("dedicated"):
            dedicated_ready.set()
            await release_dedicated.wait()

    async def overflow_holder():
        async with registry.hold("overflow"):
            overflow_ready.set()
            await release_overflow.wait()

    async def release_when_probe_waits():
        await attempted.wait()
        await asyncio.sleep(0)
        release_overflow.set()

    tasks = [asyncio.create_task(dedicated_holder())]
    try:
        await dedicated_ready.wait()
        tasks.extend(
            [
                asyncio.create_task(overflow_holder()),
                asyncio.create_task(release_when_probe_waits()),
            ]
        )
        await overflow_ready.wait()
        attempted.set()
        # The earlier dedicated scope is complete. This is an ordinary new
        # acquisition, so it must wait for the native other owner and enter.
        async with registry.hold("overflow"):
            assert release_overflow.is_set()
    finally:
        release_overflow.set()
        release_dedicated.set()
        await asyncio.gather(*tasks)
