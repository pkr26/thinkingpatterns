"""Public lock progress and custody at supported bounded registry capacities."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


async def checkpoint(event, task):
    """Observe either progress or the actor's failure, with a finite guard."""
    waiter = asyncio.create_task(event.wait())
    try:
        async with asyncio.timeout(1):
            done, _ = await asyncio.wait(
                [waiter, task], return_when=asyncio.FIRST_COMPLETED
            )
            if task in done:
                await task
                assert event.is_set(), "lock actor ended before its progress checkpoint"
    finally:
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


async def close_tasks(*tasks):
    for task in tasks:
        task.cancel()
    async with asyncio.timeout(1):
        results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(task.done() for task in tasks)
    errors = [r for r in results if isinstance(r, BaseException)
              and not isinstance(r, asyncio.CancelledError)]
    if errors:
        raise BaseExceptionGroup("lock actor cleanup failed", errors)


def test_nested_dedicated_release_preserves_foreign_capacity_refusal_and_retry():
    async def exercise():
        from app.deps import ApiError
        from app.locks import UserLocks

        registry = UserLocks(max_keys=2)
        entered, release = asyncio.Event(), asyncio.Event()

        async def foreign_owner():
            async with registry.hold("foreign"):
                entered.set()
                await release.wait()

        async with registry.hold("outer"):
            inner = registry.hold("inner")
            await inner.__aenter__()
            inner_open = True
            owner = asyncio.create_task(foreign_owner())
            try:
                await checkpoint(entered, owner)
                await inner.__aexit__(None, None, None)
                inner_open = False
                # This task still owns outer; waiting for the foreign owner
                # would deadlock because only this task signals its release.
                try:
                    async with asyncio.timeout(1):
                        with pytest.raises(ApiError) as failure:
                            async with registry.hold("foreign"):
                                pytest.fail("nested guard entered a foreign critical section")
                except TimeoutError:
                    pytest.fail("nested guard waited instead of refusing foreign contention")
                error = failure.value
                assert (error.status_code, error.code, error.headers) == (
                    503, "service_unavailable", {"Retry-After": "1"}
                )
            finally:
                release.set()
                try:
                    await close_tasks(owner)
                finally:
                    if inner_open:
                        await inner.__aexit__(None, None, None)
        # Refusal and cancellation cannot poison a subsequent ordinary user.
        async with asyncio.timeout(1):
            async with registry.hold("foreign") as lock:
                assert lock.locked()
        assert registry.total_overflow_refs() == 0

    asyncio.run(exercise())


def test_live_key_exclusion_survives_capacity_pressure_and_waiter_handoff():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks(max_keys=1)
        other_entered, release_other = asyncio.Event(), asyncio.Event()
        waiter_started, waiter_entered = asyncio.Event(), asyncio.Event()
        tasks = []
        first_active = True

        async def other_owner():
            async with registry.hold("other"):
                other_entered.set()
                await release_other.wait()

        async def waiter():
            waiter_started.set()
            async with registry.hold("first") as acquired:
                assert not first_active, "same key entered before its current owner released"
                assert acquired is first_lock, "a live key was split into a second guard"
                waiter_entered.set()

        try:
            async with registry.hold("first") as first_lock:
                assert registry.total_overflow_refs() == 0
                tasks.append(asyncio.create_task(other_owner()))
                await checkpoint(other_entered, tasks[0])
                assert registry.total_overflow_refs() == 1, "a live dedicated key must force fallback"
                tasks.append(asyncio.create_task(waiter()))
                await checkpoint(waiter_started, tasks[1])
                assert not waiter_entered.is_set()
                assert first_lock.locked()
                first_active = False
            await checkpoint(waiter_entered, tasks[1])
            await tasks[1]
        finally:
            release_other.set()
            await close_tasks(*tasks)
        async with asyncio.timeout(1):
            async with registry.hold("first") as lock:
                assert lock.locked()
        assert registry.total_overflow_refs() == 0

    asyncio.run(exercise())


def test_reentrant_fallback_keeps_outer_custody_after_cancelled_waiter():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks(max_keys=1)
        # Same logical key necessarily uses the same fallback; no hash/layout
        # introspection is needed to establish public reentrancy behavior.
        started, entered = asyncio.Event(), asyncio.Event()
        tasks = []

        async def waiter():
            started.set()
            async with registry.hold("shared"):
                entered.set()

        try:
            async with registry.hold("dedicated"):
                async with registry.hold("shared") as outer:
                    async with asyncio.timeout(1):
                        async with registry.hold("shared") as inner:
                            assert inner is outer and outer.locked()
                            assert registry.total_overflow_refs() == 2
                    assert outer.locked() and registry.total_overflow_refs() == 1
                    tasks.append(asyncio.create_task(waiter()))
                    await checkpoint(started, tasks[-1])
                    assert not entered.is_set()
                    await close_tasks(tasks[-1])
                    assert outer.locked() and registry.total_overflow_refs() == 1
                    started.clear()
                    tasks.append(asyncio.create_task(waiter()))
                    await checkpoint(started, tasks[-1])
                    assert not entered.is_set()
                await checkpoint(entered, tasks[-1])
                await tasks[-1]
        finally:
            await close_tasks(*tasks)
        assert registry.total_overflow_refs() == 0

    asyncio.run(exercise())
