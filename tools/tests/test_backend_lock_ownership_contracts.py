"""Lock ownership survives nested release without traceback-scale saturation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


def test_inner_dedicated_release_retains_the_outer_guard_before_foreign_overflow():
    async def exercise():
        from app.deps import ApiError
        from app.locks import UserLocks
        from test_backend_overflow_lock_contracts import (
            capacity_response,
            checkpoint,
            enter_without_queue,
            idle,
            key,
        )

        # This is the supported configurable capacity, not an altered native
        # limit. Ownership bookkeeping has the same obligation at every cap.
        registry = UserLocks(max_keys=2)
        first, second, foreign = key(), key(), key("patient")
        entered, release = asyncio.Event(), asyncio.Event()

        async def owner():
            async with registry.hold(foreign):
                entered.set()
                await release.wait()

        async with registry.hold(first):
            inner = registry.hold(second)
            enter_without_queue(inner)
            inner_open = True
            task = asyncio.create_task(owner())
            try:
                await checkpoint(entered, task)
                await inner.__aexit__(None, None, None)
                inner_open = False
                # A freed dedicated slot cannot hide the outer acquisition
                # from the nested contention admission check.
                with pytest.raises(ApiError) as failure:
                    enter_without_queue(registry.hold(foreign))
                capacity_response(failure.value)
            finally:
                release.set()
                await task
                if inner_open:
                    await inner.__aexit__(None, None, None)
        idle(registry)

    asyncio.run(exercise())


def test_two_dedicated_guards_release_independently_and_unblock_their_waiter():
    async def exercise():
        from app.locks import UserLocks
        from test_backend_overflow_lock_contracts import checkpoint, idle, key

        registry = UserLocks()
        first, second = sorted([key(), key()])
        started, entered = asyncio.Event(), asyncio.Event()
        task = None

        async def waiter():
            started.set()
            async with registry.hold(first):
                entered.set()

        try:
            async with registry.hold(first) as outer:
                async with registry.hold(second) as inner:
                    assert inner is not outer and inner.locked() and outer.locked()
                    task = asyncio.create_task(waiter())
                    await checkpoint(started, task)
                    assert not entered.is_set()
                assert not inner.locked() and outer.locked()
                assert not entered.is_set()
            await task
            assert entered.is_set()
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        idle(registry)

    asyncio.run(exercise())


def test_cancelled_task_releases_two_dedicated_guards_and_can_be_replaced():
    async def exercise():
        from app.locks import UserLocks
        from test_backend_overflow_lock_contracts import checkpoint, idle, key

        registry = UserLocks()
        first, second = sorted([key(), key()])
        entered, release = asyncio.Event(), asyncio.Event()

        async def owner():
            async with registry.hold(first), registry.hold(second):
                entered.set()
                await release.wait()

        task = asyncio.create_task(owner())
        try:
            await checkpoint(entered, task)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            async with registry.hold(first), registry.hold(second):
                pass
        finally:
            release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        idle(registry)

    asyncio.run(exercise())


def test_reentrant_overflow_body_error_preserves_the_outer_exclusion():
    async def exercise():
        from app.locks import UserLocks
        from test_backend_overflow_lock_contracts import (
            checkpoint,
            colliding_pair,
            idle,
            key,
        )

        registry = UserLocks(max_keys=1)
        first, second = colliding_pair(registry)
        started, entered = asyncio.Event(), asyncio.Event()
        task = None

        async def waiter():
            started.set()
            async with registry.hold(second):
                entered.set()

        try:
            async with registry.hold(key()):
                async with registry.hold(first) as outer:
                    with pytest.raises(ValueError, match="nested-body-fault"):
                        async with registry.hold(second):
                            raise ValueError("nested-body-fault")
                    assert outer.locked() and registry.total_overflow_refs() == 1
                    task = asyncio.create_task(waiter())
                    await checkpoint(started, task)
                    assert not entered.is_set()
                await task
                assert entered.is_set()
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        idle(registry)

    asyncio.run(exercise())
