"""Native-capacity sharing-lock progress, exclusion, and cleanup contracts."""

from __future__ import annotations

import asyncio
import uuid
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


def key(kind="therapist"):
    from app.locks import sharing_patient_lock_key, sharing_therapist_lock_key

    identifier = uuid.uuid4().hex
    return (
        sharing_therapist_lock_key(identifier)
        if kind == "therapist"
        else sharing_patient_lock_key(identifier)
    )


def colliding_pair(registry):
    first = key()
    for _ in range(10_000):
        second = key("patient")
        if registry._shard_for(first) is registry._shard_for(second):
            return first, second
    pytest.fail("could not find two supported UUID keys on the same fallback")


def ordered_cycle(registry):
    # Both actors acquire increasing therapist IDs, as rekey does. The
    # outside two keys alias while the middle key uses another fallback.
    candidates = sorted(key() for _ in range(256))
    for index, first in enumerate(candidates):
        for middle in candidates[index + 1 :]:
            if registry._shard_for(first) is registry._shard_for(middle):
                continue
            for last in candidates:
                if middle < last and registry._shard_for(first) is registry._shard_for(
                    last
                ):
                    return first, middle, last
    pytest.fail("could not find an ordered UUID alias cycle")


@asynccontextmanager
async def fill_native_registry(registry):
    # No reduced max_keys: every main witness saturates the released
    # default registry with real held guards rather than editing its map.
    async with AsyncExitStack() as stack:
        keys = []
        for _ in range(registry._max_keys - len(registry._locks)):
            name = key()
            keys.append(name)
            await stack.enter_async_context(registry.hold(name))
        assert len(registry._locks) == registry._max_keys
        yield keys


def enter_without_queue(guard):
    """Execute the real acquisition in its owning task to its first await.

    A free nested guard must enter immediately; a dangerous nested wait
    must immediately raise the capacity response. If it queues instead,
    cancel that acquisition and fail a progress assertion, without using
    an elapsed-time timeout as the verdict.
    """
    iterator = guard.__aenter__().__await__()
    try:
        try:
            pending = iterator.send(None)
        except StopIteration as completed:
            return completed.value
        try:
            iterator.throw(asyncio.CancelledError())
        except (asyncio.CancelledError, StopIteration):
            pass
        pytest.fail(
            f"nested admission queued instead of entering or refusing: {pending!r}"
        )
    finally:
        iterator.close()


def capacity_response(error):
    from app.deps import ApiError

    assert isinstance(error, ApiError)
    assert (error.status_code, error.detail, error.code, error.headers) == (
        503,
        "lock capacity busy; retry shortly",
        "service_unavailable",
        {"Retry-After": "1"},
    )


def idle(registry):
    assert len(registry._locks) <= registry._max_keys
    assert all(
        entry.refs == 0 and not entry.lock.locked()
        for entry in registry._locks.values()
    )
    assert registry.total_overflow_refs() == 0
    assert not registry._held
    assert all(
        shard.owner is None and not shard.lock.locked()
        for shard in registry._overflow_shards
    )


async def checkpoint(event, *tasks):
    """Propagate actor errors instead of hiding them behind an event wait."""
    waiter = asyncio.create_task(event.wait())
    try:
        done, _ = await asyncio.wait(
            [waiter, *tasks], return_when=asyncio.FIRST_COMPLETED
        )
        for task in tasks:
            if task in done:
                await task
                assert event.is_set(), (
                    "actor ended before its required progress checkpoint"
                )
    finally:
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


def test_same_task_colliding_therapist_and_patient_guards_preserve_outer_custody():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks()
        first, second = colliding_pair(registry)
        async with fill_native_registry(registry):
            async with registry.hold(first) as outer:
                nested = registry.hold(second)
                assert enter_without_queue(nested) is outer
                assert registry.total_overflow_refs() == 2
                assert outer.locked()
                await nested.__aexit__(None, None, None)
                assert outer.locked() and registry.total_overflow_refs() == 1
            assert registry.total_overflow_refs() == 0
        idle(registry)

    asyncio.run(exercise())


def test_ordered_cross_task_shard_cycle_refuses_both_nested_waits_and_can_retry():
    async def exercise():
        from app.deps import ApiError
        from app.locks import UserLocks

        registry = UserLocks()
        first, middle, last = ordered_cycle(registry)
        ready = [asyncio.Event(), asyncio.Event()]
        refused = [asyncio.Event(), asyncio.Event()]
        attempt, release = asyncio.Event(), asyncio.Event()
        failures = []

        async def actor(index, own, wanted):
            async with registry.hold(own):
                ready[index].set()
                await attempt.wait()
                try:
                    with pytest.raises(ApiError) as failure:
                        enter_without_queue(registry.hold(wanted))
                    capacity_response(failure.value)
                    failures.append(index)
                finally:
                    refused[index].set()
                await release.wait()

        async with fill_native_registry(registry):
            tasks = [
                asyncio.create_task(actor(0, first, middle)),
                asyncio.create_task(actor(1, middle, last)),
            ]
            try:
                for event in ready:
                    await checkpoint(event, *tasks)
                attempt.set()
                for event in refused:
                    await checkpoint(event, *tasks)
                assert (
                    sorted(failures) == [0, 1] and registry.total_overflow_refs() == 2
                )
                release.set()
                await asyncio.gather(*tasks)
                async with registry.hold(first):
                    nested = registry.hold(middle)
                    enter_without_queue(nested)
                    await nested.__aexit__(None, None, None)
            finally:
                release.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        idle(registry)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "direction", ["dedicated-to-overflow", "overflow-to-dedicated"]
)
def test_mixed_native_dedicated_and_overflow_contention_refuses_before_wait(direction):
    async def exercise():
        from app.deps import ApiError
        from app.locks import UserLocks

        registry = UserLocks()
        overflow_key = key("patient")
        entered, release, refused = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async with fill_native_registry(registry) as dedicated_keys:

            async def owner():
                async with registry.hold(overflow_key):
                    entered.set()
                    if direction == "overflow-to-dedicated":
                        try:
                            with pytest.raises(ApiError) as failure:
                                enter_without_queue(registry.hold(dedicated_keys[0]))
                            capacity_response(failure.value)
                        finally:
                            refused.set()
                    await release.wait()

            task = asyncio.create_task(owner())
            try:
                await checkpoint(entered, task)
                if direction == "dedicated-to-overflow":
                    with pytest.raises(ApiError) as failure:
                        enter_without_queue(registry.hold(overflow_key))
                    capacity_response(failure.value)
                else:
                    await checkpoint(refused, task)
                assert registry.total_overflow_refs() == 1
            finally:
                release.set()
                await task
            # A refusal must neither poison the fallback nor retain a task.
            async with registry.hold(overflow_key):
                assert registry.total_overflow_refs() == 1
        idle(registry)

    asyncio.run(exercise())


def test_child_task_cannot_reenter_its_parents_overflow_custody():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks()
        first, second = colliding_pair(registry)
        started, entered = asyncio.Event(), asyncio.Event()

        async def child():
            started.set()
            async with registry.hold(second):
                entered.set()

        async with fill_native_registry(registry):
            async with registry.hold(first):
                task = asyncio.create_task(child())
                await checkpoint(started, task)
                assert not entered.is_set()
                assert registry.total_overflow_refs() == 2
            await task
            assert entered.is_set()
        idle(registry)

    asyncio.run(exercise())


@pytest.mark.parametrize("fault", ["cancel-waiter", "cancel-owner", "body-error"])
def test_native_overflow_faults_release_references_owner_state_and_kernel_guard(fault):
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks()
        name = key("patient")
        started, entered, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def owner():
            async with registry.hold(name):
                entered.set()
                await release.wait()

        async def waiter():
            started.set()
            async with registry.hold(name):
                pytest.fail("cancelled waiter must not enter the held critical section")

        async with fill_native_registry(registry):
            if fault == "body-error":
                with pytest.raises(ValueError, match="actual-body-fault"):
                    async with registry.hold(name):
                        raise ValueError("actual-body-fault")
            else:
                task = asyncio.create_task(owner())
                try:
                    await checkpoint(entered, task)
                    if fault == "cancel-waiter":
                        pending = asyncio.create_task(waiter())
                        await checkpoint(started, pending)
                        assert registry.total_overflow_refs() == 2
                        pending.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await pending
                        assert registry.total_overflow_refs() == 1
                        release.set()
                        await task
                    else:
                        task.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await task
                finally:
                    release.set()
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            assert registry.total_overflow_refs() == 0
            async with registry.hold(name):
                assert registry.total_overflow_refs() == 1
        idle(registry)

    asyncio.run(exercise())


@pytest.mark.parametrize("resource", ["overflow", "dedicated"])
def test_native_waiter_handoff_is_busy_even_while_the_physical_lock_is_unlocked(
    monkeypatch, resource
):
    async def exercise():
        from app.deps import ApiError
        from app.locks import UserLocks

        registry = UserLocks()
        dedicated_name, overflow_name = key(), key("patient")
        dedicated_guard = registry.hold(dedicated_name)
        dedicated_lock = enter_without_queue(dedicated_guard)
        dedicated_open = True
        started, entered, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        probes = []
        task = None
        try:
            async with fill_native_registry(registry):
                overflow_guard = registry.hold(overflow_name)
                overflow_lock = enter_without_queue(overflow_guard)
                overflow_open = True
                requested = overflow_name if resource == "overflow" else dedicated_name
                physical = overflow_lock if resource == "overflow" else dedicated_lock
                real_release = physical.release
                armed = True

                def observed_release():
                    nonlocal armed
                    real_release()
                    if armed:
                        armed = False
                        assert not physical.locked(), (
                            "observe the real queued-handoff gap"
                        )
                        with pytest.raises(ApiError) as failure:
                            enter_without_queue(registry.hold(requested))
                        capacity_response(failure.value)
                        probes.append(failure.value.status_code)

                async def waiter():
                    started.set()
                    async with registry.hold(requested) as actual:
                        assert actual is physical
                        entered.set()
                        await release.wait()

                monkeypatch.setattr(physical, "release", observed_release)
                task = asyncio.create_task(waiter())
                try:
                    await checkpoint(started, task)
                    assert not entered.is_set()
                    if resource == "overflow":
                        await overflow_guard.__aexit__(None, None, None)
                        overflow_open = False
                    else:
                        await dedicated_guard.__aexit__(None, None, None)
                        dedicated_open = False
                    await checkpoint(entered, task)
                    assert probes == [503]
                    release.set()
                    await task
                finally:
                    release.set()
                    if task is not None:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    if overflow_open:
                        await overflow_guard.__aexit__(None, None, None)
        finally:
            if dedicated_open:
                await dedicated_guard.__aexit__(None, None, None)
        idle(registry)

    asyncio.run(exercise())


def test_dedicated_ordered_nesting_still_queues_and_preserves_exclusion():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks()
        first, second = sorted([key(), key()])
        owner_entered, release_owner, nested_started, nested_entered = (
            asyncio.Event() for _ in range(4)
        )

        async def owner():
            async with registry.hold(second):
                owner_entered.set()
                await release_owner.wait()

        async def ordered():
            async with registry.hold(first):
                nested_started.set()
                async with registry.hold(second):
                    nested_entered.set()

        one = asyncio.create_task(owner())
        await checkpoint(owner_entered, one)
        two = asyncio.create_task(ordered())
        try:
            await checkpoint(nested_started, two)
            assert not nested_entered.is_set()
            release_owner.set()
            await asyncio.gather(one, two)
            assert nested_entered.is_set()
        finally:
            release_owner.set()
            one.cancel()
            two.cancel()
            await asyncio.gather(one, two, return_exceptions=True)
        idle(registry)

    asyncio.run(exercise())


def test_idle_native_dedicated_entry_is_usable_while_the_task_owns_overflow():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks()
        dedicated_name = key()
        dedicated_guard = registry.hold(dedicated_name)
        original = enter_without_queue(dedicated_guard)
        dedicated_open = True
        try:
            async with (
                fill_native_registry(registry),
                registry.hold(key("patient")) as fallback,
            ):
                await dedicated_guard.__aexit__(None, None, None)
                dedicated_open = False
                reused = registry.hold(dedicated_name)
                assert enter_without_queue(reused) is original
                assert original.locked() and fallback.locked()
                await reused.__aexit__(None, None, None)
                assert not original.locked() and fallback.locked()
        finally:
            if dedicated_open:
                await dedicated_guard.__aexit__(None, None, None)
        idle(registry)

    asyncio.run(exercise())


def test_native_live_overflow_key_cannot_split_after_a_dedicated_slot_becomes_idle():
    async def exercise():
        from app.locks import UserLocks

        registry = UserLocks()
        dedicated_guard = registry.hold(key())
        enter_without_queue(dedicated_guard)
        dedicated_open = True
        name = key("patient")
        started, entered, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        task = None

        async def contender():
            started.set()
            async with registry.hold(name):
                entered.set()
                await release.wait()

        try:
            async with fill_native_registry(registry):
                async with registry.hold(name):
                    await dedicated_guard.__aexit__(None, None, None)
                    dedicated_open = False
                    task = asyncio.create_task(contender())
                    try:
                        await checkpoint(started, task)
                        assert not entered.is_set(), (
                            "an idle slot must not split live fallback custody"
                        )
                        assert registry.total_overflow_refs() == 2
                    except BaseException:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                        raise
                await checkpoint(entered, task)
                release.set()
                await task
        finally:
            release.set()
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if dedicated_open:
                await dedicated_guard.__aexit__(None, None, None)
        idle(registry)

    asyncio.run(exercise())


def test_native_capacity_refusal_has_the_real_http_retry_envelope():
    async def exercise():
        from app.config import Settings
        from app.locks import UserLocks
        from app.main import create_app
        from httpx import ASGITransport, AsyncClient

        registry = UserLocks()
        first, middle, _ = ordered_cycle(registry)
        entered, release = asyncio.Event(), asyncio.Event()
        app = create_app(
            Settings(environment="development", database_url="sqlite+aiosqlite://")
        )

        @app.get("/lock-capacity-contract")
        async def nested_request():
            async with registry.hold(first), registry.hold(middle):
                return {"entered": True}

        async def owner():
            async with registry.hold(middle):
                entered.set()
                await release.wait()

        try:
            async with fill_native_registry(registry):
                task = asyncio.create_task(owner())
                try:
                    await checkpoint(entered, task)
                    async with AsyncClient(
                        transport=ASGITransport(app=app), base_url="http://testserver"
                    ) as client:
                        response = await client.get("/lock-capacity-contract")
                    assert response.status_code == 503
                    assert response.json() == {
                        "detail": "lock capacity busy; retry shortly",
                        "code": "service_unavailable",
                    }
                    assert response.headers["Retry-After"] == "1"
                finally:
                    release.set()
                    await task
        finally:
            await app.state.engine.dispose()
        idle(registry)

    asyncio.run(exercise())
