"""An idle native dedicated slot must preserve unrelated-user progress."""

from __future__ import annotations

import asyncio
from pathlib import Path


def test_native_idle_slot_is_reused_before_two_new_users_share_fallback(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root))
    monkeypatch.syspath_prepend(str(root / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")

    async def exercise():
        from app.locks import UserLocks

        from tools.tests.test_backend_overflow_lock_contracts import (
            checkpoint,
            colliding_pair,
            fill_native_registry,
            idle,
            key,
        )

        registry = UserLocks()
        old = registry.hold(key())
        await old.__aenter__()
        old_open = True
        first, second = colliding_pair(registry)
        first_entered, second_started, second_entered, release = (
            asyncio.Event() for _ in range(4)
        )
        tasks = []

        async def first_user():
            async with registry.hold(first):
                first_entered.set()
                await release.wait()

        async def second_user():
            second_started.set()
            async with registry.hold(second):
                second_entered.set()
                await release.wait()

        try:
            async with fill_native_registry(registry):
                # Release a real dedicated guard; do not edit the registry or
                # its native capacity. Its idle slot can serve the first user.
                await old.__aexit__(None, None, None)
                old_open = False
                tasks.append(asyncio.create_task(first_user()))
                await checkpoint(first_entered, *tasks)
                tasks.append(asyncio.create_task(second_user()))
                await checkpoint(second_started, *tasks)
                assert second_entered.is_set(), (
                    "an available dedicated slot must prevent unnecessary "
                    "fallback serialization of these two distinct users"
                )
                release.set()
                await asyncio.gather(*tasks)
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if old_open:
                await old.__aexit__(None, None, None)
        idle(registry)

    asyncio.run(exercise())
