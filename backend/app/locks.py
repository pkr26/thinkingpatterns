"""Per-user asyncio locks shared across routers.

Entries serialize quota-check + insert; insights serialize recompute
read-modify-write. Both need the same bounded per-user lock registry, which
used to live (private) inside the entries router — insights imported a
private name across module boundaries. This module is the shared home.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


class UserLocks:
    """Per-user asyncio locks serializing check-then-write sequences.

    Without them, e.g. the storage quota is a check-then-insert race: N
    concurrent creates each observe quota-N free and all commit, overshooting
    both the entry count and the byte total. The deployment is
    single-process per instance (documented in the README), so an in-process
    lock is the authority; the registry is bounded and only idle entries are
    recycled.

    "Idle" is tracked by a refcount, not by lock.locked(): between a
    release() and a waiter's re-acquire a lock reports locked() == False,
    so evicting on locked() alone could drop a lock a waiter is parked on
    — orphaning that waiter while the next get() mints a second lock for
    the same key. The refcount is incremented synchronously (no await)
    before the caller blocks on acquire, closing that window.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        # key -> [lock, live holders+waiters]
        self._locks: dict[str, list] = {}
        self._max_keys = max_keys

    @asynccontextmanager
    async def hold(self, key: str) -> AsyncIterator[asyncio.Lock]:
        entry = self._locks.get(key)
        if entry is None:
            if len(self._locks) >= self._max_keys:
                for stale in [
                    k for k, v in self._locks.items() if v[1] == 0
                ][: len(self._locks) - self._max_keys + 1]:
                    del self._locks[stale]
            entry = [asyncio.Lock(), 0]
            self._locks[key] = entry
        entry[1] += 1
        try:
            async with entry[0]:
                yield entry[0]
        finally:
            entry[1] -= 1
