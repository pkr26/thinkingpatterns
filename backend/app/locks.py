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
from dataclasses import dataclass


@dataclass
class _LockEntry:
    lock: asyncio.Lock
    refs: int = 0


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
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        # key -> dedicated lock plus live holder/waiter count.
        self._locks: dict[str, _LockEntry] = {}
        self._max_keys = max_keys
        # When every per-key entry is live we cannot evict one without
        # splitting a key's critical section. New keys share this fallback
        # lock until its users drain; that preserves correctness AND the hard
        # registry cap, at the cost of temporary serialization under an
        # adversarial unique-key flood.
        self._overflow_lock = asyncio.Lock()
        self._overflow_refs = 0

    @asynccontextmanager
    async def hold(self, key: str) -> AsyncIterator[asyncio.Lock]:
        entry = self._locks.get(key)
        use_overflow = False
        if entry is None:
            # Once any fallback user is live, keep ALL absent keys on that
            # same lock until it drains. Otherwise an overflow key could gain
            # a fresh dedicated lock while a prior holder still uses the
            # fallback, violating serialization for that key.
            if self._overflow_refs:
                use_overflow = True
            elif len(self._locks) >= self._max_keys:
                for stale in [k for k, v in self._locks.items() if v.refs == 0][
                    : len(self._locks) - self._max_keys + 1
                ]:
                    del self._locks[stale]
                if len(self._locks) >= self._max_keys:
                    use_overflow = True
            if not use_overflow:
                entry = _LockEntry(asyncio.Lock())
                self._locks[key] = entry
        if use_overflow:
            self._overflow_refs += 1
            try:
                async with self._overflow_lock:
                    yield self._overflow_lock
            finally:
                self._overflow_refs -= 1
            return
        # `entry` is non-None here: an absent key either became a dedicated
        # entry above or returned through the overflow branch.
        assert entry is not None
        entry.refs += 1
        try:
            async with entry.lock:
                yield entry.lock
        finally:
            entry.refs -= 1


# Cross-router lifecycle fence for operations that can cause plaintext to
# leave the process. Insights holds it from the fresh consent read through
# any external LLM dispatch; withdrawal/deletion holds it while revoking.
# That makes the consent boundary linearizable rather than relying on a
# stale ORM object loaded by authentication earlier in the request.
lifecycle_locks = UserLocks()

# Sharing has a separate lifecycle: a patient can revoke a therapist's
# access while that therapist is fetching encrypted journal material.  The
# sharing routers take a patient key while they re-check consent and assemble
# a response, so a revoke/account deletion and a content read linearize at
# one explicit boundary instead of returning data from a stale consent row.
# Therapist-facing reads additionally take a therapist key first, which lets
# therapist account deletion fence all of that account's active reads without
# making unrelated patients contend with one another.
sharing_locks = UserLocks()


def sharing_therapist_lock_key(therapist_id: str) -> str:
    """Key for work scoped to one therapist's sharing account.

    Any operation that needs both sharing locks MUST acquire this key before
    :func:`sharing_patient_lock_key`; the fixed order keeps a content read,
    grant, and account deletion from forming a lock cycle.
    """
    return f"sharing-therapist:{therapist_id}"


def sharing_patient_lock_key(user_id: str) -> str:
    """Key for work scoped to one patient's shareable journal material."""
    return f"sharing-patient:{user_id}"
