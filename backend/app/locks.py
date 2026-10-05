"""Bounded per-user asyncio locks shared across API routers.

Locks serialize quota checks, recomputations, consent changes, and other
read-modify-write operations within the single-process deployment.
"""

from __future__ import annotations

import asyncio
import zlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from .deps import ApiError


@dataclass
class _LockEntry:
    lock: asyncio.Lock
    refs: int = 0


# Full registries use stable hash shards so one overflow queue cannot stall
# every unrelated user. The same key always selects the same shard.
OVERFLOW_SHARDS = 16


@dataclass
class _OverflowShard:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    refs: int = 0
    owner: asyncio.Task | None = None


@dataclass
class _HeldLocks:
    dedicated: int = 0
    overflow: int = 0


def _capacity_busy() -> ApiError:
    return ApiError(
        status_code=503,
        detail="lock capacity busy; retry shortly",
        code="service_unavailable",
        headers={"Retry-After": "1"},
    )


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
        # splitting a key's critical section. New keys fall back to their
        # SHARD's lock until that shard's users drain; that preserves
        # correctness AND the hard registry cap, at the cost of temporary
        # serialization within one shard under an adversarial unique-key
        # flood (see OVERFLOW_SHARDS).
        self._overflow_shards = tuple(_OverflowShard() for _ in range(OVERFLOW_SHARDS))
        # Only successful acquisitions retain task state; waiting and cancelled
        # callers cannot leave an idle task in this registry.
        self._held: dict[asyncio.Task, _HeldLocks] = {}

    def _shard_for(self, key: str) -> _OverflowShard:
        # crc32: a stable, process-independent mapping (str hash() is
        # per-process randomized); stability only matters WITHIN the process
        # lifetime of this registry, but determinism also keeps the mapping
        # observable in tests.
        return self._overflow_shards[zlib.crc32(key.encode("utf-8")) % OVERFLOW_SHARDS]

    def total_overflow_refs(self) -> int:
        """Live fallback holders across all shards (observability/tests)."""
        return sum(shard.refs for shard in self._overflow_shards)

    @asynccontextmanager
    async def hold(self, key: str) -> AsyncIterator[asyncio.Lock]:
        task = asyncio.current_task()
        assert task is not None
        held = self._held.get(task)
        entry = self._locks.get(key)
        use_overflow = False
        shard: _OverflowShard | None = None
        if entry is None:
            shard = self._shard_for(key)
            # Once a key's shard has a live fallback user, keep that key on
            # the SAME shard lock until it drains. Otherwise the key could
            # gain a fresh dedicated lock while a prior holder still uses the
            # shard fallback, violating serialization for that key. Distinct
            # keys never share a fallback unless they hash to the same shard
            # (which is still correct — the fallback is a real exclusion
            # lock — just briefly coarser).
            if shard.refs:
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
            assert shard is not None
            # Logical therapist/patient ordering does not order hash shards.
            # A nested wait on a foreign shard could close a physical lock
            # cycle. Refuse before waiting, including the queued-handoff window
            # where lock.locked() is false but live references remain.
            if held is not None and shard.refs and shard.owner is not task:
                raise _capacity_busy()
            shard.refs += 1
            try:
                if shard.owner is task:
                    # Different logical keys may share this physical lock.
                    # The outer context retains custody for the entire nest.
                    yield shard.lock
                    return
                async with shard.lock:
                    shard.owner = task
                    if held is None:
                        held = _HeldLocks()
                        self._held[task] = held
                    held.overflow += 1
                    try:
                        yield shard.lock
                    finally:
                        held.overflow -= 1
                        if not held.dedicated and not held.overflow:
                            del self._held[task]
                        shard.owner = None
            finally:
                shard.refs -= 1
            return
        # `entry` is non-None here: an absent key either became a dedicated
        # entry above or returned through the overflow branch.
        assert entry is not None
        # Mixed dedicated/overflow cycles are possible too. An overflow owner
        # may take an idle dedicated lock, but cannot wait behind its holder.
        if held is not None and held.overflow and entry.refs:
            raise _capacity_busy()
        entry.refs += 1
        try:
            async with entry.lock:
                if held is None:
                    held = _HeldLocks()
                    self._held[task] = held
                held.dedicated += 1
                try:
                    yield entry.lock
                finally:
                    held.dedicated -= 1
                    if not held.dedicated and not held.overflow:
                        del self._held[task]
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
