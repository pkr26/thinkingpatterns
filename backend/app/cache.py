"""Bounded in-process rate limiting and token-revocation storage.

The deployment serves one process per database; multiple workers would
split counters and revocation state. Rate-limit hits use a monotonic clock
and sliding expiry. Per-key timestamp compression and capped key eviction
bound memory under identity floods; their tradeoffs are documented below.
"""

from __future__ import annotations

import heapq
import ipaddress
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from .deps import ApiError

# Cap identity cardinality. Eviction prefers stale keys, then the oldest
# active windows; evicting an active key resets its budget early. This is
# the bounded-memory tradeoff under an identity flood.
MAX_TRACKED_KEYS = 50_000

# Eviction runs when the cap is crossed and clears down to the cap minus
# this batch: the O(n) stale-scan under the lock is paid once per batch of
# over-cap hits instead of on every single hit (the counter is touched on
# the event loop's request path, so per-hit full scans add latency).
EVICTION_BATCH = MAX_TRACKED_KEYS // 10

# Cap distinct timestamps per key. Overflow merges the oldest two entries
# at the older timestamp, preserving their total until that timestamp
# expires. The newer merged hit can consequently expire early; callers
# should treat compression as a bounded-memory approximation.
_MAX_LOG_ENTRIES = 128


@dataclass
class _WindowLog:
    """One key's retained hits: (timestamp, count) pairs, oldest first.

    ``window_seconds`` is bookkeeping the eviction path uses to judge
    idleness without a live call; hit() rewrites it on every hit. A key's
    count is the exact sum of retained entries; timestamp compression
    determines when a merged group expires.
    """

    window_seconds: int
    log: deque[tuple[float, int]] = field(default_factory=deque)
    total: int = 0

    def last_activity(self) -> float:
        return self.log[-1][0]

    def oldest_activity(self) -> float:
        return self.log[0][0]


@dataclass(frozen=True)
class HitResult:
    count: int
    retry_after: int  # seconds until this window resets (>= 1 while limited)


class SlidingWindowCounter:
    """Per-key sliding windows measured with a monotonic clock.

    Each hit/check supplies its window length. The stored length helps
    eviction identify idle keys; bucket prefixes normally use a consistent
    setting. Retry-After reports when the oldest retained group expires.
    """

    def __init__(self) -> None:
        self._hits: dict[str, _WindowLog] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, window_seconds: int, now: float | None = None) -> HitResult:
        """Record one hit; return the window count and a usable Retry-After."""
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        # Wall-clock corrections must not alter elapsed rate-limit windows.
        current = now if now is not None else time.monotonic()
        with self._lock:
            state = self._hits.get(key)
            if state is None:
                state = _WindowLog(window_seconds=window_seconds)
                self._hits[key] = state
            state.window_seconds = window_seconds
            self._prune_locked(state, current, window_seconds)
            if state.log and state.log[-1][0] == current:
                stamp, count = state.log.pop()
                state.log.append((stamp, count + 1))
            else:
                state.log.append((current, 1))
            if len(state.log) > _MAX_LOG_ENTRIES:
                # Preserve the count while bounding retained timestamps.
                oldest_timestamp, oldest_count = state.log.popleft()
                _, next_count = state.log.popleft()
                state.log.appendleft((oldest_timestamp, oldest_count + next_count))
            state.total += 1
            if len(self._hits) > MAX_TRACKED_KEYS:
                self._evict_locked(current)
            retry_after = self._retry_after_locked(state, current, window_seconds)
            return HitResult(count=state.total, retry_after=retry_after)

    def check(self, key: str, window_seconds: int, now: float | None = None) -> HitResult:
        """Read the current count WITHOUT recording a hit.

        Used by the REGISTER per-username buckets (``register-name:...``):
        the check must not count the request (only *actual conflicts* count),
        so garbage probes for a victim's name cannot anonymously lock the
        real user out of registering it. Login is deliberately IP-only —
        there is no login per-username bucket anywhere (a keyed login deny
        bucket would make a distributed attacker a trivial lockout lever
        against any victim's name).
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        current = now if now is not None else time.monotonic()
        with self._lock:
            state = self._hits.get(key)
            if state is None:
                return HitResult(count=0, retry_after=1)
            self._prune_locked(state, current, window_seconds)
            retry_after = self._retry_after_locked(state, current, window_seconds)
            return HitResult(count=state.total, retry_after=retry_after)

    @staticmethod
    def _prune_locked(state: _WindowLog, now: float, window_seconds: int) -> None:
        # Age out every entry whose instant left the sliding window. The
        # boundary is >=: a hit exactly ``window`` old no longer counts
        # (matches the fixed-window contract at exact elapsed windows).
        log = state.log
        total = state.total
        while log and now - log[0][0] >= window_seconds:
            total -= log.popleft()[1]
        state.total = total

    @staticmethod
    def _retry_after_locked(state: _WindowLog, now: float, window_seconds: int) -> int:
        if not state.log:
            return 1
        return max(1, int(state.oldest_activity() + window_seconds - now) + 1)

    def _evict_locked(self, now: float) -> None:
        # 2026-09-26 audit item 3: prefer reclaiming buckets that are IDLE
        # beyond their own window — such a key cannot influence any future
        # count, so dropping it is free. Only when the stale sweep is not
        # enough do ACTIVE keys go, smallest total first then oldest
        # activity, in one batch down to MAX_TRACKED_KEYS - EVICTION_BATCH
        # so the next batch of over-cap hits does not each pay a full scan.
        # An attacker rotating identities mints thousands of single-hit
        # buckets; a real user's multi-hit bucket must be the LAST active
        # key evicted (evicting by activity alone let 10k fresh garbage keys
        # reset a victim's count mid-window). Uses the same clock the hits
        # were recorded under — a synthetic now from hit(now=...) must not
        # be judged against wall-clock time.
        stale = [
            k
            for k, state in self._hits.items()
            if not state.log or now - state.last_activity() >= state.window_seconds
        ]
        for k in stale:
            del self._hits[k]
        overflow = len(self._hits) - (MAX_TRACKED_KEYS - EVICTION_BATCH)
        if overflow > 0:
            victims = heapq.nsmallest(
                overflow,
                self._hits,
                key=lambda k: (self._hits[k].total, self._hits[k].last_activity()),
            )
            for k in victims:
                del self._hits[k]


def _aggregate_host(host: str) -> str:
    """Aggregate an IPv6 address to its /64.

    A single device can rotate through 2^64 addresses inside its /64; without
    aggregation every request gets a fresh rate-limit bucket and the per-IP
    limit is decorative against IPv6. Non-IP and IPv4 hosts pass through.
    """
    if ":" not in host:
        return host
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version != 6:
        return host
    return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address) + "/64"


def client_key(request: Request, trust_proxy_headers: bool = False) -> str | None:
    """Best-effort client identity for rate limiting (FastAPI call sites).

    Reads the request's ``state``/``client`` attributes directly (rather
    than delegating through ``request.scope``) because call sites — and the
    suite's duck-typed request doubles — promise exactly those two fields.
    :func:`client_key_from_scope` implements the same rules over a raw ASGI
    scope for the middleware's pre-dispatch gate; the two are pinned
    to agree by test.

    Behind a reverse proxy every request appears to come from the proxy's
    IP. Forwarding metadata is used only when HardeningMiddleware has
    established that the direct socket peer belongs to the explicit
    MINDPATTERN_TRUSTED_PROXY_IPS allowlist, which it records as
    ``state.mindpattern_trusted_proxy`` plus the sanitized
    ``state.mindpattern_forwarded_client`` address. This function
    intentionally never treats a raw X-Forwarded-For header as proof: a
    direct client can freely forge one.

    2026-09-26 audit item 5: a transport that exposes NO socket peer used to
    fold every request into one shared "unknown-client" bucket — a single
    client could 429 that entire surface for everyone. There is no honest
    identity to rate limit by in that case, and a per-request unique id
    would be fail-OPEN (the limiter would never bind), so the identity is
    reported as UNAVAILABLE (None) and every consumer refuses the request
    (429) instead: fail closed, loudly, matching the module's philosophy.
    A correct deployment always has a TCP peer (uvicorn populates it); a
    socketless frontend is a topology bug this surfaces instead of silently
    degrading either availability or the limits.
    """
    if trust_proxy_headers and getattr(request.state, "mindpattern_trusted_proxy", False):
        forwarded = getattr(request.state, "mindpattern_forwarded_client", None)
        if isinstance(forwarded, str) and forwarded:
            return _aggregate_host(forwarded)
    if request.client and request.client.host:
        return _aggregate_host(request.client.host)
    return None


def client_key_from_scope(
    scope: Mapping[str, Any], trust_proxy_headers: bool = False
) -> str | None:
    """The same identity :func:`client_key` computes, from a raw ASGI scope.

    HardeningMiddleware needs the rate-limit key BEFORE the request enters
    the app (see middleware.py's malformed-body counting): at that point
    there is no ``Request`` wrapper yet, but the middleware itself has
    already recorded the proxy-trust decision and the sanitized forwarded
    address in ``scope["state"]`` — exactly the fields ``client_key`` reads
    through ``request.state`` — so both paths MUST agree on the key or the
    edge counter and the dependency counter would silently split buckets.
    Returns None under the same no-peer condition as ``client_key``
    (audit item 5): callers refuse rather than share one bucket.
    """
    state = scope.get("state") or {}
    if trust_proxy_headers and state.get("mindpattern_trusted_proxy"):
        forwarded = state.get("mindpattern_forwarded_client")
        if isinstance(forwarded, str) and forwarded:
            return _aggregate_host(forwarded)
    client = scope.get("client")
    if client and client[0]:
        return _aggregate_host(client[0])
    return None


def _limit_response(retry_after: int) -> HTTPException:
    return ApiError(
        status_code=429,
        detail="rate limit exceeded",
        code="rate_limited",
        headers={"Retry-After": str(max(1, retry_after))},
    )


def _no_identity_response() -> HTTPException:
    """429 for a request whose rate-limit identity does not exist (item 5).

    Same envelope family as _limit_response so clients branch identically;
    the detail names the cause so an operator running a socketless frontend
    sees the topology problem in logs instead of debugging silence.
    """
    return ApiError(
        status_code=429,
        detail="no client identity available for rate limiting",
        code="rate_limited",
    )


class RateLimitCheck:
    """The dependency ``make_rate_limiter`` returns, as a callable object.

    Carrying the (bucket, limit_attr, window_attr) spec as ATTRIBUTES (rather
    than burying it in closure cells) lets app wiring enumerate every
    rate-limited route and its bucket at build time — the input
    HardeningMiddleware needs to count malformed-JSON 422s into the same
    buckets the route dependencies use (M-1, 2026-09-20). Pure bookkeeping:
    the runtime behavior is the check below, unchanged.
    """

    def __init__(self, bucket: str, limit_attr: str, window_attr: str) -> None:
        self.bucket = bucket
        self.limit_attr = limit_attr
        self.window_attr = window_attr

    async def __call__(self, request: Request) -> None:
        settings = request.app.state.settings
        limit = getattr(settings, self.limit_attr)
        window = getattr(settings, self.window_attr)
        counter: SlidingWindowCounter = request.app.state.rate_counter
        key = client_key(request, trust_proxy_headers=settings.trust_proxy_headers)
        if key is None:
            raise _no_identity_response()
        result = counter.hit(f"{self.bucket}:{key}", window)
        if result.count > limit:
            raise _limit_response(result.retry_after)


def make_rate_limiter(bucket: str, limit_attr: str, window_attr: str) -> RateLimitCheck:
    """Dependency factory: 429 once the limit (read from settings at request
    time, so tests and deployment config can tune it) is hit within the window."""
    return RateLimitCheck(bucket, limit_attr, window_attr)


def check_keyed_limit_without_count(request: Request, key: str, limit: int, window: int) -> None:
    """429 once the key has reached its limit, without counting this request.

    Paired with record_keyed_failure() on the REGISTER path (the
    ``register-name:...`` buckets in auth.py and therapist.py): only ACTUAL
    conflicts — the 409 "username already taken" answers — consume the
    bucket, so an anonymous attacker spraying garbage or taken-name probes
    cannot 429 the legitimate first registrant of a free name. Login needs
    no such helper: it is deliberately IP-only.
    """
    counter: SlidingWindowCounter = request.app.state.rate_counter
    result = counter.check(key, window)
    # Unlike ``make_rate_limiter()``, the failing action is recorded *after*
    # this preflight.  ``> limit`` therefore admitted one extra conflict:
    # for a limit of three, counts 1..4 were recorded and only the FIFTH
    # conflicting request was rejected (it observed count 4 > 3).  At ``count == limit`` the budget is
    # exhausted, so reject before doing another expensive verifier hash.
    if result.count >= limit:
        raise _limit_response(result.retry_after)


def record_keyed_failure(request: Request, key: str, window: int) -> None:
    """Count one failure against a keyed bucket (see above)."""
    counter: SlidingWindowCounter = request.app.state.rate_counter
    counter.hit(key, window)


# --- single-token revocation (2026-09-26 remediation wave) ----------------------
#
# Logout now kills ONLY the presented token: its 128-bit ``jti`` is recorded
# here with a ttl equal to the token's own expiry, and deps.require_user
# refuses any bearer whose jti is resident. The account-wide epoch bump
# remains the GLOBAL revocation primitive (credential rotation, deletion).
# In-process by the same standing as the rate counter and the processing
# keystore: exact for the single-process deployment topology this server
# documents (one host per database, enforced at boot); a multi-host
# deployment must move the table to shared state along with those.
#
# Wall-clock TTLs on purpose: a revoked jti must expire exactly when its
# token does (``exp`` is wall-clock), and the store is pruned lazily on
# every mutation plus a size cap with oldest-expiry eviction so an
# attacker spamming logout on minted tokens cannot grow it unboundedly
# (every revocation requires a VALID bearer, so growth is bounded by
# legitimate logins per 24h in practice).

MAX_TRACKED_REVOCATIONS = 100_000


class TokenRevocationStore:
    """In-memory jti -> expiry map; membership means "this token was
    logged out and is dead until its own exp passes"."""

    def __init__(self, max_entries: int = MAX_TRACKED_REVOCATIONS) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._by_expiry: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries
        # Independent audit 2026-09-27: set the first time the cap forces an
        # eviction. Before that moment the in-memory map is provably a
        # complete mirror of the durable table (boot hydration + insert on
        # every revoke), so a miss is authoritative "not revoked" with no
        # database round-trip. Once entries have been evicted, a miss is
        # ambiguous and is_revoked_checked falls back to a point query.
        self._overflowed = False
        self._hydrated = False

    def revoke(self, jti: str, expires_at_epoch: float, now: float | None = None) -> None:
        """Record one revoked token id until its expiry.

        A jti whose token already expired is accepted and immediately
        prunable — harmless, and keeps the logout path branch-free."""
        if not jti:
            raise ValueError("jti must be non-empty")
        current = now if now is not None else time.time()
        with self._lock:
            self._prune_locked(current)
            self._by_expiry[jti] = max(expires_at_epoch, current)
            if len(self._by_expiry) > self._max_entries:
                # Oldest expiry first: those entries are closest to freeing
                # themselves anyway, so eviction loses the least future
                # protection per dropped entry.
                overflow = len(self._by_expiry) - self._max_entries
                for oldest in sorted(self._by_expiry, key=self._by_expiry.__getitem__)[:overflow]:
                    del self._by_expiry[oldest]
                self._overflowed = True

    def is_revoked(self, jti: str | None, now: float | None = None) -> bool:
        """Membership check for a (possibly legacy, jti-less) token."""
        if not jti:
            return False
        current = now if now is not None else time.time()
        with self._lock:
            expiry = self._by_expiry.get(jti)
            if expiry is None:
                return False
            if current >= expiry:
                del self._by_expiry[jti]
                return False
            return True

    def _prune_locked(self, now: float) -> int:
        expired = [jti for jti, exp in self._by_expiry.items() if now >= exp]
        for jti in expired:
            del self._by_expiry[jti]
        return len(expired)

    def prune(self, now: float | None = None) -> int:
        """Drop every entry past its expiry (observability/tests)."""
        with self._lock:
            return self._prune_locked(now if now is not None else time.time())

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked(time.time())
            return len(self._by_expiry)

    # --- durable backing (independent audit 2026-09-27) -----------------------
    #
    # The in-process map died with the process: a deploy or crash emptied
    # it and every logged-out bearer resurrected until its own exp. The
    # table-backed methods below keep the in-memory map as a cache (no DB
    # round-trip per request) while making the revocation itself durable:
    # logout writes through, boot re-hydrates, and once the cap has evicted
    # entries the checked lookup falls back to a point query so eviction
    # pressure can never resurrect a token either.

    async def revoke_durable(self, session, jti: str, expires_at_epoch: float) -> None:
        """Write the revocation to the durable table AND the memory cache.

        Called inside the logout lifecycle fence; the caller commits.
        ``merge`` (SELECT-then-INSERT/UPDATE) is dialect-neutral and makes
        a double logout of the same bearer idempotent — the second merge
        refreshes the same row instead of colliding on the primary key.
        """
        from .models import TokenRevocation

        self.revoke(jti, expires_at_epoch)
        expires_at = datetime.fromtimestamp(expires_at_epoch, tz=timezone.utc)
        await session.merge(TokenRevocation(jti=jti, expires_at=expires_at))
        await session.flush()

    async def hydrate(self, session, now: float | None = None) -> int:
        """Load every unexpired durable revocation into memory (boot path).

        Newest-expiry-first under the cap: if the table somehow outgrew the
        cache, the entries with the longest remaining life win. Returns the
        number loaded (observability + tests).
        """
        from sqlalchemy import select

        from .models import TokenRevocation

        current = now if now is not None else time.time()
        cutoff = datetime.fromtimestamp(current, tz=timezone.utc)
        rows = (
            (
                await session.execute(
                    select(TokenRevocation)
                    .where(TokenRevocation.expires_at > cutoff)
                    .order_by(TokenRevocation.expires_at.desc())
                    .limit(self._max_entries)
                )
            )
            .scalars()
            .all()
        )
        with self._lock:
            self._prune_locked(current)
            for row in rows:
                self._by_expiry[row.jti] = row.expires_at.timestamp()
            # 2026-09-28 audit L-1: a table larger than the cap truncates
            # the hydration — the loaded map is then NOT a complete mirror,
            # so a memory miss must fall back to the durable point query
            # exactly as it does after a runtime eviction. Without this
            # flag a boot-time truncation silently honored revoked tokens
            # that did not fit the newest-expiry-first window.
            if len(rows) == self._max_entries:
                self._overflowed = True
            self._hydrated = True
            return len(rows)

    async def is_revoked_checked(self, session, jti: str | None, now: float | None = None) -> bool:
        """Revocation check that stays exact once the cache has evicted.

        Memory hit -> revoked. Memory miss while the cache has never
        overflowed -> authoritative not-revoked (the map mirrors the table
        completely). Miss after an eviction -> point query, so an attacker
        who pressures the cap cross-tenant cannot push a victim's
        revocation out of memory and have it honored as "not revoked".
        """
        if not jti:
            return False
        if self.is_revoked(jti, now=now):
            return True
        with self._lock:
            overflowed = self._overflowed
            hydrated = self._hydrated
        if hydrated and not overflowed:
            return False
        from sqlalchemy import select

        from .models import TokenRevocation

        current_dt = datetime.fromtimestamp(
            now if now is not None else time.time(), tz=timezone.utc
        )
        row = (
            await session.execute(
                select(TokenRevocation.jti).where(
                    TokenRevocation.jti == jti, TokenRevocation.expires_at > current_dt
                )
            )
        ).first()
        return row is not None
