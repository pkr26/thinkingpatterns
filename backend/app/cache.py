"""Fixed-window rate limiting with an in-memory counter.

v1 ships the in-process counter, which is exact for the single-process
deployment the brief describes (multi-worker uvicorn would fragment every
bucket — run one worker per instance or front several instances with a
shared counter before scaling out).
"""

from __future__ import annotations

import heapq
import ipaddress
import threading
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .deps import ApiError

# Hard ceiling on tracked keys: bounds memory when an attacker rotates
# identities (spoofed XFF, IPv6). Past the cap the OLDEST windows are evicted
# even if not yet stale — worst case a few attackers' buckets reset early,
# which beats unbounded growth.
MAX_TRACKED_KEYS = 10_000

# Eviction runs when the cap is crossed and clears down to the cap minus
# this batch: the O(n) stale-scan under the lock is paid once per batch of
# over-cap hits instead of on every single hit (the counter is touched on
# the event loop's request path, so per-hit full scans add latency).
EVICTION_BATCH = MAX_TRACKED_KEYS // 10


@dataclass(frozen=True)
class HitResult:
    count: int
    retry_after: int  # seconds until this window resets (>= 1 while limited)


class FixedWindowCounter:
    """Per-key fixed windows keyed on wall-clock time.

    The window length is supplied by the CALLER on every hit()/check(); the
    window_seconds stored per key is bookkeeping the eviction path uses to
    judge staleness, and hit() rewrites it on every call. A slot's count is
    therefore judged against the window passed with the current call — in
    practice each bucket prefix uses one window from settings, so callers
    never observe a mismatch.
    """

    def __init__(self) -> None:
        self._hits: dict[
            str, tuple[int, float, int]
        ] = {}  # key -> (count, window_start, window_seconds)
        self._lock = threading.Lock()

    def hit(self, key: str, window_seconds: int, now: float | None = None) -> HitResult:
        """Record one hit; return the window count and a usable Retry-After."""
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        current = now if now is not None else time.time()
        with self._lock:
            count, start, _ = self._hits.get(key, (0, 0.0, window_seconds))
            if current - start >= window_seconds:
                count, start = 0, current
            count += 1
            self._hits[key] = (count, start, window_seconds)
            if len(self._hits) > MAX_TRACKED_KEYS:
                self._evict_oldest_locked(current)
            retry_after = max(1, int(start + window_seconds - current) + 1)
            return HitResult(count=count, retry_after=retry_after)

    def check(self, key: str, window_seconds: int, now: float | None = None) -> HitResult:
        """Read the current count WITHOUT recording a hit.

        Used by the login per-username bucket: the check must not count the
        request (only *failed verifications* count), so garbage probes for a
        victim's name cannot anonymously lock the real user out.
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        current = now if now is not None else time.time()
        with self._lock:
            count, start, _ = self._hits.get(key, (0, 0.0, window_seconds))
            if current - start >= window_seconds:
                count = 0
            retry_after = max(1, int(start + window_seconds - current) + 1)
            return HitResult(count=count, retry_after=retry_after)

    def _evict_oldest_locked(self, now: float) -> None:
        # Drop stale windows first; if still near the cap, evict among active
        # keys by smallest count then oldest start, in one batch down to
        # MAX_TRACKED_KEYS - EVICTION_BATCH so the next batch of over-cap
        # hits does not each pay a full scan. An attacker rotating identities
        # mints thousands of single-hit buckets; a real user's multi-hit
        # bucket must be the LAST active key evicted (evicting by window
        # start alone let 10k fresh garbage keys reset a victim's count
        # mid-window). Uses the same clock the hit was recorded under — a
        # synthetic now from hit(now=...) must not be judged against
        # wall-clock time.
        stale = [k for k, (_, s, w) in self._hits.items() if now - s >= w]
        for k in stale:
            del self._hits[k]
        overflow = len(self._hits) - (MAX_TRACKED_KEYS - EVICTION_BATCH)
        if overflow > 0:
            victims = heapq.nsmallest(
                overflow, self._hits, key=lambda k: (self._hits[k][0], self._hits[k][1])
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


def client_key(request: Request, trust_proxy_headers: bool = False) -> str:
    """Best-effort client identity for rate limiting.

    Behind a reverse proxy every request appears to come from the proxy's
    IP. Forwarding metadata is used only when HardeningMiddleware has
    established that the direct socket peer belongs to the explicit
    MINDPATTERN_TRUSTED_PROXY_IPS allowlist. That middleware parses the
    right-to-left forwarding chain, skips trusted proxy hops, and records a
    sanitized client address in request.state. This function intentionally
    never treats a raw X-Forwarded-For header as proof: a direct client can
    freely forge one.
    """
    if trust_proxy_headers and getattr(request.state, "mindpattern_trusted_proxy", False):
        forwarded = getattr(request.state, "mindpattern_forwarded_client", None)
        if isinstance(forwarded, str) and forwarded:
            return _aggregate_host(forwarded)
    if request.client and request.client.host:
        return _aggregate_host(request.client.host)
    return "unknown-client"


def _limit_response(retry_after: int) -> HTTPException:
    return ApiError(
        status_code=429,
        detail="rate limit exceeded",
        code="rate_limited",
        headers={"Retry-After": str(max(1, retry_after))},
    )


def make_rate_limiter(bucket: str, limit_attr: str, window_attr: str):
    """Dependency factory: 429 once the limit (read from settings at request
    time, so tests and deployment config can tune it) is hit within the window."""

    async def check(request: Request) -> None:
        settings = request.app.state.settings
        limit = getattr(settings, limit_attr)
        window = getattr(settings, window_attr)
        counter: FixedWindowCounter = request.app.state.rate_counter
        key = client_key(request, trust_proxy_headers=settings.trust_proxy_headers)
        result = counter.hit(f"{bucket}:{key}", window)
        if result.count > limit:
            raise _limit_response(result.retry_after)

    return check


def check_keyed_limit_without_count(request: Request, key: str, limit: int, window: int) -> None:
    """429 once the key has reached its limit, without counting this request.

    Paired with record_keyed_failure() on the login path: only failed
    verifications for existing accounts consume the bucket, so an anonymous
    attacker spraying garbage at a victim's username cannot lock the real
    user out of their own account.
    """
    counter: FixedWindowCounter = request.app.state.rate_counter
    result = counter.check(key, window)
    # Unlike ``make_rate_limiter()``, the failing action is recorded *after*
    # this preflight.  ``> limit`` therefore admitted one extra conflict:
    # for a limit of three, counts 1..4 were recorded and only the sixth
    # conflicting request was rejected.  At ``count == limit`` the budget is
    # exhausted, so reject before doing another expensive verifier hash.
    if result.count >= limit:
        raise _limit_response(result.retry_after)


def record_keyed_failure(request: Request, key: str, window: int) -> None:
    """Count one failure against a keyed bucket (see above)."""
    counter: FixedWindowCounter = request.app.state.rate_counter
    counter.hit(key, window)
