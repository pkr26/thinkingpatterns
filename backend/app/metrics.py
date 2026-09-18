"""Privacy-safe operational metrics (2026-09-17).

Production visibility used to be `/healthz` + `/readyz` + container logs —
deliberate for privacy, but it also meant the failure users would notice
most (a dead LLM endpoint reported as `analyzer: "llm"`, a recompute CPU
ceiling nobody can see saturating) was invisible. This module is the
minimal replacement: aggregate counters ONLY.

What will NEVER appear here, by design: usernames, entry counts per user,
pattern labels, request paths (they embed user ids), latencies per user,
anything derived from journal content. Status-code families, recompute
durations, LLM failure counts, and the keystore length carry operations
signal with zero user signal.

Single-process assumptions: the registry is process-local (same contract
as the rate counter and keystore). Locking is a plain threading.Lock —
recompute observations arrive from worker threads.
"""

from __future__ import annotations

import threading

# Cumulative histogram buckets for one recompute (seconds). The analyze
# limiter admits 4 at a time; a 2000-entry brain run measures ~1.2s on a
# development core, so the buckets straddle the interesting range up to
# "something is deeply wrong".
RECOMPUTE_BUCKETS: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0, 5.0, 15.0, 60.0, float("inf"))


class MetricsRegistry:
    """Thread-safe aggregate counters; renders Prometheus text format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, int] = {}
        self._recompute_count = 0
        self._recompute_sum = 0.0
        self._recompute_bucket_counts: dict[float, int] = {b: 0 for b in RECOMPUTE_BUCKETS}
        self._llm_failures = 0
        self._llm_successes = 0

    def observe_request(self, status: int) -> None:
        family = f"{status // 100}xx"
        with self._lock:
            self._requests[family] = self._requests.get(family, 0) + 1

    def observe_recompute(self, seconds: float) -> None:
        with self._lock:
            self._recompute_count += 1
            self._recompute_sum += seconds
            # Cumulative: every bucket at or above the observation counts it.
            for bucket in RECOMPUTE_BUCKETS:
                if seconds <= bucket:
                    self._recompute_bucket_counts[bucket] += 1

    def observe_llm(self, failed: bool) -> None:
        with self._lock:
            if failed:
                self._llm_failures += 1
            else:
                self._llm_successes += 1

    def render(self, keystore_sessions: int) -> str:
        with self._lock:
            lines: list[str] = []
            lines.append("# TYPE mindpattern_requests_total counter")
            for family in sorted(self._requests):
                lines.append(
                    f'mindpattern_requests_total{{status="{family}"}} {self._requests[family]}'
                )
            lines.append("# TYPE mindpattern_recompute_seconds histogram")
            for bucket in RECOMPUTE_BUCKETS:
                le = "+Inf" if bucket == float("inf") else str(bucket)
                lines.append(
                    f'mindpattern_recompute_seconds_bucket{{le="{le}"}} '
                    f"{self._recompute_bucket_counts[bucket]}"
                )
            lines.append(f"mindpattern_recompute_seconds_count {self._recompute_count}")
            lines.append(f"mindpattern_recompute_seconds_sum {self._recompute_sum:.6f}")
            lines.append("# TYPE mindpattern_llm_calls_total counter")
            lines.append(f'mindpattern_llm_calls_total{{outcome="failure"}} {self._llm_failures}')
            lines.append(f'mindpattern_llm_calls_total{{outcome="success"}} {self._llm_successes}')
            lines.append("# TYPE mindpattern_keystore_sessions gauge")
            lines.append(f"mindpattern_keystore_sessions {keystore_sessions}")
            return "\n".join(lines) + "\n"


class MetricsMiddleware:
    """Pure-ASGI response-status counter (no bodies, no paths, no headers).

    Sits INSIDE HardeningMiddleware, so it observes everything the
    application produced — including handled 500s and 429s (which is the
    rate-limit signal) — but not the pre-parse 413s Hardening itself
    short-circuits.
    """

    def __init__(self, app, registry: MetricsRegistry) -> None:
        self.app = app
        self.registry = registry

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                self.registry.observe_request(message["status"])
            await send(message)

        await self.app(scope, receive, send_wrapper)
