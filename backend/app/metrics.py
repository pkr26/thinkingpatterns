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
        self._audit_chain_failures = 0
        self._audit_journal_failures = 0
        self._audit_maintenance_failures = 0
        self._audit_prune_backlog = 0
        self._audit_verification_backlog = 0
        self._audit_prune_pending_rows_probe = 0
        self._audit_prune_oldest_overdue_seconds = 0.0
        self._audit_verification_pending_owners_probe = 0
        self._audit_verification_cycle_age_seconds = 0.0
        self._audit_rows_pruned = 0
        self._audit_owners_verified = 0
        self._auxiliary_backlog = {
            "deletions": 0,
            "pairing": 0,
            "revocations": 0,
            "rekeys": 0,
        }
        self._auxiliary_oldest_seconds = {
            "deletions": 0.0,
            "pairing": 0.0,
            "revocations": 0.0,
            "rekeys": 0.0,
        }
        self._auxiliary_deleted = {
            "deletions": 0,
            "pairing": 0,
            "revocations": 0,
            "rekeys": 0,
        }
        self._question_insights_pruned = 0
        self._question_retention_backlog = 0
        self._audio_deletion_backlog = 0
        self._audio_deletion_oldest_seconds = 0.0
        self._audio_orphans_reconciled = 0
        self._audio_inventory_scanned = 0
        self._audio_inventory_backlog = 0
        self._audio_inventory_cycles = 0
        self._audio_storage_failures = 0
        self._account_deletion_pending_probe = 0
        self._account_deletion_oldest_seconds = 0.0
        self._account_deletion_failures = {
            "database": 0,
            "object_store": 0,
            "state": 0,
            "unexpected": 0,
        }

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

    def observe_audit_chain(self, failures: int) -> None:
        """Daily chain-verification outcome (independent audit 2026-09-27).

        Counts FAILED patients, not rows: one tampered trail is one signal
        however many rows it has. Zero when every verified chain holds."""
        with self._lock:
            self._audit_chain_failures += failures

    def observe_audit_journal_failure(self) -> None:
        """One failed append or compaction I/O operation (no path labels)."""
        with self._lock:
            self._audit_journal_failures += 1

    def observe_audit_maintenance_failure(self) -> None:
        """A maintenance pass refused to mutate without authenticated keys."""
        with self._lock:
            self._audit_maintenance_failures += 1

    def observe_audit_progress(
        self,
        *,
        prune_backlog: bool,
        verification_backlog: bool,
        rows_pruned: int = 0,
        owners_verified: int = 0,
        prune_pending_rows_probe: int = 0,
        prune_oldest_overdue_seconds: float = 0.0,
        verification_pending_owners_probe: int = 0,
        verification_cycle_age_seconds: float = 0.0,
    ) -> None:
        """Bounded-maintenance progress without owner or event labels.

        Probe counts are intentionally capped by the maintenance page size;
        they are convergence proxies, not unbounded global counts.
        """
        with self._lock:
            self._audit_prune_backlog = int(prune_backlog)
            self._audit_verification_backlog = int(verification_backlog)
            self._audit_prune_pending_rows_probe = max(0, int(prune_pending_rows_probe))
            self._audit_prune_oldest_overdue_seconds = max(0.0, float(prune_oldest_overdue_seconds))
            self._audit_verification_pending_owners_probe = max(
                0, int(verification_pending_owners_probe)
            )
            self._audit_verification_cycle_age_seconds = max(
                0.0, float(verification_cycle_age_seconds)
            )
            self._audit_rows_pruned += rows_pruned
            self._audit_owners_verified += owners_verified

    def observe_auxiliary_retention(self, progress: dict[str, tuple]) -> None:
        """Cleanup progress labeled only by three fixed maintenance classes."""
        with self._lock:
            for name in self._auxiliary_backlog:
                backlog, oldest_seconds, deleted = progress[name]
                self._auxiliary_backlog[name] = int(bool(backlog))
                self._auxiliary_oldest_seconds[name] = float(oldest_seconds)
                self._auxiliary_deleted[name] += int(deleted)

    def observe_retention(
        self, *, question_insights: int = 0, question_backlog: bool | None = None
    ) -> None:
        with self._lock:
            self._question_insights_pruned += question_insights
            if question_backlog is not None:
                self._question_retention_backlog = int(question_backlog)

    def observe_audio_retention(
        self,
        *,
        backlog: int,
        oldest_age_seconds: float,
        reconciled: int = 0,
        inventory_scanned: int = 0,
        inventory_backlog: bool = False,
        inventory_cycle_completed: bool = False,
    ) -> None:
        with self._lock:
            self._audio_deletion_backlog = backlog
            self._audio_deletion_oldest_seconds = oldest_age_seconds
            self._audio_orphans_reconciled += reconciled
            self._audio_inventory_scanned += inventory_scanned
            self._audio_inventory_backlog = int(inventory_backlog)
            self._audio_inventory_cycles += int(inventory_cycle_completed)

    def observe_audio_storage_failure(self) -> None:
        """One normalized object-store failure, without provider labels."""
        with self._lock:
            self._audio_storage_failures += 1

    def observe_account_deletion(self, *, pending_probe: int, oldest_seconds: float) -> None:
        """Aggregate bounded-purge status with no account or object labels."""

        with self._lock:
            self._account_deletion_pending_probe = max(0, int(pending_probe))
            self._account_deletion_oldest_seconds = max(0.0, float(oldest_seconds))

    def observe_account_deletion_failure(self, category: str) -> None:
        """Count one worker failure in a fixed, privacy-safe category."""

        if category not in self._account_deletion_failures:
            category = "unexpected"
        with self._lock:
            self._account_deletion_failures[category] += 1

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
            lines.append("# TYPE mindpattern_audit_chain_failures counter")
            lines.append(f"mindpattern_audit_chain_failures {self._audit_chain_failures}")
            lines.append("# TYPE mindpattern_audit_journal_failures_total counter")
            lines.append(f"mindpattern_audit_journal_failures_total {self._audit_journal_failures}")
            lines.append("# TYPE mindpattern_audit_maintenance_failures_total counter")
            lines.append(
                f"mindpattern_audit_maintenance_failures_total {self._audit_maintenance_failures}"
            )
            lines.append("# TYPE mindpattern_audit_prune_backlog gauge")
            lines.append(f"mindpattern_audit_prune_backlog {self._audit_prune_backlog}")
            lines.append("# TYPE mindpattern_audit_verification_backlog gauge")
            lines.append(
                f"mindpattern_audit_verification_backlog {self._audit_verification_backlog}"
            )
            lines.append("# TYPE mindpattern_audit_prune_pending_rows_probe gauge")
            lines.append(
                f"mindpattern_audit_prune_pending_rows_probe {self._audit_prune_pending_rows_probe}"
            )
            lines.append("# TYPE mindpattern_audit_prune_oldest_overdue_seconds gauge")
            lines.append(
                "mindpattern_audit_prune_oldest_overdue_seconds "
                f"{self._audit_prune_oldest_overdue_seconds:.3f}"
            )
            lines.append("# TYPE mindpattern_audit_verification_pending_owners_probe gauge")
            lines.append(
                "mindpattern_audit_verification_pending_owners_probe "
                f"{self._audit_verification_pending_owners_probe}"
            )
            lines.append("# TYPE mindpattern_audit_verification_cycle_age_seconds gauge")
            lines.append(
                "mindpattern_audit_verification_cycle_age_seconds "
                f"{self._audit_verification_cycle_age_seconds:.3f}"
            )
            lines.append("# TYPE mindpattern_audit_rows_pruned_total counter")
            lines.append(f"mindpattern_audit_rows_pruned_total {self._audit_rows_pruned}")
            lines.append("# TYPE mindpattern_audit_owners_verified_total counter")
            lines.append(f"mindpattern_audit_owners_verified_total {self._audit_owners_verified}")
            lines.append("# TYPE mindpattern_auxiliary_retention_backlog gauge")
            lines.append("# TYPE mindpattern_auxiliary_retention_oldest_seconds gauge")
            lines.append("# TYPE mindpattern_auxiliary_retention_deleted_total counter")
            for name in sorted(self._auxiliary_backlog):
                lines.append(
                    "mindpattern_auxiliary_retention_backlog"
                    f'{{class="{name}"}} {self._auxiliary_backlog[name]}'
                )
                lines.append(
                    "mindpattern_auxiliary_retention_oldest_seconds"
                    f'{{class="{name}"}} {self._auxiliary_oldest_seconds[name]:.3f}'
                )
                lines.append(
                    "mindpattern_auxiliary_retention_deleted_total"
                    f'{{class="{name}"}} {self._auxiliary_deleted[name]}'
                )
            lines.append("# TYPE mindpattern_question_insights_pruned_total counter")
            lines.append(
                f"mindpattern_question_insights_pruned_total {self._question_insights_pruned}"
            )
            lines.append("# TYPE mindpattern_question_retention_backlog gauge")
            lines.append(
                f"mindpattern_question_retention_backlog {self._question_retention_backlog}"
            )
            lines.append("# TYPE mindpattern_audio_deletion_backlog gauge")
            lines.append(f"mindpattern_audio_deletion_backlog {self._audio_deletion_backlog}")
            lines.append("# TYPE mindpattern_audio_deletion_oldest_seconds gauge")
            lines.append(
                "mindpattern_audio_deletion_oldest_seconds "
                f"{self._audio_deletion_oldest_seconds:.3f}"
            )
            lines.append("# TYPE mindpattern_audio_orphans_reconciled_total counter")
            lines.append(
                f"mindpattern_audio_orphans_reconciled_total {self._audio_orphans_reconciled}"
            )
            lines.append("# TYPE mindpattern_audio_inventory_scanned_total counter")
            lines.append(
                f"mindpattern_audio_inventory_scanned_total {self._audio_inventory_scanned}"
            )
            lines.append("# TYPE mindpattern_audio_inventory_backlog gauge")
            lines.append(f"mindpattern_audio_inventory_backlog {self._audio_inventory_backlog}")
            lines.append("# TYPE mindpattern_audio_inventory_cycles_total counter")
            lines.append(f"mindpattern_audio_inventory_cycles_total {self._audio_inventory_cycles}")
            lines.append("# TYPE mindpattern_audio_storage_failures_total counter")
            lines.append(f"mindpattern_audio_storage_failures_total {self._audio_storage_failures}")
            lines.append("# TYPE mindpattern_account_deletion_pending_probe gauge")
            lines.append(
                f"mindpattern_account_deletion_pending_probe {self._account_deletion_pending_probe}"
            )
            lines.append("# TYPE mindpattern_account_deletion_oldest_seconds gauge")
            lines.append(
                "mindpattern_account_deletion_oldest_seconds "
                f"{self._account_deletion_oldest_seconds:.3f}"
            )
            lines.append("# TYPE mindpattern_account_deletion_failures_total counter")
            for category in sorted(self._account_deletion_failures):
                lines.append(
                    "mindpattern_account_deletion_failures_total"
                    f'{{category="{category}"}} {self._account_deletion_failures[category]}'
                )
            return "\n".join(lines) + "\n"


class MetricsMiddleware:
    """Pure-ASGI response-status counter (no bodies, no paths, no headers).

    Sits INSIDE HardeningMiddleware, so it observes every response the
    application SENDS — including handled 500s and the dependency-issued
    429s (which is the rate-limit signal). Two classes of response never
    reach it:

    * Responses Hardening synthesizes from exceptions the app RAISED — the
      last-ditch 500 and the deep-nesting 400 — plus its pre-dispatch 429
      for over-limit malformed-JSON clients (M-1): the exception or
      short-circuit blows straight through this layer. Since 2026-09-20
      (M-26) those are tapped into the SAME registry via
      HardeningMiddleware's ``status_observer`` (wired in main.py), so a
      crash loop still shows up in ``status="5xx"``.
    * Hardening's pre-parse rejections — 413 oversize, 408 body timeout,
      400 framing/content-length: deliberately NOT observed. Those requests
      never entered the application; that exclusion is the long-standing
      documented contract (an edge-proxy counter is the right place for
      them).
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
