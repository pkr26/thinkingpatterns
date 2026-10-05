"""Application factory."""

from __future__ import annotations

import asyncio
import hmac
import logging
import random
from contextlib import asynccontextmanager

import anyio
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, config, singleprocess
from .api import api_router, api_v1_router
from .cache import RateLimitCheck, SlidingWindowCounter, TokenRevocationStore, make_rate_limiter
from .db import SCHEMA_HEAD, build_engine, build_sessionmaker, init_models
from .deps import DEFAULT_ERROR_CODES
from .metrics import MetricsMiddleware, MetricsRegistry
from .middleware import HardeningMiddleware, RateLimitRule
from .security.enclave import InMemoryKeyStore
from .security.export_ticket import ExportTicketStore
from .security.step_up import StepUpProofStore

# Distinct from alembic/env.py's migration lock (727272): this one is held
# for the app's LIFETIME, serializing deployments of the same database.
CROSS_HOST_ADVISORY_LOCK_ID = 727273


async def _acquire_cross_host_guard(engine) -> AsyncConnection | None:
    """Postgres-only: hold a session-scoped advisory lock for the app
    lifetime so a SECOND HOST on the same database refuses to boot.

    The 2026-09-16 single-process guard is an flock — per-HOST. A second
    host booted cleanly and silently fragmented every in-process
    guarantee (single-use sessions, rate limits, quota locks), returning
    without an error. The advisory lock makes the multi-host topology
    fail loudly at boot instead. SQLite (dev/test) has no advisory locks
    and no such topology: returns None. The held connection deliberately
    stays out of the pool for the app's lifetime (pool sizing accounts
    for one connection).
    """
    # getattr: test doubles may not carry a dialect; no dialect, no guard.
    dialect = getattr(engine, "dialect", None)
    if getattr(dialect, "name", "") != "postgresql":
        return None
    conn = await engine.connect()
    try:
        acquired = (
            await conn.exec_driver_sql(
                f"SELECT pg_try_advisory_lock({CROSS_HOST_ADVISORY_LOCK_ID})"
            )
        ).scalar()
        if acquired:
            # The SELECT autobegins a transaction; close it. Session-level
            # advisory locks survive COMMIT, but a transaction held open
            # for the app lifetime leaves this connection "idle in
            # transaction" — pinning xmin and blocking vacuum on every
            # table. The CONNECTION stays open (out of the pool) for the
            # app lifetime; that part is deliberate.
            await conn.commit()
    except Exception:
        await conn.close()
        raise
    if not acquired:
        await conn.close()
        raise RuntimeError(
            "another host is already serving this database: the rate "
            "limiter, per-user locks, and processing-session keystore are "
            "all in-process (see singleprocess.py). One host per database; "
            "move shared counters/locks to Redis &c. before scaling out."
        )
    return conn


async def _release_cross_host_guard(conn: AsyncConnection | None) -> None:
    if conn is None:
        return
    try:
        await conn.exec_driver_sql(f"SELECT pg_advisory_unlock({CROSS_HOST_ADVISORY_LOCK_ID})")
    except Exception:
        logger.warning("pg_advisory_unlock failed; disconnect releases the lock")
    finally:
        await conn.close()


async def _guard_is_healthy(app: FastAPI) -> bool:
    if not app.state.guard_healthy:
        return False
    conn = app.state.guard_connection
    if conn is None:
        return True
    async with app.state.guard_check_lock:
        if not app.state.guard_healthy:
            return False
        try:

            async def probe():
                result = await conn.exec_driver_sql(
                    f"SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=0 AND objid={CROSS_HOST_ADVISORY_LOCK_ID} AND objsubid=1 AND granted)"
                )
                owned = result.scalar()
                await conn.commit()
                return owned is True

            healthy = await asyncio.wait_for(probe(), timeout=2)
        except Exception:
            healthy = False
        if not healthy:
            # Ownership never gets automatically reacquired: another host may
            # now own the database. Cancel local work and require a restart.
            app.state.guard_healthy = False
            app.state.key_store.destroy_all()
            current = asyncio.current_task()
            for task in tuple(app.state.request_tasks):
                if task is not current:
                    task.cancel()
            logger.error("cross-host ownership lost; admission is closed until restart")
        return healthy


async def _guard_monitor(app: FastAPI) -> None:
    while app.state.guard_healthy:
        await asyncio.sleep(1)
        await _guard_is_healthy(app)


logger = logging.getLogger("mindpattern")

# Kept as an alias: older code/tests reference APP_VERSION on this module.
APP_VERSION = __version__

# access_log retention sweep cadence. The DELETE used to run only inside
# POST /therapist/pairing-codes (opportunistic housekeeping), so a
# steady-state deployment — no new pairings — never pruned and the table
# grew unbounded. The sweep runs the same shared statement (see
# api/therapist.py) once at startup and then daily.
ACCESS_LOG_SWEEP_INTERVAL_SECONDS = 24 * 60 * 60
# A bounded page that reports remaining work is followed cooperatively after
# a short pause.  The pause gives ordinary requests headroom while ensuring
# cardinality above one page does not turn into a multi-year daily backlog.
AUDIT_MAINTENANCE_CATCHUP_SECONDS = 1
AUDIT_MAINTENANCE_RETRY_MAX_SECONDS = 60
# Expired generated questions can have a large legacy backlog. Bound the
# awaited startup pass, then catch up in short deterministic batches while a
# one-bit aggregate backlog gauge says more rows remain.
QUESTION_RETENTION_BATCH = 500
QUESTION_RETENTION_CATCHUP_SECONDS = 1
AUXILIARY_RETENTION_BATCH = 500
# Processing sessions contain client data keys.  The store also validates
# expiry on every access, but a periodic purge is required so an abandoned
# process does not retain expired key material merely because no later
# request happens to touch the store.  A one-second cadence keeps the
# over-TTL residency bounded without coupling one timer task to every key.
PROCESSING_KEY_PURGE_INTERVAL_SECONDS = 1
# Account erasure returns after one constant-size logical-retirement
# transaction.  Physical rows and provider objects then drain through this
# dedicated, restart-safe worker.  A request wakes it immediately; while a
# backlog exists it yields between pages so ordinary traffic retains room.
ACCOUNT_DELETION_IDLE_SECONDS = 60
ACCOUNT_DELETION_CATCHUP_SECONDS = 1


async def _prune_expired_questions_once(app: FastAPI) -> bool:
    """Delete one deterministic question-retention batch.

    Returns whether at least one more expired row was visible. Both the
    selection and delete are bounded, so a legacy backlog cannot monopolize
    startup or a SQLite WAL writer; the recurring sweep uses the result for
    prompt catch-up rather than waiting another day.
    """
    from datetime import timedelta

    from sqlalchemy import delete, select

    from .api.insights import QUESTION_RETENTION_DAYS
    from .models import KIND_QUESTION, Insight, utcnow

    cutoff = utcnow().date() - timedelta(days=QUESTION_RETENTION_DAYS)
    async with app.state.sessionmaker() as session:
        candidate_ids = list(
            (
                await session.scalars(
                    select(Insight.id)
                    .where(Insight.kind == KIND_QUESTION, Insight.for_date < cutoff)
                    .order_by(Insight.for_date, Insight.id)
                    .limit(QUESTION_RETENTION_BATCH + 1)
                )
            ).all()
        )
        batch_ids = candidate_ids[:QUESTION_RETENTION_BATCH]
        if batch_ids:
            result = await session.execute(delete(Insight).where(Insight.id.in_(batch_ids)))
            pruned = max(0, int(getattr(result, "rowcount", len(batch_ids))))
        else:
            pruned = 0
        await session.commit()
    backlog = len(candidate_ids) > QUESTION_RETENTION_BATCH
    app.state.question_retention_backlog = backlog
    if hasattr(app.state.metrics, "observe_retention"):
        app.state.metrics.observe_retention(
            question_insights=pruned,
            question_backlog=backlog,
        )
    return backlog


async def _prune_auxiliary_retention_once(app: FastAPI, session, *, now) -> dict[str, tuple]:
    """Delete one deterministic page for each auxiliary retention class.

    At most four fixed-size ID batches share this transaction.  The first
    unprocessed row in each ordered ``limit + 1`` probe supplies a privacy-
    safe backlog/oldest-age signal without another global materialization.
    """
    from sqlalchemy import delete, select

    from .api.therapist import PAIRING_RETENTION
    from .models import (
        AccountDeletionTombstone,
        PairingCode,
        RekeyJournal,
        TokenRevocation,
        User,
    )

    async def delete_page(
        model, identity_column, timestamp_column, criterion
    ) -> tuple[bool, float, int]:
        candidates = list(
            (
                await session.execute(
                    select(identity_column, timestamp_column)
                    .where(criterion)
                    .order_by(timestamp_column, identity_column)
                    .limit(AUXILIARY_RETENTION_BATCH + 1)
                )
            ).all()
        )
        selected = candidates[:AUXILIARY_RETENTION_BATCH]
        if selected:
            await session.execute(
                delete(model).where(identity_column.in_([row[0] for row in selected]))
            )
        backlog = len(candidates) > AUXILIARY_RETENTION_BATCH
        oldest_age = (
            max(0.0, (now - candidates[AUXILIARY_RETENTION_BATCH][1]).total_seconds())
            if backlog
            else 0.0
        )
        return backlog, oldest_age, len(selected)

    pairing = await delete_page(
        PairingCode,
        PairingCode.id,
        PairingCode.expires_at,
        PairingCode.expires_at < now - PAIRING_RETENTION,
    )
    revocations = await delete_page(
        TokenRevocation,
        TokenRevocation.jti,
        TokenRevocation.expires_at,
        TokenRevocation.expires_at < now,
    )
    rekeys = await delete_page(
        RekeyJournal,
        RekeyJournal.id,
        RekeyJournal.updated_at,
        RekeyJournal.user_id.not_in(select(User.id)),
    )
    deletions = await delete_page(
        AccountDeletionTombstone,
        AccountDeletionTombstone.user_id,
        AccountDeletionTombstone.expires_at,
        AccountDeletionTombstone.expires_at <= now,
    )
    return {
        "pairing": pairing,
        "revocations": revocations,
        "rekeys": rekeys,
        "deletions": deletions,
    }


async def _prune_access_log_once(app: FastAPI) -> bool:
    """Run one authenticated maintenance pass with one shared journal index."""
    from .api._audit import reusable_journal_evidence_index

    settings = app.state.settings
    try:
        mac_keys = settings.audit_mac_keyring
        current_mac_key_version = settings.audit_mac_key_version
        if not mac_keys or current_mac_key_version not in mac_keys:
            raise RuntimeError("current audit MAC key is unavailable")
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        app.state.audit_maintenance_healthy = False
        app.state.audit_maintenance_retry_needed = True
        app.state.metrics.observe_audit_maintenance_failure()
        logger.error("audit maintenance refused: MAC key ring is invalid")
        raise RuntimeError("audit maintenance requires a valid MAC key ring") from exc

    journal_evidence = None
    try:
        if settings.audit_journal_path:
            journal_evidence = await anyio.to_thread.run_sync(
                reusable_journal_evidence_index, settings.audit_journal_path
            )
            if journal_evidence.corrupt:
                app.state.metrics.observe_audit_journal_failure()
                raise RuntimeError("audit journal evidence is unavailable or malformed")
        result = await _prune_access_log_once_with_evidence(
            app,
            mac_keys=mac_keys,
            current_mac_key_version=current_mac_key_version,
            journal_evidence=journal_evidence,
        )
    except Exception:
        app.state.audit_maintenance_healthy = False
        app.state.audit_maintenance_retry_needed = True
        app.state.metrics.observe_audit_maintenance_failure()
        raise
    app.state.audit_maintenance_healthy = True
    app.state.audit_maintenance_retry_needed = False
    app.state.audit_maintenance_retry_delay_seconds = AUDIT_MAINTENANCE_CATCHUP_SECONDS
    return result


async def _prune_access_log_once_with_evidence(
    app: FastAPI,
    *,
    mac_keys,
    current_mac_key_version: int,
    journal_evidence,
) -> bool:
    """One daily housekeeping pass: authenticated, bounded access-log
    retention plus dead pairing codes (2026-09-21 audit B-7: codes were
    pruned only opportunistically inside create_pairing_code — an idle
    therapist meant dead rows accumulated forever), expired token
    revocations (independent audit 2026-09-27), and the audit-chain
    verification sweep for every durable chain owner by round-robin — the runtime caller
    that makes the chain's tamper evidence load-bearing instead of a
    test-only helper."""
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from .api._audit import (
        AUDIT_MAINTENANCE_OWNER_BATCH,
        AUDIT_VERIFY_ROW_BATCH,
        AUDIT_VERIFY_TOTAL_ROW_BATCH,
        authenticate_verification_checkpoint,
        compact_audit_journal,
        prune_access_logs,
        seal_legacy_audit_states,
        seal_verification_checkpoint,
        verify_access_log_chain_incremental,
    )
    from .models import (
        AuditChainState,
        AuditSweepCursor,
        utcnow,
    )

    now = utcnow()
    settings = app.state.settings
    async with app.state.sessionmaker() as session:
        maintenance_cursor = await session.get(AuditSweepCursor, 1)
        if maintenance_cursor is None:
            maintenance_cursor = AuditSweepCursor(
                id=1,
                last_user_id=None,
                prune_last_user_id=None,
                updated_at=now,
            )
            session.add(maintenance_cursor)
        prune_progress = {
            "backlog": False,
            "next_owner": None,
            "owners_processed": 0,
            "rows_deleted": 0,
            "pending_rows_probe": 0,
            "oldest_pending_at": None,
        }

        def observe_prune_progress(**values) -> None:
            prune_progress.update(values)

        await seal_legacy_audit_states(
            session,
            mac_keys=mac_keys,
            current_mac_key_version=current_mac_key_version,
        )
        await prune_access_logs(
            session,
            cutoff=now - timedelta(days=settings.access_log_retention_days),
            mac_keys=mac_keys,
            current_mac_key_version=current_mac_key_version,
            journal_evidence=journal_evidence,
            owner_after=maintenance_cursor.prune_last_user_id,
            progress_observer=observe_prune_progress,
        )
        maintenance_cursor.prune_last_user_id = prune_progress["next_owner"]
        audit_prune_backlog = bool(prune_progress["backlog"])
        if audit_prune_backlog:
            if maintenance_cursor.prune_cycle_started_at is None:
                maintenance_cursor.prune_cycle_started_at = now
        else:
            maintenance_cursor.prune_cycle_started_at = None
        maintenance_cursor.updated_at = now
        auxiliary_progress = await _prune_auxiliary_retention_once(app, session, now=now)
        await session.commit()
    question_backlog = await _prune_expired_questions_once(app)

    # Chain verification is bounded by owners *and rows*. A large single
    # owner resumes from a durable HMAC-authenticated checkpoint rather than
    # monopolizing one pass or being rescanned from genesis on every page.
    retention_cutoff = now - timedelta(days=settings.access_log_retention_days)
    journal_path = settings.audit_journal_path or None
    async with app.state.sessionmaker() as session:
        # Merge two independently bounded sorted pages (durable DB state and
        # disk-spooled journal-only owners). Reaching the end completes this
        # verification cycle and resets the cursor for the next daily cycle;
        # a full page schedules a cooperative follow-up instead of waiting a
        # day. No all-owner set is ever materialized in process memory.
        cursor = await session.get(AuditSweepCursor, 1)
        if cursor is None:
            cursor = AuditSweepCursor(
                id=1,
                last_user_id=None,
                prune_last_user_id=prune_progress["next_owner"],
                updated_at=now,
            )
            session.add(cursor)
        authenticate_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        active_owner = cursor.verification_owner_id
        last = cursor.last_user_id
        if active_owner is not None:
            candidates = [active_owner]
            candidate_page_has_more = True
        else:
            state_after = list(
                (
                    await session.execute(
                        select(AuditChainState.user_id)
                        .where(
                            AuditChainState.user_id > last
                            if last is not None
                            else AuditChainState.user_id.is_not(None)
                        )
                        .order_by(AuditChainState.user_id)
                        .limit(AUDIT_MAINTENANCE_OWNER_BATCH + 1)
                    )
                ).scalars()
            )
            journal_after = (
                journal_evidence.owner_ids_after(last, AUDIT_MAINTENANCE_OWNER_BATCH + 1)
                if journal_evidence is not None
                else []
            )
            candidates = sorted(set(state_after) | set(journal_after))
            candidate_page_has_more = len(candidates) > AUDIT_MAINTENANCE_OWNER_BATCH
            candidates = candidates[:AUDIT_MAINTENANCE_OWNER_BATCH]
        failures = 0
        owners_verified = 0
        rows_remaining = AUDIT_VERIFY_TOTAL_ROW_BATCH
        verification_backlog = candidate_page_has_more
        for index, uid in enumerate(candidates):
            if rows_remaining <= 0:
                verification_backlog = True
                break
            verdict = await verify_access_log_chain_incremental(
                session,
                cursor,
                uid,
                mac_keys=mac_keys,
                current_mac_key_version=current_mac_key_version,
                retention_cutoff=retention_cutoff,
                journal_evidence=journal_evidence,
                row_budget=min(AUDIT_VERIFY_ROW_BATCH, rows_remaining),
            )
            rows_remaining -= verdict.rows_checked
            if not verdict.ok:
                failures += 1
                break
            if verdict.complete:
                owners_verified += 1
            else:
                verification_backlog = True
                break
            if index + 1 < len(candidates):
                verification_backlog = True
            elif not candidate_page_has_more:
                verification_backlog = False
        if failures:
            app.state.metrics.observe_audit_chain(failures=failures)
            logger.error("audit chain verification failed for %d owner(s)", failures)
            # A failed page may have populated tentative in-memory checkpoint
            # fields before discovering the bad row. Never commit those
            # fields with the previous checkpoint MAC: retain the last known
            # authenticated resume point for diagnosis and retry.
            await session.rollback()
            raise RuntimeError("audit chain verification failed")
        if not candidates:
            verification_backlog = False
        if not verification_backlog and not failures:
            cursor.last_user_id = None
            seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        if verification_backlog:
            if cursor.verification_cycle_started_at is None:
                cursor.verification_cycle_started_at = now
        else:
            cursor.verification_cycle_started_at = None
        verification_cycle_age = (
            max(0.0, (now - cursor.verification_cycle_started_at).total_seconds())
            if cursor.verification_cycle_started_at is not None
            else 0.0
        )
        cursor.updated_at = now
        await session.commit()
    rows_pruned = prune_progress["rows_deleted"]
    if not isinstance(rows_pruned, int):  # observer is internal; fail closed on drift
        raise RuntimeError("audit prune progress is invalid")
    pending_rows_probe = prune_progress["pending_rows_probe"]
    oldest_pending_at = prune_progress["oldest_pending_at"]
    if isinstance(pending_rows_probe, bool) or not isinstance(pending_rows_probe, int):
        raise RuntimeError("audit prune progress is invalid")
    if oldest_pending_at is not None and not isinstance(oldest_pending_at, datetime):
        raise RuntimeError("audit prune progress is invalid")
    app.state.audit_prune_backlog = audit_prune_backlog
    app.state.audit_verification_backlog = verification_backlog
    auxiliary_backlog = any(bool(values[0]) for values in auxiliary_progress.values())
    app.state.auxiliary_retention_backlog = auxiliary_backlog
    app.state.metrics.observe_audit_progress(
        prune_backlog=audit_prune_backlog,
        verification_backlog=verification_backlog,
        rows_pruned=rows_pruned,
        owners_verified=owners_verified,
        prune_pending_rows_probe=pending_rows_probe,
        prune_oldest_overdue_seconds=(
            max(
                0.0,
                (retention_cutoff - oldest_pending_at).total_seconds(),
            )
            if oldest_pending_at is not None
            else 0.0
        ),
        verification_pending_owners_probe=max(0, len(candidates) - owners_verified),
        verification_cycle_age_seconds=verification_cycle_age,
    )
    app.state.metrics.observe_auxiliary_retention(auxiliary_progress)
    if journal_path and not audit_prune_backlog and not verification_backlog:
        compaction_cutoff = (retention_cutoff - timedelta(days=7)).isoformat()
        try:
            kept, dropped = await anyio.to_thread.run_sync(
                compact_audit_journal, journal_path, compaction_cutoff
            )
            if dropped:
                logger.info(
                    "audit journal compacted: %d lines kept, %d older than %s dropped",
                    kept,
                    dropped,
                    compaction_cutoff,
                )
        except Exception:  # noqa: BLE001 — compaction is best-effort by contract
            app.state.metrics.observe_audit_journal_failure()
            logger.error("audit journal compaction failed; retrying next cycle")
    return bool(
        question_backlog or audit_prune_backlog or verification_backlog or auxiliary_backlog
    )


async def _access_log_retention_sweep(app: FastAPI) -> None:
    """Recurring retention pass every 24h. The FIRST pass runs AWAITED in
    the lifespan startup (see there for why), so this loop sleeps first. A
    failed pass logs and waits for the next cycle: retention lag must
    never take the app down."""
    while True:
        retry_needed = bool(getattr(app.state, "audit_maintenance_retry_needed", False))
        question_catchup = bool(getattr(app.state, "question_retention_backlog", False))
        audit_catchup = bool(
            getattr(app.state, "audit_prune_backlog", False)
            or getattr(app.state, "audit_verification_backlog", False)
            or getattr(app.state, "auxiliary_retention_backlog", False)
        )
        catching_up = question_catchup or audit_catchup
        if retry_needed:
            retry_base = max(
                AUDIT_MAINTENANCE_CATCHUP_SECONDS,
                min(
                    float(
                        getattr(
                            app.state,
                            "audit_maintenance_retry_delay_seconds",
                            AUDIT_MAINTENANCE_CATCHUP_SECONDS,
                        )
                    ),
                    AUDIT_MAINTENANCE_RETRY_MAX_SECONDS,
                ),
            )
            # Bounded jitter prevents a fleet restarted after the same outage
            # from hammering its database in lock-step. Never exceed the cap.
            delay = min(
                AUDIT_MAINTENANCE_RETRY_MAX_SECONDS,
                retry_base * (0.8 + 0.4 * random.random()),
            )
        elif catching_up:
            delay = min(QUESTION_RETENTION_CATCHUP_SECONDS, AUDIT_MAINTENANCE_CATCHUP_SECONDS)
        else:
            delay = ACCESS_LOG_SWEEP_INTERVAL_SECONDS
        await asyncio.sleep(delay)
        try:
            if retry_needed or audit_catchup:
                await _prune_access_log_once(app)
            elif question_catchup:
                await _prune_expired_questions_once(app)
            else:
                await _prune_access_log_once(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            app.state.audit_maintenance_retry_needed = True
            current_delay = float(
                getattr(
                    app.state,
                    "audit_maintenance_retry_delay_seconds",
                    AUDIT_MAINTENANCE_CATCHUP_SECONDS,
                )
            )
            app.state.audit_maintenance_retry_delay_seconds = min(
                AUDIT_MAINTENANCE_RETRY_MAX_SECONDS,
                max(AUDIT_MAINTENANCE_CATCHUP_SECONDS, current_delay * 2),
            )
            logger.error("retention sweep failed; retrying shortly")


async def _processing_key_sweep(app: FastAPI) -> None:
    """Purge expired processing keys even while the API is otherwise idle."""
    while True:
        try:
            app.state.key_store.purge_expired()
        except asyncio.CancelledError:
            raise
        except Exception:
            # A failure here must not take the API down; expiration is still
            # enforced at get/pop/create, and the next short interval retries.
            logger.error("processing-key expiry sweep failed; retrying shortly")
        await asyncio.sleep(PROCESSING_KEY_PURGE_INTERVAL_SECONDS)


async def _purge_deleted_account_once(app: FastAPI) -> bool:
    """Drain one fixed account-erasure page and return backlog state."""
    from .models import utcnow
    from .services.account_deletion import (
        ACCOUNT_PURGE_AUDIO_BATCH,
        account_deletion_status,
        purge_one_account_page,
    )
    from .services.audio_store import drain_audio_deletions

    async with app.state.sessionmaker() as session:
        # Object deletion is itself leased, retryable and fixed-size.  Run a
        # page before advancing an ``audio_wait`` job so a completed account
        # cannot remain solely because the ordinary audio-retention cadence
        # is long.
        await drain_audio_deletions(
            session,
            app.state.settings,
            limit=ACCOUNT_PURGE_AUDIO_BATCH,
            failure_observer=lambda: app.state.metrics.observe_account_deletion_failure(
                "object_store"
            ),
        )
        await purge_one_account_page(session, app.state.settings)
        await session.commit()
        status = await account_deletion_status(session)
    backlog = status.pending_probe > 0
    oldest_seconds = (
        max(0.0, (utcnow() - status.oldest_requested_at).total_seconds())
        if status.oldest_requested_at is not None
        else 0.0
    )
    app.state.metrics.observe_account_deletion(
        pending_probe=status.pending_probe,
        oldest_seconds=oldest_seconds,
    )
    app.state.account_deletion_backlog = backlog
    app.state.account_deletion_failure_streak = 0
    if not backlog:
        retry_delay = float(ACCOUNT_DELETION_IDLE_SECONDS)
    elif status.runnable:
        retry_delay = ACCOUNT_DELETION_CATCHUP_SECONDS
    elif status.next_due_at is not None:
        retry_delay = max(
            ACCOUNT_DELETION_CATCHUP_SECONDS,
            min(
                ACCOUNT_DELETION_IDLE_SECONDS,
                (status.next_due_at - utcnow()).total_seconds(),
            ),
        )
    else:
        retry_delay = ACCOUNT_DELETION_IDLE_SECONDS
    app.state.account_deletion_retry_delay_seconds = retry_delay
    return backlog


def _account_deletion_failure_category(exc: Exception) -> str:
    """Normalize worker failures without exposing exception text or identifiers."""

    from sqlalchemy.exc import SQLAlchemyError

    from .deps import ApiError
    from .services.audio_store import AudioStoreError

    if isinstance(exc, AudioStoreError):
        return "object_store"
    if isinstance(exc, SQLAlchemyError):
        return "database"
    if isinstance(exc, (ApiError, RuntimeError)):
        return "state"
    return "unexpected"


async def _account_deletion_sweep(app: FastAPI) -> None:
    """Wakeable bounded erasure worker; durable jobs survive every restart."""
    while True:
        delay = (
            max(
                ACCOUNT_DELETION_CATCHUP_SECONDS,
                float(
                    getattr(
                        app.state,
                        "account_deletion_retry_delay_seconds",
                        ACCOUNT_DELETION_CATCHUP_SECONDS,
                    )
                ),
            )
            if bool(getattr(app.state, "account_deletion_backlog", False))
            else ACCOUNT_DELETION_IDLE_SECONDS
        )
        try:
            await asyncio.wait_for(app.state.account_deletion_wakeup.wait(), timeout=delay)
        except TimeoutError:
            pass
        except asyncio.CancelledError:
            raise
        app.state.account_deletion_wakeup.clear()
        try:
            await _purge_deleted_account_once(app)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            category = _account_deletion_failure_category(exc)
            app.state.metrics.observe_account_deletion_failure(category)
            app.state.account_deletion_backlog = True
            failure_streak = int(getattr(app.state, "account_deletion_failure_streak", 0)) + 1
            app.state.account_deletion_failure_streak = failure_streak
            app.state.account_deletion_retry_delay_seconds = min(
                ACCOUNT_DELETION_IDLE_SECONDS,
                ACCOUNT_DELETION_CATCHUP_SECONDS * (2 ** min(failure_streak, 6)),
            )
            logger.error(
                "account deletion sweep failed; category=%s; retrying with bounded backoff",
                category,
            )


async def _audio_retention_sweep(app: FastAPI) -> None:
    """Recurring 30-day audio-attachment retention pass (docs/plans/voice-plan.md).

    Deletes expired attachments' objects then rows, one bounded batch per
    cycle; a store outage logs and retries next cycle (a failed pass must
    never take the API down, and lazy per-fetch expiry still bounds
    retention even while the sweeper is behind). No-ops cheaply when the
    feature or store is unconfigured.
    """
    from .services.audio_store import (
        AudioStoreError,
        audio_deletion_backlog,
        drain_audio_deletions,
        get_audio_store_cached,
        reconcile_audio_inventory,
        sweep_expired_audio,
    )

    while True:
        settings = app.state.settings
        await asyncio.sleep(settings.audio_sweep_interval_seconds)
        try:
            store = get_audio_store_cached(settings)
            async with app.state.sessionmaker() as session:
                swept = await sweep_expired_audio(session, store, settings)
                await drain_audio_deletions(session, settings)
                inventory_progress = {
                    "scanned": 0,
                    "backlog": False,
                    "cycle_completed": False,
                }

                def observe_inventory_progress(**values) -> None:
                    inventory_progress.update(values)

                reconciled = await reconcile_audio_inventory(
                    session,
                    store,
                    settings,
                    progress_observer=observe_inventory_progress,
                )
                backlog, oldest_age = await audio_deletion_backlog(session)
                app.state.metrics.observe_audio_retention(
                    backlog=backlog,
                    oldest_age_seconds=oldest_age,
                    reconciled=reconciled,
                    inventory_scanned=int(inventory_progress["scanned"]),
                    inventory_backlog=bool(inventory_progress["backlog"]),
                    inventory_cycle_completed=bool(inventory_progress["cycle_completed"]),
                )
            if swept:
                logger.info("audio retention sweep removed %d expired attachment(s)", swept)
        except asyncio.CancelledError:
            raise
        except AudioStoreError:
            app.state.metrics.observe_audio_storage_failure()
            logger.warning("audio retention sweep deferred after storage failure")
        except Exception:
            app.state.metrics.observe_audio_storage_failure()
            logger.error("audio retention sweep failed unexpectedly; retrying next cycle")


def _error_envelope(status_code: int, detail, code: str | None = None) -> dict:
    # detail is ALWAYS a human string — never the FastAPI default list of
    # {loc, msg, input} dicts (mobile parses it as a string, and input echo
    # is an amplification/leak vector).
    if not isinstance(detail, str) or not detail:
        detail = "request failed"
    return {"detail": detail, "code": code or DEFAULT_ERROR_CODES.get(status_code, "error")}


def _limiter_checks(dependant) -> list[RateLimitCheck]:
    """Collect every RateLimitCheck reachable from a dependant tree.

    Route-level ``dependencies=[Depends(make_rate_limiter(...))]`` and
    signature-level ``Depends(make_rate_limiter(...))`` both land in the
    dependant's dependency list (the latter one recursion level down), so a
    recursive walk finds both wirings without either style being privileged.
    """
    checks: list[RateLimitCheck] = []
    for dep in dependant.dependencies:
        if isinstance(dep.call, RateLimitCheck):
            checks.append(dep.call)
        checks.extend(_limiter_checks(dep))
    return checks


def _resolve_api_routes(routes):
    """Yield every API route with its FINAL (mounted) path information.

    FastAPI >= 0.141 mounts included routers lazily as a TREE of
    ``_IncludedRouter`` wrappers that only materialize their prefixed,
    route-shaped ``_EffectiveRouteContext`` leaves through
    ``effective_candidates()``; older versions flattened eagerly and the
    iterable already held plain APIRoutes. Recursing while the branch is
    explorable handles both shapes, and yields whatever else it finds (docs
    routes, healthz) unchanged — callers filter by the attributes they
    need.
    """
    for route in routes:
        candidates = getattr(route, "effective_candidates", None)
        if callable(candidates):
            yield from _resolve_api_routes(candidates())
        else:
            yield route


def _rate_limit_rules(app: FastAPI) -> tuple[RateLimitRule, ...]:
    """(methods, compiled path, limiter checks) for every rate-limited route.

    M-1 (2026-09-20): HardeningMiddleware counts malformed-JSON 422s into
    the SAME buckets the route dependencies use, so it needs the exact
    route→bucket mapping. Walking the LIVE router (after both mounts are
    included) instead of a hand-maintained table means the edge counter and
    the dependencies can never disagree about which bucket a path belongs
    to — a new route with a limiter is covered the moment it is registered.
    Buckets are de-duplicated per route so a request that matched several
    rules carrying the same bucket name still counts exactly once.
    """
    rules: list[RateLimitRule] = []
    for route in _resolve_api_routes(app.routes):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue  # plain Starlette route (docs, static) — no limiter
        unique: list[RateLimitCheck] = []
        seen: set[str] = set()
        for check in _limiter_checks(dependant):
            if check.bucket not in seen:
                seen.add(check.bucket)
                unique.append(check)
        if unique:
            rules.append((frozenset(route.methods or ()), route.path_regex, tuple(unique)))
    return tuple(rules)


def create_app(settings: config.Settings | None = None) -> FastAPI:
    settings = settings or config.settings
    is_development = settings.environment == "development"
    if not is_development:
        from .api._audit import validate_audit_journal_path

        validate_audit_journal_path(settings.audit_journal_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # The deployment contract is ONE process per instance: rate limits,
        # per-user locks, and the processing-session keystore are all
        # in-process. A second worker used to boot silently and fragment
        # every one of those guarantees (2026-09-16 red-team finding C1) —
        # now it refuses to start. Re-entrant within a process (tests).
        with singleprocess.single_process_guard(settings.token_secret, settings.database_url):
            if settings.trust_proxy_headers:
                config.logger.warning(
                    "MINDPATTERN_TRUST_PROXY_HEADERS is on: rate-limit identity "
                    "comes only from X-Forwarded-For received over a direct peer "
                    "in MINDPATTERN_TRUSTED_PROXY_IPS=%s. Keep the API unreachable "
                    "except through that proxy, which must append its observation; "
                    "do not enable uvicorn --proxy-headers because this middleware "
                    "needs the raw peer to verify the boundary.",
                    ",".join(settings.trusted_proxy_ips),
                )
            # Cross-host guard (2026-09-17): the flock above is per-host;
            # on Postgres a session advisory lock closes the multi-HOST hole.
            boot_guard_conn = await _acquire_cross_host_guard(app.state.engine)
            app.state.guard_connection = boot_guard_conn
            app.state.guard_healthy = True
            guard_task = (
                asyncio.create_task(_guard_monitor(app)) if boot_guard_conn is not None else None
            )
            sweep_task: asyncio.Task | None = None
            key_sweep_task: asyncio.Task | None = None
            audio_sweep_task: asyncio.Task | None = None
            account_deletion_task: asyncio.Task | None = None
            try:
                # create_all is a dev/test convenience only. Outside development
                # the schema comes from `alembic upgrade head` (run by the image
                # entrypoint before uvicorn starts) — silently pre-creating the
                # schema here would leave the database without an alembic_version
                # stamp and break the first real migration with CREATE TABLE
                # conflicts.
                if is_development:
                    await init_models(app.state.engine)
                # Independent audit 2026-09-27: revive every durable logout
                # revocation into the in-memory cache — a restart must not
                # resurrect logged-out bearers. Tolerant of a schema-less
                # database (the no-create_all boot contract): the table
                # missing means the whole instance is non-functional anyway,
                # so boot proceeds with an empty cache and the sweep logs
                # loudly rather than refusing to start.
                try:
                    async with app.state.sessionmaker() as session:
                        await app.state.token_revocations.hydrate(session)
                except Exception:  # noqa: BLE001 — boot must survive a missing table
                    config.logger.warning(
                        "token-revocation hydration skipped because storage is unavailable"
                    )
                # The FIRST housekeeping pass runs AWAITED, before the app
                # serves anything: a sweep interleaving with the first
                # requests used to break savepoint-based audit appends on
                # the shared test connection, and in production it means
                # no request ever races the first prune + chain
                # verification. The recurring task (created below) sleeps
                # first, so this pass is not duplicated.
                try:
                    await _prune_access_log_once(app)
                except Exception:  # noqa: BLE001 — boot must survive a failed sweep
                    config.logger.error("initial housekeeping pass failed; retrying shortly")
                # The app.state handle pins the task's lifecycle to the
                # lifespan for tests.
                sweep_task = asyncio.create_task(_access_log_retention_sweep(app))
                app.state.access_log_sweep_task = sweep_task
                key_sweep_task = asyncio.create_task(_processing_key_sweep(app))
                app.state.processing_key_sweep_task = key_sweep_task
                # VOICE_PLAN (2026-09-29): attachment retention. The task
                # itself reads the flag live each cycle, so a runtime flag
                # flip needs no restart.
                audio_sweep_task = asyncio.create_task(_audio_retention_sweep(app))
                app.state.audio_sweep_task = audio_sweep_task
                # Wake once at every boot: a crash can leave durable purge
                # jobs even though no live request remains to signal them.
                app.state.account_deletion_wakeup.set()
                account_deletion_task = asyncio.create_task(_account_deletion_sweep(app))
                app.state.account_deletion_sweep_task = account_deletion_task
                yield
            finally:
                if guard_task is not None:
                    guard_task.cancel()
                    await asyncio.gather(guard_task, return_exceptions=True)
                if sweep_task is not None:
                    sweep_task.cancel()
                    await asyncio.gather(sweep_task, return_exceptions=True)
                if key_sweep_task is not None:
                    key_sweep_task.cancel()
                    await asyncio.gather(key_sweep_task, return_exceptions=True)
                if audio_sweep_task is not None:
                    audio_sweep_task.cancel()
                    await asyncio.gather(audio_sweep_task, return_exceptions=True)
                if account_deletion_task is not None:
                    account_deletion_task.cancel()
                    await asyncio.gather(account_deletion_task, return_exceptions=True)
                # Process shutdown is a terminal lifecycle boundary: drop
                # every key before disposing DB/network resources or returning
                # control to a process manager that may retain memory briefly.
                app.state.key_store.destroy_all()
                app.state.export_tickets.clear()
                from .api._audit import close_reusable_journal_evidence_index

                close_reusable_journal_evidence_index()
                await _release_cross_host_guard(boot_guard_conn)
                await app.state.engine.dispose()

    app = FastAPI(
        title="Fathom API",
        version=APP_VERSION,
        description="Encrypted journaling API and deterministic pattern analysis.",
        lifespan=lifespan,
        # The interactive docs and schema are developer tooling: in any
        # non-development environment they would hand an attacker a complete
        # API map for nothing (fail closed: a typo'd MINDPATTERN_ENV keeps
        # them off, matching the config gates).
        docs_url="/docs" if is_development else None,
        redoc_url="/redoc" if is_development else None,
        openapi_url="/openapi.json" if is_development else None,
    )
    app.state.guard_healthy = True
    app.state.guard_connection = None
    app.state.guard_check_lock = asyncio.Lock()
    app.state.request_tasks = set()
    app.state.settings = settings
    app.state.engine = build_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        statement_timeout_ms=settings.db_statement_timeout_ms,
        idle_in_transaction_timeout_ms=settings.db_idle_in_transaction_timeout_ms,
    )
    app.state.sessionmaker = build_sessionmaker(app.state.engine)
    app.state.key_store = InMemoryKeyStore()
    app.state.rate_counter = SlidingWindowCounter()
    # Single-token logout (2026-09-26): jti -> expiry map checked in
    # deps.require_user. In-process on the same standing as the rate
    # counter and the keystore (one host per database, enforced at boot).
    app.state.token_revocations = TokenRevocationStore()
    app.state.step_up_store = StepUpProofStore()
    app.state.export_tickets = ExportTicketStore()
    app.state.metrics = MetricsRegistry()
    app.state.audit_maintenance_healthy = True
    app.state.audit_maintenance_retry_needed = False
    app.state.audit_maintenance_retry_delay_seconds = AUDIT_MAINTENANCE_CATCHUP_SECONDS
    app.state.audit_prune_backlog = False
    app.state.audit_verification_backlog = False
    app.state.auxiliary_retention_backlog = False
    app.state.question_retention_backlog = False
    app.state.account_deletion_backlog = False
    app.state.account_deletion_retry_delay_seconds = ACCOUNT_DELETION_IDLE_SECONDS
    app.state.account_deletion_failure_streak = 0
    app.state.account_deletion_wakeup = asyncio.Event()
    # Independent audit 2026-09-27: seal every runtime audit append with
    # the keyed MAC (secret resolved from the env/file or derived from the
    # token secret — never stored in the database).
    from .api._audit import configure_audit_mac_key

    audit_keys = settings.audit_mac_keyring
    audit_key_version = settings.audit_mac_key_version
    configure_audit_mac_key(
        audit_keys[audit_key_version],
        settings.audit_journal_path,
        key_version=audit_key_version,
        previous_keys={
            version: key for version, key in audit_keys.items() if version != audit_key_version
        },
    )
    # Analysis (brain recomputes) is attacker-sized CPU work; a dedicated
    # limiter keeps it from occupying every worker thread that auth scrypt
    # and ordinary requests also need.
    app.state.analyze_limiter = anyio.CapacityLimiter(4)
    # Auth scrypt (default N=2^17, ~128 MiB per hash) likewise gets its own
    # small limiter: a login flood must not be able to queue unbounded
    # 128-MiB allocations on the shared anyio thread pool.
    app.state.auth_limiter = anyio.CapacityLimiter(4)
    # Non-blocking admission paired with auth_limiter: acquire this BEFORE
    # the login SELECT, so a flood gets a small 503 queue boundary rather
    # than retaining pooled DB connections while it waits behind scrypt.
    app.state.auth_admission_limiter = anyio.CapacityLimiter(4)
    # Exports no longer hold a cursor across the client connection, but they
    # still page through a potentially large account. Keep a small global
    # active-export cap below available database capacity as a second DoS
    # boundary (and always leave one connection for ordinary traffic).
    app.state.export_limiter = anyio.CapacityLimiter(
        max(1, min(2, settings.db_pool_size + settings.db_max_overflow - 1))
    )

    # Offset-paginated clients must read both the opaque next-page cursor
    # and the collection snapshot marker that makes a continuation safe
    # across independent requests. Hoisted so HardeningMiddleware can
    # mirror the same expose list onto its own short-circuit responses
    # (L-4) — one list, no drift between the two CORS surfaces.
    # 2026-09-26 audit (LOW, batch item a): the measures snapshot marker
    # (X-Measures-Revision, set at measures.py) and the access-log
    # continuation cursor (X-Next-Cursor, set by the patient/therapist
    # access-log reads) joined the expose list — without them a browser
    # client could paginate entries/notes but not measures or audit trails.
    cors_expose_headers = [
        "X-Next-Offset",
        "X-Entries-Revision",
        "X-Notes-Revision",
        "X-Measures-Revision",
        "X-Next-Cursor",
    ]
    app.add_middleware(
        CORSMiddleware,
        # Empty by default — the mobile app is a native client and needs no
        # CORS; browser frontends set an explicit MINDPATTERN_CORS_ORIGINS
        # allowlist. Credentials stay off.
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        # X-Processing-Token drives recomputes; X-Account-Verifier is the
        # preferred DELETE /account re-auth transport — a browser client
        # could not send either in a cross-origin request without this.
        # X-New-Processing-Token rides POST /processing/rekey (2026-09-26
        # pentest D-1): omitting it made the data-key rotation unpreflightable
        # for allow-listed browser clients, functionally pushing users to
        # SKIP the remedy after a suspected compromise.
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Processing-Token",
            "X-New-Processing-Token",
            "X-Account-Verifier",
            "X-Step-Up-Proof",
            "X-Therapist-Enrollment-Token",
            # X-Pairing-Code rides GET /therapist/pairing/sas (deep audit
            # 2026-09-28): the portal is a browser client, and a header not
            # in this list fails preflight — the SAS comparison flow was
            # unusable from exactly the allow-listed origins this serves.
            # Same omission class as the X-New-Processing-Token fix above.
            "X-Pairing-Code",
        ],
        expose_headers=cors_expose_headers,
    )
    # Inside the hardening layer: aggregate status counters (no paths, no
    # user data — see app/metrics.py). Added BEFORE HardeningMiddleware so
    # Hardening stays outermost (security headers on every response).
    app.add_middleware(MetricsMiddleware, registry=app.state.metrics)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_envelope(request: Request, exc: StarletteHTTPException):
        # Covers both fastapi.HTTPException (a subclass) and framework-raised
        # Starlette errors (unknown route 404s, 405s). ApiError instances
        # carry their own code; everything else gets the per-status default.
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_envelope(exc.status_code, exc.detail, getattr(exc, "code", None)),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_no_echo(request: Request, exc: RequestValidationError):
        # FastAPI's default 422 echoes the offending `input` — for an
        # oversized blob field that is a 2x-bandwidth amplification vector.
        # Report only WHICH fields failed and why (locations + pydantic's
        # messages carry no user input), as one human string.
        # M-1 (2026-09-20): a body the JSON parser could not read fails
        # HERE, before any route dependency — including the rate limiters —
        # has run. Mark such requests so HardeningMiddleware (the one layer
        # positioned both before the app and around this handler) can count
        # the failure into the route's own bucket. Strictly json_invalid:
        # schema failures mean the body parsed and the route's dependencies
        # already counted the request themselves.
        if any(e.get("type") == "json_invalid" for e in exc.errors()):
            request.scope.setdefault("state", {})["mindpattern_body_parse_failed"] = True
        parts = []
        for e in exc.errors():
            loc = ".".join(str(part) for part in e.get("loc", ()) if part != "body")
            msg = e.get("msg", "invalid value")
            parts.append(f"{loc}: {msg}" if loc else msg)
        detail = "; ".join(parts)[:500] or "request validation failed"
        return JSONResponse(
            status_code=422,
            content=_error_envelope(422, detail),
        )

    # Canonical mount is /api/v1; the legacy /api mount serves the same
    # routers unversioned for existing clients (deprecated — /api/meta
    # reports api_version so clients can discover the canonical base).
    app.include_router(api_v1_router)
    app.include_router(api_router)

    @app.get(
        "/healthz",
        tags=["ops"],
        # L-2 (2026-09-20): one shared generous bucket for the ops pair —
        # unthrottled, /healthz+/readyz were the only DB-touching endpoints
        # with no limiter, a free pool-pressure flood for anyone unauthenticated.
        dependencies=[
            Depends(make_rate_limiter("ops-health", "ops_rate_limit", "ops_rate_window"))
        ],
    )
    async def healthz() -> dict:
        # Liveness only: no DB touch, so a wedged pool still reports the
        # process as alive (that's what /readyz is for).
        return {"status": "ok", "version": APP_VERSION}

    @app.get(
        "/metrics",
        tags=["ops"],
        # 2026-09-26 audit item 1: /metrics was the only route besides
        # CORS preflights with no limiter at all. It renders the registry
        # (cheap), but an unauthenticated flood could still draw unlimited
        # 200s — and unlimited hardening-layer body-buffer work — outside
        # every API bucket. It joins /healthz + /readyz in the one shared,
        # generous ops bucket: load-balancer and Prometheus scrapers stay
        # comfortable while the flood is bounded.
        dependencies=[
            Depends(make_rate_limiter("ops-health", "ops_rate_limit", "ops_rate_window"))
        ],
    )
    async def metrics_endpoint(request: Request):
        # Fail closed: without an explicitly configured token the endpoint
        # exists only in development; every other environment 404s. The
        # environment is read from app.state at request time (tests flip it
        # without rebuilding the app; the value changes nothing else here).
        live_settings: config.Settings = request.app.state.settings
        if not live_settings.metrics_token:
            if live_settings.environment != "development":
                raise StarletteHTTPException(status_code=404, detail="not found")
        else:
            provided = request.headers.get("authorization", "")
            # The token ALSO comes from the live settings: the create_app
            # closure's copy goes stale the moment app.state.settings is
            # replaced at runtime — the old, possibly-empty token would
            # stay accepted forever. compare_digest (UTF-8 encodings, the
            # account.py idiom): the comparison itself must not leak.
            expected = f"Bearer {live_settings.metrics_token}"
            if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
                raise StarletteHTTPException(status_code=401, detail="metrics token required")
        keystore_len = len(request.app.state.key_store)
        return PlainTextResponse(
            request.app.state.metrics.render(keystore_len),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get(
        "/readyz",
        tags=["ops"],
        dependencies=[
            Depends(make_rate_limiter("ops-health", "ops_rate_limit", "ops_rate_window"))
        ],
    )
    async def readyz(request: Request):
        if not await _guard_is_healthy(app):
            return JSONResponse(
                status_code=503, content=_error_envelope(503, "instance ownership unavailable")
            )
        if not request.app.state.audit_maintenance_healthy:
            return JSONResponse(
                status_code=503,
                content=_error_envelope(503, "audit maintenance unavailable"),
            )
        if request.app.state.settings.audit_journal_path:
            from .api._audit import audit_journal_health

            if not audit_journal_health()[0]:
                return JSONResponse(
                    status_code=503,
                    content=_error_envelope(503, "audit journal unavailable"),
                )
        try:
            async with request.app.state.sessionmaker() as session:
                await session.execute(text("SELECT 1"))
                # Development's create_all convenience deliberately does not
                # create alembic_version. Every deployed/non-development app
                # must prove it is at the exact migration head before a load
                # balancer sends real journal traffic to it.
                if request.app.state.settings.environment != "development":
                    version = (
                        await session.execute(text("SELECT version_num FROM alembic_version"))
                    ).scalar_one_or_none()
                    if version != SCHEMA_HEAD:
                        raise RuntimeError(
                            f"database schema revision {version!r} is not required head {SCHEMA_HEAD!r}"
                        )
        except Exception:
            logger.error("readiness check failed: database or schema unavailable")
            return JSONResponse(
                status_code=503,
                content=_error_envelope(503, "database unavailable"),
            )
        return {"status": "ready", "version": APP_VERSION}

    # Outermost: body-size cap + security headers on EVERY response (413s,
    # 500s included) + last-ditch exception handling. Registered AFTER every
    # route exists — both router mounts AND the three ops routes above —
    # because its malformed-body rate rules are built from the final route
    # table by _rate_limit_rules(app) RIGHT HERE: the argument is evaluated
    # eagerly at registration, so a route added after this call would be
    # invisible to the edge counter (the re-audit caught exactly that for
    # /healthz, /metrics, /readyz). add_middleware still stacks this as the
    # outermost user middleware (each call prepends), and nothing is added
    # after it, so registering last changes nothing about the stack order.
    app.add_middleware(
        HardeningMiddleware,
        max_body_bytes=settings.max_body_bytes,
        body_buffer_concurrency=settings.body_buffer_concurrency,
        guard_check=lambda: _guard_is_healthy(app),
        request_tasks=app.state.request_tasks,
        body_read_timeout_seconds=settings.body_read_timeout_seconds,
        trust_proxy_headers=settings.trust_proxy_headers,
        trusted_proxy_ips=settings.trusted_proxy_ips,
        rate_limit_rules=_rate_limit_rules(app),
        rate_counter=app.state.rate_counter,
        rate_limit_settings=settings,
        # 2026-09-26 audit item 6: route this layer's LIMITS through a live
        # accessor of app.state.settings. The constructor's copies went stale
        # the moment tests (or a future operator surface) swapped
        # app.state.settings at runtime, while every route dependency read
        # the live object — the edge pre-dispatch gate and the dependencies
        # could then disagree about both the body cap and the bucket limits.
        # The provider keeps direct constructions (which pass a Settings
        # object only) on the historical static behavior.
        settings_provider=lambda: app.state.settings,
        cors_origins=tuple(settings.cors_origins),
        cors_expose_headers=tuple(cors_expose_headers),
        # M-26: responses this outer layer synthesizes from exceptions the
        # app raised (last-ditch 500, deep-nesting 400) and its pre-dispatch
        # flood 429s never pass the inner MetricsMiddleware — tap them into
        # the same registry so status families stay complete.
        status_observer=app.state.metrics.observe_request,
    )

    return app


app = create_app()
