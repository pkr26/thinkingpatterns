#!/usr/bin/env python3
"""Behavioral mutation campaign, round 3 (2026-09-19): backend infrastructure.

Six campaigns over the seams rounds 1-2 did not reach: authorization,
database/ORM, boundaries, error handling/transactions, cache/invalidation,
and rate limiting/concurrency. Same discipline as rounds 1-2: snapshot the
target file's bytes, apply ONE semantic mutation, run the targeted suite(s),
restore the bytes exactly (byte-wise, never git), record killed/survived +
the failing tests. Survivors are re-verified against the full fast suite by
verify_survivors.py; genuine survivors get pin tests; documented residuals
say why they are not pins.

  O  Authorization & access control: token-epoch kill switch, active-user
     gate, role walls (both directions), revoked-consent reads, note chart
     scoping, revoke ownership, feature-flag fail-closed, keystore owner
     binding (get+pop), enrollment-token gate, recompute token owner pin.
  P  Database & ORM: the load-bearing unique constraints (entries idempotency,
     undated-insight backstop), FK cascade, SQL DISTINCT, pagination order
     tiebreak, same-day upsert set_, insight delete scope, populate_existing,
     list_entries ownership filter, revision-advance guard.
  Q  Boundary & business logic: response byte budgets, has_more detection,
     note count/byte quotas, therapist page size, continuation arithmetic,
     question retention, audit-log retention, caseload caps, wrapped-key
     size bound, inner-date tolerance.
  R  Error handling & transactions: envelope string fallback, deep-JSON 400,
     headers on middleware-produced responses, FK->410 mapping, unique-
     violation classification, atomic epoch bump, export admission release,
     grant conflict mapping, revoke lifecycle recheck, pairing retry filter.
  S  Cache & invalidation: processing-session TTL enforcement, owner purge,
     per-owner session cap, revision markers (delete advance, stale
     comparison), phase-gated blob serving (patient + therapist), note
     marker advance, periodic key sweep, recompute serialization.
  T  Rate limiting & concurrency: limit off-by-one, window rollover
     boundary, probe-vs-failure counting, eviction policy, stale-window
     drop, XFF trust boundary, IPv6 /64 aggregation, lock overflow
     discipline, live-lock eviction, single-process guard.

A mutant is KILLED when any of its commands exits non-zero (or times out —
a hang is an observable behavior change).

Usage:
  python3 harness.py            # run all campaigns
  python3 harness.py O P        # run only campaigns O and P
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_DIR = pathlib.Path(__file__).resolve().parent / "results"
OUT_DIR.mkdir(exist_ok=True)

PY = ".venv/bin/python"
# The repo-root venv is the canonical interpreter (README); backend/.venv is
# not kept suite-healthy — every command runs the root venv absolutely.
ROOT_PY = os.environ.get("MUTATION_PY") or str(ROOT / ".venv" / "bin" / "python")


def backend_pytest(*targets: str, extra: tuple[str, ...] = ()) -> dict:
    return {
        "cwd": "backend",
        "cmd": [ROOT_PY, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider",
                "-m", "not slow", *extra, *targets],
        "timeout": 900,
        "kind": "pytest",
    }


MUTANTS: list[dict] = [
    # ---------------------------------------------------------------- O. authorization & access control
    dict(
        id="O1", campaign="O", name="token-epoch kill switch disabled (pre-logout bearer stays valid)",
        expectation="logout must retire every previously issued token",
        file="backend/app/deps.py",
        find='    if payload.get("ep", 1) != user.token_epoch:',
        replace="    if False:",
        tests=[backend_pytest("tests/test_auth_api.py", "tests/test_api_hardening_r3.py")],
    ),
    dict(
        id="O2", campaign="O", name="is_active check dropped (deactivated accounts authenticate)",
        expectation="a deactivated account must 401 on bearer use",
        file="backend/app/deps.py",
        find="    if user is None or not user.is_active:\n        raise failure",
        replace="    if user is None:\n        raise failure",
        tests=[backend_pytest("tests/test_hardening.py", "tests/test_auth_api.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="O3", campaign="O", name="journal role wall removed (therapist token reaches journal endpoints)",
        expectation="a therapist token must 403 on /entries and friends",
        file="backend/app/deps.py",
        find="    if user.role != ROLE_USER:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_therapist_api.py")],
    ),
    dict(
        id="O4", campaign="O", name="sharing role wall removed (patient token reaches therapist endpoints)",
        expectation="a patient token must 403 on /therapist/*",
        file="backend/app/deps.py",
        find="    if user.role != ROLE_THERAPIST:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_therapist_api.py")],
    ),
    dict(
        id="O5", campaign="O", name="revoked consent still authorizes therapist reads",
        expectation="revoked consent must read 404 everywhere",
        file="backend/app/api/therapist.py",
        find='    if consent is None or consent.status != "active":',
        replace="    if consent is None:",
        tests=[backend_pytest("tests/test_therapist_api.py")],
    ),
    dict(
        id="O6", campaign="O", name="note re-fetch drops therapist scoping (cross-therapist update/delete by id)",
        expectation="one therapist must never touch another's note id",
        file="backend/app/api/therapist.py",
        find="                    select(TherapistNote).where(\n                        TherapistNote.id == note_id, TherapistNote.therapist_id == user.id\n                    )",
        replace="                    select(TherapistNote).where(\n                        TherapistNote.id == note_id\n                    )",
        count=2,
        tests=[backend_pytest("tests/test_therapist_api.py")],
    ),
    dict(
        id="O7", campaign="O", name="revoke drops patient ownership (any patient revokes any consent id)",
        expectation="a consent id from another patient must 404",
        file="backend/app/api/consents.py",
        find="                    select(Consent)\n                    .where(Consent.id == consent_id, Consent.user_id == fresh_user.id)",
        replace="                    select(Consent)\n                    .where(Consent.id == consent_id)",
        tests=[backend_pytest("tests/test_therapist_api.py")],
    ),
    dict(
        id="O8", campaign="O", name="sharing feature flag fails open (disabled deployment serves sharing routes)",
        expectation="therapist_sharing_enabled=False must 404 the sharing surface",
        file="backend/app/deps.py",
        find='    if not bool(getattr(request.app.state.settings, "therapist_sharing_enabled", False)):',
        replace="    if False:",
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_hardening.py")],
    ),
    dict(
        id="O9", campaign="O", name="keystore owner binding removed (get + pop accept foreign tokens)",
        expectation="a token minted for one account must not serve another",
        file="backend/app/security/enclave.py",
        find="            if owner is not None and bound_owner is not None and owner != bound_owner:",
        replace="            if False:",
        count=2,
        tests=[backend_pytest("tests/test_enclave.py", "tests/test_hardening.py")],
    ),
    dict(
        id="O10", campaign="O", name="therapist enrollment-token gate removed (open self-enrollment)",
        expectation="a wrong X-Therapist-Enrollment-Token must 404 registration",
        file="backend/app/api/therapist.py",
        find="        if not hmac.compare_digest(provided_enrollment.encode(), expected_enrollment.encode()):",
        replace="        if False:",
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="O11", campaign="O", name="recompute pops the processing token without the owner pin",
        expectation="one user's session token must not steer another's recompute",
        file="backend/app/api/insights.py",
        find="        data_key = key_store.pop(x_processing_token, owner=user.id)",
        replace="        data_key = key_store.pop(x_processing_token, owner=None)",
        tests=[backend_pytest("tests/test_brain_api.py", "tests/test_enclave.py", "tests/test_adversarial.py")],
    ),
    # ---------------------------------------------------------------- P. database & ORM
    dict(
        id="P1", campaign="P", name="entries idempotency unique constraint dropped from the model",
        expectation="(user_id, client_entry_id) uniqueness must be enforced by the DB",
        file="backend/app/models.py",
        find='        UniqueConstraint("user_id", "client_entry_id", name="uq_user_client_entry"),',
        replace="",
        tests=[backend_pytest("tests/test_entries_api.py", "tests/test_migrations.py")],
    ),
    dict(
        id="P2", campaign="P", name="undated-insight partial unique index dropped (one-current-row backstop)",
        expectation="one current undated insight row per (user, kind) must be DB-enforced",
        file="backend/app/models.py",
        find='        Index(\n            "uq_insights_user_kind_undated",\n            "user_id",\n            "kind",\n            unique=True,\n            sqlite_where=text("for_date IS NULL"),\n            postgresql_where=text("for_date IS NULL"),\n        ),',
        replace="",
        tests=[backend_pytest("tests/test_insights_api.py", "tests/test_migrations.py")],
    ),
    dict(
        id="P3", campaign="P", name="Entry.user_id FK loses ondelete=CASCADE",
        expectation="oracle question: the explicit deletes make the cascade defense-in-depth?",
        file="backend/app/models.py",
        find='    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)\n    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))\n    client_entry_id: Mapped[str] = mapped_column(String(64))',
        replace='    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)\n    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))\n    client_entry_id: Mapped[str] = mapped_column(String(64))',
        tests=[backend_pytest("tests/test_account_api.py", "tests/test_adversarial.py", "tests/test_migrations.py")],
    ),
    dict(
        id="P4", campaign="P", name="_entry_dates drops SQL DISTINCT (duplicates to the threshold)",
        expectation="oracle question: does the service-level dedupe subsume the SQL one?",
        file="backend/app/api/insights.py",
        find="                select(Entry.entry_date)\n                .distinct()",
        replace="                select(Entry.entry_date)",
        tests=[backend_pytest("tests/test_threshold.py", "tests/test_insights_api.py", "tests/test_api_hardening_r3.py")],
    ),
    dict(
        id="P5", campaign="P", name="entries pagination loses the id tiebreak (unstable page order)",
        expectation="pages must be stable across requests for paginating clients",
        file="backend/app/api/entries.py",
        find="                metadata_query.order_by(\n                    Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc()\n                )",
        replace="                metadata_query.order_by(\n                    Entry.entry_date.asc(), Entry.received_at.asc()\n                )",
        tests=[backend_pytest("tests/test_entry_pagination_bytes.py", "tests/test_snapshot_revisions.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="P6", campaign="P", name="same-day question upsert no longer rewrites the blob",
        expectation="a repeated same-day recompute must store the fresh question",
        file="backend/app/api/insights.py",
        find='            set_={"blob": blob, "created_at": now},',
        replace='            set_={"created_at": now},',
        tests=[backend_pytest("tests/test_api_hardening_r3.py", "tests/test_insights_api.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="P7", campaign="P", name="undated insight replace deletes EVERY kind for the user",
        expectation="replacing patterns must not wipe the brain state or questions",
        file="backend/app/api/insights.py",
        find="            delete(Insight).where(Insight.user_id == user_id, Insight.kind == kind)",
        replace="            delete(Insight).where(Insight.user_id == user_id)",
        tests=[backend_pytest("tests/test_insights_api.py", "tests/test_brain_api.py")],
    ),
    dict(
        id="P9", campaign="P", name="entry-user re-fetch drops populate_existing (stale identity map)",
        expectation="the fresh authorization re-check must really re-read the row",
        file="backend/app/api/entries.py",
        find="    fresh = await session.get(User, user_id, populate_existing=True)",
        replace="    fresh = await session.get(User, user_id)",
        tests=[backend_pytest("tests/test_entries_api.py", "tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="P10", campaign="P", name="list_entries metadata query inverted (!= owner)",
        expectation="one user's page must never contain another's entries",
        file="backend/app/api/entries.py",
        find='            metadata_query = select(Entry.id, _blob_length(session).label("blob_bytes")).where(\n                Entry.user_id == fresh_user.id\n            )',
        replace='            metadata_query = select(Entry.id, _blob_length(session).label("blob_bytes")).where(\n                Entry.user_id != fresh_user.id\n            )',
        tests=[backend_pytest("tests/test_entries_api.py", "tests/test_adversarial.py")],
    ),
    dict(
        id="P11", campaign="P", name="revision-advance rowcount guard removed (unmarked mutation commits)",
        expectation="an entry write whose marker cannot advance must fail, not commit",
        file="backend/app/api/entries.py",
        find="    if db_rowcount(result) != 1:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_snapshot_revisions.py")],
    ),
    # ---------------------------------------------------------------- Q. boundary & business logic
    dict(
        id="Q1", campaign="Q", name="legacy entry page byte budget x100 (413 removed)",
        expectation="an unpaged request over 2 MiB ciphertext must 413",
        file="backend/app/api/entries.py",
        find="ENTRY_PAGE_BLOB_BYTES = 2 * 1024 * 1024",
        replace="ENTRY_PAGE_BLOB_BYTES = 200 * 1024 * 1024",
        tests=[backend_pytest("tests/test_entry_pagination_bytes.py", "tests/test_api_hardening_r3.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="Q2", campaign="Q", name="has_more probe row dropped (limit+1 -> limit)",
        expectation="a full page must still advertise a continuation",
        file="backend/app/api/entries.py",
        find="                .limit(limit + 1)",
        replace="                .limit(limit)",
        tests=[backend_pytest("tests/test_entry_pagination_bytes.py", "tests/test_snapshot_revisions.py")],
    ),
    dict(
        id="Q3", campaign="Q", name="per-chart note count quota disabled",
        expectation="note count over the cap must 413",
        file="backend/app/api/therapist.py",
        find="    if is_new and int(count) >= MAX_NOTES_PER_PATIENT:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="Q4", campaign="Q", name="per-chart note byte quota x1000",
        expectation="chart ciphertext over the cap must 413",
        file="backend/app/api/therapist.py",
        find="    if int(total) - previous_size + incoming > MAX_NOTE_BYTES_PER_PATIENT:",
        replace="    if int(total) - previous_size + incoming > MAX_NOTE_BYTES_PER_PATIENT * 1000:",
        tests=[backend_pytest("tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="Q5", campaign="Q", name="therapist evidence page size 25 -> 2500",
        expectation="the drill-down page must stay count-bounded",
        file="backend/app/api/therapist.py",
        find="THERAPIST_ENTRY_PAGE_SIZE = 25",
        replace="THERAPIST_ENTRY_PAGE_SIZE = 2500",
        tests=[backend_pytest("tests/test_therapist_api.py")],
    ),
    dict(
        id="Q6", campaign="Q", name="continuation advances by limit, not rows received",
        expectation="X-Next-Offset must be exactly offset + rows returned",
        file="backend/app/api/entries.py",
        find='                response.headers["X-Next-Offset"] = str(offset + len(result))',
        replace='                response.headers["X-Next-Offset"] = str(offset + limit)',
        tests=[backend_pytest("tests/test_entry_pagination_bytes.py")],
    ),
    dict(
        id="Q7", campaign="Q", name="question retention window 90 -> 900 days",
        expectation="dated question history older than 90 days must age out on recompute",
        file="backend/app/api/insights.py",
        find="QUESTION_RETENTION_DAYS = 90",
        replace="QUESTION_RETENTION_DAYS = 900",
        tests=[backend_pytest("tests/test_api_hardening_r3.py", "tests/test_deep_mutation_pins.py")],
    ),
    dict(
        id="Q8", campaign="Q", name="access-log retention x100 (prune never fires)",
        expectation="audit rows past the retention window must be deleted",
        file="backend/app/api/therapist.py",
        find="    return delete(AccessLog).where(AccessLog.at < now - timedelta(days=retention_days))",
        replace="    return delete(AccessLog).where(AccessLog.at < now - timedelta(days=retention_days * 100))",
        tests=[backend_pytest("tests/test_ops_fixes_2026_09_17b.py")],
    ),
    dict(
        id="Q9", campaign="Q", name="therapist caseload cap 100 -> 10,000",
        expectation="the caseload cap must 413 at the boundary",
        file="backend/app/api/consents.py",
        find="MAX_PATIENTS_PER_THERAPIST = 100",
        replace="MAX_PATIENTS_PER_THERAPIST = 10_000",
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="Q10", campaign="Q", name="wrapped-key size bound 256 -> 256,000",
        expectation="an oversized wrapped_key must 422",
        file="backend/app/api/consents.py",
        find="MAX_WRAPPED_KEY_BYTES = 256",
        replace="MAX_WRAPPED_KEY_BYTES = 256_000",
        tests=[backend_pytest("tests/test_sharing_crypto.py", "tests/test_therapist_api.py")],
    ),
    dict(
        id="Q11", campaign="Q", name="inner-date tolerance 1 -> 30 days",
        expectation="a far-off inner created_at must 400, not feed the decay math",
        file="backend/app/api/insights.py",
        find="INNER_DATE_TOLERANCE_DAYS = 1",
        replace="INNER_DATE_TOLERANCE_DAYS = 30",
        tests=[backend_pytest("tests/test_brain_api.py", "tests/test_brain_hardening_2026_09_17.py", "tests/test_deep_mutation_pins.py")],
    ),
    # ---------------------------------------------------------------- R. error handling & transactions
    dict(
        id="R1", campaign="R", name="error-envelope string fallback removed (non-string detail leaks)",
        expectation="detail must always render as a human string",
        file="backend/app/main.py",
        find="    if not isinstance(detail, str) or not detail:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_api_hardening_r3.py", "tests/test_hardening.py", "tests/test_deep_mutation_pins.py")],
    ),
    dict(
        id="R2", campaign="R", name="deep-JSON RecursionError arm retargeted (400 becomes 500)",
        expectation="deeply nested JSON must answer 400, not a 500",
        file="backend/app/middleware.py",
        find="        except RecursionError:",
        replace="        except IndexError:",
        tests=[backend_pytest("tests/test_hardening.py", "tests/test_api_hardening_r3.py", "tests/test_coverage_gaps.py")],
    ),
    dict(
        id="R3", campaign="R", name="middleware-produced responses drop the security header set",
        expectation="413/400/500 from the edge still carry every header",
        file="backend/app/middleware.py",
        find='                "headers": [(b"content-type", b"application/json"), *SECURITY_HEADERS],',
        replace='                "headers": [(b"content-type", b"application/json")],',
        tests=[backend_pytest("tests/test_hardening.py", "tests/test_api_hardening_r3.py", "tests/test_coverage_gaps.py")],
    ),
    dict(
        id="R4", campaign="R", name="recompute FK violation no longer maps to 410",
        expectation="account-deleted-during-recompute must 410, never a bare 500",
        file="backend/app/api/insights.py",
        find="                    if _is_fk_violation(exc):",
        replace="                    if False:",
        tests=[backend_pytest("tests/test_deep_mutation_pins.py", "tests/test_api_hardening_r3.py")],
    ),
    dict(
        id="R5", campaign="R", name="unique-violation classifier says yes to everything",
        expectation="a non-unique IntegrityError must not masquerade as 409",
        file="backend/app/api/entries.py",
        find='    return "unique" in str(orig).lower()',
        replace="    return True",
        tests=[backend_pytest("tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="R6", campaign="R", name="logout epoch bump becomes a stale read-modify-write",
        expectation="the bump must be a single atomic UPDATE expression",
        file="backend/app/api/auth.py",
        find="            update(User).where(User.id == user.id).values(token_epoch=User.token_epoch + 1)",
        replace="            update(User).where(User.id == user.id).values(token_epoch=user.token_epoch)",
        tests=[backend_pytest("tests/test_auth_api.py", "tests/test_api_hardening_r3.py")],
    ),
    dict(
        id="R7", campaign="R", name="export admission slot never released in the generator finally",
        expectation="after one export completes, the next must be admitted, not 503",
        file="backend/app/api/account.py",
        find="        finally:\n            if acquired_export_slot and export_limiter is not None:\n                export_limiter.release_on_behalf_of(export_borrower)",
        replace="        finally:\n            if acquired_export_slot and export_limiter is not None:\n                pass",
        tests=[backend_pytest("tests/test_api_resilience_coverage.py", "tests/test_adversarial.py")],
    ),
    dict(
        id="R8", campaign="R", name="grant commit conflict re-raises raw (409 contract lost)",
        expectation="a concurrent same-pair grant must 409, not 500",
        file="backend/app/api/consents.py",
        find='                raise ApiError(\n                    status_code=409, detail="consent already being granted", code="conflict"\n                ) from exc',
        replace="                raise",
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_api_resilience_coverage.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="R9", campaign="R", name="revoke lifecycle recheck disabled (deleted account still revokes)",
        expectation="a revoke that lost the lifecycle race must fail closed",
        file="backend/app/api/consents.py",
        find="    # This is the counterpart to the therapist content-read fence. It owns\n    # the patient key until the cleared key material and revoked status are\n    # committed, so no new read can see active consent after this returns.\n    async with sharing_locks.hold(sharing_patient_lock_key(user.id)):\n        fresh_user = await session.get(User, user.id, populate_existing=True)\n        if fresh_user is None or not fresh_user.is_active:\n            raise ApiError(status_code=404, detail=\"account not found\", code=\"not_found\")",
        replace="    # This is the counterpart to the therapist content-read fence. It owns\n    # the patient key until the cleared key material and revoked status are\n    # committed, so no new read can see active consent after this returns.\n    async with sharing_locks.hold(sharing_patient_lock_key(user.id)):\n        fresh_user = await session.get(User, user.id, populate_existing=True)\n        if False:\n            raise ApiError(status_code=404, detail=\"account not found\", code=\"not_found\")",
        tests=[backend_pytest("tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="R10", campaign="R", name="pairing-code retry loop swallows non-unique IntegrityErrors",
        expectation="only a unique violation may be retried; other errors raise",
        file="backend/app/api/therapist.py",
        find="            await session.rollback()\n            if not _is_unique_violation(exc):\n                raise",
        replace="            await session.rollback()\n            if False:\n                raise",
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    # ---------------------------------------------------------------- S. cache & invalidation
    dict(
        id="S1", campaign="S", name="processing-session TTL never expires at access (get + pop)",
        expectation="an expired session token must be refused and zeroized",
        file="backend/app/security/enclave.py",
        find="            if current >= expiry:",
        replace="            if False:",
        count=2,
        tests=[backend_pytest("tests/test_enclave.py")],
    ),
    dict(
        id="S2", campaign="S", name="owner purge is a no-op (logout/deletion leaves keys resident)",
        expectation="destroy_all_for_owner must wipe the account's sessions",
        file="backend/app/security/enclave.py",
        find="            doomed = [t for t, (_, _, o) in self._keys.items() if o == owner]",
        replace="            doomed = []",
        tests=[backend_pytest("tests/test_enclave.py", "tests/test_api_hardening_r3.py",
                             "tests/test_account_api.py")],
    ),
    dict(
        id="S3", campaign="S", name="per-owner processing-session cap removed",
        expectation="one account must not hoard the store's session slots",
        file="backend/app/security/enclave.py",
        find="                if owner_sessions >= self._max_sessions_per_owner:",
        replace="                if False:",
        tests=[backend_pytest("tests/test_enclave.py", "tests/test_hardening.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="S4", campaign="S", name="entry delete does not advance the snapshot revision",
        expectation="a delete must invalidate every continuation marker",
        file="backend/app/api/entries.py",
        find='            if db_rowcount(result) == 0:\n                raise ApiError(status_code=404, detail="entry not found", code="not_found")\n            await _increment_entries_revision(session, fresh_user)',
        replace='            if db_rowcount(result) == 0:\n                raise ApiError(status_code=404, detail="entry not found", code="not_found")\n            pass',
        tests=[backend_pytest("tests/test_snapshot_revisions.py")],
    ),
    dict(
        id="S5", campaign="S", name="stale marker comparison relaxed (!= -> <)",
        expectation="ANY divergence of the collection marker must 409, ahead or behind",
        file="backend/app/api/entries.py",
        find="    if expected_revision is not None and expected_revision != current_revision:",
        replace="    if expected_revision is not None and expected_revision < current_revision:",
        tests=[backend_pytest("tests/test_snapshot_revisions.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="S6", campaign="S", name="GET /insights serves the stored blob regardless of phase",
        expectation="baseline must reveal nothing, including stored leftovers",
        file="backend/app/api/insights.py",
        find="        if latest and state.phase is Phase.INSIGHT\n        else None",
        replace="        if latest\n        else None",
        tests=[backend_pytest("tests/test_insights_api.py", "tests/test_threshold.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="S7", campaign="S", name="therapist insights read serves the blob regardless of phase",
        expectation="the therapist view must phase-gate exactly like the patient's",
        file="backend/app/api/therapist.py",
        find="                if latest and state.phase is threshold.Phase.INSIGHT",
        replace="                if latest",
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_insights_api.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="S8", campaign="S", name="note write does not advance the therapist-global marker",
        expectation="note create/update must invalidate note continuations",
        file="backend/app/api/therapist.py",
        find="            if changed:\n                # The note and global therapist marker commit together. Note",
        replace="            if False:\n                # The note and global therapist marker commit together. Note",
        tests=[backend_pytest("tests/test_snapshot_revisions.py")],
    ),
    dict(
        id="S9", campaign="S", name="periodic processing-key sweep disabled",
        expectation="expired keys must not stay resident on an idle process",
        file="backend/app/main.py",
        find="        try:\n            app.state.key_store.purge_expired()",
        replace="        try:\n            pass",
        tests=[backend_pytest("tests/test_infra_coverage.py")],
    ),
    dict(
        id="S10", campaign="S", name="per-user recompute serialization broken (unique lock per call)",
        expectation="two recomputes for one account must serialize",
        file="backend/app/api/insights.py",
        find='        async with _recompute_locks.hold(f"insights:{user.id}"):',
        replace='        async with _recompute_locks.hold(f"insights:{user.id}:{time.monotonic()}"):',
        tests=[backend_pytest("tests/test_brain_api.py", "tests/test_insights_api.py")],
    ),
    # ---------------------------------------------------------------- T. rate limiting & concurrency
    dict(
        id="T1", campaign="T", name="limiter off-by-one (> -> >= rejects at the limit itself)",
        expectation="exactly `limit` requests must pass; the next 429s",
        file="backend/app/cache.py",
        find="        if result.count > limit:",
        replace="        if result.count >= limit:",
        tests=[backend_pytest("tests/test_rate_limit.py", "tests/test_mutation_pins.py")],
    ),
    dict(
        id="T2", campaign="T", name="window rollover boundary strict (>= -> >, hit + check)",
        expectation="a window aged exactly window_seconds must reset",
        file="backend/app/cache.py",
        find="            if current - start >= window_seconds:",
        replace="            if current - start > window_seconds:",
        count=2,
        tests=[backend_pytest("tests/test_hardening.py", "tests/test_mutation_pins.py")],
    ),
    dict(
        id="T3", campaign="T", name="keyed preflight counts the probe (check -> hit)",
        expectation="anonymous probes must not consume the victim's failure budget",
        file="backend/app/cache.py",
        find="    result = counter.check(key, window)",
        replace="    result = counter.hit(key, window)",
        tests=[backend_pytest("tests/test_rate_limit.py", "tests/test_redteam_fixes.py")],
    ),
    dict(
        id="T4", campaign="T", name="eviction by oldest window only (count ignored)",
        expectation="a real user's multi-hit bucket must be the LAST active key evicted",
        file="backend/app/cache.py",
        find="                overflow, self._hits, key=lambda k: (self._hits[k][0], self._hits[k][1])",
        replace="                overflow, self._hits, key=lambda k: (self._hits[k][1],)",
        tests=[backend_pytest("tests/test_mutation_pins.py", "tests/test_deep_mutation_pins.py", "tests/test_audit_fixes.py")],
    ),
    dict(
        id="T5", campaign="T", name="stale-window drop removed from eviction",
        expectation="eviction must clear stale windows first",
        file="backend/app/cache.py",
        find="        stale = [k for k, (_, s, w) in self._hits.items() if now - s >= w]",
        replace="        stale = []",
        tests=[backend_pytest("tests/test_mutation_pins.py", "tests/test_hardening.py")],
    ),
    dict(
        id="T6", campaign="T", name="XFF trusted whenever the flag is on (peer allowlist dropped)",
        expectation="a direct client forging X-Forwarded-For must not choose its bucket",
        file="backend/app/cache.py",
        find='    if trust_proxy_headers and getattr(request.state, "mindpattern_trusted_proxy", False):',
        replace="    if trust_proxy_headers:",
        tests=[backend_pytest("tests/test_infra_coverage.py", "tests/test_hardening.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="T7", campaign="T", name="IPv6 /64 aggregation removed",
        expectation="one device rotating IPv6 addresses must stay in ONE bucket",
        file="backend/app/cache.py",
        find='    return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address) + "/64"',
        replace="    return host",
        tests=[backend_pytest("tests/test_mutation_pins.py", "tests/test_hardening.py", "tests/test_audit_fixes.py")],
    ),
    dict(
        id="T8", campaign="T", name="lock overflow discipline dropped (fresh keys bypass the fallback)",
        expectation="absent keys must stay on the overflow lock until it drains",
        file="backend/app/locks.py",
        find="            if self._overflow_refs:",
        replace="            if False:",
        tests=[backend_pytest("tests/test_infra_coverage.py", "tests/test_mutation_pins_2026_09_19.py")],
    ),
    dict(
        id="T9", campaign="T", name="lock registry evicts LIVE entries (refs==0 -> True)",
        expectation="only idle lock entries may be recycled",
        file="backend/app/locks.py",
        find="                for stale in [k for k, v in self._locks.items() if v.refs == 0][",
        replace="                for stale in [k for k, v in self._locks.items() if True][",
        tests=[backend_pytest("tests/test_infra_coverage.py", "tests/test_deep_mutation_pins.py")],
    ),
    dict(
        id="T10", campaign="T", name="single-process guard never takes the flock",
        expectation="a second process serving the same deployment must refuse to boot",
        file="backend/app/singleprocess.py",
        find="        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)",
        replace="        pass",
        tests=[backend_pytest("tests/test_infra_coverage.py")],
    ),
]


def parse_failures(kind: str, output: str) -> list[str]:
    fails: list[str] = []
    if kind == "pytest":
        fails = re.findall(r"^(FAILED|ERROR) (\S+)", output, re.M)
    seen, ordered = set(), []
    for f in fails:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered[:8]


# pytest exit codes that mean the ORACLE (not the code under test) is
# broken: 2 interrupted, 3 internal error, 4 usage error (a renamed or
# deleted test file lands here), 5 no tests collected. Counting any of
# these as KILLED would print PASSED while verifying nothing — they are
# SETUP-ERRORs, reported loudly, never kills.
PYTEST_SETUP_EXITS = {2, 3, 4, 5}


def oracle_setup_error(kind: str, returncode: int, output: str) -> str | None:
    """Why this non-zero exit is a broken oracle rather than a kill, or None."""
    if kind != "pytest":
        return None
    if returncode in PYTEST_SETUP_EXITS:
        return f"pytest exited {returncode} (oracle broken, not a kill)"
    if "no tests ran" in output:
        return "pytest collected no tests (oracle broken, not a kill)"
    return None


def run_command(spec: dict, mutant_id: str) -> tuple[bool, str | None, list[str], str, float]:
    """One command against the mutated tree.

    Returns (failed, setup_error, failures, output, seconds). A non-zero
    pytest exit in PYTEST_SETUP_EXITS is a broken oracle (SETUP-ERROR),
    not a kill — oracle rot must not be able to green the gate."""
    env = dict(os.environ, CI="true")
    env["PATH"] = str(ROOT / ".tools/node/bin") + os.pathsep + env.get("PATH", "")
    # Round-2 hygiene: never write .pyc during mutant runs (same-second
    # apply/revert leaves stale MUTATED bytecode cached — found live in
    # round 2; every command runs with bytecode writing disabled).
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            spec["cmd"], cwd=ROOT / spec["cwd"], capture_output=True, text=True,
            timeout=spec["timeout"], env=env,
        )
        elapsed = round(time.monotonic() - t0, 1)
        out = (proc.stdout or "") + (proc.stderr or "")
        return (proc.returncode != 0,
                oracle_setup_error(spec["kind"], proc.returncode, out),
                parse_failures(spec["kind"], out), out[-1500:], elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - t0, 1)
        out = ((exc.stdout or b"").decode(errors="replace")
               + (exc.stderr or b"").decode(errors="replace"))
        return True, None, [], out, elapsed


def run_mutant(m: dict) -> dict:
    target = ROOT / m["file"]
    original = target.read_bytes()
    text = original.decode("utf-8")
    n = text.count(m["find"])
    want = m.get("count", 1)
    if n < want:
        return {**m, "killed": None, "status": "SETUP-ERROR",
                "detail": f"find-string matched {n} times, expected {want}"}
    mutated = text.replace(m["find"], m["replace"], want)
    target.write_text(mutated)
    specs = m["tests"] if isinstance(m["tests"], list) else [m["tests"]]
    try:
        per_cmd: list[dict] = []
        killed = False
        for spec in specs:
            failed, setup_error, failures, out, seconds = run_command(spec, m["id"])
            per_cmd.append({"kind": spec["kind"], "cmd": " ".join(spec["cmd"][:6]),
                            "failed": failed, "setup_error": setup_error,
                            "failures": failures, "seconds": seconds})
            if setup_error:
                # The oracle could not run (renamed test file, collection
                # crash, bad flag): a KILLED verdict here would verify
                # nothing. Fail loudly instead of green.
                return {**m, "killed": None, "status": "SETUP-ERROR",
                        "detail": f"{spec['kind']}: {setup_error}",
                        "commands": per_cmd}
            if failed:
                killed = True
                break  # first failing oracle is enough
        status = "KILLED" if killed else "SURVIVED"
        return {**m, "killed": killed, "status": status, "commands": per_cmd}
    finally:
        target.write_bytes(original)
        if target.read_bytes() != original:
            raise RuntimeError(f"RESTORE FAILED for {m['id']} — {m['file']}")
        # Belt and braces for the stale-bytecode hazard (round 2).
        pkg = target.parent / "__pycache__"
        if pkg.is_dir():
            stem = target.stem
            for cache in pkg.glob(f"{stem}.*.pyc"):
                cache.unlink(missing_ok=True)


def main() -> None:
    wanted = sys.argv[1:]
    todo = [m for m in MUTANTS if not wanted or m["campaign"] in wanted]
    print(f"{len(todo)} mutants queued\n", flush=True)
    results = []
    for m in todo:
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        r = run_mutant(m)
        results.append(r)
        if r["status"] == "SETUP-ERROR":
            print(f"    !! {r.get('detail', '')}", flush=True)
        else:
            which = " / ".join(
                f"{c['kind']}:{'fail' if c['failed'] else 'pass'}({c['seconds']}s)"
                for c in r.get("commands", [])
            )
            print(f"    -> {r['status']}  [{which}]"
                  + (f"  first: {r['commands'][0]['failures'][0]}"
                     if r.get("commands") and r["commands"][0]["failures"] else ""),
                  flush=True)
    killed = sum(1 for r in results if r["killed"])
    done = [r for r in results if r["killed"] is not None]
    print(f"\n{killed}/{len(done)} killed, {len(done) - killed} survived", flush=True)
    stamp = time.strftime("%Y-%m-%dT%H%M%S")
    path = OUT_DIR / f"mutation_results_{stamp}.json"
    path.write_text(json.dumps(results, indent=2))
    print(f"results: {path}")


if __name__ == "__main__":
    main()
