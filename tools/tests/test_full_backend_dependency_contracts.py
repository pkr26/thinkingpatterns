"""Authentication and transaction publication over actual SQLite sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


def signed(claims, secret="authentication-contract-secret"):
    body = (
        base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    signature = (
        base64.urlsafe_b64encode(
            hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"Bearer {body}.{signature}"


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("valid", 200),
        ("legacy", 200),
        ("therapist", 200),
        ("purpose", 401),
        ("signature", 401),
        ("missing", 401),
        ("empty", 401),
        ("prefix", 401),
        ("scheme", 401),
        ("revoked", 401),
        ("unknown", 401),
        ("inactive", 401),
        ("epoch", 401),
        ("previous", 200),
        ("previous_denied", 401),
        ("state_absent", 200),
        ("rekey_write", 409),
        ("rekey_retry", 200),
        ("rekey_sessions", 200),
        ("rekey_get", 200),
        ("rekey_head", 200),
        ("rekey_options", 200),
        ("rekey_account", 200),
        ("rekey_step_up", 200),
        ("rekey_logout", 200),
        ("rekey_llm", 200),
        ("rekey_voice", 200),
        ("rekey_delete_consent", 200),
        ("rekey_voice_consent", 200),
        ("rekey_post_consent", 409),
        ("deleted", 410),
        ("deleted_therapist", 410),
        ("deleted_tampered", 401),
        ("deleted_binary_mac", 401),
        ("deleted_legacy", 410),
        ("deleted_epoch", 401),
        ("deleted_purpose", 401),
        ("commit_fault", 200),
    ],
)
@pytest.mark.asyncio
async def test_authentication_keeps_exact_flat_failures_and_rekey_admission(
    change, expected, monkeypatch
):
    from app import deps
    from app.cache import TokenRevocationStore
    from app.db import build_engine, build_sessionmaker, init_models
    from app.models import RekeyJournal, User, utcnow
    from app.security.deletion_tombstone import new_deletion_tombstone

    secret, uid = "authentication-contract-secret", "owner"
    settings = SimpleNamespace(auth_token_secret=secret, auth_secret_version=2)
    store = TokenRevocationStore()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(settings=settings, token_revocations=store)
        ),
        state=SimpleNamespace(),
        method="GET",
        url=SimpleNamespace(path="/api/entries"),
    )
    claims = {
        "uid": uid,
        "exp": time.time() + 3600,
        "ep": 3,
        "ksv": 2,
        "jti": "a" * 32,
        "purpose": "patient",
    }
    engine = build_engine("sqlite+aiosqlite://")
    try:
        await init_models(engine)
        async with build_sessionmaker(engine)() as session:
            user = User(
                id=uid,
                username="owner",
                salt="salt",
                verifier=b"opaque",
                scrypt_salt=b"opaque",
                token_epoch=3,
                role="user",
            )
            session.add(user)
            await session.commit()
            if change == "legacy":
                for key in ("ep", "ksv", "purpose", "jti"):
                    claims.pop(key)
                user.token_epoch = 1
                settings.auth_secret_version = 1
            if change in ("therapist", "deleted_therapist"):
                user.role, claims["purpose"] = "therapist", "therapist"
            if change == "purpose":
                claims["purpose"] = "therapist"
            if change == "scheme":
                claims.pop("ksv")
            if change == "revoked":
                store.revoke("a" * 32, claims["exp"])
            if change == "unknown":
                claims["uid"] = "unknown"
            if change == "inactive":
                user.is_active = False
            if change in ("epoch", "previous", "previous_denied"):
                claims["ep"] = 2
            if change == "state_absent":
                del request.state
            if change.startswith("deleted"):
                user.is_active = False
                tombstone = new_deletion_tombstone(
                    user, secret=secret, auth_secret_version=2, now=utcnow()
                )
                if change == "deleted_tampered":
                    tombstone.record_mac = "0" * 64
                if change == "deleted_binary_mac":
                    tombstone.record_mac = b"corrupted SQLite record"
                if change == "deleted_legacy":
                    user.token_epoch = 1
                    tombstone.token_epoch = 1
                    from app.security.deletion_tombstone import (
                        compute_deletion_tombstone_mac,
                    )

                    tombstone.record_mac = compute_deletion_tombstone_mac(
                        secret, tombstone
                    )
                    claims.pop("ep")
                if change == "deleted_epoch":
                    claims["ep"] = 2
                if change == "deleted_purpose":
                    claims["purpose"] = "therapist"
                session.add(tombstone)
            if change.startswith("rekey"):
                session.add(
                    RekeyJournal(
                        user_id=uid,
                        operation_id="operation",
                        request_digest="d" * 64,
                        stage="entries",
                    )
                )
                request.method = "POST"
                request.url.path = {
                    "rekey_retry": "/api/v1/processing/rekey",
                    "rekey_sessions": "/api/processing/sessions",
                    "rekey_get": "/api/entries",
                    "rekey_head": "/api/entries",
                    "rekey_options": "/api/entries",
                    "rekey_account": "/api/account",
                    "rekey_step_up": "/api/account/step-up",
                    "rekey_logout": "/api/auth/logout",
                    "rekey_llm": "/api/account/llm-consent",
                    "rekey_voice": "/api/account/voice-consent",
                    "rekey_delete_consent": "/api/consents/share",
                    "rekey_voice_consent": "/api/consents/share/share-voice",
                    "rekey_post_consent": "/api/consents/share",
                }.get(change, "/api/v1/entries")
                if change == "rekey_get":
                    request.method = "GET"
                if change == "rekey_head":
                    request.method = "HEAD"
                if change == "rekey_options":
                    request.method = "OPTIONS"
                if change == "rekey_delete_consent":
                    request.method = "DELETE"
            await session.commit()
            authorization = signed(claims, secret)
            if change == "signature":
                authorization = signed(claims, "wrong-secret")
            if change == "missing":
                authorization = None
            if change == "empty":
                authorization = ""
            if change == "prefix":
                authorization = authorization.replace("Bearer ", "Basic ")
            if change == "commit_fault":

                async def failed():
                    raise RuntimeError("commit failed")

                monkeypatch.setattr(session, "commit", failed)
            if expected == 200:
                result = await deps._authenticate_user(
                    request,
                    authorization,
                    session,
                    allow_previous_epoch=change == "previous",
                )
                assert result.id == uid and result.username == "owner"
                if change != "state_absent":
                    assert request.state.mindpattern_token_jti == claims.get("jti")
                    assert request.state.mindpattern_token_epoch == claims.get("ep", 1)
                assert not session.in_transaction() or change == "commit_fault"
            else:
                with pytest.raises(deps.ApiError) as rejected:
                    await deps._authenticate_user(request, authorization, session)
                detail, code = {
                    401: ("invalid token", "unauthorized"),
                    409: (
                        "complete the pending key rotation before writing",
                        "rekey_in_progress",
                    ),
                    410: ("account no longer exists", "account_deleted"),
                }[expected]
                assert (
                    rejected.value.status_code,
                    rejected.value.detail,
                    rejected.value.code,
                ) == (expected, detail, code)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_role_mfa_and_feature_gates_preserve_exact_admission_and_refusals():
    from app import deps

    for role in ("user", "therapist", "other"):
        user = SimpleNamespace(role=role)
        if role == "user":
            assert await deps.require_regular_user(user) is user
        else:
            with pytest.raises(deps.ApiError) as rejected:
                await deps.require_regular_user(user)
            assert (
                rejected.value.status_code,
                rejected.value.detail,
                rejected.value.code,
            ) == (
                403,
                "therapist accounts cannot access journal endpoints",
                "forbidden",
            )
        if role == "therapist":
            assert await deps.require_therapist_account(user) is user
        else:
            with pytest.raises(deps.ApiError) as rejected:
                await deps.require_therapist_account(user)
            assert (
                rejected.value.status_code,
                rejected.value.detail,
                rejected.value.code,
            ) == (403, "not a therapist account", "forbidden")
    for enabled in (None, False, 1, True):
        user = SimpleNamespace(totp_enabled=enabled)
        if enabled is True:
            assert await deps.require_therapist(user) is user
        else:
            with pytest.raises(deps.ApiError) as rejected:
                await deps.require_therapist(user)
            assert (
                rejected.value.status_code,
                rejected.value.detail,
                rejected.value.code,
            ) == (
                403,
                "multi-factor enrollment is required before accessing patient data",
                "mfa_enrollment_required",
            )
    for enabled in (False, True, None):
        settings = (
            SimpleNamespace()
            if enabled is None
            else SimpleNamespace(therapist_sharing_enabled=enabled)
        )
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(settings=settings))
        )
        if enabled:
            await deps.require_sharing_enabled(request)
        else:
            with pytest.raises(deps.ApiError) as rejected:
                await deps.require_sharing_enabled(request)
            assert (
                rejected.value.status_code,
                rejected.value.detail,
                rejected.value.code,
            ) == (404, "not found", "not_found")


@pytest.mark.parametrize(
    "action",
    [
        "commit",
        "rollback",
        "savepoint_rollback",
        "savepoint_commit_outer_rollback",
        "tail",
        "error",
        "publication_fault",
    ],
)
@pytest.mark.asyncio
async def test_session_publishes_only_outer_committed_evidence_and_audio(
    action, monkeypatch, caplog
):
    from app import deps
    from app.api import _audit
    from app.db import build_engine, build_sessionmaker, init_models
    from app.services import audio_store
    from sqlalchemy import text

    engine = build_engine("sqlite+aiosqlite://")
    published, drained = [], []

    async def flush(session, path, failure_observer):
        published.append(
            (list(session.info["mindpattern_audit_journal_pending"]), path)
        )
        if action == "publication_fault":
            raise OSError("disk unavailable")

    async def drain(session, settings, identifiers):
        drained.append(list(identifiers))
        assert session is not original
        if action == "publication_fault":
            raise OSError("object store unavailable")

    monkeypatch.setattr(_audit, "flush_audit_journal", flush)
    monkeypatch.setattr(audio_store, "drain_audio_deletions", drain)
    settings = SimpleNamespace(audit_journal_path="durable-evidence")
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                sessionmaker=build_sessionmaker(engine),
                settings=settings,
                metrics=SimpleNamespace(observe_audit_journal_failure=lambda: None),
            )
        )
    )
    try:
        await init_models(engine)
        generator = deps.get_session(request)
        original = await anext(generator)
        await original.execute(text("SELECT 1"))
        original.info["mindpattern_audit_journal_pending"] = ["outer"]
        original.info["mindpattern_audio_deletions_pending"] = ["audio-outer"]
        if action in ("savepoint_rollback", "savepoint_commit_outer_rollback"):
            nested = await original.begin_nested()
            original.info["mindpattern_audit_journal_pending"].append("nested")
            original.info["mindpattern_audio_deletions_pending"].append("audio-nested")
            if action == "savepoint_rollback":
                await nested.rollback()
            else:
                await nested.commit()
        if action in ("rollback", "savepoint_commit_outer_rollback"):
            await original.rollback()
        elif action != "error":
            await original.commit()
            if action == "tail":
                await original.execute(text("SELECT 1"))
                original.info["mindpattern_audit_journal_pending"] = [
                    "uncommitted-tail"
                ]
                original.info["mindpattern_audio_deletions_pending"] = [
                    "audio-uncommitted-tail"
                ]
        if action == "error":
            with pytest.raises(RuntimeError, match="request failure"):
                await generator.athrow(RuntimeError("request failure"))
        else:
            with pytest.raises(StopAsyncIteration):
                await anext(generator)
        if action in ("commit", "tail", "savepoint_rollback", "publication_fault"):
            assert published == [(["outer"], "durable-evidence")]
            assert drained == [["audio-outer"]]
        else:
            assert published == [] and drained == []
        if action == "publication_fault":
            assert caplog.messages == [
                "post-commit audio cleanup deferred",
                "post-commit audit journal flush failed; readiness remains unhealthy",
            ]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_writer_rekey_gate_queries_the_actual_owner_and_returns_exact_refusals():
    from app import deps
    from app.db import build_engine, build_sessionmaker, init_models
    from app.models import RekeyJournal

    engine = build_engine("sqlite+aiosqlite://")
    try:
        await init_models(engine)
        async with build_sessionmaker(engine)() as session:
            session.add(RekeyJournal(user_id="owner"))
            await session.commit()
            await deps.ensure_no_rekey(session, "other")
            with pytest.raises(deps.ApiError) as rejected:
                await deps.ensure_no_rekey(session, "owner")
            assert (
                rejected.value.status_code,
                rejected.value.detail,
                rejected.value.code,
            ) == (
                409,
                "complete the pending key rotation before writing",
                "rekey_in_progress",
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_previous_epoch_retry_wrapper_preserves_role_and_exact_account_failures():
    from app import deps
    from app.cache import TokenRevocationStore
    from app.db import build_engine, build_sessionmaker, init_models
    from app.models import User

    engine = build_engine("sqlite+aiosqlite://")
    settings = SimpleNamespace(
        auth_token_secret="authentication-contract-secret", auth_secret_version=2
    )
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=settings, token_revocations=TokenRevocationStore()
            )
        ),
        state=SimpleNamespace(),
        method="GET",
    )
    try:
        await init_models(engine)
        async with build_sessionmaker(engine)() as session:
            user = User(
                id="owner",
                username="owner",
                salt="s",
                verifier=b"v",
                scrypt_salt=b"s",
                role="user",
                token_epoch=3,
            )
            session.add(user)
            await session.commit()
            claims = {"uid": "owner", "ep": 2, "ksv": 2, "exp": time.time() + 3600}
            assert (
                await deps.require_rekey_retry_user(request, signed(claims), session)
            ).id == "owner"
            user.role = "therapist"
            await session.commit()
            with pytest.raises(deps.ApiError) as rejected:
                await deps.require_rekey_retry_user(request, signed(claims), session)
            assert (
                rejected.value.status_code,
                rejected.value.detail,
                rejected.value.code,
            ) == (
                403,
                "therapist accounts cannot access journal endpoints",
                "forbidden",
            )
    finally:
        await engine.dispose()


@pytest.mark.parametrize("explicit_rollback", [False, True])
@pytest.mark.asyncio
async def test_failed_savepoint_flush_preserves_the_outer_committed_prefix(
    monkeypatch, explicit_rollback
):
    from app import deps
    from app.api import _audit
    from app.db import build_engine, build_sessionmaker, init_models
    from app.models import User
    from app.services import audio_store
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    published, deleted = [], []

    async def flush(session, path, failure_observer):
        published.extend(session.info["mindpattern_audit_journal_pending"])

    monkeypatch.setattr(_audit, "flush_audit_journal", flush)

    async def drain(session, settings, identifiers):
        deleted.extend(identifiers)

    monkeypatch.setattr(audio_store, "drain_audio_deletions", drain)
    engine = build_engine("sqlite+aiosqlite://")
    sessions = build_sessionmaker(engine)
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                sessionmaker=sessions,
                settings=SimpleNamespace(audit_journal_path="journal"),
                metrics=SimpleNamespace(observe_audit_journal_failure=lambda: None),
            )
        )
    )
    try:
        await init_models(engine)
        async with sessions() as seed:
            seed.add(
                User(
                    id="owner",
                    username="duplicate",
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await seed.commit()
        generator = deps.get_session(request)
        session = await anext(generator)
        await session.execute(text("SELECT 1"))
        session.info["mindpattern_audit_journal_pending"] = ["outer"]
        session.info["mindpattern_audio_deletions_pending"] = ["outer-audio"]

        async def conflict():
            session.info["mindpattern_audit_journal_pending"].append("failed-savepoint")
            session.info["mindpattern_audio_deletions_pending"].append(
                "failed-savepoint-audio"
            )
            session.add(
                User(
                    id="other",
                    username="duplicate",
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.flush()

        if explicit_rollback:
            nested = await session.begin_nested()
            with pytest.raises(IntegrityError):
                await conflict()
            await nested.rollback()
        else:
            with pytest.raises(IntegrityError):
                async with session.begin_nested():
                    await conflict()
        await session.commit()
        with pytest.raises(StopAsyncIteration):
            await anext(generator)
        assert published == ["outer"]
        assert deleted == ["outer-audio"]
    finally:
        await engine.dispose()


def test_framework_errors_have_the_released_machine_codes_and_preserve_headers():
    from app.deps import ApiError
    from app.main import _error_envelope

    expected = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        408: "request_timeout",
        409: "conflict",
        410: "gone",
        413: "payload_too_large",
        422: "validation_error",
        429: "rate_limited",
        500: "internal_error",
        503: "service_unavailable",
    }
    for status, code in expected.items():
        assert _error_envelope(status, "refused") == {"detail": "refused", "code": code}
    error = ApiError(429, "limited", "rate_limited", {"Retry-After": "3"})
    assert (error.status_code, error.detail, error.code, error.headers) == (
        429,
        "limited",
        "rate_limited",
        {"Retry-After": "3"},
    )


@pytest.mark.asyncio
async def test_outer_rollback_then_new_commit_does_not_publish_the_discarded_tail(
    monkeypatch,
):
    from app import deps
    from app.api import _audit
    from app.db import build_engine, build_sessionmaker, init_models
    from sqlalchemy import text

    published = []

    async def flush(session, path, failure_observer):
        published.extend(session.info["mindpattern_audit_journal_pending"])

    monkeypatch.setattr(_audit, "flush_audit_journal", flush)
    engine = build_engine("sqlite+aiosqlite://")
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                sessionmaker=build_sessionmaker(engine),
                settings=SimpleNamespace(audit_journal_path="journal"),
                metrics=SimpleNamespace(observe_audit_journal_failure=lambda: None),
            )
        )
    )
    try:
        await init_models(engine)
        generator = deps.get_session(request)
        session = await anext(generator)
        await session.execute(text("SELECT 1"))
        session.info["mindpattern_audit_journal_pending"] = ["rolled-back"]
        await session.rollback()
        await session.execute(text("SELECT 1"))
        session.info.setdefault("mindpattern_audit_journal_pending", []).append(
            "committed"
        )
        await session.commit()
        with pytest.raises(StopAsyncIteration):
            await anext(generator)
        assert published == ["committed"]
    finally:
        await engine.dispose()
