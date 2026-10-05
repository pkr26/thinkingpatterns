"""Real credential, SQLite authorization and one-use export capability contracts."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
AUTH_JTI = "a" * 32
EXPORT_JTI = "e" * 32


@asynccontextmanager
async def authorized(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / "tools/tests"))
    helper = importlib.import_module("test_backend_export_contracts")
    async with helper._fixture(monkeypatch, tmp_path, count=1) as db:
        from app.api.auth import hash_verifier
        from app.cache import SlidingWindowCounter
        from app.security.export_ticket import ExportTicketStore
        from app.security.step_up import StepUpProofStore
        from sqlalchemy import update

        db.password = b"p" * 32
        db.salt = b"s" * 16
        db.user.verifier = hash_verifier(db.password, db.salt, n=db.settings.scrypt_n)
        db.user.scrypt_salt = db.salt
        async with db.maker() as session:
            await session.execute(
                update(db.models.User)
                .where(db.models.User.id == db.user.id)
                .values(verifier=db.user.verifier, scrypt_salt=db.salt)
            )
            await session.commit()
        db.request.app.state.rate_counter = SlidingWindowCounter()
        db.request.app.state.step_up_store = StepUpProofStore()
        db.request.app.state.export_tickets = ExportTicketStore()
        db.request.state.mindpattern_token_jti = AUTH_JTI
        db.request.state.mindpattern_token_epoch = db.user.token_epoch
        yield db


def failure(exc, status, detail, code):
    assert (exc.value.status_code, exc.value.detail, exc.value.code) == (
        status,
        detail,
        code,
    )


def encoded(value):
    return base64.b64encode(value).decode()


def request(db, headers=None, chunks=None, query=b"", received=None):
    from starlette.requests import Request

    pending = list(chunks or [b""])

    async def receive():
        chunk = pending.pop(0)
        if received is not None:
            received.append(len(chunk))
        return {"type": "http.request", "body": chunk, "more_body": bool(pending)}

    scope = {
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "server": ("test", 80),
        "client": ("203.0.113.10", 443),
        "path": "/account/export-download",
        "query_string": query,
        "headers": [
            (key.lower().encode(), value.encode())
            for key, value in (headers or {}).items()
        ],
        "app": db.request.app,
    }
    return Request(scope, receive=receive)


async def ticket(db):
    from app.security import tokens
    from fastapi import Response

    bearer = tokens.issue_token(
        db.user.id,
        db.settings.auth_token_secret,
        300,
        epoch=db.user.token_epoch,
        ksv=db.settings.auth_secret_version,
        jti=EXPORT_JTI,
    )
    response = Response()
    req = request(db, {"Authorization": "Bearer " + bearer})
    result = await db.account.issue_export_ticket(req, response, db.user)
    assert response.headers["Cache-Control"] == "no-store"
    assert result["expires_in"] > 0
    return result["ticket"]


async def download(
    db,
    capability,
    session,
    query=b"",
    content_type="application/x-www-form-urlencoded; charset=UTF-8",
):
    raw = ("ticket=" + capability).encode()
    req = request(
        db, {"Content-Type": content_type}, chunks=[raw[:11], raw[11:]], query=query
    )
    response = await db.account.download_export(req, session)
    return response, req


async def content(response):
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk if isinstance(chunk, bytes) else chunk.encode())
    return json.loads(b"".join(chunks))


def test_verifier_gate_hashes_current_credentials_with_and_without_request_session(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.api.auth import hash_verifier
            from app.deps import ApiError
            from sqlalchemy import delete, update

            assert (
                await db.account._require_verifier(
                    db.user, encoded(db.password), db.request, None
                )
                is db.user
            )
            async with db.maker() as session:
                cached = await session.get(db.models.User, db.user.id)
                new_password = b"n" * 32
                new_salt = b"t" * 16
                async with db.maker() as rotation:
                    await rotation.execute(
                        update(db.models.User)
                        .where(db.models.User.id == db.user.id)
                        .values(
                            verifier=hash_verifier(
                                new_password, new_salt, n=db.settings.scrypt_n
                            ),
                            scrypt_salt=new_salt,
                        )
                    )
                    await rotation.commit()
                with pytest.raises(ApiError) as rejected:
                    await db.account._require_verifier(
                        cached, encoded(db.password), db.request, session
                    )
                failure(rejected, 403, "invalid credentials", "verification_failed")
                fresh = await db.account._require_verifier(
                    cached, encoded(new_password), db.request, session
                )
                assert fresh.scrypt_salt == new_salt
                # A row retired between bearer authentication and this check
                # deliberately falls back to its authenticated ORM snapshot;
                # the endpoint's lifecycle fence then decides account death.
                async with db.maker() as retirement:
                    await retirement.execute(
                        delete(db.models.User).where(db.models.User.id == db.user.id)
                    )
                    await retirement.commit()
                assert (
                    await db.account._require_verifier(
                        fresh, encoded(new_password), db.request, session
                    )
                    is fresh
                )

    asyncio.run(run())


def test_verifier_failures_share_one_user_budget_preserve_other_users_and_expire(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app import cache
            from app.deps import ApiError
            from sqlalchemy import update

            db.settings.verifier_failure_limit = 1
            db.settings.auth_rate_window = 3
            ticks = {"now": 0.0}
            monkeypatch.setattr(
                cache,
                "time",
                SimpleNamespace(monotonic=lambda: ticks["now"], time=time.time),
            )
            assert (
                await db.account._require_verifier(
                    db.user, encoded(db.password), db.request, None
                )
                is db.user
            )
            with pytest.raises(ApiError) as malformed:
                await db.account._require_verifier(
                    db.user, "!" + encoded(db.password), db.request, None
                )
            failure(malformed, 403, "invalid credentials", "verification_failed")
            async with db.maker() as session:
                await session.execute(
                    update(db.models.User)
                    .where(db.models.User.id == "foreign")
                    .values(
                        is_active=True, verifier=db.user.verifier, scrypt_salt=db.salt
                    )
                )
                await session.commit()
                other = await session.get(db.models.User, "foreign")
                other_request = request(db)
                other_request.state.mindpattern_token_jti = "f" * 32
                other_request.state.mindpattern_token_epoch = other.token_epoch
                assert (
                    await db.account._require_verifier(
                        other, encoded(db.password), other_request, session
                    )
                    is other
                )
            with pytest.raises(ApiError) as exhausted:
                await db.account._require_step_up_or_verifier(
                    db.user,
                    action="account_delete",
                    proof=None,
                    verifier=encoded(db.password),
                    request=db.request,
                    session=None,
                )
            assert (
                exhausted.value.status_code == 429
                and exhausted.value.code == "rate_limited"
            )
            ticks["now"] = 3.0
            assert (
                await db.account._require_verifier(
                    db.user, encoded(db.password), db.request, None
                )
                is db.user
            )

    asyncio.run(run())


def test_step_up_proofs_bind_the_authenticated_epoch_even_after_orm_refresh(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.schemas import StepUpRequest
            from sqlalchemy import update

            authenticated = db.user.token_epoch
            db.request.state.mindpattern_token_epoch = authenticated
            async with db.maker() as session:
                cached = await session.get(db.models.User, db.user.id)
                async with db.maker() as rotation:
                    await rotation.execute(
                        update(db.models.User)
                        .where(db.models.User.id == db.user.id)
                        .values(token_epoch=authenticated + 1)
                    )
                    await rotation.commit()
                body = StepUpRequest(
                    verifier=encoded(db.password), action="account_delete"
                )
                issued = await db.account.create_step_up_proof(
                    body, db.request, cached, session
                )
                assert cached.token_epoch == authenticated + 1
                # The actual store accepts the bearer-context epoch, not the
                # new ORM epoch populated while verifying the password.
                assert (
                    await db.account._require_step_up_or_verifier(
                        cached,
                        action="account_delete",
                        proof=issued.proof,
                        verifier=None,
                        request=db.request,
                        session=session,
                    )
                    is cached
                )
                issued = await db.account.create_step_up_proof(
                    body, db.request, cached, session
                )
                assert not await db.request.app.state.step_up_store.consume(
                    issued.proof,
                    user_id=cached.id,
                    action="account_delete",
                    token_jti=AUTH_JTI,
                    token_epoch=authenticated + 1,
                )

    asyncio.run(run())


@pytest.mark.parametrize("error", ["invalid-token", "capacity"])
def test_ticket_issue_has_exact_authentication_and_capacity_error_envelopes(
    monkeypatch, tmp_path, error
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from app.security import tokens
            from fastapi import Response

            headers = {"Authorization": "Bearer broken"}
            if error == "capacity":
                bearer = tokens.issue_token(
                    db.user.id, db.settings.auth_token_secret, 300
                )
                headers = {"Authorization": "Bearer " + bearer}

                def full(**kwargs):
                    raise RuntimeError("capacity reached")

                monkeypatch.setattr(db.request.app.state.export_tickets, "issue", full)
            with pytest.raises(ApiError) as refused:
                await db.account.issue_export_ticket(
                    request(db, headers), Response(), db.user
                )
            failure(
                refused,
                *(
                    (401, "invalid token", "unauthorized")
                    if error == "invalid-token"
                    else (
                        503,
                        "export service busy; retry shortly",
                        "service_unavailable",
                    )
                ),
            )

    asyncio.run(run())


def test_signed_export_ticket_consumes_once_and_returns_actual_ciphertext_bundle(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError

            cap = await ticket(db)
            async with db.maker() as session:
                response, _ = await download(db, cap, session)
                assert (
                    response.headers["Content-Disposition"]
                    == 'attachment; filename="fathom-export.json"'
                )
                assert response.headers["Cache-Control"] == "no-store"
                bundle = await content(response)
                assert bundle["entries"] == db.expected["entries"]
                assert bundle["username"] == "patient"
                with pytest.raises(ApiError) as replay:
                    await download(db, cap, session)
                failure(replay, 401, "invalid export ticket", "unauthorized")

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["role", "epoch", "inactive", "revoked", "query"])
def test_export_capability_refuses_changed_authorization_and_url_parameters(
    monkeypatch, tmp_path, mode
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from sqlalchemy import update

            cap = await ticket(db)
            if mode in ("role", "epoch", "inactive"):
                async with db.maker() as change:
                    await change.execute(
                        update(db.models.User)
                        .where(db.models.User.id == db.user.id)
                        .values(
                            **(
                                {"role": "therapist"}
                                if mode == "role"
                                else {"is_active": False}
                                if mode == "inactive"
                                else {"token_epoch": db.user.token_epoch + 1}
                            )
                        )
                    )
                    await change.commit()
            if mode == "revoked":
                db.request.app.state.token_revocations.revoke(
                    EXPORT_JTI, time.time() + 300
                )
            async with db.maker() as session:
                with pytest.raises(ApiError) as refused:
                    await download(
                        db,
                        cap,
                        session,
                        query=b"authorization=outside" if mode == "query" else b"",
                    )
                failure(
                    refused,
                    *(
                        (422, "invalid export form", "validation_error")
                        if mode == "query"
                        else (401, "invalid export ticket", "unauthorized")
                    ),
                )

    asyncio.run(run())


def test_export_forwards_the_ticket_jti_to_the_real_downstream_revocation_fence(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError

            cap = await ticket(db)
            store = db.request.app.state.token_revocations
            original = store.is_revoked_checked
            checks = []

            async def retire_after_first_check(session, jti, now=None):
                result = await original(session, jti, now)
                checks.append(jti)
                if len(checks) == 1:
                    store.revoke(EXPORT_JTI, time.time() + 300)
                return result

            monkeypatch.setattr(store, "is_revoked_checked", retire_after_first_check)
            async with db.maker() as session:
                with pytest.raises(ApiError) as refused:
                    await download(db, cap, session)
                failure(refused, 401, "invalid token", "unauthorized")
            assert checks == [EXPORT_JTI, EXPORT_JTI]

    asyncio.run(run())


@pytest.mark.parametrize("size", [128, 129, 256])
def test_export_form_byte_limit_counts_actual_stream_chunks_before_parsing(
    monkeypatch, tmp_path, size
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError

            raw = b"x" * size
            req = request(
                db,
                {"Content-Type": "application/x-www-form-urlencoded"},
                chunks=[raw[:64], raw[64:]],
            )
            async with db.maker() as session:
                with pytest.raises(ApiError) as refused:
                    await db.account.download_export(req, session)
                failure(
                    refused,
                    *(
                        (422, "invalid export form", "validation_error")
                        if size == 128
                        else (413, "export form too large", "payload_too_large")
                    ),
                )

    asyncio.run(run())


def test_oversized_export_chunk_is_rejected_before_reading_more_input(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError

            received = []
            req = request(
                db,
                {"Content-Type": "application/x-www-form-urlencoded"},
                chunks=[b"x" * 129, b"y" * 129],
                received=received,
            )
            async with db.maker() as session:
                with pytest.raises(ApiError) as refused:
                    await db.account.download_export(req, session)
                failure(refused, 413, "export form too large", "payload_too_large")
            # Once the first chunk exceeds the public 128-byte maximum,
            # the backend must reject before requesting more client input.
            assert received == [129]

    asyncio.run(run())


@pytest.mark.parametrize("content_type", [None, "application/json"])
def test_export_form_requires_its_native_media_type(
    monkeypatch, tmp_path, content_type
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError

            req = request(
                db,
                {} if content_type is None else {"Content-Type": content_type},
                chunks=[b"ticket=" + b"x" * 43],
            )
            async with db.maker() as session:
                with pytest.raises(ApiError) as refused:
                    await db.account.download_export(req, session)
                failure(refused, 422, "invalid export form", "validation_error")

    asyncio.run(run())


def test_download_and_direct_export_spend_the_same_configured_rate_window(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            import httpx
            from app.security import tokens

            db.settings.export_rate_limit = 1
            app = db.request.app

            async def session_dependency():
                async with db.maker() as session:
                    yield session

            app.dependency_overrides[db.account.get_session] = session_dependency
            app.include_router(db.account.router)
            bearer = tokens.issue_token(
                db.user.id,
                db.settings.auth_token_secret,
                300,
                epoch=db.user.token_epoch,
                ksv=db.settings.auth_secret_version,
                jti=EXPORT_JTI,
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, client=("203.0.113.10", 443)),
                base_url="http://test",
            ) as client:
                headers = {"Authorization": "Bearer " + bearer}
                direct = await client.get("/account/export", headers=headers)
                assert direct.status_code == 200
                assert direct.json()["entries"] == db.expected["entries"]
                issued = await client.post("/account/export-ticket", headers=headers)
                assert (
                    issued.status_code == 200
                    and issued.headers["Cache-Control"] == "no-store"
                )
                download = await client.post(
                    "/account/export-download",
                    content="ticket=" + issued.json()["ticket"],
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                assert download.status_code == 429

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["action", "jti", "replay"])
def test_step_up_refuses_wrong_binding_and_replayed_real_proofs(
    monkeypatch, tmp_path, mode
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from app.schemas import StepUpRequest

            async with db.maker() as session:
                issued = await db.account.create_step_up_proof(
                    StepUpRequest(
                        verifier=encoded(db.password), action="account_delete"
                    ),
                    db.request,
                    db.user,
                    session,
                )
                action = "llm_consent" if mode == "action" else "account_delete"
                if mode == "jti":
                    db.request.state.mindpattern_token_jti = "b" * 32
                if mode == "replay":
                    assert (
                        await db.account._require_step_up_or_verifier(
                            db.user,
                            action=action,
                            proof=issued.proof,
                            verifier=None,
                            request=db.request,
                            session=session,
                        )
                        is db.user
                    )
                with pytest.raises(ApiError) as rejected:
                    await db.account._require_step_up_or_verifier(
                        db.user,
                        action=action,
                        proof=issued.proof,
                        verifier=None,
                        request=db.request,
                        session=session,
                    )
                failure(
                    rejected,
                    403,
                    "step-up proof is invalid, expired, or already used",
                    "step_up_invalid",
                )

    asyncio.run(run())


def test_step_up_capacity_has_its_public_retry_envelope(monkeypatch, tmp_path):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from app.schemas import StepUpRequest

            async def full(**kwargs):
                raise RuntimeError("proof capacity exhausted")

            monkeypatch.setattr(db.request.app.state.step_up_store, "issue", full)
            async with db.maker() as session:
                with pytest.raises(ApiError) as rejected:
                    await db.account.create_step_up_proof(
                        StepUpRequest(
                            verifier=encoded(db.password), action="account_delete"
                        ),
                        db.request,
                        db.user,
                        session,
                    )
                failure(
                    rejected,
                    503,
                    "step-up service is temporarily at capacity",
                    "service_unavailable",
                )
                assert rejected.value.headers == {"Retry-After": "1"}

    asyncio.run(run())


def test_export_ticket_reported_lifetime_matches_its_real_download_capability(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from app.security import export_ticket, tokens
            from fastapi import Response

            ticks = {"now": 0.0}
            monkeypatch.setattr(
                export_ticket,
                "time",
                SimpleNamespace(monotonic=lambda: ticks["now"], time=time.time),
            )
            bearer = tokens.issue_token(
                db.user.id,
                db.settings.auth_token_secret,
                300,
                epoch=db.user.token_epoch,
                ksv=db.settings.auth_secret_version,
                jti=EXPORT_JTI,
            )
            caps = []
            for _ in range(2):
                caps.append(
                    await db.account.issue_export_ticket(
                        request(db, {"Authorization": "Bearer " + bearer}),
                        Response(),
                        db.user,
                    )
                )
            assert caps[0]["expires_in"] == caps[1]["expires_in"] > 0
            ticks["now"] = caps[0]["expires_in"] - 0.001
            async with db.maker() as session:
                response, _ = await download(db, caps[0]["ticket"], session)
                assert (await content(response))["entries"] == db.expected["entries"]
            ticks["now"] = caps[1]["expires_in"]
            async with db.maker() as session:
                with pytest.raises(ApiError) as expired:
                    await download(db, caps[1]["ticket"], session)
                failure(expired, 401, "invalid export ticket", "unauthorized")

    asyncio.run(run())


def test_sensitive_consent_requires_a_real_proof_or_fresh_verifier(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from app.schemas import VoiceConsentRequest

            async with db.maker() as session:
                with pytest.raises(ApiError) as rejected:
                    await db.account.set_voice_consent(
                        VoiceConsentRequest(enabled=False),
                        db.request,
                        db.user,
                        session,
                        None,
                    )
                failure(
                    rejected,
                    403,
                    "fresh authentication is required for this action",
                    "step_up_required",
                )

    asyncio.run(run())


def test_public_step_up_route_uses_its_configured_limit_and_expiring_window(
    monkeypatch, tmp_path
):
    async def run():
        async with authorized(monkeypatch, tmp_path) as db:
            import httpx
            from app import cache
            from app.security import tokens

            db.settings.auth_rate_limit = 1
            db.settings.auth_rate_window = 3
            ticks = {"now": 0.0}
            monkeypatch.setattr(
                cache,
                "time",
                SimpleNamespace(monotonic=lambda: ticks["now"], time=time.time),
            )
            app = db.request.app

            async def session_dependency():
                async with db.maker() as session:
                    yield session

            app.dependency_overrides[db.account.get_session] = session_dependency
            app.include_router(db.account.router)
            bearer = tokens.issue_token(
                db.user.id,
                db.settings.auth_token_secret,
                300,
                epoch=db.user.token_epoch,
                ksv=db.settings.auth_secret_version,
                jti=AUTH_JTI,
            )
            headers = {"Authorization": "Bearer " + bearer}
            payload = {"verifier": encoded(db.password), "action": "account_delete"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, client=("203.0.113.10", 443)),
                base_url="http://test",
            ) as client:
                first = await client.post(
                    "/account/step-up", headers=headers, json=payload
                )
                assert first.status_code == 200
                data = first.json()
                assert data["action"] == "account_delete" and data["expires_in"] > 0
                assert await app.state.step_up_store.consume(
                    data["proof"],
                    user_id=db.user.id,
                    action="account_delete",
                    token_jti=AUTH_JTI,
                    token_epoch=db.user.token_epoch,
                )
                exhausted = await client.post(
                    "/account/step-up", headers=headers, json=payload
                )
                assert exhausted.status_code == 429
                ticks["now"] = 3.0
                expired_window = await client.post(
                    "/account/step-up", headers=headers, json=payload
                )
                assert expired_window.status_code == 200

    asyncio.run(run())
