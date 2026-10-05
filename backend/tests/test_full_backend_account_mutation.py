"""Durable account lifecycle, proof and shared-budget behavior contracts."""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
from fastapi import FastAPI, Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.api import account, auth
from app.deps import (
    ApiError,
    get_session,
    require_regular_user,
    require_therapist_account,
    require_user,
)
from app.models import ConsentEvent, User
from app.schemas import (
    KeyEnvelopeUpgradeRequest,
    LlmConsentRequest,
    PasswordChangeRequest,
    RecoveryPasswordResetRequest,
    RecoverySetupRequest,
    TotpConfirmRequest,
    TotpSetupRequest,
    VoiceConsentRequest,
)
from app.security import totp
from app.security.enclave import InMemoryKeyStore
from app.security.kdf import canonical_kdf_params_json
from tests.test_full_backend_authentication_mutation import (
    AUTH_KEY,
    PARAMS,
    RECOVERY_KEY,
    authentication_db,  # noqa: F401 - shared isolated authentication fixture
    hash_proof,
)
from tests.test_full_backend_collection_mutation import (
    NOW,
    OWNER,
    b64,
    collection_db,  # noqa: F401 - imported authentication fixture dependency
    envelope,
)

DATA_KEY = b"d" * 32
NEW_AUTH_KEY = b"n" * 32
OPERATIONS = [
    "recovery",
    "clear",
    "password",
    "reset",
    "upgrade",
    "llm",
    "voice",
    "setup",
    "enable",
    "disable",
    "delete",
]


@pytest_asyncio.fixture
async def account_db(authentication_db, monkeypatch):  # noqa: F811
    db = authentication_db
    monkeypatch.setattr(account, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    monkeypatch.setattr(account, "lifecycle_locks", auth.lifecycle_locks)
    monkeypatch.setattr(account, "utcnow", lambda: NOW)
    monkeypatch.setattr(totp.time, "time", lambda: NOW.timestamp())
    db.settings.llm_url = "https://analysis.example.test"
    db.settings.stt_url = "https://transcription.example.test"
    db.request.app.state.sessionmaker = async_sessionmaker(db.engine, expire_on_commit=False)
    db.request.app.state.account_deletion_wakeup = asyncio.Event()
    db.request.app.state.account_deletion_backlog = False
    keys = InMemoryKeyStore()
    purge = keys.destroy_all_for_owner

    def destroy(owner):
        db.destroyed.append(owner)
        purge(owner)

    monkeypatch.setattr(keys, "destroy_all_for_owner", destroy)
    db.request.app.state.key_store = keys

    async def audit(session, **values):
        db.audit.append(values)

    monkeypatch.setattr(account, "append_access_log", audit)
    yield db


async def prepare(db, operation):
    db.owner.recovery_scheme = 2
    db.owner.recovery_salt = b"r" * 16
    db.owner.recovery_verifier = hash_proof(RECOVERY_KEY, b"r" * 16)
    db.owner.recovery_wrapped_data_key = b"w" * 60
    db.owner.recovery_set_at = NOW
    if operation in ["setup", "enable", "disable"]:
        db.owner.role = "therapist"
        db.owner.totp_secret = totp.wrap_secret(b"s" * 20, db.settings.totp_wrap_secret)
        db.owner.totp_enabled = operation == "disable"
        db.owner.totp_last_counter = int(NOW.timestamp() // 30) - 1
    await db.session.commit()
    db.processing_token = db.request.app.state.key_store.create(
        bytearray(DATA_KEY), 60, owner=OWNER
    )
    db.processing_key = db.request.app.state.key_store._keys[db.processing_token][0]


async def invoke(db, operation, body=None, token=None):
    credential = b64(AUTH_KEY)
    token = db.processing_token if token is None else token
    if operation == "recovery":
        return await account.set_recovery_envelope(
            body
            or RecoverySetupRequest(
                password_verifier=credential,
                verifier=b64(RECOVERY_KEY),
                wrapped_key=b64(b"w" * 60),
                scheme="v2",
            ),
            db.request,
            db.owner,
            db.session,
        )
    if operation == "clear":
        return await account.clear_recovery_envelope(db.request, db.owner, db.session, credential)
    if operation in ["password", "reset"]:
        values = dict(
            new_salt=b64(b"z" * 16), new_verifier=b64(NEW_AUTH_KEY), wrapped_data_key=b64(b"e" * 60)
        )
        if operation == "password":
            return await account.change_password(
                body or PasswordChangeRequest(verifier=credential, **values),
                db.request,
                db.owner,
                db.session,
                token,
            )
        return await account.reset_password_with_recovery_key(
            body or RecoveryPasswordResetRequest(proof=b64(RECOVERY_KEY), **values),
            db.request,
            db.owner,
            db.session,
            token,
        )
    if operation == "upgrade":
        return await account.upgrade_key_envelope(
            body or KeyEnvelopeUpgradeRequest(wrapped_data_key=b64(b"e" * 60)),
            db.request,
            db.owner,
            db.session,
            token,
            credential,
        )
    if operation in ["llm", "voice"]:
        function, model = (
            (account.set_llm_consent, LlmConsentRequest)
            if operation == "llm"
            else (account.set_voice_consent, VoiceConsentRequest)
        )
        return await function(
            body or model(enabled=True, verifier=credential), db.request, db.owner, db.session, None
        )
    if operation == "setup":
        return await account.totp_setup(
            TotpSetupRequest(verifier=credential), db.request, db.owner, db.session
        )
    if operation in ["enable", "disable"]:
        code = totp._code_for_counter(b"s" * 20, int(NOW.timestamp() // 30))
        function = account.totp_enable if operation == "enable" else account.totp_disable
        return await function(
            body or TotpConfirmRequest(verifier=credential, code=code),
            db.request,
            db.owner,
            db.session,
        )
    return await account.delete_account(db.request, None, db.owner, db.session, credential, None)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("changed", ["inactive", "epoch", "missing"])
async def test_account_mutations_reauthorize_real_database_state_after_queue(
    account_db, monkeypatch, operation, changed
):
    db = account_db
    await prepare(db, operation)
    original = account.lifecycle_locks

    class RetiringFence:
        @asynccontextmanager
        async def hold(self, key):
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                if changed == "missing":
                    await writer.execute(delete(User).where(User.id == OWNER))
                else:
                    await writer.execute(
                        update(User)
                        .where(User.id == OWNER)
                        .values(
                            **(
                                {"is_active": False}
                                if changed == "inactive"
                                else {"token_epoch": 3}
                            )
                        )
                    )
                await writer.commit()
            async with original.hold(key):
                yield

    monkeypatch.setattr(account, "lifecycle_locks", RetiringFence())
    with pytest.raises(ApiError) as failure:
        await invoke(db, operation)
    envelope(
        failure,
        401 if changed == "epoch" else 404,
        "invalid token" if changed == "epoch" else "account not found",
        "unauthorized" if changed == "epoch" else "not_found",
    )
    assert not db.audit and not db.destroyed
    if operation in ["password", "reset", "upgrade"]:
        assert db.processing_key == bytearray(32)


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_account_mutations_wait_for_shared_processing_lifecycle(account_db, operation):
    db = account_db
    await prepare(db, operation)
    async with account.lifecycle_locks.hold(f"llm-lifecycle:{OWNER}"):
        task = asyncio.create_task(invoke(db, operation))
        try:
            done, _ = await asyncio.wait({task}, timeout=0.05)
            assert not done and not db.audit and not db.destroyed
        finally:
            if task.done():
                task.result()
            else:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("operation", ["password", "reset", "upgrade"])
@pytest.mark.parametrize("params", [None, "stored", "explicit"])
async def test_account_envelope_swaps_persist_authoritative_credentials_and_keep_same_data_key(
    account_db, operation, params
):
    db = account_db
    await prepare(db, operation)
    if params == "stored":
        db.owner.kdf_params = canonical_kdf_params_json(PARAMS)
        await db.session.commit()
    fields = dict(wrapped_data_key=b64(b"e" * 60))
    if operation != "upgrade":
        fields.update(new_salt=b64(b"z" * 16), new_verifier=b64(NEW_AUTH_KEY))
    if params == "explicit":
        fields["kdf_params" if operation == "upgrade" else "new_kdf_params"] = PARAMS
    model = (
        KeyEnvelopeUpgradeRequest
        if operation == "upgrade"
        else PasswordChangeRequest
        if operation == "password"
        else RecoveryPasswordResetRequest
    )
    if operation != "upgrade":
        fields["verifier" if operation == "password" else "proof"] = b64(
            AUTH_KEY if operation == "password" else RECOVERY_KEY
        )
    await invoke(db, operation, model(**fields))
    await db.session.refresh(db.owner)
    assert db.owner.key_scheme == "v2" and db.owner.wrapped_data_key == b"e" * 60
    assert db.owner.kdf_params == canonical_kdf_params_json(PARAMS)
    assert db.owner.token_epoch == (2 if operation == "upgrade" else 3)
    if operation != "upgrade":
        assert db.owner.salt == b64(b"z" * 16)
        assert db.owner.verifier == hash_proof(NEW_AUTH_KEY, db.owner.scrypt_salt)
        assert db.destroyed == [OWNER]
    else:
        assert db.owner.verifier == hash_proof(AUTH_KEY, b"s" * 16) and not db.destroyed
    assert db.processing_key == bytearray(32)
    assert db.audit == [
        dict(
            actor_id=OWNER,
            actor_role="user",
            user_id=OWNER,
            action={
                "password": "credential_rotated",
                "reset": "password_reset_via_recovery",
                "upgrade": "key_envelope_upgrade",
            }[operation],
        )
    ]


async def test_account_recovery_kit_fields_and_status_are_created_and_completely_removed(
    account_db,
):
    db = account_db
    await prepare(db, "recovery")
    await invoke(db, "recovery")
    await db.session.refresh(db.owner)
    assert db.owner.recovery_verifier == hash_proof(RECOVERY_KEY, db.owner.recovery_salt)
    assert db.owner.recovery_wrapped_data_key == b"w" * 60 and db.owner.recovery_scheme == 2
    assert db.owner.recovery_set_at == NOW
    status = await account.get_recovery_status(db.owner)
    assert status.enabled and status.scheme == "v2" and status.set_at == NOW
    await invoke(db, "clear")
    await db.session.refresh(db.owner)
    assert all(
        getattr(db.owner, name) is None
        for name in [
            "recovery_salt",
            "recovery_verifier",
            "recovery_wrapped_data_key",
            "recovery_scheme",
            "recovery_set_at",
        ]
    )
    status = await account.get_recovery_status(db.owner)
    assert not status.enabled and status.scheme == "v1" and status.set_at is None
    assert [e["action"] for e in db.audit] == ["recovery_kit_created", "recovery_kit_removed"]


@pytest.mark.parametrize("kind", ["llm", "voice"])
async def test_account_provider_consent_events_retain_grant_and_withdrawal_evidence(
    account_db, kind
):
    db = account_db
    await prepare(db, kind)
    setattr(db.owner, kind + "_consent", False)
    await db.session.commit()
    first = await invoke(db, kind)
    assert first.enabled and first.active_for_current_policy
    disclosure = getattr(db.owner, kind + "_consent_disclosure")
    policy = getattr(db.owner, kind + "_consent_policy")
    assert disclosure and policy
    await invoke(db, kind)
    model = LlmConsentRequest if kind == "llm" else VoiceConsentRequest
    withdrawn = await invoke(db, kind, model(enabled=False, verifier=b64(AUTH_KEY)))
    assert not withdrawn.enabled and not withdrawn.active_for_current_policy
    events = list(
        (
            await db.session.scalars(
                select(ConsentEvent).order_by(ConsentEvent.occurred_at, ConsentEvent.id)
            )
        ).all()
    )
    assert sorted((e.kind, e.action, e.disclosure, e.policy) for e in events) == sorted(
        [(kind, "granted", disclosure, policy), (kind, "withdrawn", disclosure, policy)]
    )
    assert all(e.occurred_at == NOW for e in events)
    assert [e["action"] for e in db.audit] == [kind + "_consent_on", kind + "_consent_off"]


@pytest.mark.parametrize(
    "first,second",
    [
        (("PUT", "/account/recovery"), ("DELETE", "/account/recovery")),
        (("DELETE", "/account/recovery"), ("PUT", "/account/recovery")),
        (("PUT", "/account/llm-consent"), ("PUT", "/account/voice-consent")),
        (("PUT", "/account/voice-consent"), ("PUT", "/account/llm-consent")),
        (("POST", "/account/totp/setup"), ("POST", "/account/totp/enable")),
        (("POST", "/account/totp/enable"), ("POST", "/account/totp/disable")),
        (("POST", "/account/totp/disable"), ("POST", "/account/totp/setup")),
    ],
)
async def test_account_related_mutations_share_actual_http_rate_budget(account_db, first, second):
    db = account_db
    db.settings.auth_rate_limit = 2
    app = FastAPI()
    app.state = db.request.app.state
    app.include_router(account.router)

    async def user():
        return db.owner

    async def session():
        yield db.session

    for dependency in [require_user, require_regular_user, require_therapist_account]:
        app.dependency_overrides[dependency] = user
    app.dependency_overrides[get_session] = session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(2):
            response = await client.request(*first, json={})
            assert response.status_code != 429
        response = await client.request(*second, json={})
        assert response.status_code == 429


def test_account_access_history_public_page_bounds_and_default():
    app = FastAPI()
    app.include_router(account.router)
    parameters = app.openapi()["paths"]["/account/access-log"]["get"]["parameters"]
    limit = next(p["schema"] for p in parameters if p["name"] == "limit")
    assert (limit["default"], limit["minimum"], limit["maximum"]) == (50, 1, 200)


@pytest.mark.parametrize(
    "operation,field,value,detail",
    [
        (
            "recovery",
            "verifier",
            "!!!!" + b64(RECOVERY_KEY),
            "verifier and wrapped_key must be base64",
        ),
        (
            "recovery",
            "wrapped_key",
            "!!!!" + b64(b"w" * 60),
            "verifier and wrapped_key must be base64",
        ),
        ("recovery", "verifier", b64(b"r" * 31), "verifier must be exactly 32 bytes"),
        ("recovery", "verifier", b64(b"r" * 33), "verifier must be exactly 32 bytes"),
        ("recovery", "wrapped_key", b64(b"w" * 59), "wrapped_key must be exactly 60 bytes"),
        ("recovery", "wrapped_key", b64(b"w" * 61), "wrapped_key must be exactly 60 bytes"),
        *[
            (op, field, "!!!!" + b64(value), detail)
            for op, fields, detail in [
                (
                    "password",
                    [
                        ("new_salt", b"z" * 16),
                        ("new_verifier", NEW_AUTH_KEY),
                        ("wrapped_data_key", b"e" * 60),
                    ],
                    "new_salt, new_verifier and wrapped_data_key must be base64",
                ),
                (
                    "reset",
                    [
                        ("proof", RECOVERY_KEY),
                        ("new_salt", b"z" * 16),
                        ("new_verifier", NEW_AUTH_KEY),
                        ("wrapped_data_key", b"e" * 60),
                    ],
                    "proof, new_salt, new_verifier and wrapped_data_key must be base64",
                ),
                ("upgrade", [("wrapped_data_key", b"e" * 60)], "wrapped_data_key must be base64"),
            ]
            for field, value in fields
        ],
        *[
            (op, field, b64(letter * length), detail)
            for op in ["password", "reset"]
            for field, letter, lengths, detail in [
                ("new_salt", b"z", [15, 17], "new_salt must be exactly 16 bytes"),
                ("new_verifier", b"n", [31, 33], "new_verifier must be 32 bytes"),
                ("wrapped_data_key", b"e", [59, 61], "wrapped_data_key must be exactly 60 bytes"),
            ]
            for length in lengths
        ],
        (
            "upgrade",
            "wrapped_data_key",
            b64(b"e" * 59),
            "wrapped_data_key must be exactly 60 bytes",
        ),
        (
            "upgrade",
            "wrapped_data_key",
            b64(b"e" * 61),
            "wrapped_data_key must be exactly 60 bytes",
        ),
    ],
)
async def test_account_key_envelope_wire_validation_is_strict_and_exact(
    account_db, operation, field, value, detail
):
    db = account_db
    await prepare(db, operation)
    if operation == "recovery":
        body = RecoverySetupRequest(
            password_verifier=b64(AUTH_KEY),
            verifier=b64(RECOVERY_KEY),
            wrapped_key=b64(b"w" * 60),
            scheme="v2",
        )
    elif operation == "upgrade":
        body = KeyEnvelopeUpgradeRequest(wrapped_data_key=b64(b"e" * 60))
    else:
        fields = dict(
            new_salt=b64(b"z" * 16), new_verifier=b64(NEW_AUTH_KEY), wrapped_data_key=b64(b"e" * 60)
        )
        body = (
            PasswordChangeRequest(verifier=b64(AUTH_KEY), **fields)
            if operation == "password"
            else RecoveryPasswordResetRequest(proof=b64(RECOVERY_KEY), **fields)
        )
    body = body.model_copy(update={field: value})
    with pytest.raises(ApiError) as failure:
        await invoke(db, operation, body)
    envelope(failure, 422, detail, "validation_error")
    assert db.owner.token_epoch == 2 and not db.audit and db.processing_key == bytearray(DATA_KEY)


@pytest.mark.parametrize("operation", ["password", "reset", "upgrade"])
@pytest.mark.parametrize("missing", [False, True])
async def test_account_key_envelope_requires_a_live_owner_bound_processing_key(
    account_db, operation, missing
):
    db = account_db
    await prepare(db, operation)
    with pytest.raises(ApiError) as failure:
        await invoke(db, operation, token="" if missing else "unknown-session")
    envelope(
        failure,
        422 if missing else 403,
        "processing session token required (X-Processing-Token)"
        if missing
        else "processing session missing or expired",
        "processing_session_required" if missing else "processing_session_invalid",
    )
    assert not db.audit and not db.destroyed and db.owner.token_epoch == 2


@pytest.mark.parametrize("operation", ["password", "reset", "upgrade"])
@pytest.mark.parametrize("stored", [False, True])
async def test_account_key_envelope_invalid_kdf_profiles_fail_closed_before_key_consumption(
    account_db, operation, stored
):
    db = account_db
    await prepare(db, operation)
    if stored:
        db.owner.kdf_params = '{"algorithm":"unknown"}'
        await db.session.commit()
    fields = dict(wrapped_data_key=b64(b"e" * 60))
    if operation != "upgrade":
        fields.update(new_salt=b64(b"z" * 16), new_verifier=b64(NEW_AUTH_KEY))
    if not stored:
        fields["kdf_params" if operation == "upgrade" else "new_kdf_params"] = {
            "algorithm": "unknown"
        }
    if operation != "upgrade":
        fields["verifier" if operation == "password" else "proof"] = b64(
            AUTH_KEY if operation == "password" else RECOVERY_KEY
        )
    model = (
        KeyEnvelopeUpgradeRequest
        if operation == "upgrade"
        else PasswordChangeRequest
        if operation == "password"
        else RecoveryPasswordResetRequest
    )
    with pytest.raises(ApiError) as failure:
        await invoke(db, operation, model(**fields))
    envelope(
        failure,
        409 if stored else 422,
        "stored kdf_params are invalid; contact the operator"
        if stored
        else "kdf_params.algorithm must be 'pbkdf2-sha256' or 'argon2id'",
        "envelope_key_mismatch" if stored else "validation_error",
    )
    assert not db.audit and not db.destroyed and db.processing_key == bytearray(DATA_KEY)


async def test_account_totp_lifecycle_preserves_other_accounts_and_retains_exact_audits(
    account_db, monkeypatch
):
    from app.models import TotpBackupCode
    from app.security.sharing import backup_code_digest

    db = account_db
    await prepare(db, "setup")
    result = await invoke(db, "setup")
    encoded_secret = result.secret_base32
    raw = base64.b32decode(encoded_secret + "=" * (-len(encoded_secret) % 8))
    await db.session.refresh(db.owner)
    assert totp.unwrap_secret(db.owner.totp_secret, db.settings.totp_wrap_secret) == raw
    assert not db.owner.totp_enabled and db.owner.totp_last_counter is None
    assert result.otpauth_uri == totp.otpauth_uri(result.secret_base32, db.owner.username)
    foreign = TotpBackupCode(user_id=db.other.id, digest="other-backup")
    stale = TotpBackupCode(user_id=OWNER, digest="old-backup")
    db.session.add_all([foreign, stale])
    await db.session.commit()
    code = totp._code_for_counter(raw, int(NOW.timestamp() // 30))
    enabled = await invoke(db, "enable", TotpConfirmRequest(verifier=b64(AUTH_KEY), code=code))
    own = list(
        (
            await db.session.scalars(select(TotpBackupCode).where(TotpBackupCode.user_id == OWNER))
        ).all()
    )
    assert len(own) == 8 and {r.digest for r in own} == {
        backup_code_digest(c, db.settings.totp_wrap_secret) for c in enabled.backup_codes
    }
    assert await db.session.get(TotpBackupCode, foreign.id) is not None
    await db.session.refresh(db.owner)
    assert db.owner.totp_enabled and db.owner.totp_last_counter == int(NOW.timestamp() // 30)
    with pytest.raises(ApiError) as failure:
        await invoke(db, "disable", TotpConfirmRequest(verifier=b64(AUTH_KEY), code=code))
    envelope(failure, 403, "invalid totp code", "totp_code_invalid")
    monkeypatch.setattr(totp.time, "time", lambda: NOW.timestamp() + 30)
    code = totp._code_for_counter(raw, int(NOW.timestamp() // 30) + 1)
    await invoke(db, "disable", TotpConfirmRequest(verifier=b64(AUTH_KEY), code=code))
    await db.session.refresh(db.owner)
    assert (
        db.owner.totp_secret is None
        and db.owner.totp_enabled is None
        and db.owner.totp_last_counter is None
    )
    assert not list(
        (
            await db.session.scalars(select(TotpBackupCode).where(TotpBackupCode.user_id == OWNER))
        ).all()
    )
    assert await db.session.get(TotpBackupCode, foreign.id) is not None
    assert [e["action"] for e in db.audit] == ["totp_setup", "totp_enable", "totp_disable"]


async def test_account_totp_enable_refuses_replaced_pending_secret_after_code_proof(
    account_db, monkeypatch
):
    db = account_db
    await prepare(db, "enable")
    original = account.lifecycle_locks
    changed_secret = totp.wrap_secret(b"t" * 20, db.settings.totp_wrap_secret)

    class ChangedSetup:
        @asynccontextmanager
        async def hold(self, key):
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(
                    update(User).where(User.id == OWNER).values(totp_secret=changed_secret)
                )
                await writer.commit()
            async with original.hold(key):
                yield

    monkeypatch.setattr(account, "lifecycle_locks", ChangedSetup())
    with pytest.raises(ApiError) as failure:
        await invoke(db, "enable")
    envelope(failure, 409, "totp setup changed, confirm again", "version_conflict")
    assert not db.audit
    await db.session.refresh(db.owner)
    assert db.owner.totp_secret == changed_secret and not db.owner.totp_enabled


@pytest.mark.parametrize("deferred", [False, True])
async def test_account_erasure_commits_retirement_signals_backlog_and_keeps_terminal_audit(
    account_db, monkeypatch, caplog, deferred
):
    from app.services import account_deletion

    db = account_db
    await prepare(db, "delete")
    if deferred:

        async def unavailable(*args, **kwargs):
            raise OSError("purge storage unavailable")

        monkeypatch.setattr(account_deletion, "purge_one_account_page", unavailable)
    await invoke(db, "delete")
    assert db.request.app.state.account_deletion_backlog is deferred
    assert db.request.app.state.account_deletion_wakeup.is_set()
    assert db.destroyed == [OWNER] and db.processing_key == bytearray(32)
    assert db.audit == [
        dict(actor_id=OWNER, actor_role="user", user_id=OWNER, action="account_deleted")
    ]
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as reader:
        stored = await reader.get(User, OWNER)
        assert (stored is not None and not stored.is_active) if deferred else stored is None
    if deferred:
        assert caplog.messages[-1] == "bounded account purge deferred to background worker"
        assert caplog.records[-1].name == "mindpattern.account"
        assert caplog.records[-1].levelname == "ERROR"


async def seed_proof(db, kind, owner=OWNER, key=DATA_KEY, *, expired=False):
    from datetime import timedelta

    from app.models import AudioAttachment, Entry, Insight, Measure
    from app.security import crypto
    from app.security.entry_guard import seal_entry_guard
    from app.services.audio_store import storage_locator

    client = "proof-ciphertext"
    if kind == "entry":
        blob = crypto.encrypt(key, b"private journal", crypto.entry_aad_v2(owner, client, 1))
        row = Entry(
            user_id=owner,
            client_entry_id=client,
            entry_date=NOW.date(),
            received_at=NOW,
            content_version=1,
            blob=blob,
        )
        seal_entry_guard(row, db.settings, v2_bound=True)
    elif kind in ["patterns", "question"]:
        day = NOW.date() if kind == "question" else None
        aad = (
            crypto.build_aad("question", owner, day.isoformat())
            if day
            else crypto.build_aad("insights", owner, kind)
        )
        row = Insight(
            user_id=owner,
            kind=kind,
            for_date=day,
            blob=crypto.encrypt(key, b"private analysis", aad),
            created_at=NOW,
        )
    elif kind == "measure":
        row = Measure(
            user_id=owner,
            client_measure_id=client,
            measure_date=NOW.date(),
            received_at=NOW,
            blob=crypto.encrypt(
                key, b"private measure", crypto.build_aad("measure", owner, client)
            ),
        )
    else:
        blob = crypto.encrypt(key, b"private audio", crypto.build_aad("audio", owner, client, "1"))
        storage_key = f"audio/{owner}/{'c' * 32}.enc"
        await db.store.put(storage_key, blob)
        row = AudioAttachment(
            user_id=owner,
            client_entry_id=client,
            backend="local",
            storage_key=storage_key,
            storage_locator=storage_locator(db.store),
            size_bytes=len(blob),
            mime_type="audio/webm",
            duration_seconds=1,
            content_version=1,
            created_at=NOW,
            expires_at=NOW if expired else NOW + timedelta(days=1),
        )
    db.session.add(row)
    await db.session.commit()
    return row


@pytest.mark.parametrize("kind", ["entry", "patterns", "question", "measure", "audio"])
async def test_account_data_key_proof_authenticates_each_real_encrypted_store_and_its_owner(
    account_db, kind
):
    db = account_db
    await seed_proof(db, kind)
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
        is True
    )
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(b"x" * 32), db.settings
        )
        is False
    )


@pytest.mark.parametrize("kind", ["entry", "patterns", "question", "measure", "audio"])
async def test_account_data_key_proof_ignores_other_patients_ciphertext(account_db, kind):
    db = account_db
    db.other.role = "user"
    await db.session.commit()
    await seed_proof(db, kind, owner=db.other.id, key=b"o" * 32)
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
        is True
    )


async def test_account_data_key_proof_refuses_tampered_entry_guard(account_db):
    db = account_db
    row = await seed_proof(db, "entry")
    row.aad_guard_mac = "0" * 64
    await db.session.commit()
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
        is False
    )


async def test_account_data_key_proof_accepts_a_trusted_pre_upgrade_entry(account_db):
    from app.security import crypto
    from app.security.entry_guard import seal_entry_guard

    db = account_db
    row = await seed_proof(db, "entry")
    row.blob = crypto.encrypt(
        DATA_KEY,
        b"journal retained from before versioned entry bindings",
        crypto.build_aad("entry", OWNER, row.client_entry_id),
    )
    seal_entry_guard(row, db.settings, v2_bound=False)
    await db.session.commit()
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
        is True
    )
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(b"x" * 32), db.settings
        )
        is False
    )


@pytest.mark.parametrize("owned", [False, True])
async def test_account_data_key_proof_pending_rotation_scope_and_flat_retry_contract(
    account_db, owned
):
    from app.models import RekeyJournal

    db = account_db
    db.session.add(RekeyJournal(user_id=OWNER if owned else db.other.id, stage="measures"))
    await db.session.commit()
    if not owned:
        assert (
            await account._prove_current_data_key(
                db.session, db.owner, bytearray(DATA_KEY), db.settings
            )
            is True
        )
        return
    with pytest.raises(ApiError) as failure:
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
    envelope(failure, 409, "complete the pending key rotation first", "rekey_in_progress")


@pytest.mark.parametrize("unavailable", ["unconfigured", "missing"])
async def test_account_data_key_proof_audio_storage_failure_is_retryable_and_flat(
    account_db, monkeypatch, unavailable
):
    from app.services import audio_store

    db = account_db
    row = await seed_proof(db, "audio")
    if unavailable == "unconfigured":
        monkeypatch.setattr(audio_store, "store_for_object", lambda *args: None)
    else:
        await db.store.delete(row.storage_key)
    with pytest.raises(ApiError) as failure:
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
    envelope(failure, 503, "audio key proof storage unavailable", "audio_store_error")


async def test_account_data_key_proof_exactly_expired_audio_does_not_make_empty_corpus_nonempty(
    account_db,
):
    db = account_db
    await seed_proof(db, "audio", key=b"expired".ljust(32, b"x"), expired=True)
    assert (
        await account._prove_current_data_key(
            db.session, db.owner, bytearray(DATA_KEY), db.settings
        )
        is True
    )


@pytest.mark.parametrize("operation", ["password", "reset", "upgrade"])
async def test_account_envelope_swap_cannot_replace_data_key_without_real_ciphertext_possession(
    account_db, operation
):
    db = account_db
    await prepare(db, operation)
    await seed_proof(db, "measure", key=b"actual".ljust(32, b"x"))
    with pytest.raises(ApiError) as failure:
        await invoke(db, operation)
    envelope(
        failure,
        403,
        "the processing session's key did not authenticate stored ciphertext; open a session with the account's current data key",
        "envelope_key_mismatch",
    )
    assert db.owner.token_epoch == 2 and not db.audit and not db.destroyed
    assert db.processing_key == bytearray(32)


@pytest.mark.parametrize("terminal", [False, True])
async def test_account_access_history_preserves_retired_actors_subject_privacy_and_exact_continuation(
    account_db, terminal
):
    from app.models import AccessLog

    db = account_db
    own = [
        AccessLog(
            id="1" * 32,
            user_id=OWNER,
            actor_id=OWNER,
            actor_role="patient",
            action="self-change",
            at=NOW,
            chain_seq=1,
        ),
        AccessLog(
            id="2" * 32,
            user_id=OWNER,
            actor_id=db.other.id,
            actor_role="therapist",
            action="read_entries",
            at=NOW,
            chain_seq=2,
        ),
    ]
    if not terminal:
        own.append(
            AccessLog(
                id="3" * 32,
                user_id=OWNER,
                actor_id="deleted-actor",
                actor_role="therapist",
                action="read_measures",
                at=NOW,
                chain_seq=3,
            )
        )
    db.session.add_all(
        own
        + [
            AccessLog(
                id="f" * 32,
                user_id=db.other.id,
                actor_id=db.other.id,
                actor_role="therapist",
                action="another-patients-history",
                at=NOW,
                chain_seq=1,
            )
        ]
    )
    await db.session.commit()
    response = Response()
    rows = await account.read_own_access_log(db.request, response, db.owner, db.session, 2, None)
    expected = (
        [("read_entries", "therapist", "Clinician"), ("self-change", "self", None)]
        if terminal
        else [("read_measures", "therapist", None), ("read_entries", "therapist", "Clinician")]
    )
    assert [(r.action, r.actor, r.actor_name) for r in rows] == expected
    assert all(r.at == NOW for r in rows)
    if terminal:
        assert "X-Next-Cursor" not in response.headers
    else:
        cursor = NOW.isoformat() + "|" + "2" * 32
        assert response.headers["X-Next-Cursor"] == cursor
        next_response = Response()
        older = await account.read_own_access_log(
            db.request, next_response, db.owner, db.session, 2, cursor
        )
        assert [(r.action, r.actor, r.actor_name) for r in older] == [("self-change", "self", None)]
        assert "X-Next-Cursor" not in next_response.headers


@pytest.mark.parametrize("missing", ["recovery_verifier", "recovery_salt"])
async def test_account_recovery_password_requires_both_stored_proof_components(account_db, missing):
    db = account_db
    await prepare(db, "reset")
    setattr(db.owner, missing, None)
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await invoke(db, "reset")
    envelope(failure, 409, "no recovery kit on this account", "recovery_not_configured")
    assert not db.audit and not db.destroyed and db.processing_key == bytearray(DATA_KEY)


@pytest.mark.parametrize(
    "changes",
    [
        {"recovery_verifier": None},
        {"recovery_salt": None},
        {"recovery_verifier": b"different-proof"},
        {"recovery_salt": b"different-salt"},
        {"recovery_scheme": 1},
    ],
)
async def test_account_recovery_password_refuses_a_replaced_kit_after_proof(
    account_db, monkeypatch, changes
):
    db = account_db
    await prepare(db, "reset")
    original = account.lifecycle_locks

    class ReplacingFence:
        @asynccontextmanager
        async def hold(self, key):
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(update(User).where(User.id == OWNER).values(**changes))
                await writer.commit()
            async with original.hold(key):
                yield

    monkeypatch.setattr(account, "lifecycle_locks", ReplacingFence())
    with pytest.raises(ApiError) as failure:
        await invoke(db, "reset")
    envelope(failure, 401, "invalid credentials", "invalid_credentials")
    assert not db.audit and not db.destroyed and db.processing_key == bytearray(32)
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2


@pytest.mark.parametrize("kind", ["llm", "voice"])
@pytest.mark.parametrize("stale", ["disclosure", "policy"])
async def test_account_provider_reconsent_renews_each_stale_evidence_component(
    account_db, kind, stale
):
    db = account_db
    await prepare(db, kind)
    await invoke(db, kind)
    expected_disclosure = getattr(db.owner, kind + "_consent_disclosure")
    expected_policy = getattr(db.owner, kind + "_consent_policy")
    setattr(db.owner, kind + "_consent_" + stale, "old-provider-policy")
    await db.session.commit()
    result = await invoke(db, kind)
    assert result.enabled and result.active_for_current_policy
    assert getattr(db.owner, kind + "_consent_disclosure") == expected_disclosure
    assert getattr(db.owner, kind + "_consent_policy") == expected_policy
    events = list((await db.session.scalars(select(ConsentEvent))).all())
    assert len(events) == 2
    assert all(
        (event.kind, event.action, event.disclosure, event.policy)
        == (kind, "granted", expected_disclosure, expected_policy)
        for event in events
    )
    assert [event["action"] for event in db.audit] == [kind + "_consent_on"] * 2


@pytest.mark.parametrize("operation", ["llm", "voice", "delete"])
async def test_account_sensitive_actions_accept_only_their_real_single_use_step_up_proof(
    account_db, operation
):
    from app.security.step_up import StepUpProofStore

    db = account_db
    await prepare(db, operation)
    store = db.request.app.state.step_up_store = StepUpProofStore()
    action = "account_delete" if operation == "delete" else operation + "_consent"
    proof, _ = await store.issue(
        user_id=OWNER, action=action, token_jti=None, token_epoch=db.owner.token_epoch
    )
    if operation == "delete":
        await account.delete_account(db.request, None, db.owner, db.session, None, proof)
        assert db.destroyed == [OWNER] and db.audit[-1]["action"] == "account_deleted"
    else:
        function, model = (
            (account.set_llm_consent, LlmConsentRequest)
            if operation == "llm"
            else (account.set_voice_consent, VoiceConsentRequest)
        )
        result = await function(model(enabled=True), db.request, db.owner, db.session, proof)
        assert result.enabled and result.active_for_current_policy
        with pytest.raises(ApiError) as failure:
            await function(model(enabled=False), db.request, db.owner, db.session, proof)
        envelope(
            failure,
            403,
            "step-up proof is invalid, expired, or already used",
            "step_up_invalid",
        )
        assert db.audit[-1]["action"] == operation + "_consent_on"


async def test_account_totp_disable_requires_an_enabled_factor(account_db):
    db = account_db
    await prepare(db, "enable")
    with pytest.raises(ApiError) as failure:
        await invoke(db, "disable")
    envelope(failure, 404, "totp not enabled", "not_found")
    assert not db.audit and not db.destroyed


@pytest.mark.parametrize("first,second", [("llm", "voice"), ("voice", "llm")])
async def test_account_consent_reads_share_their_actual_http_rate_budget(account_db, first, second):
    db = account_db
    db.settings.read_rate_limit = 2
    app = FastAPI()
    app.state = db.request.app.state
    app.include_router(account.router)

    async def user():
        return db.owner

    app.dependency_overrides[require_regular_user] = user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(2):
            response = await client.get("/account/" + first + "-consent")
            assert response.status_code == 200
        response = await client.get("/account/" + second + "-consent")
        assert response.status_code == 429


def test_account_legacy_credential_route_documents_an_empty_response_for_generated_clients():
    app = FastAPI()
    app.include_router(account.router)
    responses = app.openapi()["paths"]["/account/credential"]["put"]["responses"]
    assert "204" in responses and "content" not in responses["204"]
    assert "205" not in responses


def test_account_api_documentation_groups_all_its_routes_for_generated_clients():
    app = FastAPI()
    app.include_router(account.router)
    operations = [
        operation
        for path, methods in app.openapi()["paths"].items()
        if path.startswith("/account/")
        for operation in methods.values()
    ]
    assert operations and all(operation["tags"] == ["account"] for operation in operations)


ACCOUNT_IDENTITY_ROUTES = [
    ("PUT", "/account/credential", 204, "auth"),
    ("GET", "/account/recovery", 200, "read"),
    ("PUT", "/account/recovery", 204, "auth"),
    ("DELETE", "/account/recovery", 204, "auth"),
    ("PUT", "/account/recovery/password", 204, "auth"),
    ("PUT", "/account/password", 204, "auth"),
    ("POST", "/account/key-envelope/upgrade", 204, "auth"),
    ("GET", "/account/access-log", 200, "read"),
    ("GET", "/account/llm-consent", 200, "read"),
    ("PUT", "/account/llm-consent", 200, "auth"),
    ("GET", "/account/voice-consent", 200, "read"),
    ("PUT", "/account/voice-consent", 200, "auth"),
    ("DELETE", "/account", 204, "auth"),
    ("POST", "/account/totp/setup", 200, "auth"),
    ("POST", "/account/totp/enable", 200, "auth"),
    ("POST", "/account/totp/disable", 204, "auth"),
]


def test_account_identity_operations_document_their_released_response_contract():
    app = FastAPI()
    app.include_router(account.router)
    schema = app.openapi()
    for method, path, status, _ in ACCOUNT_IDENTITY_ROUTES:
        operation = schema["paths"][path][method.lower()]
        assert str(status) in operation["responses"]


@pytest.mark.parametrize("method,path,status,budget", ACCOUNT_IDENTITY_ROUTES)
async def test_account_identity_requests_enforce_the_configured_work_budget(
    account_db, method, path, status, budget
):
    db = account_db
    setattr(db.settings, budget + "_rate_limit", 2)
    setattr(db.settings, budget + "_rate_window", 60)
    app = FastAPI()
    app.state = db.request.app.state
    app.include_router(account.router)

    async def user():
        return db.owner

    async def session():
        yield db.session

    for dependency in [require_user, require_regular_user, require_therapist_account]:
        app.dependency_overrides[dependency] = user
    app.dependency_overrides[get_session] = session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(2):
            response = await client.request(method, path, json={})
            assert response.status_code in [status, 403, 422]
        limited = await client.request(method, path, json={})
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) >= 1
