"""Authentication and clinical-sharing runtime contracts."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from types import SimpleNamespace

import anyio
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.api import auth, consents, therapist
from app.cache import SlidingWindowCounter, TokenRevocationStore
from app.deps import (
    ApiError,
    get_session,
    require_regular_user,
    require_therapist,
    require_therapist_account,
    require_user,
)
from app.locks import UserLocks
from app.models import User
from app.schemas import LoginRequest, RecoveryLoginRequest, RegisterRequest, SaltLookupRequest
from app.security import tokens
from app.security.kdf import canonical_kdf_params_json
from tests.test_full_backend_collection_mutation import (
    BLOB,
    MAXIMUM,
    NOW,
    OTHER,
    OWNER,
    b64,
    collection_db,  # noqa: F401 - shared isolated database fixture
    envelope,
)

AUTH_KEY = b"a" * 32
RECOVERY_KEY = b"r" * 32
PARAMS = {"algorithm": "pbkdf2-sha256", "version": 1, "iterations": 600000}


def hash_proof(key, salt):
    return hashlib.sha256(key + salt).digest()


@pytest_asyncio.fixture
async def authentication_db(collection_db, monkeypatch):  # noqa: F811 - imported pytest fixture
    db = collection_db
    db.settings.sharing_enabled = True
    db.settings.token_secret = "legacy-session-secret"
    db.settings.auth_token_secret_explicit = "split-session-secret"
    db.settings.decoy_secret = "dedicated-decoy-secret"
    db.settings.auth_rate_limit = 1000
    db.settings.verifier_failure_limit = 3
    db.owner.scrypt_salt = b"s" * 16
    db.owner.verifier = hash_proof(AUTH_KEY, db.owner.scrypt_salt)
    db.other.role = "therapist"
    db.other.display_name = "Clinician"
    db.other.wrap_pub_key = b64(b"public-wrap-key")
    db.other.wrap_key_blob = BLOB
    db.other.scrypt_salt = b"t" * 16
    db.other.verifier = hash_proof(AUTH_KEY, db.other.scrypt_salt)
    await db.session.commit()
    app = FastAPI()
    app.state.settings = db.settings
    app.state.rate_counter = SlidingWindowCounter()
    app.state.auth_limiter = anyio.CapacityLimiter(2)
    app.state.auth_admission_limiter = anyio.CapacityLimiter(2)
    app.state.token_revocations = TokenRevocationStore()
    db.destroyed = []
    app.state.key_store = SimpleNamespace(destroy_all_for_owner=db.destroyed.append)
    db.request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("test", 80),
            "app": app,
        }
    )
    db.hash_calls = []

    async def hash_work(key, salt, limiter=None, n=None):
        db.hash_calls.append((key, salt, limiter, n))
        return hash_proof(key, salt)

    monkeypatch.setattr(auth, "hash_verifier_off_loop", hash_work)
    monkeypatch.setattr(therapist, "hash_verifier_off_loop", hash_work)
    db.audit.clear()

    async def record(session, **values):
        db.audit.append(values)

    for module in [auth, consents, therapist]:
        monkeypatch.setattr(module, "append_access_log", record)
    monkeypatch.setattr(auth, "lifecycle_locks", UserLocks())
    lifecycle = UserLocks()
    monkeypatch.setattr(therapist, "lifecycle_locks", lifecycle)
    if therapist._note_locks is not None:
        monkeypatch.setattr(therapist, "_note_locks", UserLocks())
    sharing = UserLocks()
    monkeypatch.setattr(consents, "sharing_locks", sharing)
    monkeypatch.setattr(therapist, "sharing_locks", sharing)
    yield db


def test_supported_authentication_and_therapist_http_inventory_is_documented():
    app = FastAPI()
    for router in [auth.router, consents.router, therapist.router]:
        app.include_router(router)
    schema = app.openapi()
    routes = [
        ("/auth/register", "post", 201, "auth"),
        ("/auth/login", "post", 200, "auth"),
        ("/auth/recover", "post", 200, "auth"),
        ("/auth/salt", "post", 200, "auth"),
        ("/auth/key-envelope", "get", 200, "auth"),
        ("/auth/logout", "post", 204, "auth"),
        ("/consents", "get", 200, "consents"),
        ("/consents", "post", 201, "consents"),
        ("/consents/pairing/lookup", "post", 200, "consents"),
        ("/consents/{consent_id}/rewrap", "put", 200, "consents"),
        ("/consents/{consent_id}", "delete", 204, "consents"),
        ("/consents/{consent_id}/share-voice", "put", 200, "consents"),
        ("/therapist/register", "post", 201, "therapist"),
        ("/therapist/me", "get", 200, "therapist"),
        ("/therapist/wrap-key", "put", 204, "therapist"),
        ("/therapist/access-log", "get", 200, "therapist"),
        ("/therapist/account", "delete", 204, "therapist"),
        ("/therapist/pairing-codes", "post", 201, "therapist"),
        ("/therapist/pairing/sas", "get", 200, "therapist"),
        ("/therapist/patients", "get", 200, "therapist"),
        ("/therapist/patients/{user_id}/insights", "get", 200, "therapist"),
        ("/therapist/patients/{user_id}/entries", "get", 200, "therapist"),
        ("/therapist/patients/{user_id}/measures", "get", 200, "therapist"),
        ("/therapist/patients/{user_id}/audio/{attachment_id}", "get", 200, "therapist"),
        ("/therapist/patients/{user_id}/notes", "get", 200, "therapist"),
        ("/therapist/patients/{user_id}/notes", "post", 201, "therapist"),
        ("/therapist/notes/{note_id}", "patch", 200, "therapist"),
        ("/therapist/notes/{note_id}", "delete", 204, "therapist"),
        ("/therapist/notes/{note_id}/revisions", "get", 200, "therapist"),
        ("/therapist/notes/rekey", "put", 204, "therapist"),
    ]
    for path, method, status, tag in routes:
        operation = schema["paths"][path][method]
        assert str(status) in operation["responses"]
        assert operation["tags"] == [tag]


async def test_authentication_admission_overload_releases_slots_and_uses_the_worker_limiter(
    authentication_db,
):
    db = authentication_db
    assert auth._auth_limiter(db.request) is db.request.app.state.auth_limiter
    entered = asyncio.Event()
    release = asyncio.Event()
    limiter = db.request.app.state.auth_admission_limiter
    limiter.total_tokens = 1

    async def owner():
        async with auth.auth_work_slot(db.request):
            entered.set()
            await asyncio.wait_for(release.wait(), 2)

    task = asyncio.create_task(owner())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        with pytest.raises(ApiError) as failure:
            async with auth.auth_work_slot(db.request):
                pytest.fail("overloaded authentication work was admitted")
        envelope(
            failure,
            503,
            "authentication service busy; retry shortly",
            "service_unavailable",
            {"Retry-After": "1"},
        )
    finally:
        release.set()
        await asyncio.wait_for(task, 2)
    assert limiter.borrowed_tokens == 0
    async with auth.auth_work_slot(db.request):
        assert limiter.borrowed_tokens == 1
    assert limiter.borrowed_tokens == 0


def test_decoy_salts_are_independent_stable_domain_separated_hmac_vectors():
    def hkdf(secret, info):
        prk = hmac.new(b"\0" * 32, secret.encode(), hashlib.sha256).digest()
        return hmac.new(prk, info + b"\1", hashlib.sha256).digest()

    key = hkdf("secret", b"mindpattern/decoy-salt/v1")
    for name in ["Ada", "ada", " Ada ", "unknown"]:
        expected = b64(hmac.new(key, b"decoy:" + name.encode(), hashlib.sha256).digest()[:16])
        assert auth.decoy_salt(name, "secret") == expected
    keys = [auth.recovery_failure_key(name, "secret") for name in ["Ada", "ada", " Ada "]]
    assert len(set(keys)) == 3 and all(isinstance(key, str) for key in keys)


def test_verifier_hashing_delegates_shipped_memory_hard_parameters_and_explicit_factor(monkeypatch):
    calls = []

    def scrypt(key, **parameters):
        calls.append((key, parameters))
        return b"derived-verifier"

    monkeypatch.setattr(auth.hashlib, "scrypt", scrypt)
    assert auth.hash_verifier(AUTH_KEY, b"server-salt") == b"derived-verifier"
    assert auth.hash_verifier(AUTH_KEY, b"server-salt", n=16384) == b"derived-verifier"
    assert calls == [
        (
            AUTH_KEY,
            dict(salt=b"server-salt", n=131072, r=8, p=1, maxmem=536870912),
        ),
        (
            AUTH_KEY,
            dict(salt=b"server-salt", n=16384, r=8, p=1, maxmem=536870912),
        ),
    ]


@pytest.mark.parametrize(
    "role,enrolled,needed",
    [("user", False, False), ("therapist", False, True), ("therapist", True, False)],
)
async def test_issued_token_claims_match_account_purpose_epoch_and_mfa_state(
    authentication_db, role, enrolled, needed
):
    db = authentication_db
    db.owner.role = role
    db.owner.totp_enabled = enrolled
    result = auth._issue(db.request, db.owner)
    claims = tokens.verify_token(result.token, db.settings.auth_token_secret)
    assert (claims["uid"], claims["ep"], claims["ksv"], claims["purpose"]) == (
        OWNER,
        2,
        2,
        "therapist" if role == "therapist" else "patient",
    )
    assert (
        result.role == role
        and result.key_scheme == "v1"
        and result.mfa_enrollment_required is needed
    )


@pytest.mark.parametrize("v2", [False, True])
async def test_registration_persists_exact_envelope_and_age_evidence_before_issuing_token(
    authentication_db, v2
):
    db = authentication_db
    body = RegisterRequest(
        username="new-owner",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
        kdf_params=PARAMS if v2 else None,
        wrapped_data_key=b64(b"w" * 60) if v2 else None,
    )
    result = await auth.register(body, db.request, db.session)
    stored = await db.session.scalar(select(User).where(User.username == "new-owner"))
    assert stored is not None and result.user_id == stored.id
    assert (
        stored.verifier == hash_proof(AUTH_KEY, stored.scrypt_salt)
        and len(stored.scrypt_salt) >= 16
    )
    assert stored.key_scheme == ("v2" if v2 else "v1") and result.key_scheme == stored.key_scheme
    assert stored.kdf_params == (canonical_kdf_params_json(PARAMS) if v2 else None)
    assert stored.wrapped_data_key == (b"w" * 60 if v2 else None)
    assert (
        stored.age_attestation_version == "minimum_age_confirmed_v1"
        and stored.age_attested_at is not None
    )
    assert db.audit == [
        dict(
            actor_id=stored.id,
            actor_role="patient",
            user_id=stored.id,
            action="account_created",
            allow_new_chain=True,
        )
    ]


@pytest.mark.parametrize(
    "changes,detail",
    [
        ({"salt": "!!!!" + b64(b"s" * 16)}, "salt and verifier must be base64"),
        ({"verifier": "!!!!" + b64(AUTH_KEY)}, "salt and verifier must be base64"),
        ({"salt": b64(b"s" * 15)}, "salt must be exactly 16 bytes"),
        ({"salt": b64(b"s" * 17)}, "salt must be exactly 16 bytes"),
        ({"verifier": b64(b"a" * 31)}, "verifier must be 32 bytes"),
        ({"verifier": b64(b"a" * 33)}, "verifier must be 32 bytes"),
        (
            {"kdf_params": PARAMS},
            "v2 registration requires kdf_params and wrapped_data_key together",
        ),
        (
            {"wrapped_data_key": b64(b"w" * 60)},
            "v2 registration requires kdf_params and wrapped_data_key together",
        ),
        (
            {"kdf_params": PARAMS, "wrapped_data_key": "!!!!" + b64(b"w" * 60)},
            "wrapped_data_key must be base64",
        ),
        (
            {"kdf_params": PARAMS, "wrapped_data_key": b64(b"w" * 59)},
            "wrapped_data_key must be exactly 60 bytes",
        ),
        (
            {"kdf_params": PARAMS, "wrapped_data_key": b64(b"w" * 61)},
            "wrapped_data_key must be exactly 60 bytes",
        ),
        (
            {
                "kdf_params": dict(PARAMS, algorithm="unknown"),
                "wrapped_data_key": b64(b"w" * 60),
            },
            "kdf_params.algorithm must be 'pbkdf2-sha256' or 'argon2id'",
        ),
    ],
)
async def test_registration_rejects_strict_encoding_and_unpaired_envelopes(
    authentication_db, changes, detail
):
    db = authentication_db
    values = dict(
        username="new-owner",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
    )
    values.update(changes)
    with pytest.raises(ApiError) as failure:
        await auth.register(RegisterRequest(**values), db.request, db.session)
    envelope(failure, 422, detail, "validation_error")
    assert await db.session.scalar(select(User.id).where(User.username == "new-owner")) is None


async def test_salt_and_key_envelope_reads_keep_inactive_accounts_and_incomplete_v2_private(
    authentication_db,
):
    db = authentication_db
    known = await auth.get_salt(SaltLookupRequest(username=OWNER), db.request, db.session)
    assert known.salt == db.owner.salt
    db.owner.is_active = False
    await db.session.commit()
    inactive = await auth.get_salt(SaltLookupRequest(username=OWNER), db.request, db.session)
    assert inactive.salt == auth.decoy_salt(OWNER, db.settings.decoy_secret)
    absent = await auth.get_salt(SaltLookupRequest(username="absent"), db.request, db.session)
    assert absent.salt == auth.decoy_salt("absent", db.settings.decoy_secret)
    db.owner.key_scheme = "v2"
    for params, wrapped in [(None, b"w" * 60), (canonical_kdf_params_json(PARAMS), None)]:
        db.owner.kdf_params = params
        db.owner.wrapped_data_key = wrapped
        with pytest.raises(ApiError) as failure:
            await auth.get_key_envelope(db.request, db.owner)
        envelope(failure, 404, "account not found", "not_found")
    db.owner.kdf_params = canonical_kdf_params_json(PARAMS)
    db.owner.wrapped_data_key = b"w" * 60
    result = await auth.get_key_envelope(db.request, db.owner)
    assert (
        result.key_scheme == "v2"
        and result.kdf_params == PARAMS
        and result.wrapped_data_key == b64(b"w" * 60)
    )
    db.owner.key_scheme = "v1"
    db.owner.wrapped_data_key = b"leftover"
    assert (await auth.get_key_envelope(db.request, db.owner)).wrapped_data_key is None


@pytest.mark.parametrize("scheme", [1, 2])
async def test_recovery_login_consumes_exact_enrollment_and_returns_authoritative_revision(
    authentication_db, scheme
):
    db = authentication_db
    db.owner.recovery_salt = b"r" * 16
    db.owner.recovery_verifier = hash_proof(RECOVERY_KEY, db.owner.recovery_salt)
    db.owner.recovery_wrapped_data_key = b"sealed"
    db.owner.recovery_scheme = scheme
    await db.session.commit()
    result = await auth.recover_login(
        RecoveryLoginRequest(username=OWNER, verifier=b64(RECOVERY_KEY), scheme=f"v{scheme}"),
        db.request,
        db.session,
    )
    claims = tokens.verify_token(result.token, db.settings.auth_token_secret)
    assert (claims["uid"], claims["ep"], claims["ksv"], claims["purpose"]) == (
        OWNER,
        3,
        2,
        "patient",
    )
    assert (
        result.recovery_scheme == f"v{scheme}"
        and result.recovery_wrapped_data_key == b64(b"sealed")
        and result.role == "user"
    )
    assert db.destroyed == [OWNER]
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 3


@pytest.mark.parametrize(
    "variant",
    [
        "unknown",
        "inactive",
        "therapist",
        "unenrolled",
        "wrong_scheme",
        "wrong_key",
        "wrong_size",
        "invalid_b64",
    ],
)
async def test_recovery_failures_are_flat_do_not_retire_sessions_and_count_the_correct_subject(
    authentication_db, variant
):
    db = authentication_db
    db.owner.recovery_salt = b"r" * 16
    db.owner.recovery_verifier = hash_proof(RECOVERY_KEY, db.owner.recovery_salt)
    db.owner.recovery_wrapped_data_key = b"sealed"
    db.owner.recovery_scheme = 2
    if variant == "inactive":
        db.owner.is_active = False
    if variant == "therapist":
        db.owner.role = "therapist"
    if variant == "unenrolled":
        db.owner.recovery_verifier = None
    await db.session.commit()
    name = "unknown" if variant == "unknown" else OWNER
    verifier = {
        "wrong_key": b64(b"z" * 32),
        "wrong_size": b64(b"r" * 31),
        "invalid_b64": "!!!!" + b64(RECOVERY_KEY),
    }.get(variant, b64(RECOVERY_KEY))
    with pytest.raises(ApiError) as failure:
        await auth.recover_login(
            RecoveryLoginRequest(
                username=name, verifier=verifier, scheme="v1" if variant == "wrong_scheme" else "v2"
            ),
            db.request,
            db.session,
        )
    envelope(failure, 401, "invalid credentials", "invalid_credentials")
    assert db.hash_calls and db.destroyed == []
    key = auth.recovery_failure_key(name, db.settings.decoy_secret)
    assert db.request.app.state.rate_counter.check(key, db.settings.auth_rate_window).count == 1
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2


@pytest.mark.parametrize("variant", ["success", "unknown", "inactive", "wrong", "invalid_b64"])
async def test_password_login_releases_read_transactions_and_keeps_flat_failures(
    authentication_db, variant
):
    db = authentication_db
    if variant == "inactive":
        db.owner.is_active = False
        await db.session.commit()
    name = "unknown" if variant == "unknown" else OWNER
    proof = (
        "!!!!" + b64(AUTH_KEY)
        if variant == "invalid_b64"
        else b64(b"z" * 32 if variant == "wrong" else AUTH_KEY)
    )
    original = auth.hash_verifier_off_loop

    async def outside_transaction(*args, **kwargs):
        assert not db.session.in_transaction()
        return await original(*args, **kwargs)

    from unittest.mock import patch

    with patch.object(auth, "hash_verifier_off_loop", outside_transaction):
        if variant == "success":
            result = await auth.login(
                LoginRequest(username=name, verifier=proof), db.request, db.session
            )
            assert result.user_id == OWNER and result.role == "user"
        else:
            with pytest.raises(ApiError) as failure:
                await auth.login(
                    LoginRequest(username=name, verifier=proof), db.request, db.session
                )
            envelope(failure, 401, "invalid credentials", "invalid_credentials")


@pytest.mark.parametrize("legacy", [False, True])
async def test_logout_commits_single_token_or_legacy_epoch_retirement_before_key_purge(
    authentication_db, legacy, monkeypatch
):
    db = authentication_db
    payload = {"ksv": 2, "exp": 9999999999}
    if not legacy:
        payload["jti"] = "j" * 32
    monkeypatch.setattr(auth.tokens, "verify_token", lambda *args: payload)
    await auth.logout(db.request, db.owner, db.session, "Bearer signed")
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == (3 if legacy else 2)
    assert db.destroyed == [OWNER]
    if not legacy:
        assert await db.request.app.state.token_revocations.is_revoked_checked(db.session, "j" * 32)


@pytest.mark.parametrize("variant", ["token", "version"])
async def test_logout_rejects_mangled_bearers_and_retired_secret_versions(
    authentication_db, monkeypatch, variant
):
    db = authentication_db

    def verify(*args):
        if variant == "token":
            raise tokens.TokenError("invalid")
        return {"ksv": 1, "exp": 9999999999, "jti": "j" * 32}

    monkeypatch.setattr(auth.tokens, "verify_token", verify)
    with pytest.raises(ApiError) as failure:
        await auth.logout(db.request, db.owner, db.session, "Bearer signed")
    envelope(failure, 401, "invalid token", "unauthorized")
    assert db.destroyed == []


@pytest.mark.parametrize(
    "name,code,text",
    [
        ("_is_unique_violation", "23505", "UNIQUE constraint"),
        ("_is_fk_violation", "23503", "FOREIGN KEY constraint"),
    ],
)
def test_clinical_note_integrity_failures_keep_driver_code_and_cause_semantics(name, code, text):
    call = getattr(therapist, name)
    for original in [
        SimpleNamespace(pgcode=code),
        SimpleNamespace(sqlstate=code),
        RuntimeError(text),
    ]:
        assert call(IntegrityError("insert", None, original)) is True
    for original in [None, SimpleNamespace(pgcode="23502"), RuntimeError("not null constraint")]:
        assert call(IntegrityError("insert", None, original)) is False


async def test_clinical_note_guards_reload_authorization_and_release_read_transaction_for_patient_fence(
    authentication_db,
):
    db = authentication_db
    async with therapist._notes_guard(db.session, db.other):
        assert db.session.in_transaction()
    async with therapist._note_chart_guard(db.session, db.other, OWNER):
        assert not db.session.in_transaction()
    async with db.engine.begin() as connection:
        await connection.execute(update(User).where(User.id == OTHER).values(is_active=False))
    with pytest.raises(ApiError) as failure:
        async with therapist._notes_guard(db.session, db.other):
            pytest.fail("inactive clinician admitted")
    envelope(failure, 401, "invalid token", "unauthorized")


async def test_clinical_note_marker_fences_saturation_and_missing_owner(authentication_db):
    db = authentication_db
    db.other.notes_revision = MAXIMUM - 1
    await db.session.commit()
    assert await therapist._increment_notes_revision(db.session, db.other) == MAXIMUM
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await therapist._increment_notes_revision(db.session, db.other)
    envelope(
        failure,
        503,
        "unable to advance notes revision; retry shortly",
        "service_unavailable",
        {"Retry-After": "1"},
    )
    with pytest.raises(ApiError) as failure:
        await therapist._current_notes_revision(db.session, "missing")
    envelope(failure, 409, "notes changed while paging; retry the request", "collection_changed")


def test_clinical_ciphertext_decoders_are_strict_and_accept_exact_minimum():
    assert therapist._decode_note_blob(b64(b"x" * 28)) == b"x" * 28
    for module in [therapist, consents]:
        with pytest.raises(ApiError) as failure:
            module._decode_b64("!!!!" + b64(BLOB), "wrapped_key")
        envelope(failure, 422, "wrapped_key must be base64", "validation_error")
    with pytest.raises(ApiError) as failure:
        therapist._decode_note_blob("!!!!" + b64(BLOB))
    envelope(failure, 422, "blob must be base64", "validation_error")
    with pytest.raises(ApiError) as failure:
        therapist._decode_note_blob(b64(b"x" * 27))
    envelope(failure, 422, "blob must be at least 28 bytes", "validation_error")


async def test_clinician_self_response_preserves_custody_and_legacy_display_fallback(
    authentication_db,
):
    db = authentication_db
    for display in ["Dr Clinician", None]:
        db.other.display_name = display
        db.other.notes_keyring_blob = BLOB
        db.other.custody_version = 4
        db.other.totp_enabled = True
        response = await therapist.therapist_me(db.other)
        assert response.user_id == OTHER and response.display_name == (display or OTHER)
        assert (
            response.notes_keyring_blob == b64(BLOB)
            and response.custody_version == 4
            and response.totp_enabled is True
        )
        assert response.wrap_pub_key == db.other.wrap_pub_key and response.wrap_key_blob == b64(
            BLOB
        )


async def test_all_declared_sharing_routes_handle_empty_client_payloads_without_internal_errors(
    authentication_db,
):
    db = authentication_db
    app = db.request.app
    for router in [auth.router, consents.router, therapist.router]:
        app.include_router(router)
    app.dependency_overrides[require_regular_user] = lambda: db.owner
    app.dependency_overrides[require_user] = lambda: db.owner
    app.dependency_overrides[require_therapist] = lambda: db.other
    app.dependency_overrides[require_therapist_account] = lambda: db.other

    async def session():
        yield db.session

    app.dependency_overrides[get_session] = session
    declared = [
        (path, method)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
    ]
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://testserver"
    ) as client:
        for path, method in declared:
            path = (
                path.replace("{user_id}", OWNER)
                .replace("{consent_id}", "missing")
                .replace("{note_id}", "missing")
                .replace("{attachment_id}", "missing")
            )
            response = await client.request(
                method, path, json={} if method in {"post", "put", "patch"} else None
            )
            assert response.status_code < 500, (method, path, response.status_code, response.text)


@pytest_asyncio.fixture
async def sharing_db(authentication_db, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.security import sharing

    db = authentication_db
    key = ec.derive_private_key(7, ec.SECP256R1())
    db.spki = b64(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    db.other.wrap_pub_key = db.spki
    db.settings.pairing_secret_explicit = "separate-pairing-secret"
    db.step_ups = []

    async def reauthenticate(user, **values):
        db.step_ups.append((user.id, values))

    monkeypatch.setattr(consents, "_require_step_up_or_verifier", reauthenticate)
    monkeypatch.setattr(consents, "utcnow", lambda: NOW)
    monkeypatch.setattr(therapist, "utcnow", lambda: NOW)
    await db.session.commit()
    db.code = "ABCDEFGH"
    db.digest = sharing.pairing_code_digest(db.code, db.settings.pairing_secret)
    yield db


async def seed_pairing(db, *, code=None, expires=None, consumed=None):
    from datetime import timedelta

    from app.models import PairingCode
    from app.security import sharing

    code = code or db.code
    row = PairingCode(
        therapist_id=OTHER,
        code_hash=sharing.pairing_code_digest(code, db.settings.pairing_secret),
        created_at=NOW,
        expires_at=expires or NOW + timedelta(seconds=17),
        consumed_at=consumed,
    )
    db.session.add(row)
    await db.session.commit()
    return row


async def seed_consent(db, **changes):
    from app.models import Consent

    values = dict(
        id="c" * 32,
        user_id=OWNER,
        therapist_id=OTHER,
        status="active",
        disclosure="v3",
        ephemeral_pub=db.spki,
        wrapped_key=BLOB,
        granted_at=NOW,
        share_voice=False,
    )
    values.update(changes)
    row = Consent(**values)
    db.session.add(row)
    await db.session.commit()
    return row


async def consent_events(db):
    from app.models import ConsentEvent

    return list(
        (
            await db.session.scalars(
                select(ConsentEvent).order_by(ConsentEvent.occurred_at, ConsentEvent.id)
            )
        ).all()
    )


async def test_pairing_lookup_and_sas_share_exact_bound_patient_key_and_do_not_consume(sharing_db):
    from app.schemas import PairingLookupRequest
    from app.security import sharing

    db = sharing_db
    row = await seed_pairing(db)
    patient = await consents.lookup_pairing(
        PairingLookupRequest(code="  abcdefgh "), db.request, db.owner, db.session
    )
    clinician = await therapist.pairing_sas(db.request, db.other, db.session, OWNER, " abcdefgh ")
    der = base64.b64decode(db.spki)
    expected = sharing.pairing_sas(db.code, der, OWNER)
    assert patient.model_dump() == dict(
        therapist_id=OTHER,
        display_name="Clinician",
        wrap_pub_key=db.spki,
        sas=expected,
        wrap_key_fingerprint=sharing.wrap_key_fingerprint(der),
    )
    assert clinician.model_dump() == dict(
        sas=expected, wrap_key_fingerprint=sharing.wrap_key_fingerprint(der), expires_in=17
    )
    assert row.consumed_at is None
    db.other.display_name = None
    await db.session.commit()
    result = await consents.lookup_pairing(
        PairingLookupRequest(code=db.code), db.request, db.owner, db.session
    )
    assert result.display_name == OTHER


@pytest.mark.parametrize(
    "state", ["unknown", "expired", "boundary", "consumed", "inactive", "regular", "keyless"]
)
async def test_pairing_lookup_all_dead_or_unusable_credentials_are_flat_not_found(
    sharing_db, state
):
    from datetime import timedelta

    from app.schemas import PairingLookupRequest

    db = sharing_db
    if state != "unknown":
        await seed_pairing(
            db,
            expires=NOW
            if state == "boundary"
            else NOW - timedelta(seconds=1)
            if state == "expired"
            else None,
            consumed=NOW if state == "consumed" else None,
        )
    if state == "inactive":
        db.other.is_active = False
    if state == "regular":
        db.other.role = "user"
    if state == "keyless":
        db.other.wrap_pub_key = None
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await consents.lookup_pairing(
            PairingLookupRequest(code=db.code), db.request, db.owner, db.session
        )
    envelope(failure, 404, "pairing code not found", "not_found")


async def test_consent_grant_consumes_once_and_resets_scopes_on_same_retained_relationship(
    sharing_db,
):
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    row = await seed_pairing(db)
    body = ConsentGrantRequest(
        code=db.code.lower(), ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
    )
    result = await consents.grant_consent(
        body, db.request, db.owner, db.session, "credential", "proof"
    )
    consent = await db.session.get(
        __import__("app.models", fromlist=["Consent"]).Consent, result.id
    )
    assert (
        consent.user_id,
        consent.therapist_id,
        consent.status,
        consent.disclosure,
        consent.ephemeral_pub,
        consent.wrapped_key,
        consent.share_voice,
    ) == (OWNER, OTHER, "active", "v3", db.spki, BLOB, False)
    assert row.consumed_at == NOW
    assert result.model_dump() == dict(
        id=consent.id,
        therapist_id=OTHER,
        display_name="Clinician",
        username=OTHER,
        status="active",
        granted_at=consent.granted_at,
        revoked_at=None,
        therapist_wrap_pub_key=db.spki,
        share_voice=False,
    )
    assert (
        db.step_ups[-1][1]["action"] == "sharing_grant"
        and db.step_ups[-1][1]["verifier"] == "credential"
    )
    events = await consent_events(db)
    assert [
        (e.user_id, e.kind, e.action, e.disclosure, e.consent_id, e.share_voice, e.occurred_at)
        for e in events
    ] == [(OWNER, "sharing", "granted", "v3", consent.id, False, NOW)]
    assert (db.owner.consents_revision, db.other.patients_revision) == (1, 1)
    assert db.audit[-1] == dict(actor_id=OWNER, actor_role="user", user_id=OWNER, action="grant")
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(body, db.request, db.owner, db.session, "credential", "proof")
    envelope(failure, 404, "pairing code not found", "not_found")
    await db.session.rollback()
    await db.session.refresh(db.owner)
    await db.session.refresh(db.other)
    consent.status, consent.revoked_at, consent.share_voice, consent.disclosure = (
        "revoked",
        NOW,
        True,
        "v2",
    )
    await db.session.commit()
    await seed_pairing(db, code="HGFEDCBA")
    body.code, body.wrapped_key = "HGFEDCBA", b64(b"n" * 256)
    revived = await consents.grant_consent(
        body, db.request, db.owner, db.session, "credential", None
    )
    assert (
        revived.id == consent.id
        and revived.status == "active"
        and revived.revoked_at is None
        and revived.share_voice is False
    )
    assert consent.wrapped_key == b"n" * 256 and consent.disclosure == "v3"
    assert (db.owner.consents_revision, db.other.patients_revision) == (2, 2)


@pytest.mark.parametrize("route", ["grant", "rewrap"])
@pytest.mark.parametrize("bad", ["public_key", "encoding", "short", "long"])
async def test_consent_wrap_shape_failures_are_exact_and_never_modify_permissions(
    sharing_db, route, bad
):
    from app.schemas import ConsentGrantRequest, ConsentRewrapRequest

    db = sharing_db
    pub = b64(b"not a key") if bad == "public_key" else db.spki
    wrapped = (
        "!invalid!"
        if bad == "encoding"
        else b64(b"x" * (27 if bad == "short" else 257 if bad == "long" else 28))
    )
    body = dict(ephemeral_pub=pub, wrapped_key=wrapped)
    with pytest.raises(ApiError) as failure:
        if route == "grant":
            await consents.grant_consent(
                ConsentGrantRequest(code=db.code, disclosure="v3", **body),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        else:
            await consents.rewrap_consent(
                ConsentRewrapRequest(**body),
                "missing",
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
    detail = (
        "ephemeral_pub must be a P-256 SPKI key"
        if bad == "public_key"
        else "wrapped_key must be base64"
        if bad == "encoding"
        else "wrapped_key must be 28-256 bytes"
    )
    envelope(failure, 422, detail, "validation_error")
    assert not await consent_events(db)


async def test_disclosure_mismatch_refuses_before_reauthentication_or_pairing_consumption(
    sharing_db,
):
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    row = await seed_pairing(db)
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, disclosure="v2", ephemeral_pub=db.spki, wrapped_key=b64(BLOB)
            ),
            db.request,
            db.owner,
            db.session,
        )
    envelope(
        failure,
        409,
        "sharing disclosure is outdated; refresh and review it again",
        "disclosure_outdated",
    )
    assert not db.step_ups and row.consumed_at is None


async def test_consent_voice_rewrap_revoke_preserve_evidence_and_noop_is_idempotent(sharing_db):
    from app.schemas import ConsentRewrapRequest, ShareVoiceRequest

    db = sharing_db
    consent = await seed_consent(
        db, summary_blob=BLOB, summary_eph_pub=db.spki, summary_updated_at=NOW
    )
    for enabled in [True, True, False, True]:
        result = await consents.set_share_voice(
            consent.id,
            ShareVoiceRequest(enabled=enabled),
            db.request,
            db.owner,
            db.session,
            "credential",
            "proof",
        )
        assert result.share_voice is enabled
    assert (db.owner.consents_revision, db.other.patients_revision) == (3, 3)
    events = await consent_events(db)
    assert sorted(
        [(e.kind, e.action, e.disclosure, e.consent_id, e.share_voice) for e in events]
    ) == sorted(
        [
            ("sharing_voice", "granted", "v3", consent.id, True),
            ("sharing_voice", "withdrawn", "v3", consent.id, False),
            ("sharing_voice", "granted", "v3", consent.id, True),
        ]
    )
    assert [e["action"] for e in db.audit] == [
        "share_voice_on",
        "share_voice_off",
        "share_voice_on",
    ]
    result = await consents.rewrap_consent(
        ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(b"z" * 28)),
        consent.id,
        db.request,
        db.owner,
        db.session,
        "credential",
        "proof",
    )
    assert (
        result.share_voice is True
        and consent.wrapped_key == b"z" * 28
        and consent.ephemeral_pub == db.spki
    )
    assert db.audit[-1]["action"] == "rewrap"
    assert (db.owner.consents_revision, db.other.patients_revision) == (4, 4)
    await consents.revoke_consent(
        consent.id, db.request, db.owner, db.session, "credential", "proof"
    )
    assert (consent.status, consent.revoked_at, consent.share_voice) == ("revoked", NOW, False)
    assert (
        consent.wrapped_key
        is consent.ephemeral_pub
        is consent.summary_blob
        is consent.summary_eph_pub
        is consent.summary_updated_at
        is None
    )
    withdrawn = next(e for e in await consent_events(db) if e.kind == "sharing")
    assert (
        withdrawn.kind,
        withdrawn.action,
        withdrawn.share_voice,
        withdrawn.disclosure,
        withdrawn.consent_id,
    ) == ("sharing", "withdrawn", True, "v3", consent.id)
    assert (db.owner.consents_revision, db.other.patients_revision) == (5, 5)
    await consents.revoke_consent(consent.id, db.request, db.owner, db.session, "credential", None)
    assert (db.owner.consents_revision, db.other.patients_revision) == (5, 5)
    assert len(await consent_events(db)) == 4
    with pytest.raises(ApiError) as failure:
        await consents.set_share_voice(
            consent.id,
            ShareVoiceRequest(enabled=True),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 409, "consent is revoked; re-grant it before changing scopes", "conflict")
    with pytest.raises(ApiError) as failure:
        await consents.rewrap_consent(
            ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
            consent.id,
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "consent not found", "not_found")
    assert [item[1]["action"] for item in db.step_ups] == ["sharing_voice"] * 4 + [
        "sharing_rewrap",
        "sharing_revoke",
        "sharing_revoke",
        "sharing_voice",
        "sharing_rewrap",
    ]


async def test_voice_feature_switch_is_flat_not_found_before_stepup(sharing_db):
    from app.schemas import ShareVoiceRequest

    db = sharing_db
    db.settings.audio_enabled = False
    with pytest.raises(ApiError) as failure:
        await consents.set_share_voice(
            "missing", ShareVoiceRequest(enabled=True), db.request, db.owner, db.session
        )
    envelope(failure, 404, "not found", "not_found")
    assert not db.step_ups


async def test_consents_pages_return_retained_revoked_history_in_stable_order_and_revision(
    sharing_db,
):
    from datetime import timedelta

    from fastapi import Response

    from app.models import Consent
    from tests.test_full_backend_collection_mutation import account

    db = sharing_db
    clinicians = [
        account(f"{index:032x}", role="therapist", display_name=None, wrap_pub_key=db.spki)
        for index in range(1, 4)
    ]
    db.session.add_all(clinicians)
    await db.session.flush()
    relationships = [
        Consent(
            id=f"{index:032x}",
            user_id=OWNER,
            therapist_id=person.id,
            status="active" if index == 1 else "revoked",
            share_voice=index == 1,
            granted_at=NOW - timedelta(seconds=index),
            disclosure="v3",
        )
        for index, person in enumerate(clinicians, 1)
    ]
    db.session.add_all(relationships)
    db.owner.consents_revision = 7
    await db.session.commit()
    for offset, ids, more in [
        (0, [relationships[0].id, relationships[1].id], True),
        (2, [relationships[2].id], False),
        (3, [], False),
    ]:
        response = Response()
        result = await consents.list_consents(response, db.owner, db.session, 2, offset, "7")
        assert [r.id for r in result] == ids
        assert (
            response.headers["X-Consents-Revision"] == "7"
            and ("X-Next-Offset" in response.headers) is more
        )
        assert response.headers.get("X-Next-Offset") == (str(offset + len(ids)) if more else None)
        if offset == 0:
            assert (
                result[0].share_voice is True
                and result[1].status == "revoked"
                and result[1].display_name == clinicians[1].username
            )
    with pytest.raises(ApiError) as failure:
        await consents.list_consents(Response(), db.owner, db.session, 2, 0, "6")
    envelope(
        failure,
        409,
        "consents changed while paging; retry the request",
        "collection_changed",
        {"X-Consents-Revision": "7"},
    )
    await db.session.rollback()
    await db.session.refresh(db.owner)
    await db.session.refresh(db.other)
    clinicians[1].is_active = False
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await consents.list_consents(Response(), db.owner, db.session, 2, 0, "7")
    envelope(
        failure,
        409,
        "consents changed while paging; retry the request",
        "collection_changed",
        {"X-Consents-Revision": "7"},
    )


async def test_clinical_note_create_retry_edit_history_version_delete_and_audit(sharing_db):
    from fastapi import Response

    from app.models import TherapistNote, TherapistNoteRevision
    from app.schemas import NoteCreateRequest, NoteUpdateRequest

    db = sharing_db
    await seed_consent(db, status="revoked", ephemeral_pub=None, wrapped_key=None)
    body = NoteCreateRequest(
        client_note_id="offline-note-1", pattern_pid="temporal:work", blob=b64(BLOB)
    )
    first = await therapist.create_note(body, OWNER, db.other, db.session)
    assert (
        first.client_note_id == "offline-note-1"
        and first.pattern_pid == "temporal:work"
        and first.blob == b64(BLOB)
        and first.version == 1
    )
    assert db.other.notes_revision == 1
    again = await therapist.create_note(body, OWNER, db.other, db.session)
    assert again == first and db.other.notes_revision == 1
    for change in [dict(blob=b64(b"n" * 28)), dict(pattern_pid="mood_shift:")]:
        with pytest.raises(ApiError) as failure:
            await therapist.create_note(body.model_copy(update=change), OWNER, db.other, db.session)
        envelope(
            failure,
            409,
            "a different note with this client_note_id already exists; edit it with PATCH and a base_version",
            "version_conflict",
        )
        await db.session.rollback()
        await db.session.refresh(db.owner)
        await db.session.refresh(db.other)
    changed = await therapist.update_note(
        NoteUpdateRequest(blob=b64(b"n" * 28), base_version=1), first.id, db.other, db.session
    )
    assert (
        changed.version == 2
        and changed.blob == b64(b"n" * 28)
        and changed.updated_at == NOW
        and changed.pattern_pid == "temporal:work"
    )
    assert db.other.notes_revision == 2
    revisions = list((await db.session.scalars(select(TherapistNoteRevision))).all())
    assert (
        len(revisions) == 1
        and revisions[0].blob == BLOB
        and revisions[0].therapist_id == OTHER
        and revisions[0].note_id == first.id
        and revisions[0].created_at == NOW
    )
    retry = await therapist.update_note(
        NoteUpdateRequest(blob=changed.blob, base_version=2), first.id, db.other, db.session
    )
    assert retry == changed and db.other.notes_revision == 2
    for base, detail, code, status, headers in [
        (
            None,
            "base_version is required (send the note version the edit is based on)",
            "version_required",
            400,
            None,
        ),
        (
            1,
            "note was modified by another device; refetch and retry",
            "version_conflict",
            409,
            {"Retry-After": "1"},
        ),
    ]:
        with pytest.raises(ApiError) as failure:
            await therapist.update_note(
                NoteUpdateRequest(blob=b64(BLOB), base_version=base), first.id, db.other, db.session
            )
        envelope(failure, status, detail, code, headers)
        await db.session.rollback()
        await db.session.refresh(db.owner)
        await db.session.refresh(db.other)
    response = Response()
    history = await therapist.read_note_revisions(
        first.id, response, db.other, db.session, 0, 50, None, "2"
    )
    assert [(r.id, r.blob) for r in history] == [(revisions[0].id, b64(BLOB))]
    assert response.headers["X-Notes-Revision"] == "2" and "X-Next-Offset" not in response.headers
    await therapist.delete_note(first.id, response, db.other, db.session)
    assert response.headers["X-Notes-Revision"] == "3" and db.other.notes_revision == 3
    assert await db.session.get(TherapistNote, first.id) is None
    assert not list((await db.session.scalars(select(TherapistNoteRevision))).all())
    assert [(a["actor_id"], a["actor_role"], a["user_id"], a["action"]) for a in db.audit] == [
        (OTHER, "therapist", OWNER, action)
        for action in [
            "write_note",
            "write_note",
            "update_note",
            "update_note",
            "read_note_revisions",
            "delete_note",
        ]
    ]


async def test_note_revision_pruning_is_per_note_newest_fifty_by_time_then_id(sharing_db):
    from datetime import timedelta

    from app.models import TherapistNote, TherapistNoteRevision

    db = sharing_db
    notes = [
        TherapistNote(
            id=f"note-{index}",
            therapist_id=OTHER,
            user_id=OWNER,
            client_note_id=f"client-{index}",
            blob=BLOB,
            created_at=NOW,
            updated_at=NOW,
        )
        for index in range(2)
    ]
    db.session.add_all(notes)
    await db.session.flush()
    revisions = [
        TherapistNoteRevision(
            id=f"{index:032x}",
            note_id=notes[0].id,
            therapist_id=OTHER,
            blob=BLOB,
            created_at=NOW + timedelta(seconds=index // 2),
        )
        for index in range(52)
    ]
    unrelated = TherapistNoteRevision(
        id="unrelated", note_id=notes[1].id, therapist_id=OTHER, blob=BLOB, created_at=NOW
    )
    db.session.add_all([*revisions, unrelated])
    await therapist._enforce_note_revision_cap(db.session, notes[0].id)
    await db.session.commit()
    kept = list(
        (
            await db.session.scalars(
                select(TherapistNoteRevision.id)
                .where(TherapistNoteRevision.note_id == notes[0].id)
                .order_by(TherapistNoteRevision.id)
            )
        ).all()
    )
    assert kept == [r.id for r in revisions[2:]]
    assert await db.session.get(TherapistNoteRevision, unrelated.id) is unrelated


@pytest.mark.parametrize("kind", ["count", "bytes"])
async def test_note_quota_counts_live_and_history_once_and_accepts_exact_boundary(sharing_db, kind):
    from app.models import TherapistNote, TherapistNoteRevision

    db = sharing_db
    if kind == "count":
        notes = [
            TherapistNote(
                id=f"count-{index}",
                therapist_id=OTHER,
                user_id=OWNER,
                client_note_id=f"count-{index}",
                blob=b"n" * 28,
                created_at=NOW,
                updated_at=NOW,
            )
            for index in range(20)
        ]
        db.session.add_all(notes)
        await db.session.flush()
        db.session.add_all(
            [
                TherapistNoteRevision(
                    note_id=note.id, therapist_id=OTHER, blob=b"r" * 28, created_at=NOW
                )
                for index, note in enumerate(notes)
                for _ in range(48 if index == 19 else 49)
            ]
        )
        await db.session.commit()
        await therapist._assert_note_quota(db.session, OTHER, OWNER, 28, is_new=True)
        db.session.add(
            TherapistNoteRevision(
                note_id=notes[-1].id, therapist_id=OTHER, blob=b"r" * 28, created_at=NOW
            )
        )
        await db.session.commit()
        with pytest.raises(ApiError) as failure:
            await therapist._assert_note_quota(db.session, OTHER, OWNER, 28, is_new=True)
        envelope(failure, 413, "note storage quota reached (1000 notes)", "quota_exceeded")
        await therapist._assert_note_quota(
            db.session, OTHER, OWNER, 28, previous_size=28, is_new=False
        )
    else:
        unit = 1024 * 1024
        notes = [
            TherapistNote(
                id=f"n-{index}",
                therapist_id=OTHER,
                user_id=OWNER,
                client_note_id=f"n-{index}",
                blob=b"n" * unit,
                created_at=NOW,
                updated_at=NOW,
            )
            for index in range(30)
        ]
        db.session.add_all(notes)
        await db.session.flush()
        db.session.add_all(
            [
                TherapistNoteRevision(
                    note_id=notes[0].id, therapist_id=OTHER, blob=b"r" * unit, created_at=NOW
                )
                for _ in range(2)
            ]
        )
        await db.session.commit()
        await therapist._assert_note_quota(
            db.session, OTHER, OWNER, unit, previous_size=unit, is_new=False
        )
        with pytest.raises(ApiError) as failure:
            await therapist._assert_note_quota(
                db.session, OTHER, OWNER, unit + 1, previous_size=unit, is_new=False
            )
        envelope(failure, 413, "note storage quota reached (total size)", "blob_quota_exceeded")
    await therapist._assert_note_quota(db.session, OWNER, OTHER, 28, is_new=True)


async def test_registration_conflict_budget_is_per_name_and_does_not_deny_a_free_name(
    authentication_db,
):
    db = authentication_db
    db.settings.auth_rate_limit = 2
    body = RegisterRequest(
        username=OWNER,
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
    )
    for _ in range(2):
        with pytest.raises(ApiError) as failure:
            await auth.register(body, db.request, db.session)
        envelope(failure, 409, "username already taken", "conflict")
        await db.session.rollback()
    result = await auth.register(
        body.model_copy(update={"username": "free-name"}), db.request, db.session
    )
    assert (await db.session.get(User, result.user_id)).username == "free-name"
    with pytest.raises(ApiError) as failure:
        await auth.register(body, db.request, db.session)
    assert failure.value.status_code == 429


@pytest.mark.parametrize(
    "variant", ["legacy", "epoch", "inactive", "role", "verifier", "salt", "sealed", "scheme"]
)
async def test_recovery_legacy_scheme_and_concurrent_enrollment_retirement_are_authoritative(
    authentication_db, monkeypatch, variant
):
    db = authentication_db
    db.owner.recovery_scheme = None
    db.owner.recovery_salt = b"r" * 16
    db.owner.recovery_verifier = hash_proof(RECOVERY_KEY, db.owner.recovery_salt)
    db.owner.recovery_wrapped_data_key = b"sealed"
    db.owner.key_scheme = ""
    await db.session.commit()
    original = auth.hash_verifier_off_loop

    async def changed_while_hashing(*args, **kwargs):
        if variant != "legacy":
            change = {
                "epoch": {"token_epoch": 3},
                "inactive": {"is_active": False},
                "role": {"role": "therapist"},
                "verifier": {"recovery_verifier": b"new"},
                "salt": {"recovery_salt": b"new"},
                "sealed": {"recovery_wrapped_data_key": b"new"},
                "scheme": {"recovery_scheme": 2},
            }[variant]
            from sqlalchemy.ext.asyncio import async_sessionmaker

            async with async_sessionmaker(db.session.bind, expire_on_commit=False)() as writer:
                await writer.execute(update(User).where(User.id == OWNER).values(**change))
                await writer.commit()
        return await original(*args, **kwargs)

    monkeypatch.setattr(auth, "hash_verifier_off_loop", changed_while_hashing)
    body = RecoveryLoginRequest(username=OWNER, verifier=b64(RECOVERY_KEY), scheme="v1")
    if variant == "legacy":
        result = await auth.recover_login(body, db.request, db.session)
        assert result.recovery_scheme == "v1" and result.key_scheme == "v1"
        assert db.owner.token_epoch == 3 and db.destroyed == [OWNER]
    else:
        with pytest.raises(ApiError) as failure:
            await auth.recover_login(body, db.request, db.session)
        envelope(failure, 401, "invalid credentials", "invalid_credentials")
        assert not db.destroyed


async def test_totp_login_missing_bad_replayed_and_fresh_codes_have_exact_verdicts(
    authentication_db, monkeypatch
):
    from app.security import totp

    db = authentication_db
    secret = b"s" * 20
    db.owner.totp_enabled = True
    db.owner.totp_secret = totp.wrap_secret(secret, db.settings.totp_wrap_secret)
    await db.session.commit()
    monkeypatch.setattr(totp.time, "time", lambda: NOW.timestamp())
    counter = int(NOW.timestamp() // 30)
    valid = totp._code_for_counter(secret, counter)
    for value, detail, code in [
        (None, "totp code required", "totp_required"),
        ("bad-code", "invalid totp code", "totp_code_invalid"),
    ]:
        with pytest.raises(ApiError) as failure:
            await auth.login(
                LoginRequest(username=OWNER, verifier=b64(AUTH_KEY), totp_code=value),
                db.request,
                db.session,
            )
        envelope(failure, 401, detail, code)
    result = await auth.login(
        LoginRequest(username=OWNER, verifier=b64(AUTH_KEY), totp_code=" " + valid + " "),
        db.request,
        db.session,
    )
    assert result.user_id == OWNER and db.owner.totp_last_counter == counter
    with pytest.raises(ApiError) as failure:
        await auth.login(
            LoginRequest(username=OWNER, verifier=b64(AUTH_KEY), totp_code=valid),
            db.request,
            db.session,
        )
    envelope(failure, 401, "invalid totp code", "totp_code_invalid")
    monkeypatch.setattr(totp.time, "time", lambda: NOW.timestamp() + 30)
    result = await auth.login(
        LoginRequest(
            username=OWNER,
            verifier=b64(AUTH_KEY),
            totp_code=totp._code_for_counter(secret, counter + 1),
        ),
        db.request,
        db.session,
    )
    assert result.user_id == OWNER and db.owner.totp_last_counter == counter + 1


@pytest.mark.parametrize("backup_rows", [1, 2])
async def test_totp_failure_budget_is_per_verified_account_and_backup_redemption_consumes_one_row(
    authentication_db, monkeypatch, backup_rows
):
    from app.models import TotpBackupCode
    from app.security import totp
    from app.security.sharing import backup_code_digest

    db = authentication_db
    secret = b"s" * 20
    for user in [db.owner, db.other]:
        user.totp_enabled = True
        user.totp_secret = totp.wrap_secret(secret, db.settings.totp_wrap_secret)
    db.settings.totp_failure_limit = 2
    backup = "ABCDEFGHJK"
    # Enrollment draws a random set without a uniqueness constraint; a rare
    # duplicate credential must still burn exactly one persisted row per use.
    rows = [
        TotpBackupCode(
            user_id=OTHER, digest=backup_code_digest(backup, db.settings.totp_wrap_secret)
        )
        for _ in range(backup_rows)
    ]
    db.session.add_all(rows)
    await db.session.commit()
    for _ in range(2):
        with pytest.raises(ApiError) as failure:
            await auth.login(
                LoginRequest(username=OWNER, verifier=b64(AUTH_KEY), totp_code="wrong!"),
                db.request,
                db.session,
            )
        envelope(failure, 401, "invalid totp code", "totp_code_invalid")
    result = await auth.login(
        LoginRequest(username=OTHER, verifier=b64(AUTH_KEY), totp_code=backup),
        db.request,
        db.session,
    )
    assert result.user_id == OTHER
    for row in rows:
        await db.session.refresh(row)
    assert sum(row.used_at is not None for row in rows) == 1
    with pytest.raises(ApiError) as failure:
        await auth.login(
            LoginRequest(username=OWNER, verifier=b64(AUTH_KEY), totp_code="wrong!"),
            db.request,
            db.session,
        )
    assert failure.value.status_code == 429


async def test_logout_legacy_secret_version_is_not_silently_upgraded(
    authentication_db, monkeypatch
):
    db = authentication_db
    monkeypatch.setattr(tokens, "verify_token", lambda *args: {"exp": 9999999999})
    with pytest.raises(ApiError) as failure:
        await auth.logout(db.request, db.owner, db.session, "Bearer legacy")
    envelope(failure, 401, "invalid token", "unauthorized")
    assert db.owner.token_epoch == 2 and not db.destroyed
    db.settings.auth_token_secret_explicit = ""
    await auth.logout(db.request, db.owner, db.session, "Bearer legacy")
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 3 and db.destroyed == [OWNER]


@pytest.mark.parametrize("operation", ["logout", "recover"])
async def test_session_retirement_waits_for_the_processing_account_lifecycle_fence(
    authentication_db, monkeypatch, operation
):
    db = authentication_db
    db.owner.recovery_scheme = 1
    db.owner.recovery_salt = b"r" * 16
    db.owner.recovery_verifier = hash_proof(RECOVERY_KEY, db.owner.recovery_salt)
    db.owner.recovery_wrapped_data_key = b"sealed"
    await db.session.commit()
    monkeypatch.setattr(tokens, "verify_token", lambda *args: {"exp": 9999999999, "ksv": 2})
    async with auth.lifecycle_locks.hold(f"llm-lifecycle:{OWNER}"):
        call = (
            auth.logout(db.request, db.owner, db.session, "Bearer legacy")
            if operation == "logout"
            else auth.recover_login(
                RecoveryLoginRequest(username=OWNER, verifier=b64(RECOVERY_KEY), scheme="v1"),
                db.request,
                db.session,
            )
        )
        task = asyncio.create_task(call)
        try:
            done, _ = await asyncio.wait({task}, timeout=0.05)
            assert not done and not db.destroyed
        finally:
            if task.done():
                task.result()
            else:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    # Cancellation while queued must release the request admission resource.
    assert db.request.app.state.auth_admission_limiter.borrowed_tokens == 0


async def seed_relationships(db, *, side, count, active_count):
    from app.models import Consent
    from tests.test_full_backend_collection_mutation import account

    partners = [
        account(
            f"{100 + index:032x}",
            role="therapist" if side == "patient" else "user",
            wrap_pub_key=db.spki,
        )
        for index in range(count)
    ]
    db.session.add_all(partners)
    await db.session.flush()
    rows = [
        Consent(
            id=f"r-{index}",
            user_id=OWNER if side == "patient" else partner.id,
            therapist_id=partner.id if side == "patient" else OTHER,
            status="active" if index < active_count else "revoked",
            granted_at=NOW,
            disclosure="v3",
            ephemeral_pub=db.spki if index < active_count else None,
            wrapped_key=BLOB if index < active_count else None,
        )
        for index, partner in enumerate(partners)
    ]
    db.session.add_all(rows)
    await db.session.commit()
    return partners, rows


@pytest.mark.parametrize(
    "side,kind",
    [
        ("patient", "active"),
        ("therapist", "active"),
        ("patient", "retained"),
        ("therapist", "retained"),
    ],
)
async def test_grant_respects_real_account_relationship_boundaries_without_consuming_code(
    sharing_db, side, kind
):
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    await seed_relationships(
        db,
        side=side,
        count=100 if kind == "active" else 1000,
        active_count=100 if kind == "active" else 0,
    )
    pairing = await seed_pairing(db)
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    detail = (
        "retained sharing history has reached the supported limit"
        if kind == "retained"
        else "sharing history has reached the supported limit"
        if side == "patient"
        else "therapist caseload has reached the supported limit"
    )
    envelope(failure, 413, detail, "payload_too_large")
    assert pairing.consumed_at is None and not db.audit and not await consent_events(db)


@pytest.mark.parametrize("kind", ["active", "retained"])
async def test_consent_list_real_caps_accept_boundary_and_refuse_imported_overflow(
    sharing_db, kind
):
    from fastapi import Response

    from app.models import Consent
    from tests.test_full_backend_collection_mutation import account

    db = sharing_db
    bound = 100 if kind == "active" else 1000
    await seed_relationships(
        db, side="patient", count=bound, active_count=bound if kind == "active" else 0
    )
    out = await consents.list_consents(Response(), db.owner, db.session, 200, 0, None)
    assert len(out) == min(200, bound)
    partner = account("extra", role="therapist", wrap_pub_key=db.spki)
    db.session.add(partner)
    await db.session.flush()
    db.session.add(
        Consent(
            user_id=OWNER,
            therapist_id=partner.id,
            status="active" if kind == "active" else "revoked",
            granted_at=NOW,
        )
    )
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await consents.list_consents(Response(), db.owner, db.session, 200, 0, None)
    envelope(
        failure,
        413,
        "sharing history exceeds the supported list size"
        if kind == "active"
        else "retained sharing history exceeds the supported list size",
        "payload_too_large",
    )


@pytest.mark.parametrize("operation", ["grant", "rewrap", "revoke", "voice", "list"])
@pytest.mark.parametrize("changed", ["inactive", "epoch"])
async def test_consent_calls_reauthorize_the_database_after_a_stale_dependency_snapshot(
    sharing_db, monkeypatch, operation, changed
):
    from fastapi import Response
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.schemas import ConsentGrantRequest, ConsentRewrapRequest, ShareVoiceRequest

    db = sharing_db
    consent = await seed_consent(db)
    await seed_pairing(db)
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
        await writer.execute(
            update(User)
            .where(User.id == OWNER)
            .values(**({"is_active": False} if changed == "inactive" else {"token_epoch": 3}))
        )
        await writer.commit()
    with pytest.raises(ApiError) as failure:
        if operation == "grant":
            await consents.grant_consent(
                ConsentGrantRequest(
                    code=db.code, disclosure="v3", ephemeral_pub=db.spki, wrapped_key=b64(BLOB)
                ),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        elif operation == "rewrap":
            await consents.rewrap_consent(
                ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
                consent.id,
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        elif operation == "revoke":
            await consents.revoke_consent(
                consent.id, db.request, db.owner, db.session, "credential", None
            )
        elif operation == "voice":
            await consents.set_share_voice(
                consent.id,
                ShareVoiceRequest(enabled=True),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        else:
            await consents.list_consents(Response(), db.owner, db.session, 100, 0, None)
    if changed == "epoch" or operation == "list":
        envelope(failure, 401, "invalid token", "unauthorized")
    else:
        envelope(failure, 404, "account not found", "not_found")
    assert not db.audit and not await consent_events(db)


@pytest.mark.parametrize("operation", ["rewrap", "revoke", "voice"])
async def test_consent_mutations_cannot_act_on_another_patients_relationship(sharing_db, operation):
    from app.schemas import ConsentRewrapRequest, ShareVoiceRequest
    from tests.test_full_backend_collection_mutation import account

    db = sharing_db
    patient = account("different-patient")
    db.session.add(patient)
    await db.session.commit()
    consent = await seed_consent(db, user_id=patient.id)
    with pytest.raises(ApiError) as failure:
        if operation == "rewrap":
            await consents.rewrap_consent(
                ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
                consent.id,
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        elif operation == "revoke":
            await consents.revoke_consent(
                consent.id, db.request, db.owner, db.session, "credential", None
            )
        else:
            await consents.set_share_voice(
                consent.id,
                ShareVoiceRequest(enabled=True),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
    envelope(failure, 404, "consent not found", "not_found")
    assert not db.audit and not await consent_events(db)


@pytest.mark.parametrize("operation", ["grant", "voice_on", "voice_off", "revoke"])
async def test_permission_event_reserve_blocks_expansion_but_keeps_withdrawal_available(
    sharing_db, operation
):
    from sqlalchemy import insert

    from app.models import ConsentEvent
    from app.schemas import ConsentGrantRequest, ShareVoiceRequest

    db = sharing_db
    consent = await seed_consent(db, share_voice=operation in {"revoke", "voice_off"})
    await db.session.execute(
        insert(ConsentEvent),
        [
            dict(
                id=f"{index:032x}",
                user_id=OWNER,
                kind="sharing_voice",
                action="withdrawn",
                disclosure="v3",
                consent_id=consent.id,
                share_voice=False,
                occurred_at=NOW,
            )
            for index in range(9798)
        ],
    )
    await db.session.commit()
    if operation == "grant":
        await seed_pairing(db)
        with pytest.raises(ApiError) as failure:
            await consents.grant_consent(
                ConsentGrantRequest(
                    code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
                ),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
    elif operation == "voice_on":
        with pytest.raises(ApiError) as failure:
            await consents.set_share_voice(
                consent.id,
                ShareVoiceRequest(enabled=True),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
    elif operation == "voice_off":
        await consents.set_share_voice(
            consent.id,
            ShareVoiceRequest(enabled=False),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
        assert consent.share_voice is False
        assert len(await consent_events(db)) == 9799
    else:
        await consents.revoke_consent(
            consent.id, db.request, db.owner, db.session, "credential", None
        )
        assert consent.status == "revoked" and db.audit[-1]["action"] == "revoke"
        assert len(await consent_events(db)) == 9799
    if operation in {"grant", "voice_on"}:
        envelope(
            failure,
            413,
            "consent history has reached the retained safety limit",
            "payload_too_large",
        )
        assert not db.audit


@pytest.mark.parametrize("driver", ["pgcode", "sqlstate", "unknown"])
async def test_grant_database_integrity_races_have_correct_account_or_conflict_envelope(
    sharing_db, monkeypatch, driver
):
    from app.models import ConsentEvent
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    await seed_pairing(db)
    original = db.session.commit

    async def commit():
        if any(isinstance(row, ConsentEvent) for row in db.session.new):
            error = Exception("driver integrity failure")
            if driver != "unknown":
                setattr(error, driver, "23503")
            raise IntegrityError("insert consent", {}, error)
        await original()

    # Real mutation code autoflushes the event before revision updates; raise
    # at the write commit after those updates, as a database constraint race.
    original_record = consents.append_access_log

    async def audited(*args, **kwargs):
        await original_record(*args, **kwargs)
        error = Exception("driver integrity failure")
        if driver != "unknown":
            setattr(error, driver, "23503")

        async def failed_commit():
            raise IntegrityError("insert consent", {}, error)

        monkeypatch.setattr(db.session, "commit", failed_commit)

    monkeypatch.setattr(consents, "append_access_log", audited)
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(
        failure,
        409 if driver == "unknown" else 404,
        "consent already being granted" if driver == "unknown" else "account not found",
        "conflict" if driver == "unknown" else "not_found",
    )


async def test_clinical_notes_and_history_pages_are_bounded_ordered_and_snapshot_checked(
    sharing_db,
):
    from datetime import timedelta

    from fastapi import Response

    from app.models import TherapistNote, TherapistNoteRevision

    db = sharing_db
    await seed_consent(db, status="revoked", wrapped_key=None, ephemeral_pub=None)
    notes = [
        TherapistNote(
            id=f"note-{index}",
            therapist_id=OTHER,
            user_id=OWNER,
            client_note_id=f"note-{index}",
            blob=bytes([65 + index]) * size,
            created_at=NOW + timedelta(seconds=index),
            updated_at=NOW,
            pattern_pid=None,
            version=1,
        )
        for index, size in enumerate([28, 60, 28])
    ]
    db.session.add_all(notes)
    await db.session.flush()
    revisions = [
        TherapistNoteRevision(
            id=f"rev-{index}",
            note_id=notes[0].id,
            therapist_id=OTHER,
            blob=bytes([80 + index]) * size,
            created_at=NOW + timedelta(seconds=index),
        )
        for index, size in enumerate([28, 60, 28])
    ]
    db.session.add_all(revisions)
    db.other.notes_revision = 5
    await db.session.commit()
    for history in [False, True]:
        expected = list(reversed(revisions)) if history else notes

        async def read(response, offset=0, limit=2, budget=None, revision="5"):
            if history:
                return await therapist.read_note_revisions(
                    notes[0].id, response, db.other, db.session, offset, limit, budget, revision
                )
            return await therapist.list_notes(
                OWNER, response, db.other, db.session, offset, limit, budget, revision
            )

        for offset, ids, continuation in [
            (0, [expected[0].id, expected[1].id], "2"),
            (2, [expected[2].id], None),
            (3, [], None),
        ]:
            response = Response()
            out = await read(response, offset)
            assert [row.id for row in out] == ids
            assert (
                response.headers["X-Notes-Revision"] == "5"
                and response.headers.get("X-Next-Offset") == continuation
            )
        response = Response()
        out = await read(response, limit=3, budget=28)
        assert [row.id for row in out] == [expected[0].id] and out[0].blob == b64(expected[0].blob)
        assert response.headers["X-Next-Offset"] == "1"
        with pytest.raises(ApiError) as failure:
            await read(Response(), budget=27)
        envelope(
            failure,
            413,
            f"an item in this {'note revision' if history else 'note'} page exceeds the requested page byte budget",
            "payload_too_large",
        )
        await db.session.rollback()
        await db.session.refresh(db.owner)
        await db.session.refresh(db.other)
        await db.session.refresh(notes[0])
        with pytest.raises(ApiError) as failure:
            await read(Response(), revision="4")
        envelope(
            failure,
            409,
            f"{'note revisions' if history else 'notes'} changed while paging; retry the request",
            "collection_changed",
            {"X-Notes-Revision": "5"},
        )
        await db.session.rollback()
        await db.session.refresh(db.owner)
        await db.session.refresh(db.other)
        for row in [*notes, *revisions]:
            await db.session.refresh(row)


async def test_pairing_helpers_refresh_cached_rows_after_external_expiry_and_clinician_retirement(
    sharing_db,
):
    from datetime import timedelta

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import PairingCode

    db = sharing_db
    row = await seed_pairing(db)
    for changes in [{"is_active": False}, {"role": "user"}, {"wrap_pub_key": None}]:
        async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
            await writer.execute(update(User).where(User.id == OTHER).values(**changes))
            await writer.commit()
        assert await consents._therapist_for_code(db.session, row) is None
        db.other.is_active, db.other.role, db.other.wrap_pub_key = True, "therapist", db.spki
        await db.session.commit()
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
        await writer.execute(
            update(PairingCode)
            .where(PairingCode.id == row.id)
            .values(expires_at=NOW - timedelta(seconds=1))
        )
        await writer.commit()
    assert await consents._live_code(db.session, db.code, db.settings.pairing_secret) is None


@pytest.mark.parametrize("changed", ["revision", "retirement"])
async def test_consent_final_page_fence_refuses_a_concurrent_snapshot_change(
    sharing_db, monkeypatch, changed
):
    from fastapi import Response
    from sqlalchemy.ext.asyncio import async_sessionmaker

    db = sharing_db
    await seed_consent(db)
    original = db.session.execute
    changed_once = False

    async def execute(statement, *args, **kwargs):
        nonlocal changed_once
        result = await original(statement, *args, **kwargs)
        if not changed_once and "ORDER BY consents.granted_at" in str(statement):
            changed_once = True
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(
                    update(User)
                    .where(User.id == (OWNER if changed == "revision" else OTHER))
                    .values(
                        **(
                            {"consents_revision": 1}
                            if changed == "revision"
                            else {"is_active": False}
                        )
                    )
                )
                await writer.commit()
        return result

    monkeypatch.setattr(db.session, "execute", execute)
    with pytest.raises(ApiError) as failure:
        await consents.list_consents(Response(), db.owner, db.session, 100, 0, "0")
    envelope(
        failure,
        409,
        "consents changed while paging; retry the request",
        "collection_changed",
        {"X-Consents-Revision": "1" if changed == "revision" else "0"},
    )
    assert changed_once


async def test_grant_atomic_consumption_refuses_a_code_that_expires_after_preflight(
    sharing_db, monkeypatch
):
    from datetime import timedelta

    from app.schemas import ConsentGrantRequest

    db = sharing_db
    await seed_pairing(db)
    clock = iter([NOW, NOW, NOW + timedelta(seconds=17)])
    monkeypatch.setattr(consents, "utcnow", lambda: next(clock))
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "pairing code not found", "not_found")
    assert not db.audit


@pytest.mark.parametrize("operation", ["rewrap", "revoke", "voice"])
async def test_consent_commit_stale_row_races_are_flat_not_found(
    sharing_db, monkeypatch, operation
):
    from sqlalchemy.orm.exc import StaleDataError

    from app.schemas import ConsentRewrapRequest, ShareVoiceRequest

    db = sharing_db
    consent = await seed_consent(db)

    async def failed_commit():
        raise StaleDataError("concurrent deletion")

    monkeypatch.setattr(db.session, "commit", failed_commit)
    with pytest.raises(ApiError) as failure:
        if operation == "rewrap":
            await consents.rewrap_consent(
                ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
                consent.id,
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        elif operation == "revoke":
            await consents.revoke_consent(
                consent.id, db.request, db.owner, db.session, "credential", None
            )
        else:
            await consents.set_share_voice(
                consent.id,
                ShareVoiceRequest(enabled=True),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
    envelope(failure, 404, "consent not found", "not_found")


@pytest.mark.parametrize("operation", ["create", "list", "history", "update", "delete"])
async def test_private_chart_operations_wait_for_the_patient_erasure_fence(sharing_db, operation):
    from fastapi import Response

    from app.locks import sharing_patient_lock_key
    from app.models import TherapistNote
    from app.schemas import NoteCreateRequest, NoteUpdateRequest

    db = sharing_db
    await seed_consent(db)
    note = TherapistNote(
        id="chart-note",
        therapist_id=OTHER,
        user_id=OWNER,
        client_note_id="chart-note",
        blob=BLOB,
        created_at=NOW,
        updated_at=NOW,
        version=1,
    )
    db.session.add(note)
    await db.session.commit()

    async def call():
        if operation == "create":
            return await therapist.create_note(
                NoteCreateRequest(client_note_id="new-chart-note", blob=b64(BLOB)),
                OWNER,
                db.other,
                db.session,
            )
        if operation == "list":
            return await therapist.list_notes(
                OWNER, Response(), db.other, db.session, 0, 100, None, None
            )
        if operation == "history":
            return await therapist.read_note_revisions(
                note.id, Response(), db.other, db.session, 0, 50, None, None
            )
        if operation == "update":
            return await therapist.update_note(
                NoteUpdateRequest(blob=b64(b"z" * 28), base_version=1),
                note.id,
                db.other,
                db.session,
            )
        return await therapist.delete_note(note.id, Response(), db.other, db.session)

    async with therapist.sharing_locks.hold(sharing_patient_lock_key(OWNER)):
        task = asyncio.create_task(call())
        try:
            done, _ = await asyncio.wait({task}, timeout=0.05)
            assert not done and not db.audit
            assert not db.session.in_transaction()
        finally:
            if task.done():
                task.result()
            else:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def test_notes_reject_dead_chart_targets_and_other_therapist_notes(sharing_db):
    from fastapi import Response

    from app.models import TherapistNote
    from app.schemas import NoteCreateRequest, NoteUpdateRequest
    from tests.test_full_backend_collection_mutation import account

    db = sharing_db
    third = account("third-clinician", role="therapist", wrap_pub_key=db.spki)
    db.session.add(third)
    await db.session.commit()
    note = TherapistNote(
        id="other-chart",
        therapist_id=third.id,
        user_id=OWNER,
        client_note_id="other-chart",
        blob=BLOB,
        created_at=NOW,
        updated_at=NOW,
        version=1,
    )
    db.session.add(note)
    await db.session.commit()
    for call in [
        lambda: therapist.update_note(
            NoteUpdateRequest(blob=b64(BLOB), base_version=1), note.id, db.other, db.session
        ),
        lambda: therapist.delete_note(note.id, Response(), db.other, db.session),
        lambda: therapist.read_note_revisions(
            note.id, Response(), db.other, db.session, 0, 50, None, None
        ),
    ]:
        with pytest.raises(ApiError) as failure:
            await call()
        envelope(failure, 404, "note not found", "not_found")
    for patient in [OWNER, "x" * 33]:
        with pytest.raises(ApiError) as failure:
            await therapist.create_note(
                NoteCreateRequest(client_note_id="missing-pair", blob=b64(BLOB)),
                patient,
                db.other,
                db.session,
            )
        envelope(failure, 404, "patient not found", "not_found")


def test_clinical_notes_public_query_bounds_and_defaults_are_documented():
    app = FastAPI()
    app.include_router(therapist.router)
    schema = app.openapi()
    paths = {
        "/therapist/patients/{user_id}/notes": dict(
            offset=(0, 0, 100000), limit=(100, 1, 100), page_bytes=(None, 1, 2097152)
        ),
        "/therapist/notes/{note_id}/revisions": dict(
            offset=(0, 0, 100000), limit=(50, 1, 200), page_bytes=(None, 1, 2097152)
        ),
    }
    for path, expected in paths.items():
        query = {
            parameter["name"]: parameter["schema"]
            for parameter in schema["paths"][path]["get"]["parameters"]
            if parameter["in"] == "query"
        }
        for name, (default, minimum, maximum) in expected.items():
            field = query[name]
            numeric = next(
                (branch for branch in field.get("anyOf", []) if branch.get("type") == "integer"),
                field,
            )
            assert (field.get("default"), numeric.get("minimum"), numeric.get("maximum")) == (
                default,
                minimum,
                maximum,
            )


@pytest.mark.parametrize("history", [False, True])
async def test_clinical_legacy_full_pages_over_two_mib_refuse_while_byte_clients_continue(
    sharing_db, history
):
    from datetime import timedelta

    from fastapi import Response

    from app.models import TherapistNote, TherapistNoteRevision

    db = sharing_db
    await seed_consent(db)
    notes = [
        TherapistNote(
            id=f"large-{index}",
            therapist_id=OTHER,
            user_id=OWNER,
            client_note_id=f"large-{index}",
            blob=b"n" * size,
            created_at=NOW + timedelta(seconds=index),
            updated_at=NOW,
        )
        for index, size in enumerate([1024 * 1024, 1024 * 1024, 28])
    ]
    db.session.add_all(notes)
    await db.session.flush()
    revisions = [
        TherapistNoteRevision(
            id=f"large-rev-{index}",
            note_id=notes[0].id,
            therapist_id=OTHER,
            blob=b"r" * size,
            created_at=NOW + timedelta(seconds=3 - index),
        )
        for index, size in enumerate([1024 * 1024, 1024 * 1024, 28])
    ]
    db.session.add_all(revisions)
    await db.session.commit()

    async def read(response, budget):
        if history:
            return await therapist.read_note_revisions(
                notes[0].id, response, db.other, db.session, 0, 3, budget, None
            )
        return await therapist.list_notes(OWNER, response, db.other, db.session, 0, 3, budget, None)

    with pytest.raises(ApiError) as failure:
        await read(Response(), None)
    envelope(
        failure,
        413,
        f"requested {'note revision' if history else 'note'} page exceeds the 2 MiB ciphertext budget; upgrade to a byte-paginating client",
        "payload_too_large",
    )
    await db.session.rollback()
    await db.session.refresh(db.other)
    for row in notes:
        await db.session.refresh(row)
    response = Response()
    result = await read(response, 2097152)
    assert len(result) == 2 and response.headers["X-Next-Offset"] == "2"
    assert sum(len(base64.b64decode(row.blob)) for row in result) == 2097152


async def test_clinical_noop_retry_remains_available_at_a_full_real_chart_quota(sharing_db):
    from app.models import TherapistNote
    from app.schemas import NoteCreateRequest

    db = sharing_db
    await seed_consent(db)
    db.session.add_all(
        [
            TherapistNote(
                id=f"full-{index}",
                therapist_id=OTHER,
                user_id=OWNER,
                client_note_id=f"full-{index}",
                blob=BLOB,
                created_at=NOW,
                updated_at=NOW,
            )
            for index in range(1000)
        ]
    )
    await db.session.commit()
    result = await therapist.create_note(
        NoteCreateRequest(client_note_id="full-0", blob=b64(BLOB)), OWNER, db.other, db.session
    )
    assert result.id == "full-0" and db.other.notes_revision == 0
    from app.schemas import NoteUpdateRequest

    retry = await therapist.update_note(
        NoteUpdateRequest(blob=b64(BLOB), base_version=1), "full-0", db.other, db.session
    )
    assert retry.version == 1 and db.other.notes_revision == 0
    with pytest.raises(ApiError) as failure:
        await therapist.create_note(
            NoteCreateRequest(client_note_id="one-too-many", blob=b64(BLOB)),
            OWNER,
            db.other,
            db.session,
        )
    envelope(failure, 413, "note storage quota reached (1000 notes)", "quota_exceeded")


async def test_pairing_issuance_retries_unique_collisions_and_stops_with_exact_retryable_error(
    sharing_db, monkeypatch
):
    from datetime import timedelta

    from app.models import PairingCode
    from app.security import sharing

    db = sharing_db
    await seed_pairing(db)
    choices = iter([db.code, "HGFEDCBA"])
    monkeypatch.setattr(sharing, "generate_pairing_code", lambda: next(choices))
    result = await therapist.create_pairing_code(db.request, db.other, db.session)
    assert result.code == "HGFEDCBA" and result.expires_in == 900
    saved = await db.session.scalar(
        select(PairingCode).where(
            PairingCode.code_hash
            == sharing.pairing_code_digest(result.code, db.settings.pairing_secret)
        )
    )
    assert (
        saved.therapist_id == OTHER
        and saved.created_at == NOW
        and saved.expires_at == NOW + timedelta(seconds=900)
        and saved.consumed_at is None
    )
    await db.session.refresh(db.other)
    attempts = []

    def collision():
        attempts.append(True)
        return db.code

    monkeypatch.setattr(sharing, "generate_pairing_code", collision)
    with pytest.raises(ApiError) as failure:
        await therapist.create_pairing_code(db.request, db.other, db.session)
    envelope(
        failure,
        503,
        "unable to allocate a unique pairing code; retry shortly",
        "service_unavailable",
        {"Retry-After": "1"},
    )
    assert len(attempts) == 5


@pytest.mark.parametrize(
    "state", ["unknown", "expired", "boundary", "consumed", "keyless", "empty_header", "subsecond"]
)
async def test_clinician_sas_credential_expiry_and_minimum_display_lifetime(sharing_db, state):
    from datetime import timedelta

    db = sharing_db
    if state != "unknown":
        await seed_pairing(
            db,
            expires=NOW + timedelta(milliseconds=500)
            if state == "subsecond"
            else NOW
            if state == "boundary"
            else NOW - timedelta(seconds=1)
            if state == "expired"
            else None,
            consumed=NOW if state == "consumed" else None,
        )
    if state == "keyless":
        db.other.wrap_pub_key = None
        await db.session.commit()
    if state == "subsecond":
        response = await therapist.pairing_sas(db.request, db.other, db.session, OWNER, db.code)
        assert response.expires_in == 1
    else:
        with pytest.raises(ApiError) as failure:
            await therapist.pairing_sas(
                db.request,
                db.other,
                db.session,
                OWNER,
                None if state == "empty_header" else db.code,
            )
        envelope(failure, 404, "pairing code not found", "not_found")


@pytest.mark.parametrize(
    "state", ["active", "revoked", "inactive_patient", "other_patient", "oversized"]
)
async def test_active_clinical_consent_scope_is_flat_and_patient_specific(sharing_db, state):
    db = sharing_db
    row = await seed_consent(db, status="revoked" if state == "revoked" else "active")
    if state == "inactive_patient":
        db.owner.is_active = False
        await db.session.commit()
    target = (
        "x" * 33
        if state == "oversized"
        else "another-patient"
        if state == "other_patient"
        else OWNER
    )
    if state == "active":
        assert await therapist._active_consent(db.session, db.other, target) is row
    else:
        with pytest.raises(ApiError) as failure:
            await therapist._active_consent(db.session, db.other, target)
        envelope(failure, 404, "patient not found", "not_found")


@pytest.mark.parametrize("changed", ["inactive", "epoch"])
async def test_therapist_read_fence_reloads_retirement_from_database(sharing_db, changed):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    db = sharing_db
    async with therapist._therapist_sharing_guard(db.session, db.other) as fresh:
        assert fresh is db.other
    await db.session.commit()
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
        await writer.execute(
            update(User)
            .where(User.id == OTHER)
            .values(**({"is_active": False} if changed == "inactive" else {"token_epoch": 3}))
        )
        await writer.commit()
    with pytest.raises(ApiError) as failure:
        async with therapist._therapist_sharing_guard(db.session, db.other):
            pytest.fail("retired clinician was authorized")
    envelope(failure, 401, "invalid token", "unauthorized")


@pytest.mark.parametrize("operation", ["voice", "rewrap", "revoke", "grant"])
async def test_consent_operations_reload_previously_cached_revocation_state(sharing_db, operation):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import Consent
    from app.schemas import ConsentGrantRequest, ConsentRewrapRequest, ShareVoiceRequest

    db = sharing_db
    row = await seed_consent(db, share_voice=True)
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
        await writer.execute(
            update(Consent)
            .where(Consent.id == row.id)
            .values(
                status="revoked",
                wrapped_key=None,
                ephemeral_pub=None,
                revoked_at=NOW,
                share_voice=False,
            )
        )
        await writer.commit()
    if operation == "grant":
        await seed_pairing(db)
        response = await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
        assert (
            response.status == "active"
            and response.revoked_at is None
            and response.share_voice is False
        )
        assert row.ephemeral_pub == db.spki and row.wrapped_key == BLOB
    elif operation == "revoke":
        await consents.revoke_consent(row.id, db.request, db.owner, db.session, "credential", None)
        assert not db.audit and not await consent_events(db)
    else:
        with pytest.raises(ApiError) as failure:
            if operation == "voice":
                await consents.set_share_voice(
                    row.id,
                    ShareVoiceRequest(enabled=True),
                    db.request,
                    db.owner,
                    db.session,
                    "credential",
                    None,
                )
            else:
                await consents.rewrap_consent(
                    ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
                    row.id,
                    db.request,
                    db.owner,
                    db.session,
                    "credential",
                    None,
                )
        envelope(
            failure,
            409 if operation == "voice" else 404,
            "consent is revoked; re-grant it before changing scopes"
            if operation == "voice"
            else "consent not found",
            "conflict" if operation == "voice" else "not_found",
        )


async def test_voice_default_on_legacy_settings_is_disabled(sharing_db):
    from app.schemas import ShareVoiceRequest

    db = sharing_db
    db.request.app.state.settings = SimpleNamespace()
    with pytest.raises(ApiError) as failure:
        await consents.set_share_voice(
            "missing", ShareVoiceRequest(enabled=True), db.request, db.owner, db.session
        )
    envelope(failure, 404, "not found", "not_found")


async def test_exact_minimum_consent_wrap_is_accepted_for_grant_and_rewrap(sharing_db):
    from app.schemas import ConsentGrantRequest, ConsentRewrapRequest

    db = sharing_db
    await seed_pairing(db)
    response = await consents.grant_consent(
        ConsentGrantRequest(
            code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(b"m" * 28), disclosure="v3"
        ),
        db.request,
        db.owner,
        db.session,
        "credential",
        None,
    )
    assert response.status == "active"
    result = await consents.rewrap_consent(
        ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(b"z" * 28)),
        response.id,
        db.request,
        db.owner,
        db.session,
        "credential",
        None,
    )
    assert result.id == response.id


def test_consents_public_page_bounds_are_the_supported_mobile_contract():
    app = FastAPI()
    app.include_router(consents.router)
    query = {
        p["name"]: p["schema"]
        for p in app.openapi()["paths"]["/consents"]["get"]["parameters"]
        if p["in"] == "query"
    }
    assert (query["limit"]["default"], query["limit"]["minimum"], query["limit"]["maximum"]) == (
        100,
        1,
        200,
    )
    assert (query["offset"]["default"], query["offset"]["minimum"], query["offset"]["maximum"]) == (
        0,
        0,
        1000,
    )


async def test_consent_exact_terminal_page_has_no_spurious_continuation(sharing_db):
    from fastapi import Response

    db = sharing_db
    await seed_relationships(db, side="patient", count=3, active_count=3)
    response = Response()
    result = await consents.list_consents(response, db.owner, db.session, 3, 0, None)
    assert len(result) == 3 and "X-Next-Offset" not in response.headers


async def test_consent_list_ignores_unrelated_retirement_and_refuses_own_before_quota(sharing_db):
    from fastapi import Response

    from tests.test_full_backend_collection_mutation import account

    db = sharing_db
    row = await seed_consent(db)
    outsider = account("retired-outsider", role="therapist", is_active=False)
    db.session.add(outsider)
    await db.session.commit()
    result = await consents.list_consents(Response(), db.owner, db.session, 100, 0, None)
    assert [item.id for item in result] == [row.id]
    await seed_relationships(db, side="patient", count=101, active_count=101)
    db.other.is_active = False
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await consents.list_consents(Response(), db.owner, db.session, 100, 0, None)
    envelope(
        failure,
        409,
        "consents changed while paging; retry the request",
        "collection_changed",
        {"X-Consents-Revision": "0"},
    )


async def test_active_grant_refresh_at_capacity_stays_available_but_revoked_extra_cannot_expand(
    sharing_db,
):
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    row = await seed_consent(db)
    await seed_relationships(db, side="patient", count=99, active_count=99)
    await seed_pairing(db)
    response = await consents.grant_consent(
        ConsentGrantRequest(
            code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
        ),
        db.request,
        db.owner,
        db.session,
        "credential",
        None,
    )
    assert response.id == row.id and row.ephemeral_pub == db.spki and row.wrapped_key == BLOB
    row.status = "revoked"
    await db.session.commit()
    from app.models import Consent
    from tests.test_full_backend_collection_mutation import account

    extra = account("hundredth-active", role="therapist", wrap_pub_key=db.spki)
    db.session.add(extra)
    await db.session.flush()
    db.session.add(
        Consent(
            user_id=OWNER,
            therapist_id=extra.id,
            status="active",
            granted_at=NOW,
            disclosure="v3",
            wrapped_key=BLOB,
            ephemeral_pub=db.spki,
        )
    )
    await db.session.commit()
    await seed_pairing(db, code="HGFEDCBA")
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code="HGFEDCBA", ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 413, "sharing history has reached the supported limit", "payload_too_large")


@pytest.mark.parametrize("change", ["inactive", "role"])
async def test_grant_rechecks_clinician_after_code_preflight_before_database_grant(
    sharing_db, monkeypatch, change
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.schemas import ConsentGrantRequest

    db = sharing_db
    await seed_pairing(db)
    original = consents._therapist_for_code
    called = 0

    async def lookup(*args):
        nonlocal called
        result = await original(*args)
        called += 1
        if called == 2:
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(
                    update(User)
                    .where(User.id == OTHER)
                    .values(**({"is_active": False} if change == "inactive" else {"role": "user"}))
                )
                await writer.commit()
        return result

    monkeypatch.setattr(consents, "_therapist_for_code", lookup)
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "pairing code not found", "not_found")
    assert not db.audit


async def test_rewrap_refresh_deletion_race_stays_flat_not_found(sharing_db, monkeypatch):
    from sqlalchemy import inspect
    from sqlalchemy.orm.exc import ObjectDeletedError

    from app.schemas import ConsentRewrapRequest

    db = sharing_db
    row = await seed_consent(db)

    async def deleted(*args, **kwargs):
        raise ObjectDeletedError(inspect(row))

    monkeypatch.setattr(db.session, "refresh", deleted)
    with pytest.raises(ApiError) as failure:
        await consents.rewrap_consent(
            ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
            row.id,
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "consent not found", "not_found")


@pytest.mark.parametrize("operation", ["revoke", "rewrap", "voice"])
async def test_revoke_passes_password_proof_to_real_sensitive_action_authorizer(
    sharing_db, monkeypatch, operation
):
    from app.api import account as account_api
    from app.schemas import ConsentRewrapRequest, ShareVoiceRequest

    db = sharing_db
    row = await seed_consent(db)
    monkeypatch.setattr(
        consents, "_require_step_up_or_verifier", account_api._require_step_up_or_verifier
    )
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    if operation == "revoke":
        await consents.revoke_consent(row.id, db.request, db.owner, db.session, b64(AUTH_KEY), None)
        assert row.status == "revoked"
    elif operation == "rewrap":
        await consents.rewrap_consent(
            ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
            row.id,
            db.request,
            db.owner,
            db.session,
            b64(AUTH_KEY),
            None,
        )
        assert row.status == "active"
    else:
        await consents.set_share_voice(
            row.id,
            ShareVoiceRequest(enabled=True),
            db.request,
            db.owner,
            db.session,
            b64(AUTH_KEY),
            None,
        )
        assert row.share_voice is True


async def test_cached_active_consent_cannot_bypass_regrant_quota_after_external_withdrawal(
    sharing_db,
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import Consent
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    row = await seed_consent(db)
    await seed_relationships(db, side="patient", count=100, active_count=100)
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
        await writer.execute(
            update(Consent)
            .where(Consent.id == row.id)
            .values(status="revoked", wrapped_key=None, ephemeral_pub=None, revoked_at=NOW)
        )
        await writer.commit()
    await seed_pairing(db)
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 413, "sharing history has reached the supported limit", "payload_too_large")


@pytest.mark.parametrize("operation", ["rewrap", "revoke", "voice"])
async def test_retired_counterpart_consent_mutations_are_flat_not_found(sharing_db, operation):
    from app.schemas import ConsentRewrapRequest, ShareVoiceRequest

    db = sharing_db
    row = await seed_consent(db)
    db.other.is_active = False
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        if operation == "rewrap":
            await consents.rewrap_consent(
                ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(BLOB)),
                row.id,
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
        elif operation == "revoke":
            await consents.revoke_consent(
                row.id, db.request, db.owner, db.session, "credential", None
            )
        else:
            await consents.set_share_voice(
                row.id,
                ShareVoiceRequest(enabled=True),
                db.request,
                db.owner,
                db.session,
                "credential",
                None,
            )
    envelope(failure, 404, "consent not found", "not_found")
    assert not db.audit


async def test_consent_maximum_supported_rewrap_is_accepted_and_returned_to_same_clinician(
    sharing_db,
):
    from app.schemas import ConsentRewrapRequest

    db = sharing_db
    row = await seed_consent(db)
    response = await consents.rewrap_consent(
        ConsentRewrapRequest(ephemeral_pub=db.spki, wrapped_key=b64(b"z" * 256)),
        row.id,
        db.request,
        db.owner,
        db.session,
        "credential",
        None,
    )
    assert (
        response.therapist_id == OTHER
        and response.display_name == "Clinician"
        and response.therapist_wrap_pub_key == db.spki
    )
    assert row.wrapped_key == b"z" * 256


async def test_grant_does_not_cross_a_reissued_code_into_another_clinicians_fence(
    sharing_db, monkeypatch
):
    from datetime import timedelta

    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import PairingCode
    from app.schemas import ConsentGrantRequest
    from tests.test_full_backend_collection_mutation import account

    db = sharing_db
    row = await seed_pairing(db)
    third = account("reissued-clinician", role="therapist", wrap_pub_key=db.spki)
    db.session.add(third)
    await db.session.commit()
    original = consents._therapist_for_code
    called = 0

    async def lookup(*args):
        nonlocal called
        result = await original(*args)
        called += 1
        if called == 1:
            # A long-queued preflight can outlive maintenance and a fresh
            # random issuance of the same digest to a different clinician.
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(delete(PairingCode).where(PairingCode.id == row.id))
                writer.add(
                    PairingCode(
                        therapist_id=third.id,
                        code_hash=db.digest,
                        created_at=NOW,
                        expires_at=NOW + timedelta(seconds=900),
                    )
                )
                await writer.commit()
        return result

    monkeypatch.setattr(consents, "_therapist_for_code", lookup)
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "pairing code not found", "not_found")
    assert not db.audit


async def test_empty_patient_roster_still_emits_the_shared_revision_header(sharing_db):
    from fastapi import Response

    db = sharing_db
    response = Response()
    result = await therapist.list_patients(db.request, response, db.other, db.session, 100, 0, None)
    assert result == [] and response.headers["X-Patients-Revision"] == "0"
    assert "X-Next-Offset" not in response.headers


@pytest.mark.parametrize("operation", ["create", "list", "update", "history", "delete"])
async def test_retired_patient_charts_are_unavailable_while_their_rows_await_erasure(
    sharing_db, operation
):
    from fastapi import Response

    from app.models import TherapistNote
    from app.schemas import NoteCreateRequest, NoteUpdateRequest

    db = sharing_db
    await seed_consent(db)
    note = TherapistNote(
        id="retired-chart",
        therapist_id=OTHER,
        user_id=OWNER,
        client_note_id="retired-chart",
        blob=BLOB,
        created_at=NOW,
        updated_at=NOW,
        version=1,
    )
    db.session.add(note)
    db.owner.is_active = False
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        if operation == "create":
            await therapist.create_note(
                NoteCreateRequest(client_note_id="new-chart", blob=b64(BLOB)),
                OWNER,
                db.other,
                db.session,
            )
        elif operation == "list":
            await therapist.list_notes(OWNER, Response(), db.other, db.session, 0, 100, None, None)
        elif operation == "update":
            await therapist.update_note(
                NoteUpdateRequest(blob=b64(BLOB), base_version=1), note.id, db.other, db.session
            )
        elif operation == "history":
            await therapist.read_note_revisions(
                note.id, Response(), db.other, db.session, 0, 50, None, None
            )
        else:
            await therapist.delete_note(note.id, Response(), db.other, db.session)
    envelope(
        failure,
        404,
        "patient not found" if operation in {"create", "list"} else "note not found",
        "not_found",
    )
    assert not db.audit


async def test_no_history_byte_identical_note_retry_is_allowed_at_exact_ciphertext_chart_budget(
    sharing_db,
):
    from app.models import TherapistNote
    from app.schemas import NoteUpdateRequest

    db = sharing_db
    await seed_consent(db)
    db.session.add_all(
        [
            TherapistNote(
                id=f"exact-{index}",
                therapist_id=OTHER,
                user_id=OWNER,
                client_note_id=f"exact-{index}",
                blob=b"n" * 1048576,
                created_at=NOW,
                updated_at=NOW,
                version=1,
            )
            for index in range(32)
        ]
    )
    await db.session.commit()
    result = await therapist.update_note(
        NoteUpdateRequest(blob=b64(b"n" * 1048576), base_version=1), "exact-0", db.other, db.session
    )
    assert result.version == 1 and db.other.notes_revision == 0


async def test_note_update_reloads_the_version_changed_by_a_device_while_queued(
    sharing_db, monkeypatch
):
    from contextlib import asynccontextmanager

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import TherapistNote
    from app.schemas import NoteUpdateRequest

    db = sharing_db
    await seed_consent(db)
    row = TherapistNote(
        id="queued-edit",
        therapist_id=OTHER,
        user_id=OWNER,
        client_note_id="queued-edit",
        blob=BLOB,
        created_at=NOW,
        updated_at=NOW,
        version=1,
    )
    db.session.add(row)
    await db.session.commit()
    original = therapist._note_chart_guard

    @asynccontextmanager
    async def device_wins(session, user, patient_id):
        async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
            await writer.execute(
                update(TherapistNote)
                .where(TherapistNote.id == row.id)
                .values(blob=b"winner" * 8, version=2, updated_at=NOW)
            )
            await writer.commit()
        async with original(session, user, patient_id):
            yield

    monkeypatch.setattr(therapist, "_note_chart_guard", device_wins)
    with pytest.raises(ApiError) as failure:
        await therapist.update_note(
            NoteUpdateRequest(blob=b64(b"loser" * 8), base_version=1), row.id, db.other, db.session
        )
    envelope(
        failure,
        409,
        "note was modified by another device; refetch and retry",
        "version_conflict",
        {"Retry-After": "1"},
    )
    await db.session.refresh(row)
    assert row.version == 2 and row.blob == b"winner" * 8


async def test_clinical_note_guard_waits_for_shared_processing_lifecycle(sharing_db):
    db = sharing_db

    async def enter():
        async with therapist._notes_guard(db.session, db.other):
            return True

    async with therapist.lifecycle_locks.hold(f"llm-lifecycle:{OTHER}"):
        task = asyncio.create_task(enter())
        try:
            done, _ = await asyncio.wait({task}, timeout=0.05)
            assert not done
        finally:
            if task.done():
                task.result()
            else:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("history", [False, True])
async def test_private_chart_page_fetch_mismatch_identifies_the_exact_collection(
    sharing_db, monkeypatch, history
):
    from fastapi import Response

    from app.models import TherapistNote, TherapistNoteRevision

    db = sharing_db
    await seed_consent(db)
    row = TherapistNote(
        id="fetch-drift",
        therapist_id=OTHER,
        user_id=OWNER,
        client_note_id="fetch-drift",
        blob=BLOB,
        created_at=NOW,
        updated_at=NOW,
        version=1,
    )
    db.session.add(row)
    await db.session.flush()
    db.session.add(
        TherapistNoteRevision(note_id=row.id, therapist_id=OTHER, blob=BLOB, created_at=NOW)
    )
    db.other.notes_revision = 5
    await db.session.commit()
    model = TherapistNoteRevision if history else TherapistNote
    original = db.session.execute

    async def vanished(statement, *args, **kwargs):
        columns = getattr(statement, "column_descriptions", [])
        if len(columns) == 1 and columns[0].get("expr") is model and " IN " in str(statement):
            statement = statement.where(model.id == "missing")
        return await original(statement, *args, **kwargs)

    monkeypatch.setattr(db.session, "execute", vanished)
    with pytest.raises(ApiError) as failure:
        if history:
            await therapist.read_note_revisions(
                row.id, Response(), db.other, db.session, 0, 50, None, "5"
            )
        else:
            await therapist.list_notes(OWNER, Response(), db.other, db.session, 0, 100, None, "5")
    envelope(
        failure,
        409,
        f"{'note revisions' if history else 'notes'} changed while paging; retry the request",
        "collection_changed",
        {"X-Notes-Revision": "5"},
    )


@pytest_asyncio.fixture
async def note_rekey_db(sharing_db, monkeypatch):
    from app.api import account as account_api
    from app.models import TherapistNote, TherapistNoteRevision
    from app.schemas import NoteRekeyItem, NoteRekeyRequest, NoteRekeyRevisionItem

    db = sharing_db
    await seed_consent(db)
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    db.note = TherapistNote(
        id="n" * 32,
        therapist_id=OTHER,
        user_id=OWNER,
        client_note_id="rekeyed-note",
        blob=BLOB,
        created_at=NOW,
        updated_at=NOW,
        version=3,
        pattern_pid="temporal:work",
    )
    db.session.add(db.note)
    await db.session.flush()
    db.revision = TherapistNoteRevision(
        id="r" * 32, note_id=db.note.id, therapist_id=OTHER, blob=BLOB, created_at=NOW
    )
    db.session.add(db.revision)
    db.other.notes_revision = 7
    await db.session.commit()
    db.rekey_body = NoteRekeyRequest(
        items=[
            NoteRekeyItem(
                note_id=db.note.id,
                base_version=3,
                blob=b64(b"n" * len(BLOB)),
                revision_blobs=[
                    NoteRekeyRevisionItem(revision_id=db.revision.id, blob=b64(b"r" * len(BLOB)))
                ],
            )
        ]
    )
    yield db


async def test_note_rekey_preserves_identity_history_and_versions_fence_snapshots(note_rekey_db):
    from app.models import TherapistNoteRevision

    db = note_rekey_db
    await therapist.rekey_notes(db.request, db.rekey_body, db.other, db.session, b64(AUTH_KEY))
    assert (
        db.note.blob == b"n" * len(BLOB)
        and db.note.version == 4
        and db.note.pattern_pid == "temporal:work"
        and db.note.client_note_id == "rekeyed-note"
    )
    assert db.revision.blob == b"r" * len(BLOB) and db.revision.note_id == db.note.id
    assert len(list((await db.session.scalars(select(TherapistNoteRevision))).all())) == 1
    assert db.other.notes_revision == 8
    assert db.audit == [
        dict(actor_id=OTHER, actor_role="therapist", user_id=OWNER, action="rekey_notes")
    ]


@pytest.mark.parametrize(
    "bad",
    [
        "duplicate_note",
        "note_encoding",
        "note_length",
        "duplicate_revision",
        "revision_encoding",
        "missing_revision",
        "revision_length",
        "incomplete_history",
        "stale_version",
        "missing_note",
        "retired_patient",
    ],
)
async def test_note_rekey_ownership_encoding_length_and_snapshot_failures_are_exact(
    note_rekey_db, bad
):
    db = note_rekey_db
    body, item = db.rekey_body, db.rekey_body.items[0]
    status, detail, code, headers = 422, "", "validation_error", None
    if bad == "duplicate_note":
        body.items.append(item.model_copy(deep=True))
        detail = "duplicate note identifier"
    elif bad == "note_encoding":
        item.blob = "!!!!" + item.blob
        detail = "blob must be base64"
    elif bad == "note_length":
        item.blob = b64(b"n" * (len(BLOB) + 1))
        detail = "rekey blob length mismatch (the content must be unchanged)"
    elif bad == "duplicate_revision":
        item.revision_blobs.append(item.revision_blobs[0].model_copy())
        detail = "duplicate revision identifier"
    elif bad == "revision_encoding":
        item.revision_blobs[0].blob = "!!!!" + item.revision_blobs[0].blob
        detail = "revision blob must be base64"
    elif bad == "missing_revision":
        item.revision_blobs[0].revision_id = "missing"
        status, detail, code = 404, "note revision not found", "not_found"
    elif bad == "revision_length":
        item.revision_blobs[0].blob = b64(b"r" * (len(BLOB) + 1))
        detail = "rekey revision blob length mismatch"
    elif bad == "incomplete_history":
        item.revision_blobs = []
        status, detail, code = (
            409,
            "revision history changed or incomplete; refetch",
            "version_conflict",
        )
    elif bad == "stale_version":
        item.base_version = 2
        status, detail, code, headers = (
            409,
            "note was modified by another device; refetch and retry",
            "version_conflict",
            {"Retry-After": "1"},
        )
    elif bad == "missing_note":
        item.note_id = "missing"
        status, detail, code = 404, "note not found", "not_found"
    else:
        db.owner.is_active = False
        await db.session.commit()
        status, detail, code = 404, "note not found", "not_found"
    with pytest.raises(ApiError) as failure:
        await therapist.rekey_notes(db.request, body, db.other, db.session, b64(AUTH_KEY))
    envelope(failure, status, detail, code, headers)
    assert not db.audit


async def test_registration_database_unique_race_rolls_back_and_keeps_exact_conflict(
    authentication_db, monkeypatch
):
    db = authentication_db
    original = db.session.flush

    async def collided(*args, **kwargs):
        await original(*args, **kwargs)
        raise IntegrityError(
            "INSERT users", {}, ValueError("UNIQUE constraint failed: users.username")
        )

    monkeypatch.setattr(db.session, "flush", collided)
    with pytest.raises(ApiError) as failure:
        await auth.register(
            RegisterRequest(
                username="raced-name",
                salt=b64(b"s" * 16),
                verifier=b64(AUTH_KEY),
                age_attestation="minimum_age_confirmed_v1",
            ),
            db.request,
            db.session,
        )
    envelope(failure, 409, "username already taken", "conflict")
    monkeypatch.setattr(db.session, "flush", original)
    assert await db.session.scalar(select(User.id).where(User.username == "raced-name")) is None
    assert not db.destroyed and not db.audit


async def test_logout_accepts_real_bearer_header_and_retires_its_durable_token(authentication_db):
    db = authentication_db
    issued = auth._issue(db.request, db.owner)
    claims = tokens.verify_token(issued.token, db.settings.auth_token_secret)
    await auth.logout(db.request, db.owner, db.session, "Bearer " + issued.token)
    assert await db.request.app.state.token_revocations.is_revoked_checked(
        db.session, claims["jti"]
    )
    assert db.owner.token_epoch == 2 and db.destroyed == [OWNER]


@pytest.mark.parametrize("expires_before_preflight", [False, True])
async def test_consent_grant_expired_pairing_is_flat_at_both_database_reads(
    sharing_db, monkeypatch, expires_before_preflight
):
    from datetime import timedelta

    from app.schemas import ConsentGrantRequest

    db = sharing_db
    await seed_pairing(db)
    expired = NOW + timedelta(seconds=18)
    clock = iter([expired if expires_before_preflight else NOW, expired])
    monkeypatch.setattr(consents, "utcnow", lambda: next(clock))
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "pairing code not found", "not_found")
    assert not db.audit


def test_clinician_pairing_sas_public_patient_identifier_bounds():
    app = FastAPI()
    app.include_router(therapist.router)
    parameters = app.openapi()["paths"]["/therapist/pairing/sas"]["get"]["parameters"]
    schema = next(p["schema"] for p in parameters if p["name"] == "patient_user_id")
    assert (schema["minLength"], schema["maxLength"]) == (1, 32)


@pytest.mark.parametrize("history", [False, True])
async def test_clinical_terminal_page_at_exact_row_limit_has_no_continuation(
    note_rekey_db, history
):
    from fastapi import Response

    db = note_rekey_db
    response = Response()
    if history:
        rows = await therapist.read_note_revisions(
            db.note.id, response, db.other, db.session, 0, 1, None, "7"
        )
        assert [r.id for r in rows] == [db.revision.id]
    else:
        rows = await therapist.list_notes(OWNER, response, db.other, db.session, 0, 1, None, "7")
        assert [r.id for r in rows] == [db.note.id]
    assert response.headers["X-Notes-Revision"] == "7"
    assert "X-Next-Offset" not in response.headers


@pytest.mark.parametrize("history", [False, True])
async def test_clinical_blob_length_queries_support_sqlite_without_optional_octet_length(
    note_rekey_db, history
):
    db = note_rekey_db

    def unavailable(value):
        raise NotImplementedError("older supported SQLite has no octet_length")

    async with db.engine.begin() as connection:
        await connection.run_sync(
            lambda c: c.connection.create_function("octet_length", 1, unavailable)
        )
    expression = (
        therapist._revision_blob_length(db.session)
        if history
        else therapist._note_blob_length(db.session)
    )
    assert await db.session.scalar(select(expression)) == len(BLOB)


@pytest.mark.parametrize("operation", ["update", "delete", "rekey"])
async def test_note_removed_while_queued_returns_flat_not_found(
    note_rekey_db, monkeypatch, operation
):
    from contextlib import asynccontextmanager

    from fastapi import Response
    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import TherapistNote
    from app.schemas import NoteUpdateRequest

    db = note_rekey_db
    target = "_notes_guard" if operation == "rekey" else "_note_chart_guard"
    original = getattr(therapist, target)
    note_id = db.note.id

    @asynccontextmanager
    async def deleted(session, user, *args):
        async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
            await writer.execute(delete(TherapistNote).where(TherapistNote.id == note_id))
            await writer.commit()
        async with original(session, user, *args):
            yield

    monkeypatch.setattr(therapist, target, deleted)
    with pytest.raises(ApiError) as failure:
        if operation == "rekey":
            await therapist.rekey_notes(
                db.request, db.rekey_body, db.other, db.session, b64(AUTH_KEY)
            )
        elif operation == "update":
            await therapist.update_note(
                NoteUpdateRequest(blob=b64(BLOB), base_version=3), note_id, db.other, db.session
            )
        else:
            await therapist.delete_note(note_id, Response(), db.other, db.session)
    envelope(failure, 404, "note not found", "not_found")
    assert not db.audit


@pytest.mark.parametrize("change", ["device_version", "retired_patient"])
async def test_note_rekey_rechecks_patient_and_device_version_after_preflight(
    note_rekey_db, monkeypatch, change
):
    from contextlib import asynccontextmanager

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import TherapistNote, TherapistNoteRevision

    db = note_rekey_db
    original = therapist._notes_guard
    note_id, revision_id = db.note.id, db.revision.id

    @asynccontextmanager
    async def device_wins(session, user):
        async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
            if change == "device_version":
                await writer.execute(
                    update(TherapistNote)
                    .where(TherapistNote.id == note_id)
                    .values(blob=b"w" * len(BLOB), version=4)
                )
                await writer.execute(
                    update(TherapistNoteRevision)
                    .where(TherapistNoteRevision.id == revision_id)
                    .values(blob=b"h" * len(BLOB))
                )
            else:
                await writer.execute(update(User).where(User.id == OWNER).values(is_active=False))
            await writer.commit()
        async with original(session, user):
            yield

    monkeypatch.setattr(therapist, "_notes_guard", device_wins)
    with pytest.raises(ApiError) as failure:
        await therapist.rekey_notes(db.request, db.rekey_body, db.other, db.session, b64(AUTH_KEY))
    if change == "device_version":
        envelope(
            failure,
            409,
            "note was modified by another device; refetch and retry",
            "version_conflict",
            {"Retry-After": "1"},
        )
        await db.session.refresh(db.note)
        await db.session.refresh(db.revision)
        assert db.note.version == 4 and db.note.blob == b"w" * len(BLOB)
        assert db.revision.blob == b"h" * len(BLOB)
    else:
        envelope(failure, 404, "note not found", "not_found")
    assert not db.audit


@pytest.mark.parametrize("operation", ["update", "delete"])
async def test_note_queued_mutations_refuse_patient_retirement_before_the_chart_fence(
    note_rekey_db, monkeypatch, operation
):
    from contextlib import asynccontextmanager

    from fastapi import Response
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.schemas import NoteUpdateRequest

    db = note_rekey_db
    original = therapist._note_chart_guard
    note_id = db.note.id

    @asynccontextmanager
    async def retired(session, user, patient_id):
        async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
            await writer.execute(update(User).where(User.id == OWNER).values(is_active=False))
            await writer.commit()
        async with original(session, user, patient_id):
            yield

    monkeypatch.setattr(therapist, "_note_chart_guard", retired)
    with pytest.raises(ApiError) as failure:
        if operation == "update":
            await therapist.update_note(
                NoteUpdateRequest(blob=b64(BLOB), base_version=3), note_id, db.other, db.session
            )
        else:
            await therapist.delete_note(note_id, Response(), db.other, db.session)
    envelope(failure, 404, "note not found", "not_found")
    assert not db.audit


@pytest.mark.parametrize("constraint", ["unique", "foreign_key"])
async def test_clinical_note_write_database_constraint_race_keeps_exact_error_and_rolls_back(
    sharing_db, monkeypatch, constraint
):
    from app.models import TherapistNote
    from app.schemas import NoteCreateRequest

    db = sharing_db
    await seed_consent(db)
    original_audit, original_commit = therapist._audit, db.session.commit

    async def write_audit(*args, **kwargs):
        await original_audit(*args, **kwargs)

        async def failed_commit():
            error = Exception("database constraint race")
            error.sqlstate = "23505" if constraint == "unique" else "23503"
            raise IntegrityError("INSERT therapist_notes", {}, error)

        monkeypatch.setattr(db.session, "commit", failed_commit)

    monkeypatch.setattr(therapist, "_audit", write_audit)
    try:
        with pytest.raises(ApiError) as failure:
            await therapist.create_note(
                NoteCreateRequest(client_note_id="constraint-race", blob=b64(BLOB)),
                OWNER,
                db.other,
                db.session,
            )
        envelope(
            failure,
            409 if constraint == "unique" else 404,
            "note already exists" if constraint == "unique" else "patient not found",
            "conflict" if constraint == "unique" else "not_found",
        )
    finally:
        monkeypatch.setattr(db.session, "commit", original_commit)
    assert (
        await db.session.scalar(
            select(TherapistNote.id).where(TherapistNote.client_note_id == "constraint-race")
        )
        is None
    )


async def test_note_revision_page_final_marker_drift_uses_history_collection_name(
    note_rekey_db, monkeypatch
):
    from fastapi import Response

    db = note_rekey_db
    calls = 0
    original = therapist._current_notes_revision

    async def changed(session, user_id):
        nonlocal calls
        calls += 1
        current = await original(session, user_id)
        return current if calls == 1 else current + 1

    monkeypatch.setattr(therapist, "_current_notes_revision", changed)
    with pytest.raises(ApiError) as failure:
        await therapist.read_note_revisions(
            db.note.id, Response(), db.other, db.session, 0, 1, None, "7"
        )
    envelope(
        failure,
        409,
        "note revisions changed while paging; retry the request",
        "collection_changed",
        {"X-Notes-Revision": "8"},
    )


@pytest.mark.parametrize("unavailable", ["inactive", "role", "key"])
async def test_consent_grant_unavailable_clinician_is_flat_before_fences(sharing_db, unavailable):
    from app.schemas import ConsentGrantRequest

    db = sharing_db
    await seed_pairing(db)
    if unavailable == "inactive":
        db.other.is_active = False
    elif unavailable == "role":
        db.other.role = "user"
    else:
        db.other.wrap_pub_key = None
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await consents.grant_consent(
            ConsentGrantRequest(
                code=db.code, ephemeral_pub=db.spki, wrapped_key=b64(BLOB), disclosure="v3"
            ),
            db.request,
            db.owner,
            db.session,
            "credential",
            None,
        )
    envelope(failure, 404, "pairing code not found", "not_found")
    assert not db.audit
